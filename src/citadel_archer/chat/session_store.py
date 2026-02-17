# PRD: E2E Session State Persistence
# Reference: docs/PRD.md v0.3.18, Phase 4
#
# SQLite-backed storage for:
#   - Local identity keys (Ed25519 + X25519)
#   - Signed prekeys and one-time prekeys
#   - Per-contact Double Ratchet session state
#
# Security:
#   - Private keys stored as plaintext hex in local SQLite
#     TODO: Encrypt private_key columns using EncryptionService (PBKDF2 + AES-256-GCM)
#     matching the vault's trust model. See vault/encryption.py.
#   - WAL journal mode for concurrent readers
#   - Thread-safe via threading.Lock
#
# Design:
#   - Follows ContactRegistry pattern: SQLite + WAL + context manager connections
#   - Singleton accessor via get_session_store()
#   - Local keys auto-generated on first access

import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from .p2p_crypto import (
    DHKeyPair,
    PreKeyBundle,
    RatchetState,
    SigningKeyPair,
    create_prekey_bundle,
)

logger = logging.getLogger(__name__)


class SessionStore:
    """Persistent storage for E2E encryption state.

    Manages:
    - Local identity keys (generated once, reused across sessions)
    - Signed prekeys and one-time prekeys (rotatable)
    - Per-contact ratchet session state

    Usage::

        store = SessionStore()
        identity = store.get_or_create_identity()
        bundle = store.get_local_prekey_bundle()

        # After X3DH + ratchet init:
        store.save_session("contact-uuid", ratchet_state)
        state = store.load_session("contact-uuid")
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else Path("data/e2e_sessions.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_database()

    @contextmanager
    def _connect(self):
        """Open a WAL-mode SQLite connection; auto-closes on exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Create tables if they don't exist."""
        with self._connect() as conn:
            # Local identity keys (only one row expected)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS local_keys (
                    key_type TEXT PRIMARY KEY,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            # Signed prekeys (current + recent for rotation)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS prekeys (
                    prekey_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_type TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            # Per-contact ratchet sessions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    contact_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

    # ── Local Identity Keys ──────────────────────────────────────────

    def get_or_create_identity(self) -> Dict[str, Any]:
        """Get or create the local identity key pairs.

        Returns dict with:
          - signing: SigningKeyPair (Ed25519)
          - dh: DHKeyPair (X25519)
        """
        with self._lock:
            with self._connect() as conn:
                signing_row = conn.execute(
                    "SELECT private_key FROM local_keys WHERE key_type = 'signing'",
                ).fetchone()
                dh_row = conn.execute(
                    "SELECT private_key FROM local_keys WHERE key_type = 'identity_dh'",
                ).fetchone()

                if signing_row and dh_row:
                    signing = SigningKeyPair.from_private_bytes(
                        bytes.fromhex(signing_row["private_key"]),
                    )
                    dh = DHKeyPair.from_private_bytes(
                        bytes.fromhex(dh_row["private_key"]),
                    )
                    return {"signing": signing, "dh": dh}

                # Generate new identity keys
                signing = SigningKeyPair.generate()
                dh = DHKeyPair.generate()

                conn.execute(
                    "INSERT OR REPLACE INTO local_keys (key_type, private_key, public_key) "
                    "VALUES (?, ?, ?)",
                    ("signing", signing.private_bytes.hex(), signing.public_bytes.hex()),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO local_keys (key_type, private_key, public_key) "
                    "VALUES (?, ?, ?)",
                    ("identity_dh", dh.private_bytes.hex(), dh.public_bytes.hex()),
                )

                logger.info(
                    "Generated new identity keys: signing=%s... dh=%s...",
                    signing.public_bytes.hex()[:16],
                    dh.public_bytes.hex()[:16],
                )
                return {"signing": signing, "dh": dh}

    # ── Prekeys ──────────────────────────────────────────────────────

    def get_or_create_signed_prekey(self) -> DHKeyPair:
        """Get or create the current signed prekey."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT private_key FROM prekeys "
                    "WHERE key_type = 'signed' AND is_current = 1 "
                    "ORDER BY prekey_id DESC LIMIT 1",
                ).fetchone()

                if row:
                    return DHKeyPair.from_private_bytes(
                        bytes.fromhex(row["private_key"]),
                    )

                # Generate new signed prekey
                pair = DHKeyPair.generate()
                conn.execute(
                    "INSERT INTO prekeys (key_type, private_key, public_key) "
                    "VALUES (?, ?, ?)",
                    ("signed", pair.private_bytes.hex(), pair.public_bytes.hex()),
                )
                return pair

    def generate_one_time_prekeys(self, count: int = 5) -> List[DHKeyPair]:
        """Generate a batch of one-time prekeys."""
        keys = []
        with self._lock:
            with self._connect() as conn:
                for _ in range(count):
                    pair = DHKeyPair.generate()
                    conn.execute(
                        "INSERT INTO prekeys (key_type, private_key, public_key) "
                        "VALUES (?, ?, ?)",
                        ("one_time", pair.private_bytes.hex(), pair.public_bytes.hex()),
                    )
                    keys.append(pair)
        return keys

    def consume_one_time_prekey(self, public_key_hex: str) -> Optional[DHKeyPair]:
        """Consume a one-time prekey by its public key (returns and deletes it)."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT prekey_id, private_key FROM prekeys "
                    "WHERE key_type = 'one_time' AND public_key = ? AND is_current = 1",
                    (public_key_hex,),
                ).fetchone()

                if not row:
                    return None

                pair = DHKeyPair.from_private_bytes(
                    bytes.fromhex(row["private_key"]),
                )
                conn.execute(
                    "UPDATE prekeys SET is_current = 0 WHERE prekey_id = ?",
                    (row["prekey_id"],),
                )
                return pair

    def get_local_prekey_bundle(self) -> PreKeyBundle:
        """Build the local prekey bundle for sharing with peers.

        Consumes the one-time prekey (marks it as used) so it cannot be
        reused across sessions. One-time prekeys are single-use per X3DH spec.
        """
        # Single lock acquisition to prevent TOCTOU between key reads
        with self._lock:
            with self._connect() as conn:
                # Identity keys
                signing_row = conn.execute(
                    "SELECT private_key FROM local_keys WHERE key_type = 'signing'",
                ).fetchone()
                dh_row = conn.execute(
                    "SELECT private_key FROM local_keys WHERE key_type = 'identity_dh'",
                ).fetchone()

                if not signing_row or not dh_row:
                    # Keys don't exist yet — release lock and delegate to
                    # get_or_create_identity which handles generation
                    pass

        # Generate identity if needed (acquires lock internally)
        if not signing_row or not dh_row:
            identity = self.get_or_create_identity()
            signing_kp = identity["signing"]
            dh_kp = identity["dh"]
        else:
            signing_kp = SigningKeyPair.from_private_bytes(
                bytes.fromhex(signing_row["private_key"]),
            )
            dh_kp = DHKeyPair.from_private_bytes(
                bytes.fromhex(dh_row["private_key"]),
            )

        with self._lock:
            with self._connect() as conn:
                # Signed prekey
                spk_row = conn.execute(
                    "SELECT private_key FROM prekeys "
                    "WHERE key_type = 'signed' AND is_current = 1 "
                    "ORDER BY prekey_id DESC LIMIT 1",
                ).fetchone()

                if not spk_row:
                    # Need to generate — release and delegate
                    pass

        if not spk_row:
            signed_prekey = self.get_or_create_signed_prekey()
        else:
            signed_prekey = DHKeyPair.from_private_bytes(
                bytes.fromhex(spk_row["private_key"]),
            )

        # Atomically fetch and consume one-time prekey
        one_time_prekey = None
        with self._lock:
            with self._connect() as conn:
                otk_row = conn.execute(
                    "SELECT prekey_id, private_key FROM prekeys "
                    "WHERE key_type = 'one_time' AND is_current = 1 "
                    "ORDER BY prekey_id ASC LIMIT 1",
                ).fetchone()

                if otk_row:
                    one_time_prekey = DHKeyPair.from_private_bytes(
                        bytes.fromhex(otk_row["private_key"]),
                    )
                    # Mark as consumed — single-use per X3DH spec
                    conn.execute(
                        "UPDATE prekeys SET is_current = 0 WHERE prekey_id = ?",
                        (otk_row["prekey_id"],),
                    )

        return create_prekey_bundle(
            identity_signing=signing_kp,
            identity_dh=dh_kp,
            signed_prekey=signed_prekey,
            one_time_prekey=one_time_prekey,
        )

    # ── Session State ────────────────────────────────────────────────

    def save_session(self, contact_id: str, state: RatchetState) -> None:
        """Persist a ratchet session state for a contact."""
        state_json = json.dumps(state.to_dict())
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO sessions (contact_id, state_json, updated_at) "
                    "VALUES (?, ?, datetime('now'))",
                    (contact_id, state_json),
                )

    def load_session(self, contact_id: str) -> Optional[RatchetState]:
        """Load a ratchet session state for a contact."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT state_json FROM sessions WHERE contact_id = ?",
                    (contact_id,),
                ).fetchone()

                if not row:
                    return None

                return RatchetState.from_dict(json.loads(row["state_json"]))

    def delete_session(self, contact_id: str) -> bool:
        """Delete a ratchet session (e.g., when contact is blocked or deleted)."""
        with self._lock:
            with self._connect() as conn:
                cursor = conn.execute(
                    "DELETE FROM sessions WHERE contact_id = ?",
                    (contact_id,),
                )
                return cursor.rowcount > 0

    def list_sessions(self) -> List[str]:
        """List contact IDs with active sessions."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT contact_id FROM sessions ORDER BY updated_at DESC",
                ).fetchall()
                return [r["contact_id"] for r in rows]

    # ── Statistics ───────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return E2E session statistics."""
        with self._lock:
            with self._connect() as conn:
                session_count = conn.execute(
                    "SELECT COUNT(*) FROM sessions",
                ).fetchone()[0]
                otk_count = conn.execute(
                    "SELECT COUNT(*) FROM prekeys "
                    "WHERE key_type = 'one_time' AND is_current = 1",
                ).fetchone()[0]
                has_identity = conn.execute(
                    "SELECT COUNT(*) FROM local_keys",
                ).fetchone()[0] > 0

                return {
                    "has_identity_keys": has_identity,
                    "active_sessions": session_count,
                    "available_one_time_prekeys": otk_count,
                }


# ── Singleton ────────────────────────────────────────────────────────

_store: Optional[SessionStore] = None
_store_lock = threading.Lock()


def get_session_store() -> SessionStore:
    """Get or create the global SessionStore singleton."""
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                _store = SessionStore()
    return _store
