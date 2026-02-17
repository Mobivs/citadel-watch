"""Backup manager — create, list, restore, and delete encrypted backup archives.

Each backup is a single .citadel-backup file containing:
  - All SQLite databases hot-copied via sqlite3.backup()
  - Recent audit log files (last 30 days)
  - A manifest.json with metadata and SHA-256 checksum

The archive is a ZIP (deflated) encrypted as a single blob with AES-256-GCM.
"""

import hashlib
import io
import json
import logging
import shutil
import sqlite3
import tempfile
import threading
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from uuid import uuid4

from .backup_crypto import BackupCrypto
from .backup_database import BackupDatabase

logger = logging.getLogger(__name__)

# Databases to include in backups (name, relative path from data_dir)
DATA_STORES: List[tuple] = [
    ("vault", "vault.db"),
    ("e2e_sessions", "e2e_sessions.db"),
    ("assets", "assets.db"),
    ("remote_shield", "remote_shield.db"),
    ("contacts", "contacts.db"),
    ("agent_registry", "agent_registry.db"),
    ("panic_sessions", "panic_sessions.db"),
    ("securechat", "securechat.db"),
    ("agent_invitations", "agent_invitations.db"),
    ("user_preferences", "user_preferences.db"),
    ("backup_history", "backup_history.db"),
]

# Only include audit logs from the last 30 days
_AUDIT_LOG_MAX_AGE_DAYS = 30

# Manifest version — increment if archive format changes
_MANIFEST_VERSION = 1


class BackupError(Exception):
    """Raised for backup/restore failures."""


class BackupManager:
    """Orchestrates backup creation, listing, restoration, and deletion.

    Args:
        data_dir: Directory containing SQLite databases (default: project_root/data).
        backup_dir: Directory to store .citadel-backup archives (default: data/backups/).
        backup_db: BackupDatabase instance.  Created automatically if None.
        audit_log_dir: Directory containing audit log files (default: project_root/audit_logs).
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
        backup_db: Optional[BackupDatabase] = None,
        audit_log_dir: Optional[Path] = None,
    ):
        if data_dir is None:
            # Walk up from this file to find project root
            data_dir = Path(__file__).resolve().parent.parent.parent.parent / "data"
        self._data_dir = Path(data_dir)
        self._backup_dir = Path(backup_dir) if backup_dir else self._data_dir / "backups"
        self._backup_dir.mkdir(parents=True, exist_ok=True)

        self._db = backup_db or BackupDatabase(str(self._data_dir / "backup_history.db"))

        if audit_log_dir is None:
            self._audit_log_dir = self._data_dir.parent / "audit_logs"
        else:
            self._audit_log_dir = Path(audit_log_dir)

        self._lock = threading.Lock()

    # ── Create ───────────────────────────────────────────────────────

    def create_backup(self, passphrase: str, label: str = "") -> dict:
        """Create an encrypted backup archive of all dashboard state.

        Args:
            passphrase: Encryption passphrase (min 12 characters).
            label: Optional human-readable label for this backup.

        Returns:
            Backup metadata dict (same as get_backup_info).

        Raises:
            BackupError: On validation failure or I/O error.
        """
        if len(passphrase) < 12:
            raise BackupError("Passphrase must be at least 12 characters.")

        with self._lock:
            return self._create_backup_locked(passphrase, label)

    def _create_backup_locked(self, passphrase: str, label: str) -> dict:
        backup_id = uuid4().hex[:16]
        tmp_dir = Path(tempfile.mkdtemp(prefix="citadel_backup_"))

        try:
            # 1. Hot-copy databases
            db_names = []
            db_dir = tmp_dir / "databases"
            db_dir.mkdir()

            for name, rel_path in DATA_STORES:
                src_path = self._data_dir / rel_path
                if not src_path.exists():
                    continue
                dst_path = db_dir / f"{name}.db"
                self._hot_copy_db(src_path, dst_path)
                db_names.append(name)

            # 2. Collect audit logs (last 30 days)
            log_files = self._collect_audit_logs(tmp_dir)

            # 3. Build ZIP in memory (without manifest for checksum)
            created_at = datetime.now(timezone.utc).isoformat()
            zip_buf = io.BytesIO()
            with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
                # Add databases
                for name in db_names:
                    db_file = db_dir / f"{name}.db"
                    zf.write(db_file, f"databases/{name}.db")

                # Add logs
                log_dir = tmp_dir / "logs"
                for log_name in log_files:
                    log_path = log_dir / log_name
                    zf.write(log_path, f"logs/{log_name}")

            # 4. Checksum the data-only ZIP content
            data_zip_bytes = zip_buf.getvalue()
            checksum = hashlib.sha256(data_zip_bytes).hexdigest()

            # 5. Rebuild final ZIP with manifest containing the real checksum
            manifest = {
                "version": _MANIFEST_VERSION,
                "backup_id": backup_id,
                "label": label,
                "created_at": created_at,
                "db_names": db_names,
                "log_files": log_files,
                "db_count": len(db_names),
                "log_count": len(log_files),
                "checksum_sha256": checksum,
            }
            final_buf = io.BytesIO()
            with zipfile.ZipFile(final_buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for name in db_names:
                    db_file = db_dir / f"{name}.db"
                    zf.write(db_file, f"databases/{name}.db")
                log_dir = tmp_dir / "logs"
                for log_name in log_files:
                    log_path = log_dir / log_name
                    zf.write(log_path, f"logs/{log_name}")
                zf.writestr("manifest.json", json.dumps(manifest, indent=2))

            final_zip = final_buf.getvalue()

            # 6. Encrypt
            encrypted = BackupCrypto.encrypt_bytes(final_zip, passphrase)

            # 7. Write archive
            archive_path = self._backup_dir / f"{backup_id}.citadel-backup"
            archive_path.write_bytes(encrypted)

            # 8. Record in history DB
            record = self._db.record_backup(
                backup_id=backup_id,
                label=label,
                size_bytes=len(encrypted),
                db_count=len(db_names),
                log_count=len(log_files),
                checksum_sha256=checksum,
                archive_path=str(archive_path),
            )

            # 9. Audit log
            self._audit_log("backup.created", f"Backup created: {backup_id}", {
                "backup_id": backup_id,
                "label": label,
                "db_count": len(db_names),
                "log_count": len(log_files),
                "size_bytes": len(encrypted),
            })

            return record

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # ── List / Info ──────────────────────────────────────────────────

    def list_backups(self) -> List[dict]:
        """Return all backup records, marking missing archives as 'deleted'."""
        backups = self._db.list_backups()
        for b in backups:
            if b["status"] == "complete" and not Path(b["archive_path"]).exists():
                self._db.update_status(b["backup_id"], "deleted")
                b["status"] = "deleted"
        return backups

    def get_backup_info(self, backup_id: str) -> Optional[dict]:
        """Return a single backup record or None."""
        return self._db.get_backup(backup_id)

    # ── Delete ───────────────────────────────────────────────────────

    def delete_backup(self, backup_id: str) -> bool:
        """Delete a backup archive and its DB record.

        Returns True if the backup existed and was deleted.
        """
        record = self._db.get_backup(backup_id)
        if not record:
            return False

        archive = Path(record["archive_path"])
        if archive.exists():
            archive.unlink()

        self._db.delete_backup_record(backup_id)

        self._audit_log("backup.deleted", f"Backup deleted: {backup_id}", {
            "backup_id": backup_id,
        })
        return True

    # ── Restore ──────────────────────────────────────────────────────

    def restore_backup(self, backup_id: str, passphrase: str) -> dict:
        """Restore dashboard state from an encrypted backup archive.

        Creates a pre-restore safety backup before overwriting databases.

        Args:
            backup_id: ID of the backup to restore.
            passphrase: Decryption passphrase.

        Returns:
            Dict with restored_dbs, restored_logs, pre_restore_backup_id.

        Raises:
            BackupError: If backup not found, wrong passphrase, or corrupt archive.
        """
        record = self._db.get_backup(backup_id)
        if not record:
            raise BackupError(f"Backup not found: {backup_id}")

        archive = Path(record["archive_path"])
        if not archive.exists():
            raise BackupError(f"Backup archive file missing: {archive}")

        with self._lock:
            return self._restore_locked(backup_id, passphrase, archive, record)

    def _restore_locked(
        self, backup_id: str, passphrase: str, archive: Path, record: dict
    ) -> dict:
        # 1. Decrypt
        encrypted = archive.read_bytes()
        try:
            zip_bytes = BackupCrypto.decrypt_bytes(encrypted, passphrase)
        except Exception:
            raise BackupError("Invalid passphrase or corrupt archive.")

        # 2. Verify manifest
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            try:
                manifest = json.loads(zf.read("manifest.json"))
            except (KeyError, json.JSONDecodeError):
                raise BackupError("Corrupt archive: missing or invalid manifest.")

            # 3. Pre-restore safety backup
            pre_restore_id = None
            try:
                pre_result = self._create_backup_locked(
                    passphrase, label=f"pre-restore-{backup_id}"
                )
                pre_restore_id = pre_result["backup_id"]
            except Exception as e:
                logger.warning("Could not create pre-restore backup: %s", e)

            # 4. Restore databases
            restored_dbs = []
            tmp_dir = Path(tempfile.mkdtemp(prefix="citadel_restore_"))
            try:
                for name in zf.namelist():
                    if name.startswith("databases/") and name.endswith(".db"):
                        db_name = Path(name).stem
                        # Find the live path
                        live_path = None
                        for store_name, rel_path in DATA_STORES:
                            if store_name == db_name:
                                live_path = self._data_dir / rel_path
                                break
                        if live_path is None:
                            continue

                        # Extract to tmp
                        zf.extract(name, tmp_dir)
                        tmp_db = tmp_dir / name

                        # Restore via sqlite3.backup() for atomic replace
                        self._restore_db(tmp_db, live_path)
                        restored_dbs.append(db_name)

                # 5. Restore audit logs (append with .restored suffix)
                restored_logs = []
                for name in zf.namelist():
                    if name.startswith("logs/") and name.endswith(".log"):
                        log_name = Path(name).name
                        restored_name = log_name.replace(".log", ".restored.log")
                        dst = self._audit_log_dir / restored_name
                        self._audit_log_dir.mkdir(parents=True, exist_ok=True)
                        dst.write_bytes(zf.read(name))
                        restored_logs.append(restored_name)

            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        self._audit_log("backup.restored", f"Backup restored: {backup_id}", {
            "backup_id": backup_id,
            "restored_dbs": restored_dbs,
            "restored_logs": restored_logs,
            "pre_restore_backup_id": pre_restore_id,
        })

        return {
            "backup_id": backup_id,
            "restored_dbs": restored_dbs,
            "restored_logs": restored_logs,
            "pre_restore_backup_id": pre_restore_id,
        }

    # ── Helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _hot_copy_db(src: Path, dst: Path):
        """Atomic hot copy of a SQLite database using the backup API."""
        src_conn = None
        dst_conn = None
        try:
            src_conn = sqlite3.connect(str(src))
            dst_conn = sqlite3.connect(str(dst))
            src_conn.backup(dst_conn)
        finally:
            if dst_conn:
                dst_conn.close()
            if src_conn:
                src_conn.close()

    @staticmethod
    def _restore_db(src: Path, dst: Path):
        """Restore a database file via sqlite3.backup() for atomic replace."""
        dst.parent.mkdir(parents=True, exist_ok=True)
        src_conn = None
        dst_conn = None
        try:
            src_conn = sqlite3.connect(str(src))
            dst_conn = sqlite3.connect(str(dst))
            src_conn.backup(dst_conn)
        finally:
            if dst_conn:
                dst_conn.close()
            if src_conn:
                src_conn.close()

    def _collect_audit_logs(self, tmp_dir: Path) -> List[str]:
        """Copy recent audit log files into tmp_dir/logs/. Returns filenames."""
        log_dir = tmp_dir / "logs"
        log_dir.mkdir()
        collected = []

        if not self._audit_log_dir.exists():
            return collected

        cutoff = datetime.now(timezone.utc) - timedelta(days=_AUDIT_LOG_MAX_AGE_DAYS)
        for log_file in sorted(self._audit_log_dir.glob("audit_*.log")):
            # Check modification time
            mtime = datetime.fromtimestamp(log_file.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                continue
            shutil.copy2(log_file, log_dir / log_file.name)
            collected.append(log_file.name)

        return collected

    @staticmethod
    def _audit_log(event_type_value: str, message: str, details: dict):
        """Best-effort audit logging (import may fail during tests)."""
        try:
            from ..core.audit_log import EventType, EventSeverity, log_security_event
            log_security_event(
                EventType(event_type_value),
                EventSeverity.INFO,
                message,
                details=details,
            )
        except ImportError:
            logger.debug("Audit log unavailable (import): %s", message)
        except Exception:
            logger.warning("Audit log failed: %s", message, exc_info=True)
