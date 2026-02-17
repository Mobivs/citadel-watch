"""Defense Mesh HMAC key management — pre-shared key generation and storage.

v0.3.36: Each mesh node shares a single pre-shared key (PSK) used for
HMAC-SHA256 signing of heartbeat packets.  The PSK is generated once on
first mesh startup and stored via UserPreferences.  All peers must share
the same key (distributed out-of-band, e.g. during agent enrollment).

Key lifecycle:
    1. Desktop generates a 256-bit PSK on first mesh start.
    2. PSK is stored base64-encoded in UserPreferences ("mesh_psk").
    3. When enrolling a new VPS peer, the PSK is transmitted securely
       (via the existing encrypted enrollment channel).
    4. Sender signs packets: HMAC-SHA256(psk, canonical_message).
    5. Receiver verifies signature with constant-time comparison.
    6. Key rotation: generate_psk() + distribute to all peers.

Zero AI tokens consumed — pure cryptographic automation.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

PSK_LENGTH = 32  # 256-bit key
HMAC_DOMAIN = "mesh:heartbeat:v1"  # Domain separation string
PREFS_KEY = "mesh_psk"


# ── Key Generation ───────────────────────────────────────────────────


def generate_psk() -> bytes:
    """Generate a cryptographically random 256-bit pre-shared key."""
    return secrets.token_bytes(PSK_LENGTH)


def psk_to_base64(psk: bytes) -> str:
    """Encode PSK for safe storage (UserPreferences, API responses)."""
    return base64.b64encode(psk).decode("ascii")


def psk_from_base64(encoded: str) -> bytes:
    """Decode PSK from base64 storage format.

    Raises:
        binascii.Error: If the input is not valid base64.
        ValueError: If the decoded key is not PSK_LENGTH bytes.
    """
    decoded = base64.b64decode(encoded)
    if len(decoded) != PSK_LENGTH:
        raise ValueError(
            f"PSK must be {PSK_LENGTH} bytes; got {len(decoded)}"
        )
    return decoded


# ── HMAC Signing ─────────────────────────────────────────────────────


def sign_packet(packet_dict: dict, psk: bytes) -> str:
    """HMAC-SHA256 sign a heartbeat packet.

    The signature covers the canonical JSON of all fields except
    ``signature`` itself, prefixed with a domain separation string
    to prevent cross-protocol key reuse.

    Args:
        packet_dict: Packet as dict (``signature`` field is excluded).
        psk: 256-bit pre-shared key.

    Returns:
        Hex-encoded HMAC-SHA256 signature.
    """
    signable = {k: v for k, v in packet_dict.items() if k != "signature"}
    canonical = json.dumps(signable, sort_keys=True, separators=(",", ":"))
    message = f"{HMAC_DOMAIN}:{canonical}".encode("utf-8")
    return hmac.new(psk, message, hashlib.sha256).hexdigest()


def verify_signature(packet_dict: dict, signature: str, psk: bytes) -> bool:
    """Verify HMAC-SHA256 signature with constant-time comparison.

    Args:
        packet_dict: Packet as dict (``signature`` field is excluded from computation).
        signature: Hex-encoded signature from the packet.
        psk: 256-bit pre-shared key.

    Returns:
        True if signature is valid.
    """
    expected = sign_packet(packet_dict, psk)
    return secrets.compare_digest(expected, signature)


# ── Persistent Key Store ─────────────────────────────────────────────


def load_or_create_psk() -> bytes:
    """Load PSK from UserPreferences, or generate and persist a new one.

    Called once during mesh coordinator startup.  Thread-safe because
    UserPreferences uses SQLite (serialized writes).
    """
    try:
        from ..core.user_preferences import get_user_preferences
        prefs = get_user_preferences()
        stored = prefs.get(PREFS_KEY)
        if stored:
            return psk_from_base64(stored)
    except Exception:
        logger.debug("Could not load mesh PSK from preferences", exc_info=True)

    # First run — generate new PSK
    psk = generate_psk()
    try:
        from ..core.user_preferences import get_user_preferences
        prefs = get_user_preferences()
        prefs.set(PREFS_KEY, psk_to_base64(psk))
    except Exception:
        logger.warning("Could not persist mesh PSK", exc_info=True)

    return psk


def get_psk_fingerprint(psk: bytes) -> str:
    """Short fingerprint for display (first 8 hex chars of SHA-256).

    Safe for logging — does not reveal the key itself.
    """
    return hashlib.sha256(psk).hexdigest()[:8]
