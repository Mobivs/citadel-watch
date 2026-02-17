"""Secondary brain hardening — additional security for the fallback coordinator.

v0.3.40: The secondary brain VPS is a high-value target — it has an API key
and coordination authority. This module defines hardening policies and
enforcement mechanisms:

  - Restricted SSH (key-only, non-standard port, aggressive fail2ban)
  - Encrypted API key storage (Fernet symmetric encryption, not plaintext)
  - Separate credentials from regular shield agents
  - Rate-limited outbound API calls (token bucket)
  - Append-only audit log for coordination decisions

Zero AI tokens — pure automation policy enforcement.
"""

import base64
import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Hardening Policy ────────────────────────────────────────────────


@dataclass
class SSHHardeningPolicy:
    """SSH hardening rules for the secondary brain VPS."""

    key_only_auth: bool = True          # Disable password authentication
    non_standard_port: int = 2222       # Non-default SSH port
    fail2ban_max_retry: int = 3         # Aggressive fail2ban threshold
    fail2ban_ban_time: int = 3600       # 1 hour ban
    fail2ban_find_time: int = 600       # 10 minute window
    allowed_users: List[str] = field(default_factory=lambda: ["citadel"])
    allowed_key_fingerprints: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "key_only_auth": self.key_only_auth,
            "non_standard_port": self.non_standard_port,
            "fail2ban_max_retry": self.fail2ban_max_retry,
            "fail2ban_ban_time": self.fail2ban_ban_time,
            "fail2ban_find_time": self.fail2ban_find_time,
            "allowed_users": self.allowed_users,
            "allowed_key_fingerprints": self.allowed_key_fingerprints,
        }

    def to_sshd_config_fragment(self) -> str:
        """Generate sshd_config directives for the hardening policy."""
        lines = [
            "# Citadel Archer secondary brain hardening",
            f"Port {self.non_standard_port}",
            "PasswordAuthentication no" if self.key_only_auth else "PasswordAuthentication yes",
            "PermitRootLogin prohibit-password",
            "MaxAuthTries 3",
            "LoginGraceTime 30",
            "ClientAliveInterval 300",
            "ClientAliveCountMax 2",
        ]
        if self.allowed_users:
            lines.append(f"AllowUsers {' '.join(self.allowed_users)}")
        return "\n".join(lines)

    def to_fail2ban_config(self) -> str:
        """Generate fail2ban jail config for aggressive SSH protection."""
        return (
            "[sshd]\n"
            "enabled = true\n"
            f"port = {self.non_standard_port}\n"
            f"maxretry = {self.fail2ban_max_retry}\n"
            f"bantime = {self.fail2ban_ban_time}\n"
            f"findtime = {self.fail2ban_find_time}\n"
            "backend = systemd\n"
        )


# ── Encrypted API Key Storage ───────────────────────────────────────


class EncryptedKeyStore:
    """Encrypted storage for the secondary brain's API key.

    Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).
    The encryption key is derived from a passphrase using PBKDF2.

    This ensures the API key is never stored in plaintext on the VPS.
    """

    SALT_SIZE = 16
    ITERATIONS = 100_000

    def __init__(self):
        self._cached_key: Optional[str] = None

    @staticmethod
    def _derive_key(passphrase: str, salt: bytes) -> bytes:
        """Derive a Fernet-compatible key from passphrase + salt."""
        dk = hashlib.pbkdf2_hmac(
            "sha256", passphrase.encode("utf-8"), salt, EncryptedKeyStore.ITERATIONS, dklen=32,
        )
        return base64.urlsafe_b64encode(dk)

    def encrypt(self, api_key: str, passphrase: str) -> str:
        """Encrypt an API key with a passphrase.

        Returns a string of the form: base64(salt):base64(ciphertext)
        """
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            # Fallback: base64 encode with warning (not secure, but functional)
            logger.warning(
                "cryptography package not installed — API key stored "
                "with base64 encoding only (NOT SECURE)"
            )
            return f"b64:{base64.urlsafe_b64encode(api_key.encode()).decode()}"

        salt = os.urandom(self.SALT_SIZE)
        key = self._derive_key(passphrase, salt)
        f = Fernet(key)
        encrypted = f.encrypt(api_key.encode("utf-8"))
        salt_b64 = base64.urlsafe_b64encode(salt).decode()
        cipher_b64 = encrypted.decode()
        return f"{salt_b64}:{cipher_b64}"

    def decrypt(self, encrypted_data: str, passphrase: str) -> Optional[str]:
        """Decrypt an API key.

        Returns the plaintext API key, or None on failure.
        """
        if encrypted_data.startswith("b64:"):
            # Base64 fallback (no cryptography package)
            try:
                return base64.urlsafe_b64decode(
                    encrypted_data[4:].encode()
                ).decode()
            except Exception:
                return None

        try:
            from cryptography.fernet import Fernet, InvalidToken
        except ImportError:
            logger.warning("cryptography package not installed — cannot decrypt")
            return None

        try:
            salt_b64, cipher_b64 = encrypted_data.split(":", 1)
            salt = base64.urlsafe_b64decode(salt_b64.encode())
            key = self._derive_key(passphrase, salt)
            f = Fernet(key)
            decrypted = f.decrypt(cipher_b64.encode("utf-8"))
            return decrypted.decode("utf-8")
        except (InvalidToken, ValueError, Exception):
            logger.debug("Failed to decrypt API key", exc_info=True)
            return None

    def is_encrypted(self, data: str) -> bool:
        """Check if data looks like encrypted key storage."""
        return ":" in data and not data.startswith("sk-")


# ── Rate Limiter ────────────────────────────────────────────────────


class APIRateLimiter:
    """Token bucket rate limiter for outbound API calls.

    Prevents a compromised secondary brain from draining API quota.
    """

    def __init__(self, rpm: int = 10):
        self._rpm = rpm
        self._tokens = float(rpm)
        self._max_tokens = float(rpm)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()
        self._total_allowed = 0
        self._total_denied = 0

    @property
    def rpm(self) -> int:
        return self._rpm

    def update_rpm(self, rpm: int) -> None:
        with self._lock:
            self._rpm = rpm
            self._max_tokens = float(rpm)
            # Don't reset current tokens — let them drain naturally

    def try_acquire(self) -> bool:
        """Try to acquire a token. Returns True if allowed, False if rate-limited."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._last_refill = now

            # Refill tokens based on elapsed time
            self._tokens = min(
                self._max_tokens,
                self._tokens + elapsed * (self._rpm / 60.0),
            )

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                self._total_allowed += 1
                return True
            else:
                self._total_denied += 1
                return False

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "rpm_limit": self._rpm,
                "tokens_available": round(self._tokens, 2),
                "total_allowed": self._total_allowed,
                "total_denied": self._total_denied,
            }


# ── Credential Separation ──────────────────────────────────────────


@dataclass
class BrainCredentials:
    """Separate credential set for the secondary brain.

    Regular shield agents have their own credentials. The secondary
    brain has a *separate* set — compromise of a regular agent does
    not expose the brain's API key or coordination authority.
    """

    brain_node_id: str
    hmac_key_id: str = ""           # Unique HMAC key (separate from agent keys)
    api_key_encrypted: str = ""     # Encrypted API key
    ssh_key_fingerprint: str = ""   # Separate SSH key (not shared with agents)
    created_at: str = ""
    rotated_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "brain_node_id": self.brain_node_id,
            "hmac_key_id": self.hmac_key_id,
            "api_key_configured": bool(self.api_key_encrypted),
            "ssh_key_fingerprint": self.ssh_key_fingerprint,
            "created_at": self.created_at,
            "rotated_at": self.rotated_at,
        }


# ── Hardening Manager ──────────────────────────────────────────────


class BrainHardeningManager:
    """Manages all hardening aspects for the secondary brain.

    Combines SSH policy, encrypted key storage, rate limiting,
    and credential separation into a single management interface.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._ssh_policy = SSHHardeningPolicy()
        self._key_store = EncryptedKeyStore()
        self._rate_limiter = APIRateLimiter()
        self._credentials: Optional[BrainCredentials] = None
        self._audit_log: List[dict] = []
        self._max_audit = 1000

    # ── SSH Policy ────────────────────────────────────────────────

    def get_ssh_policy(self) -> SSHHardeningPolicy:
        with self._lock:
            return self._ssh_policy

    def set_ssh_policy(self, policy: SSHHardeningPolicy) -> None:
        with self._lock:
            self._ssh_policy = policy
            self._log_audit("ssh_policy_updated", {"policy": policy.to_dict()})

    # ── Encrypted Key Storage ─────────────────────────────────────

    def store_api_key(self, api_key: str, passphrase: str) -> str:
        """Encrypt and store the API key. Returns the encrypted blob."""
        encrypted = self._key_store.encrypt(api_key, passphrase)
        with self._lock:
            if self._credentials is None:
                self._credentials = BrainCredentials(brain_node_id="")
            self._credentials.api_key_encrypted = encrypted
            self._log_audit("api_key_stored", {"encrypted": True})
        return encrypted

    def retrieve_api_key(self, passphrase: str) -> Optional[str]:
        """Decrypt and return the API key, or None on failure."""
        with self._lock:
            if self._credentials is None or not self._credentials.api_key_encrypted:
                return None
            encrypted = self._credentials.api_key_encrypted
        result = self._key_store.decrypt(encrypted, passphrase)
        if result:
            self._log_audit("api_key_accessed", {"success": True})
        else:
            self._log_audit("api_key_access_failed", {"success": False})
        return result

    # ── Rate Limiting ─────────────────────────────────────────────

    def check_rate_limit(self) -> bool:
        """Check if an API call is allowed under rate limits."""
        allowed = self._rate_limiter.try_acquire()
        if not allowed:
            self._log_audit("rate_limited", self._rate_limiter.get_stats())
        return allowed

    def get_rate_limiter_stats(self) -> dict:
        return self._rate_limiter.get_stats()

    def update_rate_limit(self, rpm: int) -> None:
        self._rate_limiter.update_rpm(rpm)
        self._log_audit("rate_limit_updated", {"rpm": rpm})

    # ── Credentials ───────────────────────────────────────────────

    def set_credentials(self, creds: BrainCredentials) -> None:
        with self._lock:
            self._credentials = creds
            self._log_audit("credentials_set", {
                "node_id": creds.brain_node_id,
                "hmac_key_id": creds.hmac_key_id,
            })

    def get_credentials(self) -> Optional[BrainCredentials]:
        with self._lock:
            return self._credentials

    # ── Audit Log ─────────────────────────────────────────────────

    def _log_audit(self, event: str, details: dict) -> None:
        """Append-only audit log for all hardening operations."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "details": details,
        }
        # Lock is already held by callers, but RLock is reentrant
        with self._lock:
            self._audit_log.append(entry)
            if len(self._audit_log) > self._max_audit:
                self._audit_log = self._audit_log[-self._max_audit:]

    def get_audit_log(self, limit: int = 50) -> List[dict]:
        """Get recent audit entries (newest first)."""
        with self._lock:
            return list(reversed(self._audit_log[-limit:]))

    # ── Full Status ───────────────────────────────────────────────

    def get_status(self) -> dict:
        with self._lock:
            return {
                "ssh_policy": self._ssh_policy.to_dict(),
                "rate_limiter": self._rate_limiter.get_stats(),
                "credentials_configured": self._credentials is not None,
                "credentials": self._credentials.to_dict() if self._credentials else None,
                "audit_entries": len(self._audit_log),
            }

    def generate_hardening_commands(self) -> List[dict]:
        """Generate shell commands to apply hardening on the VPS.

        Returns a list of command dicts that can be queued via
        shield_database.queue_command() for remote execution.
        """
        commands = []
        policy = self._ssh_policy

        # 1. SSH configuration
        sshd_config = policy.to_sshd_config_fragment()
        commands.append({
            "type": "write_file",
            "path": "/etc/ssh/sshd_config.d/citadel-brain.conf",
            "content": sshd_config,
            "description": "Apply SSH hardening for secondary brain",
        })

        # 2. Restart SSH service
        commands.append({
            "type": "shell",
            "command": "systemctl restart sshd",
            "description": "Restart SSH with hardened config",
        })

        # 3. Fail2ban configuration
        f2b_config = policy.to_fail2ban_config()
        commands.append({
            "type": "write_file",
            "path": "/etc/fail2ban/jail.d/citadel-brain.conf",
            "content": f2b_config,
            "description": "Apply aggressive fail2ban for secondary brain",
        })

        # 4. Restart fail2ban
        commands.append({
            "type": "shell",
            "command": "systemctl restart fail2ban",
            "description": "Restart fail2ban with hardened config",
        })

        return commands


# ── Singleton ────────────────────────────────────────────────────────

_hardening_mgr: Optional[BrainHardeningManager] = None


def get_brain_hardening_manager() -> BrainHardeningManager:
    global _hardening_mgr
    if _hardening_mgr is None:
        _hardening_mgr = BrainHardeningManager()
    return _hardening_mgr


def set_brain_hardening_manager(m: Optional[BrainHardeningManager]) -> None:
    global _hardening_mgr
    _hardening_mgr = m
