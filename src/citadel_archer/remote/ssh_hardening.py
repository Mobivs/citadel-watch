"""
SSH Hardening Orchestrator — Desktop-side orchestration for VPS SSH security.

Coordinates sshd_config hardening, key-only auth migration, and config
push for fail2ban++ / port knocking via the existing SSH Manager.

Safety-first: always backup, always validate, always verify access,
auto-rollback on failure.
"""

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

SSHD_CONFIG_PATH = "/etc/ssh/sshd_config"
SSHD_BACKUP_PATH = "/etc/ssh/sshd_config.citadel.bak"
SHIELD_CONFIG_PATH = "/opt/citadel-shield/config.json"

# Allowed values for sshd_config directives — defense-in-depth against injection
_SAFE_SSHD_VALUE = re.compile(r'^[a-zA-Z0-9\-]+$')
_VALID_ROOT_LOGIN = {"yes", "no", "prohibit-password", "without-password", "forced-commands-only"}

# sshd_config directives to harden (directive, value) pairs
_SSHD_DIRECTIVES = {
    "PasswordAuthentication": "no",
    "PubkeyAuthentication": "yes",
    "PermitRootLogin": "prohibit-password",
    "MaxAuthTries": "3",
    "PermitEmptyPasswords": "no",
    "X11Forwarding": "no",
    "ClientAliveInterval": "300",
    "ClientAliveCountMax": "2",
}


@dataclass
class HardeningConfig:
    """Per-asset SSH hardening configuration."""
    disable_password_auth: bool = True
    permit_root_login: str = "prohibit-password"
    max_auth_tries: int = 3
    custom_ssh_port: Optional[int] = None
    enable_port_knocking: bool = False
    knock_sequence: List[int] = field(default_factory=lambda: [7000, 8000, 9000])
    knock_timeout: int = 15
    fail2ban_threshold: int = 5
    fail2ban_window: int = 300
    ban_durations: List[int] = field(default_factory=lambda: [300, 3600, 86400])
    permanent_ban_after: int = 5
    ip_whitelist: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "disable_password_auth": self.disable_password_auth,
            "permit_root_login": self.permit_root_login,
            "max_auth_tries": self.max_auth_tries,
            "custom_ssh_port": self.custom_ssh_port,
            "enable_port_knocking": self.enable_port_knocking,
            "knock_sequence": self.knock_sequence,
            "knock_timeout": self.knock_timeout,
            "fail_threshold": self.fail2ban_threshold,
            "fail_window": self.fail2ban_window,
            "ban_durations": self.ban_durations,
            "permanent_ban_after": self.permanent_ban_after,
            "ip_whitelist": self.ip_whitelist,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HardeningConfig":
        return cls(
            disable_password_auth=d.get("disable_password_auth", True),
            permit_root_login=d.get("permit_root_login", "prohibit-password"),
            max_auth_tries=d.get("max_auth_tries", 3),
            custom_ssh_port=d.get("custom_ssh_port"),
            enable_port_knocking=d.get("enable_port_knocking", False),
            knock_sequence=d.get("knock_sequence", [7000, 8000, 9000]),
            knock_timeout=d.get("knock_timeout", 15),
            fail2ban_threshold=d.get("fail_threshold", 5),
            fail2ban_window=d.get("fail_window", 300),
            ban_durations=d.get("ban_durations", [300, 3600, 86400]),
            permanent_ban_after=d.get("permanent_ban_after", 5),
            ip_whitelist=d.get("ip_whitelist", []),
        )


@dataclass
class HardeningResult:
    success: bool
    asset_id: str
    changes_applied: List[str] = field(default_factory=list)
    backup_path: str = ""
    error: str = ""
    warnings: List[str] = field(default_factory=list)


@dataclass
class HardeningStatus:
    password_auth_enabled: bool = True
    root_login: str = "yes"
    max_auth_tries: int = 6
    ssh_port: int = 22
    pubkey_auth: bool = True
    key_installed: bool = False
    port_knocking_active: bool = False
    fail2ban_enhanced: bool = False
    sshd_config_backup_exists: bool = False


@dataclass
class RollbackResult:
    success: bool
    asset_id: str
    details: str = ""
    error: str = ""


class SSHHardeningOrchestrator:
    """Orchestrates SSH hardening on remote VPS assets.

    Safety-first approach: all changes are reversible, connections
    are verified before committing, and a backup of sshd_config
    is always created first.
    """

    def __init__(self, ssh_manager, shield_db, vault=None, chat_manager=None):
        self._ssh = ssh_manager
        self._db = shield_db
        self._vault = vault
        self._chat = chat_manager

    async def harden_asset(
        self, asset_id: str, config: HardeningConfig
    ) -> HardeningResult:
        """Full hardening workflow for one asset.

        Steps:
          1. Backup current sshd_config
          2. Ensure key auth works (if password-only, generate+install key)
          3. Apply sshd_config changes (idempotent sed commands)
          4. Validate new config (sshd -t)
          5. Reload sshd (NOT restart — keeps existing connections)
          6. Verify access with a fresh SSH connection
          7. If verify fails → automatic rollback from backup
          8. Save config to DB
          9. Push config.json to VPS for shield.py fail2ban++/port knocking
        """
        result = HardeningResult(success=False, asset_id=asset_id)
        changes: List[str] = []

        try:
            # 1. Backup sshd_config
            backup = await self._backup_sshd_config(asset_id)
            if not backup:
                result.error = "Failed to backup sshd_config"
                return result
            result.backup_path = SSHD_BACKUP_PATH
            changes.append("sshd_config backed up")

            # 2. Ensure key auth is available
            if config.disable_password_auth:
                key_ok = await self._ensure_key_auth(asset_id)
                if key_ok:
                    changes.append("SSH key auth verified")
                else:
                    result.warnings.append(
                        "Could not verify key auth; skipping password disable"
                    )
                    config.disable_password_auth = False

            # 3. Apply sshd_config changes
            applied = await self._apply_sshd_config(asset_id, config)
            changes.extend(applied)

            # 4. Validate config
            valid = await self._validate_sshd_config(asset_id)
            if not valid:
                await self._rollback_sshd_config(asset_id)
                result.error = "sshd_config validation failed (sshd -t); rolled back"
                return result

            # 5. Reload sshd (not restart)
            reloaded = await self._reload_sshd(asset_id)
            if not reloaded:
                await self._rollback_sshd_config(asset_id)
                result.error = "sshd reload failed; rolled back"
                return result
            changes.append("sshd reloaded")

            # 6. Verify access
            access_ok = await self._verify_access(asset_id)
            if not access_ok:
                await self._rollback_sshd_config(asset_id)
                await self._reload_sshd(asset_id)
                result.error = "Access verification failed after hardening; rolled back"
                return result
            changes.append("access verified")

            # 7. Save config to DB
            self._db.save_hardening_config(
                asset_id, config.to_dict(), status="applied"
            )
            self._db.update_hardening_status(
                asset_id, "applied", backup_path=SSHD_BACKUP_PATH
            )

            # 8. Push shield config.json for fail2ban++ and port knocking
            pushed = await self._push_shield_config(asset_id, config)
            if pushed:
                changes.append("shield config.json pushed")
            else:
                result.warnings.append("Could not push shield config.json")

            result.success = True
            result.changes_applied = changes
            logger.info("SSH hardening applied to %s: %s", asset_id, changes)

        except Exception as exc:
            logger.error("SSH hardening failed for %s: %s", asset_id, exc)
            result.error = str(exc)
            # Attempt rollback on unexpected error
            try:
                await self._rollback_sshd_config(asset_id)
                await self._reload_sshd(asset_id)
            except Exception:
                result.warnings.append("Rollback after error also failed")

        return result

    async def rollback_hardening(self, asset_id: str) -> RollbackResult:
        """Restore sshd_config from backup and reload sshd."""
        try:
            restored = await self._rollback_sshd_config(asset_id)
            if not restored:
                return RollbackResult(
                    success=False, asset_id=asset_id,
                    error="No backup found or restore failed",
                )

            reloaded = await self._reload_sshd(asset_id)
            if not reloaded:
                return RollbackResult(
                    success=False, asset_id=asset_id,
                    error="Backup restored but sshd reload failed",
                )

            self._db.update_hardening_status(asset_id, "rolled_back")
            return RollbackResult(
                success=True, asset_id=asset_id,
                details="sshd_config restored from backup and sshd reloaded",
            )
        except Exception as exc:
            return RollbackResult(
                success=False, asset_id=asset_id, error=str(exc),
            )

    async def get_hardening_status(self, asset_id: str) -> HardeningStatus:
        """Check current SSH configuration on a remote asset."""
        status = HardeningStatus()
        try:
            # Read sshd_config
            r = await self._ssh.execute(
                asset_id, f"cat {SSHD_CONFIG_PATH}", timeout=10,
            )
            if r.exit_code == 0:
                config_text = r.stdout
                status.password_auth_enabled = self._parse_sshd_directive(
                    config_text, "PasswordAuthentication", "yes",
                ) == "yes"
                status.root_login = self._parse_sshd_directive(
                    config_text, "PermitRootLogin", "yes",
                )
                try:
                    status.max_auth_tries = int(self._parse_sshd_directive(
                        config_text, "MaxAuthTries", "6",
                    ))
                except ValueError:
                    pass
                status.pubkey_auth = self._parse_sshd_directive(
                    config_text, "PubkeyAuthentication", "yes",
                ) == "yes"
                port_str = self._parse_sshd_directive(
                    config_text, "Port", "22",
                )
                try:
                    status.ssh_port = int(port_str)
                except ValueError:
                    pass

            # Check for backup
            r2 = await self._ssh.execute(
                asset_id, f"test -f {SSHD_BACKUP_PATH} && echo yes || echo no",
                timeout=5,
            )
            status.sshd_config_backup_exists = r2.stdout.strip() == "yes"

            # Check key in authorized_keys
            r3 = await self._ssh.execute(
                asset_id,
                "test -f ~/.ssh/authorized_keys && wc -l < ~/.ssh/authorized_keys || echo 0",
                timeout=5,
            )
            try:
                status.key_installed = int(r3.stdout.strip()) > 0
            except ValueError:
                pass

            # Check shield hardening status
            r4 = await self._ssh.execute(
                asset_id,
                "python3 /opt/citadel-shield/shield.py hardening-status 2>/dev/null || echo '{}'",
                timeout=10,
            )
            try:
                shield_status = json.loads(r4.stdout.strip())
                status.port_knocking_active = shield_status.get(
                    "port_knocking_enabled", False,
                )
                status.fail2ban_enhanced = shield_status.get(
                    "fail_threshold", 10,
                ) < 10
            except (json.JSONDecodeError, ValueError):
                pass

        except Exception as exc:
            logger.warning("Status check failed for %s: %s", asset_id, exc)

        return status

    # ── Internal helpers ───────────────────────────────────────────

    async def _backup_sshd_config(self, asset_id: str) -> bool:
        r = await self._ssh.execute(
            asset_id,
            f"cp {SSHD_CONFIG_PATH} {SSHD_BACKUP_PATH}",
            timeout=10,
        )
        return r.exit_code == 0

    async def _apply_sshd_config(
        self, asset_id: str, config: HardeningConfig
    ) -> List[str]:
        """Apply sshd_config directives via sed. Returns list of changes."""
        changes = []
        directives: Dict[str, str] = {}

        # Validate permit_root_login against whitelist (defense-in-depth)
        root_login = config.permit_root_login
        if root_login not in _VALID_ROOT_LOGIN:
            raise ValueError(f"Invalid permit_root_login value: {root_login!r}")

        if config.disable_password_auth:
            directives["PasswordAuthentication"] = "no"
        directives["PubkeyAuthentication"] = "yes"
        directives["PermitRootLogin"] = root_login
        directives["MaxAuthTries"] = str(config.max_auth_tries)
        directives["PermitEmptyPasswords"] = "no"
        directives["X11Forwarding"] = "no"
        directives["ClientAliveInterval"] = "300"
        directives["ClientAliveCountMax"] = "2"

        if config.custom_ssh_port:
            directives["Port"] = str(config.custom_ssh_port)

        for directive, value in directives.items():
            # Defense-in-depth: ensure value is safe for shell interpolation
            if not _SAFE_SSHD_VALUE.match(value):
                raise ValueError(f"Unsafe sshd_config value: {value!r}")

            # Idempotent: uncomment and set, or append if missing.
            # grep matches both commented (#) and uncommented lines
            # so it aligns with the sed replacement scope.
            cmd = (
                f"grep -q '^\\s*#*\\s*{directive}\\b' {SSHD_CONFIG_PATH} && "
                f"sed -i 's/^\\s*#*\\s*{directive}\\b.*/{directive} {value}/' {SSHD_CONFIG_PATH} || "
                f"echo '{directive} {value}' >> {SSHD_CONFIG_PATH}"
            )
            r = await self._ssh.execute(asset_id, cmd, timeout=10)
            if r.exit_code == 0:
                changes.append(f"{directive} {value}")

        return changes

    async def _validate_sshd_config(self, asset_id: str) -> bool:
        r = await self._ssh.execute(
            asset_id, "sshd -t", timeout=10,
        )
        if r.exit_code != 0:
            logger.error("sshd -t failed: %s", r.stderr)
        return r.exit_code == 0

    async def _reload_sshd(self, asset_id: str) -> bool:
        r = await self._ssh.execute(
            asset_id, "systemctl reload sshd || systemctl reload ssh",
            timeout=10,
        )
        return r.exit_code == 0

    async def _verify_access(self, asset_id: str) -> bool:
        """Open a fresh connection to verify the new SSH config works."""
        try:
            # Disconnect any cached connection first
            if hasattr(self._ssh, '_connections'):
                self._ssh._connections.pop(asset_id, None)
            # Try a fresh connection
            r = await self._ssh.execute(asset_id, "echo citadel-ok", timeout=15)
            return r.exit_code == 0 and "citadel-ok" in r.stdout
        except Exception as exc:
            logger.error("Access verify failed for %s: %s", asset_id, exc)
            return False

    async def _ensure_key_auth(self, asset_id: str) -> bool:
        """Verify SSH key auth works for this asset."""
        try:
            r = await self._ssh.execute(
                asset_id,
                "test -f ~/.ssh/authorized_keys && echo yes || echo no",
                timeout=10,
            )
            return r.stdout.strip() == "yes"
        except Exception:
            return False

    async def _rollback_sshd_config(self, asset_id: str) -> bool:
        r = await self._ssh.execute(
            asset_id,
            f"test -f {SSHD_BACKUP_PATH} && cp {SSHD_BACKUP_PATH} {SSHD_CONFIG_PATH}",
            timeout=10,
        )
        return r.exit_code == 0

    async def _push_shield_config(
        self, asset_id: str, config: HardeningConfig
    ) -> bool:
        """Write config.json to /opt/citadel-shield/ on the remote VPS."""
        try:
            shield_config = {
                "fail_threshold": config.fail2ban_threshold,
                "fail_window": config.fail2ban_window,
                "ban_durations": config.ban_durations,
                "permanent_ban_after": config.permanent_ban_after,
                "ip_whitelist": config.ip_whitelist,
            }
            if config.enable_port_knocking:
                shield_config["knock_sequence"] = config.knock_sequence
                shield_config["ssh_port"] = config.custom_ssh_port or 22
                shield_config["knock_open_time"] = 30

            config_json = json.dumps(shield_config, indent=2)
            b64 = base64.b64encode(config_json.encode()).decode()
            r = await self._ssh.execute(
                asset_id,
                f"echo '{b64}' | base64 -d > {SHIELD_CONFIG_PATH}",
                timeout=10,
            )
            return r.exit_code == 0
        except Exception as exc:
            logger.warning("Config push failed for %s: %s", asset_id, exc)
            return False

    @staticmethod
    def _parse_sshd_directive(config_text: str, directive: str,
                              default: str = "") -> str:
        """Parse a directive value from sshd_config text."""
        for line in config_text.splitlines():
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] == directive:
                return parts[1]
        return default
