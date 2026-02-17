"""
Desktop Firewall Manager — Manages VPS firewall rules from the desktop.

Desktop is source of truth for firewall rules. Rules are stored in
RemoteShieldDatabase and pushed to the VPS config.json for the shield
agent to apply via iptables.

Follows the same pattern as ssh_hardening.py (desktop orchestrates,
VPS agent executes).
"""

import base64
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .ssh_manager import SSHConnectionManager
    from .shield_database import RemoteShieldDatabase

logger = logging.getLogger(__name__)

SHIELD_CONFIG_PATH = "/opt/citadel-shield/config.json"
GEO_CIDRS_REMOTE_PATH = "/opt/citadel-shield/geo_cidrs.dat"


class DesktopFirewallManager:
    """Desktop-side firewall rule management for remote VPS assets.

    Args:
        ssh_manager: SSH connection manager for remote execution.
        shield_db: RemoteShieldDatabase for persistent rule storage.
    """

    def __init__(
        self,
        ssh_manager: "SSHConnectionManager",
        shield_db: "RemoteShieldDatabase",
    ):
        self._ssh = ssh_manager
        self._db = shield_db

    def add_rule(self, asset_id: str, rule: dict) -> int:
        """Add a firewall rule for an asset. Returns the rule ID."""
        return self._db.save_firewall_rule(asset_id, rule)

    def remove_rule(self, rule_id: int) -> bool:
        """Remove a firewall rule by ID."""
        return self._db.delete_firewall_rule(rule_id)

    def get_rules(self, asset_id: str, enabled_only: bool = True) -> List[dict]:
        """Get all firewall rules for an asset."""
        return self._db.get_firewall_rules(asset_id, enabled_only=enabled_only)

    def update_rule(self, rule_id: int, updates: dict) -> bool:
        """Update a firewall rule."""
        return self._db.update_firewall_rule(rule_id, updates)

    def add_auto_rule(
        self,
        asset_id: str,
        source: str,
        reason: str,
        duration_seconds: int = 3600,
    ) -> int:
        """Add an auto-generated rule with expiry (e.g., from threshold engine).

        Returns the rule ID.
        """
        expires_at = (
            datetime.utcnow() + timedelta(seconds=duration_seconds)
        ).isoformat()
        rule = {
            "action": "deny",
            "source": source,
            "protocol": "any",
            "port": "",
            "direction": "in",
            "priority": 50,  # auto-rules get higher priority
            "enabled": True,
            "auto_generated": True,
            "expires_at": expires_at,
            "comment": reason,
        }
        return self._db.save_firewall_rule(asset_id, rule)

    def compile_config(self, asset_id: str) -> List[dict]:
        """Compile enabled rules into config.json firewall_rules format.

        Returns the list of rule dicts suitable for the agent's config.json.
        """
        db_rules = self._db.get_firewall_rules(asset_id, enabled_only=True)
        compiled = []
        for r in db_rules:
            entry = {
                "action": r["action"],
                "source": r["source"],
                "protocol": r["protocol"],
                "port": r["port"],
                "priority": r["priority"],
                "enabled": True,
            }
            if r["action"] == "rate_limit":
                # Rate is stored in comment field for rate_limit rules
                rate = r.get("comment", "").strip()
                if not rate or "/" not in rate:
                    rate = "100/minute"  # safe default
                entry["rate"] = rate
            compiled.append(entry)
        return compiled

    async def push_rules(self, asset_id: str) -> dict:
        """Compile rules and push to VPS config.json.

        Merges firewall_rules into the existing config.json on the VPS
        (preserving other keys like fail_threshold, knock_sequence, etc.).

        Returns:
            {"success": bool, "pushed_count": int, "error": str}
        """
        # Compile rules
        rules = self.compile_config(asset_id)

        # Read existing remote config
        try:
            result = await self._ssh.execute(
                asset_id, f"cat {SHIELD_CONFIG_PATH}", timeout=10,
            )
            if result.success and result.stdout:
                remote_config = json.loads(result.stdout.strip())
            else:
                remote_config = {}
        except Exception:
            remote_config = {}

        # Merge firewall_rules into config
        remote_config["firewall_rules"] = rules

        # Push back
        config_json = json.dumps(remote_config, indent=2)
        b64 = base64.b64encode(config_json.encode()).decode()
        try:
            result = await self._ssh.execute(
                asset_id,
                f"echo '{b64}' | base64 -d > {SHIELD_CONFIG_PATH}",
                timeout=10,
            )
            if not result.success:
                return {
                    "success": False,
                    "pushed_count": 0,
                    "error": f"Config push failed: {result.error}",
                }
        except Exception as exc:
            return {
                "success": False,
                "pushed_count": 0,
                "error": str(exc),
            }

        # Clean up expired rules in DB
        self._db.delete_expired_firewall_rules()

        return {"success": True, "pushed_count": len(rules), "error": ""}

    async def push_geo_data(self, asset_id: str, geo_data_path: str) -> dict:
        """Upload geo_cidrs.dat to the VPS.

        Args:
            asset_id: Target asset.
            geo_data_path: Local path to geo_cidrs.dat file.

        Returns:
            {"success": bool, "error": str}
        """
        try:
            await self._ssh.upload_file(
                asset_id, geo_data_path, GEO_CIDRS_REMOTE_PATH,
            )
            return {"success": True, "error": ""}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
