# PRD: Remote Shield — Agent Deployment
# Reference: Plan Milestone 3
#
# Orchestrates deploying the Citadel Shield agent to a VPS over SSH:
#   1. SCP shield.py + install.sh to /opt/citadel-shield/
#   2. Execute install.sh
#   3. Verify via `shield.py status`
#   4. Register agent in RemoteShieldDatabase

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..chat.chat_manager import ChatManager

from .ssh_manager import SSHConnectionManager

logger = logging.getLogger(__name__)

# Path to the agent source files (in our repo)
_AGENT_DIR = Path(__file__).parent.parent / "agent"
_SHIELD_PY = _AGENT_DIR / "shield.py"
_INSTALL_SH = _AGENT_DIR / "install.sh"

REMOTE_DIR = "/opt/citadel-shield"


class AgentDeployer:
    """Deploys the Citadel Shield agent to a VPS over SSH.

    Args:
        ssh_manager: The SSH connection manager for remote operations.
        chat_manager: Optional ChatManager for posting progress to SecureChat.
    """

    def __init__(
        self,
        ssh_manager: SSHConnectionManager,
        chat_manager: Optional["ChatManager"] = None,
    ):
        self._ssh = ssh_manager
        self._chat = chat_manager

    async def _chat_msg(self, text: str):
        """Post a progress message to SecureChat (if available)."""
        if self._chat:
            from ..chat.message import MessageType
            await self._chat.send_system(text, MessageType.SETUP)

    async def deploy(self, asset_id: str) -> dict:
        """Deploy the agent to the given asset.

        Returns a dict with deployment result:
            {"success": True/False, "agent_status": {...}, "error": "..."}
        """
        await self._chat_msg(f"Deploying Citadel Shield agent to {asset_id}...")

        # 1. Create remote directory
        try:
            result = await self._ssh.execute(
                asset_id, f"mkdir -p {REMOTE_DIR}"
            )
            if not result.success:
                error = f"Failed to create {REMOTE_DIR}: {result.error}"
                await self._chat_msg(error)
                return {"success": False, "error": error}
        except Exception as exc:
            error = f"SSH execution failed: {exc}"
            await self._chat_msg(error)
            return {"success": False, "error": error}

        # 2. Upload shield.py
        await self._chat_msg("Uploading shield.py...")
        try:
            await self._ssh.upload_file(
                asset_id,
                str(_SHIELD_PY),
                f"{REMOTE_DIR}/shield.py",
            )
        except Exception as exc:
            error = f"Upload shield.py failed: {exc}"
            await self._chat_msg(error)
            return {"success": False, "error": error}

        # 3. Upload install.sh
        await self._chat_msg("Uploading install.sh...")
        try:
            await self._ssh.upload_file(
                asset_id,
                str(_INSTALL_SH),
                f"{REMOTE_DIR}/install.sh",
            )
        except Exception as exc:
            error = f"Upload install.sh failed: {exc}"
            await self._chat_msg(error)
            return {"success": False, "error": error}

        # 4. Run installer
        await self._chat_msg("Running installer (systemd setup)...")
        try:
            result = await self._ssh.execute(
                asset_id,
                f"bash {REMOTE_DIR}/install.sh",
                timeout=30,
            )
            if not result.success:
                error = f"Install script failed: {result.error}"
                await self._chat_msg(error)
                return {"success": False, "error": error}
        except Exception as exc:
            error = f"Install execution failed: {exc}"
            await self._chat_msg(error)
            return {"success": False, "error": error}

        # 5. Verify agent is running
        await self._chat_msg("Verifying agent status...")
        try:
            result = await self._ssh.execute(
                asset_id,
                f"python3 {REMOTE_DIR}/shield.py status",
                timeout=10,
            )
            if result.success and result.stdout:
                status = json.loads(result.stdout.strip())
                if status.get("running"):
                    await self._chat_msg(
                        f"Agent deployed and running! v{status.get('version', '?')}, "
                        f"hostname: {status.get('hostname', 'unknown')}"
                    )

                    # 6. Register agent in RemoteShieldDatabase
                    await self._register_agent(asset_id, status)

                    # 7. Push hardening config (if pre-configured)
                    await self._push_hardening_config(asset_id)

                    return {"success": True, "agent_status": status}
                else:
                    await self._chat_msg(
                        "Agent installed but not running. "
                        "Check: systemctl status citadel-shield"
                    )
                    return {
                        "success": False,
                        "error": "Agent not running after install",
                        "agent_status": status,
                    }
        except Exception as exc:
            error = f"Status check failed: {exc}"
            await self._chat_msg(error)
            return {"success": False, "error": error}

        return {"success": False, "error": "Unknown failure"}

    async def _register_agent(self, asset_id: str, status: dict):
        """Register the deployed agent in RemoteShieldDatabase."""
        try:
            from ..remote.shield_database import RemoteShieldDatabase
            import secrets

            db = RemoteShieldDatabase()
            agent_id = f"shield_{asset_id}"

            # Get asset IP for registration
            from ..api.asset_routes import get_inventory
            inv = get_inventory()
            asset = inv.get(asset_id)
            ip_address = asset.ip_address if asset else ""

            # Generate a token for the agent (stored as hash in DB)
            api_token = secrets.token_hex(32)

            db.create_agent(
                agent_id=agent_id,
                hostname=status.get("hostname", ""),
                ip_address=ip_address,
                api_token=api_token,
            )

            # Link agent to asset
            inv.link_remote_shield_agent(asset_id, agent_id)

        except Exception as exc:
            logger.warning(f"Failed to register agent in DB: {exc}")

    async def _push_hardening_config(self, asset_id: str):
        """Push pre-configured hardening config.json to the remote VPS."""
        try:
            from .shield_database import RemoteShieldDatabase

            db = RemoteShieldDatabase()
            hardening = db.get_hardening_config(asset_id)
            if not hardening or hardening.get("status") != "pending":
                return

            config_json = json.dumps(hardening["config"], indent=2)
            b64 = base64.b64encode(config_json.encode()).decode()
            await self._ssh.execute(
                asset_id,
                f"echo '{b64}' | base64 -d > {REMOTE_DIR}/config.json",
                timeout=10,
            )
            await self._chat_msg("SSH hardening config pushed to agent.")
        except Exception as exc:
            logger.warning(f"Hardening config push skipped: {exc}")
