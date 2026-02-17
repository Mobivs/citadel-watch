# PRD: SecureChat — "deploy agent" Command Handler
# Reference: Plan Milestone 3
#
# Handles "deploy agent <asset_id>" typed in chat sidebar.
# Deploys the Citadel Shield agent to a registered VPS.

import logging
import re
from typing import TYPE_CHECKING

from ..message import MessageType

if TYPE_CHECKING:
    from ..chat_manager import ChatManager

logger = logging.getLogger(__name__)


def _parse_asset_id(text: str) -> str:
    """Extract asset_id from 'deploy agent <id>'."""
    match = re.search(r"deploy\s+agent\s+(\S+)", text, re.IGNORECASE)
    return match.group(1) if match else ""


async def handle_deploy_agent(text: str, manager: "ChatManager"):
    """Handle the 'deploy agent <asset_id>' chat command."""
    asset_id = _parse_asset_id(text)
    if not asset_id:
        await manager.send_system(
            "Usage: deploy agent <asset_id>",
            MessageType.RESPONSE,
        )
        return

    # Verify asset exists
    try:
        from ...api.asset_routes import get_inventory, get_ssh_manager
        inv = get_inventory()
        asset = inv.get(asset_id)
        if not asset:
            await manager.send_system(
                f"Asset not found: {asset_id}",
                MessageType.RESPONSE,
            )
            return

        if not asset.ssh_credential_id:
            await manager.send_system(
                f"Asset {asset_id} has no SSH credential linked. "
                "Use 'add vps <ip>' to set one up.",
                MessageType.RESPONSE,
            )
            return
    except Exception as exc:
        await manager.send_system(
            f"Error checking asset: {exc}",
            MessageType.EVENT,
        )
        return

    # Deploy
    try:
        from ...remote.agent_deployer import AgentDeployer

        ssh = get_ssh_manager()
        deployer = AgentDeployer(ssh, chat_manager=manager)
        result = await deployer.deploy(asset_id)

        if result.get("success"):
            await manager.send_system(
                f"Agent deployment complete for {asset_id}. "
                "Citadel will begin polling for events.",
                MessageType.SETUP,
            )
        else:
            await manager.send_system(
                f"Deployment failed: {result.get('error', 'unknown')}",
                MessageType.EVENT,
            )

    except Exception as exc:
        await manager.send_system(
            f"Deployment error: {exc}",
            MessageType.EVENT,
        )


def register_commands(manager: "ChatManager"):
    """Register the deploy commands with the ChatManager."""
    manager.register_command("deploy agent", handle_deploy_agent)
