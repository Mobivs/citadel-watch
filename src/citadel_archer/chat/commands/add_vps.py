# PRD: SecureChat — "add vps" Command Handler
# Reference: Plan Milestone 2
#
# Handles the "add vps <ip>" command typed in the chat sidebar.
# Orchestrates: key gen → vault store → show install command →
# wait for "done" → verify SSH → register asset.

import asyncio
import ipaddress
import logging
import re
from typing import Optional, TYPE_CHECKING

from ..message import ChatMessage, MessageType, PARTICIPANT_CITADEL, PARTICIPANT_USER

if TYPE_CHECKING:
    from ..chat_manager import ChatManager

logger = logging.getLogger(__name__)

# Track pending verification per IP
_pending_verifications: dict = {}


def _parse_ip(text: str) -> Optional[str]:
    """Extract an IP address from 'add vps <ip>' text."""
    match = re.search(r"add\s+vps\s+([\d\.]+)", text, re.IGNORECASE)
    if not match:
        return None
    ip_str = match.group(1)
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except ValueError:
        return None


def _parse_port(text: str) -> int:
    """Extract optional port from 'add vps <ip> port <N>'."""
    match = re.search(r"port\s+(\d+)", text, re.IGNORECASE)
    if match:
        return int(match.group(1))
    return 22


def _parse_username(text: str) -> str:
    """Extract optional username from 'add vps <ip> user <name>'."""
    match = re.search(r"user\s+(\S+)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return "root"


async def handle_add_vps(text: str, manager: "ChatManager"):
    """Handle the 'add vps <ip>' chat command."""
    ip = _parse_ip(text)
    if not ip:
        await manager.send_system(
            "Usage: add vps <ip_address> [port <N>] [user <name>]",
            MessageType.RESPONSE,
        )
        return

    port = _parse_port(text)
    username = _parse_username(text)

    # Check for duplicate
    try:
        from ...api.asset_routes import get_inventory
        inv = get_inventory()
        existing = inv.find_by_ip(ip)
        if existing:
            await manager.send_system(
                f"Asset already registered for {ip}: {existing.name or existing.asset_id}",
                MessageType.RESPONSE,
            )
            return
    except Exception:
        pass

    # Step 1: Generate keypair
    await manager.send_system(
        f"Generating ed25519 keypair for {ip}...",
        MessageType.SETUP,
    )

    try:
        from ...remote.ssh_keygen import generate_ed25519_keypair, build_install_command
        comment = f"citadel-archer-{ip}"
        private_key, public_key = generate_ed25519_keypair(comment)
    except Exception as exc:
        await manager.send_system(
            f"Key generation failed: {exc}",
            MessageType.EVENT,
        )
        return

    # Step 2: Store in Vault
    await manager.send_system(
        "Storing private key in Vault...",
        MessageType.SETUP,
    )

    credential_id = None
    try:
        from ...api.vault_routes import vault_manager
        success, result = vault_manager.add_ssh_credential(
            title=f"VPS {ip}",
            auth_type="key",
            private_key=private_key,
            default_username=username,
            default_port=port,
        )
        if success:
            credential_id = result
        else:
            await manager.send_system(
                f"Vault storage failed: {result}. Is the Vault unlocked?",
                MessageType.EVENT,
            )
            return
    except Exception as exc:
        await manager.send_system(
            f"Vault error: {exc}. Make sure the Vault is unlocked first.",
            MessageType.EVENT,
        )
        return

    # Step 3: Show the install command
    install_cmd = build_install_command(public_key)

    msg = ChatMessage(
        from_id=PARTICIPANT_CITADEL,
        to_id=PARTICIPANT_USER,
        msg_type=MessageType.SETUP,
        payload={
            "text": (
                "Public key ready. Run this command on your VPS "
                f"({ip}) to authorize Citadel:"
            ),
            "copyable": install_cmd,
        },
    )
    await manager.send(msg)

    # Store pending verification state
    _pending_verifications[ip] = {
        "ip": ip,
        "port": port,
        "username": username,
        "credential_id": credential_id,
    }

    await manager.send_system(
        "After running the command, type 'done' or 'verify' to test the connection.",
        MessageType.SETUP,
    )


async def handle_done(text: str, manager: "ChatManager"):
    """Handle 'done' or 'verify' — complete pending VPS verification."""
    if not _pending_verifications:
        await manager.send_system(
            "No pending VPS verification. Use 'add vps <ip>' first.",
            MessageType.RESPONSE,
        )
        return

    # Process the most recent pending verification (last inserted)
    ip = list(_pending_verifications.keys())[-1]
    pending = _pending_verifications[ip]

    await manager.send_system(
        f"Connecting to {ip}:{pending['port']} as {pending['username']}...",
        MessageType.SETUP,
    )

    # Register the asset first so we can test connection
    try:
        from ...api.asset_routes import get_inventory
        from ...intel.assets import Asset, AssetPlatform, AssetType, AssetStatus

        inv = get_inventory()
        asset = Asset(
            name=f"VPS {ip}",
            hostname="",
            ip_address=ip,
            platform=AssetPlatform.LINUX,
            asset_type=AssetType.VPS,
            status=AssetStatus.UNKNOWN,
            ssh_port=pending["port"],
            ssh_username=pending["username"],
            ssh_credential_id=pending["credential_id"],
        )
        asset_id = inv.register(asset)

        # Link the credential
        inv.link_ssh_credential(asset_id, pending["credential_id"])

    except Exception as exc:
        await manager.send_system(
            f"Asset registration failed: {exc}",
            MessageType.EVENT,
        )
        return

    # Test the connection
    try:
        from ...api.asset_routes import get_ssh_manager
        ssh = get_ssh_manager()
        result = await ssh.test_connection(asset_id)

        if result.success:
            # Update asset with discovered info
            updates = {}
            if result.hostname:
                updates["hostname"] = result.hostname
                updates["name"] = f"{result.hostname} ({ip})"
            if result.remote_os:
                updates["os_version"] = result.remote_os
            updates["status"] = "online"

            inv.update(asset_id, **updates)

            # Remove from pending
            del _pending_verifications[ip]

            await manager.send_system(
                f"Connected! {result.remote_os or 'Unknown OS'}, "
                f"hostname: {result.hostname or 'unknown'}, "
                f"uptime: {result.uptime or 'unknown'}",
                MessageType.SETUP,
            )
            await manager.send_system(
                f"Asset registered as {asset_id}. "
                f"Ready to deploy agent (type 'deploy agent {asset_id}').",
                MessageType.SETUP,
            )
        else:
            await manager.send_system(
                f"Connection failed: {result.error}. "
                "Check that the key was installed correctly and try 'verify' again.",
                MessageType.EVENT,
            )

    except Exception as exc:
        await manager.send_system(
            f"Connection test failed: {exc}",
            MessageType.EVENT,
        )


def register_commands(manager: "ChatManager"):
    """Register the add_vps commands with the ChatManager."""
    manager.register_command("add vps", handle_add_vps)
    manager.register_command("done", handle_done)
    manager.register_command("verify", handle_done)
