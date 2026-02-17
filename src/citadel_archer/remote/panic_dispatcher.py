"""Remote Panic Dispatcher — queue panic commands to Remote Shield agents.

When the Panic Room targets an asset backed by a Remote Shield agent, this
dispatcher queues isolation/termination/rollback commands via the existing
command queue instead of executing over SSH.

v0.3.31: Initial implementation — panic_isolate, panic_terminate, panic_rollback.
"""

import logging
import uuid
from typing import Dict, List, Optional

from .shield_database import RemoteShieldDatabase

logger = logging.getLogger(__name__)

# Maps playbook action types to agent command types
_ACTION_TO_COMMAND = {
    "network": "panic_isolate",
    "firewall": "panic_isolate",
    "credentials": "panic_isolate",  # agent locks down network as part of cred rotation
    "processes": "panic_terminate",
    "system": "panic_terminate",
    "forensics": "panic_isolate",    # snapshot = isolate first
    "backup": "panic_isolate",       # secure backup = isolate first
}


class RemotePanicDispatcher:
    """Dispatches panic commands to Remote Shield agents via the command queue."""

    def __init__(self, shield_db: RemoteShieldDatabase):
        self._db = shield_db
        self._agent_cache: Dict[str, Optional[str]] = {}

    def dispatch(
        self,
        agent_id: str,
        action_type: str,
        payload: dict,
        session_id: str,
    ) -> dict:
        """Queue a panic command to a specific agent.

        Args:
            agent_id: Target Remote Shield agent.
            action_type: Playbook action type (e.g., "network", "processes").
            payload: Action parameters from the playbook.
            session_id: Panic session ID for tracking.

        Returns:
            {"command_id": str, "agent_id": str, "command_type": str, "status": "queued"}
        """
        command_type = _ACTION_TO_COMMAND.get(action_type, "panic_isolate")
        command_id = str(uuid.uuid4())

        cmd_payload = {
            "session_id": session_id,
            "action_type": action_type,
            **{k: v for k, v in payload.items() if k != "target_asset"},
        }

        self._db.queue_command(
            command_id=command_id,
            agent_id=agent_id,
            command_type=command_type,
            payload=cmd_payload,
        )

        logger.info(
            "Queued %s for agent %s (session %s)", command_type, agent_id, session_id,
        )

        return {
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": command_type,
            "status": "queued",
        }

    def dispatch_rollback(self, agent_id: str, session_id: str) -> dict:
        """Queue a panic_rollback command to restore pre-panic state.

        Returns:
            {"command_id": str, "agent_id": str, "command_type": "panic_rollback", "status": "queued"}
        """
        command_id = str(uuid.uuid4())

        self._db.queue_command(
            command_id=command_id,
            agent_id=agent_id,
            command_type="panic_rollback",
            payload={"session_id": session_id},
        )

        logger.info("Queued panic_rollback for agent %s (session %s)", agent_id, session_id)

        return {
            "command_id": command_id,
            "agent_id": agent_id,
            "command_type": "panic_rollback",
            "status": "queued",
        }

    def get_remote_status(self, session_id: str) -> List[dict]:
        """Get status of all panic commands for a session.

        Queries agent_commands table for commands whose payload contains
        the given session_id.

        Returns:
            List of {"agent_id", "command_id", "command_type", "status", "result"}
        """
        panic_types = {"panic_isolate", "panic_terminate", "panic_rollback"}
        results = []
        commands = self._db.list_commands(status=None, limit=1000)
        for cmd in commands:
            if cmd["command_type"] not in panic_types:
                continue
            payload = cmd.get("payload", {})
            if isinstance(payload, str):
                continue
            if payload.get("session_id") == session_id:
                results.append({
                    "agent_id": cmd["agent_id"],
                    "command_id": cmd["command_id"],
                    "command_type": cmd["command_type"],
                    "status": cmd["status"],
                    "result": cmd.get("result", ""),
                })

        return results

    def resolve_agent_id(self, asset_id: str) -> Optional[str]:
        """Look up the Remote Shield agent_id for an asset.

        Returns None if the asset has no linked agent (i.e., it's local or SSH-only).
        """
        if asset_id in self._agent_cache:
            return self._agent_cache[asset_id]

        try:
            agents = self._db.list_agents()
            for agent in agents:
                aid = agent.get("asset_id", "")
                if aid:
                    self._agent_cache[aid] = agent["id"]
        except Exception:
            logger.warning("Failed to refresh agent cache", exc_info=True)
            return None

        result = self._agent_cache.get(asset_id, "")
        if not result:
            self._agent_cache[asset_id] = ""  # cache miss sentinel
            return None
        return result

    def clear_cache(self) -> None:
        """Clear the agent resolution cache."""
        self._agent_cache.clear()
