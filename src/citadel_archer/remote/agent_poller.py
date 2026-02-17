# PRD: Remote Shield — Agent Poller
# Reference: Plan Milestone 4
#
# Background asyncio task that pulls events from deployed agents
# via SSH (low-level system route, no AI tokens) and feeds them
# into the existing EventAggregator → dashboard pipeline.
#
# Critical events are escalated to SecureChat for command-level attention.

import asyncio
import json
import logging
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..chat.chat_manager import ChatManager
    from ..intel.event_aggregator import EventAggregator

from .shield_database import RemoteShieldDatabase
from .ssh_manager import SSHConnectionManager

logger = logging.getLogger(__name__)

POLL_INTERVAL = 60  # seconds
REMOTE_DIR = "/opt/citadel-shield"
MAX_CONSECUTIVE_FAILURES = 3

# Severity levels that trigger chat escalation
ESCALATION_SEVERITIES = {"critical", "high"}


class AgentPoller:
    """Background poller that syncs events from VPS agents.

    Low-level system route: SSH into each agent, pull events, feed
    into EventAggregator. NO AI tokens consumed.

    Critical events are escalated to SecureChat.
    """

    def __init__(
        self,
        ssh_manager: SSHConnectionManager,
        event_aggregator: Optional["EventAggregator"] = None,
        chat_manager: Optional["ChatManager"] = None,
        shield_db: Optional[RemoteShieldDatabase] = None,
    ):
        self._ssh = ssh_manager
        self._aggregator = event_aggregator
        self._chat = chat_manager
        self._shield_db = shield_db or RemoteShieldDatabase()
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Track last synced event ID per agent
        self._last_event_id: Dict[str, int] = {}
        # Track consecutive failures per agent
        self._failures: Dict[str, int] = {}

    async def start(self):
        """Start the polling loop as a background task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        logger.info("Agent poller started (interval=%ds)", POLL_INTERVAL)

    async def stop(self):
        """Stop the polling loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Agent poller stopped")

    async def _poll_loop(self):
        """Main polling loop."""
        while self._running:
            try:
                await self._poll_all_agents()
            except Exception:
                logger.exception("Poller cycle error")
            await asyncio.sleep(POLL_INTERVAL)

    async def _poll_all_agents(self):
        """Poll all registered agents."""
        agents = self._shield_db.list_agents()
        if not agents:
            return

        for agent in agents:
            if not self._running:
                break

            agent_id = agent.get("id") or agent.get("agent_id")
            if not agent_id:
                continue

            # Derive asset_id from agent_id (shield_<asset_id>)
            asset_id = agent.get("asset_id") or ""
            if not asset_id and agent_id.startswith("shield_"):
                asset_id = agent_id[7:]  # strip "shield_" prefix

            if not asset_id:
                continue

            try:
                await self._poll_agent(agent_id, asset_id)
                self._failures[agent_id] = 0
                self._shield_db.update_agent_heartbeat(agent_id)
            except Exception as exc:
                self._failures[agent_id] = self._failures.get(agent_id, 0) + 1
                logger.warning(
                    "Poll failed for %s (%d/%d): %s",
                    agent_id,
                    self._failures[agent_id],
                    MAX_CONSECUTIVE_FAILURES,
                    exc,
                )

                if self._failures[agent_id] >= MAX_CONSECUTIVE_FAILURES:
                    self._mark_agent_offline(agent_id, asset_id)

    async def _poll_agent(self, agent_id: str, asset_id: str):
        """Poll a single agent: pull events + status."""
        since_id = self._last_event_id.get(agent_id, 0)

        # 1. Pull events
        result = await self._ssh.execute(
            asset_id,
            f"python3 {REMOTE_DIR}/shield.py events --since {since_id}",
            timeout=15,
        )

        if not result.success:
            raise RuntimeError(f"Events query failed: {result.error}")

        data = json.loads(result.stdout.strip())
        events = data.get("events", [])

        if events:
            max_id = 0
            critical_count = 0
            critical_summaries = []

            for evt in events:
                evt_id = evt.get("id", 0)
                if evt_id > max_id:
                    max_id = evt_id

                # Feed into EventAggregator (low-level system route)
                if self._aggregator:
                    self._aggregator.ingest(
                        event_type=f"remote.{evt.get('sensor', 'unknown')}",
                        severity=evt.get("severity", "info"),
                        asset_id=asset_id,
                        message=evt.get("detail", ""),
                        details={
                            "sensor": evt.get("sensor"),
                            "action_taken": evt.get("action_taken", ""),
                            "agent_id": agent_id,
                        },
                        timestamp=evt.get("timestamp"),
                    )

                # Track critical events for escalation
                if evt.get("severity") in ESCALATION_SEVERITIES:
                    critical_count += 1
                    critical_summaries.append(evt.get("detail", "")[:100])

            # Acknowledge events on the agent
            if max_id > 0:
                await self._ssh.execute(
                    asset_id,
                    f"python3 {REMOTE_DIR}/shield.py ack --through {max_id}",
                    timeout=10,
                )
                self._last_event_id[agent_id] = max_id

            # Escalate critical events to SecureChat (ONE summary, not per-event)
            if critical_count > 0 and self._chat:
                from ..chat.message import MessageType
                summary = (
                    f"Agent {agent_id}: {critical_count} critical/high event(s) — "
                    + "; ".join(critical_summaries[:3])
                )
                await self._chat.send_system(summary, MessageType.EVENT)

        # 2. Update agent health
        status_result = await self._ssh.execute(
            asset_id,
            f"python3 {REMOTE_DIR}/shield.py status",
            timeout=10,
        )

        if status_result.success and status_result.stdout:
            try:
                status = json.loads(status_result.stdout.strip())
                self._shield_db.update_agent_last_scan(agent_id)

                # Update asset status
                from ..api.asset_routes import get_inventory
                inv = get_inventory()
                if status.get("running"):
                    inv.mark_protected(asset_id)
                else:
                    inv.mark_online(asset_id)
            except (json.JSONDecodeError, Exception):
                pass

    def _mark_agent_offline(self, agent_id: str, asset_id: str):
        """Mark an agent as offline after max failures."""
        logger.warning("Marking agent %s as offline", agent_id)
        try:
            from ..api.asset_routes import get_inventory
            inv = get_inventory()
            inv.mark_offline(asset_id)
        except Exception:
            pass

        # Escalate to chat
        if self._chat:
            asyncio.create_task(
                self._chat.send_system(
                    f"Agent {agent_id} unreachable after "
                    f"{MAX_CONSECUTIVE_FAILURES} attempts. Asset marked offline.",
                )
            )
