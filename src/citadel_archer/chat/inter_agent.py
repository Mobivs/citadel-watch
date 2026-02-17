# PRD: Inter-Agent Communication Protocol
# Reference: docs/PRD.md v0.3.20, Phase 4
#
# AI agent-to-AI agent coordination via SecureChat (SCS).
# Enables external agents (Forge, Claude Code, OpenClaw) to:
#   - Declare capabilities (what they can do)
#   - Discover other agents by capability
#   - Delegate tasks to specific agents with request-response correlation
#   - Track agent presence via heartbeats
#   - Route messages directly to target agents (not just broadcast)
#
# Security:
#   - Agent authentication via existing Bearer token system
#   - All inter-agent messages persisted to ChatStore (audit trail)
#   - SCS quota enforced per agent participant
#   - Task delegation restricted to active agents only
#
# Design:
#   - Builds on existing ChatManager + AgentRegistry infrastructure
#   - ChatMessage.reply_to + correlation_id for request-response correlation
#   - MessageType.DELEGATION + ACK for structured task lifecycle
#   - Presence tracking via in-memory cache with configurable timeout

import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4

from .message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_CITADEL,
)

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

HEARTBEAT_TIMEOUT_SECONDS = 300   # 5 minutes — agent is offline if no heartbeat
DEFAULT_TASK_TIMEOUT = 300        # 5 minutes default for delegated tasks
MAX_TASK_TIMEOUT = 3600           # 1 hour max
MAX_CAPABILITIES = 20             # Max capabilities per agent
MAX_INBOX_SIZE = 100              # Max messages buffered per agent inbox


# ── Data Models ──────────────────────────────────────────────────────


class TaskStatus(str, Enum):
    """Lifecycle states for a delegated task."""
    PENDING = "pending"         # Task sent, waiting for ACK
    ACCEPTED = "accepted"       # Agent acknowledged, processing
    COMPLETED = "completed"     # Agent returned result
    FAILED = "failed"           # Agent reported error
    TIMED_OUT = "timed_out"     # No response within timeout


@dataclass
class AgentCapability:
    """A capability declared by an agent."""
    name: str                           # e.g., "threat_analysis", "code_review"
    description: str = ""               # Human-readable description
    domains: List[str] = field(default_factory=list)  # e.g., ["endpoint", "network"]
    sla_seconds: int = DEFAULT_TASK_TIMEOUT  # Expected response time

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentCapability":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AgentPresence:
    """Tracks whether an agent is online."""
    agent_id: str
    last_heartbeat: datetime
    capabilities: List[AgentCapability] = field(default_factory=list)
    version: str = ""
    status_detail: str = ""

    @property
    def is_online(self) -> bool:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS)
        return self.last_heartbeat >= cutoff

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "is_online": self.is_online,
            "capabilities": [c.to_dict() for c in self.capabilities],
            "version": self.version,
            "status_detail": self.status_detail,
        }


@dataclass
class DelegatedTask:
    """Tracks a task delegated from one agent to another."""
    task_id: str
    correlation_id: str
    from_agent: str          # Requesting agent's participant ID
    to_agent: str            # Target agent's participant ID
    capability: str          # Requested capability name
    payload: Dict[str, Any]  # Task input data
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    timeout_seconds: int = DEFAULT_TASK_TIMEOUT
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


# ── Inter-Agent Protocol ─────────────────────────────────────────────


class InterAgentProtocol:
    """Manages inter-agent communication: capabilities, presence, delegation.

    Usage::

        protocol = InterAgentProtocol(chat_manager)

        # Agent declares capabilities
        protocol.register_capabilities("agent-id", [
            AgentCapability(name="threat_analysis", domains=["network"])
        ])

        # Agent heartbeat
        protocol.heartbeat("agent-id")

        # Discover agents by capability
        agents = protocol.discover("threat_analysis")

        # Delegate task
        task = await protocol.delegate(
            from_agent="ext-agent:forge",
            to_agent="ext-agent:guardian",
            capability="threat_analysis",
            payload={"events": [...]},
        )

        # Agent responds to task
        protocol.complete_task(task.task_id, result={...})
    """

    def __init__(self, chat_manager=None):
        self._chat_manager = chat_manager
        self._lock = threading.Lock()

        # In-memory state (resets on restart, which is acceptable for
        # presence and active tasks — persistent state is in ChatStore)
        self._presence: Dict[str, AgentPresence] = {}
        self._capabilities: Dict[str, List[AgentCapability]] = {}
        self._tasks: Dict[str, DelegatedTask] = {}
        self._inbox: Dict[str, List[ChatMessage]] = {}

    def set_chat_manager(self, chat_manager):
        """Set ChatManager after init (for lazy wiring in main.py)."""
        self._chat_manager = chat_manager

    # ── Capabilities ─────────────────────────────────────────────────

    def register_capabilities(
        self, agent_id: str, capabilities: List[AgentCapability]
    ) -> List[AgentCapability]:
        """Register or replace an agent's declared capabilities.

        Returns the stored capabilities (capped at MAX_CAPABILITIES).
        """
        capped = capabilities[:MAX_CAPABILITIES]
        with self._lock:
            self._capabilities[agent_id] = capped
            # Also update presence capabilities if present
            if agent_id in self._presence:
                self._presence[agent_id].capabilities = capped
        logger.info(
            "Agent %s registered %d capabilities: %s",
            agent_id, len(capped),
            [c.name for c in capped],
        )
        return capped

    def get_capabilities(self, agent_id: str) -> List[AgentCapability]:
        """Get an agent's declared capabilities."""
        with self._lock:
            return list(self._capabilities.get(agent_id, []))

    def discover(
        self,
        capability_name: str,
        domain: Optional[str] = None,
        online_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """Find agents that have a specific capability.

        Args:
            capability_name: The capability to search for.
            domain: Optional domain filter within the capability.
            online_only: If True, only return agents with recent heartbeat.

        Returns:
            List of dicts with agent_id, capabilities, and presence info.
        """
        results = []
        with self._lock:
            for agent_id, caps in self._capabilities.items():
                matching = [
                    c for c in caps
                    if c.name == capability_name
                    and (domain is None or domain in c.domains)
                ]
                if not matching:
                    continue

                presence = self._presence.get(agent_id)
                if online_only and (not presence or not presence.is_online):
                    continue

                results.append({
                    "agent_id": agent_id,
                    "capabilities": [c.to_dict() for c in matching],
                    "is_online": presence.is_online if presence else False,
                    "last_heartbeat": (
                        presence.last_heartbeat.isoformat() if presence else None
                    ),
                })
        return results

    # ── Presence ─────────────────────────────────────────────────────

    def heartbeat(
        self,
        agent_id: str,
        version: str = "",
        status_detail: str = "",
        capabilities: Optional[List[AgentCapability]] = None,
    ) -> AgentPresence:
        """Record an agent heartbeat (marks agent as online).

        Optionally updates capabilities and metadata.
        """
        now = datetime.now(timezone.utc)
        with self._lock:
            existing = self._presence.get(agent_id)
            if existing:
                existing.last_heartbeat = now
                if version:
                    existing.version = version
                if status_detail:
                    existing.status_detail = status_detail
                if capabilities is not None:
                    existing.capabilities = capabilities[:MAX_CAPABILITIES]
                    self._capabilities[agent_id] = existing.capabilities
                return existing

            caps = (capabilities or [])[:MAX_CAPABILITIES]
            presence = AgentPresence(
                agent_id=agent_id,
                last_heartbeat=now,
                capabilities=caps,
                version=version,
                status_detail=status_detail,
            )
            self._presence[agent_id] = presence
            if caps:
                self._capabilities[agent_id] = caps
            return presence

    def get_presence(self, agent_id: str) -> Optional[AgentPresence]:
        """Get an agent's presence info."""
        with self._lock:
            return self._presence.get(agent_id)

    def list_online_agents(self) -> List[Dict[str, Any]]:
        """List all agents with recent heartbeats."""
        with self._lock:
            return [
                p.to_dict() for p in self._presence.values()
                if p.is_online
            ]

    # ── Task Delegation ──────────────────────────────────────────────

    async def delegate(
        self,
        from_agent: str,
        to_agent: str,
        capability: str,
        payload: Dict[str, Any],
        timeout_seconds: int = DEFAULT_TASK_TIMEOUT,
    ) -> DelegatedTask:
        """Delegate a task from one agent to another.

        Creates a DELEGATION message, routes it to the target agent,
        and tracks the task lifecycle.

        Returns:
            DelegatedTask with task_id for tracking.

        Raises:
            ValueError: If target agent is not known or has no matching capability.
        """
        # Opportunistic cleanup of expired tasks
        self.cleanup_expired_tasks()

        timeout_seconds = max(1, min(timeout_seconds, MAX_TASK_TIMEOUT))

        # Verify target has the capability
        caps = self.get_capabilities(to_agent)
        if not any(c.name == capability for c in caps):
            raise ValueError(
                f"Agent '{to_agent}' does not have capability '{capability}'"
            )

        task_id = f"task_{uuid4().hex[:16]}"
        correlation_id = f"corr_{uuid4().hex[:16]}"

        task = DelegatedTask(
            task_id=task_id,
            correlation_id=correlation_id,
            from_agent=from_agent,
            to_agent=to_agent,
            capability=capability,
            payload=payload,
            timeout_seconds=timeout_seconds,
        )

        with self._lock:
            self._tasks[task_id] = task

        # Build and send DELEGATION message
        msg = ChatMessage(
            from_id=from_agent,
            to_id=to_agent,
            msg_type=MessageType.DELEGATION,
            payload={
                "text": f"Task delegation: {capability}",
                "task_id": task_id,
                "capability": capability,
                "task_payload": payload,
                "timeout_seconds": timeout_seconds,
            },
            correlation_id=correlation_id,
        )

        # Buffer in target agent's inbox
        self._buffer_message(to_agent, msg)

        # Route through ChatManager for persistence + listeners
        if self._chat_manager:
            await self._chat_manager.send(msg)

        logger.info(
            "Task delegated: %s → %s (capability=%s, task=%s)",
            from_agent, to_agent, capability, task_id,
        )
        return task

    def accept_task(self, task_id: str) -> Optional[DelegatedTask]:
        """Mark a task as accepted (agent acknowledged and is processing)."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status == TaskStatus.PENDING:
                task.status = TaskStatus.ACCEPTED
                return task
            return None

    def complete_task(
        self,
        task_id: str,
        result: Dict[str, Any],
    ) -> Optional[DelegatedTask]:
        """Mark a task as completed with a result."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status in (TaskStatus.PENDING, TaskStatus.ACCEPTED):
                task.status = TaskStatus.COMPLETED
                task.result = result
                return task
            return None

    def fail_task(
        self,
        task_id: str,
        error: str,
    ) -> Optional[DelegatedTask]:
        """Mark a task as failed with an error message."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task and task.status in (TaskStatus.PENDING, TaskStatus.ACCEPTED):
                task.status = TaskStatus.FAILED
                task.error = error
                return task
            return None

    def get_task(self, task_id: str) -> Optional[DelegatedTask]:
        """Get a task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(
        self,
        agent_id: Optional[str] = None,
        status: Optional[TaskStatus] = None,
    ) -> List[DelegatedTask]:
        """List tasks with optional filtering."""
        with self._lock:
            tasks = list(self._tasks.values())
            if agent_id:
                tasks = [
                    t for t in tasks
                    if t.from_agent == agent_id or t.to_agent == agent_id
                ]
            if status:
                tasks = [t for t in tasks if t.status == status]
        return tasks

    def cleanup_expired_tasks(self) -> int:
        """Mark timed-out tasks and remove old completed/failed tasks."""
        now = datetime.now(timezone.utc)
        cleaned = 0
        with self._lock:
            expired_ids = []
            for task_id, task in self._tasks.items():
                if task.status in (TaskStatus.PENDING, TaskStatus.ACCEPTED):
                    created = datetime.fromisoformat(task.created_at)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    if (now - created).total_seconds() > task.timeout_seconds:
                        task.status = TaskStatus.TIMED_OUT
                        task.error = "Task timed out"
                        cleaned += 1
                elif task.status in (
                    TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMED_OUT
                ):
                    created = datetime.fromisoformat(task.created_at)
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    # Remove terminal tasks older than 1 hour
                    if (now - created).total_seconds() > 3600:
                        expired_ids.append(task_id)

            for tid in expired_ids:
                del self._tasks[tid]
                cleaned += 1

        return cleaned

    # ── Agent Inbox (Polling) ────────────────────────────────────────

    def _buffer_message(self, agent_id: str, msg: ChatMessage):
        """Buffer a message for an agent's inbox (for polling retrieval)."""
        with self._lock:
            inbox = self._inbox.setdefault(agent_id, [])
            inbox.append(msg)
            # Cap inbox size (evict oldest via slice, not O(n) pop(0) loop)
            if len(inbox) > MAX_INBOX_SIZE:
                self._inbox[agent_id] = inbox[-MAX_INBOX_SIZE:]

    def get_inbox(self, agent_id: str, limit: int = 50) -> List[ChatMessage]:
        """Get and clear buffered messages for an agent.

        Returns up to `limit` messages, removing them from the inbox.
        """
        with self._lock:
            inbox = self._inbox.get(agent_id, [])
            messages = inbox[:limit]
            self._inbox[agent_id] = inbox[limit:]
            return messages

    def inbox_count(self, agent_id: str) -> int:
        """Get the number of buffered messages for an agent."""
        with self._lock:
            return len(self._inbox.get(agent_id, []))

    # ── Statistics ───────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """Return inter-agent protocol statistics."""
        with self._lock:
            online = sum(1 for p in self._presence.values() if p.is_online)
            total_agents = len(self._presence)
            total_tasks = len(self._tasks)
            by_status = {}
            for t in self._tasks.values():
                by_status[t.status.value] = by_status.get(t.status.value, 0) + 1
            total_caps = sum(len(c) for c in self._capabilities.values())
            total_inbox = sum(len(m) for m in self._inbox.values())

        return {
            "online_agents": online,
            "total_agents_seen": total_agents,
            "total_capabilities": total_caps,
            "total_tasks": total_tasks,
            "tasks_by_status": by_status,
            "total_inbox_messages": total_inbox,
        }


# ── Singleton ────────────────────────────────────────────────────────

_protocol: Optional[InterAgentProtocol] = None
_protocol_lock = threading.Lock()


def get_inter_agent_protocol() -> InterAgentProtocol:
    """Get or create the global InterAgentProtocol singleton."""
    global _protocol
    if _protocol is None:
        with _protocol_lock:
            if _protocol is None:
                _protocol = InterAgentProtocol()
    return _protocol
