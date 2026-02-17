# Tests for v0.3.21 — Inter-Agent Communication Protocol
# Covers: ChatMessage extensions, InterAgentProtocol (capabilities, presence,
#         delegation, inbox, task lifecycle), API routes, ChatManager routing

import asyncio
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.inter_agent import (
    HEARTBEAT_TIMEOUT_SECONDS,
    MAX_CAPABILITIES,
    MAX_INBOX_SIZE,
    AgentCapability,
    AgentPresence,
    DelegatedTask,
    InterAgentProtocol,
    TaskStatus,
)
from citadel_archer.chat.message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_CITADEL,
    PARTICIPANT_USER,
)


# ── ChatMessage Extensions ───────────────────────────────────────────


class TestChatMessageExtensions:
    def test_new_message_types_exist(self):
        assert MessageType.DELEGATION == "delegation"
        assert MessageType.ACK == "ack"

    def test_reply_to_field(self):
        msg = ChatMessage(
            from_id="ext-agent:a",
            to_id="ext-agent:b",
            msg_type=MessageType.RESPONSE,
            reply_to="msg_original_123",
        )
        assert msg.reply_to == "msg_original_123"
        d = msg.to_dict()
        assert d["reply_to"] == "msg_original_123"

    def test_correlation_id_field(self):
        msg = ChatMessage(
            from_id="ext-agent:a",
            to_id="ext-agent:b",
            msg_type=MessageType.DELEGATION,
            correlation_id="corr_workflow_1",
        )
        assert msg.correlation_id == "corr_workflow_1"
        d = msg.to_dict()
        assert d["correlation_id"] == "corr_workflow_1"

    def test_fields_default_none(self):
        msg = ChatMessage(
            from_id="user", to_id="citadel", msg_type=MessageType.TEXT,
        )
        assert msg.reply_to is None
        assert msg.correlation_id is None

    def test_from_dict_preserves_new_fields(self):
        d = {
            "from_id": "ext-agent:a",
            "to_id": "ext-agent:b",
            "msg_type": "delegation",
            "payload": {},
            "reply_to": "msg_123",
            "correlation_id": "corr_456",
        }
        msg = ChatMessage.from_dict(d)
        assert msg.reply_to == "msg_123"
        assert msg.correlation_id == "corr_456"
        assert msg.msg_type == MessageType.DELEGATION


# ── AgentCapability ──────────────────────────────────────────────────


class TestAgentCapability:
    def test_to_dict(self):
        cap = AgentCapability(
            name="threat_analysis",
            description="Analyze threats",
            domains=["network", "endpoint"],
            sla_seconds=120,
        )
        d = cap.to_dict()
        assert d["name"] == "threat_analysis"
        assert d["domains"] == ["network", "endpoint"]
        assert d["sla_seconds"] == 120

    def test_from_dict(self):
        cap = AgentCapability.from_dict({
            "name": "code_review",
            "description": "Review code",
            "domains": ["python"],
        })
        assert cap.name == "code_review"
        assert cap.domains == ["python"]
        assert cap.sla_seconds == 300  # default

    def test_defaults(self):
        cap = AgentCapability(name="simple")
        assert cap.description == ""
        assert cap.domains == []
        assert cap.sla_seconds == 300


# ── AgentPresence ────────────────────────────────────────────────────


class TestAgentPresence:
    def test_is_online_recent_heartbeat(self):
        p = AgentPresence(
            agent_id="test",
            last_heartbeat=datetime.now(timezone.utc),
        )
        assert p.is_online is True

    def test_is_offline_stale_heartbeat(self):
        stale = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS + 10)
        p = AgentPresence(agent_id="test", last_heartbeat=stale)
        assert p.is_online is False

    def test_to_dict(self):
        p = AgentPresence(
            agent_id="test",
            last_heartbeat=datetime.now(timezone.utc),
            version="1.0",
            status_detail="idle",
        )
        d = p.to_dict()
        assert d["agent_id"] == "test"
        assert d["is_online"] is True
        assert d["version"] == "1.0"


# ── InterAgentProtocol: Capabilities ─────────────────────────────────


class TestCapabilities:
    def setup_method(self):
        self.protocol = InterAgentProtocol()

    def test_register_and_get(self):
        caps = [AgentCapability(name="threat_analysis", domains=["network"])]
        self.protocol.register_capabilities("agent-a", caps)

        result = self.protocol.get_capabilities("agent-a")
        assert len(result) == 1
        assert result[0].name == "threat_analysis"

    def test_register_replaces(self):
        self.protocol.register_capabilities("agent-a", [
            AgentCapability(name="old_cap")
        ])
        self.protocol.register_capabilities("agent-a", [
            AgentCapability(name="new_cap")
        ])

        result = self.protocol.get_capabilities("agent-a")
        assert len(result) == 1
        assert result[0].name == "new_cap"

    def test_max_capabilities_capped(self):
        caps = [AgentCapability(name=f"cap_{i}") for i in range(30)]
        result = self.protocol.register_capabilities("agent-a", caps)
        assert len(result) == MAX_CAPABILITIES

    def test_get_unknown_agent(self):
        assert self.protocol.get_capabilities("unknown") == []


# ── InterAgentProtocol: Discovery ────────────────────────────────────


class TestDiscovery:
    def setup_method(self):
        self.protocol = InterAgentProtocol()
        self.protocol.register_capabilities("agent-a", [
            AgentCapability(name="threat_analysis", domains=["network", "endpoint"]),
            AgentCapability(name="code_review", domains=["python"]),
        ])
        self.protocol.register_capabilities("agent-b", [
            AgentCapability(name="threat_analysis", domains=["cloud"]),
        ])
        # Make both agents online
        self.protocol.heartbeat("agent-a")
        self.protocol.heartbeat("agent-b")

    def test_discover_by_capability(self):
        results = self.protocol.discover("threat_analysis")
        assert len(results) == 2

    def test_discover_by_domain(self):
        results = self.protocol.discover("threat_analysis", domain="network")
        assert len(results) == 1
        assert results[0]["agent_id"] == "agent-a"

    def test_discover_online_only(self):
        # Make agent-b offline
        stale = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS + 10)
        self.protocol._presence["agent-b"].last_heartbeat = stale

        results = self.protocol.discover("threat_analysis", online_only=True)
        assert len(results) == 1
        assert results[0]["agent_id"] == "agent-a"

    def test_discover_include_offline(self):
        stale = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS + 10)
        self.protocol._presence["agent-b"].last_heartbeat = stale

        results = self.protocol.discover("threat_analysis", online_only=False)
        assert len(results) == 2

    def test_discover_no_match(self):
        assert self.protocol.discover("nonexistent") == []


# ── InterAgentProtocol: Presence ─────────────────────────────────────


class TestPresence:
    def setup_method(self):
        self.protocol = InterAgentProtocol()

    def test_heartbeat_creates_presence(self):
        p = self.protocol.heartbeat("agent-a", version="1.0")
        assert p.agent_id == "agent-a"
        assert p.version == "1.0"
        assert p.is_online is True

    def test_heartbeat_updates_existing(self):
        self.protocol.heartbeat("agent-a", version="1.0")
        p = self.protocol.heartbeat("agent-a", version="2.0", status_detail="busy")
        assert p.version == "2.0"
        assert p.status_detail == "busy"

    def test_heartbeat_with_capabilities(self):
        caps = [AgentCapability(name="analysis")]
        p = self.protocol.heartbeat("agent-a", capabilities=caps)
        assert len(p.capabilities) == 1
        # Also stored in capabilities registry
        assert len(self.protocol.get_capabilities("agent-a")) == 1

    def test_get_presence(self):
        self.protocol.heartbeat("agent-a")
        assert self.protocol.get_presence("agent-a") is not None
        assert self.protocol.get_presence("unknown") is None

    def test_list_online_agents(self):
        self.protocol.heartbeat("agent-a")
        self.protocol.heartbeat("agent-b")

        online = self.protocol.list_online_agents()
        assert len(online) == 2

    def test_list_online_excludes_stale(self):
        self.protocol.heartbeat("agent-a")
        self.protocol.heartbeat("agent-b")

        # Make agent-b stale
        stale = datetime.now(timezone.utc) - timedelta(seconds=HEARTBEAT_TIMEOUT_SECONDS + 10)
        self.protocol._presence["agent-b"].last_heartbeat = stale

        online = self.protocol.list_online_agents()
        assert len(online) == 1
        assert online[0]["agent_id"] == "agent-a"


# ── InterAgentProtocol: Task Delegation ──────────────────────────────


class TestTaskDelegation:
    def setup_method(self):
        self.chat_mgr = MagicMock()
        self.chat_mgr.send = AsyncMock()
        self.protocol = InterAgentProtocol(chat_manager=self.chat_mgr)
        self.protocol.register_capabilities("agent-target", [
            AgentCapability(name="threat_analysis"),
        ])

    @pytest.mark.asyncio
    async def test_delegate_creates_task(self):
        task = await self.protocol.delegate(
            from_agent="ext-agent:requester",
            to_agent="agent-target",
            capability="threat_analysis",
            payload={"events": [1, 2, 3]},
        )
        assert task.task_id.startswith("task_")
        assert task.status == TaskStatus.PENDING
        assert task.from_agent == "ext-agent:requester"
        assert task.to_agent == "agent-target"
        assert task.capability == "threat_analysis"

    @pytest.mark.asyncio
    async def test_delegate_sends_message(self):
        await self.protocol.delegate(
            from_agent="ext-agent:requester",
            to_agent="agent-target",
            capability="threat_analysis",
            payload={},
        )
        self.chat_mgr.send.assert_called_once()
        msg = self.chat_mgr.send.call_args[0][0]
        assert msg.msg_type == MessageType.DELEGATION
        assert msg.to_id == "agent-target"
        assert msg.payload["capability"] == "threat_analysis"

    @pytest.mark.asyncio
    async def test_delegate_buffers_in_inbox(self):
        await self.protocol.delegate(
            from_agent="ext-agent:requester",
            to_agent="agent-target",
            capability="threat_analysis",
            payload={},
        )
        inbox = self.protocol.get_inbox("agent-target")
        assert len(inbox) == 1
        assert inbox[0].msg_type == MessageType.DELEGATION

    @pytest.mark.asyncio
    async def test_delegate_no_capability_raises(self):
        with pytest.raises(ValueError, match="does not have capability"):
            await self.protocol.delegate(
                from_agent="ext-agent:req",
                to_agent="agent-target",
                capability="nonexistent",
                payload={},
            )

    def test_accept_task(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )
        self.protocol._tasks["t1"] = task

        result = self.protocol.accept_task("t1")
        assert result is not None
        assert result.status == TaskStatus.ACCEPTED

    def test_accept_nonexistent(self):
        assert self.protocol.accept_task("nonexistent") is None

    def test_complete_task(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )
        self.protocol._tasks["t1"] = task

        result = self.protocol.complete_task("t1", {"analysis": "safe"})
        assert result.status == TaskStatus.COMPLETED
        assert result.result == {"analysis": "safe"}

    def test_fail_task(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )
        self.protocol._tasks["t1"] = task

        result = self.protocol.fail_task("t1", "timeout")
        assert result.status == TaskStatus.FAILED
        assert result.error == "timeout"

    def test_cannot_complete_already_completed(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
            status=TaskStatus.COMPLETED,
        )
        self.protocol._tasks["t1"] = task
        assert self.protocol.complete_task("t1", {}) is None

    def test_list_tasks(self):
        for i in range(3):
            self.protocol._tasks[f"t{i}"] = DelegatedTask(
                task_id=f"t{i}", correlation_id=f"c{i}",
                from_agent="a", to_agent="b",
                capability="test", payload={},
                status=TaskStatus.PENDING if i < 2 else TaskStatus.COMPLETED,
            )

        all_tasks = self.protocol.list_tasks()
        assert len(all_tasks) == 3

        pending = self.protocol.list_tasks(status=TaskStatus.PENDING)
        assert len(pending) == 2

    def test_list_tasks_by_agent(self):
        self.protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="agent-a", to_agent="agent-b",
            capability="test", payload={},
        )
        self.protocol._tasks["t2"] = DelegatedTask(
            task_id="t2", correlation_id="c2",
            from_agent="agent-c", to_agent="agent-d",
            capability="test", payload={},
        )

        tasks = self.protocol.list_tasks(agent_id="agent-a")
        assert len(tasks) == 1
        assert tasks[0].task_id == "t1"

    def test_get_task(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )
        self.protocol._tasks["t1"] = task
        assert self.protocol.get_task("t1") is task
        assert self.protocol.get_task("nonexistent") is None


# ── Timeout & Cleanup ────────────────────────────────────────────────


class TestCleanup:
    def setup_method(self):
        self.protocol = InterAgentProtocol()

    def test_cleanup_marks_timed_out(self):
        past = (datetime.now(timezone.utc) - timedelta(seconds=400)).isoformat()
        self.protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
            created_at=past, timeout_seconds=300,
        )

        cleaned = self.protocol.cleanup_expired_tasks()
        assert cleaned >= 1
        assert self.protocol.get_task("t1").status == TaskStatus.TIMED_OUT

    def test_cleanup_removes_old_terminal(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        self.protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
            created_at=old, status=TaskStatus.COMPLETED,
        )

        self.protocol.cleanup_expired_tasks()
        assert self.protocol.get_task("t1") is None

    def test_cleanup_keeps_recent_tasks(self):
        self.protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
            timeout_seconds=300,
        )

        cleaned = self.protocol.cleanup_expired_tasks()
        assert cleaned == 0
        assert self.protocol.get_task("t1").status == TaskStatus.PENDING


# ── Inbox ────────────────────────────────────────────────────────────


class TestInbox:
    def setup_method(self):
        self.protocol = InterAgentProtocol()

    def test_buffer_and_retrieve(self):
        msg = ChatMessage(
            from_id="a", to_id="b", msg_type=MessageType.DELEGATION,
        )
        self.protocol._buffer_message("agent-b", msg)

        inbox = self.protocol.get_inbox("agent-b")
        assert len(inbox) == 1
        assert inbox[0].from_id == "a"

    def test_get_clears_inbox(self):
        msg = ChatMessage(
            from_id="a", to_id="b", msg_type=MessageType.TEXT,
        )
        self.protocol._buffer_message("agent-b", msg)
        self.protocol.get_inbox("agent-b")

        # Second call should be empty
        assert len(self.protocol.get_inbox("agent-b")) == 0

    def test_inbox_count(self):
        for i in range(5):
            msg = ChatMessage(
                from_id="a", to_id="b", msg_type=MessageType.TEXT,
            )
            self.protocol._buffer_message("agent-b", msg)

        assert self.protocol.inbox_count("agent-b") == 5

    def test_inbox_capped(self):
        for i in range(MAX_INBOX_SIZE + 20):
            msg = ChatMessage(
                from_id="a", to_id="b", msg_type=MessageType.TEXT,
                payload={"text": f"msg_{i}"},
            )
            self.protocol._buffer_message("agent-b", msg)

        assert self.protocol.inbox_count("agent-b") == MAX_INBOX_SIZE

    def test_empty_inbox(self):
        assert self.protocol.get_inbox("unknown") == []
        assert self.protocol.inbox_count("unknown") == 0


# ── Statistics ───────────────────────────────────────────────────────


class TestStats:
    def test_stats(self):
        protocol = InterAgentProtocol()
        protocol.heartbeat("agent-a")
        protocol.register_capabilities("agent-a", [
            AgentCapability(name="test"),
        ])
        protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )

        stats = protocol.stats()
        assert stats["online_agents"] == 1
        assert stats["total_agents_seen"] == 1
        assert stats["total_capabilities"] == 1
        assert stats["total_tasks"] == 1
        assert stats["tasks_by_status"]["pending"] == 1


# ── ChatManager Target Routing ───────────────────────────────────────


class TestChatManagerTargetRouting:
    @pytest.mark.asyncio
    async def test_target_listener_notified(self):
        from citadel_archer.chat.chat_manager import ChatManager

        mgr = ChatManager(store=MagicMock())
        mgr._store.save = MagicMock()

        listener = MagicMock()
        mgr.subscribe_target("ext-agent:bob", listener)

        msg = ChatMessage(
            from_id="ext-agent:alice",
            to_id="ext-agent:bob",
            msg_type=MessageType.DELEGATION,
        )
        await mgr.send(msg)

        listener.assert_called_once_with(msg)

    @pytest.mark.asyncio
    async def test_target_listener_not_called_for_other(self):
        from citadel_archer.chat.chat_manager import ChatManager

        mgr = ChatManager(store=MagicMock())
        mgr._store.save = MagicMock()

        listener = MagicMock()
        mgr.subscribe_target("ext-agent:bob", listener)

        msg = ChatMessage(
            from_id="ext-agent:alice",
            to_id="ext-agent:charlie",
            msg_type=MessageType.TEXT,
        )
        await mgr.send(msg)

        listener.assert_not_called()

    @pytest.mark.asyncio
    async def test_unsubscribe_target(self):
        from citadel_archer.chat.chat_manager import ChatManager

        mgr = ChatManager(store=MagicMock())
        mgr._store.save = MagicMock()

        listener = MagicMock()
        mgr.subscribe_target("ext-agent:bob", listener)
        mgr.unsubscribe_target("ext-agent:bob", listener)

        msg = ChatMessage(
            from_id="ext-agent:alice",
            to_id="ext-agent:bob",
            msg_type=MessageType.TEXT,
        )
        await mgr.send(msg)

        listener.assert_not_called()


# ── DelegatedTask Serialization ──────────────────────────────────────


class TestDelegatedTaskSerialization:
    def test_to_dict(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={"key": "val"},
            status=TaskStatus.COMPLETED,
            result={"output": 42},
        )
        d = task.to_dict()
        assert d["task_id"] == "t1"
        assert d["status"] == "completed"
        assert d["result"]["output"] == 42
        assert d["capability"] == "test"


# ── API Routes ───────────────────────────────────────────────────────


class TestInterAgentAPIRoutes:
    @pytest.fixture(autouse=True)
    def setup_api(self):
        """Set up FastAPI test client with mocked dependencies."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from citadel_archer.api.agent_api_routes import router
        from citadel_archer.api.security import initialize_session_token

        app = FastAPI()
        app.include_router(router)

        self.token = initialize_session_token()
        self.session_headers = {"X-Session-Token": self.token}
        self.client = TestClient(app)

        # Create a mock registry + protocol
        from citadel_archer.chat.agent_registry import AgentRegistry
        from citadel_archer.chat.inter_agent import InterAgentProtocol

        self._protocol = InterAgentProtocol()
        self._protocol_patcher = patch(
            "citadel_archer.chat.inter_agent.get_inter_agent_protocol",
            return_value=self._protocol,
        )

        # We need a real-ish registry for token verification
        import tempfile, os
        self._tmp = tempfile.mkdtemp()
        db_path = os.path.join(self._tmp, "test_registry.db")
        self._registry = AgentRegistry(db_path=db_path)

        self._registry_patcher = patch(
            "citadel_archer.api.agent_api_routes.get_agent_registry",
            return_value=self._registry,
        )

        # Mock chat manager
        self._chat_mgr = MagicMock()
        self._chat_mgr.send = AsyncMock()
        self._chat_patcher = patch(
            "citadel_archer.api.chat_routes.get_chat_manager",
            return_value=self._chat_mgr,
        )

        self._protocol_patcher.start()
        self._registry_patcher.start()
        self._chat_patcher.start()

        # Register a test agent
        self._agent_id, self._agent_token = self._registry.register_agent(
            name="TestAgent", agent_type="custom",
        )
        self.agent_headers = {"Authorization": f"Bearer {self._agent_token}"}

        # Register a second agent for delegation targets
        self._target_id, self._target_token = self._registry.register_agent(
            name="TargetAgent", agent_type="custom",
        )
        self.target_headers = {"Authorization": f"Bearer {self._target_token}"}

    def teardown_method(self):
        self._protocol_patcher.stop()
        self._registry_patcher.stop()
        self._chat_patcher.stop()

    def test_register_capabilities(self):
        resp = self.client.post(
            f"/api/ext-agents/{self._agent_id}/capabilities",
            json={"capabilities": [
                {"name": "threat_analysis", "domains": ["network"]},
            ]},
            headers=self.agent_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["capabilities"]) == 1
        assert data["capabilities"][0]["name"] == "threat_analysis"

    def test_register_capabilities_wrong_agent(self):
        resp = self.client.post(
            f"/api/ext-agents/{self._target_id}/capabilities",
            json={"capabilities": [{"name": "test"}]},
            headers=self.agent_headers,  # agent_id doesn't match path
        )
        assert resp.status_code == 403

    def test_discover_agents(self):
        # Register capabilities first (using participant ID as the API does)
        participant = f"ext-agent:{self._agent_id}"
        self._protocol.register_capabilities(participant, [
            AgentCapability(name="threat_analysis"),
        ])
        self._protocol.heartbeat(participant)

        resp = self.client.get(
            "/api/ext-agents/discover?capability=threat_analysis",
            headers=self.session_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_discover_no_match(self):
        resp = self.client.get(
            "/api/ext-agents/discover?capability=nonexistent",
            headers=self.session_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_heartbeat(self):
        resp = self.client.post(
            f"/api/ext-agents/{self._agent_id}/heartbeat",
            json={"version": "1.0", "status_detail": "idle"},
            headers=self.agent_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_online"] is True
        assert data["version"] == "1.0"

    def test_heartbeat_wrong_agent(self):
        resp = self.client.post(
            f"/api/ext-agents/{self._target_id}/heartbeat",
            json={},
            headers=self.agent_headers,
        )
        assert resp.status_code == 403

    def test_delegate_task(self):
        # Target needs capability (stored under participant ID)
        target_participant = f"ext-agent:{self._target_id}"
        self._protocol.register_capabilities(target_participant, [
            AgentCapability(name="analysis"),
        ])

        resp = self.client.post(
            "/api/ext-agents/delegate",
            json={
                "to_agent": target_participant,
                "capability": "analysis",
                "payload": {"data": [1, 2, 3]},
            },
            headers=self.agent_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "pending"
        assert data["capability"] == "analysis"

    def test_delegate_no_capability(self):
        resp = self.client.post(
            "/api/ext-agents/delegate",
            json={
                "to_agent": f"ext-agent:{self._target_id}",
                "capability": "nonexistent",
                "payload": {},
            },
            headers=self.agent_headers,
        )
        assert resp.status_code == 400

    def test_task_response_accept(self):
        # Create a task directly
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent=f"ext-agent:{self._agent_id}",
            to_agent=f"ext-agent:{self._target_id}",
            capability="test", payload={},
        )
        self._protocol._tasks["t1"] = task

        resp = self.client.post(
            "/api/ext-agents/task-response",
            json={"task_id": "t1", "status": "accepted"},
            headers=self.target_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "accepted"

    def test_task_response_complete(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent=f"ext-agent:{self._agent_id}",
            to_agent=f"ext-agent:{self._target_id}",
            capability="test", payload={},
            status=TaskStatus.ACCEPTED,
        )
        self._protocol._tasks["t1"] = task

        resp = self.client.post(
            "/api/ext-agents/task-response",
            json={"task_id": "t1", "status": "completed", "result": {"score": 0.95}},
            headers=self.target_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "completed"
        assert resp.json()["result"]["score"] == 0.95

    def test_task_response_wrong_agent(self):
        task = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent=f"ext-agent:{self._target_id}",
            to_agent=f"ext-agent:{self._target_id}",  # target is target
            capability="test", payload={},
        )
        self._protocol._tasks["t1"] = task

        # Agent (not target) tries to respond
        resp = self.client.post(
            "/api/ext-agents/task-response",
            json={"task_id": "t1", "status": "accepted"},
            headers=self.agent_headers,
        )
        assert resp.status_code == 403

    def test_get_inbox(self):
        msg = ChatMessage(
            from_id="a", to_id=f"ext-agent:{self._agent_id}",
            msg_type=MessageType.DELEGATION,
            payload={"text": "task for you"},
        )
        self._protocol._buffer_message(f"ext-agent:{self._agent_id}", msg)

        resp = self.client.get(
            f"/api/ext-agents/{self._agent_id}/inbox",
            headers=self.agent_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_get_inbox_wrong_agent(self):
        resp = self.client.get(
            f"/api/ext-agents/{self._target_id}/inbox",
            headers=self.agent_headers,
        )
        assert resp.status_code == 403

    def test_protocol_stats(self):
        resp = self.client.get(
            "/api/ext-agents/protocol/stats",
            headers=self.session_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "online_agents" in data
        assert "total_tasks" in data

    def test_list_tasks(self):
        self._protocol._tasks["t1"] = DelegatedTask(
            task_id="t1", correlation_id="c1",
            from_agent="a", to_agent="b",
            capability="test", payload={},
        )

        resp = self.client.get(
            "/api/ext-agents/protocol/tasks",
            headers=self.session_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_list_online_agents(self):
        self._protocol.heartbeat("agent-a")

        resp = self.client.get(
            "/api/ext-agents/protocol/online",
            headers=self.session_headers,
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
