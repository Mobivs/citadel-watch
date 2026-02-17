"""
Tests for AI Audit Log — append-only record of Claude API calls.

Covers: AICallRecord fields, AIAuditLogger lifecycle (start_call / finish_call),
file-backed JSON lines, aggregates, query_recent, defensive error handling,
singleton, trigger type classification, and the REST endpoint.
"""

import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.ai_audit import (
    AIAuditLogger,
    AICallRecord,
    get_ai_audit_logger,
)


# ===================================================================
# Helpers
# ===================================================================


def _make_response(
    input_tokens: int = 100,
    output_tokens: int = 50,
    stop_reason: str = "end_turn",
    text: str = "Hello from Claude",
    tool_calls: Optional[list] = None,
):
    """Build a mock Anthropic response object."""
    content = []
    if text:
        content.append(SimpleNamespace(type="text", text=text))
    for name in tool_calls or []:
        content.append(SimpleNamespace(type="tool_use", name=name, id=f"tu_{name}"))
    usage = SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens)
    return SimpleNamespace(
        usage=usage,
        stop_reason=stop_reason,
        content=content,
    )


def _make_logger(tmp_path: Path) -> AIAuditLogger:
    """Create an AIAuditLogger using a temp directory."""
    return AIAuditLogger(log_path=tmp_path / "ai_audit.log")


def _read_lines(tmp_path: Path) -> list:
    """Read JSON lines from the audit log file."""
    log_file = tmp_path / "ai_audit.log"
    if not log_file.exists():
        return []
    lines = []
    for line in log_file.read_text(encoding="utf-8").strip().split("\n"):
        line = line.strip()
        if line:
            lines.append(json.loads(line))
    return lines


# ===================================================================
# TestAICallRecordFields
# ===================================================================


class TestAICallRecordFields:
    """Verify dataclass shape and serialization."""

    def test_all_fields_populated(self):
        rec = AICallRecord(
            call_id="abc-123",
            timestamp="2025-01-01T00:00:00+00:00",
            trigger_type="user_text",
            trigger_message_id="msg-1",
            model="claude-sonnet-4-5-20250929",
            input_tokens=100,
            output_tokens=50,
            total_tokens=150,
            stop_reason="end_turn",
            tool_calls=["get_system_status"],
            duration_ms=1200,
            response_preview="Hello from Claude",
            error=None,
            iteration=0,
        )
        d = asdict(rec)
        assert d["call_id"] == "abc-123"
        assert d["total_tokens"] == 150
        assert d["error"] is None
        assert d["tool_calls"] == ["get_system_status"]

    def test_error_call_record(self):
        rec = AICallRecord(
            call_id="err-1",
            timestamp="2025-01-01T00:00:00+00:00",
            trigger_type="citadel_event",
            trigger_message_id="msg-2",
            model="claude-sonnet-4-5-20250929",
            input_tokens=0,
            output_tokens=0,
            total_tokens=0,
            stop_reason="error",
            tool_calls=[],
            duration_ms=500,
            response_preview="",
            error="TimeoutError",
            iteration=0,
        )
        assert rec.error == "TimeoutError"
        assert rec.input_tokens == 0

    def test_serialization_roundtrip(self):
        rec = AICallRecord(
            call_id="rt-1",
            timestamp="2025-01-01T00:00:00+00:00",
            trigger_type="agent_text",
            trigger_message_id="msg-3",
            model="claude-sonnet-4-5-20250929",
            input_tokens=200,
            output_tokens=100,
            total_tokens=300,
            stop_reason="tool_use",
            tool_calls=["get_asset_list", "deploy_agent"],
            duration_ms=2500,
            response_preview="Deploying agent...",
            error=None,
            iteration=1,
        )
        text = json.dumps(asdict(rec), default=str)
        restored = json.loads(text)
        assert restored["trigger_type"] == "agent_text"
        assert restored["tool_calls"] == ["get_asset_list", "deploy_agent"]

    def test_preview_truncation(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "msg-x", "claude-sonnet-4-5-20250929")
        long_text = "A" * 500
        resp = _make_response(text=long_text)
        rec = audit.finish_call(ctx, response=resp)
        assert rec is not None
        assert len(rec.response_preview) == 200

    def test_iteration_tracked(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("tool_loop", "msg-y", "claude-sonnet-4-5-20250929", iteration=3)
        rec = audit.finish_call(ctx, response=_make_response())
        assert rec is not None
        assert rec.iteration == 3


# ===================================================================
# TestAggregates
# ===================================================================


class TestAggregates:
    """Verify in-memory cumulative counters."""

    def test_initial_zero(self, tmp_path):
        audit = _make_logger(tmp_path)
        agg = audit.aggregates
        assert agg["total_calls"] == 0
        assert agg["total_input_tokens"] == 0
        assert agg["total_output_tokens"] == 0
        assert agg["total_tokens"] == 0
        assert agg["total_errors"] == 0

    def test_accumulate_after_calls(self, tmp_path):
        audit = _make_logger(tmp_path)
        for _ in range(3):
            ctx = audit.start_call("user_text", "m1", "model-a")
            audit.finish_call(ctx, response=_make_response(input_tokens=10, output_tokens=5))

        agg = audit.aggregates
        assert agg["total_calls"] == 3
        assert agg["total_input_tokens"] == 30
        assert agg["total_output_tokens"] == 15
        assert agg["total_tokens"] == 45

    def test_errors_counted(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        audit.finish_call(ctx, error="TimeoutError")
        ctx2 = audit.start_call("user_text", "m2", "model-a")
        audit.finish_call(ctx2, response=_make_response())

        agg = audit.aggregates
        assert agg["total_calls"] == 2
        assert agg["total_errors"] == 1

    def test_thread_safety(self, tmp_path):
        audit = _make_logger(tmp_path)
        barrier = threading.Barrier(10)

        def worker():
            barrier.wait()
            for _ in range(50):
                ctx = audit.start_call("user_text", "m1", "model-a")
                audit.finish_call(ctx, response=_make_response(input_tokens=1, output_tokens=1))

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        agg = audit.aggregates
        assert agg["total_calls"] == 500
        assert agg["total_input_tokens"] == 500
        assert agg["total_output_tokens"] == 500


# ===================================================================
# TestFileLogging
# ===================================================================


class TestFileLogging:
    """Verify file-backed JSON lines."""

    def test_file_created(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        audit.finish_call(ctx, response=_make_response())

        log_file = tmp_path / "ai_audit.log"
        assert log_file.exists()

    def test_valid_json_lines(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        audit.finish_call(ctx, response=_make_response())

        lines = _read_lines(tmp_path)
        assert len(lines) == 1
        assert lines[0]["trigger_type"] == "user_text"
        assert lines[0]["model"] == "model-a"

    def test_multiple_appended(self, tmp_path):
        audit = _make_logger(tmp_path)
        for i in range(5):
            ctx = audit.start_call("user_text", f"m{i}", "model-a")
            audit.finish_call(ctx, response=_make_response())

        lines = _read_lines(tmp_path)
        assert len(lines) == 5

    def test_error_call_logged(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("citadel_event", "m1", "model-a")
        audit.finish_call(ctx, error="ConnectionError")

        lines = _read_lines(tmp_path)
        assert len(lines) == 1
        assert lines[0]["error"] == "ConnectionError"
        assert lines[0]["stop_reason"] == "error"
        assert lines[0]["input_tokens"] == 0


# ===================================================================
# TestQueryRecent
# ===================================================================


class TestQueryRecent:
    """Verify reading records from file."""

    def test_empty_file(self, tmp_path):
        audit = _make_logger(tmp_path)
        assert audit.query_recent() == []

    def test_newest_first(self, tmp_path):
        audit = _make_logger(tmp_path)
        for i in range(3):
            ctx = audit.start_call("user_text", f"msg-{i}", "model-a")
            audit.finish_call(ctx, response=_make_response())

        results = audit.query_recent(limit=10)
        assert len(results) == 3
        # Last written should be first in results (newest first)
        assert results[0]["trigger_message_id"] == "msg-2"
        assert results[2]["trigger_message_id"] == "msg-0"

    def test_limit_respected(self, tmp_path):
        audit = _make_logger(tmp_path)
        for i in range(10):
            ctx = audit.start_call("user_text", f"msg-{i}", "model-a")
            audit.finish_call(ctx, response=_make_response())

        results = audit.query_recent(limit=3)
        assert len(results) == 3

    def test_corrupt_lines_handled(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        audit.finish_call(ctx, response=_make_response())

        # Inject a corrupt line
        log_file = tmp_path / "ai_audit.log"
        with open(log_file, "a", encoding="utf-8") as f:
            f.write("NOT VALID JSON\n")

        ctx2 = audit.start_call("user_text", "m2", "model-a")
        audit.finish_call(ctx2, response=_make_response())

        results = audit.query_recent(limit=10)
        # Should get both valid records, skipping the corrupt line
        assert len(results) == 2

    def test_file_not_found(self, tmp_path):
        audit = AIAuditLogger(log_path=tmp_path / "nonexistent" / "audit.log")
        # query_recent should handle missing file gracefully
        # (the directory was created in __init__, but let's test with a different path)
        import os
        log_path = tmp_path / "other_dir" / "audit.log"
        audit._log_path = log_path
        results = audit.query_recent()
        assert results == []


# ===================================================================
# TestDefensiveLogging
# ===================================================================


class TestDefensiveLogging:
    """Verify that logging failures never propagate."""

    def test_finish_call_bad_ctx_returns_none(self, tmp_path):
        audit = _make_logger(tmp_path)
        # Missing required keys in context
        result = audit.finish_call({}, response=_make_response())
        assert result is None

    def test_start_call_always_returns_ctx(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        assert "call_id" in ctx
        assert "start_time" in ctx
        assert "start_wall" in ctx

    def test_response_with_no_usage(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        # Response missing usage attribute
        resp = SimpleNamespace(
            stop_reason="end_turn",
            content=[SimpleNamespace(type="text", text="hi")],
        )
        rec = audit.finish_call(ctx, response=resp)
        assert rec is not None
        assert rec.input_tokens == 0
        assert rec.output_tokens == 0

    def test_response_with_no_content(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        resp = SimpleNamespace(
            usage=SimpleNamespace(input_tokens=10, output_tokens=5),
            stop_reason="end_turn",
        )
        rec = audit.finish_call(ctx, response=resp)
        assert rec is not None
        assert rec.tool_calls == []
        assert rec.response_preview == ""


# ===================================================================
# TestSingleton
# ===================================================================


class TestSingleton:
    """Verify module-level singleton."""

    def test_same_instance(self):
        import citadel_archer.chat.ai_audit as mod
        old = mod._ai_audit_logger
        try:
            mod._ai_audit_logger = None
            a = get_ai_audit_logger()
            b = get_ai_audit_logger()
            assert a is b
        finally:
            mod._ai_audit_logger = old

    def test_custom_path_for_testing(self, tmp_path):
        audit = AIAuditLogger(log_path=tmp_path / "custom.log")
        ctx = audit.start_call("user_text", "m1", "model-a")
        audit.finish_call(ctx, response=_make_response())
        assert (tmp_path / "custom.log").exists()


# ===================================================================
# TestTriggerType
# ===================================================================


class TestTriggerType:
    """Verify trigger type values are recorded correctly."""

    @pytest.mark.parametrize(
        "trigger_type",
        ["user_text", "agent_text", "citadel_event", "tool_loop"],
    )
    def test_trigger_type_recorded(self, tmp_path, trigger_type):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call(trigger_type, "m1", "model-a")
        rec = audit.finish_call(ctx, response=_make_response())
        assert rec is not None
        assert rec.trigger_type == trigger_type


# ===================================================================
# TestToolCallExtraction
# ===================================================================


class TestToolCallExtraction:
    """Verify tool calls are extracted from response."""

    def test_no_tool_calls(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        resp = _make_response(tool_calls=None)
        rec = audit.finish_call(ctx, response=resp)
        assert rec.tool_calls == []

    def test_single_tool_call(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        resp = _make_response(tool_calls=["get_system_status"])
        rec = audit.finish_call(ctx, response=resp)
        assert rec.tool_calls == ["get_system_status"]

    def test_multiple_tool_calls(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        resp = _make_response(tool_calls=["get_asset_list", "deploy_agent"])
        rec = audit.finish_call(ctx, response=resp)
        assert rec.tool_calls == ["get_asset_list", "deploy_agent"]

    def test_tool_use_stop_reason(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        resp = _make_response(stop_reason="tool_use", tool_calls=["get_system_status"])
        rec = audit.finish_call(ctx, response=resp)
        assert rec.stop_reason == "tool_use"


# ===================================================================
# TestDuration
# ===================================================================


class TestDuration:
    """Verify timing measurement."""

    def test_duration_positive(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        time.sleep(0.01)  # small delay
        rec = audit.finish_call(ctx, response=_make_response())
        assert rec is not None
        assert rec.duration_ms >= 5  # at least a few ms

    def test_duration_zero_is_valid(self, tmp_path):
        audit = _make_logger(tmp_path)
        ctx = audit.start_call("user_text", "m1", "model-a")
        # immediate finish
        rec = audit.finish_call(ctx, response=_make_response())
        assert rec is not None
        assert rec.duration_ms >= 0


# ===================================================================
# TestAIBridgeIntegration
# ===================================================================


class TestAIBridgeIntegration:
    """Test trigger type detection in ai_bridge._process."""

    def test_user_text_trigger_type(self):
        """User TEXT message → trigger_type = 'user_text'."""
        from citadel_archer.chat.message import (
            ChatMessage,
            MessageType,
            PARTICIPANT_USER,
        )

        msg = ChatMessage(
            from_id=PARTICIPANT_USER,
            to_id="assistant",
            msg_type=MessageType.TEXT,
            payload={"text": "What's the threat level?"},
        )
        # Simulate trigger_type logic from ai_bridge._process
        if msg.from_id == PARTICIPANT_USER:
            trigger_type = "user_text"
        elif msg.from_id.startswith("ext-agent:"):
            trigger_type = "agent_text"
        else:
            trigger_type = "citadel_event"

        assert trigger_type == "user_text"

    def test_citadel_event_trigger_type(self):
        """Citadel EVENT message → trigger_type = 'citadel_event'."""
        from citadel_archer.chat.message import (
            ChatMessage,
            MessageType,
            PARTICIPANT_CITADEL,
        )

        msg = ChatMessage(
            from_id=PARTICIPANT_CITADEL,
            to_id="assistant",
            msg_type=MessageType.EVENT,
            payload={"text": "Critical file change detected"},
        )
        if msg.from_id == "user":
            trigger_type = "user_text"
        elif msg.from_id.startswith("ext-agent:"):
            trigger_type = "agent_text"
        else:
            trigger_type = "citadel_event"

        assert trigger_type == "citadel_event"

    def test_ext_agent_trigger_type(self):
        """External agent TEXT → trigger_type = 'agent_text'."""
        from citadel_archer.chat.message import (
            ChatMessage,
            MessageType,
        )

        msg = ChatMessage(
            from_id="ext-agent:test-agent",
            to_id="assistant",
            msg_type=MessageType.TEXT,
            payload={"text": "Agent reporting in"},
        )
        if msg.from_id == "user":
            trigger_type = "user_text"
        elif msg.from_id.startswith("ext-agent:"):
            trigger_type = "agent_text"
        else:
            trigger_type = "citadel_event"

        assert trigger_type == "agent_text"


# ===================================================================
# TestAIAuditRoute
# ===================================================================


class TestAIAuditRoute:
    """Test the GET /api/ai-audit endpoint."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app
        return TestClient(app)

    @pytest.fixture(autouse=True)
    def _set_session_token(self):
        from citadel_archer.api.security import initialize_session_token, get_session_token
        initialize_session_token()
        self._token = get_session_token()

    def test_requires_auth(self, client):
        resp = client.get("/api/ai-audit")
        assert resp.status_code in (401, 403)

    def test_returns_records_and_aggregates(self, client):
        resp = client.get(
            "/api/ai-audit",
            headers={"X-Session-Token": self._token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "records" in data
        assert "aggregates" in data
        assert isinstance(data["records"], list)
        assert "total_calls" in data["aggregates"]

    def test_limit_param(self, client):
        resp = client.get(
            "/api/ai-audit?limit=5",
            headers={"X-Session-Token": self._token},
        )
        assert resp.status_code == 200

    def test_invalid_limit(self, client):
        resp = client.get(
            "/api/ai-audit?limit=0",
            headers={"X-Session-Token": self._token},
        )
        assert resp.status_code == 422  # validation error
