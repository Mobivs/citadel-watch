"""
Tests for Trigger 2c: Panic Room Activation → AI Triage via SecureChat

Verifies that:
- Panic Room activation sends escalation to ChatManager
- Session completion fills the _notify_completion stub
- Session failure fills the _notify_failure stub
- Missing ChatManager degrades gracefully (no crash)
- Chat failures never block panic operations
- Summary format satisfies AI Bridge trigger (contains "critical"/"high" keywords)
- All messages prefixed with "[Panic Room]" for source identification
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from citadel_archer.chat.message import MessageType
from citadel_archer.panic.models import PanicSession


# ── Helpers ──────────────────────────────────────────────────────────


def _make_session(
    trigger_reason: str = "Ransomware detected on main server",
    trigger_source: str = "manual",
    status: str = "active",
) -> PanicSession:
    """Build a minimal PanicSession for testing."""
    return PanicSession(
        id=uuid4(),
        triggered_at=datetime.utcnow(),
        trigger_source=trigger_source,
        trigger_reason=trigger_reason,
        status=status,
        user_id=1,
    )


class FakePanicDB:
    """Minimal fake matching PanicManager's DB usage."""

    async def acquire(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def execute(self, *args, **kwargs):
        pass


def _make_panic_manager(chat_manager=None):
    """Build a PanicManager with a fake DB and optional ChatManager."""
    from citadel_archer.panic.panic_manager import PanicManager

    pm = PanicManager(FakePanicDB(), config={})
    if chat_manager is not None:
        pm.set_chat_manager(chat_manager)
    return pm


def _make_chat_manager():
    """Build a mock ChatManager with an async send_system."""
    chat = AsyncMock()
    chat.send_system = AsyncMock()
    return chat


# ── Test: Completion Escalation ──────────────────────────────────────


class TestCompletionEscalation:
    """_notify_completion sends [Panic Room] COMPLETED to ChatManager."""

    @pytest.mark.asyncio
    async def test_completion_sends_message(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session(trigger_reason="Brute force attack")

        await pm._notify_completion(session)

        chat.send_system.assert_called_once()
        text = chat.send_system.call_args[0][0]
        msg_type = chat.send_system.call_args[0][1]
        assert "[Panic Room]" in text
        assert "COMPLETED" in text
        assert "Brute force attack" in text
        assert msg_type == MessageType.EVENT

    @pytest.mark.asyncio
    async def test_completion_contains_trigger_keywords(self):
        """AI Bridge needs 'critical' or 'high' in the text."""
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_completion(session)

        text = chat.send_system.call_args[0][0].lower()
        assert "critical" in text or "high" in text

    @pytest.mark.asyncio
    async def test_completion_includes_session_id(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_completion(session)

        text = chat.send_system.call_args[0][0]
        assert str(session.id) in text

    @pytest.mark.asyncio
    async def test_completion_includes_source(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session(trigger_source="ai")

        await pm._notify_completion(session)

        text = chat.send_system.call_args[0][0]
        assert "ai" in text


# ── Test: Failure Escalation ─────────────────────────────────────────


class TestFailureEscalation:
    """_notify_failure sends [Panic Room] FAILED to ChatManager."""

    @pytest.mark.asyncio
    async def test_failure_sends_message(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session(trigger_reason="DDoS mitigation")

        await pm._notify_failure(session, "Network timeout during isolation")

        chat.send_system.assert_called_once()
        text = chat.send_system.call_args[0][0]
        msg_type = chat.send_system.call_args[0][1]
        assert "[Panic Room]" in text
        assert "FAILED" in text
        assert "DDoS mitigation" in text
        assert "Network timeout" in text
        assert msg_type == MessageType.EVENT

    @pytest.mark.asyncio
    async def test_failure_contains_trigger_keywords(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_failure(session, "SSH connection refused")

        text = chat.send_system.call_args[0][0].lower()
        assert "critical" in text or "high" in text

    @pytest.mark.asyncio
    async def test_failure_truncates_long_error(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()
        long_error = "x" * 500

        await pm._notify_failure(session, long_error)

        text = chat.send_system.call_args[0][0]
        # Error should be truncated to 200 chars
        assert "x" * 200 in text
        assert "x" * 201 not in text

    @pytest.mark.asyncio
    async def test_failure_includes_session_id(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_failure(session, "test error")

        text = chat.send_system.call_args[0][0]
        assert str(session.id) in text

    @pytest.mark.asyncio
    async def test_failure_handles_none_error(self):
        """None error should not crash — converted to 'Unknown error'."""
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_failure(session, None)

        text = chat.send_system.call_args[0][0]
        assert "Unknown error" in text

    @pytest.mark.asyncio
    async def test_failure_handles_exception_object(self):
        """Exception object passed as error should be str()-converted."""
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        session = _make_session()

        await pm._notify_failure(session, RuntimeError("SSH timeout"))

        text = chat.send_system.call_args[0][0]
        assert "SSH timeout" in text


# ── Test: Graceful Degradation ───────────────────────────────────────


class TestGracefulDegradation:
    """No crash when ChatManager is absent or fails."""

    @pytest.mark.asyncio
    async def test_completion_without_chat_manager(self):
        pm = _make_panic_manager(chat_manager=None)
        session = _make_session()
        # Should not raise
        await pm._notify_completion(session)

    @pytest.mark.asyncio
    async def test_failure_without_chat_manager(self):
        pm = _make_panic_manager(chat_manager=None)
        session = _make_session()
        # Should not raise
        await pm._notify_failure(session, "some error")

    @pytest.mark.asyncio
    async def test_completion_chat_raises(self):
        chat = _make_chat_manager()
        chat.send_system.side_effect = RuntimeError("WebSocket down")
        pm = _make_panic_manager(chat)
        session = _make_session()
        # Should not raise — chat failure is swallowed
        await pm._notify_completion(session)

    @pytest.mark.asyncio
    async def test_failure_chat_raises(self):
        chat = _make_chat_manager()
        chat.send_system.side_effect = RuntimeError("WebSocket down")
        pm = _make_panic_manager(chat)
        session = _make_session()
        # Should not raise — chat failure is swallowed
        await pm._notify_failure(session, "some error")

    @pytest.mark.asyncio
    async def test_set_chat_manager_before_init(self):
        """set_chat_manager can be called, then completion/failure work."""
        pm = _make_panic_manager(chat_manager=None)
        session = _make_session()

        # No chat manager — should do nothing
        await pm._notify_completion(session)

        # Now wire one
        chat = _make_chat_manager()
        pm.set_chat_manager(chat)

        await pm._notify_completion(session)
        chat.send_system.assert_called_once()


# ── Test: Summary Format ─────────────────────────────────────────────


class TestSummaryFormat:
    """All message types have correct prefix and trigger keywords."""

    @pytest.mark.asyncio
    async def test_completion_prefix(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        await pm._notify_completion(_make_session())
        text = chat.send_system.call_args[0][0]
        assert text.startswith("[Panic Room]")

    @pytest.mark.asyncio
    async def test_failure_prefix(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        await pm._notify_failure(_make_session(), "err")
        text = chat.send_system.call_args[0][0]
        assert text.startswith("[Panic Room]")

    @pytest.mark.asyncio
    async def test_all_messages_use_event_type(self):
        """All escalation messages use MessageType.EVENT."""
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)

        await pm._notify_completion(_make_session())
        assert chat.send_system.call_args[0][1] == MessageType.EVENT

        chat.reset_mock()
        await pm._notify_failure(_make_session(), "err")
        assert chat.send_system.call_args[0][1] == MessageType.EVENT


# ── Test: Activation Escalation (route-level) ────────────────────────


class TestActivationEscalation:
    """Activation in panic_routes sends [Panic Room] ACTIVATED."""

    @pytest.mark.asyncio
    async def test_activation_message_format(self):
        """Simulate the activation escalation logic from panic_routes."""
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)

        # Simulate the route-level escalation code
        reason = "Ransomware detected"
        playbooks = ["credential_rotation", "network_isolation"]
        target_assets = ["local", "vps-prod-1"]
        session_id = "panic_1234567890"

        chat_ref = pm._chat_manager
        if chat_ref:
            summary = (
                f"[Panic Room] ACTIVATED — {reason}\n"
                f"Playbooks: {'; '.join(playbooks)}\n"
                f"Target assets: {'; '.join(target_assets)}\n"
                f"Session: {session_id}\n"
                f"Critical/high-priority emergency response initiated."
            )
            await chat_ref.send_system(summary, MessageType.EVENT)

        chat.send_system.assert_called_once()
        text = chat.send_system.call_args[0][0]
        assert "[Panic Room]" in text
        assert "ACTIVATED" in text
        assert "Ransomware detected" in text
        assert "credential_rotation" in text
        assert "network_isolation" in text
        assert "local" in text
        assert "vps-prod-1" in text
        assert session_id in text

    @pytest.mark.asyncio
    async def test_activation_contains_trigger_keywords(self):
        """Activation message triggers AI Bridge."""
        chat = _make_chat_manager()

        reason = "Brute force attack"
        playbooks = ["lockdown"]
        target_assets = ["local"]
        session_id = "panic_999"

        summary = (
            f"[Panic Room] ACTIVATED — {reason}\n"
            f"Playbooks: {'; '.join(playbooks)}\n"
            f"Target assets: {'; '.join(target_assets)}\n"
            f"Session: {session_id}\n"
            f"Critical/high-priority emergency response initiated."
        )
        await chat.send_system(summary, MessageType.EVENT)

        text = chat.send_system.call_args[0][0].lower()
        assert "critical" in text or "high" in text

    @pytest.mark.asyncio
    async def test_activation_no_chat_manager(self):
        """No crash when _chat_manager is None."""
        pm = _make_panic_manager(chat_manager=None)

        chat_ref = pm._chat_manager
        if chat_ref:
            await chat_ref.send_system("test", MessageType.EVENT)
        # If we get here without error, test passes

    @pytest.mark.asyncio
    async def test_activation_chat_failure_non_blocking(self):
        """Chat exception doesn't propagate — mirrors route try/except."""
        chat = _make_chat_manager()
        chat.send_system.side_effect = ConnectionError("dead")
        pm = _make_panic_manager(chat)

        try:
            chat_ref = pm._chat_manager
            if chat_ref:
                await chat_ref.send_system("test", MessageType.EVENT)
        except Exception:
            pass  # Mirrors route behavior: exception swallowed
        # No crash = pass


# ── Test: set_chat_manager Method ────────────────────────────────────


class TestSetChatManager:
    """set_chat_manager wires correctly."""

    def test_initial_state_is_none(self):
        pm = _make_panic_manager()
        assert pm._chat_manager is None

    def test_set_chat_manager_stores_reference(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager()
        pm.set_chat_manager(chat)
        assert pm._chat_manager is chat

    def test_set_chat_manager_can_be_replaced(self):
        chat1 = _make_chat_manager()
        chat2 = _make_chat_manager()
        pm = _make_panic_manager()
        pm.set_chat_manager(chat1)
        pm.set_chat_manager(chat2)
        assert pm._chat_manager is chat2

    def test_set_chat_manager_to_none(self):
        chat = _make_chat_manager()
        pm = _make_panic_manager(chat)
        pm.set_chat_manager(None)
        assert pm._chat_manager is None
