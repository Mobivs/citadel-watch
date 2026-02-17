"""
Tests for AI Bridge Trigger 1b — External AI Agent Messages.

Verifies:
- ext-agent TEXT triggers AI Bridge (needs_ai = True)
- ext-agent COMMAND does NOT trigger
- ext-agent EVENT does NOT trigger AI Bridge
- History labels external agent correctly
- Existing triggers unaffected (regression)
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_ASSISTANT,
    PARTICIPANT_CITADEL,
    PARTICIPANT_USER,
)


# ── Helpers ───────────────────────────────────────────────────────────


def _make_msg(from_id, msg_type, text="test", payload_extra=None):
    """Build a ChatMessage for testing."""
    payload = {"text": text}
    if payload_extra:
        payload.update(payload_extra)
    return ChatMessage(
        from_id=from_id,
        to_id=PARTICIPANT_CITADEL,
        msg_type=msg_type,
        payload=payload,
    )


def _get_bridge():
    """Create an AIBridge with mocked dependencies."""
    from citadel_archer.chat.ai_bridge import AIBridge

    bridge = AIBridge.__new__(AIBridge)
    bridge._chat = MagicMock()
    bridge._chat.get_recent = MagicMock(return_value=[])
    bridge._api_key = "test-key"
    bridge._model = "test-model"
    bridge._system_prompt = "test"
    bridge._processing = False
    bridge._pending_msg = None
    bridge._tools = []
    bridge._aggregator = None
    bridge._inventory = None
    bridge._shield_db = None
    return bridge


# ── Trigger Tests ─────────────────────────────────────────────────────


class TestExtAgentTrigger:
    @pytest.mark.asyncio
    async def test_ext_agent_text_triggers_ai(self):
        """ext-agent:* + TEXT → needs_ai = True → creates processing task."""
        bridge = _get_bridge()
        msg = _make_msg(
            "ext-agent:abc123",
            MessageType.TEXT,
            "Desktop agent is offline, should I activate defense?",
            {"agent_name": "Forge", "agent_type": "forge"},
        )

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_ext_agent_command_does_not_trigger(self):
        """ext-agent:* + COMMAND → needs_ai = False."""
        bridge = _get_bridge()
        msg = _make_msg("ext-agent:abc123", MessageType.COMMAND, "/status")

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_not_called()

    @pytest.mark.asyncio
    async def test_ext_agent_event_does_not_trigger(self):
        """ext-agent:* + EVENT → needs_ai = False (no critical/high keyword check for ext-agents)."""
        bridge = _get_bridge()
        msg = _make_msg("ext-agent:abc123", MessageType.EVENT, "Info event")

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_not_called()


# ── Regression Tests ──────────────────────────────────────────────────


class TestExistingTriggersUnaffected:
    @pytest.mark.asyncio
    async def test_user_text_still_triggers(self):
        """Trigger 1a: user TEXT → needs_ai = True (regression)."""
        bridge = _get_bridge()
        msg = _make_msg(PARTICIPANT_USER, MessageType.TEXT, "What's the threat level?")

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_citadel_critical_event_still_triggers(self):
        """Trigger 2a-c/3a: citadel EVENT with 'critical' → needs_ai = True (regression)."""
        bridge = _get_bridge()
        msg = _make_msg(
            PARTICIPANT_CITADEL,
            MessageType.EVENT,
            "[Local Guardian] 3 critical/high events",
        )

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_called_once()

    @pytest.mark.asyncio
    async def test_citadel_info_event_does_not_trigger(self):
        """citadel EVENT without critical/high → needs_ai = False (regression)."""
        bridge = _get_bridge()
        msg = _make_msg(
            PARTICIPANT_CITADEL,
            MessageType.EVENT,
            "Heartbeat received from agent",
        )

        with patch("asyncio.create_task") as mock_task:
            await bridge._on_message(msg)
            mock_task.assert_not_called()


# ── History Labeling ──────────────────────────────────────────────────


class TestHistoryLabeling:
    def test_ext_agent_labeled_with_name(self):
        """ext-agent messages should be labeled as 'ExtAgent <name>' in history."""
        bridge = _get_bridge()
        msg = _make_msg(
            "ext-agent:abc123",
            MessageType.TEXT,
            "Should I enable defense mode?",
            {"agent_name": "Forge-1", "agent_type": "forge"},
        )
        bridge._chat.get_recent = MagicMock(return_value=[msg])

        history = bridge._build_history()
        assert len(history) >= 1
        # Find the ext-agent message
        found = False
        for entry in history:
            if "ExtAgent Forge-1" in entry["content"]:
                found = True
                break
        assert found, f"Expected 'ExtAgent Forge-1' label in history: {history}"

    def test_ext_agent_fallback_label_without_name(self):
        """If agent_name missing from payload, fall back to agent_id."""
        bridge = _get_bridge()
        msg = _make_msg(
            "ext-agent:abc123def",
            MessageType.TEXT,
            "Hello from agent",
        )
        # Remove agent_name from payload
        msg.payload.pop("agent_name", None)
        bridge._chat.get_recent = MagicMock(return_value=[msg])

        history = bridge._build_history()
        found = False
        for entry in history:
            if "ExtAgent abc123def" in entry["content"]:
                found = True
                break
        assert found, f"Expected 'ExtAgent abc123def' fallback label in history: {history}"

    def test_regular_agent_label_unchanged(self):
        """agent:* messages still labeled as 'Agent <id>' (regression)."""
        bridge = _get_bridge()
        msg = _make_msg(
            "agent:vps-001",
            MessageType.EVENT,
            "Threat detected",
        )
        bridge._chat.get_recent = MagicMock(return_value=[msg])

        history = bridge._build_history()
        found = False
        for entry in history:
            if "Agent vps-001" in entry["content"]:
                found = True
                break
        assert found, f"Expected 'Agent vps-001' label in history: {history}"
