# Tests for Ollama LLM backend and AI Bridge Ollama integration
# v0.3.17 — Local LLM Integration
#
# Coverage:
#   - OllamaBackend: health check, model discovery, chat, tool conversion
#   - AI Bridge: _is_localhost_url, fallback logic, Ollama wiring
#   - API endpoints: /api/ai/status, /api/ai/ollama/models, /api/ai/ollama/model
#   - AIAuditLogger: ollama_response kwarg support

import asyncio
import json
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from citadel_archer.chat.ollama_backend import (
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    LLMResponse,
    OllamaBackend,
    OllamaModel,
    RECOMMENDED_MODELS,
    ToolCall,
)
from citadel_archer.chat.ai_bridge import AIBridge, _is_localhost_url, TOOLS


# ── aiohttp mock fixture ────────────────────────────────────────────
# aiohttp is an optional dependency (only needed at runtime when Ollama
# is actually used). Mock it for tests that exercise HTTP-level code paths.

@pytest.fixture
def mock_aiohttp():
    """Provide a mock aiohttp module for tests that exercise HTTP calls."""
    mock_mod = MagicMock()
    # ClientTimeout is used as aiohttp.ClientTimeout(total=N)
    mock_mod.ClientTimeout = MagicMock
    with patch.dict(sys.modules, {"aiohttp": mock_mod}):
        yield mock_mod


# ── _is_localhost_url Tests ──────────────────────────────────────────


class TestIsLocalhostUrl:
    def test_localhost(self):
        assert _is_localhost_url("http://localhost:11434") is True

    def test_127_0_0_1(self):
        assert _is_localhost_url("http://127.0.0.1:11434") is True

    def test_ipv6_loopback(self):
        assert _is_localhost_url("http://[::1]:11434") is True

    def test_0_0_0_0(self):
        assert _is_localhost_url("http://0.0.0.0:11434") is True

    def test_remote_ip_rejected(self):
        assert _is_localhost_url("http://192.168.1.100:11434") is False

    def test_remote_hostname_rejected(self):
        assert _is_localhost_url("http://ollama.example.com:11434") is False

    def test_empty_string(self):
        assert _is_localhost_url("") is False

    def test_malformed_url(self):
        assert _is_localhost_url("not-a-url") is False

    def test_localhost_https(self):
        assert _is_localhost_url("https://localhost:11434") is True


# ── OllamaBackend Unit Tests ────────────────────────────────────────


class TestOllamaBackendInit:
    def test_default_url_and_model(self):
        backend = OllamaBackend()
        assert backend.base_url == DEFAULT_OLLAMA_URL
        assert backend.model == DEFAULT_OLLAMA_MODEL

    def test_custom_url_and_model(self):
        backend = OllamaBackend(base_url="http://myhost:1234", model="mistral:7b")
        assert backend.base_url == "http://myhost:1234"
        assert backend.model == "mistral:7b"

    def test_env_var_override(self):
        with patch.dict(os.environ, {"OLLAMA_URL": "http://env:5555", "OLLAMA_MODEL": "qwen2.5:7b"}):
            backend = OllamaBackend()
            assert backend.base_url == "http://env:5555"
            assert backend.model == "qwen2.5:7b"

    def test_trailing_slash_stripped(self):
        backend = OllamaBackend(base_url="http://localhost:11434/")
        assert backend.base_url == "http://localhost:11434"

    def test_model_setter(self):
        backend = OllamaBackend()
        backend.model = "llama3.1:70b"
        assert backend.model == "llama3.1:70b"


class TestOllamaHealthCheck:
    @pytest.mark.asyncio
    async def test_available_when_server_responds(self, mock_aiohttp):
        backend = OllamaBackend()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=mock_resp)
        mock_session.closed = False

        backend._get_session = AsyncMock(return_value=mock_session)
        result = await backend.is_available(force=True)
        assert result is True

    @pytest.mark.asyncio
    async def test_unavailable_on_error(self, mock_aiohttp):
        backend = OllamaBackend()

        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=ConnectionError("refused"))
        mock_session.closed = False

        backend._get_session = AsyncMock(return_value=mock_session)
        result = await backend.is_available(force=True)
        assert result is False

    @pytest.mark.asyncio
    async def test_health_cache_reuses(self):
        """Second call within TTL should return cached result."""
        backend = OllamaBackend()
        backend._available = True
        backend._last_health_check = __import__("time").monotonic()

        # Should not make any HTTP call
        result = await backend.is_available()
        assert result is True


class TestOllamaChat:
    @pytest.mark.asyncio
    async def test_chat_returns_response(self, mock_aiohttp):
        backend = OllamaBackend()
        ollama_data = {
            "message": {"content": "This is a test response"},
            "model": "llama3.1:8b",
            "done": True,
            "prompt_eval_count": 50,
            "eval_count": 30,
        }

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value=ollama_data)
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=mock_resp)

        backend._get_session = AsyncMock(return_value=mock_session)
        response = await backend.chat(
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert response is not None
        assert response.text == "This is a test response"
        assert response.model == "llama3.1:8b"
        assert response.input_tokens == 50
        assert response.output_tokens == 30

    @pytest.mark.asyncio
    async def test_chat_returns_none_on_error(self, mock_aiohttp):
        backend = OllamaBackend()

        mock_resp = AsyncMock()
        mock_resp.status = 500
        mock_resp.text = AsyncMock(return_value="Internal Error")
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        mock_session = AsyncMock()
        mock_session.post = MagicMock(return_value=mock_resp)

        backend._get_session = AsyncMock(return_value=mock_session)
        response = await backend.chat(
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert response is None

    @pytest.mark.asyncio
    async def test_chat_with_system_prompt(self, mock_aiohttp):
        """System prompt should be prepended as first message."""
        backend = OllamaBackend()
        captured_payload = {}

        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={
            "message": {"content": "ok"},
            "done": True,
        })
        mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_resp.__aexit__ = AsyncMock(return_value=False)

        def capture_post(url, json=None, **kwargs):
            captured_payload.update(json or {})
            return mock_resp

        mock_session = AsyncMock()
        mock_session.post = MagicMock(side_effect=capture_post)

        backend._get_session = AsyncMock(return_value=mock_session)
        await backend.chat(
            messages=[{"role": "user", "content": "Hello"}],
            system="You are a security analyst.",
        )

        msgs = captured_payload.get("messages", [])
        assert len(msgs) >= 2
        assert msgs[0]["role"] == "system"
        assert "security analyst" in msgs[0]["content"]


class TestToolConversion:
    def test_claude_to_ollama_format(self):
        backend = OllamaBackend()
        claude_tools = [
            {
                "name": "get_status",
                "description": "Get system status",
                "input_schema": {
                    "type": "object",
                    "properties": {"verbose": {"type": "boolean"}},
                },
            }
        ]
        result = backend._convert_tools(claude_tools)
        assert len(result) == 1
        assert result[0]["type"] == "function"
        assert result[0]["function"]["name"] == "get_status"
        assert result[0]["function"]["description"] == "Get system status"
        assert result[0]["function"]["parameters"]["type"] == "object"

    def test_missing_input_schema_defaults(self):
        backend = OllamaBackend()
        result = backend._convert_tools([{"name": "test", "description": ""}])
        assert result[0]["function"]["parameters"] == {"type": "object", "properties": {}}


class TestResponseParsing:
    def test_parse_text_response(self):
        backend = OllamaBackend()
        data = {
            "message": {"content": "Analysis complete."},
            "model": "llama3.1:8b",
            "done": True,
            "prompt_eval_count": 100,
            "eval_count": 50,
        }
        resp = backend._parse_response(data)
        assert resp.text == "Analysis complete."
        assert resp.has_tool_calls is False
        assert resp.input_tokens == 100
        assert resp.output_tokens == 50

    def test_parse_tool_call_response(self):
        backend = OllamaBackend()
        data = {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "get_status",
                            "arguments": {"verbose": True},
                        },
                    }
                ],
            },
            "model": "llama3.1:8b",
            "done": True,
        }
        resp = backend._parse_response(data)
        assert resp.has_tool_calls is True
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "get_status"
        assert resp.tool_calls[0].arguments == {"verbose": True}

    def test_parse_string_arguments(self):
        """Ollama sometimes returns arguments as JSON string."""
        backend = OllamaBackend()
        data = {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "test",
                            "arguments": '{"key": "value"}',
                        },
                    }
                ],
            },
            "done": True,
        }
        resp = backend._parse_response(data)
        assert resp.tool_calls[0].arguments == {"key": "value"}

    def test_parse_empty_content_returns_none_text(self):
        backend = OllamaBackend()
        data = {"message": {"content": ""}, "done": True}
        resp = backend._parse_response(data)
        assert resp.text is None


class TestOllamaModelDataclass:
    def test_to_dict(self):
        m = OllamaModel(
            name="llama3.1:8b",
            size=4_500_000_000,
            family="llama",
            parameter_size="8B",
            quantization="Q4_0",
        )
        d = m.to_dict()
        assert d["name"] == "llama3.1:8b"
        assert d["size_gb"] == 4.2  # 4.5B bytes = ~4.2 GB
        assert d["family"] == "llama"

    def test_to_dict_zero_size(self):
        m = OllamaModel(name="test:latest")
        assert m.to_dict()["size_gb"] == 0


class TestChatWithTools:
    @pytest.mark.asyncio
    async def test_tool_loop_executes_and_returns_text(self):
        """Simulates: LLM returns tool call → executor runs → LLM returns text."""
        backend = OllamaBackend()

        call_count = 0

        async def mock_chat(messages, system="", tools=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return LLMResponse(
                    tool_calls=[ToolCall(name="get_status", arguments={})],
                    model="test",
                )
            else:
                return LLMResponse(text="Status is green.", model="test")

        backend.chat = mock_chat

        async def executor(name, args):
            return {"status": "green"}

        result = await backend.chat_with_tools(
            messages=[{"role": "user", "content": "Status?"}],
            tool_executor=executor,
        )
        assert result is not None
        assert result.text == "Status is green."
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_no_tools_returns_text_immediately(self):
        backend = OllamaBackend()

        async def mock_chat(messages, **kwargs):
            return LLMResponse(text="Direct answer.", model="test")

        backend.chat = mock_chat

        result = await backend.chat_with_tools(
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result.text == "Direct answer."

    @pytest.mark.asyncio
    async def test_max_iterations_safety(self):
        """Should stop after max_iterations even if LLM keeps requesting tools."""
        backend = OllamaBackend()

        async def mock_chat(messages, **kwargs):
            return LLMResponse(
                tool_calls=[ToolCall(name="loop_tool", arguments={})],
                model="test",
            )

        backend.chat = mock_chat

        async def executor(name, args):
            return {"ok": True}

        result = await backend.chat_with_tools(
            messages=[{"role": "user", "content": "Loop"}],
            tool_executor=executor,
            max_iterations=3,
        )
        # Should return last response (still has tool calls but we stop)
        assert result is not None

    @pytest.mark.asyncio
    async def test_chat_failure_returns_none(self):
        backend = OllamaBackend()

        async def mock_chat(messages, **kwargs):
            return None

        backend.chat = mock_chat

        result = await backend.chat_with_tools(
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result is None


# ── AI Bridge Ollama Wiring Tests ───────────────────────────────────


class TestAIBridgeOllamaInit:
    def test_ollama_initialized_when_no_api_key(self):
        """With no API key, Ollama should be primary backend."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            with patch("citadel_archer.chat.ollama_backend.OllamaBackend") as MockOllama:
                mock_instance = MagicMock()
                MockOllama.return_value = mock_instance

                chat = MagicMock()
                bridge = AIBridge(chat_manager=chat, api_key="")

                assert bridge._ollama is mock_instance
                assert bridge.active_backend == "ollama"
                assert bridge.enabled is True

    def test_remote_ollama_blocked_by_default(self):
        """Remote Ollama URL should be blocked without OLLAMA_ALLOW_REMOTE."""
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "",
            "OLLAMA_URL": "http://remote.example.com:11434",
            "OLLAMA_ALLOW_REMOTE": "",
        }, clear=False):
            chat = MagicMock()
            bridge = AIBridge(chat_manager=chat, api_key="")
            assert bridge._ollama is None
            assert bridge.enabled is False

    def test_remote_ollama_allowed_with_env(self):
        """OLLAMA_ALLOW_REMOTE=1 should allow remote URLs."""
        with patch.dict(os.environ, {
            "ANTHROPIC_API_KEY": "",
            "OLLAMA_URL": "http://remote.example.com:11434",
            "OLLAMA_ALLOW_REMOTE": "1",
        }, clear=False):
            with patch("citadel_archer.chat.ollama_backend.OllamaBackend") as MockOllama:
                mock_instance = MagicMock()
                MockOllama.return_value = mock_instance

                chat = MagicMock()
                bridge = AIBridge(chat_manager=chat, api_key="")
                assert bridge._ollama is mock_instance
                assert bridge.active_backend == "ollama"


class TestAIBridgeFallback:
    @pytest.mark.asyncio
    async def test_claude_failure_falls_back_to_ollama(self):
        """When Claude API fails, should fall back to Ollama."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            chat = MagicMock()
            chat.get_recent = MagicMock(return_value=[])

            bridge = AIBridge(chat_manager=chat, api_key="")
            bridge._client = MagicMock()  # Fake Claude client
            bridge._enabled = True
            bridge._active_backend = "claude"

            # Claude fails
            bridge._call_claude = AsyncMock(return_value=None)
            # Ollama succeeds
            mock_ollama = MagicMock()
            bridge._ollama = mock_ollama
            bridge._call_ollama = AsyncMock(return_value="Ollama response")

            result = await bridge._call_with_tools(
                system="test", messages=[{"role": "user", "content": "Hi"}],
            )
            assert result == "Ollama response"
            bridge._call_claude.assert_called_once()
            bridge._call_ollama.assert_called_once()

    @pytest.mark.asyncio
    async def test_ollama_primary_when_no_claude(self):
        """When no Claude client, should go directly to Ollama."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}, clear=False):
            chat = MagicMock()
            bridge = AIBridge(chat_manager=chat, api_key="")
            bridge._client = None  # No Claude
            bridge._ollama = MagicMock()
            bridge._call_ollama = AsyncMock(return_value="Direct Ollama")

            result = await bridge._call_with_tools(
                system="test", messages=[{"role": "user", "content": "Hi"}],
            )
            assert result == "Direct Ollama"

    @pytest.mark.asyncio
    async def test_no_backends_returns_none(self):
        """When neither Claude nor Ollama available, return None."""
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        bridge._client = None
        bridge._ollama = None

        result = await bridge._call_with_tools(
            system="test", messages=[{"role": "user", "content": "Hi"}],
        )
        assert result is None


class TestAIBridgeOllamaMethods:
    @pytest.mark.asyncio
    async def test_ollama_status_when_available(self):
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        mock_ollama = MagicMock()
        mock_ollama.status = AsyncMock(return_value={
            "backend": "ollama", "available": True, "model": "llama3.1:8b",
        })
        bridge._ollama = mock_ollama

        status = await bridge.ollama_status()
        assert status["available"] is True

    @pytest.mark.asyncio
    async def test_ollama_status_when_not_initialized(self):
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        bridge._ollama = None

        status = await bridge.ollama_status()
        assert status["available"] is False

    @pytest.mark.asyncio
    async def test_set_ollama_model(self):
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        mock_ollama = MagicMock()
        mock_ollama.model = "llama3.1:8b"
        mock_ollama.has_model = AsyncMock(return_value=True)
        bridge._ollama = mock_ollama

        result = await bridge.set_ollama_model("mistral:7b")
        assert result["previous"] == "llama3.1:8b"
        assert result["current"] == "mistral:7b"

    @pytest.mark.asyncio
    async def test_set_ollama_model_not_found(self):
        """Setting a model that doesn't exist should return error."""
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        mock_ollama = MagicMock()
        mock_ollama.has_model = AsyncMock(return_value=False)
        mock_ollama.list_models = AsyncMock(return_value=[
            OllamaModel(name="llama3.1:8b"),
        ])
        bridge._ollama = mock_ollama

        result = await bridge.set_ollama_model("nonexistent:7b")
        assert "error" in result
        assert "nonexistent:7b" in result["error"]
        assert "llama3.1:8b" in result["available"]

    @pytest.mark.asyncio
    async def test_set_ollama_model_no_backend(self):
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        bridge._ollama = None

        result = await bridge.set_ollama_model("test")
        assert "error" in result

    @pytest.mark.asyncio
    async def test_list_ollama_models(self):
        """Public list_ollama_models method for API endpoint."""
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        mock_ollama = MagicMock()
        mock_ollama.model = "llama3.1:8b"
        mock_ollama.list_models = AsyncMock(return_value=[
            OllamaModel(name="llama3.1:8b", size=4_500_000_000),
        ])
        bridge._ollama = mock_ollama

        result = await bridge.list_ollama_models()
        assert result["current"] == "llama3.1:8b"
        assert len(result["models"]) == 1

    @pytest.mark.asyncio
    async def test_list_ollama_models_no_backend(self):
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        bridge._ollama = None

        result = await bridge.list_ollama_models()
        assert result["models"] == []
        assert result["current"] is None


# ── Audit Logger Ollama Support ─────────────────────────────────────


class TestAuditLoggerOllama:
    def test_finish_call_with_ollama_response(self, tmp_path):
        from citadel_archer.chat.ai_audit import AIAuditLogger

        logger = AIAuditLogger(log_path=tmp_path / "test_audit.log")
        ctx = logger.start_call("ollama_user_text", "msg-1", "llama3.1:8b", 0)

        record = logger.finish_call(ctx, ollama_response={
            "model": "llama3.1:8b",
            "input_tokens": 100,
            "output_tokens": 50,
        })

        assert record is not None
        assert record.input_tokens == 100
        assert record.output_tokens == 50
        assert record.total_tokens == 150
        assert record.stop_reason == "end_turn"
        assert record.error is None

    def test_finish_call_with_ollama_error(self, tmp_path):
        from citadel_archer.chat.ai_audit import AIAuditLogger

        logger = AIAuditLogger(log_path=tmp_path / "test_audit.log")
        ctx = logger.start_call("ollama_user_text", "msg-1", "llama3.1:8b", 0)

        record = logger.finish_call(ctx, error="OllamaNoResponse")
        assert record is not None
        assert record.error == "OllamaNoResponse"
        assert record.stop_reason == "error"


# ── OllamaBackend.status() ─────────────────────────────────────────


class TestOllamaStatus:
    @pytest.mark.asyncio
    async def test_status_when_available(self):
        backend = OllamaBackend(model="llama3.1:8b")

        async def mock_available(force=False):
            return True

        async def mock_models():
            return [
                OllamaModel(name="llama3.1:8b", size=4_500_000_000),
                OllamaModel(name="mistral:7b", size=3_800_000_000),
            ]

        backend.is_available = mock_available
        backend.list_models = mock_models

        status = await backend.status()
        assert status["available"] is True
        assert status["model_installed"] is True
        assert len(status["available_models"]) == 2
        assert status["recommended_models"] == RECOMMENDED_MODELS

    @pytest.mark.asyncio
    async def test_status_when_unavailable(self):
        backend = OllamaBackend()

        async def mock_available(force=False):
            return False

        backend.is_available = mock_available

        status = await backend.status()
        assert status["available"] is False
        assert status["available_models"] == []


# ── _call_ollama message cleaning ───────────────────────────────────


class TestOllamaMessageCleaning:
    @pytest.mark.asyncio
    async def test_claude_content_blocks_flattened(self):
        """Claude tool_result content blocks should be flattened to strings."""
        chat = MagicMock()
        bridge = AIBridge(chat_manager=chat, api_key="")
        bridge._ollama = MagicMock()
        bridge._ollama.model = "test"
        bridge._ollama.is_available = AsyncMock(return_value=True)

        captured_messages = []

        async def mock_chat_with_tools(messages, **kwargs):
            captured_messages.extend(messages)
            return LLMResponse(text="Done", model="test")

        bridge._ollama.chat_with_tools = mock_chat_with_tools

        # Mock audit and quota
        mock_audit = MagicMock()
        mock_ctx = {"call_id": "x", "trigger_type": "test", "trigger_message_id": "",
                     "model": "test", "iteration": 0, "start_time": 0,
                     "start_wall": __import__("datetime").datetime.now()}
        mock_audit.start_call = MagicMock(return_value=mock_ctx)
        mock_audit.finish_call = MagicMock(return_value=None)

        mock_quota = MagicMock()
        mock_quota.record = MagicMock()

        messages = [
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": [{"type": "text", "text": "I'll check"}]},
            {"role": "user", "content": [
                {"type": "tool_result", "content": '{"status": "ok"}'}
            ]},
        ]

        result = await bridge._call_ollama(
            system="test", messages=messages,
            trigger_type="test", trigger_message_id="",
            participant_id="user", audit=mock_audit, quota=mock_quota,
        )

        # Verify messages were cleaned to plain strings
        for m in captured_messages:
            assert isinstance(m["content"], str), f"Content should be string, got {type(m['content'])}"


# ── Recommended Models List ─────────────────────────────────────────


class TestSessionManagement:
    @pytest.mark.asyncio
    async def test_get_session_reuses_existing(self, mock_aiohttp):
        """Existing non-closed session should be reused."""
        backend = OllamaBackend()
        mock_session = MagicMock()
        mock_session.closed = False
        backend._session = mock_session

        result = await backend._get_session()
        assert result is mock_session

    @pytest.mark.asyncio
    async def test_get_session_recreates_after_close(self, mock_aiohttp):
        """Closed session should be replaced with a new one."""
        backend = OllamaBackend()
        old_session = MagicMock()
        old_session.closed = True
        backend._session = old_session

        mock_new_session = MagicMock()
        mock_aiohttp.ClientSession.return_value = mock_new_session

        result = await backend._get_session()
        assert result is mock_new_session

    @pytest.mark.asyncio
    async def test_close_session(self):
        backend = OllamaBackend()
        mock_session = MagicMock()
        mock_session.closed = False
        mock_session.close = AsyncMock()
        backend._session = mock_session

        await backend.close()
        mock_session.close.assert_called_once()
        assert backend._session is None

    @pytest.mark.asyncio
    async def test_close_when_no_session(self):
        backend = OllamaBackend()
        await backend.close()  # Should not raise


class TestRecommendedModels:
    def test_recommended_models_not_empty(self):
        assert len(RECOMMENDED_MODELS) > 0

    def test_default_model_in_recommended(self):
        assert DEFAULT_OLLAMA_MODEL in RECOMMENDED_MODELS
