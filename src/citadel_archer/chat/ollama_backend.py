# PRD: Local LLM Integration — Ollama Backend
# Reference: docs/PRD.md v0.3.17, Phase 4
#
# Provides a local LLM backend using Ollama for fully offline AI analysis.
# Speaks Ollama's /api/chat REST endpoint (supports tool calling).
#
# Features:
#   - Automatic model discovery (list available models)
#   - Health check (is Ollama running?)
#   - Chat completion with tool support (mirrors Claude's tool loop)
#   - Configurable base URL and model selection
#   - Graceful degradation (returns None if Ollama is unavailable)
#
# Design:
#   - Pure HTTP via aiohttp (no SDK dependency)
#   - Shares the LLMResponse/ToolCall abstractions with the AI Bridge
#   - Thread-safe: can be queried from API endpoints concurrently

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default Ollama server URL
DEFAULT_OLLAMA_URL = "http://localhost:11434"

# Default model — good balance of capability and speed for security analysis
DEFAULT_OLLAMA_MODEL = "llama3.1:8b"

# Recommended models for security analysis (ordered by preference)
RECOMMENDED_MODELS = [
    "llama3.1:8b",
    "llama3.1:70b",
    "mistral:7b",
    "qwen2.5:7b",
    "gemma2:9b",
    "phi3:medium",
]


# ── Data Classes ─────────────────────────────────────────────────────


@dataclass
class ToolCall:
    """A tool call from the LLM."""
    name: str
    arguments: Dict[str, Any]
    id: str = ""


@dataclass
class LLMResponse:
    """Unified response from any LLM backend."""
    text: Optional[str] = None
    tool_calls: List[ToolCall] = field(default_factory=list)
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    done: bool = True

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


@dataclass
class OllamaModel:
    """Metadata for an available Ollama model."""
    name: str
    size: int = 0  # bytes
    modified: str = ""
    family: str = ""
    parameter_size: str = ""
    quantization: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size_gb": round(self.size / (1024 ** 3), 1) if self.size else 0,
            "modified": self.modified,
            "family": self.family,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
        }


# ── Ollama Backend ───────────────────────────────────────────────────


class OllamaBackend:
    """Local LLM backend using Ollama's REST API.

    Provides chat completion with tool support, model discovery,
    and health checking. Designed for fully offline AI analysis.

    Usage::

        backend = OllamaBackend()
        if await backend.is_available():
            response = await backend.chat(
                messages=[{"role": "user", "content": "Analyze this threat"}],
                system="You are a security analyst.",
            )
            print(response.text)
    """

    def __init__(
        self,
        base_url: str = "",
        model: str = "",
    ):
        import os
        self._base_url = (
            base_url
            or os.environ.get("OLLAMA_URL", "")
            or DEFAULT_OLLAMA_URL
        ).rstrip("/")
        self._model = (
            model
            or os.environ.get("OLLAMA_MODEL", "")
            or DEFAULT_OLLAMA_MODEL
        )
        self._available: Optional[bool] = None
        self._last_health_check: float = 0.0
        self._health_cache_ttl = 30.0  # seconds
        self._session = None  # reusable aiohttp.ClientSession

    @property
    def model(self) -> str:
        return self._model

    @model.setter
    def model(self, value: str) -> None:
        self._model = value

    @property
    def base_url(self) -> str:
        return self._base_url

    # ── Session Management ───────────────────────────────────────────

    async def _get_session(self):
        """Get or create a reusable aiohttp session.

        Reusing the session avoids creating a new TCP connection pool
        per request (recommended by aiohttp docs).
        """
        import aiohttp

        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self):
        """Close the HTTP session. Call on shutdown."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ── Health Check ──────────────────────────────────────────────────

    async def is_available(self, force: bool = False) -> bool:
        """Check if Ollama is running and responsive.

        Caches the result for 30 seconds to avoid hammering the server.
        """
        now = time.monotonic()
        if (
            not force
            and self._available is not None
            and (now - self._last_health_check) < self._health_cache_ttl
        ):
            return self._available

        try:
            import aiohttp

            session = await self._get_session()
            async with session.get(
                f"{self._base_url}/api/tags",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                self._available = resp.status == 200
        except Exception:
            self._available = False

        self._last_health_check = now
        return self._available

    # ── Model Discovery ───────────────────────────────────────────────

    async def list_models(self) -> List[OllamaModel]:
        """List locally available Ollama models."""
        try:
            import aiohttp

            session = await self._get_session()
            async with session.get(
                f"{self._base_url}/api/tags",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
        except Exception:
            return []

        models = []
        for m in data.get("models", []):
            details = m.get("details", {})
            models.append(OllamaModel(
                name=m.get("name", ""),
                size=m.get("size", 0),
                modified=m.get("modified_at", ""),
                family=details.get("family", ""),
                parameter_size=details.get("parameter_size", ""),
                quantization=details.get("quantization_level", ""),
            ))
        return models

    async def has_model(self, model_name: str) -> bool:
        """Check if a specific model is available locally."""
        models = await self.list_models()
        return any(m.name == model_name or m.name.startswith(f"{model_name}:") for m in models)

    async def pull_model(self, model_name: str) -> bool:
        """Pull a model from the Ollama registry.

        WARNING: This is a long-running operation (can take 10+ minutes for
        large models). Do NOT call from an API request handler directly.
        Use as a background task with progress streaming when exposing to users.
        """
        try:
            import aiohttp

            session = await self._get_session()
            async with session.post(
                f"{self._base_url}/api/pull",
                json={"name": model_name, "stream": False},
                timeout=aiohttp.ClientTimeout(total=600),
            ) as resp:
                return resp.status == 200
        except Exception:
            logger.warning("Failed to pull Ollama model %s", model_name)
            return False

    # ── Chat Completion ───────────────────────────────────────────────

    async def chat(
        self,
        messages: List[Dict[str, Any]],
        system: str = "",
        tools: Optional[List[Dict[str, Any]]] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
    ) -> Optional[LLMResponse]:
        """Send a chat completion request to Ollama.

        Args:
            messages: List of {role, content} message dicts.
            system: System prompt text.
            tools: Optional list of tool definitions (OpenAI format).
            max_tokens: Maximum tokens to generate.
            temperature: Sampling temperature (lower = more deterministic).

        Returns:
            LLMResponse with text and/or tool calls, or None on failure.
        """
        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }

        if system:
            # Ollama supports system message as first message or via system field
            payload["messages"] = [
                {"role": "system", "content": system}
            ] + messages

        if tools:
            payload["tools"] = self._convert_tools(tools)

        try:
            import aiohttp

            session = await self._get_session()
            async with session.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                if resp.status != 200:
                    error_text = await resp.text()
                    logger.warning(
                        "Ollama chat failed (HTTP %d): %s",
                        resp.status, error_text[:200],
                    )
                    return None
                data = await resp.json()
        except Exception as exc:
            logger.warning("Ollama chat request failed: %s", exc)
            return None

        return self._parse_response(data)

    async def chat_with_tools(
        self,
        messages: List[Dict[str, Any]],
        system: str = "",
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_executor=None,
        max_iterations: int = 5,
        max_tokens: int = 1024,
        temperature: float = 0.3,
    ) -> Optional[LLMResponse]:
        """Chat with automatic tool execution loop.

        Mirrors the AI Bridge's tool loop: call LLM → execute tools →
        feed results back → repeat until text response or max iterations.

        Args:
            messages: Initial messages.
            system: System prompt.
            tools: Tool definitions.
            tool_executor: Async callable(name, args) -> result.
            max_iterations: Safety valve for tool loop.
            max_tokens: Max tokens per response.
            temperature: Sampling temperature.

        Returns:
            Final LLMResponse with text, or None on failure.
        """
        current_messages = list(messages)
        total_input = 0
        total_output = 0

        for iteration in range(max_iterations + 1):
            response = await self.chat(
                messages=current_messages,
                system=system if iteration == 0 else "",
                tools=tools,
                max_tokens=max_tokens,
                temperature=temperature,
            )

            if response is None:
                return None

            total_input += response.input_tokens
            total_output += response.output_tokens

            if not response.has_tool_calls or tool_executor is None:
                response.input_tokens = total_input
                response.output_tokens = total_output
                return response

            # Execute tool calls
            # Add assistant message with tool calls
            current_messages.append({
                "role": "assistant",
                "content": response.text or "",
                "tool_calls": [
                    {
                        "function": {
                            "name": tc.name,
                            "arguments": tc.arguments,
                        },
                    }
                    for tc in response.tool_calls
                ],
            })

            # Execute each tool and add results
            for tc in response.tool_calls:
                try:
                    result = await tool_executor(tc.name, tc.arguments)
                except Exception as exc:
                    result = {"error": str(exc)}

                current_messages.append({
                    "role": "tool",
                    "content": json.dumps(result, default=str),
                })

        # Exceeded max iterations — return last response
        if response is not None:
            response.input_tokens = total_input
            response.output_tokens = total_output
        return response

    # ── Status ────────────────────────────────────────────────────────

    async def status(self) -> Dict[str, Any]:
        """Return backend status for API/dashboard display."""
        available = await self.is_available()
        models = await self.list_models() if available else []
        has_model = any(
            m.name == self._model or m.name.startswith(f"{self._model}:")
            for m in models
        )

        return {
            "backend": "ollama",
            "available": available,
            "base_url": self._base_url,
            "model": self._model,
            "model_installed": has_model,
            "available_models": [m.to_dict() for m in models],
            "recommended_models": RECOMMENDED_MODELS,
        }

    # ── Internal Helpers ──────────────────────────────────────────────

    def _convert_tools(self, claude_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert Claude tool format to Ollama/OpenAI tool format.

        Claude format:
            {"name": "...", "description": "...", "input_schema": {...}}

        Ollama/OpenAI format:
            {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
        """
        converted = []
        for tool in claude_tools:
            converted.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                },
            })
        return converted

    def _parse_response(self, data: Dict[str, Any]) -> LLMResponse:
        """Parse Ollama's /api/chat response into an LLMResponse."""
        message = data.get("message", {})
        text = message.get("content", "")

        # Parse tool calls if present
        tool_calls = []
        for tc in message.get("tool_calls", []):
            func = tc.get("function", {})
            name = func.get("name", "")
            args = func.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, TypeError):
                    args = {}
            if name:
                tool_calls.append(ToolCall(
                    name=name,
                    arguments=args,
                    id=tc.get("id", ""),
                ))

        # Token usage
        input_tokens = data.get("prompt_eval_count", 0)
        output_tokens = data.get("eval_count", 0)

        return LLMResponse(
            text=text if text else None,
            tool_calls=tool_calls,
            model=data.get("model", self._model),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            done=data.get("done", True),
        )
