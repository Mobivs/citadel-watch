# PRD: Append-only AI Audit Log (Phase 2 Hardening)
# Reference: docs/PRD.md — "Append-only AI audit log (data/ai_audit.log)"
#
# Immutable record of every Claude API call. Tracks: timestamp, trigger type,
# model, token counts, stop reason, tool calls, duration, errors.
# Separate from core/audit_log.py (security events) — this is API-call-level.
#
# Uses RotatingFileHandler (5MB max, 5 backups) with propagate=False
# to stay fully isolated from the structlog pipeline.

import itertools
import json
import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)

_DEFAULT_LOG_PATH = Path("data/ai_audit.log")


# ── Data Model ──────────────────────────────────────────────────


@dataclass
class AICallRecord:
    """One JSON line per Claude API call."""

    call_id: str
    timestamp: str
    trigger_type: str  # user_text, agent_text, citadel_event, tool_loop
    trigger_message_id: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    stop_reason: str  # end_turn, tool_use, max_tokens, error
    tool_calls: List[str]  # tool names invoked in this response
    duration_ms: int
    response_preview: str  # first 200 chars of AI text output
    error: Optional[str]  # None on success
    iteration: int  # 0 = initial call, 1+ = tool loop


# ── Logger ──────────────────────────────────────────────────────


class AIAuditLogger:
    """Append-only, file-backed audit log for Claude API calls.

    Thread-safe. Failures in logging never propagate to callers.


    Usage (from ai_bridge.py):
        audit = get_ai_audit_logger()
        ctx = audit.start_call(trigger_type="user_text", ...)
        response = await client.messages.create(...)
        audit.finish_call(ctx, response=response)
    """

    _logger_seq = itertools.count(1)

    def __init__(self, log_path: Optional[Path] = None):
        self._log_path = log_path or _DEFAULT_LOG_PATH
        self._log_path.parent.mkdir(parents=True, exist_ok=True)

        self._lock = threading.Lock()

        # Aggregates (in-memory, reset on restart)
        self._total_calls = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_errors = 0

        # Dedicated logger isolated from structlog/root.
        # Use itertools.count (atomic under GIL) to avoid stale handler reuse
        # when the logging module returns a cached logger after GC reclaims
        # a previous instance at the same memory address.
        seq = next(AIAuditLogger._logger_seq)

        self._file_logger = logging.getLogger(
            f"citadel.ai_audit.{seq}"
        )
        self._file_logger.setLevel(logging.INFO)
        self._file_logger.propagate = False

        # Always replace handlers to ensure correct file path
        self._file_logger.handlers.clear()
        handler = RotatingFileHandler(
            str(self._log_path),
            maxBytes=5 * 1024 * 1024,  # 5 MB
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        self._file_logger.addHandler(handler)

    # ── Call lifecycle ────────────────────────────────────────────

    def start_call(
        self,
        trigger_type: str,
        trigger_message_id: str,
        model: str,
        iteration: int = 0,
    ) -> Dict[str, Any]:
        """Begin timing an API call. Returns context dict for finish_call."""
        return {
            "call_id": str(uuid4()),
            "trigger_type": trigger_type,
            "trigger_message_id": trigger_message_id,
            "model": model,
            "iteration": iteration,
            "start_time": time.monotonic(),
            "start_wall": datetime.now(timezone.utc),
        }

    def finish_call(
        self,
        ctx: Dict[str, Any],
        response: Any = None,
        error: Optional[str] = None,
        ollama_response: Optional[Dict[str, Any]] = None,
    ) -> Optional[AICallRecord]:
        """Log a completed (or failed) API call.

        Supports both Claude SDK response objects (via ``response``) and
        Ollama response dicts (via ``ollama_response``). Returns the
        record on success, None if logging itself fails.
        Never raises — defensive by design.
        """
        try:
            duration_ms = int((time.monotonic() - ctx["start_time"]) * 1000)

            input_tokens = 0
            output_tokens = 0
            stop_reason = "error"
            tool_calls: List[str] = []
            response_preview = ""

            if ollama_response is not None and error is None:
                # Ollama backend — token counts from dict
                input_tokens = ollama_response.get("input_tokens", 0)
                output_tokens = ollama_response.get("output_tokens", 0)
                stop_reason = "end_turn"
            elif response is not None and error is None:
                usage = getattr(response, "usage", None)
                if usage:
                    input_tokens = getattr(usage, "input_tokens", 0)
                    output_tokens = getattr(usage, "output_tokens", 0)

                stop_reason = getattr(response, "stop_reason", "unknown") or "unknown"

                for block in getattr(response, "content", []):
                    if getattr(block, "type", None) == "tool_use":
                        tool_calls.append(getattr(block, "name", "unknown"))
                    if hasattr(block, "text") and block.text:
                        if not response_preview:
                            response_preview = block.text[:200]

            record = AICallRecord(
                call_id=ctx["call_id"],
                timestamp=ctx["start_wall"].isoformat(),
                trigger_type=ctx["trigger_type"],
                trigger_message_id=ctx["trigger_message_id"],
                model=ctx["model"],
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=input_tokens + output_tokens,
                stop_reason=stop_reason,
                tool_calls=tool_calls,
                duration_ms=duration_ms,
                response_preview=response_preview,
                error=error,
                iteration=ctx["iteration"],
            )

            with self._lock:
                self._file_logger.info(json.dumps(asdict(record), default=str))
                for handler in self._file_logger.handlers:
                    handler.flush()
                self._total_calls += 1
                self._total_input_tokens += input_tokens
                self._total_output_tokens += output_tokens
                if error:
                    self._total_errors += 1

            return record

        except Exception:
            logger.debug("AI audit logging failed (non-fatal)", exc_info=True)
            return None

    # ── Query API ────────────────────────────────────────────────

    @property
    def aggregates(self) -> Dict[str, int]:
        """Cumulative counters since last restart."""
        with self._lock:
            return {
                "total_calls": self._total_calls,
                "total_input_tokens": self._total_input_tokens,
                "total_output_tokens": self._total_output_tokens,
                "total_tokens": self._total_input_tokens + self._total_output_tokens,
                "total_errors": self._total_errors,
            }

    def query_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read last N records from log file (newest first).

        Uses a deque to retain only the tail of the file in memory,
        avoiding a full 5 MB allocation on large log files.
        """
        from collections import deque

        results: List[Dict[str, Any]] = []
        # Check current file and first backup to survive rotation boundary
        files_to_check = [self._log_path]
        backup = Path(f"{self._log_path}.1")
        if backup.exists():
            files_to_check.append(backup)

        for log_file in files_to_check:
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    tail = deque(f, maxlen=limit + 20)

                for line in reversed(tail):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                    if len(results) >= limit:
                        return results
            except FileNotFoundError:
                continue
            except Exception:
                logger.debug("AI audit query failed", exc_info=True)

        return results


# ── Singleton ────────────────────────────────────────────────────

_ai_audit_logger: Optional[AIAuditLogger] = None
_ai_audit_lock = threading.Lock()


def get_ai_audit_logger() -> AIAuditLogger:
    """Get or create the global AI audit logger singleton."""
    global _ai_audit_logger
    if _ai_audit_logger is None:
        with _ai_audit_lock:
            if _ai_audit_logger is None:
                _ai_audit_logger = AIAuditLogger()
    return _ai_audit_logger
