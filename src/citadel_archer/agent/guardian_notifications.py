"""guardian_notifications.py — Push action completion events to Guardian AI.

A thin hook layer so API route handlers can notify the AI bridge when
daemon actions and SSH commands complete, without creating circular imports.

Usage:
    # In ai_bridge.py startup:
    from ..agent.guardian_notifications import register_handler
    register_handler(self._on_completion_event)

    # In any route handler:
    from ..agent.guardian_notifications import notify
    notify("ssh_command_result", {...})
"""
import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, Optional

logger = logging.getLogger(__name__)

# Registered by AIBridge on startup — None until then
_handler: Optional[Callable[[str, Dict[str, Any]], Awaitable[None]]] = None


def register_handler(fn: Callable[[str, Dict[str, Any]], Awaitable[None]]) -> None:
    """Register the AIBridge completion callback. Called once at startup."""
    global _handler
    _handler = fn


def notify(event_type: str, data: Dict[str, Any]) -> None:
    """Fire-and-forget: push a completion event to Guardian AI.

    Safe to call from any thread or async context. If the event loop is
    running the coroutine is scheduled; otherwise it is silently dropped
    (Guardian is not yet available).

    Event types:
        daemon_action_result  — daemon reported success/failed
        daemon_action_approved — user approved a pending action
        daemon_action_denied  — user denied a pending action
        ssh_command_result    — approved SSH command completed
        ssh_command_denied    — user denied an SSH command
    """
    if _handler is None:
        return
    try:
        coro = _handler(event_type, data)
        if asyncio.iscoroutine(coro):
            try:
                loop = asyncio.get_running_loop()
                # All callers are async FastAPI handlers, so we're always on the
                # event loop thread — schedule directly without the threadsafe detour.
                # The `c=coro` default arg prevents late-binding closure issues.
                if loop.is_running():
                    asyncio.ensure_future(coro)
                else:
                    loop.call_soon_threadsafe(lambda c=coro: asyncio.ensure_future(c))
            except RuntimeError:
                # No running loop — Guardian not yet available, drop silently
                coro.close()  # prevent "coroutine was never awaited" warning
    except Exception:
        logger.exception("guardian_notifications.notify failed for %s", event_type)
