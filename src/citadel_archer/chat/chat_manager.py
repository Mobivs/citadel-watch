# PRD: SecureChat — Message Routing & Dispatch
# Reference: Plan Milestone 1
#
# ChatManager is the central hub for sending and receiving messages.
# It persists messages, notifies subscribers, and dispatches commands.

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

from .chat_store import ChatStore
from .message import (
    ChatMessage,
    MessageType,
    PARTICIPANT_CITADEL,
    PARTICIPANT_USER,
    system_message,
)

logger = logging.getLogger(__name__)

# Type alias for message listener callbacks
MessageListener = Callable[[ChatMessage], Any]


class ChatManager:
    """Central message router for the SecureChat system.

    Responsibilities:
      - Persist every message to ChatStore
      - Notify registered listeners (by message type or wildcard)
      - Parse and dispatch user commands (e.g. "add vps <ip>")
      - Provide a broadcast callback for the WebSocket layer

    Args:
        store: ChatStore instance for persistence.
    """

    def __init__(self, store: Optional[ChatStore] = None):
        self._store = store or ChatStore()
        self._listeners: Dict[str, List[MessageListener]] = {}
        self._target_listeners: Dict[str, List[MessageListener]] = {}
        self._command_handlers: Dict[str, Callable] = {}
        self._ws_broadcast: Optional[Callable] = None

    # ------------------------------------------------------------------
    # WebSocket integration
    # ------------------------------------------------------------------

    def set_ws_broadcast(self, broadcast_fn: Callable):
        """Set the WebSocket broadcast function (from main.py ConnectionManager)."""
        self._ws_broadcast = broadcast_fn

    # ------------------------------------------------------------------
    # Send / receive
    # ------------------------------------------------------------------

    async def send(self, msg: ChatMessage) -> ChatMessage:
        """Send a message: persist, notify listeners, push to WebSocket."""
        # 1. Persist
        self._store.save(msg)

        # 2. Notify type-specific listeners
        type_key = msg.msg_type.value
        for listener in self._listeners.get(type_key, []):
            try:
                result = listener(msg)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception(f"Listener error for type={type_key}")

        # 3. Notify to_id-targeted listeners (inter-agent routing)
        for listener in self._target_listeners.get(msg.to_id, []):
            try:
                result = listener(msg)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception(f"Target listener error for to_id={msg.to_id}")

        # 4. Notify wildcard listeners
        for listener in self._listeners.get("*", []):
            try:
                result = listener(msg)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("Wildcard listener error")

        # 5. Push to WebSocket clients
        if self._ws_broadcast:
            try:
                ws_payload = {
                    "type": "chat_message",
                    "message": msg.to_dict(),
                }
                result = self._ws_broadcast(ws_payload)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                logger.exception("WebSocket broadcast failed")

        return msg

    async def send_system(self, text: str, msg_type: MessageType = MessageType.TEXT) -> ChatMessage:
        """Send a system message from citadel to user."""
        msg = system_message(text, msg_type)
        return await self.send(msg)

    async def handle_user_input(self, text: str) -> ChatMessage:
        """Process a message from the user.

        If the text matches a registered command, dispatch it.
        Otherwise, send as a plain text message.
        """
        text = text.strip()

        # Check for command match
        for prefix, handler in self._command_handlers.items():
            if text.lower().startswith(prefix):
                # Save the user message first
                user_msg = ChatMessage(
                    from_id=PARTICIPANT_USER,
                    to_id=PARTICIPANT_CITADEL,
                    msg_type=MessageType.COMMAND,
                    payload={"text": text},
                )
                await self.send(user_msg)

                # Dispatch command (handler should call send() for responses)
                try:
                    result = handler(text, self)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as exc:
                    logger.exception(f"Command handler error: {prefix}")
                    await self.send_system(
                        f"Command failed: {exc}", MessageType.RESPONSE
                    )
                return user_msg

        # Plain text message
        user_msg = ChatMessage(
            from_id=PARTICIPANT_USER,
            to_id=PARTICIPANT_CITADEL,
            msg_type=MessageType.TEXT,
            payload={"text": text},
        )
        return await self.send(user_msg)

    # ------------------------------------------------------------------
    # Listeners
    # ------------------------------------------------------------------

    def subscribe(self, msg_type: str, listener: MessageListener):
        """Subscribe to messages of a given type (or '*' for all)."""
        self._listeners.setdefault(msg_type, []).append(listener)

    def unsubscribe(self, msg_type: str, listener: MessageListener):
        """Remove a listener."""
        listeners = self._listeners.get(msg_type, [])
        if listener in listeners:
            listeners.remove(listener)

    def subscribe_target(self, to_id: str, listener: MessageListener):
        """Subscribe to messages addressed to a specific to_id (inter-agent routing)."""
        self._target_listeners.setdefault(to_id, []).append(listener)

    def unsubscribe_target(self, to_id: str, listener: MessageListener):
        """Remove a to_id-targeted listener."""
        listeners = self._target_listeners.get(to_id, [])
        if listener in listeners:
            listeners.remove(listener)

    # ------------------------------------------------------------------
    # Command handlers
    # ------------------------------------------------------------------

    def register_command(self, prefix: str, handler: Callable):
        """Register a command handler for messages starting with `prefix`.

        Example:
            manager.register_command("add vps", handle_add_vps)
        """
        self._command_handlers[prefix.lower()] = handler

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_recent(self, limit: int = 50) -> List[ChatMessage]:
        """Get recent messages for the chat sidebar."""
        return self._store.get_recent(limit=limit)

    def get_messages(self, **kwargs) -> List[ChatMessage]:
        """Query messages with filters (delegates to ChatStore)."""
        return self._store.get_messages(**kwargs)

    @property
    def store(self) -> ChatStore:
        return self._store
