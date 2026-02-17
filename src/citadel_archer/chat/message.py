# PRD: SecureChat — Message Model
# Reference: Plan Milestone 1
#
# Defines the ChatMessage dataclass and MessageType enum.
# Messages flow between participants: user, assistant, citadel, agent:<id>

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4


class MessageType(str, Enum):
    """Types of messages in the SecureChat system."""

    TEXT = "text"            # Human-readable chat message
    COMMAND = "command"      # User-issued command (e.g. "add vps 1.2.3.4")
    EVENT = "event"         # System event escalated to chat
    QUERY = "query"         # Request for information
    RESPONSE = "response"   # Reply to a query
    HEARTBEAT = "heartbeat" # Participant health check
    SETUP = "setup"         # Onboarding / configuration flow
    DELEGATION = "delegation"  # Task delegation from agent to agent
    ACK = "ack"              # Acknowledgment / task status update


# Well-known participant IDs
PARTICIPANT_USER = "user"
PARTICIPANT_ASSISTANT = "assistant"
PARTICIPANT_CITADEL = "citadel"


def agent_participant(asset_id: str) -> str:
    """Build a participant ID for a VPS agent."""
    return f"agent:{asset_id}"


@dataclass
class ChatMessage:
    """A single message in the SecureChat system.

    Messages are the atomic unit of communication between all
    participants (user, assistant, citadel, agents).
    """

    from_id: str
    to_id: str
    msg_type: MessageType
    payload: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: f"msg_{uuid4().hex[:16]}")
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    signature: Optional[str] = None  # Future: cryptographic signature
    reply_to: Optional[str] = None  # Links response to parent message ID
    correlation_id: Optional[str] = None  # Chains multi-leg request workflows

    @property
    def text(self) -> str:
        """Convenience accessor for the 'text' field in payload."""
        return self.payload.get("text", "")

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["msg_type"] = self.msg_type.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChatMessage":
        data = dict(data)  # shallow copy
        if "msg_type" in data and isinstance(data["msg_type"], str):
            data["msg_type"] = MessageType(data["msg_type"])
        if "payload" in data and isinstance(data["payload"], str):
            data["payload"] = json.loads(data["payload"])
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def system_message(text: str, msg_type: MessageType = MessageType.TEXT) -> ChatMessage:
    """Create a message from the citadel system."""
    return ChatMessage(
        from_id=PARTICIPANT_CITADEL,
        to_id=PARTICIPANT_USER,
        msg_type=msg_type,
        payload={"text": text},
    )
