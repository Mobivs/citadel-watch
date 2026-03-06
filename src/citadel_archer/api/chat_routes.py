# PRD: SecureChat — REST API Routes
# Reference: Plan Milestone 1
#
# Provides endpoints for the always-visible chat sidebar:
#   GET  /api/chat/messages     — paginated message history
#   POST /api/chat/send         — user sends text / command
#   GET  /api/chat/participants — connected participants + status

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..chat import ChatManager, ChatMessage, MessageType
from .security import verify_session_token

router = APIRouter(prefix="/api/chat", tags=["chat"])

# Singleton ChatManager — set in main.py startup_event
_chat_manager: Optional[ChatManager] = None
_ai_bridge = None  # AIBridge — set in main.py startup_event


def get_chat_manager() -> ChatManager:
    global _chat_manager
    if _chat_manager is None:
        from ..chat import ChatStore
        _chat_manager = ChatManager(ChatStore())
    return _chat_manager


def set_chat_manager(mgr: ChatManager):
    global _chat_manager
    _chat_manager = mgr


def set_ai_bridge(bridge) -> None:
    global _ai_bridge
    _ai_bridge = bridge


# ── Request / Response models ──────────────────────────────────────

class SendMessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50_000)


class ChatMessageResponse(BaseModel):
    id: str
    from_id: str
    to_id: str
    msg_type: str
    payload: dict
    timestamp: str
    signature: Optional[str] = None


# ── Endpoints ──────────────────────────────────────────────────────

@router.get("/messages")
async def get_messages(
    limit: int = 50,
    before: Optional[str] = None,
    after: Optional[str] = None,
    _token: str = Depends(verify_session_token),
):
    """Get recent chat messages for the sidebar."""
    mgr = get_chat_manager()

    if before or after:
        messages = mgr.get_messages(limit=limit, before=before, after=after)
    else:
        messages = mgr.get_recent(limit=limit)

    return {
        "messages": [m.to_dict() for m in messages],
        "count": len(messages),
    }


@router.post("/send")
async def send_message(
    req: SendMessageRequest,
    _token: str = Depends(verify_session_token),
):
    """Send a user message (text or command)."""
    mgr = get_chat_manager()
    msg = await mgr.handle_user_input(req.text)
    return {
        "message": msg.to_dict(),
        "status": "sent",
    }


@router.post("/interrupt")
async def interrupt_ai(
    _token: str = Depends(verify_session_token),
):
    """Cancel the current in-flight AI processing task."""
    if _ai_bridge is None:
        return {"status": "no_ai", "interrupted": False}
    cancelled = _ai_bridge.interrupt()
    return {"status": "ok", "interrupted": cancelled}


@router.get("/participants")
async def get_participants(
    _token: str = Depends(verify_session_token),
):
    """List known participants and their status."""
    # For now, return the always-present local participants.
    # Agent participants will be added dynamically in Milestone 3+.
    participants = [
        {
            "id": "user",
            "label": "You",
            "type": "local",
            "status": "online",
        },
        {
            "id": "citadel",
            "label": "Citadel",
            "type": "local",
            "status": "online",
        },
        {
            "id": "assistant",
            "label": "AI Assistant",
            "type": "local",
            "status": "online",
        },
    ]

    # Add registered agents from AssetInventory
    try:
        from .asset_routes import get_inventory
        inv = get_inventory()
        for asset in inv.all():
            if asset.remote_shield_agent_id:
                participants.append({
                    "id": f"agent:{asset.asset_id}",
                    "label": asset.name or asset.hostname or asset.ip_address,
                    "type": "agent",
                    "status": asset.status.value,
                    "asset_id": asset.asset_id,
                })
    except Exception:
        pass

    # Add external AI agents from AgentRegistry (Trigger 1b)
    try:
        from .agent_api_routes import get_agent_registry
        for agent in get_agent_registry().list_agents():
            if agent["status"] == "active":
                participants.append({
                    "id": f"ext-agent:{agent['agent_id']}",
                    "label": agent["name"],
                    "type": "external_agent",
                    "agent_type": agent["agent_type"],
                    "status": "online",
                })
    except Exception:
        pass

    return {"participants": participants}


@router.post("/test-approval-card")
async def test_approval_card(
    _token: str = Depends(verify_session_token),
):
    """Send a fake SSH approval card to the chat sidebar.

    Used to test whether the approval card UI renders correctly,
    independent of the AI flow. Call from browser console:
        fetch('/api/chat/test-approval-card', {method:'POST',
              headers:{'X-Session-Token': '<token>'}})
    """
    from ..chat.message import ChatMessage, MessageType, PARTICIPANT_CITADEL, PARTICIPANT_USER
    from .asset_routes import register_pending_ssh

    # Use a non-existent asset ID so clicking Approve resolves to a 404 from
    # the execute-ssh endpoint — safe even if the user clicks through.
    approval_uuid = register_pending_ssh("__test__", "echo approval-card-test", 30)

    msg = ChatMessage(
        from_id=PARTICIPANT_CITADEL,
        to_id=PARTICIPANT_USER,
        msg_type=MessageType.RESPONSE,
        payload={
            "text": (
                "**SSH Command Approval Required** *(UI test only)*\n\n"
                "**Asset:** `__test__`\n"
                "**Command:** `echo approval-card-test`\n"
                "\n*This is a test card to verify rendering. Clicking Approve is safe — no command executes.*"
            ),
            "action_type": "ssh_approval_request",
            "approval_uuid": approval_uuid,
            "asset_id": "__test__",
            "asset_label": "__test__",
            "command": "echo approval-card-test",
        },
    )

    mgr = get_chat_manager()
    await mgr.send(msg)
    return {"status": "sent", "approval_uuid": approval_uuid}
