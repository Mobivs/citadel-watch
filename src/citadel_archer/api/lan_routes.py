# LAN Sentinel Routes — REST API for local network device inventory.
#
# GET  /api/lan/devices            — list all known LAN devices
# GET  /api/lan/status             — scanner status (last scan, counts, mode)
# POST /api/lan/scan               — trigger immediate scan
# POST /api/lan/devices/{mac}/known — mark a device as acknowledged

from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .security import verify_session_token
from ..local.lan_scanner import get_lan_device_store

router = APIRouter(prefix="/api/lan", tags=["lan"])


class MarkKnownRequest(BaseModel):
    label: Optional[str] = None


@router.get("/devices")
async def list_devices(
    _token: str = Depends(verify_session_token),
):
    """Return all LAN devices, unknown/new devices first."""
    return get_lan_device_store().get_all()


@router.get("/status")
async def get_status(
    request: Request,
    _token: str = Depends(verify_session_token),
):
    """Return scanner status: last scan time, device count, new count, mode."""
    scanner = getattr(request.app.state, "lan_scanner", None)
    if scanner is None:
        counts = get_lan_device_store().count()
        return {
            "last_scan": None,
            "device_count": counts["total"],
            "new_count": counts["new"],
            "scanner_active": False,
            "scan_interval": 300,
            "subnet": "unknown",
            "mode": "unavailable",
        }
    return scanner.status()


@router.post("/scan")
async def trigger_scan(
    request: Request,
    _token: str = Depends(verify_session_token),
) -> Dict:
    """Trigger an immediate LAN scan. Returns scan results."""
    scanner = getattr(request.app.state, "lan_scanner", None)
    if scanner is None:
        raise HTTPException(status_code=503, detail="LAN scanner not initialized")
    return await scanner.scan_once()


@router.post("/devices/{mac}/known")
async def mark_device_known(
    mac: str,
    body: MarkKnownRequest,
    _token: str = Depends(verify_session_token),
) -> Dict:
    """Mark a LAN device as acknowledged (known/trusted)."""
    store = get_lan_device_store()
    success = store.mark_known(mac, label=body.label)
    if not success:
        raise HTTPException(status_code=404, detail=f"Device not found: {mac}")
    return {"success": True, "mac": mac.upper(), "label": body.label}
