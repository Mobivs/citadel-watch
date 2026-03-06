"""Hostinger REST API client.

Provides async VPS management operations for the Guardian AI.
API key is read from UserPreferences (key: hostinger_api_key) — never hardcoded.

Base URL: https://developers.hostinger.com
Auth:     Authorization: Bearer {api_key}
"""

from typing import Any, Dict, List, Optional
import httpx

_BASE = "https://developers.hostinger.com"
_TIMEOUT = 20.0


def _get_api_key() -> str:
    """Read the Hostinger API key from UserPreferences.

    Raises ValueError if the key has not been configured.
    """
    from ..core.user_preferences import get_user_preferences
    key = get_user_preferences().get("hostinger_api_key")
    if not key:
        raise ValueError(
            "Hostinger API key not configured. Add it in Settings → Integrations."
        )
    return key


class HostingerClient:
    """Thin async wrapper around the Hostinger VPS API v1."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self._api_key = api_key or _get_api_key()
        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        """Like raise_for_status() but includes the response body in the message."""
        if resp.is_error:
            try:
                body = resp.json()
                detail = body.get("message") or body.get("error") or str(body)
            except Exception:
                detail = resp.text[:200] or "(empty body)"
            raise httpx.HTTPStatusError(
                f"{resp.status_code} from Hostinger: {detail}",
                request=resp.request,
                response=resp,
            )

    async def _get(self, path: str) -> Any:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(f"{_BASE}{path}", headers=self._headers)
            self._raise_for_status(resp)
            return resp.json()

    async def _post(self, path: str, json: Optional[Dict] = None) -> Any:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                f"{_BASE}{path}", headers=self._headers, json=json or {}
            )
            self._raise_for_status(resp)
            # Some endpoints return 204 No Content on success
            if resp.status_code == 204 or not resp.content:
                return {"status": "ok"}
            return resp.json()

    async def _put(self, path: str, json: Optional[Dict] = None) -> Any:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.put(
                f"{_BASE}{path}", headers=self._headers, json=json or {}
            )
            self._raise_for_status(resp)
            if resp.status_code == 204 or not resp.content:
                return {"status": "ok"}
            return resp.json()

    async def _delete(self, path: str) -> Any:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.delete(f"{_BASE}{path}", headers=self._headers)
            self._raise_for_status(resp)
            if resp.status_code == 204 or not resp.content:
                return {"status": "ok"}
            return resp.json()

    async def list_vps(self) -> List[Dict]:
        """Return all virtual machines on this account."""
        data = await self._get("/api/vps/v1/virtual-machines")
        # API returns {"data": [...]} or a list directly
        if isinstance(data, dict):
            return data.get("data", [])
        return data

    async def get_vps(self, vps_id: int) -> Dict:
        """Return details for a single VPS."""
        return await self._get(f"/api/vps/v1/virtual-machines/{vps_id}")

    async def restart_vps(self, vps_id: int) -> Dict:
        """Reboot a VPS. Returns immediately; restart takes ~60s."""
        return await self._post(f"/api/vps/v1/virtual-machines/{vps_id}/reboot")

    async def get_metrics(self, vps_id: int) -> Dict:
        """Return resource metrics (CPU, RAM, disk) for a VPS."""
        return await self._get(f"/api/vps/v1/virtual-machines/{vps_id}/metrics")

    # ── SSH key management ─────────────────────────────────────────────────

    async def list_account_ssh_keys(self) -> List[Dict]:
        """List all SSH public keys registered on this Hostinger account."""
        data = await self._get("/api/vps/v1/public-keys")
        if isinstance(data, dict):
            return data.get("data", [])
        return data or []

    async def create_account_ssh_key(self, name: str, public_key: str) -> Dict:
        """Upload a new public key to the Hostinger account.

        Returns the created key record (includes 'id' field needed for attach).
        """
        return await self._post("/api/vps/v1/public-keys", {
            "name": name,
            "public_key": public_key,
        })

    async def attach_ssh_key_to_vps(self, vps_id: int, key_id: int) -> Dict:
        """Attach an account SSH key to a VPS.

        NOTE: This records the key association in Hostinger but does NOT
        dynamically update authorized_keys on a running VPS — only takes
        effect at next provision/reinstall.
        """
        return await self._post(
            f"/api/vps/v1/public-keys/attach/{vps_id}",
            {"public_key_ids": [key_id]},
        )

    async def delete_account_ssh_key(self, key_id: int) -> Dict:
        """Remove an SSH key from the Hostinger account."""
        return await self._delete(f"/api/vps/v1/public-keys/{key_id}")

    async def set_root_password(self, vps_id: int, password: str) -> Dict:
        """Set the root password for a VPS via Hostinger API.

        Emergency recovery only — allows console login when SSH keys are broken.
        """
        return await self._put(
            f"/api/vps/v1/virtual-machines/{vps_id}/root-password",
            {"password": password},
        )
