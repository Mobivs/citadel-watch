"""Public enrollment routes for Easy Deployment (v0.3.32).

These endpoints are **unauthenticated** — the invitation secret in the
URL query parameter serves as the access control. Family members reach
these pages via the enrollment link shared by the admin.

Endpoints:
  GET /enroll/{invitation_id}                        Enrollment landing page
  GET /enroll/{invitation_id}/download/windows_shield.py  Pre-configured agent download
  GET /enroll/{invitation_id}/install.ps1            PowerShell one-liner installer
  GET /enroll/{invitation_id}/status                 Invitation status (polling)
"""

import hashlib
import html as _html
import json
import logging
import re
import secrets
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["enrollment"])

# Rate limiting: 10 requests per minute per IP
_rate_limit: dict = {}
_RATE_WINDOW = 60
_RATE_MAX = 10
_CLEANUP_INTERVAL = 300  # evict stale entries every 5 minutes
_last_cleanup = 0.0

INVITATION_ID_PATTERN = re.compile(r"^[0-9a-f]{12}$")

# Path to the Windows Shield agent source
_AGENT_SOURCE = Path(__file__).resolve().parent.parent / "agent" / "windows_shield.py"

# Path to the enrollment HTML page (project_root/frontend/enroll.html)
# __file__ = src/citadel_archer/api/enrollment_routes.py → 4 parents to project root
_ENROLL_HTML = Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "enroll.html"


def _rate_check(ip: str) -> bool:
    """Return True if the IP is within rate limits."""
    global _last_cleanup
    now = time.monotonic()

    # Periodic cleanup of stale entries to prevent unbounded growth
    if now - _last_cleanup > _CLEANUP_INTERVAL:
        stale = [k for k, (t, _) in _rate_limit.items() if now - t > _RATE_WINDOW]
        for k in stale:
            del _rate_limit[k]
        _last_cleanup = now

    entry = _rate_limit.get(ip)
    if entry is None or now - entry[0] > _RATE_WINDOW:
        _rate_limit[ip] = (now, 1)
        return True
    if entry[1] >= _RATE_MAX:
        return False
    _rate_limit[ip] = (entry[0], entry[1] + 1)
    return True


def _get_store():
    """Lazy import to avoid circular imports at module load time."""
    from ..chat.agent_invitation import get_invitation_store
    return get_invitation_store()


def _get_server_url(request: Request) -> str:
    """Derive the server URL from the request (LAN-accessible address)."""
    return str(request.base_url).rstrip("/")


# ── Enrollment Landing Page ────────────────────────────────────────


@router.get("/enroll/{invitation_id}", response_class=HTMLResponse)
async def enrollment_page(
    invitation_id: str,
    request: Request,
    s: str = Query("", description="Enrollment secret"),
):
    """Public enrollment page. Family member clicks the link from their email."""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(429, "Too many requests. Please wait a minute.")

    if not INVITATION_ID_PATTERN.match(invitation_id):
        raise HTTPException(404, "Invalid invitation link.")

    store = _get_store()

    if not s:
        return HTMLResponse(_error_page("Invalid enrollment link — missing token."), 400)

    # Verify secret without consuming
    if not store.verify_secret_only(invitation_id, s):
        # Check if it was already redeemed
        inv = store.get_invitation(invitation_id)
        if inv and inv.status.value == "redeemed":
            return HTMLResponse(_error_page(
                "This invitation has already been used. "
                "The agent should already be installed and running."
            ))
        return HTMLResponse(_error_page(
            "This invitation link is invalid or has expired."
        ))

    # Mark that the page was visited
    store.mark_page_visited(invitation_id)

    # Get invitation details for the page
    inv = store.get_invitation(invitation_id)
    if not inv:
        return HTMLResponse(_error_page("Invitation not found."), 404)

    server_url = _get_server_url(request)

    # Read the enrollment HTML template and inject data
    if not _ENROLL_HTML.exists():
        return HTMLResponse(_error_page("Enrollment page not configured."), 500)

    html = _ENROLL_HTML.read_text(encoding="utf-8")

    # Inject enrollment data as a JSON script block
    enroll_data = {
        "invitation_id": invitation_id,
        "agent_name": inv.agent_name,
        "agent_type": inv.agent_type,
        "expires_at": inv.expires_at,
        "server_url": server_url,
    }
    # Escape </ to prevent script block breakout via malicious Host header
    enroll_json = json.dumps(enroll_data).replace("</", "<\\/")
    inject = f'<script>window.ENROLL_DATA = {enroll_json};</script>'
    html = html.replace("</head>", f"{inject}\n</head>", 1)

    return HTMLResponse(
        html,
        headers={
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src data:;"
            ),
        },
    )


# ── Pre-Configured Agent Download ──────────────────────────────────


@router.get("/enroll/{invitation_id}/download/windows_shield.py")
async def download_agent(
    invitation_id: str,
    request: Request,
    s: str = Query("", description="Enrollment secret"),
):
    """Download windows_shield.py with server URL and invitation pre-embedded."""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(429, "Too many requests.")

    if not INVITATION_ID_PATTERN.match(invitation_id) or not s:
        raise HTTPException(401, "Invalid download link.")

    store = _get_store()
    if not store.verify_secret_only(invitation_id, s):
        raise HTTPException(401, "Invalid or expired invitation.")

    if not _AGENT_SOURCE.exists():
        raise HTTPException(500, "Agent source not found.")

    server_url = _get_server_url(request)
    compact_string = f"CITADEL-1:{invitation_id}:{s}"

    source = _AGENT_SOURCE.read_text(encoding="utf-8")

    # Embed auto-enrollment config at the top of the file
    auto_enroll_block = (
        "\n# ── Auto-Enrollment (pre-configured by Citadel dashboard) ──────\n"
        f'AUTO_ENROLL_SERVER = "{server_url}"\n'
        f'AUTO_ENROLL_STRING = "{compact_string}"\n'
        "# ── End Auto-Enrollment ─────────────────────────────────────────\n\n"
    )

    # Insert after the module docstring (after the first triple-quote block)
    # Find the end of the docstring
    insert_pos = source.find('"""', source.find('"""') + 3) + 3
    if insert_pos > 3:
        source = source[:insert_pos] + auto_enroll_block + source[insert_pos:]
    else:
        logger.warning("Could not find module docstring in windows_shield.py for auto-enroll injection")

    # Also patch the main() function to auto-enroll if no config exists
    auto_main_patch = '''
    # Auto-enrollment (pre-configured download)
    if command == "daemon" and not config.get("agent_id"):
        if AUTO_ENROLL_SERVER and AUTO_ENROLL_STRING:
            print("Auto-enrolling with pre-configured invitation...")
            success = enroll(AUTO_ENROLL_SERVER, AUTO_ENROLL_STRING)
            if success:
                config = load_config()
            else:
                print("Auto-enrollment failed. Run 'enroll' manually.", file=sys.stderr)
                sys.exit(1)
'''
    # Insert before 'elif command == "daemon":'
    marker = '    elif command == "daemon":'
    if marker not in source:
        logger.warning("Could not find daemon command marker in windows_shield.py for auto-enroll patch")
    else:
        source = source.replace(marker, auto_main_patch + marker, 1)

    return PlainTextResponse(
        content=source,
        media_type="text/x-python",
        headers={
            "Content-Disposition": 'attachment; filename="citadel_shield.py"',
        },
    )


# ── PowerShell One-Liner Installer ────────────────────────────────


_PS1_TEMPLATE = r"""# Citadel Shield - One-Click Installer
# Generated for: {agent_name}
$ErrorActionPreference = 'Stop'

$installDir = "$env:LOCALAPPDATA\CitadelShield"
$agentUrl = "{download_url}"
$serverUrl = "{server_url}"
$invitation = "{compact_string}"

Write-Host ""
Write-Host "  Citadel Shield Installer" -ForegroundColor Cyan
Write-Host "  ========================" -ForegroundColor Cyan
Write-Host ""

# Create install directory
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Write-Host "  [1/4] Created $installDir" -ForegroundColor Gray

# Download agent
Write-Host "  [2/4] Downloading agent..." -ForegroundColor Gray
try {{
    Invoke-WebRequest -Uri $agentUrl -OutFile "$installDir\citadel_shield.py" -UseBasicParsing
}} catch {{
    Write-Host "  ERROR: Download failed. Check network connection." -ForegroundColor Red
    exit 1
}}

# Find Python
$python = $null
foreach ($cmd in @("python", "python3", "py")) {{
    $python = Get-Command $cmd -ErrorAction SilentlyContinue
    if ($python) {{ break }}
}}
if (-not $python) {{
    Write-Host "  ERROR: Python not found. Install Python 3.8+ from python.org" -ForegroundColor Red
    exit 1
}}
Write-Host "  Found Python: $($python.Source)" -ForegroundColor Gray

# Enroll
Write-Host "  [3/4] Enrolling with Citadel server..." -ForegroundColor Gray
& $python.Source "$installDir\citadel_shield.py" enroll $serverUrl $invitation
if ($LASTEXITCODE -ne 0) {{
    Write-Host "  ERROR: Enrollment failed." -ForegroundColor Red
    exit 1
}}

# Install scheduled task
Write-Host "  [4/4] Setting up auto-start..." -ForegroundColor Gray
& $python.Source "$installDir\citadel_shield.py" install

# Start daemon in background
Start-Process -FilePath $python.Source -ArgumentList "$installDir\citadel_shield.py", "daemon" -WindowStyle Hidden

Write-Host ""
Write-Host "  Citadel Shield installed and running!" -ForegroundColor Green
Write-Host "  Location: $installDir" -ForegroundColor Gray
Write-Host ""
"""


@router.get("/enroll/{invitation_id}/install.ps1")
async def install_script(
    invitation_id: str,
    request: Request,
    s: str = Query("", description="Enrollment secret"),
):
    """PowerShell installer script. Usage: irm <url> | iex"""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(429, "Too many requests.")

    if not INVITATION_ID_PATTERN.match(invitation_id) or not s:
        raise HTTPException(401, "Invalid install link.")

    store = _get_store()
    if not store.verify_secret_only(invitation_id, s):
        raise HTTPException(401, "Invalid or expired invitation.")

    inv = store.get_invitation(invitation_id)
    agent_name = inv.agent_name if inv else "Citadel Shield"

    server_url = _get_server_url(request)
    compact_string = f"CITADEL-1:{invitation_id}:{s}"
    download_url = f"{server_url}/enroll/{invitation_id}/download/windows_shield.py?s={s}"

    script = _PS1_TEMPLATE.format(
        agent_name=agent_name,
        download_url=download_url,
        server_url=server_url,
        compact_string=compact_string,
    )

    return PlainTextResponse(content=script, media_type="text/plain")


# ── Invitation Status (Polling) ───────────────────────────────────


@router.get("/enroll/{invitation_id}/status")
async def enrollment_status(
    invitation_id: str,
    request: Request,
    s: str = Query("", description="Enrollment secret"),
):
    """Check invitation status. Used by the enrollment page for real-time feedback."""
    ip = request.client.host if request.client else "unknown"
    if not _rate_check(ip):
        raise HTTPException(429, "Too many requests.")

    if not INVITATION_ID_PATTERN.match(invitation_id) or not s:
        return JSONResponse({"status": "invalid"}, status_code=401)

    store = _get_store()

    inv = store.get_invitation(invitation_id)
    if not inv:
        return JSONResponse({"status": "not_found"}, status_code=404)

    # For pending invitations, full verify (includes HMAC binding check)
    if store.verify_secret_only(invitation_id, s):
        return {"status": inv.status.value if hasattr(inv.status, "value") else inv.status}

    # For non-pending (redeemed/expired), verify just the secret hash
    # (verify_secret_only returns False for non-pending status)
    candidate_hash = hashlib.sha256(s.encode()).hexdigest()
    if not secrets.compare_digest(candidate_hash, inv.secret_hash):
        return JSONResponse({"status": "invalid"}, status_code=401)

    return {"status": inv.status.value if hasattr(inv.status, "value") else inv.status}


# ── Error Page Helper ─────────────────────────────────────────────


def _error_page(message: str) -> str:
    """Generate a minimal error page with the project's dark theme."""
    safe_message = _html.escape(message)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Citadel Archer - Enrollment</title>
<style>
  body {{ margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0a0e17; color: #e0e0e0; display: flex; align-items: center;
         justify-content: center; min-height: 100vh; }}
  .card {{ background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(0, 217, 255, 0.15);
           border-radius: 12px; padding: 2rem; max-width: 500px; text-align: center; }}
  h1 {{ color: #00D9FF; font-size: 1.5rem; margin-bottom: 1rem; }}
  p {{ color: #a0a0a0; line-height: 1.6; }}
</style>
</head>
<body>
<div class="card">
  <h1>Citadel Archer</h1>
  <p>{safe_message}</p>
</div>
</body>
</html>"""
