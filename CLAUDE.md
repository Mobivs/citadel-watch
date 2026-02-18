# Citadel Archer — Project Instructions

## What This Is
Citadel Archer is a **desktop** AI-centric defensive cybersecurity dashboard (Python/FastAPI backend, static HTML/JS/CSS frontend). It runs on Windows via Edge app mode (`msedge.exe --app=http://localhost:8000`). It coordinates security monitoring across the user's machines using remote agents.

## Current Version & State (v0.3.44)
- **Last session**: 2026-02-17 — Successfully enrolled a remote Claude Code agent on a Hostinger VPS via Tailscale mesh network
- **What works**: Agent enrollment flow (invitation → onboarding prompt → enroll → heartbeat → capabilities → context delivery)
- **What's broken**: Enrolled agents don't appear in the Assets page; no actual security automation running on VPS after enrollment

## Priority Work (next session)
1. **Fix agent visibility in Assets** — enrolled agents must show up in the Assets page
2. **Build persistent agent daemon** — Python script for VPS that heartbeats, polls inbox, runs security scans, reports findings
3. **One-liner setup script** — `curl ... | bash` that installs Tailscale, enrolls agent, starts daemon
4. **UX is job 2 behind security** — target users are NOT security experts; everything must be automated and painless

## Architecture
- Backend: FastAPI at port 8000, bound to `0.0.0.0` (for Tailscale access)
- Frontend: Static files in `frontend/`, served by FastAPI
- Database: SQLite (various `.db` files in `data/`)
- Agent routes: `/api/ext-agents/` (NOT `/api/agents/`)
- Shield routes: `/api/shield/`
- Auth: Session token (desktop admin) + Bearer tokens (remote agents)

## Tailscale Network
- Home (nucbox-evo-x2): 100.68.75.8
- Hostinger VPS (srv1360615): 100.87.127.46
- Use `tailscale serve --bg --tcp 8000 tcp://localhost:8000` on Windows (firewall bypass)
- CORS origin for Tailscale: `http://100.68.75.8:8000`

## Key Conventions
- Dark glassmorphic theme, neon blue (#00D9FF) accent
- No emoji in Python print/logging (Windows cp1252 encoding crashes)
- Tab pages use `init()`/`destroy()` lifecycle; only one tab content in DOM at a time
- Audit logging: `log_security_event(EventType, EventSeverity, message, details=...)`
- Tests: `python -m pytest tests/ -q` — currently 3,469 passing

## Enrolled Agent
- ID: f468e151e1bf4165994b76ea9b84615d
- Name: Hostinger-VPS-8, Type: claude_code
- Capabilities: system monitoring, log analysis, process inspection, network audit, file integrity, patch status, security scanning
