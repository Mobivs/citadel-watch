# Citadel Archer — Project Instructions

## What This Is
Citadel Archer is a **desktop** AI-centric defensive cybersecurity dashboard (Python/FastAPI backend, static HTML/JS/CSS frontend). It runs on Windows via Edge app mode (`msedge.exe --app=http://localhost:8000`). It coordinates security monitoring across the user's machines using remote agents.

## Current Version & State (v0.3.47)
- **Last session**: 2026-02-19
- **What works**: Full daemon deployment pipeline — `citadel_daemon.py` (Linux security agent, ext-agent API), `setup_daemon.sh` (one-liner), daemon threats/patch-status endpoints, chat thinking indicator (animated dots + per-tool status labels), 37/37 daemon tests + 19/19 smoke tests

## Priority Work (next session)
1. **Enroll VPS daemon** — create `vps` invitation in Assets UI, copy one-liner, run on Hostinger VPS (100.87.127.46), verify `systemctl status citadel-daemon` and threat reports in dashboard
2. **Verify timestamp fix** — restart app, confirm catch-up reports ~actual offline time (not hours)
3. **Bug #4 (PID 0)** — should be fixed (fix is in code); needs server restart to take effect

## Daemon Deployment
- One-liner: `curl -fsSL http://100.68.75.8:8000/api/ext-agents/setup.sh | sudo bash -s -- <invitation> http://100.68.75.8:8000`
- Daemon uses ext-agent API (`/api/ext-agents/`), NOT Shield API (`/api/agents/`)
- Invitation type must be `vps` (Shield type) — create in Assets UI
- Sensors: auth_log, processes, cron, file_integrity, resources, patches
- New endpoints: `POST /api/ext-agents/{id}/threats`, `POST /api/ext-agents/{id}/patch-status`

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

## Testing Strategy (smoke-first)
**Default**: `python -m pytest tests/test_smoke.py -v` (19 tests, ~18s) — run after every change.

**Only drill down when a smoke section fails**:
| Smoke Section | Full Test File(s) |
|---|---|
| S1 API Health | tests/test_integration.py |
| S2 Guardian File Monitor | tests/test_guardian_escalation.py |
| S3 Dashboard Ext | tests/test_dashboard_ext.py |
| S4 Alert System | tests/test_phase2_alerts.py |
| S5 Audit Log | tests/test_ai_audit.py |
| S6 Asset Inventory | tests/test_asset_aggregator.py |
| S7 Agent System | tests/test_agent_registry.py, test_agent_invitation.py |
| S8 Guardian Escalation | tests/test_guardian_escalation.py |
| S9 Risk / Threat Intel | tests/test_risk_metrics.py |
| S10 Remote Shield | tests/test_remote_shield_escalation.py |
| S11 Event Aggregator | tests/test_aggregator.py |
| S12 Panic Room | tests/test_remote_panic.py |

**NEVER run `python -m pytest tests/ -q`** for routine verification — it takes too long. Full suite only before major releases.

## v0.4.0 Backlog
- **Process execution logging** (Guardian, medium priority): When a file modification event fires, also capture the process that caused it — name, PID, command line, user. Allows identifying "was this Windows Update or malware?" Use `psutil` to correlate open file handles or Windows Event Log (Event ID 4663). Target format: `{"event_type": "file.modified", "process": {"name": "...", "pid": ..., "command_line": "...", "user": "..."}, "file": "...", "severity": "..."}`

## Enrolled Agent
- ID: f468e151e1bf4165994b76ea9b84615d
- Name: Hostinger-VPS-8, Type: claude_code
- Capabilities: system monitoring, log analysis, process inspection, network audit, file integrity, patch status, security scanning
