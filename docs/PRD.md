# Citadel Archer — Product Requirements Document

**Version:** v0.4.1
**Last Updated:** 2026-02-28
**Status:** Active Development — Core platform complete, v0.4.x hardening phase
**Changelog:** See [CHANGELOG.md](CHANGELOG.md) for the full version-by-version build history

---

## Executive Summary

**Citadel Archer** is a comprehensive defensive security platform empowering individuals to protect their digital presence with the sophistication typically available only to well-funded organizations. Built on the principle that **freedom requires security**, Citadel Archer provides active monitoring, rapid threat response, secure communications, and proactive defense across all managed systems — the local workstation, remote VPS instances, and family computers.

**Core Philosophy:**
- **Defense, Not Offense** — White hat protection only. No profiling, no offensive capabilities.
- **Privacy First** — All data stays on the user's machine. Zero telemetry, zero cloud storage.
- **Power to Individuals** — Enterprise-grade security accessible to everyone.
- **AI Acts, Not Asks** — AI acts within security level first, informs after. Questions only when ambiguous AND high-impact.
- **Token Minimization** — Automation handles ~90% of events at zero AI cost. AI is the last resort, not first responder.
- **Accessible to Non-Experts** — AI explains threats in plain language. Simplified Mode for non-technical users.
- **Proactive Protection** — "The promise of our app is doing nothing" — agents do the security work after enrolling.

---

## Problem Statement

### The Current Reality
Modern users face sophisticated, persistent threats:
- **Personal machines** compromised through phishing, malicious downloads, and browser extension spyware
- **Remote servers (VPS)** penetrated within days of deployment despite firewalls
- **Recovery is painful** — weeks to rebuild trust in compromised systems
- **Asymmetric power** — attackers have sophisticated tools; defenders have fragmented solutions
- **Privacy erosion** — security tools often become surveillance tools themselves
- **Technical barrier** — effective security requires expertise most people don't have

### What Users Need
- **Early warning system** — detect intrusions immediately, not months later
- **One-click mitigation** — rapid response without technical expertise
- **Secure communications** — coordinate with AI agents through an encrypted channel
- **Secrets management** — credentials that rotate instantly under attack
- **Remote protection** — secure VPS and family computers from a single interface
- **Peace of mind** — confidence that protection is always active and working

---

## Target Users

### Primary: Individual Power Users
- Technical enough to run VPS or manage family tech
- Targeted by persistent threats (activists, journalists, small business owners)
- Value privacy and autonomy
- Willing to learn but need tools that "just work"

### Secondary: Family & Friends
- Non-technical users protected through Citadel Archer's remote management
- Benefit from one-click panic button and automated protection
- Need simple, clear alerts (Simplified Mode)

### Tertiary: Security & Privacy Community
- Third-party security auditors validating approaches
- Privacy-focused users benefiting from shared threat intelligence (opt-in, anonymized)
- Beta testers helping refine detection capabilities and accuracy

---

## Core Modules — Current Capabilities

All modules below are **fully implemented** as of v0.4.0. Each section describes built capability.

---

### 1. Guardian — Local Machine Protection

**Purpose:** Real-time security monitoring of the local workstation.

**Implemented:**
- Filesystem monitoring via `watchdog` — detects unauthorized file changes, monitors critical paths
- Process monitoring via `psutil` — flags suspicious process behavior, privilege escalation
- Browser extension inventory scanning across all Chromium browsers (Chrome, Edge, Brave, Vivaldi)
- Real-time extension watcher — alerts on new installations, cross-references known-malicious database (6 categories: spyware, phishing, adware, cryptostealer, bloatware, suspicious)
- Automatic Guardian signature hot-reload from Intel feeds (no restart required)
- All events flow through EventAggregator → Watchtower → AI pipeline

**Key files:** `src/citadel_archer/guardian/`, `guardian/extension_scanner.py`, `guardian/extension_watcher.py`, `intel/guardian_updater.py`

---

### 2. Watchtower — Threat Detection & Intelligence

**Purpose:** Multi-layer threat analysis combining local events, remote agent data, and threat intelligence feeds.

**Implemented:**
- **Event Aggregator** — central event bus from all sensors (file, process, network, vault, system, remote, AI, user, intel)
- **Anomaly Detector** — scikit-learn Isolation Forest + Z-score fallback, 5-feature vector, cold-start protection (LOW threat until 20+ samples)
- **Threat Scorer** — risk matrix combining severity × confidence × anomaly × intel matches → RiskLevel (low/medium/high/critical)
- **Context Engine** — behavioral baselines per activity type; per-VPS baselines; detects anomalies vs. normal patterns
- **4 active intel feeds** — AlienVault OTX, abuse.ch (URLhaus + ThreatFox), MITRE ATT&CK, NVD CVE (daily scheduled at 02:00 UTC)
- **Cross-asset threat correlation** — detects shared IOCs, coordinated attacks, propagation patterns, intel matches across all managed assets
- **Threshold/Correlation Engine** — 10 rules (SSH brute force, critical file burst, vault unlock failures, network block surge, suspicious process cluster, VPS-specific rules), 30s batch windows, 5-min dedup, rate-limited escalation
- **Unified threat timeline** — merges local, Remote Shield, and correlation events chronologically with source filtering

**Key files:** `src/citadel_archer/intel/`, `chat/threshold_engine.py`, `intel/cross_asset_correlation.py`

---

### 3. Panic Room — Emergency Response System

**Purpose:** One-click emergency response that can isolate, snapshot, rotate credentials, and recover from active attacks — locally and remotely.

**Implemented:**
- **Action framework** — base class lifecycle (execute/verify/rollback) for all panic actions
- **Playbook engine** — orchestrates multi-action playbooks with pre-flight checks, async execution, progress tracking
- **Credential rotation** — SSH keys, API tokens, passwords; updates Vault; supports remote rotation via SSH; 30-day key archive
- **Network isolation** — iptables rules with whitelist, state capture, full rollback capability
- **System snapshot** — forensic captures (process dumps, network state, file hashes, log collection)
- **Secure backup** — encrypted backup with integrity verification and restore
- **Remote panic dispatch** — dispatches isolation/termination/rollback to Remote Shield agents via command queue
- **Per-asset rollback** — independent recovery scoping per managed asset in multi-target sessions
- **AI triage** — Panic Room activation/completion/failure escalates to AI for guidance (Trigger 2c)

**Key files:** `src/citadel_archer/panic/`, `panic/playbook_engine.py`, `panic/actions/`, `remote/panic_dispatcher.py`

---

### 4. Vault — Secrets Management

**Purpose:** Encrypted storage for credentials, API keys, and SSH keys with Panic Room integration.

**Implemented:**
- Per-entry AES-256-GCM encryption via `cryptography` library
- PBKDF2 key derivation from master password (600,000 iterations)
- Rate-limited unlock — prevents brute-force against master password
- SSH credential type — structured metadata for host, port, username, key material
- Panic Room integration for instant credential rotation
- REST API with session-token authentication

**Key files:** `src/citadel_archer/vault/vault_manager.py`, `vault/encryption.py`

---

### 5. SecureChat — Command Infrastructure

**Purpose:** The encrypted communication backbone for all command-level interaction between the user, AI agents, and the Citadel system. Not "chat with friends" — foundational infrastructure.

**The Two-Tier Communication Model:**

| Tier | Name | What flows through it |
|------|------|-----------------------|
| Low-level | Automation Communication System (ACS) | Sensor data, heartbeats, metrics, routine alerts — no AI, no tokens |
| High-level | SecureChat System (SCS) | User commands, AI analysis, escalations, agent coordination — tokens when AI involved |

**Token Minimization — 4-level escalation hierarchy:**

| Level | Component | Tokens? | Resolves |
|-------|-----------|---------|----------|
| 1 | Tripwire Rules | None | Known patterns — malware sigs, known-bad IPs, brute force thresholds |
| 2 | Threshold/Correlation Engine | None | Aggregated patterns — dedup same attack from N agents, breach thresholds |
| 3 | AI Analysis (AI Bridge) | Yes | Novel threats, ambiguous patterns, strategic recommendations, multi-step response |
| 4 | Human Decision | N/A | <5% of events — ambiguous + high-impact situations where AI defers to user |

**Cost model:** Levels 1-2 handle ~80-90% of events at zero token cost. Typical daily usage: 10-30 AI calls.

**Implemented:**
- Always-visible sidebar (not a tab — independent of tab-loader lifecycle)
- Message persistence (SQLite `data/securechat.db`)
- Real-time WebSocket delivery; collapse/expand with unread badge
- AI Bridge — Claude API with tool use, context building, 8 AI triggers (all implemented)
- **Serial approval system** — write commands create an asyncio.Future; AI tool loop blocks per-command until user approves or denies; stale approval cards purged on restart
- All 8 AI triggers: 1a (user TEXT), 1b (ext agent REST API), 2a (remote agents), 2b (local Guardian), 2c (Panic Room), 3a (daily posture), 3b (startup catch-up), 3c (threshold breach)
- Per-participant token quota (200K/hr user, 50K/hr ext-agent, 500K/hr system)
- Append-only AI audit log for all tool invocations and decisions
- Do Not Disturb mode — silences AI messages including VPS daemon reports
- Ollama local LLM fallback when Claude API is unavailable
- Multi-AI participant support: user, Claude Code, OpenClaw, Forge, Citadel system

**Key files:** `src/citadel_archer/chat/ai_bridge.py`, `chat/chat_manager.py`, `chat/threshold_engine.py`, `chat/startup_catchup.py`

---

### 6. Intel — Threat Intelligence

**Purpose:** Live threat intelligence from 4 feeds, automatically updating Guardian signatures.

**Implemented:**
- **AlienVault OTX** — IOC/CVE extraction with pagination and retry
- **abuse.ch** (URLhaus + ThreatFox) — malicious URLs and IOCs with severity mapping
- **MITRE ATT&CK** — STIX 2.1 Enterprise bundle; TTPs with platform and sub-technique handling
- **NVD CVE** — NIST CVE API v2.0 with CVSS v3/v2 scoring and rate-limit compliance
- Daily scheduled fetches (APScheduler, 02:00 UTC), deduplication, severity-based conflict resolution
- SQLite intel store with query/filter capabilities
- Auto-generates Guardian detection rules from IOCs/TTPs/CVEs (hot-reload, no restart)

**Key files:** `src/citadel_archer/intel/`

---

### 7. Remote Shield — VPS & Remote Protection

**Purpose:** Extend Citadel Archer protection to remote Linux VPS and Windows machines. Deploy, monitor, manage, and respond from the dashboard.

**Implemented:**
- **Linux daemon** (`citadel_daemon.py`) — persistent systemd service, 6 sensors: auth_log, processes, cron, file_integrity, resources, patches
- **One-liner deployment** — `curl -fsSL .../setup.sh | sudo bash -s -- <invitation> <url>` installs and starts daemon
- **Daemon threat reporting** — `POST /api/ext-agents/{id}/threats` and `POST /api/ext-agents/{id}/patch-status`
- **Windows Shield agent** (`windows_shield.py`) — stdlib-only, 5 sensors (Event Log, Defender, Firewall, Processes, Software), installs as Task Scheduler task
- **Invitation-based enrollment** — HMAC-signed one-time tokens with TTL; email invite flow with enrollment landing page and live status polling
- **SSH hardening** — key-only auth, port knocking (iptables `recent` module), fail2ban++ with escalating progressive banning
- **VPS firewall management** — desktop-managed iptables rules pushed via SSH; geo-blocking via CIDR file
- **Automated patching** — Windows Update monitoring; remote "Check for Updates" trigger via command queue
- **Group policies** — named security profiles fanned out to agent groups via command queue
- **Node onboarding orchestrator** — 6-step workflow with WebSocket real-time progress
- **Threat routing to AI** — VPS events flow through EventAggregator → Watchtower → AI pipeline (Trigger 2a)
- **Agent context delivery** — enrolled agents receive operational context and API reference at enrollment via `GET /api/ext-agents/context`
- **Tailscale network** — agents communicate over Tailscale VPN; CORS and HMAC auth configured

**Tailscale Network:**
- Home machine (nucbox-evo-x2): 100.68.75.8
- Hostinger VPS (srv1360615): 100.87.127.46

**Key files:** `src/citadel_archer/agent/citadel_daemon.py`, `agent/setup_daemon.sh`, `agent/windows_shield.py`, `remote/`, `api/agent_api_routes.py`, `api/ext_agent_routes.py`

---

### 8. Dashboard — Unified Control Center

**Purpose:** Dark glassmorphic desktop application (Edge app mode) displaying all security data with always-visible AI assistant sidebar.

**Implemented tabs:**
- **Intelligence** — main threat feed, AI chat sidebar
- **Assets** — managed assets with status, enrollment flow, SSH command approval cards
- **Charts** — real-time event charts (Chart.js)
- **Timeline** — unified chronological threat timeline (D3.js) with source filtering (local/remote/correlation)
- **Risk Metrics** — risk gauges, anomaly scores, fleet attention scoring
- **Remote Shield** — VPS agents, threat feeds, patching, group policies (technical + simplified views)
- **Vault** — credential management
- **Backup** — encrypted backup/restore of all 11 databases
- **Performance** — fleet health, per-asset attention scores (0-100), reason chips
- **Panic Room** — emergency response with playbook selection and real-time remote status
- **Ops Center** — operational topology, metrics, event feed (session-authenticated)

**Simplified Mode:** Non-technical users see reduced tab set; plain-English threat descriptions; colored-dot status; "Suggested Action" cards.

**Key files:** `frontend/`, `frontend/js/`, `src/citadel_archer/desktop.py`

#### Feature: Event Resolution Status (v0.4.1 — Planned)

**Problem:** Yellow warning badges persist indefinitely after a threat is remediated. There is no visual distinction between "active threat" and "resolved threat." Users cannot tell at a glance what is actionable versus what is historical.

**Behaviour spec:**

Keep the original severity badge (color unchanged — shows what the threat level *was*). Change the event text and add resolution metadata inline:

```
[YELLOW]  26 pending patches on srv1360615 — ✓ Resolved  apply_patches · 2026-03-01 14:32 UTC
[RED]     SSH brute force from 185.220.101.42 — ✓ Resolved  block_ip · 2026-03-01 09:14 UTC
[YELLOW]  Suspicious process: miner.exe — ⏳ Active
```

- **Badge** — original severity color unchanged (yellow/red/orange/green) = "this is what happened"
- **Text** — muted gray when resolved, normal when active = "is this still a problem?"
- **Resolution chip** — `✓ Resolved · <action_taken> · <timestamp>` appended inline
- **Active chip** — `⏳ Active` for unresolved threats in the active threat view

**Resolution triggers (both):**
1. **Auto** — when the AI executes a defensive action (`block_ip`, `apply_patches`, `kill_process`, `execute_ssh_command` with a write command), the AI bridge calls `mark_event_resolved(event_id, action, notes)` for the relevant event(s)
2. **Manual** — user right-clicks / long-presses any event card and selects "Mark Resolved" with optional notes

**Applies to:** Unified Timeline tab, Remote Shield threat cards, Intelligence feed — all event display surfaces.

**Technical approach:**
- New `event_resolutions` table in a shared DB (`data/resolutions.db`) — keyed by `source` (aggregator/shield/correlation/daemon) + `external_id`; stores `action_taken`, `resolved_at`, `resolved_by` (ai/user), `notes`
- New AI Bridge tool: `mark_event_resolved(event_id, source, action_taken, notes)` — called automatically after defensive actions
- New REST endpoint: `POST /api/events/{source}/{id}/resolve` (session auth, manual resolution); `DELETE` to un-resolve
- Frontend: resolution state fetched alongside events; rendering updated per surface (timeline.js, remote-shield.js, chat-sidebar.js)
- No existing event schemas modified — resolution is a side-car record, not inline mutation

**UX principle:** Yellow badge = "was serious." Green/gray text = "we handled it." Together = full audit trail without cluttering the active threat view.

---

### 9. Defense Mesh — Distributed Resilience

**Purpose:** Multi-node coordination protocol where each node monitors peers and can operate autonomously when the coordinator goes dark.

**Implemented:**
- **Mutual heartbeat protocol** — UDP-based, HMAC-SHA256 signed with 256-bit pre-shared keys
- **Escalation state machine** — NORMAL → ALERT (haiku AI, 3 missed) → HEIGHTENED (sonnet AI, 5 missed) → AUTONOMOUS (opus AI, 10 missed)
- **Autonomous escalation** — progressive defensive actions without coordinator: lower thresholds → emergency firewall rules → full lockdown
- **Peer alerting** — surviving nodes notify each other of failures via signed UDP packets
- **Secondary brain** — designate a VPS as fallback coordinator; sanitized asset registry (no private keys); decisions queued for desktop review on reconnection
- **Brain hardening** — restricted SSH, fail2ban, encrypted API keys (AES-128-CBC/PBKDF2), separate credentials, API rate limiter
- **Compartmentalized secrets** — role-based access control (SecretScope: GLOBAL/BRAIN/AGENT/MESH); each node provisioned only what it needs
- **Recovery/reconciliation** — 5-step protocol when desktop returns: sync events, review decisions (auto-accept safe/auto-rollback dangerous), resolve conflicts, restore heartbeats, merge audit log
- **Escalation deduplication** — distributed attacks across N agents produce ONE merged escalation

**Key files:** `src/citadel_archer/mesh/`

---

### 10. LocalHostDefender — Protect the Command Center

**Purpose:** Execute security commands on the local machine without SSH. Registers the machine running Citadel Archer itself as a managed asset so the AI can investigate and respond to local threats.

**Problem it solves:** The command center was the least protected asset — not registered, no command execution capability, couldn't take defensive action against local threats.

**Implemented:**
- Auto-registers `localhost` as `asset_id="localhost"` on startup (idempotent, uses `AssetPlatform.LOCAL`)
- PowerShell executor (Windows) or bash (Linux/macOS)
- `execute_command_async` via `run_in_executor` — never blocks the asyncio event loop; prevents heartbeat watchdog crash
- **Direct ssh-keygen executor** — bypasses PowerShell entirely; avoids PS 5.x empty-argument dropping bug; `-N ""` passed as separate Python list elements reaching the binary intact
- Same approval flow as SSH commands: Guardian/Observer requires user approval (asyncio.Future serial); Sentinel auto-executes
- Whitelist extended with PowerShell read-only cmdlets: `Get-Process`, `Get-FileHash`, `Get-AuthenticodeSignature`, `Get-NetFirewallRule`, `Get-NetTCPConnection`, `Get-Service`, `Get-ScheduledTask`, `Get-LocalUser`, `Get-WinEvent`, etc.
- AI can rotate SSH keys end-to-end: generate → read public key → push to VPS authorized_keys

**Key files:** `src/citadel_archer/local/local_defender.py`

---

### 11. LAN Sentinel — Local Network Device Inventory

**Purpose:** Maintain a live inventory of every device on the home LAN and alert when an unknown device joins the network. Provides the visibility layer that the proprietary Verizon 5G router blocks at the router level.

**Problem it solves:** The Verizon 5G router has no API or SSH access — it is a black box. An attacker or rogue device can join the LAN completely undetected. Since the NucBox already sits on the LAN, it can perform ARP sweeps and connection monitoring without any router cooperation.

**Architecture:**
- `LanDeviceStore` — SQLite singleton at `data/lan_devices.db`; table `lan_devices (mac TEXT PK, ip, hostname, manufacturer, first_seen, last_seen, is_known INTEGER DEFAULT 0, label TEXT)`
- `LanScanner` — background asyncio task started in `startup_event()`; uses `run_coroutine_threadsafe` pattern (same as GuardianEscalation); all subprocess calls wrapped in `run_in_executor`
- Scan dispatch: `shutil.which("nmap")` probe — nmap when installed (richer: MAC vendor + PTR hostname), `Get-NetNeighbor` Windows-native fallback (zero new dependencies)
- Subnet auto-detection: `Get-NetIPAddress` → JSON → Python `ipaddress` stdlib to compute CIDR
- New device → `aggregator.ingest(event_type="lan.new_device", severity="alert")` + `await broadcast({"type": "lan_device_discovered", ...})`

**Implemented (Phase 1):**
- Periodic ARP scan every 5 minutes (configurable via `LAN_SCAN_INTERVAL` env var)
- Device inventory UI (`lan-sentinel.html` tab) with status badges (Known / Unknown with pulse animation)
- "Scan Now" button for manual immediate scan
- "Mark as Known" per-device acknowledgement with optional friendly label
- WebSocket live updates — new-device toast notification instantly appears without polling
- Footer: last scan time, subnet being scanned, mode (nmap / native), scan interval
- REST API: `GET /api/lan/devices`, `GET /api/lan/status`, `POST /api/lan/scan`, `POST /api/lan/devices/{mac}/known`

**Phase 2 (Planned):**
- AdGuard Home Docker container on NucBox — DNS-level LAN protection, per-device filtering, query logs
- AdGuard Home REST API integration for blocklist management and per-device policies

**Phase 3 (Planned):**
- Outbound connection monitoring (Zeek or Suricata lightweight) — detect C2 beaconing patterns
- VLAN capability assessment when a managed router is available

**Key files:** `src/citadel_archer/local/lan_scanner.py`, `src/citadel_archer/api/lan_routes.py`, `frontend/lan-sentinel.html`, `frontend/js/lan-sentinel.js`

---

### 12. Advanced Communications — P2P Encrypted Messaging

**Purpose:** Signal-like end-to-end encrypted peer-to-peer messaging, contact management, and secure file sharing between trusted contacts.

**Implemented:**
- **X3DH key agreement** — Extended Triple Diffie-Hellman session establishment (4 DH exchanges); Ed25519 signed prekeys; one-time prekeys for forward secrecy
- **Double Ratchet** — full Signal-spec implementation; DH ratchet for forward secrecy; symmetric ratchet for message key derivation; out-of-order message handling (capped skipped keys)
- **AES-256-GCM AEAD** — 96-bit random nonces; associated data binds session identity to ciphertext
- **Contact registry** — SQLite-backed, trust levels (pending/verified/trusted/blocked), Ed25519 public key management, SHA-256 fingerprint display, tag filtering
- **Secure file sharing** — per-file AES-256 keys, self-destruct on download, TTL (1-168h), SHA-256 integrity verification, Content-Disposition sanitized against header injection
- **Inter-agent protocol** — capability-based discovery, task delegation (PENDING → ACCEPTED → COMPLETED/FAILED), presence tracking via heartbeat, buffered inbox

**Key files:** `src/citadel_archer/chat/p2p_crypto.py`, `chat/session_store.py`, `chat/contact_registry.py`, `chat/secure_file.py`, `chat/inter_agent.py`

---

## AI-Centric Architecture

### AI Tools Available to the AI Bridge

**Read-only (all security levels — auto-execute):**
- `get_system_status` — current security posture, event counts, anomaly scores
- `get_asset_list` — all managed assets with status
- `get_agent_events` — VPS agent health + severity breakdown (critical/high/medium/low counts)
- `get_vps_summary` — bird's-eye view of all VPS agents with grouped threat counts
- `get_recent_events` — filtered event log
- `get_vault_status` — vault lock state (NOT contents — never exposes secrets)
- `get_threat_intel` — recent IOCs and CVEs
- `get_risk_metrics` — current risk scores
- `execute_ssh_command` (read-only commands) — auto-execute against safe-command whitelist

**Write (Guardian/Observer: require user approval; Sentinel: auto-execute, logged):**
- `execute_ssh_command` (write commands) — remote or local command execution via serial approval
- `block_ip` / `unblock_ip` — firewall management
- `kill_process` — terminate suspicious processes
- `quarantine_file` — isolate suspicious files
- `rotate_credentials` — trigger Panic Room credential rotation
- `activate_panic_room` — full emergency response

### The 8 AI Triggers (All Implemented)

| # | Trigger | Category |
|---|---------|----------|
| 1a | User sends TEXT in SecureChat | SecureChat message |
| 1b | External AI agent sends via REST API | SecureChat message |
| 2a | Remote Shield / Linux daemon escalation | Critical threat |
| 2b | Local Guardian ALERT/CRITICAL event | Critical threat |
| 2c | Panic Room activation/completion/failure | Critical threat |
| 3a | Scheduled daily posture analysis | App-initiated |
| 3b | Startup catch-up (offline event summary) | App-initiated |
| 3c | Threshold/correlation breach | App-initiated |

---

## Technical Architecture

### Technology Stack

**Backend:**
- Python 3.11+, FastAPI, uvicorn (0.0.0.0:8000, Tailscale accessible)
- SQLite with WAL mode for all databases via `core/db.py`
- WebSocket real-time push for dashboard and AI chat
- Anthropic SDK (Claude API); aiohttp (Ollama local LLM fallback)

**Frontend:**
- Vanilla JS + Web Components (no React, no npm build pipeline, no supply chain risk)
- Chart.js + D3.js loaded lazily per tab
- Dark glassmorphic theme, neon blue (#00D9FF) accent, 13px base font

**Desktop:**
- Microsoft Edge app mode (`msedge.exe --app=http://localhost:8000`) — no pywebview, guaranteed on Windows 10/11
- Session auth: 256-bit tokens (`secrets.token_urlsafe`), X-Session-Token header, constant-time comparison
- Heartbeat watchdog: 120-second grace period; auto-shutdown on window close (survives Edge timer throttling when minimized)

**Security:**
- AES-256-GCM encryption (Vault, backups, P2P file sharing, secure notes)
- PBKDF2-SHA256 key derivation (600K iterations)
- HMAC-SHA256 mesh heartbeat signing (256-bit pre-shared keys)
- X3DH + Double Ratchet (Signal protocol) for P2P encrypted messaging
- Constant-time secret comparison throughout (no timing side-channels)

**Networking:**
- Tailscale VPN for desktop-VPS communication
- CORS origin allowlist includes Tailscale addresses
- External agents: Bearer token auth (`Authorization: Bearer ...`)
- Dashboard: session token in `X-Session-Token` header
- `tailscale serve --bg --tcp 8000 tcp://localhost:8000` bypasses Windows Firewall for Tailscale adapter

### Database Layout

All databases under `data/` (relative to working directory), WAL mode:

| File | Contents |
|------|----------|
| `securechat.db` | Chat messages, participants |
| `vault.db` | Encrypted credentials |
| `agent_registry.db` | External AI agents and tokens |
| `shield.db` | Remote Shield agents, threats, commands, firewall rules |
| `intel.db` | Threat intelligence items (IOCs, CVEs, TTPs) |
| `ai_audit.log` | Append-only AI tool invocation log (JSON lines) |
| `audit.db` | Security event audit trail |
| `panic.db` | Panic sessions, action history, recovery states |
| `backup.db` | Backup metadata |
| `mesh.db` | Mesh peers, heartbeat log |
| `user_prefs.db` | User preferences (dashboard mode, templates) |

---

## Development Status & Roadmap

### Completed — v0.1.0 through v0.3.49

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1: Foundation | Guardian, Watchtower, Vault, SecureChat sidebar + AI Bridge, Dashboard, session auth | ✅ Complete |
| Phase 2: Intelligence & Remote | Intel feeds (4), VPS agents, SSH hardening, Windows Shield, group policies, cross-asset correlation, AI triggers 1-8 | ✅ Complete |
| Phase 3: Panic Room | Emergency response framework, credential rotation, remote panic dispatch, per-asset rollback | ✅ Complete |
| Phase 4: Advanced Comms | E2E P2P crypto (X3DH + Double Ratchet), contact registry, secure file sharing, inter-agent protocol | ✅ Complete |
| Phase 5: Defense Mesh | Mutual heartbeat + HMAC, autonomous escalation, secondary brain, compartmentalized secrets, recovery protocol | ✅ Complete |
| Additional Features | Performance analytics, backup/restore, simplified mode, email enrollment, ops center, LocalHostDefender, Linux daemon + one-liner, serial approval, DND mode, LAN Sentinel Phase 1 | ✅ Complete |

### Current Focus — v0.4.x (Hardening & Production Readiness)

1. **VPS daemon enrollment** — Enroll Hostinger VPS (100.87.127.46), verify threat reports appear in dashboard
2. **Timestamp accuracy** — Confirm catch-up reports show correct offline duration after restart
3. **SSH key rotation** — End-to-end via LocalHostDefender (generate → distribute → verify)
4. **Bug fixes** — PID 0 in process events (fix deployed, needs restart to confirm)
5. **Event Resolution Status UI** (v0.4.1) — See Dashboard module feature spec above. Backend: `event_resolutions` table + `mark_event_resolved` AI tool + REST endpoint. Frontend: all event display surfaces updated. Auto-resolves on AI defensive action; manual resolve available to user.
6. **Chocolatey reinstall defensive action** — `choco reinstall <package>` as a first-class defensive action for Windows package remediation. System file locks (SYSTEM process holds `C:\Program Files\*`) prevent PowerShell force-deletion of managed packages. Chocolatey handles the lock and reinstall atomically. AI should prefer this over delete+install sequences for any Chocolatey-managed package.
7. **Guardian file-level whitelisting** — When a change is detected in a system-protected directory that cannot be scripted away (locked by SYSTEM, requires MSI/Chocolatey), allow marking the event "known compromise — awaiting manual remediation" to suppress repeat alerts. Persistent per-path suppression with optional expiry. Prevents infinite re-alerting loops on locked files.
8. **Process execution logging** — When a file modification event fires, capture the causative process (name, PID, command line, user) via `psutil` or Event ID 4663. Distinguishes Windows Update from malware on the same file path.

### Windows Platform Notes

These behaviors are **expected and documented** — they are not bugs in Citadel Archer:

| Directory | Lock holder | Correct remediation |
|---|---|---|
| `C:\Program Files\nodejs` | SYSTEM process | `choco reinstall nodejs -y` |
| `C:\Program Files\*` (any choco package) | SYSTEM / installer | `choco uninstall <pkg> -y && choco install <pkg>` |
| `C:\Windows\System32\*` | SYSTEM / TrustedInstaller | Windows Update or DISM; no script workaround |
| `C:\ProgramData\*` | Service processes | Stop the owning service first, then act |

**Guardian alert strategy for locked files**: When Guardian fires on a path in a system-protected directory that our scripts cannot modify, the correct AI response is:
1. Mark the event resolved with `action_taken="awaiting_manual_remediation"` using `mark_event_resolved`
2. Tell the user what manual step is required (e.g., "run `choco reinstall nodejs` in an admin terminal")
3. Do NOT retry the failed delete — it will loop

### Next Phase — v0.5.0 (Distribution & Always-On)

- **Windows Service** (`citadel-service`) — Guardian sensors running 24/7 even when the desktop app is closed; headless ACS protection
- **Auto-update mechanism** — notify + one-click install with code signature verification
- **Forge/Telegram integration** — out-of-band notifications via user's personal AI assistant when away from dashboard
- **SecureChat browser client** — web-based access to the SecureChat sidebar from any device

### Future — v1.0+ (Platform)

- Community threat sharing (anonymized, opt-in)
- Mobile app (iOS/Android remote management)
- Hardware key support (YubiKey for Vault)
- Voice/video calls (WebRTC, E2E encrypted)
- White-label licensing for security companies
- Enterprise multi-tenant deployment

---

## Security Considerations

### Threat Model

**What we protect against:**
- Malware and ransomware
- Phishing and social engineering
- Remote intrusions and lateral movement
- Credential theft and reuse
- Data exfiltration and persistent backdoors
- Zero-day exploits (through behavioral analysis)
- Browser extension threats (keystroke loggers, DOM injection, silent sideloads)
- Supply chain attacks on software dependencies

**What we don't protect against:**
- Nation-state actors with unlimited resources (we make it significantly harder)
- Physical access to an unlocked machine
- User intentionally disabling protection
- Supply chain attacks on hardware

### Privacy Guarantees
- **Local-first** — all data on user's machine, never in cloud
- **No telemetry** — zero data collection without explicit opt-in
- **Encrypted at rest** — AES-256-GCM for credentials, backups, P2P messages
- **User control** — user owns all data; can export or delete anytime
- **Transparent AI** — clear documentation of what AI can access; append-only audit trail

### Security Architecture Principles
- Principle of least privilege throughout all modules
- Constant-time secret comparison everywhere (no timing side-channels)
- Append-only AI audit trail for all tool invocations (immutable accountability)
- Session tokens rotate on every restart — invalidates all outstanding HMAC-bound invitations
- All databases in WAL mode via `core/db.py` (concurrent access safety)
- No mutable defaults in Pydantic models (`Field(default_factory=...)`)
- Command output capped at 8KB per stream (prevents memory exhaustion from verbose commands)
- Stale approval cards purged from database on startup (prevents phantom approval UX after crash)

---

## Decided Architecture (Locked In)

1. ✅ **Platform Priority** — Windows 10/11 first; Ubuntu for VPS agents second
2. ✅ **AI Models** — Claude API (Anthropic SDK) primary; Ollama local LLM fallback
3. ✅ **Frontend** — Vanilla JS + Web Components (no React, no npm; minimal supply chain risk)
4. ✅ **Desktop GUI** — Microsoft Edge app mode (`msedge.exe --app=URL`); guaranteed on Windows 10/11
5. ✅ **Session Authentication** — 256-bit tokens (`secrets.token_urlsafe`), X-Session-Token header, constant-time comparison; rotates on restart
6. ✅ **Two-Tier Communication** — ACS (sensor/metric/heartbeat, no AI) + SCS (command-level, AI-assisted when needed)
7. ✅ **Token Minimization** — 4-level escalation; tripwire → threshold → AI → human. AI is last resort.
8. ✅ **Multi-AI Participation** — SecureChat supports multiple AI agent types (Claude Code, Forge, OpenClaw, ext agents) authenticated via Bearer tokens
9. ✅ **Heartbeat HMAC** — All mesh heartbeats HMAC-SHA256 signed with 256-bit pre-shared keys; spoofing prevention
10. ✅ **Append-Only AI Audit** — All AI tool invocations logged to immutable `ai_audit.log` (JSON lines, rotating file handler)
11. ✅ **Forge/Telegram Channel** — Out-of-band notification path via user's AI assistant (planned v0.5.0)
12. ✅ **Anomaly Detection ML** — scikit-learn Isolation Forest primary; Z-score statistical fallback; sensitivity presets
13. ✅ **Database Convention** — All databases under `data/`, WAL mode, via `core/db.py`; no absolute system paths
14. ✅ **Licensing** — Proprietary with free tier (protects defensive algorithms from attacker study)
15. ✅ **AI Autonomy** — Hybrid: auto-respond to known threats within security level; ask user only for ambiguous + high-impact
16. ✅ **Serial Approval** — Write commands block the AI tool loop via asyncio.Future until user approves/denies; `max_iterations` raised to 20 for multi-step chains
17. ✅ **LocalHostDefender** — Local machine is a first-class managed asset; commands bypass SSH and use subprocess executor; ssh-keygen runs directly (not via PowerShell) to avoid PS 5.x empty-argument dropping
18. ✅ **Linux Daemon** — VPS agents run as systemd services via one-liner setup; use ext-agent API (`/api/ext-agents/`) NOT Shield API (`/api/agents/`)
19. ✅ **Server Binding** — Backend binds to 0.0.0.0 (required for Tailscale access); session token + CORS origin allowlist for auth
20. ✅ **Approval Future Resolution** — If `future_resolved=True`, skip guardian notification (Claude already has result via tool_result; firing creates redundant AI calls)

---

## Open Questions (Deferred)

1. **Community threat sharing** — what data is safe to share anonymously? (v1.0+)
2. **Mobile** — native app or managed from desktop only? (v1.0+)
3. **SecureChat relay** — optional relay server for remote web access? (v0.5.0)
4. **Hardware keys** — YubiKey integration priority? (v0.5.0 or v1.0)
5. **Always-on service** — Windows Service vs. scheduled task for headless Guardian?

---

## Glossary

- **ACS** — Automation Communication System; low-level tier for sensor data, heartbeats, metrics (no AI, no tokens)
- **C2** — Command and Control (attacker's remote access mechanism)
- **CVE** — Common Vulnerabilities and Exposures (public vulnerability database)
- **Defense Mesh** — Multi-node coordination protocol where each node monitors peers and can operate autonomously
- **DND** — Do Not Disturb mode; silences AI assistant messages including VPS daemon reports
- **E2E** — End-to-End Encryption
- **ext-agent API** — The `/api/ext-agents/` route prefix used by Linux daemons and enrolled VPS agents (NOT `/api/agents/`)
- **Forge** — The user's personal AI assistant; can reach user via Telegram at any time
- **HMAC** — Hash-based Message Authentication Code; signs mesh heartbeats to prevent spoofing
- **IOC** — Indicator of Compromise (evidence of breach)
- **LocalHostDefender** — Module executing security commands on the local machine without SSH; registers the command center as a managed asset
- **MITRE ATT&CK** — Framework of adversary tactics and techniques
- **SCS** — SecureChat System; high-level tier for command-level communication (user, AI agents, escalations)
- **Serial Approval** — asyncio.Future pattern blocking the AI tool loop per-command until user approves or denies
- **Threshold Engine** — Component between ACS and SCS that correlates patterns, deduplicates events, and escalates to SCS on breach
- **Token Minimization** — Design principle: resolve at the lowest automation level before involving AI; AI is expensive and adds latency
- **VPS** — Virtual Private Server
- **WAL** — Write-Ahead Logging; SQLite mode enabling concurrent read/write access
- **Zero-day** — Previously unknown vulnerability with no available patch

---

## Appendix: Design Inspiration

### UI/UX References
- Glassmorphism: [glassmorphism.com](https://glassmorphism.com)
- Neon blue aesthetic: Cyberpunk 2077 UI, Tron Legacy
- Security dashboards: Splunk, Datadog, Grafana (but leaner and prettier)

### Security Tool References
- **OSSEC** — Host-based IDS (inspiration for Guardian)
- **Snort/Suricata** — Network IDS (inspiration for Watchtower)
- **Bitwarden** — Password manager (inspiration for Vault)
- **Signal** — Secure messaging with X3DH + Double Ratchet (inspiration for P2P SecureChat)

---

*This is a living document updated to reflect what is actually built. See [CHANGELOG.md](CHANGELOG.md) for the complete version-by-version build history.*
