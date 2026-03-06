# Citadel Archer — Changelog

This file contains the complete version-by-version build history. For what is currently built and the product vision, see [PRD.md](PRD.md).

**Format:** Newest versions at the top.

---

## v0.4.1 (2026-02-28) — Event Resolution Status UI

**Status:** Complete — 31/31 smoke tests passing.

**Summary:** When a threat is remediated via defensive action, event displays update to show resolution status while preserving the original severity badge. The severity badge stays unchanged (shows what happened); description text turns gray and a green `✓ action_taken` chip is added (shows it was handled). Guardian AI calls `mark_event_resolved` automatically after defensive actions. Users can also resolve manually via the detail panel.

**Key components:**
- `src/citadel_archer/intel/resolution_store.py` (NEW) — `ResolutionStore` singleton, WAL SQLite at `data/resolutions.db`. Table: `event_resolutions (source, external_id, action_taken, resolved_at, resolved_by, notes)`. Methods: `resolve()` upsert, `unresolve()`, `get()` (thread-safe), `get_many()` bulk.
- `src/citadel_archer/api/resolution_routes.py` (NEW) — `POST /api/events/{source}/{id}/resolve`, `DELETE` to un-resolve, `POST /api/events/resolutions/query` for bulk enrichment. Source validated against `{"local","remote-shield","correlation"}`. Request body uses typed `ResolutionPair` Pydantic model.
- `mark_event_resolved` AI Bridge tool — inserts before `execute_ssh_command` (cache_control boundary). `resolved_by="guardian_ai"` to distinguish auto vs manual.
- `frontend/js/timeline.js` — `resolutionsMap` state, `enrichWithResolutions()` after each refresh, inline chip in description cell, resolution banner + Mark Resolved / Un-resolve button in detail panel. Styles injected once via `injectResolutionStyles()`, removed in `destroy()`.
- `frontend/js/remote-shield.js` — `threatResolutionsMap`, `enrichThreatResolutions()` after `fetchThreats()`, chip inline in threat title. Added `apiClient.initialize()` to `init()` for session-auth on resolution calls.
- `tests/test_smoke.py` S14 — 7 tests: resolve, get, unresolve, unresolve-missing, upsert, bulk-get, route smoke.

**Incident that drove item #6/#7 in the v0.4.x backlog:**
Attempted PowerShell remediation of a Node.js installation found that Windows SYSTEM process holds locks on `C:\Program Files\nodejs`. `takeown` + force-delete failed. Correct fix: `choco reinstall nodejs -y`. This exposed two gaps — no Chocolatey defensive action, and Guardian re-alerts indefinitely on paths that can't be scripted. Both added to PRD backlog (items 6 and 7).

---

## v0.4.0 (2026-02-28) — LocalHostDefender: Protect the Command Center

**Status:** Complete — The machine running Citadel Archer is now a first-class managed asset.

**Problem solved:** The command center machine was the least protected asset — not registered, no command execution capability, AI couldn't investigate or respond to local threats.

**Changes:**
- **`local/local_defender.py`** (NEW): `LocalHostDefender` class — subprocess executor for localhost without SSH. PowerShell on Windows, bash elsewhere. `execute_command_async` via `run_in_executor` so subprocess.run never blocks the asyncio event loop. `LocalCommandResult` mirrors `SSHCommandResult` shape.
- **`_execute_ssh_keygen` method**: Bypasses PowerShell entirely for ssh-keygen commands. PowerShell 5.x silently drops empty-string arguments to native executables — `-N ""` inside a `-Command` string never reaches the binary. Solution: run ssh-keygen directly with Python list argv; `["-N", ""]` arrives as two distinct argv slots, guaranteed.
- **`_split_shell_tokens` + `_expand_env` helpers**: Tokenize AI-generated command strings (respecting quoted paths with spaces), expand `$env:USERPROFILE`-style vars per-token before exec.
- **`ensure_localhost_asset(inventory)`**: Idempotent bootstrap — auto-registers `asset_id="localhost"` with `AssetPlatform.LOCAL` on startup.
- **`api/main.py`**: Calls `ensure_localhost_asset` in startup_event; purges stale approval cards (`ssh_approval_request`) on startup to prevent phantom rapid-fire approvals after crash.
- **`api/asset_routes.py`**: Local platform routing in `execute-ssh` endpoint (calls `LocalHostDefender` instead of SSH); added missing `logger` import (was a NameError crash in approval flow).
- **`chat/ai_bridge.py`**: All 3 local command paths use `execute_command_async` to avoid blocking the event loop.
- **`api/ops_routes.py`**: Added `verify_session_token` auth to all 3 REST endpoints (topology, metrics, events) — was unauthenticated despite server binding to 0.0.0.0.
- **`chat/posture_analyzer.py`**: Fixed 3 `datetime.utcnow()` → `datetime.now(timezone.utc)` (was causing TypeError when comparing tz-aware datetimes).
- **Windows subprocess flags**: `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW` (NOT `DETACHED_PROCESS` — that silences PowerShell's `[Console]::Out` even with PIPE open).
- **Safe-command whitelist extended**: `Get-Process`, `Get-FileHash`, `Get-AuthenticodeSignature`, `Get-NetFirewallRule`, `Get-NetTCPConnection`, `Get-Service`, `Get-ScheduledTask`, `Get-LocalUser`, `Get-WinEvent`, `tasklist`, `ipconfig`, `systeminfo`, `whoami`.
- **Tests**: `tests/test_local_defender.py` (~20 tests); S13 section in `test_smoke.py` (24 total tests, was 19).

---

## v0.3.49 (2026-02-22) — DND Blocks Ext-Agent Messages

**Status:** Complete — Do Not Disturb now fully silences all AI-generated messages.

**Changes:**
- DND mode now blocks ext-agent message processing in addition to user-facing notifications
- VPS daemon threat reports respect DND — no phantom AI responses when user is away

---

## v0.3.48 (2026-02-19) — SSH Asset Management, AI Bridge Improvements, Heartbeat Watchdog

**Status:** Complete — Major AI tooling and stability improvements.

**Changes:**
- **SSH asset management** in Assets UI — generate, view, and manage SSH keys for managed assets directly from dashboard
- **AI Bridge `max_iterations`** raised from 5 → 20 to support long multi-step approval chains
- **Heartbeat watchdog** — 120-second grace period (survives Edge timer throttling when window is minimized); auto-shutdown when window is genuinely closed
- **Serial approval system** — write commands create `asyncio.Future`; tool loop blocks per-command until user approves/denies; `resolve_approval_future(uuid, result)` returns True if waiter was found; if `future_resolved=True`, skip guardian notification (avoids redundant AI calls)
- **`create_approval_future(uuid)` / `resolve_approval_future(uuid, result)`** in `asset_routes.py`
- Approve/deny endpoint calls `resolve_approval_future` which returns True if a tool loop was waiting

---

## v0.3.47 (2026-02-18) — Serial Approval Hardening

**Status:** Complete

**Changes:**
- asyncio.Future-based serial approval: one pending card at a time, AI tool loop truly blocks
- Stale card detection improved — crash recovery correctly identifies unresolvable UUIDs
- `max_iterations` raised to handle complex multi-tool sessions

---

## v0.3.46 (2026-02-18) — Do Not Disturb Mode

**Status:** Complete — Silence Guardian AI messages when you need focus.

**Changes:**
- DND toggle in dashboard settings
- Blocks AI assistant messages system-wide while DND is active
- Persistent via UserPreferences (survives restarts)
- Visual indicator in sidebar when DND is active

---

## v0.3.45 (2026-02-17) — Persistent Linux Daemon + One-Liner Setup + Agent Visibility

**Status:** Complete — Remote VPS agents now run persistently as systemd services, deployable in one command.

**Changes:**
- **`agent/citadel_daemon.py`** (NEW): Production Linux security agent with 6 sensors (auth_log, processes, cron, file_integrity, resources, patches). Runs as systemd service, survives reboots.
- **`agent/setup_daemon.sh`** (NEW): One-liner setup script. `curl -fsSL .../setup.sh | sudo bash -s -- <invitation> <url>` installs Python, deploys daemon, registers systemd service, starts immediately.
- **New threat/patch-status endpoints**: `POST /api/ext-agents/{id}/threats`, `POST /api/ext-agents/{id}/patch-status`
- **Agent visibility fix**: Enrolled agents now appear correctly in Assets tab with type, status, and last heartbeat
- Daemon type must be `vps` (Shield type) — create invitation via Assets UI

---

## v0.3.44 (2026-02-16) — Agent Context Delivery System

**Status:** Complete — Enrolled agents receive operational context and onboarding at enrollment.

**Changes:**
- **`GET /api/ext-agents/context`** — enrolled agents fetch operational context: API reference, security guidelines, system state
- Onboarding prompts delivered at enrollment (first-person, task-framed to pass Claude Code safety filters)
- Tailscale support documented in context delivery
- Templates customizable via UserPreferences
- AI (claude_code, forge, custom) agents get full API reference; Shield (vps, workstation, cloud) agents get compact instructions

---

## v0.3.43 (2026-02-16) — Defense Mesh: Escalation Deduplication

**Status:** Complete — Distributed attacks across multiple agents produce ONE escalation, not N.

**Changes:**
- **Escalation deduplicator** (`mesh/escalation_dedup.py`): Mesh-level dedup engine correlating same-attack events from multiple agents. `EscalationEvent` submitted on threshold breach. Events grouped by attack signature (rule_id + event_type). Configurable merge window (default 60s). `MergedEscalation` output lists all affected agents, total event count, highest severity. Background flush thread. Safety caps: MAX_PENDING_SIGNATURES=200, MAX_AGENTS_PER_MERGE=50. History ring buffer (100 entries).
- **Mesh API routes**: Added `GET /api/mesh/dedup/status`, `GET /api/mesh/dedup/pending`, `GET /api/mesh/dedup/history`.
- **Tests**: 31 tests in `test_escalation_dedup.py`.

---

## v0.3.42 (2026-02-16) — Defense Mesh: Recovery/Reconciliation Protocol

**Status:** Complete — Desktop resumes control after outage with full reconciliation.

**Changes:**
- **Recovery protocol manager** (`mesh/recovery_protocol.py`): 5-step recovery when desktop comes back online. `RecoveryState` enum (IDLE/SYNCING/REVIEWING/RESOLVING/RESTORING/COMPLETE). Steps: (1) sync events from secondary brain, (2) review decisions (auto-accept safe, auto-rollback dangerous), (3) resolve conflicts, (4) restore heartbeats, (5) merge audit log. `RecoveryReport` captures full metrics. `run_full_recovery()` for automated recovery.
- **Mesh API routes**: 10 new endpoints for recovery lifecycle.
- **Tests**: 22 tests in `test_recovery_protocol.py`.

---

## v0.3.41 (2026-02-16) — Defense Mesh: Compartmentalized Secrets

**Status:** Complete — Each node only has the credentials it needs.

**Changes:**
- **Secret compartment manager** (`mesh/compartmentalized_secrets.py`): Role-based access control for secret distribution. `SecretScope` (GLOBAL/BRAIN/AGENT/MESH), `SecretType` (SSH keys, HMAC PSK, API keys, vault master, agent config, escalation tokens, asset registry). Access policies enforced per role. Per-node `NodeSecretManifest`. `check_compliance()` audits for policy violations.
- **Tests**: 30 tests in `test_compartmentalized_secrets.py`.

---

## v0.3.40 (2026-02-16) — Defense Mesh: Secondary Brain Hardening

**Status:** Complete — Security hardening for the fallback VPS coordinator.

**Changes:**
- **Brain hardening manager** (`mesh/brain_hardening.py`): SSH hardening policy (key-only, non-standard port, aggressive fail2ban). `EncryptedKeyStore` uses Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 (100k iterations). `APIRateLimiter` token-bucket prevents API quota exhaustion. `BrainCredentials` isolates secondary brain credentials from regular agents.
- **Tests**: 30 tests in `test_brain_hardening.py`.

---

## v0.3.39 (2026-02-16) — Defense Mesh: Secondary Brain Designation

**Status:** Complete — Fallback VPS coordinator with sanitized asset registry.

**Changes:**
- **Secondary brain manager** (`mesh/secondary_brain.py`): `BrainRole` enum, `BrainState` enum (STANDBY/ACTIVATING/ACTIVE/DEACTIVATING/DISABLED). `SanitizedAsset` strips private keys from registry. `CoordinationDecision` logs all decisions for desktop review on reconnection. Phase-change handler activates on AUTONOMOUS, deactivates on NORMAL recovery.
- **Tests**: 36 tests in `test_secondary_brain.py`.

---

## v0.3.38 (2026-02-16) — Defense Mesh: Peer Alerting

**Status:** Complete — Surviving nodes notify each other of failures.

**Changes:**
- **Peer alert broadcaster** (`mesh/peer_alerting.py`): Broadcasts alerts on escalation phase transitions. `AlertType` constants: `PEER_UNREACHABLE`, `PEER_ESCALATED`, `PEER_RECOVERED`. Alerts broadcast as UDP heartbeat packets to all surviving peers. HMAC-signed when PSK configured. Alert log capped at 100 entries.
- **Tests**: 22 tests in `test_peer_alerting.py`.

---

## v0.3.37 (2026-02-16) — Defense Mesh: Autonomous Escalation Behavior

**Status:** Complete — Progressive defensive actions when coordinator goes dark.

**Changes:**
- **Autonomous escalation handler** (`mesh/autonomous_escalation.py`): `EscalationPolicy` per node. ALERT phase: lower thresholds + increase polling. HEIGHTENED: emergency firewall rules + tighten commands. AUTONOMOUS: lockdown + full isolation. RECOVERY: remove emergency rules + restore normal. Uses `shield_database.queue_command()` and `FirewallManager.add_auto_rule()`. All actions audited.
- **Tests**: 20 tests in `test_autonomous_escalation.py`.

---

## v0.3.36 (2026-02-16) — Defense Mesh: HMAC-Signed Heartbeats

**Status:** Complete — HMAC-SHA256 signing with pre-shared keys for mesh heartbeat authentication.

**Changes:**
- **Mesh key manager** (`mesh/mesh_keys.py`): 256-bit PSK via `secrets.token_bytes(32)`, HMAC-SHA256 with domain separation string (`mesh:heartbeat:v1`), constant-time verification via `secrets.compare_digest()`, persistent `load_or_create_psk()`, safe fingerprint display.
- **HeartbeatSender/Receiver**: Optional PSK signing/verification; `packets_rejected` counter; `update_psk()` for live rotation; backwards-compatible (no PSK = accept all).
- **New endpoints**: `GET /api/mesh/psk`, `POST /api/mesh/psk/rotate`.
- **Tests**: 85 tests in `test_heartbeat_protocol.py` (+19 from v0.3.35).

---

## v0.3.35 (2026-02-16) — Defense Mesh: Mutual Heartbeat Protocol

**Status:** Complete — UDP heartbeat protocol with model-graduated escalation state machine.

**Changes:**
- **Mesh package** (`mesh/`): NEW package for Defense Mesh subsystem.
- **Heartbeat protocol** (`mesh/heartbeat_protocol.py`): UDP-based mutual heartbeat. `HeartbeatSender` background daemon. `HeartbeatReceiver` binds UDP socket.
- **Mesh state machine** (`mesh/mesh_state.py`): `EscalationPhase` enum with `model_tier` property — NORMAL=None, ALERT=haiku (3 missed), HEIGHTENED=sonnet (5 missed), AUTONOMOUS=opus (10 missed). `MeshCoordinator`.
- **Mesh database** (`mesh/mesh_database.py`): SQLite persistence for peers and heartbeat log.
- **Mesh API routes** (`api/mesh_routes.py`): 7 endpoints for peer CRUD and config.
- **Audit events**: MESH_PEER_ONLINE, MESH_PEER_OFFLINE, MESH_ESCALATION, MESH_RECOVERY added.
- **Tests**: 62 tests in `test_heartbeat_protocol.py`.

---

## v0.3.34 (2026-02-16) — Performance Analytics (Which Systems Need Attention)

**Status:** Complete — Composite attention scoring engine + fleet health dashboard tab.

**Changes:**
- **Performance analytics engine** (`intel/performance_analytics.py`): Computes attention score (0-100) per asset from 5 sub-scores: status (0-40), threats (0-25), patches (0-20), heartbeat staleness (0-10), guardian coverage (0-5). Categories: 0-24=healthy, 25-49=watch, 50-74=attention, 75-100=critical.
- **Performance API** (`api/performance_routes.py`): `GET /api/performance` (fleet summary), `GET /api/performance/{asset_id}` (single asset).
- **Performance tab** (`frontend/performance.html`, `frontend/js/performance.js`): Fleet summary strip, score bars, sub-score grids, reason chips, 60s refresh.
- **Tests**: 45 tests in `test_performance_analytics.py`.

---

## v0.3.33 (2026-02-16) — Backup and Sync Across Systems

**Status:** Complete — Local encrypted backup + restore of all dashboard state.

**Changes:**
- **Backup crypto** (`backup/backup_crypto.py`): AES-256-GCM matching vault/encryption.py pattern. 600k PBKDF2 iterations.
- **Backup manager** (`backup/backup_manager.py`): `sqlite3.backup()` API for atomic hot copies of 11 live databases. ZIP archives with manifest. Whole-archive encryption. Checksum via SHA-256 of data-only ZIP.
- **Backup API** (`api/backup_routes.py`): POST/GET/DELETE backups, restore, with session auth.
- **Backup tab** (`frontend/backup.html`, `frontend/js/backups.js`): Create/restore modals, stats bar.
- **Tests**: 48 tests in `test_backup_system.py`.

---

## v0.3.32 (2026-02-16) — Easy Deployment: Email Invite → One-Click Install

**Status:** Complete — Admin generates invitation → shares via email → family member clicks link → one-click install.

**Changes:**
- **Public enrollment routes** (`api/enrollment_routes.py`): Rate-limited (10/min per IP). `GET /enroll/{id}` serves landing page with platform detection. `GET /enroll/{id}/install.ps1` returns PowerShell installer (downloads agent → enrolls → installs scheduled task → starts daemon). `GET /enroll/{id}/status` for polling.
- **Enrollment landing page** (`frontend/enroll.html`): Self-contained, dark glassmorphic. Windows: PowerShell one-liner + download. Countdown timer. Status polling every 5s.
- **Dashboard invite modal**: Recipient name + email fields; "Share via Email" button opens `mailto:`; enrollment URL; live status badge (Waiting → Installed).
- **Security fixes**: XSS in error page (`html.escape()`), script injection via JSON (`</` → `<\/`), CSP header, rate limiter periodic cleanup.

---

## v0.3.31 (2026-02-16) — Remote Panic Capabilities

**Status:** Complete — Panic Room dispatches isolation/termination/rollback to Remote Shield agents.

**Changes:**
- **RemotePanicDispatcher** (`remote/panic_dispatcher.py`): Maps playbook action types to agent command types. Queues commands with session_id. `get_remote_status(session_id)` for tracking.
- **PlaybookEngine integration**: Routes to RemotePanicDispatcher for assets with Remote Shield agents.
- **Windows Shield handlers**: `panic_isolate` (firewall lockdown, whitelist heartbeat endpoint), `panic_terminate` (taskkill), `panic_rollback` (restore defaults).
- **Frontend polling**: `startRemoteStatusPolling()` polls every 5s with dedup dict.

---

## v0.3.30 (2026-02-16) — Group Policies

**Status:** Complete — Named security profiles fan out to all group members via command queue.

**Changes:**
- **Policy group tables** (`shield_database.py`): `policy_groups`, `policy_group_members`, `policy_application_log`.
- **GroupPolicyEngine** (`remote/group_policy.py`): `apply_policy()`, `resolve_effective_rules()` (priority + conflict merge), `get_compliance_summary()`.
- **API routes** (`api/group_policy_routes.py`): 10 endpoints for group CRUD, membership, application, compliance.
- **Tests**: 29 tests in `test_group_policies.py`.

---

## v0.3.29 (2026-02-16) — Cross-System Threat Correlation: Alert Bridging

**Status:** Complete — Remote Shield threats feed into correlator; correlated alerts propagate back to affected agents.

**Changes:**
- **EventAggregator bridge**: Every Remote Shield threat bridged into local EventAggregator with normalized severity.
- **AlertPropagator** (`remote/alert_propagator.py`): Resolves asset_id → agent_id (with cache + known-missing sentinel), queues `threat_alert` commands.
- **Windows Shield**: `threat_alert` handler logs cross-system alerts to stderr.
- **Tests**: 20 tests in `test_cross_system_correlation.py`.

---

## v0.3.28 (2026-02-16) — Unified Cross-System Threat Timeline

**Status:** Complete — Single chronological view merging local, Remote Shield, and correlation events.

**Changes:**
- **`GET /api/timeline/unified`**: Queries EventAggregator + RemoteShieldDatabase + CrossAssetCorrelator. Server-side merge with source/severity/time filters. 30s cache TTL.
- **WS broadcasts**: `threat:remote-shield` and `threat:correlation` added.
- **Timeline tab**: Source filter dropdown, color-coded source badges, source stats pills, drill-down panel.
- **Tests**: 52 tests in `test_unified_timeline.py`.

---

## v0.3.27 (2026-02-16) — Automated Patching (Windows Update Monitoring)

**Status:** Complete — Per-device update status + remote "Check for Updates" trigger.

**Changes:**
- **Generic command queue** (`shield_database.py`): `agent_commands` table, three-state lifecycle (pending → delivered → acknowledged).
- **Windows Update sensor**: `sensor_windows_updates()` — queries Microsoft.Update.Session COM + Get-HotFix + registry RebootRequired. Reports threat when pending > 7 days or reboot required.
- **Dashboard**: Per-device patch cards with status badge and "Check for Updates" button.
- **Tests**: 31 tests across `test_patch_status.py` + `test_windows_updates_sensor.py`.

---

## v0.3.26 (2026-02-16) — Code Review Fixes (Thread Safety, Invitation Resilience, API Validation)

**Changes:**
- Cross-thread SQLite fix in `windows_shield.py` — each sensor thread now has its own connection
- `InvitationStore.revert_consumed()` — reverts consumed invitation back to pending on downstream failure
- `PreferenceUpdate` Pydantic model for strict preference endpoint validation
- `THREAT_GUIDANCE` key alignment fix in `remote-shield.js`

---

## v0.3.25 (2026-02-16) — Simplified Protected Mode

**Status:** Complete — Dashboard mode toggle for non-technical users.

**Changes:**
- **UserPreferences** (`core/user_preferences.py`): SQLite key/value preference store. Singleton.
- **Simplified Mode**: Reduced tab set (Intelligence/Assets/Remote Shield only). Plain-English threat descriptions. Colored-dot status. "Suggested Action" cards for assets.
- **Preference API**: `GET/PUT /api/preferences/{key}` — session auth protected.
- **Alert threshold delivery**: `alert_threshold` in heartbeat response; Windows agent filters sub-threshold events locally.
- **Tests**: 56 new tests (11 user_preferences + 40 simplified_mode + others).

---

## v0.3.24 (2026-02-16) — Windows Remote Shield Agent

**Status:** Complete — Windows agent + invitation-based Shield enrollment.

**Changes:**
- **Shield enrollment endpoint** (`POST /api/agents/enroll`): Unauthenticated, IP rate-limited. Verifies invitation is SHIELD type. Atomically consumes and creates agent. Returns Bearer token.
- **Windows Shield agent** (`agent/windows_shield.py`): Stdlib-only, Python 3.8+. 5 sensors: Event Log, Defender, Firewall, Processes, Software. CLI: enroll/daemon/status/install/uninstall. Task Scheduler integration.
- **Windows threat types**: 6 new ThreatType values (defender_disabled, firewall_disabled, logon_failure, etc.)
- **Tests**: 44 tests across `test_windows_shield_enroll.py` + `test_windows_shield_agent.py`.

---

## v0.3.23 (2026-02-16) — Invitation Flow UI in Assets Tab

**Changes:**
- Two-step invite modal in Assets tab: name/type form → monospace invitation code with copy-to-clipboard
- Clipboard copy with DOM textarea fallback. "Copied!" feedback animation.
- "Or add an asset manually" link preserves existing form.

---

## v0.3.22 (2026-02-16) — Secure Invitation-Based Agent Enrollment

**Status:** Complete — One-time HMAC-signed invitation tokens for external agent enrollment.

**Changes:**
- **InvitationStore**: SQLite-backed. 256-bit secrets (`secrets.token_urlsafe(32)`), only SHA-256 stored. HMAC-SHA256 binding (invitation_id + secret_hash, keyed by session token). Compact format: `CITADEL-1:<12_hex_id>:<base64url_secret>`.
- **One-time atomic consumption**: Runs under threading.Lock + single SQLite transaction. Status: PENDING → REDEEMED.
- **Failed attempt tracking**: 5 failures → LOCKED (permanent). IP tracking.
- **Generic error responses**: not_found/expired/invalid_secret all → 401. Only locked → 423.
- **Tests**: 65 tests in `test_agent_invitation.py`.

---

## v0.3.21 (2026-02-16) — Inter-Agent Communication Protocol

**Status:** Complete — AI agent-to-AI agent coordination via SecureChat.

**Changes:**
- **InterAgentProtocol**: Capability declaration, discovery by capability name/domain, task delegation with correlation_id, presence tracking via heartbeats.
- **Task delegation lifecycle**: PENDING → ACCEPTED → COMPLETED/FAILED/TIMED_OUT.
- **Agent inbox**: Buffered per-agent with read-and-clear semantics. MAX_INBOX_SIZE=100.
- **9 new API endpoints**: capabilities, discover, delegate, task-response, inbox, heartbeat, stats, tasks, online.
- **Tests**: 67 tests in `test_inter_agent.py`.

---

## v0.3.20 (2026-02-16) — Secure File Sharing

**Status:** Complete — Encrypted, time-limited, self-destructing file sharing.

**Changes:**
- **AES-256-GCM file encryption**: Unique 256-bit key per file. 12-byte random nonce. SHA-256 integrity verification.
- **SecureFileManager**: SQLite-backed metadata + keys. Self-destruct: atomic delete-before-return (concurrent requests: only one gets content). TTL: 1-168 hours. `cleanup_expired()`.
- **API routes** (`api/file_routes.py`): Upload, download, list, delete, extend TTL, cleanup, stats. Content-Disposition sanitized against header injection.
- **Tests**: 53 tests in `test_secure_file.py`.

---

## v0.3.19 (2026-02-16) — E2E Encrypted Peer-to-Peer Messaging

**Status:** Complete — Signal-like E2E encryption for P2P messaging.

**Changes:**
- **X3DH key agreement**: 4 DH exchanges. Ed25519 signed prekeys. Optional one-time prekeys.
- **Double Ratchet**: Full Signal spec. DH ratchet + symmetric ratchet. Out-of-order handling (MAX_SKIP=100 globally, prevents DoS). Forward secrecy + future secrecy.
- **AES-256-GCM AEAD**: 96-bit nonces. Associated data binds session identity + header.
- **Session store** (`chat/session_store.py`): SQLite-backed identity keys, prekeys, ratchet state.
- **Tests**: 66 tests in `test_p2p_crypto.py`.

---

## v0.3.18 (2026-02-16) — Contact Management & Trusted Peer Registry

**Changes:**
- **ContactRegistry**: SQLite-backed. Trust levels: pending/verified/trusted/blocked. Ed25519 public key management. SHA-256 fingerprint display. Tag filtering (comma-boundary matching prevents false positives).
- **API**: 8 endpoints — list, add, get, update, delete, set trust, stats, verify fingerprint.
- **Tests**: 66 tests in `test_contact_registry.py`.

---

## v0.3.17 (2026-02-16) — Local LLM Integration (Ollama)

**Changes:**
- **OllamaBackend**: Health check (30s cache), model discovery, chat completion with tool calling. Localhost-only by default (`OLLAMA_ALLOW_REMOTE=1` for remote).
- **Claude → Ollama fallback**: When Claude API fails or unconfigured, automatically falls back to Ollama.
- **Tool format conversion**: Translates Claude tool format → Ollama/OpenAI format.
- **Tests**: 56 tests covering both backends and fallback logic.

---

## v0.3.16 (2026-02-15) — Extension Directory Watcher + Threat Intel Database

**Changes:**
- **ExtensionWatcher**: watchdog Observer on Chromium extension directories. Detects manifest.json creation/modification. 5s debounce, 200-entry cap.
- **ExtensionIntelDatabase**: 6 known-malicious categories. Custom blocklist. 3 dangerous permission signatures (nativeMessaging + broad host, debugger, management API).
- **Tests**: 38 tests in `test_extension_watcher.py`.

---

## v0.3.15 (2026-02-15) — Browser Extension Inventory Scanner

**Changes:**
- **ExtensionScanner**: Enumerates extensions across all Chromium browsers. 4 risk levels. Dangerous permissions + combos. Install source classification (Chrome Web Store / sideloaded / dev). MV2/MV3 handling.
- **Tests**: 61 tests in `test_extension_scanner.py`.

---

## v0.3.14 (2026-02-15) — Cross-Asset Threat Correlation (Watchtower Completion)

**Changes:**
- **CrossAssetCorrelator**: 4 correlation patterns: Shared IOC (same indicator on 2+ assets within 1hr), Coordinated Attack (same type on 3+ assets within 10min), Propagation (high-severity spreading within 30min), Intel Match.
- 30s flush, 10min dedup, 10/hr rate limit. Sliding window memory management (5000 indicators per type).
- **Tests**: 52 tests in `test_cross_asset_correlation.py`.

---

## v0.3.13 (2026-02-15) — Intel Feed Completion: abuse.ch + MITRE ATT&CK + NVD

**Changes:**
- **AbuseChFetcher**: URLhaus + ThreatFox. Severity mapping from confidence scores.
- **MitreFetcher**: STIX 2.1 Enterprise bundle (~15MB). TTPs with technique ID, tactic, platforms. Sub-technique severity escalation.
- **NVDFetcher**: NIST CVE API v2.0. CVSS v3.1/v3.0/v2.0 cascade fallback. Pagination with rate-limit compliance.
- All 4 fetchers registered with daily schedule (02:00 UTC).
- **Tests**: 133 tests across 3 fetcher test files.

---

## v0.3.12 (2026-02-15) — AI Threat Analysis for VPS

**Changes:**
- **REMOTE event category**: Added with 5 sensor mappings + prefix fallback.
- **RemoteShieldEscalation**: Mirrors GuardianEscalation — subscribes to EventAggregator, filters REMOTE category, batches/deduplicates/rate-limits (15/hr), groups by asset_id.
- **VPS behavioral baselines**: REMOTE_AUTH and REMOTE_SENSOR behavior types in ContextEngine.
- **4 new VPS threshold rules**: remote_file_integrity_burst, remote_cron_changes, remote_process_anomaly, multi_vps_coordinated.
- **Enhanced AI tools**: `get_agent_events` returns health info + severity breakdown. New `get_vps_summary`.
- **Tests**: 64 tests across 5 files.

---

## v0.3.11 (2026-02-15) — VPS Firewall Management + Node Onboarding

**Changes:**
- **DesktopFirewallManager**: Desktop-managed iptables rules pushed to VPS via SSH. `CITADEL-FW` chain. Supports deny/allow/rate_limit, port ranges, priority, TTL expiry, geo-blocking (CIDR file).
- **Node onboarding orchestrator**: 6-step automated workflow with per-step state tracking and WebSocket progress.
- **Config hot-reload**: ShieldDaemon monitors config.json mtime every 30s.
- **Bug fix**: Added `DashboardServices.get()` method (was crashing with AttributeError in production).
- **Tests**: 48 tests across 6 files.

---

## v0.3.10 (2026-02-15) — SSH Hardening: Key-Only Auth, Port Knocking, fail2ban++

**Changes:**
- **SSHHardeningOrchestrator**: 9-step safety-first workflow: backup → verify key auth → apply directives → `sshd -t` validate → reload (not restart) → verify with fresh connection → auto-rollback on failure.
- **Port knocking** (`PortKnockGuard`): kernel-level `iptables recent` module; `KnockClient` sends TCP SYN sequence; SSH manager auto-knocks before connecting.
- **fail2ban++ progressive banning**: 5min → 1hr → 24hr → permanent after 5 offenses. `ip_bans` SQLite table. IP whitelist prevents self-lockout. `BanExpiryManager` auto-unblocks expired bans every 60s.
- **Tests**: 49 tests across 5 files.

---

## v0.3.9 (2026-02-15) — Per-Asset Rollback

**Changes:**
- `recovery_states` schema adds `asset_id` column; UNIQUE constraint on `(session_id, component, component_id, asset_id)`.
- Rollback can now target specific assets in multi-target panic sessions independently.
- Schema migration (detect → rename → rebuild → copy → drop).
- **Tests**: 29 tests in `test_per_asset_rollback.py`.

---

## v0.3.8 (2026-02-15) — SQLite WAL Mode: Central Connection Utility

**Changes:**
- **`core/db.py`**: `connect()` sets WAL, `busy_timeout=5000`, `foreign_keys=ON` on every connection.
- Migrated 7 database modules; 2 inline WAL (vault, shield agent).
- FK-safe cascade delete in `cleanup_old_sessions()`.
- **Tests**: 22 tests in `test_sqlite_wal.py`.

---

## v0.3.7 (2026-02-15) — SCS Rate Limiting: Per-Participant Token Quotas

**Changes:**
- **SCSQuotaTracker**: Rolling-window (1hr) token budgets per participant. Pre-call estimate + check. Post-call record. Participant resolution: user=200K/hr, ext-agent=50K/hr, citadel=500K/hr.
- Pre-call gate, tool-loop re-check before each iteration.
- **Tests**: 33 tests in `test_scs_quota.py`.

---

## v0.3.6 (2026-02-15) — Append-Only AI Audit Log

**Changes:**
- **AIAuditLogger**: Records every Claude API call to `data/ai_audit.log` (JSON lines). Tracks call_id, timestamp, trigger_type, model, tokens, tool_calls, duration_ms, response_preview, error, iteration.
- RotatingFileHandler (5MB, 5 backups). Thread-safe singleton.
- **Tests**: 41 tests in `test_ai_audit.py`.

---

## v0.3.5 (2026-02-14) — Trigger 3c: Threshold Breach Detection

**Changes:**
- **ThresholdEngine**: Subscribes to EventAggregator. 6 default rules: SSH brute force, critical file burst, vault unlock failures, network block surge, suspicious process cluster, coordinated attack correlation. COUNT + CORRELATION rule types. 30s sweep loop. Per-rule cooldown + dedup + rate limiting (15/hr).
- **All 8 AI triggers now implemented** across all 3 categories.
- **Tests**: 53 tests in `test_threshold_engine.py`.

---

## v0.3.4 (2026-02-14) — Trigger 3b: Startup Catch-Up

**Changes:**
- **StartupCatchup**: One-shot async task (30s delay). Queries audit log for last SYSTEM_STOP → offline window. Gathers events from audit log + Remote Shield DB + asset inventory. Sends summary to SecureChat → AI Bridge.
- **Tests**: 40 tests in `test_startup_catchup.py`.

---

## v0.3.3 (2026-02-14) — Trigger 1b: External AI Agent REST API

**Changes:**
- **AgentRegistry** (`chat/agent_registry.py`): SQLite-backed, SHA-256 token hashing, WAL.
- **Agent rate limiter**: In-memory sliding window (60s window, per-agent limits).
- **Agent API routes** (`api/agent_api_routes.py`): register, send, list, revoke, rotate-token. Dual auth: session token (admin) + Bearer token (agent).
- **Category 1 complete**: Both 1a (user TEXT) and 1b (external AI agent) implemented.
- **Tests**: 71 tests across 4 files.

---

## v0.3.2 (2026-02-14) — Trigger 3a: Scheduled Daily Security Posture Analysis

**Changes:**
- **PostureAnalyzer**: Background async task every 24h. Gathers from EventAggregator, AssetInventory, RemoteShieldDatabase, AnomalyDetector. Graceful degradation per source.
- **Tests**: 41 tests in `test_posture_analyzer.py`.

---

## v0.3.1 (2026-02-14) — Trigger 2c: Panic Room → AI Triage

**Changes:**
- Panic Room activation, completion, and failure escalate to AI. Three lifecycle points: activation (triage), completion (confirmation), failure (intervention).
- **Category 2 complete**: All critical threat escalation paths (2a remote, 2b Guardian, 2c Panic Room) reach AI.

---

## v0.3.0 (2026-02-14) — Trigger 2b: Local Guardian → AI Escalation

**Changes:**
- **GuardianEscalation**: Subscribes to EventAggregator, filters ALERT/CRITICAL from FILE/PROCESS categories. 30s batch window. 5-min dedup. 10/hr rate limit. Sync→async bridge.
- **Tests**: 41 tests in `test_guardian_escalation.py`.

---

## v0.2.x — Foundation & Architecture Decisions

The v0.2.x series established the foundational architecture. Key milestones:

- **v0.2.9** — Comprehensive codebase audit, PRD accuracy pass, GUI framework corrected (Edge app mode, not pywebview), session auth documented, ML anomaly detection documented
- **v0.2.8** — Token minimization as core design principle; 4-level escalation hierarchy; Forge/Telegram channel; mesh HMAC auth; append-only AI audit; SQLite WAL; escalation dedup; recovery protocol; secondary brain hardening
- **v0.2.7** — Always-On Protection architecture (`citadel-service` + `citadel-archer`); Distributed Resilience / Defense Mesh; multi-AI participation in SecureChat; ACS/SCS two-tier model formalized; 8-trigger AI model established
- **v0.2.6** — SecureChat repositioned from "chat with friends" to foundational communication infrastructure; VPS onboarding through chat; AI Bridge trigger model
- **v0.2.5** — Asset Management Addendum: asset DB persistence, CRUD API, Remote Shield auto-linking, Vault SSH credentials, SSH Connection Manager, Panic Room remote scope
- **v0.2.4** — Browser Extension Protection added to Guardian (real-world trigger: 14 unauthorized extensions found in Edge including keystroke-logging AI extension)
- **v0.2.3** — Vanilla JS over React (security-first: minimal supply chain risk)
- **v0.2.2** — Proactive Protection principle: "ACT first, inform after. NEVER ask unless truly necessary."
- **v0.2.1** — UX clarity for non-technical users; Progressive Disclosure; AI as expert advisor
- **v0.2.0** — Remote Shield (VPS) moved from Phase 5 → Phase 2 (user's VPS was being compromised within days)

---

## v0.1.0 (2026-02-01) — Initial PRD

**Status:** Baseline locked.

**Major decisions:**
- AI-centric architecture (AI as adaptive brain, modules as sensors/tools)
- Proprietary licensing (protects defensive algorithms)
- Freemium model (Free/Premium/Enterprise)
- Windows 10/11 first, Ubuntu for VPS second
- Cloud LLMs for MVP (Claude API), local models later
- User-configurable security levels (Observer/Guardian/Sentinel)

---

*Versions v0.3.0 and below — for the line-by-line implementation details, see git log: `git log --oneline` or `git show <commit>`.*
