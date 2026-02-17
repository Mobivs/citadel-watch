# Citadel Archer - Product Requirements Document (PRD)

**Version:** 0.3.43
**Last Updated:** 2026-02-16
**Status:** Active Development

---

## Version History & Changelog

### v0.3.43 (2026-02-16) - Defense Mesh: Escalation Deduplication
**Status**: Complete - Distributed attacks across multiple agents produce ONE escalation, not N.

**Changes**:
- **Escalation deduplicator** (`mesh/escalation_dedup.py`): NEW — Mesh-level dedup engine that correlates same-attack events from multiple agents. `EscalationEvent` submitted by each agent's threshold breach. Events grouped by **attack signature** (rule_id + event_type). Configurable merge window (default 60s) waits for all agents to report before flushing. `MergedEscalation` output lists all affected agents, total event count, highest severity, per-agent details. Background flush thread with configurable interval. Subscriber callback pattern (`on_merged()`) for delivery to audit log / WebSocket / SCS. Safety caps: MAX_PENDING_SIGNATURES=200, MAX_AGENTS_PER_MERGE=50. History ring buffer (100 entries). Full introspection API (status, pending, history).
- **Main.py wiring** (`api/main.py`): Mesh phase-change callback now submits escalation events to the deduplicator for non-NORMAL transitions. Deduplicator initialized on startup, stopped on shutdown.
- **Mesh API routes** (`api/mesh_routes.py`): Added 3 endpoints — `GET /api/mesh/dedup/status`, `GET /api/mesh/dedup/pending`, `GET /api/mesh/dedup/history`.

**Tests**: 31 tests in `test_escalation_dedup.py` (2 event, 2 merged, 3 signature, 2 severity, 15 deduplicator core, 2 singleton, 5 route).

---

### v0.3.42 (2026-02-16) - Defense Mesh: Recovery/Reconciliation Protocol
**Status**: Complete - Desktop resumes control after outage with full reconciliation.

**Changes**:
- **Recovery protocol manager** (`mesh/recovery_protocol.py`): NEW — 5-step recovery process for when desktop comes back online after being dark. `RecoveryState` enum (IDLE/SYNCING/REVIEWING/RESOLVING/RESTORING/COMPLETE) tracks progress. `RecoveryManager` orchestrates: (1) `sync_events()` — collect missed events from secondary brain, (2) `review_decisions()` — auto-accept safe actions (lower_alert_threshold, increase_polling_frequency, queue_tighten_rules, add_emergency_firewall_rules), auto-rollback dangerous ones (rotate_credentials, kill_all_ssh_sessions), support custom accept/rollback lists, (3) `resolve_conflicts()` — identify and resolve conflicting decisions, (4) `restore_heartbeats()` — notify peers desktop is back, (5) `merge_audit_log()` — merge secondary brain audit entries into primary log. `RecoveryReport` captures full metrics (events_synced, decisions_reviewed/accepted/rolled_back, conflicts_resolved, audit_entries_merged, step timing). `run_full_recovery()` for non-interactive automated recovery. History capped with configurable limit.
- **Mesh API routes** (`api/mesh_routes.py`): Added 10 endpoints — `GET /api/mesh/recovery/status`, `POST /api/mesh/recovery/start`, `POST /api/mesh/recovery/sync-events`, `POST /api/mesh/recovery/review-decisions`, `POST /api/mesh/recovery/resolve-conflicts`, `POST /api/mesh/recovery/restore-heartbeats`, `POST /api/mesh/recovery/merge-audit`, `POST /api/mesh/recovery/complete`, `POST /api/mesh/recovery/run-full`, `GET /api/mesh/recovery/history`.

**Tests**: 22 tests in `test_recovery_protocol.py` (2 report, 13 manager, 2 singleton, 5 route).

---

### v0.3.41 (2026-02-16) - Defense Mesh: Compartmentalized Secrets
**Status**: Complete - Each node only has the credentials it needs.

**Changes**:
- **Secret compartment manager** (`mesh/compartmentalized_secrets.py`): NEW — Role-based access control for secret distribution: `SecretScope` (GLOBAL/BRAIN/AGENT/MESH), `SecretType` (SSH keys, HMAC PSK, API keys, Vault master, agent config, escalation tokens, asset registry). `SecretCompartmentManager` enforces access policies: Desktop (primary) gets all scopes/types, agents get only agent+mesh scope and HMAC/config/escalation types, secondary brain gets brain+mesh scope and API key/HMAC/public key types. Per-node `NodeSecretManifest` tracks provisioned secrets. `provision_secret()` checks both scope and type policies before allowing. `check_compliance()` audits a node for policy violations. `get_secret_distribution()` provides mesh-wide overview. Append-only audit log tracks all provisioning/revocation events.
- **Mesh API routes** (`api/mesh_routes.py`): Added 8 endpoints — `GET /api/mesh/secrets/distribution`, `GET /api/mesh/secrets/manifests`, `POST /api/mesh/secrets/nodes/{id}` (register), `GET /api/mesh/secrets/nodes/{id}` (list secrets), `POST /api/mesh/secrets/nodes/{id}/provision`, `DELETE /api/mesh/secrets/nodes/{id}/{secret_id}` (revoke), `GET /api/mesh/secrets/nodes/{id}/compliance`, `GET /api/mesh/secrets/audit`.

**Tests**: 30 tests in `test_compartmentalized_secrets.py` (8 access policy, 2 secret entry, 12 manager, 2 singleton, 7 route).

---

### v0.3.40 (2026-02-16) - Defense Mesh: Secondary Brain Hardening
**Status**: Complete - Security hardening for the fallback VPS coordinator.

**Changes**:
- **Brain hardening manager** (`mesh/brain_hardening.py`): NEW — `SSHHardeningPolicy` with key-only auth, non-standard port, aggressive fail2ban (3 retries, 1hr ban), AllowUsers directive. Generates sshd_config and fail2ban jail config fragments. `EncryptedKeyStore` uses Fernet (AES-128-CBC + HMAC-SHA256) with PBKDF2 key derivation (100k iterations) for API key encryption — falls back to base64 when cryptography package unavailable. `APIRateLimiter` token-bucket implementation prevents a compromised brain from draining API quota. `BrainCredentials` provides separate credential isolation (brain has its own HMAC key, SSH key, encrypted API key — distinct from regular agents). `BrainHardeningManager` ties it all together with append-only audit log and `generate_hardening_commands()` for remote execution.
- **Mesh API routes** (`api/mesh_routes.py`): Added 6 endpoints — `GET /api/mesh/hardening` (full status), `PUT /api/mesh/hardening/ssh-policy`, `GET/PUT /api/mesh/hardening/rate-limiter`, `GET /api/mesh/hardening/commands` (shell commands for remote deployment), `GET /api/mesh/hardening/audit`.

**Tests**: 30 tests in `test_brain_hardening.py` (4 SSH policy, 4 encrypted key store, 4 rate limiter, 2 credentials, 8 manager, 2 singleton, 6 route).

---

### v0.3.39 (2026-02-16) - Defense Mesh: Secondary Brain Designation
**Status**: Complete - Fallback VPS coordinator with sanitized asset registry.

**Changes**:
- **Secondary brain manager** (`mesh/secondary_brain.py`): NEW — `SecondaryBrainManager` handles designation, activation, and deactivation of a fallback VPS coordinator. `BrainRole` enum (PRIMARY/SECONDARY/AGENT), `BrainState` enum (STANDBY/ACTIVATING/ACTIVE/DEACTIVATING/DISABLED). `SecondaryBrainConfig` defines per-node policy: activation threshold, rate-limited API access, allowed/denied action lists, max coordination hours, desktop approval requirement. `SanitizedAsset` strips secrets from asset registry (no passwords or private keys — only connection info and public key fingerprints). `CoordinationDecision` logs all decisions for desktop review on reconnection. Phase-change handler activates when desktop peer enters AUTONOMOUS, deactivates on NORMAL recovery. Thread-safe with RLock.
- **Mesh API routes** (`api/mesh_routes.py`): Added 7 endpoints — `GET/PUT/DELETE /api/mesh/secondary-brain` (status, designate, remove), `GET /api/mesh/secondary-brain/decisions` (with pending_only filter), `POST /api/mesh/secondary-brain/decisions/{id}/review`, `POST /api/mesh/secondary-brain/decisions/review-all`, `GET /api/mesh/secondary-brain/assets` (sanitized registry).
- **Main.py wiring** (`api/main.py`): Phase-change callback now invokes `SecondaryBrainManager.handle_phase_change()` for desktop peer state tracking.

**Tests**: 36 tests in `test_secondary_brain.py` (3 config, 2 brain state/role, 1 sanitized asset, 2 decision, 18 manager, 2 singleton, 8 route).

---

### v0.3.38 (2026-02-16) - Defense Mesh: Peer Alerting
**Status**: Complete - Surviving nodes notify each other of failures.

**Changes**:
- **Peer alert broadcaster** (`mesh/peer_alerting.py`): NEW — `PeerAlertBroadcaster` creates and broadcasts alerts on escalation phase transitions. `AlertType` constants: `PEER_UNREACHABLE` (ALERT phase), `PEER_ESCALATED` (HEIGHTENED/AUTONOMOUS), `PEER_RECOVERED` (back to NORMAL). `PeerAlert` dataclass with subject/reporter node IDs, phase info, missed count, and timestamp. Alerts broadcast as UDP heartbeat packets with `mesh_alert` payload key to all surviving peers (excludes the subject node). Alert log capped at 100 entries. Thread-safe with lock. HMAC-signed when PSK is configured.
- **Mesh API routes** (`api/mesh_routes.py`): Added `GET /api/mesh/alerts` endpoint returning recent peer alerts (newest first, configurable limit).
- **Main.py wiring** (`api/main.py`): Phase-change callback now invokes `PeerAlertBroadcaster.handle_phase_change()` with all peers from state manager. Broadcaster initialized on startup with desktop node_id and mesh PSK.

**Tests**: 22 tests in `test_peer_alerting.py` (1 alert type, 4 peer alert dataclass, 11 broadcaster, 2 singleton, 4 route).

---

### v0.3.37 (2026-02-16) - Defense Mesh: Autonomous Escalation Behavior
**Status**: Complete - Progressive defensive actions when coordinator goes dark.

**Changes**:
- **Autonomous escalation handler** (`mesh/autonomous_escalation.py`): NEW — `EscalationPolicy` dataclass defines per-node defensive actions for each phase. `AutonomousEscalationHandler` executes progressive actions: ALERT (lower thresholds + increase polling), HEIGHTENED (emergency firewall rules + tighten commands), AUTONOMOUS (lockdown rules + full isolation commands), RECOVERY (remove emergency rules + restore normal). Uses existing infrastructure: `shield_database.queue_command()` for async agent commands, `FirewallManager.add_auto_rule()` for time-limited firewall rules. All actions audited via EventType.MESH_ESCALATION. Best-effort execution — failures are non-fatal.
- **Mesh API routes** (`api/mesh_routes.py`): Added `GET/PUT /api/mesh/escalation/{node_id}` for per-node policy management. `EscalationPolicyRequest` Pydantic model.
- **Main.py wiring** (`api/main.py`): Phase-change callback now invokes `get_escalation_handler().handle_phase_change()` after audit log.

**Tests**: 20 tests in `test_autonomous_escalation.py` (3 policy, 2 action result, 10 handler, 2 singleton, 3 route).

---

### v0.3.36 (2026-02-16) - Defense Mesh: HMAC-Signed Heartbeats
**Status**: Complete - HMAC-SHA256 signing with pre-shared keys for mesh heartbeat authentication.

**Changes**:
- **Mesh key manager** (`mesh/mesh_keys.py`): NEW — 256-bit PSK generation via `secrets.token_bytes(32)`, base64 encode/decode for storage, HMAC-SHA256 signing with domain separation string (`mesh:heartbeat:v1`), constant-time verification via `secrets.compare_digest()`, persistent `load_or_create_psk()` via UserPreferences, safe fingerprint display (first 8 chars of SHA-256 hash).
- **Heartbeat protocol** (`mesh/heartbeat_protocol.py`): Added `sign(psk)` and `verify(psk)` methods to HeartbeatPacket. HeartbeatSender accepts optional `psk` and signs all outgoing packets. HeartbeatReceiver accepts optional `psk` and rejects unsigned/invalid-signature packets (new `packets_rejected` counter). Both have `update_psk()` for live key rotation. Backwards-compatible: no PSK = accept all (unsigned mode).
- **Mesh coordinator** (`mesh/mesh_state.py`): MeshCoordinator accepts `psk` and passes to sender/receiver. Added `update_psk()` for coordinated key rotation, `psk_fingerprint` property. Updated `receiver_stats` to include `packets_rejected`.
- **Mesh API routes** (`api/mesh_routes.py`): Added `packets_rejected` and `psk_fingerprint` to status response. NEW endpoints: `GET /api/mesh/psk` (PSK status/fingerprint), `POST /api/mesh/psk/rotate` (generate new key, returns base64 once for peer distribution).
- **Main.py wiring** (`api/main.py`): Startup calls `load_or_create_psk()` and passes PSK to MeshCoordinator. Logs fingerprint on startup.

**Tests**: 85 tests in `test_heartbeat_protocol.py` (+19 from v0.3.35: 10 key management, 2 sender signing, 4 receiver HMAC verification, 3 PSK route tests).

---

### v0.3.35 (2026-02-16) - Defense Mesh: Mutual Heartbeat Protocol
**Status**: Complete - UDP heartbeat protocol with model-graduated escalation state machine.

**Changes**:
- **Mesh package** (`mesh/__init__.py`): NEW — Package for Defense Mesh subsystem.
- **Heartbeat protocol** (`mesh/heartbeat_protocol.py`): NEW — UDP-based mutual heartbeat. `HeartbeatPacket` dataclass (JSON serialized, HMAC `signature` field reserved for next version). `HeartbeatSender` background daemon thread sends to all configured peers at configurable interval (5-300s). `HeartbeatReceiver` background daemon binds UDP socket, calls callback on valid packets. Per-peer send failures are non-fatal. Pure automation — zero AI tokens consumed.
- **Mesh state machine** (`mesh/mesh_state.py`): NEW — `EscalationPhase` enum with `model_tier` property for cost-graduated AI: NORMAL=None (pure automation), ALERT=haiku (3 missed, ~$0.001 triage), HEIGHTENED=sonnet (5 missed, context analysis), AUTONOMOUS=opus (10 missed, critical decisions). `MeshStateManager` (RLock, subscriber callbacks on phase transitions). `MeshCoordinator` ties sender+receiver+state with single start/stop lifecycle.
- **Mesh database** (`mesh/mesh_database.py`): NEW — SQLite persistence for peers and heartbeat log. `mesh_peers` table (node_id, ip_address, port, escalation phase). `mesh_heartbeat_log` ring buffer (1000 per node). Follows shield_database.py pattern.
- **Mesh API routes** (`api/mesh_routes.py`): NEW — 7 endpoints: GET /api/mesh/status (peer counts by phase), GET/POST/DELETE /api/mesh/peers (CRUD), GET /api/mesh/peers/{node_id} (detail + history), GET/PUT /api/mesh/config (interval). Session auth. Returns 503 if coordinator not started.
- **Audit log events** (`core/audit_log.py`): Added MESH_PEER_ONLINE, MESH_PEER_OFFLINE, MESH_ESCALATION, MESH_RECOVERY to EventType enum.
- **Main.py wiring** (`api/main.py`): Mesh coordinator created on startup with persisted config (UserPreferences). Phase-change callback logs to audit + broadcasts `mesh_phase_change` via WebSocket. Persisted peers loaded from MeshDatabase. Graceful shutdown.

**Tests**: 62 tests in `test_heartbeat_protocol.py` (6 packet, 7 sender, 6 receiver, 4 escalation phase, 4 peer state, 12 state manager, 5 coordinator, 9 database, 7 routes, 3 structural).

---

### v0.3.34 (2026-02-16) - Performance Analytics (Which Systems Need Attention)
**Status**: Complete - Composite attention scoring engine + fleet health dashboard tab.

**Changes**:
- **Performance analytics engine** (`intel/performance_analytics.py`): NEW — Pure computation module with no I/O dependencies. Computes composite "attention score" (0–100) per asset by combining 5 sub-scores: status (0-40, compromised=40/offline=25/unknown=15), threats (0-25, weighted avg_risk_score + highest_risk), patches (0-20, pending*2 + oldest_days//7 + reboot*2), heartbeat staleness (0-10, >1h=2/>6h=5/>24h=8/>72h=10), guardian coverage (0-5, inactive=5). Categories: 0-24=healthy, 25-49=watch, 50-74=attention, 75-100=critical. Fleet summary with weighted average score. Dataclasses: `PatchInsight`, `HeartbeatInsight`, `AssetAttentionScore`, `FleetHealthSummary`.
- **Performance API routes** (`api/performance_routes.py`): NEW — 2 endpoints: `GET /api/performance` (fleet summary + sorted per-asset scores), `GET /api/performance/{asset_id}` (single asset, 404 if not found). Pydantic response models with `Field(default_factory=list)` for mutable defaults. Gathers data from existing services (asset_inventory, shield_db, event_aggregator, threat_scorer) via `dashboard_ext.services` singleton.
- **Performance tab** (`frontend/performance.html`): NEW — Dark glassmorphic themed page. Fleet summary strip (4 stat cards: Total/Healthy/Watch+Attn/Critical), fleet health bar (CSS flex segments proportional to category counts), sort/filter controls (by attention score/name/status, filter by category), asset cards container with empty state.
- **Performance JS module** (`frontend/js/performance.js`): NEW — Module lifecycle with `init()`/`destroy()`. Fetches `/api/performance`, renders fleet summary + per-asset cards with score bars, sub-score grids, and reason chips. 60-second refresh interval. WebSocket subscriptions (`event`, `threat_detected`) with 2-second debounce. Sort/filter controls. Preserves empty-state div via `insertAdjacentHTML` instead of innerHTML.
- **Tab wiring** (`frontend/index.html`, `frontend/js/dashboard-nav.js`, `frontend/js/tab-loader.js`): Performance tab added between Backup and Panic Room. Registered in TAB_IDS, TAB_CONFIG, CDN_DEPS, MODULE_PATHS, and PAGE_SOURCES. Activity icon (heartbeat waveform SVG).
- **Router registration** (`api/main.py`): Mounted performance_router.

**Code review fixes applied**:
1. [Warning] Upgraded error log levels from `debug` to `warning` with `exc_info=True` in `_gather_performance_data()` — production errors no longer silently swallowed
2. [Warning] Fixed mutable default `reasons: List[str] = []` in Pydantic `AssetAttentionModel` — now uses `Field(default_factory=list)`
3. [Warning] Fleet "Watch" stat card label changed to "Watch / Attn" to reflect that it combines watch + attention counts
4. [Warning] Fixed `renderAssetCards` clobbering `#perf-empty` div — now removes `.asset-attention-card` elements only, uses `insertAdjacentHTML` to append new cards
5. [Warning] Added 2-second debounce to WebSocket-triggered refresh — prevents burst of API calls on rapid events; timer cleaned up in `destroy()`
6. [Suggestion] Added test for `GET /api/performance/{asset_id}` 404 case

**Tests**: 45 tests in `test_performance_analytics.py` (5 status score, 4 threat score, 4 patch score, 5 heartbeat score, 2 guardian score, 5 composite scoring, 4 fleet summary, 3 reason generation, 6 API routes, 7 frontend structural).

---

### v0.3.33 (2026-02-16) - Backup and Sync Across Systems
**Status**: Complete - Local encrypted backup + restore of all dashboard state. Off-site push to agents deferred to v0.3.34.

**Changes**:
- **Backup crypto** (`backup/backup_crypto.py`): NEW — AES-256-GCM encryption matching vault/encryption.py pattern (PBKDF2-SHA256, 600k iterations, 32-byte salt, 12-byte nonce). `encrypt_bytes()` / `decrypt_bytes()` for whole-archive encryption.
- **Backup database** (`backup/backup_database.py`): NEW — SQLite persistence for backup metadata following shield_database.py pattern. Table tracks backup_id, label, timestamps, size, checksums, archive paths, storage locations, and status. Uses `core.db.connect()` with WAL mode and `row_factory` parameter.
- **Backup manager** (`backup/backup_manager.py`): NEW — Core orchestrator using `sqlite3.backup()` API for atomic hot copies of 11 live databases without locking the application. Creates ZIP archives with databases, manifest, and audit logs (30-day cap). Whole-archive encryption into `.citadel-backup` files. Restore creates pre-restore safety backup (no unencrypted .db.bak files on disk). `threading.Lock` serializes concurrent operations. Checksum verification via SHA-256 of data-only ZIP content.
- **Backup API routes** (`api/backup_routes.py`): NEW — 6 endpoints: POST/GET /api/backups, GET/DELETE /api/backups/{id}, POST /api/backups/{id}/restore, POST /api/backups/{id}/push (501 — deferred v0.3.34). Pydantic validation, session token auth, BackupError → 400.
- **Audit log events** (`core/audit_log.py`): Added BACKUP_CREATED, BACKUP_RESTORED, BACKUP_DELETED to EventType enum.
- **Frontend backup tab** (`frontend/backup.html`, `frontend/js/backups.js`): NEW — Dedicated tab with dark glassmorphic theme. Stats bar (total, last backup, size), backup list table with status chips, Create Backup modal (passphrase + label), Restore modal with pre-restore warning. Module lifecycle with `init()`/`destroy()`.
- **Tab wiring** (`frontend/index.html`, `frontend/js/dashboard-nav.js`, `frontend/js/tab-loader.js`): Backup tab added between Remote Shield and Panic Room. Registered in TAB_IDS, TAB_CONFIG, CDN_DEPS, MODULE_PATHS, and PAGE_SOURCES.
- **Router registration** (`api/main.py`): Mounted backup_router.

**Code review fixes applied**:
1. [Critical] Registered backup tab in `tab-loader.js` CDN_DEPS/MODULE_PATHS/PAGE_SOURCES; removed redundant script tag from `backup.html`
2. [Critical] Fixed checksum computation — now checksums data-only ZIP (without manifest), then rebuilds final ZIP with manifest containing the real checksum
3. [Critical] Fixed ZipFile handle leak in `_restore_locked` — replaced manual open/close with `with` context manager
4. [Warning] Guarded `_hot_copy_db`/`_restore_db` against `UnboundLocalError` — initialize connections to None with `if` guards in finally
5. [Warning] Split `_audit_log` exception handling — `ImportError` (expected in tests) vs other exceptions (logged with `exc_info=True`)
6. [Warning] `BackupDatabase._connect()` now accepts `row_factory` parameter; removed manual `conn.row_factory` assignments
7. [Suggestion] Strengthened `test_manifest_has_checksum` — verifies checksum matches DB record (consistency check)

**Tests**: 48 tests in `test_backup_system.py` (5 crypto, 6 database, 8 create, 6 restore, 2 list, 2 delete, 8 API routes, 5 structural, 6 frontend structural).

---

### v0.3.32 (2026-02-16) - Easy Deployment: Email Invite → One-Click Install
**Status**: Complete - Admin generates invitation → shares via email → family member clicks link → one-click install

**Changes**:
- **InvitationStore enhancements** (`chat/agent_invitation.py`): Added `recipient_email`, `recipient_name`, `page_visited_at` columns with idempotent ALTER TABLE migration. New `verify_secret_only(invitation_id, raw_secret)` validates secret without consuming invitation (for page loads/downloads). New `mark_page_visited(invitation_id)` records enrollment page visit timestamp. Updated dataclass, `to_dict()`, `_row_to_invitation()` with backward-compatible column access.
- **Public enrollment routes** (`api/enrollment_routes.py`): New unauthenticated router with 4 endpoints, all rate-limited 10/min per IP. `GET /enroll/{id}?s={secret}` serves enrollment landing page (reads `enroll.html`, injects `window.ENROLL_DATA` JSON). `GET /enroll/{id}/download/windows_shield.py?s={secret}` downloads pre-configured agent with embedded server URL + invitation string + auto-enroll patch. `GET /enroll/{id}/install.ps1?s={secret}` returns PowerShell installer script (downloads agent → enrolls → installs scheduled task → starts daemon). `GET /enroll/{id}/status?s={secret}` returns invitation status JSON for real-time polling.
- **Enrollment landing page** (`frontend/enroll.html`): Self-contained (inline CSS/JS), dark glassmorphic theme. Platform detection: Windows shows PowerShell `irm | iex` one-liner + download button + manual setup; other platforms show copy invitation string. Countdown timer to expiry, status polling every 5s (shows "Installed!" when redeemed).
- **API enhancements** (`api/agent_api_routes.py`): `CreateInvitationRequest` accepts optional `recipient_email` and `recipient_name`. `CreateInvitationResponse` includes `enrollment_url` (constructed from `request.base_url`) and `mailto_url` (pre-filled subject + body with enrollment link). Passes email/name to InvitationStore.
- **Dashboard invite modal** (`frontend/assets.html`, `frontend/js/assets.js`): Step 1 adds recipient name + email fields. Step 2 adds "Share via Email" button (opens `mailto:` link), "Open Enrollment Page" button (opens enrollment URL in new tab), invitation status badge (Waiting → Installed/Expired). JS sends recipient fields in POST, stores enrollment/mailto URLs from response, starts status polling after generation with cleanup on close/destroy.
- **Router wiring** (`api/main.py`): Mounted `enrollment_router` for public access.

**Code review fixes applied**:
- Critical: XSS in `_error_page()` — user-controlled message now escaped with `html.escape()` before embedding in HTML
- Critical: Script injection via JSON in enrollment page — `json.dumps()` output now escapes `</` to `<\/` preventing script block breakout; added Content-Security-Policy header (`default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:;`)
- Warning: Rate limiter unbounded growth — added periodic cleanup (every 5min) evicting stale IP entries from `_rate_limit` dict
- Warning: Fragile compact string parsing in `agent_api_routes.py` — replaced inline `split(":", 2)[1:]` with `InvitationStore.parse_compact_string()`
- Warning: Brittle source patching in download endpoint — added `logger.warning()` when docstring or daemon marker not found in `windows_shield.py`
- Warning: Status endpoint skipped HMAC binding — restructured to use `verify_secret_only()` (full HMAC check) for pending invitations, hash-only fallback for non-pending states with `secrets.compare_digest()`
- Suggestion: Countdown timer in `enroll.html` now clears `setInterval` when expired instead of ticking forever

### v0.3.31 (2026-02-16) - Remote Panic Capabilities: Isolate Any System from Dashboard
**Status**: Complete - Panic Room dispatches isolation/termination/rollback commands to Remote Shield agents via command queue

**Changes**:
- **RemotePanicDispatcher** (`remote/panic_dispatcher.py`): New module following `alert_propagator.py` pattern. `dispatch(agent_id, action_type, payload, session_id)` maps playbook action types to agent command types via `_ACTION_TO_COMMAND` dict (`network→panic_isolate`, `processes→panic_terminate`, etc.) and queues commands with session_id in payload for tracking. `dispatch_rollback()` queues `panic_rollback` command. `get_remote_status(session_id)` returns all panic commands for a session with per-command status. `resolve_agent_id(asset_id)` resolves asset→agent with empty-string sentinel cache.
- **PlaybookEngine integration** (`panic/playbook_engine.py`): Added `set_panic_dispatcher()` method. In `execute_playbook()` inner loop, checks if asset has a Remote Shield agent via `resolve_agent_id()` — if yes, dispatches via command queue instead of running action handler. Local assets and SSH-backed assets unchanged.
- **Command allowlist** (`api/remote_shield_routes.py`): Added `panic_isolate`, `panic_terminate`, `panic_rollback` to `ALLOWED_COMMAND_TYPES`.
- **Agent handlers** (`agent/windows_shield.py`): 3 new command handlers — `panic_isolate` (saves firewall state, enables all profiles, blocks all traffic, whitelists heartbeat endpoint IP via `socket.gethostbyname()`, saves config with `panic_active: true`), `panic_terminate` (iterates process_names/pids with `taskkill /F`, checks return codes), `panic_rollback` (deletes CitadelHeartbeat rule, restores default outbound policy, clears panic_active flag).
- **Remote status endpoint** (`api/panic_routes.py`): `GET /sessions/{session_id}/remote-status` returns per-agent command statuses. Reuses wired dispatcher from PanicManager when available, falls back to ephemeral instance.
- **PanicManager wiring** (`panic/panic_manager.py` + `api/main.py`): `set_panic_dispatcher()` propagates to PlaybookEngine. Startup wiring creates `RemotePanicDispatcher(shield_db)` and sets it on the PanicManager.
- **Frontend polling** (`panic-room.js`): `startRemoteStatusPolling()` polls remote-status every 5s for non-local assets with `seenStatuses` dedup dict (keyed by `command_id:status`). Stops when all commands acknowledged. Cleanup in `destroy()`.
- **Removed** "Parental controls integration (optional)" from Phase 5 checklist.

**Code review fixes applied**:
- Critical: Removed misleading `for cmd_type in panic_types` loop with `break` in `get_remote_status()` — now queries once with limit=1000
- Critical: `panic_isolate` now resolves hostname to IP via `socket.gethostbyname()` before passing to `netsh advfirewall firewall add rule ... remoteip=`
- Warning: Agent cache uses empty-string sentinel (matches AlertPropagator pattern) instead of None
- Warning: `panic_terminate` checks `taskkill` return code before incrementing killed count
- Warning: Frontend `startRemoteStatusPolling()` tracks `seenStatuses` dict to prevent duplicate log entries
- Suggestion: `remote-status` endpoint reuses wired dispatcher from PanicManager, falls back to ephemeral

### v0.3.30 (2026-02-16) - Group Policies: Apply Security Rules to Multiple Systems
**Status**: Complete - Named security profiles fan out to all group members via command queue

**Changes**:
- **Policy group tables** (`shield_database.py`): 3 new tables — `policy_groups` (group_id, name, description, rules_json blob, priority, timestamps), `policy_group_members` (group_id → agent_id with UNIQUE constraint), `policy_application_log` (audit trail: application_id, group_id, agent_id, command_id, status, applied_at). 12 new methods for full CRUD, membership management, application logging, and compliance tracking.
- **GroupPolicyEngine** (`remote/group_policy.py`): New module following `alert_propagator.py` pattern. `apply_policy(group_id)` fans out `apply_policy` commands to all group members via the existing command queue. `resolve_effective_rules(agent_id)` merges rules from all groups an agent belongs to — conflict resolution: lowest priority number wins for `alert_threshold`, most-frequent wins for `update_schedule` (daily > weekly > manual), firewall rules are unioned with dedup by (source, port). `get_compliance_summary(group_id)` returns per-agent applied/pending/never_applied status.
- **API routes** (`api/group_policy_routes.py`): New APIRouter at `/api/policies` with 10 endpoints — group CRUD (POST/GET/PUT/DELETE `/groups`), membership (POST/DELETE `/groups/{id}/members`), policy application (POST `/groups/{id}/apply`), compliance (GET `/groups/{id}/compliance`), effective policy (GET `/agents/{id}/effective-policy`). Pydantic models with validation: `PolicyGroupCreate`, `PolicyGroupUpdate`, `AddMembersRequest`. Rules validated against `SUPPORTED_RULE_TYPES = {"alert_threshold", "update_schedule", "firewall_rules"}`.
- **Router wiring** (`main.py`): Imported and included `group_policy_router`.
- **Command allowlist** (`remote_shield_routes.py`): Added `"apply_policy"` to `ALLOWED_COMMAND_TYPES`.
- **Agent handler** (`agent/windows_shield.py`): New `apply_policy` handler in `_execute_command()` — applies `alert_threshold` and `update_schedule` to local config, logs firewall rule count, saves config if changed. Returns `"policy_applied:threshold=N,schedule=S"`.
- **Frontend section** (`remote-shield.html`): "Group Policies" section between Patch Status and Threat Timeline with CSS for `.policy-section`, `.policy-card`, `.compliance-badge` (ok/partial/none states).
- **Frontend JS** (`remote-shield.js`): `fetchPolicyGroups()`, `renderPolicyGroups()`, `createPolicyGroup()`, `applyPolicy()` with session token auth via `_authHeaders()` helper. Wired into `init()`/`destroy()` lifecycle and 30s refresh interval.

**Code review fixes applied**:
- Critical: Added `apiClient` import and `_authHeaders()` helper — all policy fetch calls now include `X-Session-Token` (was missing, causing 401)
- Critical: Fixed XSS in onclick handler — `group_id` sanitized with `replace(/[^a-zA-Z0-9_-]/g, '')` for JS context, `escapeHtml()` for HTML attributes
- Warning: Added `_validate_rules()` rejecting unknown rule types in create and update endpoints
- Warning: Added agent existence validation in `add_group_members` — unknown agent_ids returned in `not_found` list
- Warning: Optimized N+1 compliance queries to single SQL with `MAX(id)` subquery for latest log entry per agent

**Tests**: 29 tests in `test_group_policies.py` — Database CRUD (5: create/get, list by priority, update rules, delete cascades members, nonexistent returns None), Membership (4: add/get, duplicate returns false, remove, get agent groups sorted), Application log (2: log/update status, compliance shows status), Policy engine (7: apply queues commands, empty group, nonexistent group, single group effective rules, priority merge, firewall union, compliance summary), Structural wiring (5: apply_policy in allowlist, main includes router, routes module, engine module, windows_shield handler), Frontend structure (6: HTML section/CSS, JS exports/lifecycle/session token/XSS escaping). Total: 2956 tests, 0 failures.

### v0.3.29 (2026-02-16) - Cross-System Threat Correlation: Alert Bridging & Propagation
**Status**: Complete - Remote Shield threats now feed into the correlator; correlated alerts propagate back to affected agents

**Changes**:
- **EventAggregator bridge** (`remote_shield_routes.py`): `submit_threat()` now bridges every Remote Shield threat into the local `EventAggregator.ingest()` with `remote.{type}` event_type, normalized severity via `_normalize_remote_severity()`, and linked `asset_id` from agent data. Best-effort with debug logging on failure.
- **Alert propagation callback** (`cross_asset_correlation.py`): New `set_alert_propagation(callback)` method and `_alert_propagation_callback` attribute. `_emit_threat()` calls the callback with the `CorrelatedThreat` when `affected_assets` is non-empty. Best-effort with debug logging.
- **AlertPropagator module** (`remote/alert_propagator.py`): New `AlertPropagator` class that resolves `asset_id` → `agent_id` (with cache + known-missing sentinel), queues `threat_alert` commands via `shield_db.queue_command()`. `clear_cache()` method for agent registration invalidation.
- **Startup wiring** (`main.py`): Creates `AlertPropagator(shield_db)` and wires `.propagate` to `correlator.set_alert_propagation()` (defensive: guarded by `shield_db is not None` + try/except with logging).
- **Command allowlist** (`remote_shield_routes.py`): Added `"threat_alert"` to `ALLOWED_COMMAND_TYPES`.
- **Agent handler** (`agent/windows_shield.py`): New `threat_alert` handler in `_execute_command()` logs cross-system alerts to stderr with severity, description, and indicator. Returns `"alert_received"`.

**Code review fixes applied**:
- Critical: Added `logger.debug()` to bridge try/except in `remote_shield_routes.py` (was bare `pass`)
- Critical: Added `logger.debug()` to correlator propagation callback try/except (was bare `pass`)
- Warning: Added known-missing sentinel (empty string) to `_resolve_agent()` cache to prevent repeated full-table scans for local-only assets
- Warning: Added sentinel check in cache hit path — empty string returns `None` without re-querying DB

**Tests**: 20 new tests in `test_cross_system_correlation.py` — AlertPropagator (8: queues commands, resolves agents, skips unknown, payload shape, empty assets, no-asset_id agents, cache reuse, cache clear), correlator propagation (4: method exists, callback called, empty assets skipped, failure resilience), severity normalization bridge (1), ALLOWED_COMMAND_TYPES (2), windows_shield handler (1), structural wiring (4). Total: 2927 tests, 0 failures.

### v0.3.28 (2026-02-16) - Unified Cross-System Threat Timeline
**Status**: Complete - Merges local, Remote Shield, and correlation events into a single chronological view

**Changes**:
- **Severity normalization** (`dashboard_ext.py`): Two pure-function helpers map Remote Shield's 1-10 integer severity and correlator's low/medium/high/critical strings to the 4-level scale (info/investigate/alert/critical). Original values preserved in `source_detail` for drill-down.
- **Unified timeline endpoint** (`dashboard_ext.py`): New `GET /api/timeline/unified` with session auth. Queries `EventAggregator`, `RemoteShieldDatabase.list_threats()`, and `CrossAssetCorrelator.recent_correlations()`. Server-side merge: normalizes severity, applies filters (severity, asset, source, time_from, time_to), sorts chronologically, computes per-source and per-severity stats. 30-second cache TTL. New Pydantic models: `UnifiedTimelineEntry` (extends `TimelineEntry` with `source` and `source_detail`) and `UnifiedTimelineResponse`.
- **WS broadcast for remote threats** (`remote_shield_routes.py`): `submit_threat()` now broadcasts `threat:remote-shield` on the main WebSocket after DB persist (best-effort, lazy import avoids circular).
- **WS broadcast for correlations** (`cross_asset_correlation.py`): New `set_ws_broadcast(callback)` method on `CrossAssetCorrelator`. `_emit_threat()` fires `threat:correlation` via `asyncio.run_coroutine_threadsafe` (best-effort). Wired in `main.py` startup.
- **Timeline tab enhancement** (`timeline.html`, `timeline.js`): Source filter dropdown (Local/Remote Shield/Correlations), new Source column with color-coded badges (green=local, cyan=remote, purple=correlation), source stats pills, `renderSourceDetail()` for drill-down panel showing agent_id/hostname/original severity for remote events and correlation_type/indicator/affected_assets for correlations. D3 scatter dots differentiated by source stroke. Updated `fetchTimeline()` to call `/api/timeline/unified`, added 2 new WS subscriptions (`threat:remote-shield`, `threat:correlation`).
- **WebSocket message types** (`websocket-handler.js`): Added `threat:remote-shield` and `threat:correlation` to `MESSAGE_TYPES`.

**Code review fixes applied**:
- Critical: Fixed `datetime` not JSON-serializable in WS broadcast — added `.isoformat()` to `threat.timestamp` in `remote_shield_routes.py`
- Warning: Normalized empty string params to `None` in `get_unified_timeline()` for consistent cache keys
- Warning: Added `_norm_ts()` helper to strip timezone suffixes (`Z`, `+00:00`) for safe string-based timestamp comparison in filters and sort
- Suggestion: Changed asset_id filter from raw substring (`in`) to split-based membership (`in e.asset_id.split(",")`) to prevent false matches on partial IDs

**Tests**: 52 new tests in `test_unified_timeline.py` — severity normalization (10), models (3), unified timeline method (14: empty/local/remote/correlation/merged sort/filters/pagination/stats/source_detail), WS wiring (3), HTML structure (8), JS structure (9), WS handler (2), route endpoint (3). Total: 2907 tests, 0 failures.

### v0.3.27 (2026-02-16) - Automated Patching (Windows Update Monitoring)
**Status**: Complete - Per-device update status + remote "Check for Updates" trigger

**Changes**:
- **Generic command queue** (`shield_database.py`): New `agent_commands` table with three-state lifecycle (`pending → delivered → acknowledged`). Atomic delivery marking prevents duplicate commands on rapid heartbeats. Reusable for future command types (run_scan, restart_defender, etc.).
- **Patch status storage** (`shield_database.py`): Added `patch_status_json TEXT` column on `remote_shield_agents` via migration. Parsed into `patch_status` dict in `_row_to_agent()`. CRUD methods: `update_patch_status()`, `get_patch_status()`.
- **Server endpoints** (`remote_shield_routes.py`): 4 new endpoints — `POST/GET /api/agents/{id}/patch-status` (agent reports status / dashboard reads), `POST /api/agents/{id}/commands` (dashboard queues command, session auth, allowlisted types only), `POST /api/agents/{id}/commands/ack` (agent acknowledges). Heartbeat response extended with `pending_commands` field for piggyback delivery.
- **Windows Update sensor** (`windows_shield.py`): New `sensor_windows_updates()` runs every 60 minutes with own DB connection (thread-safe pattern from v0.3.26). Queries `Microsoft.Update.Session` COM for pending updates, `Get-HotFix` for recent installs, registry `RebootRequired` key, `AutoUpdate.Results` for last check date. Falls back to `wmic qfe` on failure. Reports `windows_update_overdue` threat when pending > 7 days or reboot required.
- **Command execution** (`windows_shield.py`): `_execute_command()` dispatches `check_updates` → `wuauclt /detectnow` (user-level, triggers Windows Update service check). Acknowledges result back to server. `send_heartbeat()` now processes `pending_commands` from response.
- **Dashboard UI** (`remote-shield.html`, `remote-shield.js`): Patch status section in technical view with per-device cards showing status badge (Up to Date/Pending/Overdue/Reboot Required), pending count, installed count, last check/install dates, pending update titles. "Check for Updates" button queues command. Simplified view shows update status line per device card.
- **Tests**: 31 new tests — `test_patch_status.py` (16 tests: command queue CRUD, patch status JSON, row_to_agent integration) + `test_windows_updates_sensor.py` (15 tests: PS output parsing, wmic fallback, sensor threats, command execution, heartbeat commands). Full suite: 2855 passed, 0 failed.
- **Code review fixes**: (1) XSS: added single-quote escaping (`&#x27;`) to `escapeHtml()` for safe JS string interpolation in onclick handlers. (2) Auth: added `verify_session_token` to `GET /agents/{id}/patch-status` endpoint. (3) Correctness: `get_pending_commands()` now returns `status: 'delivered'` reflecting actual DB state. (4) Validation: `list_commands()` rejects invalid status values with `ValueError`. (5) Error logging: sensor loop prints errors to stderr instead of silent swallow. (6) Performance: removed N+1 `fetchPatchStatuses()` — `fetchAgents()` already includes `patch_status` in response data.

### v0.3.26 (2026-02-16) - Code Review Fixes (v0.3.24 + v0.3.25)
**Status**: Complete - Thread safety, invitation resilience, and API validation fixes

**Changes**:
- **Cross-thread SQLite fix** (`windows_shield.py`): Daemon previously shared a single SQLite connection across 5 sensor threads + main loop. Each sensor now creates its own connection via `init_db()` (with `try/finally: conn.close()`), and the main loop uses a separate `main_conn`. Prevents `sqlite3.ProgrammingError` at runtime.
- **Invitation recovery on failure** (`agent_invitation.py`, `remote_shield_routes.py`): Added `InvitationStore.revert_consumed(invitation_id)` method that atomically reverts a consumed invitation back to pending status. The Shield enrollment endpoint now calls `revert_consumed()` in its except block when `create_agent()` fails, preventing permanently burned invitations on transient errors.
- **Preference endpoint validation** (`dashboard_ext.py`): Replaced `body: dict = Body(...)` with typed Pydantic model `PreferenceUpdate(BaseModel): value: str`. Rejects missing or non-string values with 422 instead of silently accepting empty strings.
- **THREAT_GUIDANCE key alignment** (`remote-shield.js`): Fixed incorrect keys (`suspicious_process`, `new_service`, `rdp_enabled`) to match actual ThreatType enum values (`process_anomaly`, `suspicious_software`, `unauthorized_access`, `windows_update_overdue`).
- **Platform validation**: Already uses `Literal["linux", "windows", "macos"]` (confirmed no change needed).
- **Tests**: Updated `test_windows_shield_agent.py` sensor test for new per-thread connection pattern. Full suite: 2824 passed, 0 failed.

### v0.3.25 (2026-02-16) - Simplified Protected Mode
**Status**: Complete - Dashboard mode toggle for non-technical users

**Changes**:
- **UserPreferences SQLite store**: New `src/citadel_archer/core/user_preferences.py` — key/value preference persistence following RemoteShieldDatabase pattern. Uses `core.db.connect()` helper for WAL mode. Methods: `get(key, default)`, `set(key, value)` (upsert), `get_all()`, `delete(key)`. Singleton via `get_user_preferences()`/`set_user_preferences()`. Constant: `PREF_DASHBOARD_MODE = "dashboard_mode"`.
- **Preference API endpoints**: 3 new session-auth protected endpoints in `dashboard_ext.py`: `GET /api/preferences` (all prefs as dict), `GET /api/preferences/{key}` (single key), `PUT /api/preferences/{key}` (upsert with `{"value": "..."}` body).
- **Agent alert threshold**: `remote_shield_agents` table gains `alert_threshold INTEGER DEFAULT 0` column via ALTER TABLE migration. New methods: `set_agent_alert_threshold(agent_id, threshold)`, `get_agent_alert_threshold(agent_id)`. `_row_to_agent()` includes `alert_threshold` with safe fallback.
- **Heartbeat threshold delivery**: `HeartbeatResponse` model extended with `alert_threshold: int` field. Agent heartbeat endpoint reads threshold from DB and includes in response. New `PUT /api/agents/{agent_id}/alert-threshold` admin endpoint (session auth, validates 0-10 range).
- **Windows agent threshold filtering**: `windows_shield.py` `report_threats()` filters events below threshold — sub-threshold events are marked as reported locally (prevents buildup) but never sent to server. `send_heartbeat()` parses `alert_threshold` from heartbeat response and saves to config when changed.
- **Dashboard mode toggle**: Settings panel in `index.html` with "Technical" / "Simplified" mode buttons. `settings.js` implements full toggle lifecycle: `openGeneralSettings()` shows panel, `loadCurrentMode()` reads localStorage (fast) + API (authoritative), `saveMode()` persists to both + dispatches `dashboard-mode-changed` custom event.
- **Tab filtering**: `dashboard-nav.js` adds `SIMPLIFIED_TABS = ['intelligence', 'assets', 'remote-shield']` — simplified mode hides Charts, Timeline, Risk Metrics, Panic Room, Vault tabs. `applyDashboardMode()` shows/hides tab buttons and redirects to intelligence if current tab is hidden. Keyboard nav respects `getVisibleTabs()`.
- **Remote Shield simplified view**: `remote-shield.html` gains `rs-simplified-view` section (sibling to `rs-technical-view`). `remote-shield.js` adds `THREAT_GUIDANCE` dictionary (7 threat types with friendly title templates + "What to do" guidance), `renderHeroStatus()` (green shield/yellow shield/red triangle based on threat severity), `renderDeviceList()` (colored dots + plain status text per device), `renderAlertCards()` (critical+high threats only with plain-English descriptions).
- **Assets simplified view**: `assets.js` branches `renderTable()` → `renderSimplifiedAssets()` in simplified mode (3-column: Device/Status/Last Check with colored dots). `openDetail()` → `openSimplifiedDetail()` shows centered icon + status + "Suggested Action" card.
- **CSS overrides**: `body.simplified-mode` class hides add-asset-btn, filter-threat, filter-status, clear-filters-btn, page-size-select via `!important` rules.
- **New files**: `src/citadel_archer/core/user_preferences.py` (~108 lines), `tests/test_user_preferences.py` (11 tests), `tests/test_simplified_mode.py` (40 tests).
- **Modified**: `src/citadel_archer/api/dashboard_ext.py`, `src/citadel_archer/remote/shield_database.py`, `src/citadel_archer/api/remote_shield_routes.py`, `src/citadel_archer/agent/windows_shield.py`, `frontend/index.html`, `frontend/js/settings.js`, `frontend/js/dashboard-nav.js`, `frontend/remote-shield.html`, `frontend/js/remote-shield.js`, `frontend/js/assets.js`, `frontend/css/styles.css`.
- **Tests**: 56 new tests (11 user_preferences + 40 simplified_mode + 3 alert_threshold + 2 preference endpoints). Full suite: 2824 passed, 0 failed.

### v0.3.24 (2026-02-16) - Windows Remote Shield Agent
**Status**: Complete - Windows agent + invitation-based Shield enrollment

**Changes**:
- **Shield enrollment endpoint**: `POST /api/agents/enroll` — unauthenticated, IP rate-limited (10/min). Accepts invitation string from `v0.3.22` system, verifies it's a SHIELD agent type (vps/workstation/cloud), atomically consumes invitation, creates Remote Shield agent in `shield_database.py`, auto-links to managed asset with correct platform mapping. Agent type validation happens before invitation consumption (prevents credential waste on type mismatch). Returns `agent_id` + Bearer `api_token`.
- **Agent type categories**: `VALID_AGENT_TYPES` expanded to include shield types. `SHIELD_AGENT_TYPES = {"vps", "workstation", "cloud"}` for Shield enrollment. `AI_AGENT_TYPES = {"forge", "openclaw", "claude_code", "custom"}` for AI agent enrollment. Invitation creation now accepts both categories.
- **Platform column**: `remote_shield_agents` table gains `platform TEXT DEFAULT 'linux'` via ALTER TABLE migration. `create_agent()` accepts platform param. `_row_to_agent()` includes platform with safe fallback for pre-migration rows.
- **Windows threat types**: `ThreatType` enum expanded with 6 Windows-specific types: `defender_disabled`, `firewall_disabled`, `logon_failure`, `audit_log_cleared`, `suspicious_software`, `windows_update_overdue`.
- **Platform asset mapping**: `_auto_link_agent()` maps platform → correct `AssetPlatform`/`AssetType`: windows→WINDOWS/WORKSTATION, linux→VPS/VPS, macos→MAC/WORKSTATION.
- **Input validation**: `ShieldEnrollRequest.platform` constrained to `Literal["linux", "windows", "macos"]`. Hostname validated: 1-253 chars, alphanumeric + dots/hyphens/underscores only.
- **Windows Shield agent**: Standalone single-file Python script (`src/citadel_archer/agent/windows_shield.py`, ~440 lines). Stdlib-only (no pip), Python 3.8+. Enrolls via invitation string, monitors 5 sensors (Event Log via `wevtutil`, Defender via `PowerShell`, Firewall via `netsh`, Processes via `tasklist`, Software via `reg query`), each in its own thread. Reports threats + heartbeats to server via HTTP. CLI: `enroll <url> <invitation>`, `daemon`, `status`, `install` (Task Scheduler), `uninstall`. Storage: `%LOCALAPPDATA%\CitadelShield\` (config.json, events.db, shield.pid). SQLite uses `check_same_thread=False` + WAL for cross-thread safety. Config file permissions restricted to current user.
- **Frontend updates**: Invite modal dropdown updated to "VPS (Linux)" / "Windows PC" / "Cloud". Platform-specific enrollment instructions shown after generating invitation (workstation: download + PowerShell steps; vps/cloud: SSH steps).
- **New files**: `src/citadel_archer/agent/windows_shield.py` (~440 lines), `tests/test_windows_shield_enroll.py` (16 tests), `tests/test_windows_shield_agent.py` (28 tests).
- **Modified**: `src/citadel_archer/chat/agent_registry.py`, `src/citadel_archer/remote/shield_database.py`, `src/citadel_archer/api/remote_shield_routes.py`, `frontend/assets.html`, `frontend/js/assets.js`.
- **Tests**: 44 new tests (16 enrollment + 28 agent). Full suite: 2768 passed, 0 failed.

### v0.3.23 (2026-02-16) - Invitation Flow UI in Assets Tab
**Status**: Complete - Frontend UI for generating and copying agent enrollment invitations

**Changes**:
- **Invite Remote Agent modal**: Two-step modal in Assets tab triggered by "Add Asset" button. Step 1: agent name + type form with "Generate Invitation" button. Step 2: monospace code box displaying compact invitation string (`CITADEL-1:...`) with copy-to-clipboard button and step-by-step instructions (SSH → Claude Code → paste).
- **Clipboard copy with fallback**: Uses `navigator.clipboard.writeText()` with DOM textarea fallback for older browsers/non-HTTPS contexts. "Copied!" feedback tooltip with CSS fade animation.
- **Manual asset form preserved**: "Or add an asset manually" link in invite modal switches to existing asset creation form. No functionality lost.
- **CSS styles**: `.invite-code-box` (monospace, dark bg, neon-blue border), `.invite-copy-btn` (positioned icon button), `.invite-copy-feedback` (animated tooltip), `.invite-step` toggle, `.invite-instructions` (numbered steps), `.invite-link` (underlined text link).
- **Listener cleanup**: All invite modal event listeners registered via `_trackListener()` for proper cleanup on tab switch (no memory leaks).
- **Modified**: `frontend/assets.html` (~140 lines added — CSS + HTML), `frontend/js/assets.js` (~100 lines added — modal logic + API call).
- **Tests**: 18 new tests in `tests/test_assets_frontend.py` — `TestInviteModalHTML` (11 tests: overlay, steps, inputs, code box, copy button, add-manually link, copy feedback, instructions, CSS classes) + `TestInviteModalJS` (7 tests: functions, API call, clipboard, button wiring). Full suite: 2724 passed, 0 failed.

### v0.3.22 (2026-02-16) - Secure Invitation-Based Agent Enrollment
**Status**: Complete - Security hardening: One-time invitation codes for external AI agent enrollment

**Changes**:
- **InvitationStore**: SQLite-backed store for one-time enrollment invitations. WAL journal mode, contextmanager connections, threading.Lock, singleton via `get_invitation_store()`. Follows ContactRegistry/AgentRegistry patterns. Schema: `agent_invitations` table with invitation_id (PK), secret_hash, hmac_tag, status, TTL, failed attempts, IP tracking, audit fields.
- **256-bit enrollment secrets**: `secrets.token_urlsafe(32)` generates high-entropy enrollment tokens. Only `SHA-256(secret)` stored in database — raw secrets never persisted. Constant-time comparison via `secrets.compare_digest()` for all secret verification.
- **HMAC-SHA256 binding**: Each invitation has an HMAC tag binding `invitation_id` to `secret_hash` using the server session token as key. Prevents mix-and-match attacks (using one invitation's secret with another's ID). HMAC verified against stored hash (not candidate) for independent database integrity checking.
- **Compact invitation string**: Terminal-friendly format `CITADEL-1:<12_hex_id>:<base64url_secret>`. No special characters, safe for copy-paste across terminals. Strict format validation via regex patterns in `parse_compact_string()`.
- **One-time atomic consumption**: `verify_and_consume()` runs entirely under `threading.Lock` + single SQLite transaction. Checks: exists → status==pending → not expired → not locked → secret correct (constant-time) → HMAC valid (constant-time). Status set to REDEEMED atomically. Concurrent redemption test validates only one of two simultaneous attempts succeeds.
- **Failed attempt tracking + lockout**: Each wrong secret increments `failed_attempts` and records `last_attempt_ip` + `last_attempt_at`. After N failures (default 5, configurable 1-20), status permanently set to LOCKED — terminal state, cannot be unlocked.
- **Short TTL**: Default 600 seconds (10 minutes), configurable 60s-86400s (1 min to 24h). Clamped at boundaries. Server restart invalidates all pending invitations (HMAC key = session token, which rotates on restart).
- **IP rate limiting on enrollment**: Separate `AgentRateLimiter` instance keyed by client IP, 10 attempts/minute on the unauthenticated `/enroll` endpoint. Applied before any database or crypto operations.
- **Generic error responses**: Enrollment endpoint maps not_found, already_redeemed, revoked, expired, invalid_secret all to `401 "Invalid or expired invitation"`. Only `locked` gets distinct `423` response. Prevents invitation ID enumeration.
- **Registration failure handling**: If `AgentRegistry.register_agent()` fails after invitation is consumed, error is caught and logged (prevents raw 500 + stack trace leakage). Consumed-but-unregistered state is explicitly logged for admin investigation.
- **HMAC key safety**: `_get_hmac_key()` only falls back to dev key on `ImportError` (test environments). `RuntimeError` (session token not initialized) is re-raised — prevents silent use of static key in production.
- **API endpoints (4 new)**: `POST /invitations` (admin creates invitation, session auth), `GET /invitations` (list with optional status filter + expired cleanup, session auth), `DELETE /invitations/{id}` (revoke pending, session auth), `POST /enroll` (redeem invitation + get Bearer token, NO auth, IP rate-limited).
- **Full audit trail**: Every action logged via `log_security_event()`: invitation creation (INFO), successful enrollment (INFO with agent_id+IP), failed enrollment (ALERT with error_code+IP), lockout (CRITICAL), revocation (ALERT), rate limiting (ALERT).
- **New file**: `src/citadel_archer/chat/agent_invitation.py` (~540 lines) — InvitationStatus, AgentInvitation, InvitationStore, get_invitation_store().
- **Modified**: `src/citadel_archer/api/agent_api_routes.py` — 4 new endpoints, Pydantic models, enrollment rate limiter.
- **Tests**: 65 tests in `tests/test_agent_invitation.py` — DB init (3), creation (12), compact parsing (5), verification (8), one-time use (2), expiry (3), failed attempt tracking (5), admin operations (8), to_dict (2), API create (4), API list (3), API revoke (3), API enroll (7 including rate limiting, lockout, expired, wrong secret). Full suite: 2706 passed, 0 failed.

### v0.3.21 (2026-02-16) - Inter-Agent Communication Protocol
**Status**: Complete - Phase 4 Advanced Communications: AI agent-to-AI agent coordination via SecureChat

**Changes**:
- **InterAgentProtocol**: Core protocol class enabling agent-to-agent coordination. Capabilities declaration (`register_capabilities()`), discovery by capability name + domain + online filter (`discover()`), task delegation with request-response correlation (`delegate()`), and agent presence tracking via heartbeats. Thread-safe with `threading.Lock`. Singleton via `get_inter_agent_protocol()`.
- **Capability-based discovery**: Agents declare capabilities (name, description, domains, SLA seconds) capped at MAX_CAPABILITIES=20. Other agents discover by capability name with optional domain filter and online-only filter. Discovery returns agent metadata, matched capabilities, and presence status.
- **Task delegation lifecycle**: `delegate()` creates a DELEGATION message with correlation_id, routes to target agent's inbox, and persists via ChatManager. Full lifecycle tracking: PENDING → ACCEPTED → COMPLETED/FAILED/TIMED_OUT. `accept_task()`, `complete_task()`, `fail_task()` enforce valid state transitions (can't complete an already-completed task). Timeout clamped to 1-3600 seconds.
- **Agent presence**: Heartbeat-based online detection with HEARTBEAT_TIMEOUT_SECONDS=300 (5 min). `heartbeat()` creates or updates presence, optionally refreshing capabilities. `is_online` property compares last heartbeat against UTC cutoff. `list_online_agents()` returns all agents with recent heartbeats.
- **Agent inbox (polling)**: Buffered messages per agent with MAX_INBOX_SIZE=100. `get_inbox()` returns and clears messages (atomic read-and-clear). O(1) overflow eviction via slice assignment (not O(n) pop(0) loop). Inbox count available without consuming messages.
- **Expired task cleanup**: `cleanup_expired_tasks()` marks timed-out active tasks and removes terminal tasks older than 1 hour. Called opportunistically during `delegate()` to prevent unbounded memory growth.
- **ChatMessage extensions**: Added `reply_to` (links response to parent message ID) and `correlation_id` (chains multi-leg request workflows) fields. Added `DELEGATION` and `ACK` message types. All new fields persisted to ChatStore via schema migration (ALTER TABLE with graceful column-exists handling).
- **ChatManager target routing**: Added `subscribe_target(to_id, listener)` / `unsubscribe_target()` for direct to_id-based message delivery. Target listeners notified between type-specific and wildcard listeners in `send()`.
- **ChatStore persistence**: Schema migration adds `reply_to`, `correlation_id` columns and `idx_chat_to` index on `to_id`. `save()` writes new fields. `_row_to_message()` reads them with graceful fallback for pre-migration rows.
- **API endpoints (9 new)**: `POST /{agent_id}/capabilities` (declare capabilities, Bearer auth), `GET /discover` (find agents by capability, session auth), `POST /delegate` (delegate task, Bearer auth), `POST /task-response` (accept/complete/fail task, Bearer auth with ownership check), `GET /{agent_id}/inbox` (poll messages with Query-validated limit, Bearer auth), `POST /{agent_id}/heartbeat` (presence ping, Bearer auth), `GET /protocol/stats` (protocol statistics, session auth), `GET /protocol/tasks` (list tasks with filters, session auth), `GET /protocol/online` (online agents, session auth).
- **Agent ID namespace consistency**: API endpoints use `ext-agent:{agent_id}` participant IDs consistently for capabilities, heartbeats, delegation, and inbox — matching the existing participant ID convention used by ChatMessage routing.
- **Thread safety**: `list_tasks()` filtering moved inside lock scope to prevent race condition reading task status concurrently with state transitions.
- **New file**: `src/citadel_archer/chat/inter_agent.py` (~390 lines) — InterAgentProtocol, AgentCapability, AgentPresence, DelegatedTask, TaskStatus.
- **Modified**: `src/citadel_archer/chat/message.py` — DELEGATION/ACK types, reply_to/correlation_id fields.
- **Modified**: `src/citadel_archer/chat/chat_manager.py` — Target listener routing (subscribe_target/unsubscribe_target).
- **Modified**: `src/citadel_archer/chat/chat_store.py` — Schema migration + persistence for new ChatMessage fields + to_id index.
- **Modified**: `src/citadel_archer/api/agent_api_routes.py` — 9 new inter-agent endpoints with Pydantic models.
- **Tests**: 67 tests in `tests/test_inter_agent.py` — ChatMessage extensions (5), AgentCapability (3), AgentPresence (3), capabilities (4), discovery (5), presence (6), task delegation (11), cleanup (3), inbox (5), stats (1), ChatManager target routing (3), DelegatedTask serialization (1), API routes (17 covering all endpoints + auth checks + error cases). Full suite: 2641 passed, 0 failed.

### v0.3.20 (2026-02-16) - Secure File Sharing
**Status**: Complete - Phase 4 Advanced Communications: Encrypted, time-limited, self-destructing file sharing

**Changes**:
- **AES-256-GCM file encryption**: Each file encrypted with a unique random 256-bit key. 12-byte random nonce per encryption, stored as nonce‖ciphertext on disk. SHA-256 integrity verification before and after encryption. Max file size: 100 MB.
- **SecureFileManager**: SQLite-backed metadata + keys with encrypted files on disk. WAL mode + contextmanager connections + thread-safe (follows ContactRegistry/SessionStore pattern). Operations: `share_file()`, `download()`, `get()`, `list_shares()`, `delete()`, `extend_ttl()`, `cleanup_expired()`, `stats()`. Singleton via `get_file_manager()`.
- **Self-destruct**: Files can be configured to delete after first download. Atomic delete-before-return pattern prevents race condition where concurrent requests both receive the file content — the DB record is deleted under the lock before decryption, so only one thread proceeds.
- **Time-limited shares**: Configurable TTL (1-168 hours, default 24h). Expired shares auto-deleted on download attempt. Manual `cleanup_expired()` removes all expired shares from disk and database. `extend_ttl()` caps at MAX_TTL from current time.
- **FileShare dataclass**: `to_dict()` intentionally omits server-only fields (`encrypted_path`, `encryption_key`) to prevent leaking encryption material to API consumers.
- **API routes**: `POST /api/files/share` (multipart upload → temp file → encrypt → share), `GET /api/files/{id}/download` (decrypt + integrity check + Content-Disposition), `GET /api/files` (list with contact filter), `DELETE /api/files/{id}`, `POST /api/files/{id}/extend`, `POST /api/files/cleanup`, `GET /api/files/stats/summary`.
- **Security hardening**: Content-Disposition filename sanitized against header injection (regex strips non-word/dot/hyphen chars). Temp file suffix sanitized against path traversal. File descriptor properly closed in inner `finally` block to prevent fd leak on write failure. Public `update_filename()` method replaces direct private member access from route handler.
- **New file**: `src/citadel_archer/chat/secure_file.py` (~590 lines) — File encryption, SecureFileManager, FileShare dataclass.
- **New file**: `src/citadel_archer/api/file_routes.py` (~230 lines) — REST API endpoints for file sharing.
- **Modified**: `src/citadel_archer/api/main.py` — Added `file_router` registration.
- **Tests**: 53 tests in `tests/test_secure_file.py` — encrypt/decrypt (9), verify_checksum (3), FileShare (2), SecureFileManager (19 including self-destruct, TTL, cleanup, stats, expired auto-delete), API routes (20 including auth, upload, download, list, filter, delete, extend, cleanup, stats, self-destruct, empty file rejection). Full suite: 2574 passed, 0 failed.

### v0.3.19 (2026-02-16) - E2E Encrypted Peer-to-Peer Messaging
**Status**: Complete - Phase 4 Advanced Communications: Signal-like E2E encryption for P2P messaging

**Changes**:
- **X3DH key agreement**: Extended Triple Diffie-Hellman (X3DH) protocol for session establishment between peers. Uses 4 DH exchanges (IK↔SPK, EK↔IK, EK↔SPK, EK↔OPK) to compute a shared secret without both parties being online simultaneously. PreKeyBundle creation with Ed25519 signature verification on signed prekeys. Optional one-time prekeys for additional forward secrecy.
- **Double Ratchet**: Full Signal-spec Double Ratchet implementation with DH ratchet (X25519 key exchange advances root key), symmetric ratchet (HMAC-SHA256 chain key → message key derivation), and out-of-order message handling (skipped message keys stored, capped at MAX_SKIP=100 per-call and globally to prevent DoS). Forward secrecy: compromising current keys cannot decrypt past messages. Future secrecy: DH ratchet step heals from key compromise.
- **AES-256-GCM AEAD**: Message encryption uses AES-256-GCM with 96-bit random nonces. Associated data binds session identity keys + message header to ciphertext, preventing cross-session replay attacks and header manipulation.
- **Key derivation**: HKDF-SHA256 for X3DH shared secret and root key derivation (zero salt per Signal convention, domain-separated via info strings). HMAC-SHA256 for symmetric chain key advancement (0x01 → chain key, 0x02 → message key).
- **Key pairs**: X25519 `DHKeyPair` for Diffie-Hellman key exchange, Ed25519 `SigningKeyPair` for identity and prekey signing. Full serialization round-trip for persistence.
- **RatchetState**: Serializable dataclass containing all session state (DH keys, root key, chain keys, counters, skipped message keys). Safe `__repr__` redacts all key material to prevent accidental logging of secrets. `to_dict()`/`from_dict()` for SQLite persistence.
- **Session store**: `SessionStore` provides SQLite-backed persistence for local identity keys (Ed25519 + X25519, auto-generated on first access), signed prekeys, one-time prekeys (single-use per X3DH spec — consumed on bundle creation), and per-contact ratchet session state. WAL mode + contextmanager connections + thread-safe. Private key storage is plaintext hex (tracked TODO for encryption via EncryptionService before production use).
- **Prekey management**: `get_or_create_signed_prekey()` for long-lived signed prekey, `generate_one_time_prekeys(count)` for batch OPK generation, `consume_one_time_prekey()` for responder-side OPK consumption, `get_local_prekey_bundle()` builds and publishes bundle (atomically consumes OPK to prevent reuse).
- **Message format**: `MessageHeader` (sender DH public key + chain counters, 40-byte binary encoding), `EncryptedMessage` (header + nonce‖ciphertext). Full JSON serialization for wire transport.
- **New file**: `src/citadel_archer/chat/p2p_crypto.py` (~470 lines) — X3DH, Double Ratchet, AEAD, key pairs, message format.
- **New file**: `src/citadel_archer/chat/session_store.py` (~310 lines) — SQLite persistence for keys + sessions.
- **Code review fixes**: Bounded skipped message keys globally (evicts oldest when exceeding MAX_SKIP), fixed off-by-one in per-call skip limit, OPK consumed on bundle creation (single-use enforcement), MessageHeader.decode validates input length, HKDF docstring warns against changing zero salt, RatchetState.__repr__ redacts secrets, corrected security comment about plaintext key storage.
- **Tests**: 66 tests in `tests/test_p2p_crypto.py` — key pairs (4+5), key derivation (6), AEAD (4), PreKeyBundle (5), X3DH (4), Double Ratchet (10 including global skip cap), MessageHeader (3), EncryptedMessage (1), RatchetState serialization (5 including repr), SessionStore (15 including OPK consumption + multi-OPK pool), full protocol integration (4). Full suite: 2521 passed, 0 failed.

### v0.3.18 (2026-02-16) - Contact Management & Trusted Peer Registry
**Status**: Complete - Phase 4 Advanced Communications: Contact registry for SecureChat P2P messaging

**Changes**:
- **Contact registry**: `ContactRegistry` provides SQLite-backed contact management for trusted peer messaging. Thread-safe with WAL journal mode, following the `AgentRegistry` pattern. CRUD operations: add, get (by ID/fingerprint/public key), list (with trust/tag/search filtering), update, delete. All operations use proper contextmanager-based connection lifecycle (connect → yield → commit → close, with rollback on error) to prevent SQLite connection leaks.
- **Trust levels**: `TrustLevel` enum (pending → verified → trusted, or blocked at any point). `is_trusted()` returns True only for VERIFIED or TRUSTED contacts. `is_blocked()` gates message rejection. `set_trust()` validates contact exists via rowcount check before returning (returns None for nonexistent contacts).
- **Ed25519 public key management**: Keys stored as 64-char hex (32 bytes). `validate_public_key()` enforces exact length + valid hex. `compute_fingerprint()` produces SHA-256 colon-separated hex display (e.g., "AB:CD:EF:12:34:...") for out-of-band verification. Duplicate keys rejected at both public_key and fingerprint unique constraints.
- **Tag filtering**: Comma-boundary matching prevents false positives — tag "dev" won't match "devops" or "webdev". Uses 4-way LIKE pattern: exact match, starts-with, ends-with, contains-with-commas.
- **Message tracking**: `record_message()` increments count and updates last_message_at timestamp. Returns bool indicating whether contact was found (prevents silent failures on nonexistent contacts).
- **API routes**: 8 endpoints on `/api/contacts` — list (GET, with trust/tag/search query params), add (POST), get (GET /{id}), update (PUT /{id}), delete (DELETE /{id}), set trust (POST /{id}/trust), stats (GET /stats), verify fingerprint (GET /verify/{fp}). All require session auth via `verify_session_token`.
- **Pydantic validation**: `AddContactRequest` enforces `^[0-9a-fA-F]{64}$` hex pattern on public_key field. `SetTrustRequest` uses `TrustLevel` enum directly (Pydantic validates enum values, returning 422 for invalid input). Field length limits on all string inputs.
- **New file**: `src/citadel_archer/chat/contact_registry.py` (~510 lines) — `ContactRegistry`, `Contact`, `TrustLevel`, `compute_fingerprint()`, `validate_public_key()`, `get_contact_registry()` singleton.
- **New file**: `src/citadel_archer/api/contact_routes.py` (~185 lines) — FastAPI router with 8 endpoints + Pydantic request models.
- **Modified**: `src/citadel_archer/api/main.py` — Wired contact_router in app startup.
- **Tests**: 66 tests in `tests/test_contact_registry.py` — fingerprint computation (4), key validation (5), CRUD add (6), get (4), list+filtering (6 including tag false-positive test), update (4), delete (2), trust management (11), message tracking (2), stats (2), to_dict (2), enum (2), API route tests (17 covering all endpoints + error cases).

### v0.3.17 (2026-02-16) - Local LLM Integration (Ollama)
**Status**: Complete - Phase 4 Advanced AI: Ollama local LLM backend with Claude API fallback

**Changes**:
- **Ollama backend**: `OllamaBackend` class provides local LLM inference via Ollama's `/api/chat` REST endpoint. Supports health check with 30s cache, model discovery (`/api/tags`), chat completion with tool calling, and configurable model selection. Uses reusable `aiohttp` session (recommended by aiohttp docs) instead of per-request session creation. Pure HTTP — no SDK dependency.
- **Claude → Ollama fallback**: `AIBridge._call_with_tools()` refactored into `_call_claude()` + `_call_ollama()`. When Claude API fails or is unconfigured, automatically falls back to Ollama. When neither backend is available, bridge disables gracefully. Active backend tracked via `active_backend` property.
- **Localhost security enforcement**: `_is_localhost_url()` gates Ollama connections — only localhost/127.0.0.1/::1 allowed by default. Remote Ollama servers require explicit `OLLAMA_ALLOW_REMOTE=1` env var, preventing accidental data leakage to untrusted LLM endpoints. Security audit logging for all Ollama calls via existing `AIAuditLogger`.
- **Tool format conversion**: `_convert_tools()` translates Claude tool format (`input_schema`) to Ollama/OpenAI format (`function.parameters`). `chat_with_tools()` implements full tool execution loop mirroring the Claude tool loop (call → execute → feed results → repeat up to 5 iterations).
- **Message cleaning**: `_call_ollama()` sanitizes Claude content blocks (lists of ContentBlock objects) to plain `{role, content}` string dicts before forwarding to Ollama.
- **Model validation**: `set_ollama_model()` validates model exists via `has_model()` before switching, returns available models list on failure.
- **Audit logger extended**: `AIAuditLogger.finish_call()` accepts optional `ollama_response` dict for Ollama token tracking, maintaining full audit parity with Claude calls.
- **API endpoints**: `GET /api/ai/status` (backend status), `GET /api/ai/ollama/models` (available models via public `list_ollama_models()` method), `POST /api/ai/ollama/model` (switch model). All endpoints require session auth.
- **Dashboard services wiring**: `_ai_bridge` reference added to `DashboardServices`, wired in `main.py` startup. Welcome message now shows active backend name.
- **Tests**: 56 tests covering localhost validation (9), backend init/health/chat/tools/parsing, AI Bridge fallback logic, audit logger ollama support, session management, message cleaning, model validation. All endpoints tested through AIBridge public API.

### v0.3.16 (2026-02-15) - Extension Directory Watcher + Threat Intel Database
**Status**: Complete - Phase 2 Intelligence Layer: Real-time extension install monitoring + known-malicious extension cross-referencing

**Changes**:
- **Extension directory watcher**: `ExtensionWatcher` uses watchdog `Observer` to monitor Chromium extension directories in real-time. Detects `manifest.json` creation/modification, extracts extension ID from path structure, debounces duplicate events (5s window with automatic pruning at 200 entries), parses manifests and runs risk analysis on each detection. Mirrors the `FileMonitor` watchdog pattern for consistent Guardian lifecycle.
- **Known-vs-new detection**: Watcher maintains a set of known extension IDs (seeded from initial scan on startup). New installs emit `system.extension_install` events; existing extensions are tracked silently. Known set auto-updates as new extensions are detected.
- **Extension threat intel database**: `ExtensionIntelDatabase` cross-references extension IDs against a curated known-malicious database (6 entries: spyware, suspicious, bloatware, adware, phishing, cryptostealer). Thread-safe with full lock coverage on check/blocklist/stats operations. Supports user-configurable custom blocklist with add/remove/list operations.
- **Dangerous permission signatures**: 3 signature patterns auto-flag unknown extensions regardless of ID match: nativeMessaging + broad host access (critical), debugger access (high), management API access (high). Watcher invokes `check_permissions()` when ID lookup returns clean, ensuring permission-based threats are caught.
- **Category-severity mapping**: spyware/cryptostealer/phishing/malware → critical, adware/suspicious/tracker → high, bloatware → medium. Custom blocklist entries use category-based severity.
- **Event emission**: Malicious extensions emit `system.extension_malicious` (severity=critical) with intel reason in details. New installs emit `system.extension_install` with severity mapped from risk level (critical/alert/info). Both event types registered in EventAggregator category map.
- **API endpoints**: `GET /api/extensions/intel` (database stats + blocklist), `GET /api/extensions/watcher` (watcher status + detected count). `POST /api/extensions/scan` now refreshes watcher's known set after rescan.
- **Startup wiring**: ExtensionIntelDatabase created, ExtensionWatcher started with known IDs seeded from initial scan. Graceful shutdown via `watcher.stop()`. Wrapped in try/except to avoid blocking app startup.
- **New file**: `src/citadel_archer/guardian/extension_watcher.py` (~290 lines) — `ExtensionInstallHandler`, `ExtensionWatcher`.
- **New file**: `src/citadel_archer/guardian/extension_intel.py` (~250 lines) — `ExtensionIntelDatabase`, `IntelMatch`, `_KNOWN_MALICIOUS`, `_DANGEROUS_PERMISSION_COMBOS`.
- **Modified**: `src/citadel_archer/api/dashboard_ext.py` — Added `_extension_watcher`/`_extension_intel` service slots, 2 new endpoints, updated scan endpoint.
- **Modified**: `src/citadel_archer/api/main.py` — Wired ExtensionIntelDatabase + ExtensionWatcher in startup/shutdown.
- **Modified**: `src/citadel_archer/intel/event_aggregator.py` — Added `system.extension_install` and `system.extension_malicious` event types.
- **Code review fixes**: Consolidated `check()` under single lock (race condition on `_custom` dict), added `_recent` dict pruning at 200 entries (memory leak), consistent lock usage on `known_count`/`get_known_ids()`, wired `check_permissions()` into watcher detection path (was dead code), fixed stop ordering (observer stops before flag), upgraded watch failure log level to WARNING.
- **Test coverage**: 38 tests in `tests/test_extension_watcher.py` across 10 classes — intel DB CRUD (10), permission signatures (5), IntelMatch (2), thread safety (1), watcher lifecycle (4), known set (3), malicious detection + permission flagging (3), severity mapping (4), install handler (5), profile detection (1). Full suite: 2332 passed, 0 failed.

---

### v0.3.15 (2026-02-15) - Browser Extension Inventory Scanner
**Status**: Complete - Phase 1 + Phase 2 Intelligence Layer: Browser extension inventory scanning with permission risk analysis

**Changes**:
- **Browser extension inventory scanner**: `ExtensionScanner` enumerates installed extensions across all Chromium-based browsers (Chrome, Edge, Brave, Vivaldi) on Windows. Discovers extension directories under `%LOCALAPPDATA%`, finds all profiles (Default + Profile 1, 2, ...), parses `manifest.json` for each extension, and extracts permissions, host patterns, content script matches.
- **Permission risk analysis**: Classifies extensions into 4 risk levels (low/medium/high/critical). Dangerous permissions flagged: `clipboardRead`, `nativeMessaging`, `debugger`, `webRequestBlocking`, `management`, `proxy`, `desktopCapture`, etc. Dangerous combos escalate risk: broad host + webRequest, nativeMessaging + broad host, clipboardRead + broad host, tabs + activeTab + broad host. Broad host detection for `<all_urls>`, `*://*/*`, and overly-broad wildcard patterns.
- **Install source classification**: Chrome Web Store IDs (32 lowercase a-p chars), UUID-style IDs (sideloaded/Edge), enterprise policy paths, development mode extensions. Sideloaded/dev extensions get risk bump.
- **MV2/MV3 manifest handling**: Properly separates API permissions from host patterns (MV2 puts both in `permissions`; MV3 uses `host_permissions`). Content script `matches` extracted separately.
- **Event emission**: Summary event (`system.extension_scan` — total count, flagged count, risk breakdown) + individual events for high/critical extensions (`system.extension_risk` — severity mapped to alert/critical for AI escalation pipeline). Both added to EventAggregator category map.
- **API endpoints**: `GET /api/extensions` (returns last scan results), `POST /api/extensions/scan` (triggers fresh scan). Session-token authenticated.
- **Startup scan**: Initial scan runs on server startup, results cached in `ExtensionScanner.last_scan` (thread-safe).
- **New file**: `src/citadel_archer/guardian/extension_scanner.py` (~400 lines) — `ExtensionScanner`, `BrowserExtension`, `ScanResult`, `analyze_risk()`, `parse_manifest()`, `_classify_install_source()`.
- **Modified**: `src/citadel_archer/api/dashboard_ext.py` — Added `_extension_scanner` service slot, `GET /api/extensions`, `POST /api/extensions/scan` endpoints.
- **Modified**: `src/citadel_archer/api/main.py` — Wired ExtensionScanner in startup with initial scan.
- **Modified**: `src/citadel_archer/intel/event_aggregator.py` — Added `system.extension_scan` and `system.extension_risk` event types.
- **Test coverage**: 61 tests in `tests/test_extension_scanner.py` across 14 classes — manifest parsing (4), host pattern extraction (4), broad access (7), install source (5), risk analysis (12), model (2), scan results (4), scanner FS (9), event emission (5), browser roots (2), MV2/MV3 (2), edge cases (5). Full suite: 2294 passed, 0 failed.

---

### v0.3.14 (2026-02-15) - Cross-Asset Threat Correlation (Watchtower Completion)
**Status**: Complete - Phase 2 Intelligence Layer: Watchtower cross-asset correlation engine completes the multi-asset threat detection pipeline

**Changes**:
- **Cross-asset threat correlation engine**: `CrossAssetCorrelator` subscribes to EventAggregator (sync callback), tracks indicators (IPs, domains, hashes) across all managed assets via in-memory sliding windows, and detects 4 correlation patterns: (1) **Shared IOC** — same indicator on 2+ assets within 1hr, (2) **Coordinated Attack** — same event type on 3+ assets within 10min, (3) **Attack Propagation** — high-severity events spreading across assets within 30min, (4) **Intel Match** — event indicators match known IOCs from IntelStore.
- **Thread-safe design**: 5 locks protect concurrent access — `_indicator_lock` (indicator map), `_asset_events_lock` (per-asset event windows), `_threat_lock` (output buffer + rate-limit state), `_dedup_lock` (dedup cache), `_history_lock` (correlation history). Sync callback from any thread, async flush loop for escalation.
- **Batch escalation to SecureChat**: 30s flush interval, dedup (10min window), rate limiting (10/hr). Summary format contains "critical/high" to trigger AI Bridge analysis. Failed sends are re-queued (up to 200 buffered).
- **Sliding window memory management**: Indicator sightings bounded at 5000 per type, per-asset events at 500. Stale entries evicted on flush cycle (indicators, dedup cache, per-asset events). `defaultdict`-based maps auto-clean empty keys.
- **API endpoints**: `GET /api/correlations` returns recent correlations + stats + total count. `GET /api/correlation-stats` returns engine statistics (running state, indicator count, tracked assets, escalation count, by-type breakdown).
- **New file**: `src/citadel_archer/intel/cross_asset_correlation.py` (~530 lines) — `CrossAssetCorrelator`, `CorrelationType`, `CorrelatedThreat`, `extract_indicators()`, `_format_correlation_summary()`.
- **Modified**: `src/citadel_archer/api/main.py` — Wired CrossAssetCorrelator in startup (after intel aggregator) with IntelStore for IOC matching, shutdown hook.
- **Modified**: `src/citadel_archer/api/dashboard_ext.py` — Added `_correlator` slot to `DashboardServices.__init__`, added `/api/correlations` and `/api/correlation-stats` endpoints.
- **Test coverage**: 52 tests in `tests/test_cross_asset_correlation.py` across 15 classes — indicator extraction (7), shared IOC (4), coordinated attack (4), propagation (3), intel match (4), no-asset filtering (1), dedup + rate limiting (3), flush loop (4), summary format (4), helpers (4), model (2), history + stats (3), lifecycle (4), window eviction (2), end-to-end (3). Full suite: 2233 passed, 0 failed.

---

### v0.3.13 (2026-02-15) - Intel Feed Completion: abuse.ch + MITRE ATT&CK + NVD
**Status**: Complete - Phase 2 Intelligence Layer: All 4 threat intelligence feeds active (was 1 of 4)

**Changes**:
- **abuse.ch fetcher (URLhaus + ThreatFox)**: `AbuseChFetcher` fetches malicious URLs from URLhaus and IOCs from ThreatFox. Two sub-feeds configurable independently. URLhaus threats mapped to severity (malware_distribution→CRITICAL, malware_download/phishing→HIGH). ThreatFox confidence mapped to severity (≥75→HIGH, ≥25→MEDIUM, <25→LOW). Handles IPv4 and IPv6 bracketed ip:port extraction. Tags parsed from both string and list formats.
- **MITRE ATT&CK fetcher**: `MitreFetcher` fetches the Enterprise ATT&CK STIX 2.1 JSON bundle (~15MB) from MITRE CTI GitHub. Extracts attack-pattern objects as TTP IntelItems with technique ID, name, tactic, platforms, data sources, references. Supports platform filtering (e.g., Windows-only), time filtering with proper datetime comparison, sub-technique severity escalation (sub-techniques→HIGH, parent→MEDIUM). Skips revoked/deprecated techniques.
- **NVD fetcher**: `NVDFetcher` fetches from NIST NVD CVE API v2.0. Extracts CVE entries with CVSS v3.1/v3.0/v2.0 scoring (cascade fallback) + per-product Vulnerability entries from CPE configurations with fix version tracking. Pagination with rate-limit compliance (6.5s delay without key, 0.7s with key). Supports API key authentication, keyword search, CVSS minimum filter. ISO 8601 dates include required UTC timezone offset.
- **IntelAggregator wiring**: All 4 fetchers (OTX + abuse.ch + MITRE + NVD) registered in `main.py` startup. Daily scheduled fetch at 02:00 UTC via APScheduler. Aggregator stopped in shutdown.
- **New file**: `src/citadel_archer/intel/abusech_fetcher.py` (~310 lines) — `AbuseChFetcher` class.
- **New file**: `src/citadel_archer/intel/mitre_fetcher.py` (~290 lines) — `MitreFetcher` class.
- **New file**: `src/citadel_archer/intel/nvd_fetcher.py` (~370 lines) — `NVDFetcher` class.
- **Modified**: `src/citadel_archer/api/main.py` — Added IntelAggregator startup with 4 fetchers + shutdown, added logging import.
- **Test coverage**: 133 tests across 3 files — `test_abusech_fetcher.py` (45), `test_mitre_fetcher.py` (35), `test_nvd_fetcher.py` (53). Full suite: 2181 passed, 0 failed.

---

### v0.3.12 (2026-02-15) - AI Threat Analysis for VPS
**Status**: Complete - Phase 2 AI Pipeline: VPS events now flow through the same AI analysis pipeline as local Guardian events

**Changes**:
- **REMOTE event category**: Added `REMOTE = "remote"` to `EventCategory` enum with 5 explicit sensor mappings (`remote.auth_log`, `remote.process_monitor`, `remote.file_integrity`, `remote.cron_monitor`, `remote.network_anomaly`). Prefix fallback: any `remote.*` event auto-categorizes without explicit mapping.
- **Remote Shield escalation handler (Trigger 2d)**: `RemoteShieldEscalation` mirrors `GuardianEscalation` pattern — subscribes to EventAggregator, filters REMOTE category + alert/critical/high severity, batches (30s), deduplicates (5min), rate-limits (15/hr — higher than Guardian's 10/hr for VPS volume). Groups summaries by asset_id so the AI knows which VPS is affected. Output format contains "critical/high" to trigger AI Bridge.
- **VPS behavioral baselines**: Added `REMOTE_AUTH` and `REMOTE_SENSOR` behavior types to ContextEngine. Granular mapping: `remote.auth_log` → REMOTE_AUTH, all other remote sensors → REMOTE_SENSOR. Auth events keyed by `auth:{detail}` (e.g., "auth:failed_password"), sensors keyed by sensor name. Enables per-VPS baselines: "VPS1 normally sees 5 failed auths/hour, 50 is anomalous."
- **4 new VPS threshold rules**: `remote_file_integrity_burst` (5+ in 1hr), `remote_cron_changes` (3+ in 1hr, cron changes are rare), `remote_process_anomaly` (10+ high/critical in 1hr), `multi_vps_coordinated` (CORRELATION: auth events + file/cron changes within 1hr = potential breach). All group_by_asset for per-VPS detection.
- **Enhanced AI tools**: `get_agent_events` now returns dict with agent health info (hostname, version, last_heartbeat, status) and severity breakdown (critical/high/medium/low counts) instead of raw threat list. New `get_vps_summary` tool gives bird's-eye overview of all VPS agents with grouped threat counts.
- **New file**: `src/citadel_archer/chat/remote_shield_escalation.py` (~230 lines) — `RemoteShieldEscalation` class.
- **Modified**: `src/citadel_archer/intel/event_aggregator.py` — REMOTE category + prefix fallback.
- **Modified**: `src/citadel_archer/intel/context_engine.py` — REMOTE_AUTH/REMOTE_SENSOR behavior types + granular event key extraction.
- **Modified**: `src/citadel_archer/chat/threshold_engine.py` — 4 new VPS rules (10 total).
- **Modified**: `src/citadel_archer/chat/ai_bridge.py` — Enhanced get_agent_events, new get_vps_summary tool.
- **Modified**: `src/citadel_archer/api/main.py` — Wired RemoteShieldEscalation in startup/shutdown.
- **Test coverage**: 64 tests across 5 files — `test_event_category_remote.py` (7), `test_remote_shield_escalation.py` (14), `test_context_engine_vps.py` (13), `test_vps_threshold_rules.py` (16), `test_ai_bridge_vps_tools.py` (11), plus 1 updated existing test. Full suite: 2048 passed, 0 failed.

### v0.3.11 (2026-02-15) - VPS Firewall Management + Node Onboarding
**Status**: Complete - Phase 2 Remote Shield Enhancement: dynamic firewall rules with geo-blocking + orchestrated node enrollment

**Changes**:
- **BUG FIX: `DashboardServices.get()` missing**: `services.get("ssh_manager")` in route files would crash with `AttributeError` in production (masked by test mocks using `dependency_overrides`). Added `get()` method via `getattr(self, key, default)` and service slots (`ssh_manager`, `shield_db`, `vault`, `chat_manager`). Wired services in `main.py` startup.
- **VPS firewall management**: Desktop-managed iptables rules pushed to VPS via SSH. Rules stored in `shield_database.py` (`firewall_rules` table, 13 columns), compiled into config.json `firewall_rules` array, pushed to VPS where shield agent applies them via `CITADEL-FW` iptables chain. Supports deny/allow/rate_limit actions, TCP/UDP/ICMP/any protocols, port ranges, priority ordering, auto-generated rules with TTL expiry, and geo-blocking via country CIDR file.
- **Geo-blocking via CIDR file**: Desktop generates `geo_cidrs.dat` (format: `CC CIDR` per line), pushes to VPS `/opt/citadel-shield/geo_cidrs.dat`. Shield agent reads locally — no external API calls from VPS side. `_resolve_geo_cidrs()` in shield.py, `push_geo_data()` in desktop firewall manager.
- **Rate limiting via iptables hashlimit**: Rules with `action: "rate_limit"` use iptables `hashlimit` module (`--hashlimit-above rate --hashlimit-mode srcip`).
- **Config hot-reload**: `ShieldDaemon` monitors config.json mtime every 30s, reloads firewall rules on change without daemon restart.
- **Node onboarding orchestrator**: 6-step automated workflow for enrolling remote VPS/computers: (1) validate asset exists + has credentials, (2) test SSH connection + gather OS info, (3) deploy shield agent + install systemd service, (4) apply SSH hardening (optional), (5) configure firewall rules + geo-blocks (optional), (6) verify all sensors active + agent reporting. Per-step state tracking in `onboarding_sessions` DB table, WebSocket broadcast for real-time progress UI, retry support for failed steps, partial completion support (e.g., agent deployed but hardening skipped).
- **New file**: `src/citadel_archer/remote/firewall_manager.py` (~155 lines) — `DesktopFirewallManager` class: `add_rule()`, `remove_rule()`, `get_rules()`, `update_rule()`, `add_auto_rule()`, `compile_config()`, `push_rules()`, `push_geo_data()`.
- **New file**: `src/citadel_archer/remote/onboarding.py` (~320 lines) — `OnboardingOrchestrator`, `OnboardingConfig`, `StepResult`, `OnboardingResult` dataclasses, 6 step methods with error isolation.
- **New file**: `src/citadel_archer/api/firewall_routes.py` (~180 lines) — FastAPI router at `/api/firewall`. Endpoints: POST/GET `/rules/{asset_id}`, PUT/DELETE `/rules/{rule_id}`, POST `/push/{asset_id}`. Pydantic validation with field_validators.
- **New file**: `src/citadel_archer/api/onboarding_routes.py` (~160 lines) — FastAPI router at `/api/onboarding`. Endpoints: POST `/start`, GET `/{session_id}`, POST `/{session_id}/retry/{step}`, GET `/sessions/list`.
- **Modified**: `src/citadel_archer/remote/shield_database.py` — Added `firewall_rules` table (13 columns) and `onboarding_sessions` table (9 columns), 10 CRUD methods, 2 row converters.
- **Modified**: `src/citadel_archer/agent/shield.py` (~150 lines) — `FirewallRuleManager` class with `CITADEL-FW` iptables chain (follows `CITADEL-KNOCK` pattern), config.json hot-reload, `cli_firewall_status` CLI command.
- **Modified**: `src/citadel_archer/api/dashboard_ext.py` — Added `get()` method + 4 service slots to `DashboardServices`.
- **Modified**: `src/citadel_archer/api/main.py` — Registered firewall and onboarding routers, wired services in startup.
- **Modified**: `frontend/js/assets.js` + `frontend/assets.html` — "Onboard Node" button in asset detail panel, progress modal with step-by-step status via WebSocket, retry on failed steps.
- **Test coverage**: 48 tests across 6 files — `test_firewall_database.py` (7), `test_shield_firewall.py` (8), `test_firewall_manager.py` (7), `test_firewall_routes.py` (8), `test_onboarding.py` (12), `test_onboarding_routes.py` (6). Full suite: 1984 passed, 0 failed.

---

### v0.3.10 (2026-02-15) - SSH Hardening: Key-Only Auth, Port Knocking, fail2ban++
**Status**: Complete - Phase 2 Remote Shield Enhancement: SSH hardening with safety-first orchestration

**Changes**:
- **SSH hardening orchestrator**: Desktop-side `SSHHardeningOrchestrator` manages sshd_config remotely via SSH with safety-first 9-step workflow: backup sshd_config → verify key auth exists → apply sed directives (idempotent) → `sshd -t` validation → reload (NOT restart, preserves existing connections) → verify access with fresh SSH connection → auto-rollback on failure → save config to DB → push config.json to VPS. Dataclasses: `HardeningConfig` (serializable), `HardeningResult`, `HardeningStatus`, `RollbackResult`.
- **Port knocking via iptables `recent` module**: Kernel-level knock sequence tracking without external daemon (knockd). `PortKnockGuard` class in shield.py creates `CITADEL-KNOCK` iptables chain with stage transitions. Desktop-side `KnockClient` sends TCP SYN to each port in sequence via stdlib `socket`. SSH manager auto-knocks before connecting if port knocking is enabled for the asset.
- **fail2ban++ progressive banning**: Escalating ban durations (5min → 1hr → 24hr → permanent after 5 offenses). New `ip_bans` SQLite table tracks ban history. IP whitelist from config.json prevents accidental self-lockout. `BanExpiryManager` checks for expired bans every 60s in daemon loop, auto-unblocks. Existing `block_ip()` refactored into `_apply_firewall_block()`, `unblock_ip()`, and progressive `block_ip()` with backward-compatible signature.
- **New file**: `src/citadel_archer/remote/ssh_hardening.py` (~320 lines) — Orchestrator with harden_asset(), rollback_hardening(), get_hardening_status(), internal helpers for each sub-operation.
- **New file**: `src/citadel_archer/remote/knock_client.py` (~60 lines) — `KnockClient` class + `knock_and_connect()` async helper.
- **New file**: `src/citadel_archer/api/ssh_hardening_routes.py` (~200 lines) — FastAPI router at `/api/hardening`. Endpoints: POST/DELETE/GET `/ssh/{asset_id}`, GET `/ssh`. Pydantic validation (port range 1-65535, auth tries 1-10, etc.).
- **Modified**: `src/citadel_archer/remote/shield_database.py` — Added `ssh_hardening_configs` table with UPSERT pattern, 5 CRUD methods, `_row_to_hardening()` converter.
- **Modified**: `src/citadel_archer/agent/shield.py` (~180 lines) — `ip_bans` table, `_load_config()`, `BanExpiryManager`, `PortKnockGuard`, enhanced `AuthLogSensor` (configurable thresholds from config.json), enhanced `ShieldDaemon` (port knock on start, ban expiry in main loop), `cli_hardening_status` CLI command.
- **Modified**: `src/citadel_archer/remote/ssh_manager.py` (~25 lines) — Port-knock awareness in `connect()`, `_get_knock_config()` helper.
- **Modified**: `src/citadel_archer/remote/agent_deployer.py` (~30 lines) — Step 7: push pending hardening config.json to VPS after agent registration.
- **Test coverage**: 49 tests across 5 files — `test_hardening_database.py` (6), `test_shield_fail2ban.py` (12), `test_port_knocking.py` (8), `test_ssh_hardening.py` (15), `test_hardening_routes.py` (8). Full suite: 1936 passed, 0 failed.

---

### v0.3.9 (2026-02-15) - Per-Asset Rollback: Independent Recovery Scoping
**Status**: Complete - Phase 3 completion: rollback operations scoped per-asset for multi-target panic sessions

**Changes**:
- **Per-asset rollback implemented**: `recovery_states` schema now includes `asset_id` column with UNIQUE constraint `(session_id, component, component_id, asset_id)`, enabling independent state tracking when a panic session targets multiple assets (local + remote VPS). Rollback can now target specific assets without affecting others in the same session.
- **Modified**: `src/citadel_archer/panic/panic_database.py` — Added `asset_id TEXT NOT NULL DEFAULT 'local'` to `recovery_states` schema, updated UNIQUE constraint, added schema migration (detect missing column → rename → rebuild → copy → drop), added 3 new methods: `save_recovery_state()`, `get_recovery_states()` (component + asset filtering), `mark_state_rolled_back()`.
- **Modified**: `src/citadel_archer/panic/panic_manager.py` — `_save_recovery_state()` stores `asset_id`, uses `excluded.current_state` for UPSERT (adapter-safe). `rollback_panic()` accepts `target_assets` parameter, results keyed by `component:asset_id`. `_get_recovery_states()` supports 4 query paths (both filters, component-only, asset-only, none). Fixed `_mark_rolled_back()` to set `rollback_available = false` (was missing, causing rolled-back states to reappear as available).
- **Modified**: `src/citadel_archer/api/panic_routes.py` — `RollbackRequest` model accepts `target_assets: Optional[List[str]]`, passed to manager, included in audit log details.
- **No changes to action handlers**: Asset info flows through the `recovery_state` dict with injected `'asset'` alias — action handlers read `recovery_state.get('asset', 'local')` without signature changes.
- **Test coverage**: 29 tests in `tests/test_per_asset_rollback.py` across 9 classes covering: schema correctness (4), state isolation across assets (2), rollback filtering (6), mark-rolled-back semantics (3), schema migration (2), API model validation (3), manager state persistence (3), rollback orchestration including partial failure (5), result key format (1).

---

### v0.3.8 (2026-02-15) - SQLite WAL Mode: Central Connection Utility
**Status**: Complete - Phase 2 Hardening item: all databases use WAL for concurrent access

**Changes**:
- **Central SQLite connect utility**: `core/db.py` provides `connect()` function that sets WAL journal mode, `busy_timeout=5000`, and `foreign_keys=ON` on every connection. Replaces 30+ scattered `sqlite3.connect()` calls across 8 database modules.
- **New file**: `src/citadel_archer/core/db.py` (~40 lines) — `connect(db_path, *, row_factory=False, check_same_thread=True)`. Every database connection now gets consistent PRAGMAs.
- **Migrated modules (7)**: `remote/shield_database.py` (refactored, already had WAL), `chat/agent_registry.py` (refactored, already had WAL), `panic/panic_database.py` (15 call sites migrated, adds WAL), `panic/recovery_key.py` (4 helpers migrated), `intel/store.py` (adds WAL), `intel/assets.py` (adds WAL), `chat/chat_store.py` (adds WAL).
- **Inline WAL**: `vault/vault_manager.py` (WAL after PRAGMA key for SQLCipher compat), `agent/shield.py` (standalone single-file, cannot import from package).
- **FK enforcement fix**: `panic/panic_database.py` `cleanup_old_sessions()` now deletes child rows (action_logs, recovery_snapshots, panic_logs, recovery_states, credential_rotations) before parent sessions — required because `foreign_keys=ON` is now enforced on all connections.
- **Modified**: `core/__init__.py` (exports `db_connect`).
- **Test coverage**: 22 tests in `tests/test_sqlite_wal.py` across 5 classes covering: CoreDBConnect utility (9 PRAGMAs, paths, thread safety), ExistingDBsWALMode (7 per-module integration tests including vault), ShieldAgentWAL (1 inline WAL), ConcurrentAccess (3 tests: read-during-write, busy_timeout, multiple readers), WALPersistence (2 tests: cross-connection persistence, sidecar files).
- **Code review fixes**: vault_manager.py added to migration (inline WAL after PRAGMA key), cleanup_old_sessions FK-safe cascade delete, shield.py foreign_keys=ON for consistency, intel/store.py defensive foreign_keys re-assert after executescript.

---

### v0.3.7 (2026-02-15) - SCS Rate Limiting: Per-Participant Token Quotas
**Status**: Complete - Phase 2 Hardening item: prevents budget exhaustion by any single participant

**Changes**:
- **SCS token quota tracker implemented**: `SCSQuotaTracker` enforces per-participant rolling-window (1-hour) token budgets. Two-phase design: pre-call `estimate_tokens()` + `check()` gates the call; post-call `record()` tracks actual consumption. Prevents any single source (user, external agent, system escalation) from exhausting the Claude API budget.
- **New file**: `src/citadel_archer/chat/scs_quota.py` — `TokenEntry` dataclass, `SCSQuotaTracker` class with: participant resolution (`user` → 200K/hr, `ext-agent:*` → 50K/hr, `citadel` → 500K/hr), sliding window eviction, per-participant isolation, per-ID quota overrides, conservative token estimation (0.3 tok/char + 2K overhead, capped at 4K), `get_all_usage()` for REST endpoint, thread-safe singleton (double-checked locking).
- **Modified**: `src/citadel_archer/chat/ai_bridge.py` — Pre-call quota gate in `_on_message()` (estimate + check + graceful rejection with system message), post-call recording in `_call_with_tools()` (record actual tokens after `audit.finish_call`), tool-loop re-check before each iteration (prevents multi-tool messages from overshooting quota), `participant_id` parameter threaded from `_process()`.
- **New file**: `src/citadel_archer/api/scs_quota_routes.py` — `GET /api/scs-quota` (session-token protected), returns `{participants, defaults, window_seconds}`.
- **Modified**: `src/citadel_archer/api/main.py` — Router registration for scs_quota_routes.
- **Test coverage**: 33 tests in `tests/test_scs_quota.py` across 11 classes covering: participant resolution (4), quota check boundary cases (6), token recording + defensive guards (3), sliding window eviction with time mocking (2), per-participant isolation (2), quota overrides per-type and per-ID (2), token estimation clamping (5), reset operations (3), get_all_usage + default types (2), singleton (1), REST endpoint auth + data + usage reflection (3).
- **Code review fixes**: Tool-loop quota re-check before each iteration (prevents 6x estimate overshoot), direct await with try/except for rate-limit notification (was fire-and-forget `create_task`), clarifying comment on fallback quota.

---

### v0.3.6 (2026-02-15) - Append-Only AI Audit Log
**Status**: Complete - Phase 2 Hardening item: immutable Claude API call tracking

**Changes**:
- **AI Audit Log implemented**: `AIAuditLogger` records every Claude API call to `data/ai_audit.log` (JSON lines). Tracks: call_id, timestamp, trigger_type (user_text/agent_text/citadel_event/tool_loop), model, input/output/total tokens, stop_reason, tool_calls, duration_ms, response_preview (200 chars), error, iteration. Separate from `core/audit_log.py` (security events) — this is API-call-level cost/debugging accountability.
- **New file**: `src/citadel_archer/chat/ai_audit.py` — `AICallRecord` dataclass (14 fields), `AIAuditLogger` class with context-pair pattern (`start_call` → API → `finish_call`), `RotatingFileHandler` (5MB, 5 backups) with `propagate=False` for structlog isolation, thread-safe in-memory aggregates (total_calls, tokens, errors), `query_recent(limit)` with deque tail-read and rotation backup fallback, `get_ai_audit_logger()` thread-safe singleton (double-checked locking).
- **Modified**: `src/citadel_archer/chat/ai_bridge.py` — Trigger type detection in `_process()` (user_text/agent_text/citadel_event), both API call sites in `_call_with_tools()` wrapped with start/finish audit lifecycle, tool-loop iterations tracked with `trigger_type="tool_loop"` and `iteration=N`, inner try/except re-raises so error path is always logged.
- **New file**: `src/citadel_archer/api/ai_audit_routes.py` — `GET /api/ai-audit?limit=50` (session-token protected), returns `{records, aggregates}`.
- **Modified**: `src/citadel_archer/api/main.py` — Router registration for ai_audit_routes.
- **Test coverage**: 41 tests in `tests/test_ai_audit.py` across 11 classes covering: AICallRecord fields (5), aggregates + thread safety (4), file logging (4), query_recent + rotation + corrupt lines (5), defensive error handling (4), singleton (2), trigger types (4), tool call extraction (4), duration (2), AI bridge integration (3), REST endpoint auth + validation (4).
- **Code review fixes**: Thread-safe singleton with double-checked locking, `itertools.count` for atomic logger name counter (prevents stale handler reuse after GC), file write + aggregate updates inside same lock for consistency, `deque(maxlen)` for O(limit) memory in `query_recent`, rotation backup fallback (`ai_audit.log.1`).

---

### v0.3.5 (2026-02-14) - Trigger 3c: Threshold Breach Detection
**Status**: Complete - All 8 AI triggers implemented across 3 categories

**Changes**:
- **Trigger 3c implemented**: `ThresholdEngine` subscribes to EventAggregator and monitors event patterns against configurable threshold rules (COUNT and CORRELATION). When thresholds are breached, escalates summary to SecureChat → AI Bridge for analysis. Level 2 escalation — pure automation, no tokens consumed until breach promotes to SCS.
- **New file**: `src/citadel_archer/chat/threshold_engine.py` — Data models (RuleType, CorrelationCondition, ThresholdRule, BreachRecord), 6 default rules (SSH brute force, critical file burst, vault unlock failures, network block surge, suspicious process cluster, coordinated attack correlation), ThresholdEngine class with hybrid evaluation (COUNT checked per-event, CORRELATION checked every 30s in sweep loop), per-rule cooldown, dedup, rate limiting (15/hr), breach buffer with send-failure re-queue, periodic stale entry eviction.
- **Wired in**: `src/citadel_archer/api/main.py` startup/shutdown hooks (after StartupCatchup).
- **Test coverage**: 53 tests in `tests/test_threshold_engine.py` across 12 classes covering COUNT rule basics, filtering, group-by-asset, cooldown, dedup + rate limiting, CORRELATION rules, breach summary format, flush behavior, lifecycle, end-to-end flow, default rules validation, and helper functions.
- **Code review fixes**: Thread-unsafe access to `_cooldowns`/`_breach_dedup` dicts protected with `_counter_lock`, `asyncio.get_event_loop()` → `asyncio.get_running_loop()`, periodic `_evict_stale_entries()` added to sweep loop for unbounded dict growth prevention.
- **AI trigger model complete**: All 8 triggers across 3 categories now implemented (1a, 1b, 2a, 2b, 2c, 3a, 3b, 3c).

---

### v0.3.4 (2026-02-14) - Trigger 3b: Startup Catch-Up
**Status**: Complete - App startup now includes AI security briefing

**Changes**:
- **Trigger 3b implemented**: `StartupCatchup` one-shot async task runs once at startup (30s delay), queries audit log for most recent `SYSTEM_STOP` to determine offline window, gathers events from audit log + Remote Shield DB + asset inventory, sends summary to SecureChat → AI Bridge for proactive analysis.
- **New file**: `src/citadel_archer/chat/startup_catchup.py` — StartupCatchup class with offline window detection, multi-source data gathering (each independently try/excepted), severity-aware summary formatting, AI Bridge trigger keywords.
- **Wired in**: `src/citadel_archer/api/main.py` startup hook (after PostureAnalyzer).
- **Test coverage**: 40 tests in `tests/test_startup_catchup.py` covering lifecycle, offline window detection (SYSTEM_STOP found/missing/naive timestamps, max lookback cap, skip < 5min), data gathering (all sources/missing/failing), summary format (prefix, trigger keywords, severity counts), chat failure resilience, `_format_duration` helper.
- **Code review fixes**: ISO string comparison replaced with proper `_parse_ts()` datetime parsing for tz-aware/naive timestamp compatibility, `_severity_label()` helper for numeric-to-label severity mapping, naive timestamp edge case tests added.
- **Category 3 progress**: 3a (daily posture) + 3b (startup catch-up) implemented. Only 3c (threshold breach) remains.

---

### v0.3.3 (2026-02-14) - Trigger 1b: External AI Agent REST API
**Status**: Complete - Multi-AI collaboration enabled via REST API

**Changes**:
- **Trigger 1b implemented**: External AI agents (Forge, OpenClaw, Claude Code) can register and send messages into SecureChat via REST API, triggering AI Brain analysis for collaborative defense.
- **New file**: `src/citadel_archer/chat/agent_registry.py` — SQLite-backed agent registry with SHA-256 token hashing, WAL journal, `data/agent_registry.db`. CRUD operations, token rotation, message stats tracking.
- **New file**: `src/citadel_archer/chat/agent_rate_limiter.py` — In-memory sliding window rate limiter (60s window, per-agent limits).
- **New file**: `src/citadel_archer/api/agent_api_routes.py` — REST endpoints: `POST /register` (admin), `POST /send` (agent Bearer auth), `GET /` (admin list), `DELETE /{agent_id}` (admin revoke), `POST /{agent_id}/rotate-token` (admin). Dual auth model: session token for admin ops, Bearer token for agent API.
- **Modified**: `src/citadel_archer/chat/ai_bridge.py` — Added `ext-agent:* + TEXT → needs_ai = True` trigger and `ExtAgent` history label.
- **Modified**: `src/citadel_archer/api/chat_routes.py` — Active external agents appear in `/api/chat/participants` list.
- **Modified**: `src/citadel_archer/api/main.py` — Router registration for agent API endpoints.
- **Test coverage**: 71 tests across 4 files — `test_agent_registry.py` (29 tests: DB init, CRUD, token security, rotation, persistence, message stats), `test_agent_rate_limiter.py` (9 tests: behavior, sliding window, isolation, reset), `test_agent_api_routes.py` (27 tests: register, send, rate limit, revoke, list, delete, rotate, participants), `test_ai_bridge_ext_agent.py` (9 tests: trigger, regression, history labels).
- **Code review fixes**: Audit logging corrected (`log_security_event` + `EventType.AI_DECISION`), token rotation blocked on revoked agents (`AND status = 'active'`), `datetime.utcnow()` → `datetime.now(timezone.utc)`, UUID truncation removed (full 128-bit IDs).
- **Category 1 complete**: Both SecureChat message triggers (1a user TEXT, 1b external AI agent) now reach the AI.

---

### v0.3.2 (2026-02-14) - Trigger 3a: Scheduled Daily Security Posture Analysis
**Status**: Active - First Category 3 (App-Initiated Processing) trigger implemented

**Changes**:
- **Trigger 3a implemented**: `PostureAnalyzer` background async task runs every 24h (configurable), gathers data from 5 optional sources (EventAggregator, AssetInventory, RemoteShieldDatabase, AnomalyDetector), formats a structured summary, sends to SecureChat → AI Bridge for proactive analysis.
- **New file**: `src/citadel_archer/chat/posture_analyzer.py` — PostureAnalyzer class with start/stop/run_now lifecycle, graceful degradation (each source independent), `_is_recent()` helper with full timezone safety.
- **Wired in**: `src/citadel_archer/api/main.py` startup + shutdown hooks.
- **Test coverage**: 41 tests in `tests/test_posture_analyzer.py` covering lifecycle, loop scheduling, data gathering (all/missing/failing sources), summary format, AI Bridge trigger keywords, chat failure resilience, `_is_recent` edge cases (None, empty, tz-aware/naive).
- **Code review fixes**: Type annotation corrected (`Optional[str]`), timezone normalization for tz-aware callers, narrowed startup exception handling, shutdown safety wrapper, loop scheduling tests added.

---

### v0.3.1 (2026-02-14) - Trigger 2c: Panic Room → AI Triage
**Status**: Complete

**Changes**:
- **Trigger 2c implemented**: Panic Room activation, completion, and failure now escalate to SecureChat → AI Bridge. Three lifecycle points: activation (immediate triage guidance), completion (confirmation), failure (intervention recommendation).
- **Modified**: `src/citadel_archer/panic/panic_manager.py` — `set_chat_manager()` injection, filled `_notify_completion()` and `_notify_failure()` stubs with ChatManager escalation + defensive error handling.
- **Modified**: `src/citadel_archer/api/panic_routes.py` — activation escalation in both v1 and v2 endpoints, non-blocking (chat failure never blocks panic ops).
- **Wired in**: `src/citadel_archer/api/main.py` startup (ChatManager → PanicManager via setter injection).
- **Test coverage**: 26 tests in `tests/test_panic_escalation.py` covering completion, failure, graceful degradation, summary format, activation, non-string errors, and set_chat_manager lifecycle.
- **Category 2 complete**: All critical threat escalation paths (2a remote agents, 2b local Guardian, 2c Panic Room) now reach the AI.

---

### v0.3.0 (2026-02-14) - Trigger 2b: Local Guardian → AI Escalation
**Status**: Complete

**Changes**:
- **Trigger 2b implemented**: `GuardianEscalation` class subscribes to EventAggregator, filters ALERT/CRITICAL from FILE/PROCESS, batches in 30s windows, deduplicates within 5-min windows, rate-limits to 10/hr, bridges sync→async, sends summary to SecureChat as EVENT type that triggers AI Bridge analysis.
- **New file**: `src/citadel_archer/chat/guardian_escalation.py` (~230 lines)
- **Wired in**: `src/citadel_archer/api/main.py` startup/shutdown
- **Test coverage**: 41 tests in `tests/test_guardian_escalation.py` covering severity filtering, category filtering, dedup, dedup cache eviction, rate limiting, batch aggregation, summary format, send failure re-queue, lifecycle, and concurrency.
- **Trigger model updated**: 2b status changed from "Gap" to "Implemented" in AI Bridge trigger table and roadmap.

**Rationale**:
Guardian sensors detect threats locally but the AI never knew about them — critical events only appeared as dashboard chart data points. This closes the gap where a rootkit detection or suspicious process would go unanalyzed by the AI Brain.

---

### v0.2.9 (2026-02-13) - Codebase Audit, PRD Accuracy Pass & Duplicate Cleanup
**Status**: Active - Comprehensive audit of PRD claims against actual implementation

**Changes — Accuracy Pass**:
- **Phase 1 checkmarks updated**: 5 of 6 items verified as implemented and marked `[x]` with implementation details (file paths, specific capabilities). Browser extension scan remains `[ ]` (not yet implemented).
- **Phase 2 Intelligence Layer checkmarks updated**: 3 items changed from `[ ]` to `[x]` — anomaly detection (context engine + Isolation Forest + threat scorer), automatic Guardian signature updates (hot-reload rule generation from IOC/TTP/CVE), advanced UI (Chart.js + D3.js + risk gauges + WebSocket real-time). 2 items marked `[~]` (partial) — Intel module (only OTX fetcher of 4 planned feeds), Watchtower (asset inventory exists, no cross-asset correlation).
- **Phase 3 checkmarks updated**: 8 of 8 items verified as implemented and marked `[x]` with implementation details. Phase 3 complete.
- **GUI framework corrected**: pywebview claim replaced with actual implementation — Microsoft Edge app mode (`msedge.exe --app=URL`). Updated in Technology Stack, Dashboard Technical Approach, and Decided Architecture.
- **Session authentication documented**: 256-bit tokens via `secrets.token_urlsafe`, X-Session-Token header, constant-time comparison. Added to Technology Stack, Security section, and Decided Architecture.
- **Backend Services rewritten**: Replaced generic/inaccurate descriptions with actual module paths and capabilities for all 7 backend subsystems.
- **Watchtower technical approach expanded**: From 4 generic lines to 7 specific modules with file paths (event_aggregator, anomaly_detector, threat_scorer, context_engine, guardian_updater, chart_data, alert_timeline, risk_metrics, asset_view).
- **Anomaly detection ML documented**: scikit-learn Isolation Forest with Z-score fallback, 5-feature vector, sensitivity presets, cold-start protection. Previously claimed "no ML dependencies" — corrected.
- **DB path inconsistency flagged**: SecureChat/Vault use `data/` (relative), but Panic Room uses `/var/lib/citadel/panic/` and Intel uses `/var/citadel/` (absolute system paths). Documented as known issue in Decided Architecture with normalization target.
- **Roadmap legend added**: `[x]` = implemented, `[~]` = partially implemented, `[ ]` = not yet implemented.

**Changes — Duplicate & Gap Cleanup**:
- **Decided Architecture #5/#13 duplicate resolved**: #5 (Two-Tier Communication Model) was identical to #13 (Communication Tiers). #5 now points to #13.
- **Guardian Technical Approach updated**: Replaced outdated "pywin32" and "Local ML model" claims with actual implementation (watchdog, psutil, anomaly detection in Watchtower pipeline).
- **Intel Technical Approach updated**: Replaced aspirational claims ("Local LLM", "community intel") with actual implementation (OTX fetcher, aggregator, dedup, scheduling). Planned items now clearly marked.
- **Vault Technical Approach updated**: Expanded from generic 4-line description to actual implementation details (AES-256-GCM per-entry, PBKDF2 600k iterations, rate-limited unlock, SSH credential type).
- **Panic Room Technical Approach updated**: Expanded from generic 5-line description to actual action framework architecture (base class lifecycle, playbook engine, specific action modules with file paths).
- **AI Tool Access sections clarified**: Added cross-reference between implemented tools (AI Bridge → Tool Model) and full vision tools (AI Tool Access).
- **Security section updated**: Added session authentication details, actual encryption specs, file paths. Previously was 5 generic bullets.
- **Browser Extension sections consolidated**: Reduced overlap between Guardian module and Security Considerations — Security section now cross-references Guardian for details.
- **v0.2.3 changelog pywebview note**: Added clarifying note that GUI framework changed in v0.2.8.
- **Phase 2 scope clarified**: Always-On Protection, AI Trigger Expansion, and Hardening sub-sections now note they are "designed here, implemented in later phases" to explain why they're in Phase 2 but unchecked.

**Sections Updated**:
- Core Modules → Guardian, Watchtower, Panic Room, Vault, Intel (all Technical Approach sections)
- Technology Stack → Security (expanded from generic to actual implementation)
- AI-Centric Architecture → AI Tool Access (cross-reference to implemented tools)
- Security Considerations → Browser Extension Attack Surface (consolidated with cross-ref)
- Development Roadmap → Phase 2 (scope clarification on unimplemented sub-sections)
- Decided Architecture (#5 merged into #13, added #20-23)
- Version History → v0.2.3 (pywebview historical note)

**Rationale**:
The PRD had drifted from reality — features were implemented but unchecked, technical claims were outdated (pywebview, pywin32, no ML), module descriptions were generic/aspirational, and duplicate content had accumulated across versions. This pass aligns every Technical Approach section with the actual codebase, eliminates content duplication, and makes the document reliable for development use.

---

### v0.2.8 (2026-02-13) - Token Minimization, Hardening & Escalation Hierarchy
**Status**: Active - Architectural hardening and efficiency pass

**Changes**:
- **Token minimization as core design principle**: Resolve at the lowest automation level possible before escalating to AI. Tripwire rules first (no tokens), threshold engine second (no tokens), AI analysis third (tokens), human decision fourth (rare). AI is the last resort, not the first responder.
- **Escalation hierarchy (4 levels)**:
  - Level 1: Tripwire rules — pattern match → auto-action (block, kill, quarantine). No tokens.
  - Level 2: Threshold/correlation engine — aggregate patterns across sensors and time, dedup same attack from multiple agents, breach threshold triggers escalation. No tokens.
  - Level 3: AI analysis — AI Bridge invoked with full context, decides and acts within security level, responds via SCS. Uses tokens.
  - Level 4: Human decision — rare (<5%), only when ambiguous + high impact. User reached via SecureChat, Claude Code, or Forge via Telegram.
- **Forge/Telegram notification channel**: Forge (the user's AI assistant) can reach the user at any time via Telegram — this is the out-of-band notification path when the user isn't at the computer.
- **Three remote interaction paths**: When away from the computer, the user can interact via: (1) Forge through Telegram, (2) Claude Code via SSH, (3) SecureChat browser client (future).
- **Threshold/correlation engine**: New component between ACS and SCS that watches automation data for patterns, deduplicates same-attack events from multiple agents, and escalates to SCS only when thresholds are breached (Trigger 3c).
- **Heartbeat HMAC authentication**: All mesh heartbeats must be HMAC-signed with pre-shared keys to prevent spoofing by compromised nodes.
- **SCS API rate limiting**: Rate-limited API tokens for each participant to prevent abuse or compromised agents flooding the chat.
- **Append-only audit log**: All AI tool invocations logged to an immutable, append-only audit trail separate from securechat.db.
- **SQLite WAL mode**: Shared event store between citadel-service (writer) and citadel-archer (reader) requires WAL mode for concurrent access.
- **Escalation deduplication**: Multiple agents detecting the same attack (e.g., distributed brute force) are correlated before a single SCS escalation is generated.
- **Recovery/reconciliation protocol**: When desktop comes back online after being dark — sync missed events, merge secondary brain decisions, desktop resumes control.
- **Secondary brain hardening**: The designated secondary VPS is a high-value target and requires additional hardening (restricted SSH, fail2ban, separate credentials, encrypted API key storage).
- **Panic Room connections**: Panic Room now properly connected to Vault (credentials), SCS (triage guidance), and remote agents (remote actions).

**Sections Updated**:
- Core Modules → SecureChat (added token minimization, Forge/Telegram, escalation hierarchy, threshold engine)
- AI-Centric Architecture → AI Bridge (added escalation hierarchy levels, threshold engine as trigger 3c source)
- Always-On Protection (added SQLite WAL mode, heartbeat HMAC)
- Distributed Resilience / Defense Mesh (added HMAC auth, recovery protocol, secondary brain hardening, escalation dedup)
- Decided Architecture (added 4 new locked decisions)
- Development Roadmap (added threshold engine, audit log, rate limiting items)
- Architecture Diagram (updated to v0.2.8 with all fixes)

**Rationale**:
1. **Tokens cost money and add latency**: Every AI invocation uses tokens. The system should resolve as much as possible through automation before involving the AI. This is both cost-efficient and faster.
2. **The user isn't always at the computer**: Forge via Telegram is the out-of-band channel. The architecture must support remote interaction without the dashboard open.
3. **Unauth'd heartbeats are dangerous**: A compromised node could spoof heartbeats to make the mesh think all nodes are healthy. HMAC prevents this.
4. **AI actions need accountability**: Chat messages are mutable (editable, deletable). AI tool invocations need an immutable audit trail.
5. **Same attack, multiple agents**: Without dedup, a distributed brute force across 5 agents generates 5 escalations instead of 1 correlated summary.

---

### v0.2.7 (2026-02-13) - Always-On Protection, Defense Mesh & Multi-AI Architecture
**Status**: Active - Major architectural expansion

**Changes**:
- **Formalized two-tier communication model** with official terminology:
  - **Automation Communication System (ACS)**: Low-level sensor data, heartbeats, metrics, routine alerts — no AI, no tokens. Handles all routine automation between sensors and the dashboard.
  - **SecureChat System (SCS)**: High-level command channel used by humans AND AI agents — the user, Claude Code instances on each machine, OpenClaw agents, the user's AI assistant "Forge", and future AI participants. Uses tokens when AI is involved.
- **Multi-AI agent participation in SecureChat**: SecureChat is NOT just one in-process AI Bridge calling Claude API. It is the communication backbone for multiple AI agent types across multiple devices:
  - Claude Code instances installed on each machine
  - OpenClaw agents (external AI agents)
  - "Forge" (the user's personal AI assistant)
  - Future: any authenticated AI participant
- **Always-On Protection architecture**: Desktop app split into two components:
  - `citadel-service` (Windows Service / systemd on Linux): Guardian sensors, event store, tripwire rules, heartbeat emitter — runs 24/7 even when user is logged out
  - `citadel-archer` (Desktop app): Dashboard UI, SecureChat, AI Bridge, Vault — user-facing, launched on demand
- **Distributed Resilience / Defense Mesh**: Multi-node coordination protocol where each node (desktop + VPS agents) monitors the others:
  - Mutual heartbeat monitoring (each node watches its peers)
  - Peer alerting (VPS1 tells VPS2 "Desktop coordinator is down")
  - Autonomous escalation (agents enter heightened defense mode when coordinator goes dark)
  - Compartmentalized secrets (each node only has credentials it needs)
  - Secondary brain designation (fallback coordinator if primary is compromised)
- **Complete AI trigger model** expanded from 2 to 8 subtypes across 3 categories:
  - Category 1 (SecureChat message): 1a user TEXT (implemented), 1b external AI agent via API (implemented)
  - Category 2 (Critical threats): 2a remote agent events (implemented), 2b local Guardian events (implemented), 2c Panic Room activation (implemented)
  - Category 3 (App processing): 3a scheduled analysis (implemented), 3b startup catch-up (implemented), 3c threshold breach (implemented)

**Sections Updated**:
- Core Modules → SecureChat (formalized ACS/SCS terminology, added multi-AI participant model)
- AI-Centric Architecture → Architecture Diagram (updated for two named tiers, multi-AI, defense mesh)
- AI-Centric Architecture → AI Bridge (expanded trigger model to 8 subtypes)
- NEW: Always-On Protection (Windows Service architecture)
- NEW: Distributed Resilience / Defense Mesh
- Decided Architecture (added 3 new locked decisions)
- Development Roadmap → Phase 2 (added always-on service items)
- Development Roadmap → Phase 5 (added defense mesh items)

**Rationale**:
1. **Protection stops when the app closes**: VPS agents run as systemd services (always on), but the desktop has zero protection when Citadel Archer is closed. A Windows Service solves this.
2. **Hub-and-spoke is a single point of failure**: If the desktop coordinator is compromised, all coordination stops. Defense mesh gives each node autonomous capability and peer awareness.
3. **Multiple AI brains, not one**: The user has Claude Code on each machine, OpenClaw agents, and "Forge." These are all SecureChat participants, not just the single in-process AI Bridge. The architecture must support multi-AI coordination.
4. **Communication clarity**: "High-level" and "Low-level" were ambiguous. "Automation Communication System" and "SecureChat System" are precise, descriptive names that the team can reference unambiguously.

---

### v0.2.6 (2026-02-13) - SecureChat as Foundational Infrastructure
**Status**: Active - Architectural repositioning of SecureChat

**Changes**:
- **SecureChat repositioned from Phase 4 "chat with friends" to foundational communication layer** — it is the encrypted backbone for all command-level communication between the user, AI assistant, and system
- **Hybrid Communication Model**: Two tiers of communication formally defined:
  - **SecureChat (High-Level)**: AI-assisted, uses tokens — user commands, strategic decisions, escalations, onboarding, deployment conversations
  - **Existing System API Routes (Low-Level)**: No AI, no tokens — sensor data, heartbeats, routine alerts, metric collection, all existing EventAggregator flows
- **Always-visible chat sidebar**: SecureChat lives as a permanent sidebar in the dashboard, not a tab — independent of tab-loader lifecycle
- **VPS onboarding through chat**: "add vps <ip>" command flow — key generation, authorization, verification, asset registration, agent deployment — all through conversational commands
- **Citadel Shield agent**: Lightweight Python daemon deployed to VPS via SSH — monitors auth.log, processes, cron, file integrity with autonomous tripwire actions
- **Background event sync**: AgentPoller pulls events from agents via SSH (low-level), escalates critical events to SecureChat (high-level)
- **AI Bridge** (`chat/ai_bridge.py`): Connects the AI Brain (Claude API) to SecureChat — listens for user questions and agent escalations, builds context (chat history + system state), calls Claude with tools (get_system_status, get_asset_list, get_agent_events, deploy_agent), routes responses back as "assistant" messages. Gracefully degrades if no API key is configured.
- **Trigger model**: AI is only invoked for command-level attention (user TEXT, critical escalations). Routine data stays in system-level routes. ~10-30 API calls/day for typical usage.
- **Tool model**: AI has read-only tools (all levels) + action tools gated by security level (Guardian/Sentinel)

**Sections Updated**:
- Core Modules → SecureChat (complete rewrite — from "chat with friends" to system communication backbone)
- Development Roadmap → Phase 2 (SecureChat foundation + VPS agent pipeline added)
- Development Roadmap → Phase 4 (SecureChat removed, repurposed for advanced communication features)
- AI-Centric Architecture → Architecture Diagram (updated to show SecureChat sidebar, AI Bridge, Remote Shield, communication tiers)
- AI-Centric Architecture → AI Bridge (new section — trigger model, context building, tool model, invocation patterns)
- Decided Architecture (added SecureChat hybrid model decision)

**Rationale**:
1. **SecureChat was mispositioned**: Originally described as "chat with friends" in Phase 4. In reality, it is the foundational communication layer through which the user, AI, and system coordinate.
2. **Two tiers are critical**: The existing app routes handle routine automation (no AI needed). SecureChat handles command-level attention (user decisions, AI reasoning, setup conversations). Both are essential — they serve different purposes.
3. **VPS servers are unprotected NOW**: The user has live VPS instances with no monitoring. SecureChat enables immediate onboarding and agent deployment.
4. **Conversational setup is natural**: Typing "add vps 154.49.137.24" in the chat is simpler than navigating forms. The AI guides the user through each step.

---

### v0.2.5 (2026-02-11) - Asset Management & Remote Execution Gap Fix
**Status**: Active - Critical architectural gap identified and planned

**Changes**:
- **Asset Management Addendum**: Comprehensive plan to close the gap between Assets, Remote Shield, Vault, and Panic Room
- **Asset DB Persistence**: `AssetInventory` to be backed by SQLite (currently in-memory only, data lost on restart)
- **Asset CRUD API**: New `POST/PUT/DELETE /api/assets` endpoints (currently no way to create assets from frontend)
- **Remote Shield Auto-Linking**: Agents auto-create/link managed assets on registration
- **Vault SSH Credentials**: New `ssh` credential category for storing SSH keys with structured metadata
- **SSH Connection Manager**: New `remote/ssh_manager.py` module using asyncssh for remote command execution
- **Panic Room Remote Scope**: Asset scope selector — choose which assets panic playbooks target
- **Remote Credential Rotation**: Rotate SSH keys on remote assets via SSH (not just localhost)

**Addendum Document**: [ASSET_MANAGEMENT_ADDENDUM.md](ASSET_MANAGEMENT_ADDENDUM.md)

**Sections Updated**:
- Development Roadmap → Phase 2 (added asset persistence, CRUD API, Remote Shield persistence)
- Development Roadmap → Phase 3 (added asset scope selector, remote execution)
- Core Modules → Dashboard (acknowledged asset management gap)

**Rationale**:
1. **Panic Room is local-only**: Credential rotation only affects `~/.ssh/authorized_keys` on the server running Citadel. Remote VPS instances are unprotected.
2. **Assets have no persistence**: The in-memory `AssetInventory` loses all data on restart and has no frontend CRUD.
3. **Remote Shield is disconnected**: Agents register and report threats but don't create Asset records and can't receive commands.
4. **No SSH management**: There is no way to execute commands on remote servers — the fundamental capability needed for remote panic operations.
5. **Vault doesn't store SSH credentials**: SSH keys for managed hosts have nowhere to live securely.

---

### v0.2.4 (2026-02-07) - Browser Extension Protection (Attack Surface Defense)
**Status**: Active - New Guardian capability added

**Changes**:
- ✅ **Browser Extension Detection & Protection**: Guardian now defends against unauthorized browser extensions injecting code into protected pages
- ✅ **Real-world motivation**: Discovered 14 unauthorized extensions silently installed in Microsoft Edge (never installed by user, never used Edge) — including "Mano" AI extension that injects content scripts on ALL URLs, reads Gmail data, and admits to keystroke logging
- ✅ **Cross-browser scope**: Protects against extensions in Chrome, Edge, Firefox, and any Chromium-based browser
- ✅ **Dashboard integration**: Extension threat alerts appear in Guardian status and event log

**Sections Updated**:
- Guardian Module → Browser Extension Protection (expanded from single bullet to full sub-section)
- Security Considerations → Threat Model (added browser extension threat class)
- Security Considerations → Browser Extension Attack Surface (new section)

**Rationale**:
1. **Real attack vector**: Browser extensions have `<all_urls>` permissions, can inject JavaScript into any page including localhost/security dashboards
2. **Silent installation**: Software bundlers (Norton, OEM bloatware) silently sideload extensions into Edge/Chrome without user consent
3. **Keystroke logging**: Extensions can capture keystrokes, read page DOM, exfiltrate data — directly undermining Citadel Archer's protection
4. **Supply chain risk**: Extension updates can introduce malicious behavior after initial install (extensions auto-update silently)
5. **Cross-browser leakage**: Edge on Windows can intercept localhost URLs even when Chrome is the default browser

---

### v0.2.3 (2026-02-02) - Vanilla JS Over React (Security-First Frontend)
**Status**: Active - Frontend architecture simplified

**Changes**:
- ✅ **Replaced React with Vanilla JS + Web Components**: Simpler, more secure, smaller attack surface
- ✅ **Rationale**: For a security-focused desktop app, fewer dependencies = more auditable code
- ✅ **Still Modern**: ES6 modules, Web Components, Shadow DOM, Tailwind CSS
- ✅ **No Build Complexity**: Direct deployment, faster cold start, no npm ecosystem risk

**Sections Updated**:
- Technical Architecture → Technology Stack (Frontend)

**Rationale**:
1. **Security**: React apps have 1000+ npm dependencies (supply chain risk). Vanilla JS has near-zero external dependencies.
2. **Simplicity**: No Babel, Webpack, JSX transforms. Just HTML/CSS/JS that users can audit.
3. **Performance**: No virtual DOM overhead. Direct DOM manipulation in pywebview.
4. **Appropriate**: Our Phase 1 UI is simple (status dashboard, process list, event log). React is overkill.
5. **Desktop Context**: No SSR, no code splitting, no SEO. Browser APIs (WebSocket, Fetch) are sufficient.

For a proprietary security product where users need to trust the code, minimal dependencies is a feature, not a limitation.

> *Note: This changelog originally referenced pywebview. The GUI framework was later changed to Edge app mode in v0.2.8.*

---

### v0.2.2 (2026-02-01) - Proactive Protection (ACT, Don't Ask)
**Status**: Active - Critical UX principle added

**Changes**:
- ✅ **PROACTIVE PROTECTION**: AI acts FIRST, informs AFTER (not ask before)
- ✅ **Minimize User Questions**: Questions are RARE, only for truly ambiguous AND important situations
- ✅ **Default to Autonomous Action**: Within security level, AI decides and acts immediately

**Key Principle**:
> "If we're asking the user 'Should I block this malware?' we've already failed.
> ACT proactively, then INFORM. Don't ASK unless absolutely necessary."

**Rationale**: Target users are NOT security experts. They don't know if "update.exe connecting to 185.220.101.42" is dangerous. By the time they decide, damage could be done. AI must act autonomously (within security level), then explain what it did and why.

---

### v0.2.1 (2026-02-01) - UX Clarity for Non-Technical Users
**Status**: Active - UX principles clarified

**Changes**:
- ✅ **Added Progressive Disclosure UX Principle**: Simple view by default, advanced details on-demand
- ✅ **AI as Expert Advisor**: AI explains threats in plain language ("This is normal" vs "This needs attention NOW")
- ✅ **Prevent Alert Panic**: Users rely on AI to distinguish serious threats from normal activity

**Sections Updated**:
- Core Philosophy (added "Accessible to Non-Experts")
- User Experience (added Progressive Disclosure section)
- Dashboard UX (simplified primary view, advanced drill-down)
- AI Communication guidelines

**Rationale**: Most users aren't security experts. They'll see alerts and panic unless the AI guides them with clear, calm explanations. Security tools that overwhelm users with technical jargon create alert fatigue and get disabled.

---

### v0.2.0 (2026-02-01) - VPS Protection Prioritized
**Status**: Active - Updated roadmap

**Changes**:
- ✅ **Moved Remote Shield (VPS) from Phase 5 → Phase 2** (Months 4-6 instead of 13-15)
- ✅ **Rationale**: VPS protection is a core use case, not a late addition. User experiences VPS compromises within days and needs rapid defense capability.
- ✅ **Phase 2 Now Includes**: Intel module + AI threat analysis + Remote Shield VPS agent
- ✅ **Phase 5 Adjusted**: Focus shifts to family computer protection and multi-system orchestration

**Sections Updated**:
- Development Roadmap (Phase 2 and Phase 5)
- Platform Support timeline (Ubuntu moved to Phase 2)

**Rationale**: VPS management is first-class, not second-class. Moving it to Phase 2 ensures:
1. User gets end-to-end protection (local + VPS) within 6 months
2. Intelligence layer (Phase 2) benefits both local and remote systems simultaneously
3. Remote Shield gets proper development time, not rushed
4. Aligns with user's primary use case (protecting VPS from rapid compromise)

---

### v0.1.0 (2026-02-01) - Initial PRD
**Status**: Active - This is our locked baseline

**Major Decisions**:
- ✅ AI-centric architecture (AI as central brain, modules as sensors/tools)
- ✅ Proprietary licensing (not open source) to protect defensive algorithms
- ✅ Freemium model (Free/Premium/Enterprise tiers)
- ✅ Windows 10/11 first, Ubuntu for VPS second
- ✅ Cloud LLMs for MVP (Claude API, OpenAI), local models later
- ✅ User-configurable security levels (Observer/Guardian/Sentinel)

**Sections Established**:
- Executive Summary & Philosophy
- Problem Statement & Target Users
- 8 Core Modules (Guardian, Watchtower, Panic Room, Vault, SecureChat, Intel, Remote Shield, Dashboard)
- AI-Centric Architecture (detailed)
- Technical Architecture & Stack
- User Experience Flows
- 18-Month Development Roadmap (6 phases)
- Monetization Strategy (3 tiers with revenue projections)
- Security Considerations & Threat Model
- Decided Architecture (locked decisions)

**Next Steps**:
- Begin Phase 1 implementation
- Update to v0.2.0 if any architecture changes occur

---

### Version Update Process

**When to update PRD version**:
- **Patch (0.1.X)**: Minor clarifications, typo fixes, no functionality change
- **Minor (0.X.0)**: Feature additions/removals, priority changes, phase adjustments
- **Major (X.0.0)**: Fundamental architecture changes, business model pivots

**Process**:
1. Identify need for change (technical constraint, user feedback, better approach)
2. Update relevant PRD section(s)
3. Increment version number
4. Add entry to Changelog (above)
5. Mark changed sections with ~~strikethrough~~ for old, **bold** for new
6. Create ADR in `docs/adr/` if architectural decision
7. Get user approval before implementing

**All changes must be documented - never silently deviate from PRD.**

---

## Executive Summary

**Citadel Archer** is a comprehensive defensive security platform that empowers individuals to protect their digital presence with the sophistication typically available only to well-funded organizations. Built on the principle that **freedom requires security**, Citadel Archer provides active monitoring, rapid threat response, secure communications, and proactive defense against persistent threats.

**Core Philosophy:**
- **Defense, Not Offense**: White hat protection only - no profiling, no offensive capabilities
- **Privacy First**: User data stays with the user - no telemetry, no tracking
- **Power to Individuals**: Enterprise-grade security accessible to everyone
- **Rapid Response**: Automated mitigation measured in seconds, not days
- **AI-Centric Protection**: AI as the adaptive brain that learns and defends your unique environment
- **Strategic Closed Source**: Proprietary algorithms to prevent attackers from studying our defenses
- **Accessible to Non-Experts**: AI explains threats in plain language; simple UI by default, advanced details on-demand
- **Proactive Protection**: AI acts FIRST (within security level), informs AFTER. Questions only when truly necessary.

---

## Problem Statement

### The Current Reality
Modern users face sophisticated, persistent threats:
- **Personal machines** are compromised through phishing, malicious links, and drive-by downloads
- **Remote servers (VPS)** are penetrated within days of deployment despite firewalls
- **Recovery is painful**: Taking weeks to rebuild trust in compromised systems
- **Asymmetric power**: Attackers have sophisticated tools; defenders have fragmented solutions
- **Privacy erosion**: Security tools often become surveillance tools themselves
- **Technical barrier**: Effective security requires expertise most people don't have

### What Users Need
- **Early warning system**: Detect intrusions immediately, not months later
- **One-click mitigation**: Rapid response without technical expertise
- **Secure communications**: Command and coordinate with AI agents and system through an encrypted channel (SecureChat System)
- **Secrets management**: Credentials that can be rotated instantly under attack
- **Remote protection**: Secure VPS and family computers from a single interface
- **Peace of mind**: Confidence that protection is active and current

---

## Target Users

### Primary: Individual Power Users
- Technical enough to run VPS or manage family tech
- Targeted by persistent threats (activists, journalists, small business owners)
- Value privacy and autonomy
- Willing to learn but need tools that "just work"

### Secondary: Family & Friends
- Non-technical users protected through Citadel Archer's remote management
- Benefit from "panic button" and automated protection
- Need simple, clear alerts

### Tertiary: Security & Privacy Community
- Third-party security auditors validate our approaches (annual audits)
- Privacy-focused users benefit from shared threat intelligence (opt-in, anonymized)
- Beta testers help refine features and detection capabilities
- Free tier ensures accessibility for activists, journalists, and those at risk

---

## Core Modules

### 1. **Guardian** - Local Machine Protection
**Purpose**: Secure and actively monitor the user's workstation

**Key Features:**
- Real-time filesystem monitoring (unauthorized changes, suspicious binaries)
- Network traffic analysis (outbound C2 connections, data exfiltration)
- Process monitoring (suspicious processes, privilege escalation attempts)
- **Browser Extension Protection** (see detailed sub-section below)
- Memory scanning for rootkits and injected code
- Boot integrity verification
- Automated quarantine and cleanup

**Technical Approach (Implemented):**
- Python agent using `watchdog` for filesystem event monitoring and `psutil` for process monitoring (cross-platform, not pywin32)
- Anomaly detection via Watchtower/Intel pipeline (`anomaly_detector.py` — Isolation Forest + Z-score), not in-process ML
- Automatic signature updates from Intel module via `guardian_updater.py` (hot-reload, no restart)
- All events logged to `EventAggregator` for forensics and dashboard display

#### Browser Extension Protection (v0.2.4)

**Problem**: Browser extensions are one of the most dangerous and overlooked attack surfaces. They can:
- Inject JavaScript into ANY page (including localhost security dashboards)
- Read and modify page DOM, intercept form submissions, capture keystrokes
- Exfiltrate data to external servers with minimal user visibility
- Be silently installed by software bundlers, OEM bloatware, or malware
- Auto-update silently, introducing malicious behavior post-install
- Operate across browser boundaries (Edge extensions loading on Chrome-intended pages)

**Detection Capabilities:**

1. **Extension Inventory Scanning**
   - Enumerate installed extensions across all Chromium browsers (Chrome, Edge, Brave, Vivaldi)
   - Parse each extension's `manifest.json` for permission analysis
   - Flag extensions with dangerous permission combinations:
     - `<all_urls>` content script matches (injects into every page)
     - `webRequest`/`webRequestBlocking` (can intercept/modify all HTTP traffic)
     - `tabs` + `activeTab` (can read all tab URLs and content)
     - `clipboardRead`/`clipboardWrite` (clipboard access)
     - `nativeMessaging` (can communicate with local executables)
   - Detect non-standard extension ID formats (UUID-style IDs indicate sideloaded/dev extensions)
   - Cross-reference extension IDs against known malicious extension databases

2. **Unauthorized Installation Detection**
   - Monitor browser extension directories for new installations
   - Alert when extensions appear that user didn't explicitly install
   - Detect sideloaded extensions (installed by other software, group policy, or registry manipulation)
   - Track extension install source (Chrome Web Store vs. sideloaded vs. enterprise policy)

3. **Runtime Behavior Monitoring**
   - Monitor extension network traffic (what domains do extensions phone home to?)
   - Detect extensions injecting content scripts into Citadel Archer's dashboard
   - Flag extensions making requests to suspicious or newly-registered domains
   - Monitor for extensions accessing sensitive page content (password fields, API keys)

4. **Content Security Policy (CSP) Enforcement**
   - Apply strict CSP headers to Citadel Archer's dashboard pages
   - Detect and alert when extensions bypass or modify CSP headers
   - Use nonce-based script loading to identify unauthorized injected scripts

5. **Cross-Browser Awareness**
   - Scan ALL installed browsers, not just the default
   - Detect when non-default browsers (e.g., Edge) have extensions that could affect browsing
   - Alert users to extensions in browsers they don't actively use (common sideload target)

**Response Actions (by Security Level):**

| Level | Action |
|-------|--------|
| Observer | Inventory and report all extensions, flag risky permissions |
| Guardian | Alert on new/unauthorized extensions, recommend removal of dangerous ones |
| Sentinel | Auto-disable sideloaded extensions, block extension network traffic to suspicious domains |

**Dashboard Integration:**
- Extension health status in Guardian panel ("X extensions found, Y flagged")
- Extension threat alerts in event log with severity ratings
- Detailed extension audit view (permissions, install source, network behavior)
- One-click "audit all extensions" action

---

### 2. **Watchtower** - Intrusion Detection System (IDS)
**Purpose**: Active monitoring and alerting across all protected assets

**Key Features:**
- Multi-asset dashboard (local machine, VPS instances, remote systems)
- Real-time threat scoring and prioritization
- Alert aggregation and noise reduction
- Attack pattern recognition
- Automated response playbooks
- Historical attack timeline
- Forensic log collection

**Technical Approach (Implemented):**
- **Event Aggregator** (`intel/event_aggregator.py`): Central event collection from all sensors, categorized by type (file, process, network, vault, system, AI, user, intel)
- **Anomaly Detector** (`intel/anomaly_detector.py`): Behavioral anomaly scoring with configurable sensitivity (low/medium/high), `ThreatLevel` enum
- **Threat Scorer** (`intel/threat_scorer.py`): Risk matrix combining severity x confidence x anomaly x intel matches → `RiskLevel` (low/medium/high/critical)
- **Context Engine** (`intel/context_engine.py`): Behavioral context tracking by activity type — builds patterns to distinguish normal from anomalous
- **Guardian Updater** (`intel/guardian_updater.py`): Auto-generates Guardian detection rules from IOCs/TTPs/CVEs with severity-based action mapping
- **Dashboard Data** (`intel/chart_data.py`, `alert_timeline.py`, `risk_metrics.py`, `asset_view.py`): Pre-built chart data, paginated alert history, risk gauge metrics, enriched asset views
- Integration with Guardian sensors and Remote Shield agents via event bus

---

### 3. **Panic Room** - Emergency Response System
**Purpose**: Instant security posture reset when under active attack

**Key Features:**
- One-click "Panic Button" activation
- Automated credential rotation across all services
- Emergency network isolation (cut all non-essential connections)
- Snapshot current state for forensics
- Secure backup of critical data
- Step-by-step recovery guidance
- Post-incident analysis and hardening
- **Asset scope selector** — target local machine, specific VPS, or all managed assets *(v0.2.5)*
- **Remote credential rotation** — rotate SSH keys on remote assets via SSH Connection Manager *(v0.2.5)*

**Technical Approach (Implemented):**
- **Action framework** (`panic/actions/base.py`): Base class with `execute()`, `verify()`, `rollback()` lifecycle for all panic actions
- **Playbook engine** (`panic/playbook_engine.py`): Orchestrates multi-action playbooks with pre-flight checks, async execution, progress tracking, and rollback on failure
- **Credential rotation** (`panic/actions/credential_rotation.py`): SSH keys, API tokens, passwords — updates Vault, supports remote rotation via SSH, 30-day key archive
- **Network isolation** (`panic/actions/network_isolation.py`): iptables rules with whitelist, state capture, full rollback capability
- **Secure backup** (`panic/actions/secure_backup.py`): Encrypted backup with integrity verification and restore
- **System snapshot** (`panic/actions/system_snapshot.py`): Forensic captures — process dumps, network state, file hashing, log collection
- **Panic database** (`panic/panic_database.py`): Session persistence, action history, scope tracking
- Integration with Vault for credential operations, SSH Connection Manager for remote assets *(v0.2.5)*
- SCS integration for AI triage guidance (Trigger 2c — implemented v0.3.1: activation/completion/failure escalation to SecureChat)
- Remote agent actions via VPS agents for remote isolation/rotation *(v0.2.8)*

---

### 4. **Vault** - Secrets Management
**Purpose**: Secure storage and management of credentials, API keys, certificates

**Key Features:**
- Military-grade encryption at rest (AES-256)
- Master password + optional hardware key (YubiKey support)
- Automatic credential rotation scheduling
- Password generation (configurable complexity)
- Secure sharing with trusted contacts (encrypted, time-limited)
- Breach monitoring (check credentials against known breaches)
- Auto-fill integration (browser, SSH, applications)
- Emergency access delegation ("dead man's switch")

**Technical Approach (Implemented):**
- Local SQLite database with **per-entry AES-256-GCM encryption** via `cryptography` library (not cloud-based)
- **PBKDF2 key derivation** from master password (600,000 iterations — `vault/encryption.py`)
- **Rate-limited unlock** — prevents brute-force against master password
- **SSH credential type** — structured metadata for host, port, username, key material (`vault/vault_manager.py`)
- Zero-knowledge architecture — vault is inaccessible without master password
- Panic Room integration for instant credential rotation
- **Planned**: SQLCipher database-level encryption, system keychain integration (Windows Credential Manager), hardware key support (YubiKey)

---

### 5. **SecureChat** - Core Communication Infrastructure *(v0.2.6 — repositioned, v0.2.7 — expanded)*
**Purpose**: The encrypted communication backbone for all command-level interaction between the user, AI agents, and Citadel system. SecureChat is NOT a "chat with friends" feature — it is foundational infrastructure.

**Why SecureChat is Foundational:**
SecureChat provides the channel through which command-level system communication flows:
- **User <-> AI Agents**: The user's primary interface for assessing threats, issuing commands, and receiving strategic guidance from any AI (Claude Code, Forge, OpenClaw)
- **AI Agent <-> Citadel**: AI brains dispatch setup actions, deployment commands, and security decisions
- **Citadel <-> VPS Agents**: Escalations from remote agents requiring command-level attention
- **AI Agent <-> AI Agent**: Inter-agent coordination across machines (e.g., Claude Code on desktop tells Forge on VPS to investigate)

#### Two-Tier Communication Model *(v0.2.7 — formalized)*

Citadel Archer uses two formally named communication tiers — this is critical to the architecture:

**Automation Communication System (ACS)** — Low-level, no AI, no tokens:
| What flows through ACS | Examples |
|------------------------|----------|
| Sensor data | auth.log events, process lists, file integrity hashes |
| Heartbeats | Agent alive/dead status, uptime counters |
| Routine alerts | Failed SSH attempt #47, known-bad IP blocked |
| Metrics | CPU/RAM/disk usage, network throughput |
| Agent status | Sensor health, last scan time, event counts |

**SecureChat System (SCS)** — High-level, AI-assisted, uses tokens when AI involved:
| What flows through SCS | Examples |
|------------------------|----------|
| User commands | "add vps 154.49.137.24", "deploy agent", "rotate credentials" |
| AI analysis | "The brute force pattern suggests a botnet. Here's my recommendation..." |
| Strategic decisions | "Should we escalate to Sentinel mode?" |
| Escalations | "Agent vps1: 3 critical events — cron tampered, needs command-level attention" |
| Setup conversations | VPS onboarding, agent deployment, configuration changes |
| Cross-AI coordination | Claude Code asking Forge to investigate an anomaly on another machine |

**Rule**: If sensors and automation handle it → ACS. If it needs command-level attention (human decision, AI reasoning, setup conversation, cross-device coordination) → SCS.

#### Token Minimization Principle *(v0.2.8)*

> **Resolve at the lowest level possible before escalating to the AI. AI is the last resort, not the first responder.**

The system uses a 4-level escalation hierarchy. Each level resolves what it can and only passes up what it cannot:

| Level | Component | Tokens? | Resolves |
|-------|-----------|---------|----------|
| **1** | Tripwire Rules | None | Known patterns — malware sigs, known-bad IPs, brute force thresholds |
| **2** | Threshold/Correlation Engine | None | Aggregated patterns — dedup same attack from multiple agents, breach thresholds, time-series anomalies |
| **3** | AI Analysis (AI Bridge) | Yes | Novel threats, ambiguous patterns, strategic recommendations, multi-step response coordination |
| **4** | Human Decision | N/A | Rare (<5%) — ambiguous + high impact situations where AI defers to user judgment |

**Cost impact**: Levels 1-2 handle ~80-90% of all events with zero token usage. Level 3 handles ~10-15% (command-level attention). Level 4 is <5%. Typical daily token usage: 10-30 AI calls, not hundreds.

#### Forge/Telegram — Out-of-Band Notification *(v0.2.8)*

The user's AI assistant **Forge** can reach the user at any time via **Telegram**. This is the out-of-band notification channel when the user isn't at the computer.

**Three remote interaction paths** (when user is away from the dashboard):
1. **Forge via Telegram** — Forge monitors SCS and can alert the user via Telegram for critical events. Bidirectional: user can respond and issue commands back through Forge.
2. **Claude Code via SSH** — User can SSH into their machine and use Claude Code CLI to interact with the system directly.
3. **SecureChat browser client** *(future)* — Web-based access to the SecureChat sidebar.

#### Multi-AI Agent Participation *(v0.2.7)*

SecureChat is NOT limited to a single in-process AI Bridge calling the Claude API. It is the communication backbone for **multiple AI agent types** across **multiple devices**:

| Participant | Type | Where it runs | How it connects |
|------------|------|---------------|-----------------|
| **User** | Human | Desktop | Dashboard sidebar (WebSocket) |
| **Claude Code** | AI Agent | Each machine (desktop + VPS) | REST API (`POST /api/chat/send`) or in-process |
| **Forge** | AI Assistant | User's primary AI assistant | REST API polling or WebSocket; reaches user via **Telegram** when away |
| **OpenClaw** | External AI Agent | Any authorized device | REST API with auth token |
| **Citadel** | System | Local process | In-process (ChatManager) |
| **agent:\<id\>** | Shield Agent | Each VPS | Escalations via AgentPoller → ChatManager |

Each participant has a unique `from_id` in messages. AI participants are authenticated via API tokens or local trust (in-process). The system supports any number of AI agents — not just one.

**Key Features (Current):**
- Always-visible sidebar in dashboard (not a tab — independent of tab-loader lifecycle)
- Message persistence (SQLite at `data/securechat.db`)
- Real-time push via WebSocket (uses existing wsHandler)
- Command dispatch ("add vps", "deploy agent", "done/verify")
- Message types: COMMAND, EVENT, QUERY, RESPONSE, HEARTBEAT, SETUP, TEXT
- Participant model: user, assistant, citadel, agent:<asset_id> — extensible for multi-AI
- Collapse/expand with unread badge
- AI assistant via AI Bridge (`chat/ai_bridge.py`) — Claude API with tool use, context building, trigger model, graceful degradation

**Key Features (Future):**
- Multi-AI agent authentication (API tokens for external AI participants)
- E2E encrypted peer-to-peer messaging with trusted contacts
- Local LLM integration (Ollama) for fully offline AI assistant
- Cross-device message sync (desktop ↔ VPS agent SecureChat instances)
- Secure file sharing (encrypted, time-limited)
- Voice/video calls (WebRTC, encrypted)
- Self-destructing messages

**Technical Approach:**
- Python ChatManager for message routing and command dispatch
- SQLite persistence with ChatStore
- REST API (`/api/chat/messages`, `/api/chat/send`, `/api/chat/participants`)
- WebSocket push for real-time message delivery
- Future: Multi-AI auth (API tokens per participant), P2P connections (STUN/TURN), libsodium cryptography, WebRTC for voice/video

---

### 6. **Intel** - Threat Intelligence
**Purpose**: Stay current with latest threats, tactics, and vulnerabilities

**Key Features:**
- Daily automated threat feeds (CVEs, malware signatures, IOCs)
- AI-powered threat analysis (summarize, prioritize, contextualize)
- Automatic security updates for Guardian signatures
- Threat actor profiling (understand who targets you)
- Vulnerability scanning (outdated software, misconfigurations)
- Community threat sharing (anonymized, opt-in)
- Custom threat research (search by keyword, technique)

**Technical Approach (Implemented):**
- **OTX fetcher** (`intel/otx_fetcher.py`): AlienVault OTX integration with pagination, retry, IOC/CVE extraction
- **Aggregator** (`intel/aggregator.py`): Scheduled daily fetches via APScheduler, parallel execution, deduplication, severity-based conflict resolution
- **Data models** (`intel/models.py`): IOC, CVE, TTP, Vulnerability with structured fields
- **SQLite store** (`intel/store.py`): Persistent threat intel with query/filter capabilities
- Integration with Guardian via `guardian_updater.py` for automatic rule generation
- **Planned**: Additional feeds (abuse.ch, MITRE ATT&CK, NVD), local LLM summarization (Ollama), community intel sharing

---

### 7. **Remote Shield** - VPS & Remote System Protection
**Purpose**: Extend Citadel Archer protection to remote servers and family computers

**Key Features:**
- Remote agent deployment (one-click install script)
- Centralized monitoring from local dashboard
- SSH hardening (key-only auth, port knocking, fail2ban++)
- Firewall management (dynamic rules, geo-blocking)
- Service monitoring (unexpected services, privilege escalation)
- File integrity monitoring (tripwire-style)
- Automated patching (OS and software updates)
- Remote panic button (isolate and lock down)

**Technical Approach:**
- Lightweight Python agent on remote systems (`agent/shield.py` — stdlib only, no pip deps)
- **Current**: SSH-based polling from desktop — AgentPoller queries agent CLI every 60s, pulls events, syncs state
- **Current**: Agent deployed via SCP + SSH (`remote/agent_deployer.py`), runs as systemd service
- **Current**: Agent has local SQLite event store, CLI for status/events/ack queries
- **Future**: Encrypted C2 channel back to Watchtower (certificate-based mutual auth, persistent connection)
- **Future**: Agent auto-updates from trusted source
- Critical events escalated via SCS (SecureChat); routine data stays in ACS (system API routes)

---

### 8. **Dashboard** - Unified Control Center
**Purpose**: Single interface for all Citadel Archer functions

**Key Features:**
- Real-time security status (all assets, color-coded health)
- Threat feed and alerts (prioritized, actionable)
- Quick actions (panic button, isolate asset, rotate credentials)
- Asset management (add/remove/configure protected systems) — *see [Asset Management Addendum](ASSET_MANAGEMENT_ADDENDUM.md) for full spec*
- Settings and preferences (notification rules, auto-response config)
- Reports and forensics (incident timelines, log search)
- Help and documentation (context-sensitive, tutorials)

**UI/UX Design:**
- **Dark mode by default** (OLED-friendly, easy on eyes)
- **Glassmorphic design** (frosted glass cards, depth, translucency)
- **Neon blue accent color** (#00D9FF or similar)
- **Cyberpunk aesthetic** (but functional, not cluttered)
- **Responsive layout** (works on all screen sizes)
- **Animations** (smooth transitions, loading states)
- **Data visualization** (charts for threat trends, network activity)

**Technical Approach:**
- Python backend (FastAPI REST API + WebSocket)
- Vanilla JavaScript frontend (ES6 modules, Web Components, Shadow DOM) — no React/Vue *(decided v0.2.3)*
- Microsoft Edge app mode for native desktop wrapper (guaranteed on Windows 10/11, no external dependency)
- WebSocket for real-time updates (shared wsHandler)
- Local-first architecture (works offline)
- SecureChat sidebar always visible alongside tab content

---

## AI-Centric Architecture

### The AI Brain Concept

Citadel Archer is **fundamentally AI-driven**, not just "AI-assisted." The AI serves as the central intelligence that:
- **Learns your environment**: Understands your normal behavior, applications, and patterns
- **Makes holistic decisions**: Analyzes data from all sensors (Guardian, Watchtower, Intel) together
- **Adapts in real-time**: Responds to novel threats that no static rules could catch
- **Operates autonomously**: Takes action within user-defined guardrails

**Why AI-Centric?**
Since our code is proprietary (not open source), attackers cannot study our algorithms. But even if they could, the AI's adaptive nature means each installation learns unique patterns for each user - making generic attacks ineffective.

### Architecture Diagram *(updated v0.2.8)*

```
┌─────────────────────────────────────────────────────────────────────┐
│                   DESKTOP (citadel-archer.exe)                       │
│  ┌──────────────────────────────┐  ┌────────────────────────────┐  │
│  │    Dashboard (Tabs)          │  │  SecureChat System (SCS)    │  │
│  │  Charts, Timeline, Assets,  │  │  Sidebar — always visible   │  │
│  │  Risk Metrics, Remote Shield │  │                             │  │
│  │                              │  │  Participants:              │  │
│  │  Receives: ACS data         │  │  • User (human)             │  │
│  │  (sensors, metrics, health) │  │  • Claude Code (per-device) │  │
│  │                              │  │  • Forge (AI assistant)     │  │
│  │                              │  │  • OpenClaw (external AI)   │  │
│  └──────────┬───────────────────┘  │  • Citadel (system)        │  │
│             │                      │  • agent:<id> (escalations) │  │
│             │                      └─────────┬──────────────────┘  │
│             │ ACS (Automation)               │ SCS (Command-level) │
└─────────────┼────────────────────────────────┼─────────────────────┘
              │                                │
              │         ┌──────────────────────┤
              │         │                      │
              ↓         ↓                      ↓
┌─────────────────────────────────────────────────────────────────────┐
│                        AI BRAIN (Multi-Agent)                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  AI Bridge (in-process)     External AI Agents (REST API)    │  │
│  │  - Claude API (primary)     - Claude Code (each machine)     │  │
│  │  - Triggers: 1a,2a-c,3a (now) - Forge (user's AI assistant)    │  │
│  │    1b,3b-c (planned)        - OpenClaw (external agents)     │  │
│  │  - Tools: get_status,        All auth'd via API tokens       │  │
│  │    get_assets, get_events,                                    │  │
│  │    deploy_agent              POST /api/chat/send              │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────┬────────────┬────────────┬────────────┬──────────┬─────────────┘
     │            │            │            │          │
     ↓            ↓            ↓            ↓          ↓
┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ ┌─────────────┐
│ Guardian │ │Watchtower│ │  Intel   │ │ Vault  │ │Remote Shield│
│ (Sensor) │ │ (Sensor) │ │ (Intel)  │ │ (Tool) │ │(VPS Agents) │
│ local FS,│ │ event    │ │ threat   │ │ AES256 │ │ auth.log,   │
│ process, │ │ aggreg., │ │ feeds,   │ │ creds, │ │ processes,  │
│ network, │ │ alerting │ │ CVE/IOC  │ │ SSH    │ │ cron, files │
│ browser  │ │          │ │          │ │ keys   │ │ tripwires   │
└────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ └──────┬──────┘
     │            │            │            │             │
     └────────────┴────────────┴────────────┘             │
                   │                              SSH polling (60s)
                   ↓                              AgentPoller
         ┌─────────────────┐                      │
         │  System Actions  │←────────────────────┘
         │ (quarantine,     │  escalations → SCS (SecureChat)
         │  block, kill,    │  routine data → ACS (Dashboard)
         │  alert, rotate)  │
         └─────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              ALWAYS-ON (citadel-service / systemd)                   │
│  Guardian sensors, event store, heartbeat emitter, tripwire rules   │
│  Runs 24/7 — even when desktop app is closed or user is logged out  │
│  Feeds ACS data to dashboard when app opens (catch-up sync)         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                    DEFENSE MESH (v0.2.7)                             │
│  Desktop ←──heartbeat──→ VPS1 ←──heartbeat──→ VPS2                  │
│  Each node monitors peers. If coordinator goes dark:                 │
│  • Agents enter heightened defense mode autonomously                 │
│  • Secondary brain (designated VPS) assumes coordination             │
│  • Peer alerting: surviving nodes notify each other                  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                   THRESHOLD / CORRELATION ENGINE (v0.2.8)            │
│  ACS data → correlate across sensors → dedup multi-agent events     │
│  Breach threshold? → Escalate ONE summary to SCS (Trigger 3c)      │
│  No tokens used — pure automation bridge between ACS and SCS        │
└─────────────────────────────────────────────────────────────────────┘

Communication Tiers:
  SCS (SecureChat System): User, AI agents, escalations — command-level, uses tokens
  ACS (Automation Comm):   Sensors, heartbeats, metrics — no AI, no tokens

Escalation Hierarchy (Token Minimization — v0.2.8):
  Level 1: Tripwire Rules          → auto-action (no tokens, ~80% of events)
  Level 2: Threshold Engine        → correlate + dedup (no tokens, ~10%)
  Level 3: AI Analysis             → strategic reasoning (tokens, ~10%)
  Level 4: Human Decision          → ambiguous + high impact (rare, <5%)

Remote Interaction (when user is away):
  Forge → Telegram    (Forge can reach user anytime)
  Claude Code → SSH   (user connects to machine)
  SecureChat → Web    (future browser client)
```

### How It Works

1. **Sensors Collect Data**:
   - Guardian monitors files, processes, network, memory
   - Watchtower aggregates events across all assets
   - Intel provides threat intelligence updates

2. **AI Brain Analyzes Holistically**:
   - "Is this file change normal for this user?"
   - "Does this network connection match known C2 patterns?"
   - "Is this process behavior consistent with the application's purpose?"
   - "Should I act autonomously or ask the user?"

3. **AI Takes Action**:
   - Within user's security level (Observer/Guardian/Sentinel)
   - Executes via tools (Vault for credential rotation, system APIs for quarantine/block)
   - Logs all decisions for forensics and learning

4. **AI Learns Continuously**:
   - Builds profile of user's normal behavior
   - Adapts to new legitimate software and patterns
   - Gets smarter over time, reducing false positives

### AI Bridge: Connecting the Brain to SecureChat *(v0.2.6)*

The AI Brain described above is not a persistent running process — it's Claude, invoked on demand through the Anthropic API. The **AI Bridge** (`chat/ai_bridge.py`) is the module that connects the stateless AI to the stateful SecureChat infrastructure.

**The fundamental problem**: Claude doesn't run as a daemon. It's an API you call. Something must decide *when* to wake the AI, *what context* to give it, and *how* to route its responses back to the user.

#### When the AI Wakes Up (Trigger Model) *(v0.2.7 — expanded to 8 subtypes)*

The AI is invoked when command-level attention is needed. Three categories, eight subtypes:

**Category 1: SecureChat Message Received**
| Subtype | Trigger | Status | Example |
|---------|---------|--------|---------|
| **1a** | User TEXT in SecureChat | Implemented | "What should I do about the brute force attacks?" |
| **1b** | External AI agent message via REST API | Implemented | Forge posts: "Desktop agent is offline, should I activate heightened defense?" — `AgentRegistry` + `AgentRateLimiter` + `agent_api_routes.py`, Bearer token auth, `ext-agent:` prefix |

**Category 2: Critical Threat Escalation**
| Subtype | Trigger | Status | Example |
|---------|---------|--------|---------|
| **2a** | Remote agent critical event (via AgentPoller) | Implemented | "Agent vps1: 3 critical events — cron tampered" |
| **2b** | Local Guardian critical event | Implemented | Guardian detects rootkit on desktop → `GuardianEscalation` batches + escalates to AI via SecureChat |
| **2c** | Panic Room activation | Implemented | Panic activation/completion/failure → `PanicManager` escalates to AI via `ChatManager.send_system()` at 3 lifecycle points |

**Category 3: App-Initiated Processing**
| Subtype | Trigger | Status | Example |
|---------|---------|--------|---------|
| **3a** | Scheduled analysis (periodic) | Implemented | Daily security posture review via `PostureAnalyzer` (24h cycle, 5 data sources, AI Bridge summary). `chat/posture_analyzer.py` |
| **3b** | Startup catch-up | Implemented | App opens → `StartupCatchup` queries audit log for SYSTEM_STOP, gathers offline events from 3 persistent sources, sends AI briefing. `chat/startup_catchup.py` |
| **3c** | Threshold breach detection | Implemented | `ThresholdEngine` monitors event patterns via 6 configurable rules (5 COUNT + 1 CORRELATION). Hybrid evaluation: COUNT per-event, CORRELATION every 30s. Per-rule cooldown + dedup + rate limiting. `chat/threshold_engine.py` |

**NOT triggered** (stays in ACS — resolved at Level 1 or 2):
- Known commands ("add vps", "deploy agent") — handled by deterministic command handlers (no tokens)
- Routine events, heartbeats, sensor data — Automation Communication System handles these
- Individual low-severity alerts — processed by tripwire rules (Level 1), not AI
- Correlated patterns below threshold — processed by threshold engine (Level 2), not AI
- Duplicate escalations from multiple agents detecting same attack — deduplicated by threshold engine before any SCS escalation

**Threshold/Correlation Engine** *(v0.2.8 — Trigger 3c source)*:
The threshold engine is a new component sitting between ACS and SCS. It watches automation data for patterns that individual tripwire rules cannot detect:
- **Correlation**: Aggregates events across multiple sensors and agents (e.g., failed SSH + cron change + new process = coordinated attack)
- **Deduplication**: If 3 agents all detect the same distributed brute force, generates ONE escalation, not 3
- **Time-series thresholds**: 50+ failed SSH in an hour, 3+ critical file changes in a day, etc.
- **No tokens**: The engine is pure automation. Only when a threshold is breached does it promote the pattern to SCS for AI analysis.

**Cost control**: The AI is only invoked for command-level attention. Levels 1-2 (tripwires + threshold engine) handle ~80-90% of events with zero tokens. Level 3 (AI) handles ~10-15%. Typical usage: 10-30 API calls per day. Trigger 3a adds ~1 call/day (daily posture review). Trigger 1b adds variable calls/day (depends on external agent activity, rate-limited per agent). Trigger 3b adds 1 call/startup (startup catch-up). Trigger 3c adds ~5-15 calls/day (threshold breach escalations, rate-limited to 15/hr).

#### What the AI Sees (Context Building)

Each invocation, the bridge builds fresh context from persistent stores:

1. **System prompt**: Role definition, personality, security level constraints, rules
2. **System state snapshot**: Threat level, guardian status, uptime, managed assets summary
3. **Chat history**: Last 20 messages from SecureChat (converted to Claude message format)
4. **Trigger message**: The specific user question or agent escalation that triggered invocation

This makes a stateless API call feel stateful — the AI has full conversational context.

#### What the AI Can Do (Tool Model)

The AI has access to tools, gated by the user's security level:

**Read-only tools** (all levels):
- `get_system_status` — current threat level, guardian status, uptime
- `get_asset_list` — all managed assets with status and agent info
- `get_agent_events` — recent security events from a specific agent

**Action tools** (Guardian/Sentinel only):
- `deploy_agent` — deploy Citadel Shield to a VPS
- Future: `block_ip`, `rotate_credentials`, `kill_remote_process`

**Observer level**: AI can analyze and explain but cannot take autonomous actions.
**Guardian level**: AI can block known threats, deploy agents, rotate credentials.
**Sentinel level**: Full autonomy within system capabilities.

**Append-Only Audit Log** *(v0.2.8)*: Every AI tool invocation is logged to an immutable, append-only audit trail (`data/ai_audit.log`), separate from `securechat.db`. Chat messages can be edited or deleted; audit entries cannot. Each entry records: timestamp, trigger type, tool called, parameters, result, security level at time of action. This log is the authoritative record of what the AI did and why.

**SCS API Rate Limiting** *(v0.2.8)*: Each SCS participant has a rate-limited API token to prevent abuse:
- Agents: 10 escalations/minute (prevents compromised agent flooding)
- External AI (OpenClaw): 30 messages/minute
- Claude Code: 60 messages/minute (higher trust — runs on user's own machines)
- Forge: 60 messages/minute (trusted AI assistant)
- System (Citadel): Unlimited (internal process)

#### Invocation Patterns

The AI Bridge supports multiple invocation patterns for different use cases:

| Pattern | Method | Best for |
|---------|--------|----------|
| **In-process** | Anthropic Python SDK (async) | Real-time chat responses (<3 sec) |
| **External script** | REST API polling + CLI | Background analysis, complex tasks |
| **Future: Agent SDK** | Anthropic Agent SDK | Multi-step autonomous workflows |

**Primary (implemented)**: In-process via `AIBridge` class registered as a ChatManager listener. Calls `anthropic.messages.create()` with tools.

**Secondary (future)**: External scripts can poll `GET /api/chat/messages` for messages needing attention, call Claude Code CLI for complex reasoning, and post responses via `POST /api/chat/send`.

#### Graceful Degradation

If no `ANTHROPIC_API_KEY` is configured:
- AI Bridge is disabled (logged at startup)
- All chat commands still work (`add vps`, `deploy agent`, etc.)
- Agent escalations still appear in the sidebar
- User sees "(Set ANTHROPIC_API_KEY to enable AI assistant.)"

This ensures the system is valuable even without AI — the infrastructure works independently.

### User-Configurable Security Levels

Users choose their comfort level during onboarding (can change anytime):

#### Level 1: "Observer" 🔍
**Best for**: Users who want full control, or evaluating Citadel Archer

**AI Capabilities**:
- ✅ Monitor all system activity
- ✅ Analyze logs and network traffic
- ✅ Alert user to potential threats
- ❌ No autonomous actions (user approves everything)

**Use Case**: "Show me everything, but let me decide what to do."

---

#### Level 2: "Guardian" 🛡️ (RECOMMENDED)
**Best for**: Most users - balances security and convenience

**AI Capabilities**:
- ✅ Everything in Observer, PLUS:
- ✅ Auto-quarantine files matching known malware signatures
- ✅ Auto-block connections to known malicious IPs/domains
- ✅ Auto-kill obviously malicious processes (ransomware, cryptominers, keyloggers)
- ✅ Rotate credentials on Vault when breach detected
- ⚠️ Ask before: Killing legitimate-looking processes, modifying system config, blocking entire ports

**Use Case**: "Protect me from known threats automatically, but ask about ambiguous situations."

---

#### Level 3: "Sentinel" ⚔️
**Best for**: High-risk users (activists, journalists) or those under active attack

**AI Capabilities**:
- ✅ Everything in Guardian, PLUS:
- ✅ Modify firewall rules proactively (block suspicious IPs/ports)
- ✅ Kill suspicious processes based on behavior analysis
- ✅ Modify system configuration (disable vulnerable services, harden registry)
- ✅ Auto-enable "panic mode" when sustained attack detected
- ⚠️ Ask only for: Destructive actions (delete files, format disks)

**Use Case**: "I'm under attack. Do whatever it takes to protect me."

---

### AI Tool Access (Full Vision)

> **Note**: For currently implemented tools, see **AI Bridge → Tool Model** above. This section describes the full target capability set for all phases.

The AI Brain has access to these tools (within security level constraints):

**Monitoring Tools** (read-only):
- Filesystem access (read file contents, metadata, permissions)
- Process information (running processes, memory usage, parent/child relationships)
- Network traffic (connections, DNS queries, packet analysis)
- System logs (Event Viewer on Windows, syslog on Linux)
- Registry access (Windows) or config files (Linux)

**Action Tools** (write access, controlled by security level):
- File operations (quarantine to isolated location, delete if confirmed malware)
- Process control (kill process, suspend process)
- Network control (block IP/domain, modify firewall rules, force disconnect)
- System configuration (modify registry, disable services, update Group Policy)
- Vault operations (rotate passwords, regenerate API keys)
- Backup/restore (snapshot system state, restore from backup)

**Communication Tools**:
- User alerts (push notification, dashboard alert, email if critical)
- Logging (immutable audit trail of all AI decisions and actions)
- External APIs (query threat intel feeds, check hash reputation)

### AI Provider Support

**MVP (Phase 1-2)**: Cloud LLM APIs
- Anthropic Claude API (primary recommendation)
- OpenAI GPT-4 API (alternative)
- User brings their own API key (free tier)
- Premium tier includes subsidized API access

**Future (Phase 4)**: Local LLM Support
- Ollama integration for local inference
- Privacy-focused users can run 100% offline
- Trade-off: Less capable than cloud models, but full privacy

### Always-On Protection *(v0.2.7)*

**Problem**: The desktop is only protected when the Citadel Archer app is running. VPS agents run as systemd services (always on), but the desktop has zero protection when the app is closed, the user is logged out, or the system is idle.

**Solution**: Split the desktop application into two components:

#### `citadel-service` — The Always-On Guardian

| Aspect | Detail |
|--------|--------|
| **What** | Windows Service (or systemd on Linux) that runs 24/7 |
| **Starts** | System boot (before user login) |
| **Stops** | Never (unless explicitly disabled or system shuts down) |
| **Runs as** | SYSTEM account (Windows) / root (Linux) |
| **Components** | Guardian sensors, local event store (SQLite), tripwire rules, heartbeat emitter |
| **No UI** | Headless — logs to Windows Event Log / journald |
| **No AI** | Pure automation — rules-based detection and response (ACS tier) |
| **Event queue** | Stores events in local SQLite; desktop app reads on connect (catch-up sync) |

**What it does while the app is closed:**
- Monitors filesystem changes (unauthorized modifications, suspicious binaries)
- Monitors running processes (crypto miners, reverse shells, privilege escalation)
- Monitors network connections (C2 beacons, data exfiltration)
- Executes tripwire rules autonomously (kill malicious process, block IP)
- Emits heartbeats to VPS agents (defense mesh — "I'm alive")
- Queues events for the dashboard to consume when it opens

#### `citadel-archer` — The User-Facing Dashboard

| Aspect | Detail |
|--------|--------|
| **What** | Desktop app with Dashboard UI, SecureChat, AI Bridge, Vault |
| **Starts** | User launches it (or auto-start on login, user preference) |
| **Stops** | User closes it |
| **Components** | Full dashboard, SecureChat sidebar, AI Bridge, Vault UI, tab pages |
| **AI** | Yes — AI Bridge invokes Claude API for command-level attention (SCS tier) |
| **Catch-up** | On launch, reads queued events from `citadel-service` and syncs to dashboard |

**Interaction between the two:**
```
citadel-service (always running)          citadel-archer (user opens)
       │                                         │
       │ ←─ Shared SQLite event store ──→        │
       │    (citadel-service writes,              │
       │     citadel-archer reads)                │
       │                                         │
       │ ←─ IPC (named pipe / socket) ──→        │
       │    (real-time event push when            │
       │     both are running)                    │
       │                                         │
       │ ──→ Defense mesh heartbeats ──→ VPS agents
       │      (always, even when app is closed)
```

**SQLite WAL Mode** *(v0.2.8)*: The shared event store between `citadel-service` (writer) and `citadel-archer` (reader) **must** use WAL (Write-Ahead Logging) mode for safe concurrent access. Without WAL, the service would block while the app reads, or vice versa. WAL allows one writer and multiple readers simultaneously.

**Trigger 3b (Startup Catch-Up)** from the AI trigger model connects here: when `citadel-archer` opens, it queries `citadel-service` for events that occurred while the app was closed, and the AI Bridge produces a summary: "While you were away: 2 critical events, 14 blocked IPs, 1 process killed."

---

### Distributed Resilience / Defense Mesh *(v0.2.7)*

**Problem**: The current architecture is hub-and-spoke — the desktop coordinator manages all VPS agents. If the desktop is compromised, offline, or destroyed, all coordination stops. VPS agents continue their local tripwire rules but lose centralized oversight, event collection, and strategic AI analysis.

**Solution**: A Defense Mesh where each node monitors the others, can operate autonomously, and can designate a secondary brain when the primary coordinator goes dark.

#### Mesh Protocol

```
     ┌────────────┐
     │  Desktop   │ ←── Primary Coordinator
     │ (citadel-  │     (AI Bridge, SecureChat, Vault)
     │  service)  │
     └──┬────┬────┘
        │    │
   heartbeat heartbeat
        │    │
        ↓    ↓
  ┌─────────┐ ┌─────────┐
  │  VPS 1  │ │  VPS 2  │
  │ (shield │ │ (shield │
  │  agent) │ │  agent) │
  └────┬────┘ └────┬────┘
       │           │
       └──heartbeat┘
         (peer-to-peer)
```

#### Mutual Heartbeat Monitoring

Every node emits a heartbeat at a configurable interval (default: 30s):
- **Desktop → VPS agents**: "Coordinator alive" (sent by `citadel-service`, not the app)
- **VPS → Desktop**: "Agent alive" (existing AgentPoller, promoted to bidirectional)
- **VPS → VPS**: "Peer alive" (new — agents know about each other)

**HMAC Authentication** *(v0.2.8)*: All heartbeats must be **HMAC-signed** with pre-shared keys distributed during agent deployment. This prevents a compromised node from spoofing heartbeats to make the mesh think all nodes are healthy. Each node-pair has a unique HMAC key (Desktop↔VPS1, Desktop↔VPS2, VPS1↔VPS2). Keys are stored in Vault on desktop and in the agent's local config on VPS.

**Heartbeat Transport**: Heartbeats use a lightweight UDP-based protocol (not SSH) — SSH is too heavy for 30-second intervals. The HMAC-signed payload includes: sender ID, timestamp, sequence number, node health summary. The `citadel-service` (not the app) owns the heartbeat emitter, so SSH keys from Vault are not needed — only the lightweight HMAC key provisioned during deployment.

If a node misses 3 consecutive heartbeats from a peer, it considers that peer offline.

#### Autonomous Escalation

When an agent loses contact with the desktop coordinator:

| Phase | After | Action |
|-------|-------|--------|
| **Alert** | 3 missed heartbeats (~90s) | Agent logs warning, continues normal operation |
| **Heightened** | 5 missed heartbeats (~150s) | Agent tightens tripwire rules: lower thresholds, block on fewer failures, increase scan frequency |
| **Autonomous** | 10 missed heartbeats (~5min) | Agent operates fully independently — all decisions local, events queued for later sync |
| **Peer Alert** | Concurrent with Heightened | Agent tells other VPS agents: "Desktop is offline" |

#### Secondary Brain Designation

One VPS can be designated as the **secondary coordinator** (fallback brain):
- Receives a copy of the asset registry (sanitized — no raw secrets, only public keys and connection info)
- Can run a lightweight AI Bridge (Claude Code CLI or API) for command-level decisions
- Takes over event collection and strategic analysis if desktop is offline
- Relinquishes control when desktop comes back online (see Recovery Protocol below)

**Secondary Brain Hardening** *(v0.2.8)*: The secondary brain VPS is a high-value target — it has an API key and coordination authority. Additional hardening required:
- Restricted SSH access (key-only, non-standard port, fail2ban with aggressive thresholds)
- Encrypted API key storage (not plaintext in config — use OS keyring or encrypted file)
- Separate credentials from regular shield agents (compromise of a regular agent doesn't expose the brain)
- Rate-limited outbound API calls (prevent a compromised brain from draining API quota)
- Audit logging of all coordination decisions (append-only, shipped to desktop on reconnect)

#### Recovery / Reconciliation Protocol *(v0.2.8)*

When the desktop coordinator comes back online after being dark:

1. **Sync missed events**: Desktop pulls all events queued by agents during the outage (same `citadel-shield events --since` mechanism, but for potentially large backlogs)
2. **Merge secondary brain decisions**: If the secondary brain made coordination decisions (IP blocks, escalations, mode changes), desktop reviews and either accepts or overrides them
3. **Conflict resolution**: Desktop wins — any decision the secondary brain made that conflicts with desktop policy is rolled back
4. **Heartbeat restoration**: Desktop resumes emitting heartbeats, agents drop back from autonomous/heightened to normal mode
5. **Audit reconciliation**: Secondary brain's append-only audit log is merged into the desktop's master audit trail

#### Compartmentalized Secrets

Each node only has the credentials it needs:
| Node | Has access to |
|------|--------------|
| Desktop | Vault (all secrets), all SSH keys, full asset registry, all HMAC keys, master audit log |
| VPS Agent | Its own config, peer heartbeat HMAC keys, escalation endpoint, rate-limited SCS API token |
| Secondary Brain | Asset registry (read-only), its own SSH key, encrypted API key for Claude, coordination audit log |

No single VPS compromise exposes the entire system.

---

### Why This Approach Wins

**Traditional security software**:
- Static rules and signatures
- Attackers study the code (if open source) or reverse engineer (if closed)
- Easily defeated once patterns are known

**Citadel Archer's AI approach**:
- Learns each user's unique environment
- Adapts to novel attack techniques
- Even if attackers know our architecture, they can't predict the AI's decisions
- Each installation is effectively a unique defense system

---

## Technical Architecture

### Technology Stack

**Desktop Application:**
- **Language**: Python 3.11+
- **GUI Framework**: Microsoft Edge app mode (`msedge.exe --app=URL`) — guaranteed on Windows 10/11, no external GUI framework dependency. Fallback to system `webbrowser` if Edge not found. *(decided v0.2.8 — pywebview removed)*
- **Frontend**: Vanilla JavaScript (ES6+ modules) with Web Components
- **Styling**: Tailwind CSS + custom glassmorphic components
- **State Management**: Native JavaScript (simple reactive patterns)
- **API**: FastAPI (local REST server at port 8000 + WebSocket at `/ws`)
- **Session Auth**: Cryptographically secure session tokens (256-bit, `secrets.token_urlsafe`) — X-Session-Token header, constant-time comparison to prevent timing attacks

**Backend Services:**
- **Guardian Agent**: Python with OS-specific libraries (watchdog for FS events, psutil for process monitoring)
- **Watchtower / Intel Pipeline**: Event aggregation (`event_aggregator.py`), anomaly detection (`anomaly_detector.py` — Isolation Forest via scikit-learn with Z-score fallback), threat scoring (`threat_scorer.py`), behavioral baselines (`context_engine.py`), guardian rule generation (`guardian_updater.py`), intel aggregation (`aggregator.py` + `otx_fetcher.py`)
- **Vault**: SQLCipher database-level encryption + per-entry AES-256-GCM via `cryptography` library
- **SecureChat**: Python ChatManager + SQLite persistence + WebSocket push + AI Bridge (Anthropic SDK); future: WebRTC (aiortc), libsodium for P2P
- **Intel**: OTX/AlienVault integration (`otx_fetcher.py`), IOC/CVE/TTP models with SQLite store; future: more feeds + local LLM (Ollama)
- **Remote Shield**: Lightweight Python agent (`agent/shield.py` — stdlib only, no pip deps), asyncssh-based SSH manager on desktop side
- **Panic Room**: Action framework (`panic/actions/`) with base class supporting execute/verify/rollback; playbook engine for orchestration

**Security (Implemented):**
- **Encryption at rest**: AES-256-GCM per-entry (Vault), SQLite databases for all stores
- **Encryption in transit**: TLS 1.3 for external APIs; localhost API is HTTP (same-machine only, session-token protected)
- **Session Authentication**: 256-bit tokens (`secrets.token_urlsafe`), `X-Session-Token` header, constant-time comparison (`api/security.py`, `core/auth.py`). Token generated on backend startup, fetched by frontend `api-client.js`.
- **Key Management**: PBKDF2 key derivation (600k iterations), Ed25519 keypairs for SSH (`remote/ssh_keygen.py`)
- **Audit Logging**: Event-level audit via `core/audit_log.py` (INFO/INVESTIGATE/ALERT/CRITICAL severity levels)
- **Planned**: Code signing for executables, hardware key support (YubiKey), append-only AI audit log, sandboxed components

**Deployment:**
- **Packaging**: PyInstaller for single-executable distribution
- **Updates**: Secure auto-update mechanism (signature verification)
- **Platform Support**:
  - **Phase 1**: Windows 10/11 (primary development and testing platform)
  - **Phase 2**: Ubuntu/Debian Linux (for VPS Remote Shield agent)
  - **Future**: macOS, other Linux distros

---

## User Experience

### First Launch Experience
1. **Welcome & Philosophy**: Brief intro to Citadel Archer's mission and defensive approach
2. **Choose Your Tier**: Free (bring your own API key) vs. Premium (we handle AI costs)
3. **AI Provider Setup**:
   - Free tier: Enter Claude or OpenAI API key
   - Premium tier: No setup needed (we handle it)
4. **Security Level Selection**: Choose Observer, Guardian, or Sentinel (explained with examples)
5. **Master Password Setup**: Create Vault master password (strong, memorable, we validate strength)
6. **Quick Scan**: Immediate assessment of current machine security (AI analyzes results)
7. **Guided Hardening**: Step-by-step AI-recommended fixes for identified issues
8. **Dashboard**: User sees their first "green status" and can explore features

### Daily Usage
- Launch app → Dashboard shows security status
- Glance at threat feed (any new alerts?)
- Everything green? Continue work with peace of mind
- Suspicious activity? Alert notification with recommended action
- One click to investigate, mitigate, or panic

### Emergency (Under Attack)
1. User suspects compromise or sees alert
2. Click **Panic Button** (prominent, red, impossible to miss)
3. System asks: "Isolate network? Rotate credentials? Lock down?"
4. User confirms → Automated response executes in <30 seconds
5. Dashboard shows "Safe Mode" with recovery steps
6. User follows guided recovery process

### Progressive Disclosure UX (Simplicity by Default)

**Core Principle**: Most users are NOT security experts. The UI must be simple, calm, and guided by AI explanations.

**Primary View (Default - For Everyone)**:
- 🟢 **Green Status**: "Everything is normal. You're protected."
- 🟡 **Yellow Alert**: "Something unusual detected. Investigating..." (AI explains what)
- 🔴 **Red Alert**: "Threat detected. [AI ACTION TAKEN]" (AI explains threat + response)

**AI Communication Style**:
```
❌ BAD (Technical Jargon):
"Detected process 'svchost.exe' (PID 4821) with suspicious memory
allocation pattern matching CVE-2024-1337 exploitation attempt.
Network connection established to 185.220.101.42:443 (known C2)."

✅ GOOD (Plain Language):
"🔴 THREAT BLOCKED
A suspicious program tried to connect to a known hacker server.
I stopped it and quarantined the file.

You're safe now. No action needed.

[Show Details] ← Click if you want to learn more"
```

**Advanced View (On-Demand)**:
User clicks "Show Details" to see:
- Technical details (process name, PID, CVE, IOCs)
- Attack timeline (what happened when)
- AI reasoning ("I blocked this because...")
- Forensic logs (for technical users or reporting)

**Alert Priority Levels** (AI decides):

1. **🟢 INFO** (No action needed):
   - "Windows Update installed successfully"
   - "New software detected: Visual Studio Code (safe)"
   - User sees: Subtle notification, dismisses automatically

2. **🟡 INVESTIGATE** (AI is checking):
   - "Unusual network activity from Chrome. Checking..."
   - "File modified in System32. Verifying legitimacy..."
   - User sees: AI is working on it, will update soon

3. **🟠 ALERT** (AI took action, user informed):
   - "Blocked connection to suspicious website"
   - "Quarantined file matching malware signature"
   - User sees: What happened, what AI did, why they're safe

4. **🔴 CRITICAL** (User decision needed):
   - "Ransomware detected. I blocked it. Panic Room recommended?"
   - "Multiple failed login attempts. Credential rotation suggested?"
   - User sees: Clear explanation + recommended action

**Dashboard Simplification**:

**Simple Mode** (Default):
```
┌────────────────────────────────────┐
│  🟢 You're Protected                │
│                                     │
│  Last Scan: 2 minutes ago          │
│  Threats Blocked Today: 3          │
│  Everything looks good!            │
│                                     │
│  [View Details] [Settings]         │
└────────────────────────────────────┘
```

**Advanced Mode** (Click "View Details"):
```
┌────────────────────────────────────┐
│  Guardian Status: Active            │
│  - File Monitor: 1,247 events/hr   │
│  - Process Monitor: 43 processes   │
│  - Network Monitor: 12 connections │
│                                     │
│  Threats Blocked Today: 3          │
│  - 2x Malicious URLs (Chrome)      │
│  - 1x Suspicious Process (killed)  │
│                                     │
│  [Forensic Logs] [Export Report]   │
└────────────────────────────────────┘
```

**Proactive Action > Reactive Questions**:

**CRITICAL PRINCIPLE**: AI acts FIRST (within security level), asks RARELY.

**When AI ACTS AUTONOMOUSLY (No Questions)**:
- ✅ Known malware signatures → Quarantine immediately, inform user
- ✅ Known C2 servers → Block connection immediately, inform user
- ✅ Obvious malicious behavior → Kill process, inform user
- ✅ Suspicious but low-risk → Monitor closely, inform if escalates
- ✅ 95%+ confidence it's a threat → Act first, explain after

**When AI MIGHT Ask (RARE, <5% of cases)**:
- ⚠️ Ambiguous activity with HIGH potential impact (e.g., process wants to delete entire user folder)
- ⚠️ User-initiated action that looks dangerous (e.g., user about to run ransomware.exe they downloaded)
- ⚠️ Conflicting signals (legitimate software behaving suspiciously)

**Example - AI Acts Proactively** (95% of cases):
```
┌────────────────────────────────────┐
│  🟠 THREAT BLOCKED                  │
│                                     │
│  "I blocked 'update.exe' from      │
│  connecting to a suspicious server.│
│                                     │
│  This looked like malware trying   │
│  to download more threats. I       │
│  quarantined it for safety.        │
│                                     │
│  You're protected. ✓               │
│                                     │
│  [Show Details] [Restore if Safe]  │
└────────────────────────────────────┘
```
*AI decided, acted, explained. User can override if needed.*

**Example - AI Asks (RARE, <5% of cases)**:
```
┌────────────────────────────────────┐
│  🟡 UNUSUAL - Your Input Needed     │
│                                     │
│  "You're about to run 'crack.exe'  │
│  which looks like piracy/malware.  │
│                                     │
│  I STRONGLY recommend blocking it. │
│                                     │
│  But you downloaded it, so maybe   │
│  you know something I don't?       │
│                                     │
│  [🛡️ Block (Recommended)] [✅ Run]│
└────────────────────────────────────┘
```
*AI asks because user explicitly initiated this action.*

**Decision Tree**:
```
Threat Detected
    ↓
Is confidence >95%?
    ↓ YES → ACT NOW (block/quarantine/kill) → Inform user after
    ↓ NO
Is user explicitly involved?
    ↓ YES → Ask user (they might know context)
    ↓ NO → ACT CONSERVATIVELY (monitor, log) → Escalate if needed
```

**Settings: Verbosity Control**:

Users can adjust how much detail they want:
- **Minimal**: Only show critical alerts requiring user action
- **Balanced** (Default): Show threats + AI actions taken
- **Detailed**: Show everything including INFO-level events
- **Expert**: Full technical logs, real-time event stream

**Onboarding Sets Expectations**:

During first launch, AI asks:
```
"How comfortable are you with security alerts?

🟢 Beginner: Show me only what I need to know, explain everything
🟡 Intermediate: I know some security basics, give me context
🔴 Expert: Give me all the technical details"
```

This sets the default verbosity + UI complexity.

**Key UX Principles**:

1. ✅ **Assume user is NOT a security expert**
2. ✅ **AI is the trusted advisor, not an alarm system**
3. ✅ **ACT FIRST, inform AFTER** (proactive protection, not reactive questions)
4. ✅ **Questions are RARE** (<5% of cases, only when truly ambiguous + high impact)
5. ✅ **Default to calm, clear, actionable language**
6. ✅ **Technical details available on-demand, not forced**
7. ✅ **Color coding is universal** (🟢 = safe, 🟡 = checking, 🟠 = action taken, 🔴 = critical)
8. ✅ **"You're safe" is the most important message**
9. ✅ **Reduce alert fatigue** (don't cry wolf about normal activity)
10. ✅ **User can override AI decisions** (restore quarantined files, unblock if false positive)

---

## Success Metrics

### Security Effectiveness
- **Detection Rate**: % of known threats detected in testing
- **False Positive Rate**: Keep under 1% (don't cry wolf)
- **Response Time**: Average time from detection to mitigation
- **Recovery Time**: Time from panic button to restored confidence

### User Experience
- **Time to First Green**: How quickly can new user secure their machine?
- **Daily Interaction Time**: Should be <30 seconds unless incident
- **User Confidence Score**: Self-reported "I feel safe" metric
- **Community Growth**: Active users, contributors, shared threat intel

### Technical Performance
- **Resource Usage**: CPU/RAM footprint (should be minimal)
- **Agent Uptime**: Reliability of monitoring agents
- **Update Success Rate**: Auto-updates that work smoothly
- **Crash Rate**: Target 99.9% stability

---

## Development Roadmap

**Legend**: `[x]` = implemented, `[~]` = partially implemented, `[ ]` = not yet implemented

### Phase 1: Foundation (Months 1-3)
- [x] Core Guardian agent (file monitoring via watchdog, process monitoring via psutil — `guardian/file_monitor.py`, `guardian/process_monitor.py`)
- [x] Basic Dashboard (system status, Web Components, real-time WebSocket updates, tab-based navigation)
- [x] Vault (AES-256-GCM encryption, PBKDF2 key derivation 600k iterations, rate-limited unlock, SSH credential support)
- [x] Threat detection rules engine (`intel/guardian_updater.py` — auto-generates rules from IOCs/TTPs/CVEs, severity mapping, conflict resolution)
- [x] Initial dark glassmorphic UI (CSS design tokens, neon blue #00D9FF, glassmorphic cards with backdrop-filter blur, responsive breakpoints)
- [x] Browser extension inventory scan — `ExtensionScanner` enumerates extensions across Chrome/Edge/Brave/Vivaldi, parses manifest.json, analyzes permission risk (4 levels), detects install source (web store/sideloaded/enterprise/dev), emits events to EventAggregator (`guardian/extension_scanner.py`, v0.3.15)

**Milestone**: User can secure their local machine, store secrets, and view real-time threat dashboard. Browser extension audit planned for Phase 2.

### Phase 2: Intelligence & VPS Protection (Months 4-6) 🔥 **PRIORITY**
**Focus**: Add AI threat analysis + Extend protection to VPS (Ubuntu) + SecureChat as foundational communication layer

**SecureChat Foundation** *(v0.2.6 — foundational, not Phase 4)*:
- [x] Chat message model + SQLite persistence (`data/securechat.db`)
- [x] ChatManager — message routing, command dispatch, listener pattern
- [x] Always-visible chat sidebar in dashboard (independent of tab-loader)
- [x] REST API + WebSocket push for real-time messages
- [x] "add vps" command — conversational VPS onboarding (key gen, verify, register)
- [x] "deploy agent" command — agent deployment through chat
- [x] AI assistant integration — AI Bridge (`chat/ai_bridge.py`) connects Claude API to SecureChat with tool use, context building, and graceful degradation

**Intelligence Layer**:
- [x] Intel module — 4 threat feeds active: OTX/AlienVault (`intel/otx_fetcher.py`), abuse.ch URLhaus+ThreatFox (`intel/abusech_fetcher.py`), MITRE ATT&CK STIX 2.1 (`intel/mitre_fetcher.py`), NVD CVE API v2.0 (`intel/nvd_fetcher.py`). Aggregator with dedup + scheduling (`intel/aggregator.py`), IOC/CVE/TTP/Vulnerability models (`intel/models.py`), SQLite store. Daily fetch at 02:00 UTC. (v0.3.13)
- [x] Watchtower — asset inventory + multi-asset dashboard (`intel/assets.py`, `intel/asset_view.py`), cross-asset threat correlation engine (`intel/cross_asset_correlation.py` — 4 correlation patterns: shared IOC, coordinated attack, propagation, intel match; sliding windows, dedup, rate-limited escalation to SecureChat), API endpoints (`/api/correlations`, `/api/correlation-stats`) (v0.3.14)
- [x] AI-powered anomaly detection — context engine with 7-day rolling behavioral baselines (`intel/context_engine.py`), anomaly detector with Isolation Forest + Z-score fallback (`intel/anomaly_detector.py`), threat scorer combining severity/anomaly/intel signals (`intel/threat_scorer.py`)
- [x] Automatic Guardian signature updates (`intel/guardian_updater.py` — auto-generates rules from IOC/TTP/CVE, severity mapping, conflict resolution, hot-reload callbacks)
- [x] Advanced UI — Chart.js charts (`charts.html`), D3.js interactive timeline (`timeline.html`), risk metrics with gauge + sparklines (`risk-metrics.html`), all with WebSocket real-time updates + 30s auto-refresh
- [ ] Browser extension runtime monitoring (behavior analysis, network traffic, injection detection) — **not yet implemented**
- [x] Extension threat intelligence — `ExtensionIntelDatabase` cross-references IDs against curated known-malicious database (6 families: spyware, adware, phishing, cryptostealer, bloatware, suspicious), dangerous permission signature detection (nativeMessaging+broad, debugger, management), custom blocklist support, thread-safe. `ExtensionWatcher` uses watchdog for real-time filesystem monitoring of extension installs with debounce + known-vs-new tracking. Events emitted: `system.extension_install`, `system.extension_malicious`. API endpoints: `GET /api/extensions/intel`, `GET /api/extensions/watcher` (v0.3.16)

**Remote Shield - VPS Protection**:
- [x] Lightweight Python agent for Ubuntu/Debian VPS (`agent/shield.py` — stdlib only)
- [x] Remote agent deployment via SSH (`remote/agent_deployer.py`)
- [x] Agent sensors: auth.log, process monitoring, cron changes, file integrity
- [x] Autonomous tripwire actions (IP blocking, process termination)
- [x] Background event sync (`remote/agent_poller.py` — 60s polling via SSH)
- [x] Critical event escalation to SecureChat (high-level summary, not raw data)
- [x] SSH hardening (key-only auth, port knocking, fail2ban++) — safety-first orchestrator with auto-rollback, iptables `recent` module port knocking, progressive banning (v0.3.10)
- [x] VPS firewall management (dynamic rules, geo-blocking, automated responses) — desktop-managed iptables rules with CITADEL-FW chain, geo-CIDR file, rate limiting, config hot-reload (v0.3.11)
- [x] Node onboarding orchestrator — 6-step automated enrollment (validate → connect → deploy → harden → firewall → verify) with retry + WebSocket progress (v0.3.11)
- [ ] Persistent encrypted C2 channel (certificate-based auth) — currently using SSH polling, future: persistent connection
- [x] AI threat analysis for VPS (same AI brain, different sensor) — REMOTE event category, RemoteShieldEscalation handler, VPS behavioral baselines (REMOTE_AUTH/REMOTE_SENSOR), 4 VPS threshold rules, enhanced AI tools (v0.3.12)

**Asset Management & Infrastructure** *(v0.2.5 — see [Addendum](ASSET_MANAGEMENT_ADDENDUM.md))*:
- [x] Asset database persistence (SQLite storage for managed assets)
- [x] Asset CRUD API (`POST/PUT/DELETE /api/assets`)
- [x] Asset management frontend (Add/Edit/Delete assets from dashboard)
- [x] Remote Shield agent auto-linking (agents auto-register as managed assets)
- [x] Remote Shield database persistence (agent + threat data survives restart)
- [x] Vault SSH credential type (store SSH keys/passwords with structured metadata)
- [x] SSH Connection Manager (`remote/ssh_manager.py` — asyncssh-based remote execution)

**Always-On Protection** *(v0.2.7 — designed here, implemented in Phase 5 alongside Defense Mesh)*:
- [ ] `citadel-service` Windows Service — headless Guardian sensors running 24/7
- [ ] Shared SQLite event store (service writes, app reads on connect)
- [ ] IPC channel (named pipe) for real-time event push when both are running
- [ ] Startup catch-up sync (AI trigger 3b — "While you were away..." summary)
- [ ] Heartbeat emitter in service (feeds defense mesh even when app is closed)

**AI Trigger Expansion** *(v0.2.7 — designed here, implemented incrementally across Phases 2-5)*:
- [x] Trigger 2b — Local Guardian critical events escalate to AI via SecureChat (`chat/guardian_escalation.py`: batching, dedup, rate limiting)
- [x] Trigger 2c — Panic Room activation/completion/failure escalate to AI via SecureChat (`panic/panic_manager.py`: 3 lifecycle points, non-blocking, defensive error handling)
- [x] Trigger 2d — Remote Shield VPS events escalate to AI via SecureChat (`chat/remote_shield_escalation.py`: REMOTE category filter, per-asset grouping, 15/hr rate limit, v0.3.12)
- [x] Trigger 3a — Scheduled daily security posture analysis (`chat/posture_analyzer.py`: 24h cycle, 5 data sources, graceful degradation, AI Bridge summary)
- [x] Trigger 3b — Startup catch-up (`chat/startup_catchup.py`: offline window detection from SYSTEM_STOP, multi-source data gathering, AI briefing)
- [x] Trigger 3c — Threshold breach detection (`chat/threshold_engine.py`: 10 rules (6 original + 4 VPS v0.3.12), hybrid COUNT/CORRELATION eval, cooldown, dedup, rate limiting)

**Hardening & Efficiency** *(v0.2.8 — designed here, implemented when Always-On Protection lands)*:
- [x] Threshold/correlation engine — ACS→SCS bridge for pattern detection and escalation dedup (`chat/threshold_engine.py`, v0.3.5)
- [x] Append-only AI audit log (`data/ai_audit.log`) — immutable record of all Claude API calls (`chat/ai_audit.py`, v0.3.6)
- [x] SCS API rate limiting — per-participant token quotas to prevent abuse (`chat/scs_quota.py`, v0.3.7)
- [x] SQLite WAL mode — for concurrent citadel-service writes / citadel-archer reads on shared event store (`core/db.py`, v0.3.8)

**Milestone**: System proactively detects threats across local machine AND VPS, with AI-powered analysis protecting both. **SecureChat provides the command-level communication channel for user + multiple AI agents. Desktop protection runs 24/7 via always-on service. All managed assets are persistent, editable, and SSH-accessible from the dashboard. Token minimization ensures AI is only invoked when automation can't resolve — threshold engine handles pattern correlation and dedup. Forge reaches user via Telegram when away.**

### Phase 3: Response (Months 7-9)
- [x] Panic Room (emergency response playbooks — `panic/playbook_engine.py` with pre-flight checks, async execution, rollback)
- [x] Automated credential rotation (`panic/actions/credential_rotation.py` — SSH keys, API tokens, passwords, vault update, 30-day archive)
- [x] Network isolation capabilities (`panic/actions/network_isolation.py` — iptables rules, whitelist, state capture, rollback)
- [x] Backup and recovery system (`panic/actions/secure_backup.py` — encrypted backup, integrity verification, restore)
- [x] Incident forensics and reporting (`panic/actions/system_snapshot.py` — process dumps, network state, file hashing, log collection)
- [x] **Asset scope selector** — multi-checkbox UI in panic-room.html, integrated with playbook execution *(v0.2.5)*
- [x] **Remote credential rotation** — SSH-based rotation with recovery key safety (`_rotate_ssh_keys_remote`, atomic authorized_keys update)
- [x] **Per-asset rollback** — `recovery_states` schema includes `asset_id` with per-asset UNIQUE constraint, rollback filters by `target_assets`, results keyed by `component:asset_id` (v0.3.9)

**Milestone**: One-click response to active attacks **across all managed assets (local + remote)**

### Phase 4: Advanced Communications & AI (Months 10-12)
**Focus**: Extend SecureChat with peer-to-peer encrypted messaging and advanced AI integration
- [x] E2E encrypted peer-to-peer messaging (Signal protocol or similar)
- [x] Local LLM integration (Ollama) for fully offline AI assistant
- [x] Secure file sharing (encrypted, time-limited, self-destructing)
- [x] Contact management and trusted peer registry
- [x] Inter-agent communication protocol (AI agent-to-AI agent coordination via SCS)
- [x] Secure invitation-based agent enrollment (one-time codes for external AI agent onboarding)
- [x] Invitation flow UI in Assets tab (generate + copy invitation from dashboard)

**Milestone**: SecureChat extends from system backbone to full secure communications platform with multi-AI agent coordination

### Phase 5: Family & Multi-System Orchestration (Months 13-15)
**Focus**: Extend protection to family computers + Advanced multi-system management

**Family Computer Protection**:
- [x] Windows Remote Shield agent (for family PCs)
- [x] Simplified "protected mode" for non-technical users
- [x] Remote monitoring without overwhelming alerts
- [x] Automated patching (OS and software updates)
- [x] Easy deployment (email invite → one-click install)

**Multi-System Orchestration**:
- [x] Unified dashboard for all protected systems (local, VPS, family PCs)
- [x] Cross-system threat correlation (attack on one system alerts others)
- [x] Group policies (apply security rules to multiple systems)
- [x] Remote panic capabilities (isolate any system from dashboard)
- [x] Backup and sync across systems
- [x] Performance analytics (which systems need attention)

**Defense Mesh** *(v0.2.7, hardened v0.2.8)*:
- [x] Mutual heartbeat protocol (desktop ↔ VPS, VPS ↔ VPS, configurable interval)
- [x] HMAC-signed heartbeats with pre-shared keys (lightweight UDP, not SSH) *(v0.2.8)* — `mesh_keys.py` HMAC-SHA256 with PSK, domain separation, constant-time verify (v0.3.36)
- [x] Autonomous escalation behavior (agents tighten rules when coordinator goes dark) — `autonomous_escalation.py` progressive defense: ALERT→HEIGHTENED→AUTONOMOUS with policy engine (v0.3.37)
- [x] Peer alerting (surviving nodes notify each other of failures)
- [x] Secondary brain designation (fallback VPS coordinator with lightweight AI)
- [x] Secondary brain hardening (restricted SSH, encrypted API key, separate credentials, rate-limited API) *(v0.2.8)*
- [x] Compartmentalized secrets (each node only has credentials it needs)
- [x] Recovery/reconciliation protocol (sync events, merge decisions, desktop resumes control) *(v0.2.8)* — v0.3.42
- [x] Multi-AI agent authentication (API tokens for Claude Code, Forge, OpenClaw in SecureChat) — `AgentRegistry` with SHA-256 token hashing, Bearer auth, rate limiting (v0.3.3)
- [x] AI trigger 1b — External AI agent messages via REST API — `agent_api_routes.py`, 5 endpoints, dual auth model (v0.3.3)
- [x] Escalation deduplication (correlate same-attack events from multiple agents) *(v0.2.8)* — v0.3.43

**Milestone**: Protect entire digital ecosystem (user's machines + VPS + family) from single dashboard. **Defense mesh ensures no single point of failure — system continues operating even if primary coordinator is compromised or offline.**

### Phase 6: Community & Polish (Months 16-18)
- [ ] Voice/video calls (WebRTC, encrypted)
- [ ] Third-party security audit (annual)
- [ ] Community threat sharing (anonymized, opt-in)
- [ ] Plugin architecture for extensions
- [ ] Comprehensive documentation and tutorials
- [ ] Beta program for early adopters
- [ ] Premium tier launch

**Milestone**: Production-ready, audited, and scalable platform

---

## Monetization Strategy

### Licensing & Business Model

**Proprietary Software with Free Tier** - Citadel Archer is **not open source** to protect defensive algorithms from attackers. However, we remain committed to accessibility and transparency through:
- Free tier for individuals
- Third-party security audits (public reports)
- Clear documentation of capabilities
- User-controlled data (no vendor lock-in)

### Tier Structure

#### 🆓 Free Tier: "Defender"
**Target**: Individual users, activists, journalists, students

**Includes**:
- ✅ Full Guardian local protection
- ✅ Basic Watchtower monitoring
- ✅ Vault password manager (unlimited passwords)
- ✅ Manual threat intel updates
- ✅ Observer & Guardian security levels
- ✅ Community threat intelligence (receive only)
- ⚠️ **Requires**: User brings their own AI API key (Claude, OpenAI, etc.)
- ⚠️ **Limitation**: AI analysis rate-limited by user's API quota

**Cost**: $0 forever

**Why free tier?**
- Security should be accessible to all
- Activists and journalists need protection without payment barriers
- Builds community and word-of-mouth growth
- Users become advocates when they see value

---

#### 💎 Premium Tier: "Sentinel"
**Target**: Power users, small teams, freelancers

**Everything in Free, PLUS**:
- ✅ **Subsidized AI access** (no need for your own API key - we handle it)
- ✅ Sentinel security level (maximum AI autonomy)
- ✅ Automatic real-time threat intel updates
- ✅ Priority support (email, <24hr response)
- ✅ SecureChat AI assistant with subsidized API access (no BYOK needed)
- ✅ SecureChat P2P messaging with unlimited contacts *(Phase 4)*
- ✅ Up to 3 remote systems (VPS, family PCs)
- ✅ Advanced forensics and reporting
- ✅ Community threat intelligence (send & receive)

**AI Usage Included**:
- Up to 10,000 AI requests/month (covers typical usage)
- Equivalent to ~$50-75 of API costs at retail rates
- We negotiate bulk pricing to offer this at lower cost

**Cost**: $19.99/month or $199/year (save 17%)

**Value proposition**:
- Save money vs. buying your own AI API credits
- No usage anxiety - we handle the AI costs
- More features and faster updates
- Support real humans who respond

---

#### 🏢 Enterprise Tier: "Fortress"
**Target**: Small businesses, agencies, security teams

**Everything in Premium, PLUS**:
- ✅ **Unlimited AI access** (no rate limits)
- ✅ Unlimited remote systems (VPS, employee machines, servers)
- ✅ Centralized management dashboard
- ✅ Team collaboration features
- ✅ Custom threat intel feeds
- ✅ Dedicated account manager
- ✅ Priority support (phone, Slack, <4hr response, 24/7 emergency)
- ✅ Custom playbooks and automation
- ✅ Compliance reporting (SOC 2, GDPR, HIPAA-ready logs)
- ✅ Volume discounts for seats

**AI Usage Included**:
- Unlimited AI requests
- Optional: Private AI deployment (your own API key + our infra)
- Optional: Fine-tuned models for your specific environment

**Cost**: Custom pricing (starts at $99/user/month, volume discounts)

**Why Enterprise?**
- SMBs need security but can't afford dedicated teams
- Managed service feel without managed service costs
- We handle the AI complexity and scaling

---

### Revenue Projections

**Year 1 Goals** (Post-MVP):
- 10,000 free tier users (word of mouth, community)
- 500 premium subscribers ($120K ARR)
- 5 enterprise customers ($60K ARR)
- **Total Year 1**: ~$180K ARR

**Year 2 Goals**:
- 50,000 free tier users
- 2,500 premium subscribers ($600K ARR)
- 25 enterprise customers ($300K ARR)
- **Total Year 2**: ~$900K ARR

**Path to profitability**:
- Break even at ~150 premium subscribers (covers hosting, AI costs, 1 FTE)
- Profitable at 250+ premium subscribers
- Enterprise deals accelerate profitability

---

### Why This Model Works

**For Users**:
- Free tier removes barriers to entry
- Premium tier is cheaper than buying AI API access directly
- Enterprise tier provides white-glove service for businesses

**For Us**:
- Free tier builds user base and reputation
- Premium tier provides predictable recurring revenue
- Enterprise tier funds rapid development and infrastructure
- LLM bulk pricing gives us margin (buy at $0.003/1K tokens, effective user cost ~$0.005/1K tokens)

**Competitive Advantage**:
- Most security tools are either expensive enterprise products OR free but feature-limited
- We're high-quality AND accessible
- AI-centric approach is novel - no direct competitors yet
- Proprietary algorithms can't be copied by open source alternatives

---

### Future Monetization Opportunities (Phase 3+)

1. **White-label licensing** - Security companies can rebrand and resell
2. **Managed Security Service** - We monitor and respond for you (SOC-as-a-service)
3. **Threat Intel Marketplace** - Organizations can purchase curated threat feeds
4. **Training & Certification** - Courses on using Citadel Archer effectively
5. **API Access** - Other security tools can integrate with our threat intelligence

---

## Security Considerations

### Threat Model
**What we protect against:**
- Malware and ransomware
- Phishing and social engineering
- Remote intrusions and lateral movement
- Credential theft and reuse
- Data exfiltration
- Persistent backdoors
- Zero-day exploits (through behavior analysis)
- **Browser extension threats** (unauthorized extensions, sideloaded spyware, keystroke loggers, DOM injection)

**What we DON'T protect against:**
- Nation-state actors with unlimited resources (but we make it harder)
- Physical access to unlocked machine
- User intentionally disabling protection
- Supply chain attacks on hardware (beyond our scope)

### Privacy Guarantees
- **Local-first**: All data stored on user's machine, not cloud
- **No telemetry**: Zero data collection without explicit user opt-in
- **Third-party audits**: Annual security audits by reputable firms (published reports)
- **Encrypted everything**: Data at rest and in transit (AES-256, TLS 1.3)
- **User control**: User owns their data, can export/delete anytime
- **Transparent capabilities**: Clear documentation of what the AI can access and do

### Attack Surface Minimization
- Principle of least privilege (no unnecessary permissions)
- Code signing and integrity verification
- Minimal dependencies (reduce supply chain risk)
- Sandboxed components where possible
- Regular security audits and penetration testing
- **Browser extension audit and protection** (see Guardian module)

### Browser Extension Attack Surface (v0.2.4)

> For full detection capabilities, response actions, and dashboard integration, see **Guardian → Browser Extension Protection** in Core Modules.

Browser extensions represent a critical and often overlooked attack vector:
1. **Invisible code injection** into every page (including localhost security dashboards)
2. **Silent sideloading** by software bundlers, OEM utilities, or registry manipulation
3. **Auto-update abuse** — benign extensions become malicious post-install
4. **Cross-browser contamination** — Edge extensions affect Chrome-intended pages on Windows
5. **Keystroke logging** — many extensions admit to collecting keystrokes in their privacy disclosures
6. **Excessive permissions normalized** — `<all_urls>` + `webRequest` = full MITM capability

**Defense**: Inventory → Classify (risk score by permissions/source/behavior) → Alert → CSP enforcement → User education. *See Guardian module for details.*

---

## Decided Architecture (Locked In)

1. ✅ **Platform Priority**: Windows 10/11 first, Ubuntu for VPS agents second
2. ✅ **AI Models**: Cloud LLMs (Claude API, OpenAI) for MVP; add local Ollama support in later phase
3. ✅ **Update Mechanism**: Notify + one-click install with signature verification
4. ✅ **SecureChat Architecture**: Foundational system communication layer (local ChatManager + SQLite + WebSocket) for MVP; P2P encrypted messaging with peers in Phase 4
5. ✅ **Two-Tier Communication Model**: *(merged into #13 — see below for full description)*
6. ✅ **Threat Intel Sources**: AlienVault OTX, abuse.ch (URLhaus, MalwareBazaar), MITRE ATT&CK, NVD/CVE feeds
7. ✅ **Licensing**: Proprietary with free tier (protects defensive algorithms from attackers)
8. ✅ **Monetization**: Freemium model with LLM access subsidies and premium features
9. ✅ **AI Autonomy**: Hybrid approach (auto-respond to known threats, ask for novel situations)
10. ✅ **AI Access Level**: User-configurable (Observer/Guardian/Sentinel security levels)
11. ✅ **Hardware Keys**: Phase 2 or 3 (not critical for MVP)
12. ✅ **AI Invocation Model**: In-process AI Bridge (Anthropic SDK) as primary; external CLI scripts as secondary for complex analysis. AI is invoked on demand, not persistent. Context built fresh each call from persistent stores (chat history, system state).
13. ✅ **Communication Tiers** *(v0.2.7)*: Two formally named tiers — Automation Communication System (ACS) for sensor/metric/heartbeat data (no AI, no tokens), SecureChat System (SCS) for command-level attention (user, AI agents, escalations, strategic decisions).
14. ✅ **Always-On Protection** *(v0.2.7)*: Desktop split into `citadel-service` (Windows Service, runs 24/7, headless Guardian sensors + heartbeat emitter) and `citadel-archer` (desktop app, UI + AI + Vault, user-launched). Service handles ACS; app handles SCS.
15. ✅ **Multi-AI Participation** *(v0.2.7)*: SecureChat supports multiple AI agent types as participants — Claude Code instances (per-device), Forge (user's AI assistant), OpenClaw agents (external), all authenticated via API tokens. Not limited to single in-process AI Bridge.
16. ✅ **Token Minimization** *(v0.2.8)*: 4-level escalation hierarchy — tripwire rules (no tokens) → threshold/correlation engine (no tokens) → AI analysis (tokens) → human decision (rare). Resolve at the lowest level possible.
17. ✅ **Heartbeat HMAC** *(v0.2.8)*: All defense mesh heartbeats HMAC-signed with pre-shared keys. Lightweight UDP transport (not SSH). Each node-pair has a unique key.
18. ✅ **Append-Only AI Audit** *(v0.2.8)*: All AI tool invocations logged to immutable append-only audit trail separate from securechat.db. Authoritative record of AI decisions.
19. ✅ **Forge/Telegram Channel** *(v0.2.8)*: Forge (user's AI assistant) reaches user via Telegram as out-of-band notification path. Three remote interaction paths: Forge/Telegram, Claude Code/SSH, SecureChat browser (future).
20. ✅ **Desktop GUI** *(v0.2.9)*: Microsoft Edge app mode (`msedge.exe --app=URL`) — no pywebview dependency. Edge is guaranteed on Windows 10/11. FastAPI backend serves frontend static files directly at port 8000.
21. ✅ **Session Authentication** *(v0.2.9)*: Cryptographically secure session tokens (256-bit via `secrets.token_urlsafe`), X-Session-Token header, constant-time comparison. Generated on backend startup, fetched by frontend `api-client.js`.
22. ✅ **Anomaly Detection ML** *(v0.2.9)*: scikit-learn Isolation Forest as primary anomaly detector with Z-score statistical fallback. 5-feature vector (hour, category, severity, event freq, asset freq). Sensitivity presets: LOW/MODERATE/HIGH. Cold-start protection: uses LOW threat until 20+ samples collected.
23. ⚠️ **Database Path Convention** *(v0.2.9 — known inconsistency)*: SecureChat uses `data/securechat.db` (relative to working dir), Vault uses `data/vault.db`, but Panic Room uses `/var/lib/citadel/panic/panic_sessions.db` and Intel uses `/var/citadel/intel.db` (absolute system paths). Needs normalization — target: all DBs under `data/` for portability, with configurable override for system-level services.

## Open Questions (Deferred to Later Phases)

1. **Community Features**: Anonymous threat sharing - what data is safe to share? (Phase 6)
2. **Mobile**: Native mobile app or just manage from desktop? (Phase 5+)
3. **Local LLM Integration**: Specific Ollama models and configuration (Phase 4+)
4. **SecureChat Relay**: Optional relay server architecture and deployment (Phase 4+)

---

## Glossary

- **ACS**: Automation Communication System — low-level tier for sensor data, heartbeats, metrics (no AI, no tokens)
- **C2**: Command and Control (attacker's remote access mechanism)
- **CVE**: Common Vulnerabilities and Exposures (public vulnerability database)
- **Defense Mesh**: Multi-node coordination protocol where each node monitors peers and can operate autonomously
- **E2E**: End-to-End Encryption
- **Forge**: The user's personal AI assistant — can reach the user via Telegram at any time
- **HMAC**: Hash-based Message Authentication Code — used to sign heartbeats and verify authenticity
- **IOC**: Indicator of Compromise (evidence of breach)
- **IDS**: Intrusion Detection System
- **MITRE ATT&CK**: Framework of adversary tactics and techniques
- **SCS**: SecureChat System — high-level tier for command-level communication (user, AI agents, escalations)
- **Threshold Engine**: Component between ACS and SCS that correlates patterns, deduplicates events, and escalates to SCS on threshold breach
- **Token Minimization**: Design principle — resolve at the lowest automation level before involving AI; tokens are expensive and add latency
- **VPS**: Virtual Private Server
- **WAL**: Write-Ahead Logging — SQLite mode enabling concurrent read/write access
- **Zero-day**: Previously unknown vulnerability

---

## Appendix: Design Inspiration

### UI/UX References
- Glassmorphism: [glassmorphism.com](https://glassmorphism.com)
- Neon blue aesthetic: Cyberpunk 2077 UI, Tron Legacy
- Security dashboards: Splunk, Datadog, Grafana (but prettier)

### Security Tool References
- **OSSEC**: Host-based IDS (inspiration for Guardian)
- **Snort/Suricata**: Network IDS (inspiration for Watchtower)
- **Bitwarden**: Password manager (inspiration for Vault)
- **Signal**: Secure messaging (inspiration for SecureChat)

---

**End of PRD v0.3.10**

*This is a living document. We'll iterate and refine as we build.*
