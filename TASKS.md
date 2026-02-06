# Phase 1 Tasks: Citadel-Archer Development

**Phase:** Phase 1 — Foundation
**Start Date:** 2026-02-06
**Target Completion:** 2026-02-27 (3 weeks)
**Total Tasks:** 25 items (organized by module)
**Est. Total Effort:** 80-100 development hours

---

## Task Organization

Tasks are grouped by module and ordered by dependency. **First 5 tasks are safe to start immediately** (Forge can spawn Dev Agent now).

**Color Coding:**
- 🟢 Ready to start (no dependencies)
- 🟡 Can start after dependency completes
- 🔴 Blocked (waiting on other task)
- ✅ Complete

---

## MODULE 1: Secrets Management (6 Tasks)

### T1.1 — Project Setup & Dependencies ⭐ START HERE

**Status:** 🟢 Ready  
**Effort:** S (Small)  
**Owner:** Dev Agent  
**Description:**
- Clone https://github.com/Mobivs/citadel-watch to `/projects/active/citadel-archer/citadel-watch-source/`
- Create Python virtual environment
- Install requirements: FastAPI, uvicorn, psutil, watchdog, click, sqlcipher3, pydantic
- Create directory structure: `/var/citadel/`, `/projects/active/citadel-archer/src/`
- Create initial `__init__.py`, config files
- Verify imports work (no broken dependencies)

**Acceptance Criteria:**
- [ ] venv created and activated
- [ ] All pip dependencies installed
- [ ] `python -c "import citadel_archer"` works
- [ ] No import errors in tests

**Blocking:** T1.2, T2.1, T3.1, T4.1, T5.1

---

### T1.2 — Secrets Store Foundation ⭐ START HERE

**Status:** 🟢 Ready  
**Effort:** M (Medium)  
**Depends On:** T1.1  
**Owner:** Dev Agent  
**Description:**
- Design secrets schema (secret_name, secret_value, created_at, last_rotated, last_accessed)
- Implement encryption using `python-age` library (PBKDF2 key derivation)
- Create SecretsStore class:
  - `add_secret(name, value)` → encrypts and stores
  - `get_secret(name)` → decrypts and returns
  - `rotate_secret(name, new_value)` → updates with timestamp
  - `list_secrets()` → returns names only (not values)
- Store encrypted vault in `/var/citadel/secrets.vault` (JSON structure, encrypted)
- Create unit tests for encryption/decryption roundtrips

**Acceptance Criteria:**
- [ ] SecretsStore class implemented
- [ ] Encryption/decryption verified (test vector)
- [ ] Secrets survive file I/O (encrypt → write → read → decrypt)
- [ ] Master key derived correctly from password
- [ ] `rotate_secret` updates last_rotated timestamp

**Blocking:** T1.3, T1.4, T1.5

---

### T1.3 — Scoped Access API

**Status:** 🟡 Can start after T1.2  
**Effort:** M  
**Depends On:** T1.2  
**Owner:** Dev Agent  
**Description:**
- FastAPI endpoints for secrets:
  - `POST /secrets/get` - Request secret by name (returns value if authorized)
  - `POST /secrets/rotate` - Rotate secret (only accessible by Forge)
  - `GET /secrets/list` - List secret names (for audit/inventory)
- Implement authorization: Only Forge can call endpoints (check API key header)
- Validate request: Agent name, timestamp, signature (Phase 1: simple header token, Phase 2: OAuth)
- Return secret value for short-lived injection into agent environment (max 1-minute cache, then discard)

**Acceptance Criteria:**
- [ ] POST /secrets/get returns secret value
- [ ] Unauthorized requests rejected
- [ ] Rotation updates secret in store
- [ ] List returns names only
- [ ] API key validation works

**Blocking:** T1.5 (logging integration)

---

### T1.4 — CLI Tool for Rotation

**Status:** 🟡 Can start after T1.2  
**Effort:** S  
**Depends On:** T1.2  
**Owner:** Dev Agent  
**Description:**
- Create Click CLI for secret management:
  - `citadel-secrets rotate <secret_name> <new_value>` - Rotate secret
  - `citadel-secrets add <secret_name> <value>` - Add new secret
  - `citadel-secrets list` - List all secret names (not values)
  - `citadel-secrets vault-status` - Check vault integrity
- Require master password for all operations (PBKDF2 key derivation)
- No output of secret values to stdout (security)

**Acceptance Criteria:**
- [ ] CLI parses arguments correctly
- [ ] Master password verification works
- [ ] Rotation updates vault file
- [ ] List shows names only
- [ ] Error handling for bad passwords

**Not Blocking:** (Parallel with T1.3)

---

### T1.5 — Audit Trail Integration

**Status:** 🟡 Can start after T1.3  
**Effort:** S  
**Depends On:** T1.3, T5.1 (audit logging)  
**Owner:** Dev Agent  
**Description:**
- When secret accessed: Log to audit.log
  - Event: `secrets_accessed`
  - Fields: agent_name, secret_name (NOT secret_value), timestamp, action (get/rotate)
- When secret rotated: Log to audit.log
  - Event: `secrets_rotated`
  - Fields: agent_name, secret_name, timestamp, old_value_hash (for verification, not actual value)
- Integration: Call audit logger from SecretsStore.get_secret() and .rotate_secret()

**Acceptance Criteria:**
- [ ] Access logged with agent name + secret name + timestamp
- [ ] Rotation logged with old_value_hash
- [ ] No plaintext secret values in logs
- [ ] Audit log appended (not overwritten)

---

### T1.6 — Secrets Documentation

**Status:** 🟡 Can start after T1.5  
**Effort:** S  
**Depends On:** T1.5  
**Owner:** Dev Agent  
**Description:**
- Document how to use secrets in Phase 1:
  - How Forge injects secrets at agent spawn
  - How to rotate a secret (CLI command)
  - How to audit secret access
  - Key recovery procedure (if master key lost)
- Document: `/projects/active/citadel-archer/docs/SECRETS_OPERATIONS.md`

**Acceptance Criteria:**
- [ ] Operations guide complete
- [ ] Examples for all CLI commands
- [ ] Recovery procedure documented

---

## MODULE 2: Guardian Agent (5 Tasks)

### T2.1 — File Monitoring Foundation

**Status:** 🟢 Ready  
**Effort:** M  
**Owner:** Dev Agent  
**Description:**
- Implement FileMonitor class using watchdog library
- Monitor critical paths: `/root/.ssh`, `/opt`, `/projects`, `/var/citadel`
- Detect events: created, deleted, modified, moved
- For each event, capture: path, event_type, timestamp
- Implement observer pattern: Start/stop monitoring
- Log all events to audit trail (via T5.1)
- No action yet (Phase 1: detection only, unless Guardian/Sentinel level)

**Acceptance Criteria:**
- [ ] Watchdog observer running
- [ ] File create/modify/delete detected
- [ ] Events logged with timestamp
- [ ] Can start/stop monitoring cleanly

**Blocking:** T2.2, T2.3, T2.4

---

### T2.2 — Process Monitoring Foundation

**Status:** 🟢 Ready  
**Effort:** M  
**Owner:** Dev Agent  
**Description:**
- Implement ProcessMonitor class using psutil
- Scan running processes every 5 seconds (configurable)
- Detect: New processes, process termination, parent-child relationships
- Capture: Process name, PID, parent PID, command line, user
- Compare snapshots: Detect anomalies (new process not in baseline)
- Log suspicious patterns to audit trail
- Phase 1: Detection and logging, no killing yet

**Acceptance Criteria:**
- [ ] Process scan runs every 5 seconds
- [ ] New process detected and logged
- [ ] Parent-child relationships tracked
- [ ] No false positives on normal processes

**Blocking:** T2.4

---

### T2.3 — Threat Rules Engine

**Status:** 🟡 Can start after T2.1 + T2.2  
**Effort:** M  
**Depends On:** T2.1, T2.2  
**Owner:** Dev Agent  
**Description:**
- Create RulesEngine class that evaluates file/process events against rules
- Phase 1 rules (hardcoded):
  - File rule: Executables (.exe, .dll) with double extensions → suspicious
  - File rule: Unsigned executables in System32 → suspicious
  - Process rule: Child process of Office app → suspicious (macro attack)
  - Process rule: Known crypto miner signatures → suspicious
  - Network rule: Outbound to known C2 IPs → suspicious (manual list)
- Each rule has: name, severity (low/medium/high), action (log, alert, block)
- Evaluation: File/process event → check against all rules → log matches
- Security levels control action:
  - Observer: Log only
  - Guardian: Log + alert + (optional) kill
  - Sentinel: Log + alert + kill

**Acceptance Criteria:**
- [ ] RulesEngine loads all Phase 1 rules
- [ ] File events evaluated against file rules
- [ ] Process events evaluated against process rules
- [ ] Matches logged with rule name + severity
- [ ] Security level controls action

**Blocking:** T4.1 (dashboard integration)

---

### T2.4 — Guardian Integration & Startup

**Status:** 🟡 Can start after T2.3  
**Effort:** M  
**Depends On:** T2.1, T2.2, T2.3  
**Owner:** Dev Agent  
**Description:**
- Create Guardian class that coordinates FileMonitor, ProcessMonitor, RulesEngine
- Startup: Load rules, start file monitor, start process monitor
- Event loop: Monitor for new events, evaluate against rules, log results
- Configuration: Security level (Observer/Guardian/Sentinel) stored in settings
- Status: Expose Guardian status via API (active/inactive, event count, last_event_time)

**Acceptance Criteria:**
- [ ] Guardian starts without errors
- [ ] File and process monitors running
- [ ] Rules evaluated on events
- [ ] Status API endpoint works
- [ ] Can change security level at runtime

**Blocking:** T4.1, T4.2 (dashboard integration)

---

### T2.5 — Guardian Tests

**Status:** 🟡 Can start after T2.4  
**Effort:** M  
**Depends On:** T2.4  
**Owner:** Dev Agent  
**Description:**
- Unit tests for FileMonitor (mock file system events)
- Unit tests for ProcessMonitor (mock process list)
- Unit tests for RulesEngine (test each rule independently)
- Integration test: Full Guardian startup + file/process changes
- Verification: Rules triggered correctly for known patterns

**Acceptance Criteria:**
- [ ] All unit tests pass
- [ ] Integration test creates file → Guardian detects → logs event
- [ ] Process spawn → Guardian detects → evaluates rule
- [ ] >90% code coverage for Guardian module

---

## MODULE 3: Vault (4 Tasks)

### T3.1 — Vault Database Setup

**Status:** 🟢 Ready  
**Effort:** M  
**Owner:** Dev Agent  
**Description:**
- Create SQLCipher database schema:
  - passwords table: (id, domain, username, encrypted_password, created_at, updated_at)
  - settings table: (key, value) for config
- Implement VaultDB class:
  - `__init__(master_password)` - Unlock with master password
  - `add_password(domain, username, password)` - Encrypt + store
  - `get_password(id)` - Decrypt + return
  - `list_passwords()` - List (domain, username) pairs only
  - `delete_password(id)` - Remove entry
  - `change_master_password(old, new)` - Re-encrypt all with new key
- Master password → PBKDF2 key derivation → SQLCipher encryption

**Acceptance Criteria:**
- [ ] SQLCipher database created
- [ ] Master password unlocks database
- [ ] Add/get/delete/list work correctly
- [ ] Passwords encrypted at rest (verify file is binary)
- [ ] Can change master password without losing data

**Blocking:** T3.2, T3.3

---

### T3.2 — Vault API Endpoints

**Status:** 🟡 Can start after T3.1  
**Effort:** M  
**Depends On:** T3.1  
**Owner:** Dev Agent  
**Description:**
- FastAPI endpoints:
  - `POST /vault/unlock` - Unlock vault with master password
  - `GET /vault/passwords` - List passwords (after unlock)
  - `POST /vault/passwords/add` - Add new password
  - `GET /vault/passwords/{id}` - Get password (auto-copy to clipboard)
  - `DELETE /vault/passwords/{id}` - Delete password
  - `POST /vault/change-master-password` - Change master password
  - `POST /vault/generate-password` - Generate random password
- Session management: Master password verified once per session, then use session token
- Clipboard auto-clear: After getting password, mark for clearance after 30 seconds

**Acceptance Criteria:**
- [ ] All endpoints implemented
- [ ] Master password validation works
- [ ] Passwords returned decrypted
- [ ] Session token used for subsequent requests
- [ ] Error handling for invalid passwords

**Blocking:** T4.2 (dashboard integration)

---

### T3.3 — Vault UI (Dashboard Integration)

**Status:** 🟡 Can start after T3.2  
**Effort:** M  
**Depends On:** T3.2, T4.2  
**Owner:** Dev Agent  
**Description:**
- Dashboard UI for vault:
  - Master password entry (if not already unlocked)
  - List view: All passwords (domain, username) with copy button
  - Add: Form for new password (domain, username, password) + generate option
  - Delete: Confirmation dialog for removal
  - Change master password: Form with old + new password
- Client-side: Fetch from `/vault/` endpoints, display results
- UX: Dark mode, glassmorphic design, consistent with Guardian display

**Acceptance Criteria:**
- [ ] Password list displays
- [ ] Can add new password via UI
- [ ] Copy button works (fetches decrypted password)
- [ ] Delete works with confirmation
- [ ] Change master password flow works

---

### T3.4 — Vault Tests

**Status:** 🟡 Can start after T3.3  
**Effort:** S  
**Depends On:** T3.3  
**Owner:** Dev Agent  
**Description:**
- Unit tests for VaultDB (add/get/delete)
- Unit tests for master password change
- Integration tests for API endpoints
- Test encryption/decryption roundtrip
- Test session management

**Acceptance Criteria:**
- [ ] All tests pass
- [ ] Vault survives master password change
- [ ] Passwords encrypted at rest verified

---

## MODULE 4: Dashboard (4 Tasks)

### T4.1 — Dashboard Backend Setup

**Status:** 🟢 Ready  
**Effort:** M  
**Owner:** Dev Agent  
**Description:**
- Create FastAPI app main structure
- Setup CORS (localhost only)
- Create WebSocket endpoint for real-time Guardian events
- Implement system status API:
  - `GET /api/status` - Guardian status, threat level, event count, last event time
  - `GET /api/events` - Recent Guardian events (last 50)
  - `GET /api/settings` - Current security level, vault status
  - `PUT /api/settings` - Update security level
- Broadcasting: When Guardian logs event, emit via WebSocket to all connected dashboards

**Acceptance Criteria:**
- [ ] FastAPI app starts on localhost:8000
- [ ] CORS allows localhost only
- [ ] WebSocket accepts connections
- [ ] Status API returns correct data
- [ ] Events broadcast to WebSocket clients

**Blocking:** T4.2, T4.3

---

### T4.2 — Dashboard Frontend (Vanilla JS)

**Status:** 🟡 Can start after T4.1  
**Effort:** L (Large)  
**Depends On:** T4.1  
**Owner:** Dev Agent  
**Description:**
- Frontend structure (vanilla JS, no build step):
  - `/static/index.html` - Main page
  - `/static/css/style.css` - Dark mode, glassmorphic design
  - `/static/js/app.js` - Main application logic
  - `/static/js/components/` - Web Components for modular UI
- Components:
  - status-display: Shows Guardian status, threat level (green/yellow/red)
  - event-log: Real-time list of file/process events
  - security-level-selector: Observer/Guardian/Sentinel radio buttons
  - vault-section: Password list, add/delete UI (integrated from T3.3)
  - hardening-section: VPS hardening task list (from T6.x)
- WebSocket client: Connect to `/ws`, listen for Guardian events, update UI in real-time
- Color scheme: Dark background, neon blue (#00D9FF) accents, red for threats
- Responsive: Works on different screen sizes (for Phase 2 GUI)

**Acceptance Criteria:**
- [ ] Page loads at http://localhost:8000
- [ ] Guardian status displays correctly
- [ ] Real-time events appear as they happen
- [ ] Security level selector updates settings
- [ ] No console errors
- [ ] Glassmorphic design matches PRD

**Blocking:** T4.3

---

### T4.3 — Dashboard Tests

**Status:** 🟡 Can start after T4.2  
**Effort:** S  
**Depends On:** T4.2  
**Owner:** Dev Agent  
**Description:**
- Test WebSocket connection (mock server)
- Test event display updates in real-time
- Test security level selector saves setting
- Test page layout (responsive)

**Acceptance Criteria:**
- [ ] WebSocket tests pass
- [ ] Event display tests pass
- [ ] UI responsive on mobile/tablet sizes

---

### T4.4 — pywebview Integration

**Status:** 🟡 Can start after T4.2  
**Effort:** M  
**Depends On:** T4.2  
**Owner:** Dev Agent  
**Description:**
- Create desktop app wrapper using pywebview:
  - Launches FastAPI backend in subprocess
  - Opens browser window pointing to localhost:8000
  - Single executable (Phase 1: just script, Phase 2: PyInstaller)
- System tray integration (Phase 1: basic, Phase 2: full)
- Config: Auto-start on boot (Phase 1: manual, Phase 2: systemd service)

**Acceptance Criteria:**
- [ ] pywebview app starts and shows dashboard
- [ ] Backend FastAPI runs in background
- [ ] Can close app without leaving zombie processes

---

## MODULE 5: Audit Logging (2 Tasks)

### T5.1 — Central Audit Logger

**Status:** 🟢 Ready  
**Effort:** M  
**Owner:** Dev Agent  
**Description:**
- Create AuditLogger class:
  - Logs events to `/var/citadel/audit.log` (JSON Lines format)
  - Each line is a JSON object: {timestamp, event_type, agent_name, fields...}
  - Append-only (never truncate/overwrite)
  - Rotation: Daily rollover to `.log.YYYY-MM-DD` (90-day retention)
  - Thread-safe (locks for concurrent writes)
- Event schema examples:
  ```json
  {"timestamp": "2026-02-06T14:55:00Z", "event": "agent_spawned", "agent": "dev_agent", "task": "t1_2"}
  {"timestamp": "2026-02-06T14:55:05Z", "event": "file_modified", "path": "/projects/active/citadel-archer/src/secrets.py"}
  {"timestamp": "2026-02-06T14:55:10Z", "event": "secrets_accessed", "agent": "dev_agent", "secret": "github_token"}
  {"timestamp": "2026-02-06T14:55:15Z", "event": "agent_ended", "agent": "dev_agent", "exit_code": 0}
  ```
- Logging points: Guardian events, secrets access, agent sessions, hardening script runs

**Acceptance Criteria:**
- [ ] AuditLogger writes JSON Lines
- [ ] File append-only
- [ ] Thread-safe writes
- [ ] Daily rotation working
- [ ] 90-day retention enforced

**Blocking:** T5.2, T1.5, T2.1, T2.2

---

### T5.2 — Log Viewer CLI

**Status:** 🟡 Can start after T5.1  
**Effort:** M  
**Depends On:** T5.1  
**Owner:** Dev Agent  
**Description:**
- Create Click CLI for log viewing:
  - `citadel-log view [--since 2h] [--event file_modified]` - View recent logs
  - `citadel-log search --agent dev_agent --event secrets_accessed` - Filter by field
  - `citadel-log anomaly [--hours 24]` - Flag unusual patterns
  - `citadel-log export --format csv --since 7d` - Export for analysis
- Anomaly detection (heuristics):
  - Agent running longer than 2 hours (unusual)
  - >100 file modifications in 1 minute (suspicious)
  - Secret accessed by unexpected agent (manual review)
  - Process killed by Guardian >5 times in 1 hour (attack?)
- Output: Human-readable (timestamp, event, details)

**Acceptance Criteria:**
- [ ] CLI parses arguments
- [ ] Filters work (agent, event type, time range)
- [ ] Anomalies flagged
- [ ] Export formats work

---

## MODULE 6: VPS Hardening (3 Tasks)

### T6.1 — Service & Port Audit

**Status:** 🟢 Ready  
**Effort:** S  
**Owner:** Dev Agent  
**Description:**
- Create audit script that reports:
  - Open ports (via `ss -tlnp`)
  - Running services (systemctl list-units)
  - Enabled-on-boot services
  - Network interfaces
  - Firewall rules (iptables / ufw)
  - SSH configuration (check for key-only auth, non-standard port)
- Output: JSON report to `/var/citadel/audit-baseline.json` (first run)
- Subsequent runs: Compare against baseline, show changes (drift detection)

**Acceptance Criteria:**
- [ ] Audit script runs without errors
- [ ] Reports open ports correctly
- [ ] Shows SSH config (should be key-only, port 65002)
- [ ] Firewall rules listed

**Blocking:** T6.2

---

### T6.2 — Hardening Script (Idempotent)

**Status:** 🟡 Can start after T6.1  
**Effort:** L  
**Depends On:** T6.1  
**Owner:** Dev Agent  
**Description:**
- Create idempotent hardening script:
  - Disable unnecessary services (cups, avahi, etc.) if running
  - Tighten SSH config: Key-only auth, disable password login, disable root login
  - Firewall rules: Allow SSH (22), HTTP (80), HTTPS (443) only
  - Fail2ban: Configure for SSH brute-force protection
  - Log rotation: Ensure logs rotate and don't fill disk
  - Kernel hardening: sysctl settings (disable IP forwarding, enable SYN cookies, etc.)
  - File permissions audit: Ensure critical files have correct permissions (/var/citadel, /root/.ssh)
- `--dry-run` mode: Print what would change without changing it
- Idempotent: Running twice produces same result (no double-application)
- Logging: Log all changes to audit trail

**Acceptance Criteria:**
- [ ] Script runs to completion
- [ ] `--dry-run` mode works
- [ ] Running twice produces no changes (idempotent)
- [ ] Critical files have correct permissions
- [ ] SSH configured for key-only auth
- [ ] Firewall allows only necessary ports

**Blocking:** T6.3

---

### T6.3 — Hardening Documentation

**Status:** 🟡 Can start after T6.2  
**Effort:** S  
**Depends On:** T6.2  
**Owner:** Dev Agent  
**Description:**
- Document hardening strategy:
  - What was hardened and why
  - How to run the hardening script (`--dry-run` first)
  - How to verify hardening was applied
  - How to troubleshoot if something breaks
  - Recovery procedure if hardening locks you out

**Acceptance Criteria:**
- [ ] Hardening guide complete
- [ ] Examples for all commands
- [ ] Recovery procedure documented

---

## MODULE 7: Testing & Integration (1 Task)

### T7.1 — End-to-End Integration Test

**Status:** 🟡 Can start after T4.4 + T5.2  
**Effort:** L  
**Depends On:** All major tasks completed  
**Owner:** Dev Agent  
**Description:**
- Full integration test:
  1. Start Citadel-Archer (Guardian + Dashboard + Vault + Secrets + Logging)
  2. Create a test file in monitored directory
  3. Guardian detects + logs to audit
  4. Dashboard shows event in real-time
  5. Log viewer displays event
  6. Vault stores/retrieves a password
  7. Change security level → action changes
  8. Rotate a secret → log event
  9. Run hardening script → apply changes safely
  10. All systems operational, no crashes, all logs clean

**Acceptance Criteria:**
- [ ] All modules start without errors
- [ ] File monitoring works end-to-end
- [ ] Dashboard displays real-time events
- [ ] Vault functional
- [ ] Secrets scoped and audited
- [ ] Log viewer works
- [ ] No critical errors in logs

---

## Task Dependencies Graph

```
T1.1 (Project Setup)
├─ T1.2 (Secrets Store) ← T1.3, T1.4, T1.5
├─ T2.1 (File Monitor) ← T2.2, T2.3
├─ T2.2 (Process Monitor) ← T2.3
├─ T3.1 (Vault DB) ← T3.2, T3.3
├─ T4.1 (Dashboard Backend) ← T4.2, T4.3, T4.4
├─ T5.1 (Audit Logger) ← T5.2

T2.3 (Rules Engine) depends on T2.1 + T2.2
T2.4 (Guardian Integration) depends on T2.1 + T2.2 + T2.3
T4.4 (pywebview) depends on T4.2
T6.1 (Service Audit) depends on nothing
T6.2 (Hardening Script) depends on T6.1
T7.1 (Integration Test) depends on all major tasks
```

---

## Parallelization Strategy

**Wave 1 (Start Now):** T1.1, T1.2, T2.1, T2.2, T3.1, T4.1, T5.1, T6.1
- All have no dependencies
- Can run in parallel
- ~40 hours work (can parallelize with multiple agents in Phase 2)

**Wave 2 (After Wave 1):** T1.3, T1.4, T1.5, T2.3, T3.2, T3.3, T4.2, T5.2, T6.2, T6.3
- Depend on Wave 1 tasks
- Most are independent from each other
- ~40 hours work

**Wave 3 (Final):** T2.4, T2.5, T3.4, T4.3, T4.4, T7.1
- Integration tasks
- Polish + testing
- ~20 hours work

---

## Success Metrics

**Phase 1 Complete When:**
- ✅ All 25 tasks completed
- ✅ All acceptance criteria met
- ✅ Integration test passes
- ✅ No P1/P2 bugs remaining
- ✅ Audit log captures all activity
- ✅ Scott can review agent logs in <5 minutes
- ✅ Team can use Citadel-Archer for ops

---

*Task breakdown created by: Forge (Liaison) + Scott (Product Owner)*
*Ready for Dev Agent to begin Phase 1 execution.*
