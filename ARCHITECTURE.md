# Architecture: Citadel-Archer Phase 1

**Version:** 1.0
**Date:** 2026-02-06
**Architect:** Forge (Liaison) + Scott (Product Owner)
**Tech Lead Input:** Opus Level Decision-Making

---

## 1. System Overview

**Citadel-Archer Phase 1** is a security foundation for:
1. **The Product:** Windows AI-centric security platform (from PRD v0.2.3)
2. **The Team:** Secure ops toolkit for autonomous dev team (from SPEC)

This architecture merges both requirements: Phase 1 builds the **foundation** that serves both the eventual commercial product AND the team's immediate operational security needs.

---

## 2. Module Architecture

### 2.1 Secrets Management Module

**Purpose:** Encrypted storage of credentials with scoped, audited access.

**Components:**
- **Encrypted Store:** Age encryption (lightweight, auditable, no heavy key management)
  - File-based store: `/var/citadel/secrets.vault` (encrypted)
  - Master key derivation: PBKDF2 (high iteration count, resistant to brute force)
  - Format: JSON structure, encrypted at rest with AES-256 equivalent (age)
- **Scoped Access Layer:** CLI + API that injects secrets only when needed
  - Agent requests secret by name at spawn time (not stored in environment permanently)
  - Forge logs access: agent name, timestamp, secret name (not value)
  - Rotation without re-deploy: CLI command updates vault, next agent spawn gets new value
- **Audit Trail:** Append-only log of all access (integrated with Action Logging)

**Data Flow:**
```
Forge spawns Dev Agent
  → Forge requests secret "github_token" from Secrets module
  → Secrets module logs access (Dev Agent, github_token, 14:55 UTC)
  → Secrets module injects value into agent's env vars
  → Dev Agent runs with secret
  → Secret never persists in logs or .env files
```

**Decision:** Age over GPG because simpler, more auditable, appropriate for single-VPS deployment.

---

### 2.2 Guardian Agent Module

**Purpose:** Real-time file and process monitoring (from PRD).

**Components:**
- **File Monitor:** Watchdog library + custom rules
  - Monitors critical paths: System32, Program Files, /opt, /root/.ssh, /projects
  - Detects: File creation/deletion, unauthorized modifications, suspicious extensions
  - Rules: Hardcoded for Phase 1 (dynamic rule updates in Phase 2)
- **Process Monitor:** psutil + behavior analysis
  - Detects: Crypto miners, keyloggers, privilege escalation, suspicious parents
  - Actions: Log, alert (Observer level), kill process (Guardian/Sentinel levels)
- **Threat Rules Engine:** Simple pattern matching
  - Known malware signatures (YARA-compatible format, Phase 2)
  - C2 IP/domain blocklist (manual for Phase 1)
  - Security level controls: Observer (report only), Guardian (auto-block known), Sentinel (aggressive)

**Data Flow:**
```
File changed on disk
  → Guardian detects via watchdog
  → Evaluates against rules
  → Logs to audit (file path, change type, timestamp, rule match)
  → If match + Guardian/Sentinel level: blocks/kills
  → If Observer level: alerts only
  → Dashboard shows real-time events
```

**Decision:** Watchdog + psutil because built-in, no external dependencies, works cross-platform (prep for Phase 2 Ubuntu).

---

### 2.3 Vault Module

**Purpose:** Encrypted password manager for user credentials (from PRD).

**Components:**
- **Database:** SQLCipher (encrypted SQLite)
  - Master password → PBKDF2 key derivation → AES-256 encryption
  - Schema: passwords table (domain, username, encrypted_password, created, updated)
  - Immutable created timestamp, updated timestamp for audit
- **UI/API:** FastAPI endpoints for CRUD
  - `/vault/passwords` - list (master password verified)
  - `/vault/passwords/add` - create new
  - `/vault/passwords/{id}/get` - retrieve (auto-clear clipboard after 30s)
  - `/vault/passwords/{id}/delete` - remove
  - `/vault/generate` - random password generation (configurable complexity)
- **Encryption:** Master password never stored, derived from user input each session

**Data Flow:**
```
User enters master password
  → PBKDF2 derives encryption key
  → Database unlocked (SQLCipher handles decryption)
  → User can view/edit passwords
  → Session ends, key discarded
  → Passwords remain encrypted at rest
```

**Decision:** SQLCipher because battle-tested, transparent encryption, no app-level decryption logic.

---

### 2.4 Dashboard Module

**Purpose:** Unified real-time security status (from PRD + SPEC).

**Components:**
- **Frontend:** Vanilla JS + Web Components (changed from React in PRD v0.2.3)
  - Dark mode, glassmorphic design, neon blue accents
  - No build step, direct ES6 modules
  - Embedded in pywebview (desktop app)
- **Backend:** FastAPI + WebSocket
  - REST endpoints for settings, password management, hardening tasks
  - WebSocket for real-time Guardian events
  - CORS: localhost only (not internet-facing)
- **Real-Time Updates:** Guardian → Dashboard via WebSocket
  - Events streamed as they happen
  - No polling, low latency
- **System Status Display:**
  - Guardian status (active/inactive, threat level)
  - Recent events (file changes, processes, alerts)
  - Security level selector (Observer/Guardian/Sentinel)
  - Vault entry count, last backup time

**Data Flow:**
```
Guardian detects file change
  → Emits event to WebSocket
  → Dashboard receives in real-time
  → UI updates threat level color (green/yellow/red)
  → User sees event in recent activity
```

**Decision:** Vanilla JS over React (from PRD v0.2.3) because:
- Fewer npm dependencies = smaller attack surface for security tool
- No build complexity
- Appropriate for simple dashboard UI
- Users can audit code more easily

---

### 2.5 Audit Logging Module

**Purpose:** Immutable forensic log of all system activity (from SPEC).

**Components:**
- **Central Log:** Append-only log file
  - Format: JSON Lines (one JSON object per line, easy to parse)
  - Location: `/var/citadel/audit.log` (rotated daily)
  - Encryption: Encrypted at rest (GPG or similar, Phase 1 decision: plaintext for now, Phase 2 encrypt)
  - Retention: 90 days rolling (configurable)
- **Events Logged:**
  - Agent session start/end (agent name, task, start time, end time, status)
  - Secrets accessed (agent, secret name, timestamp, operation)
  - File modifications (Guardian events, path, change type, rule matched)
  - Process alerts (process name, PID, action taken)
  - System changes (hardening script runs, firewall changes)
- **Log Viewer:** CLI tool + simple read API
  - `citadel-log view --since 2h` - last 2 hours
  - `citadel-log search agent=Dev --hours=24` - filter by agent, time range
  - `citadel-log anomaly --hours=24` - flag unusual patterns

**Data Flow:**
```
Any security event occurs
  → Emitted by relevant module (Guardian, Secrets, hardening script)
  → Audit logger formats as JSON
  → Appends to audit.log
  → Scott can review via log viewer (no database needed)
```

**Decision:** JSON Lines + plaintext for Phase 1 (simpler) → encryption in Phase 2.

---

### 2.6 Agent Sandboxing & VPS Hardening

**Purpose:** Enforce boundaries + harden infrastructure (from SPEC).

**Components (Phase 1):**
- **Filesystem Boundaries:**
  - Dev Agent: Read `/projects`, `/tmp/citadel-watch`, write `/projects/active/{task}/`, own git branch
  - Opus Lead: Read-only access to project state files
  - Forge: Full read access to project + VPS, controlled write access
  - Enforcement: File permissions (chmod), git branch protection, process confinement
- **VPS Hardening Script:**
  - Audit script: Reports open ports, running services, firewall rules
  - Idempotent hardening: Apply security baseline, can be run repeatedly
  - `--dry-run` mode: Shows what would change without changing it
  - Baseline snapshot: First run creates baseline, subsequent runs diff against it
- **Service Audit:**
  - Document what's running, what's exposed, what's unnecessary
  - Recommendations: Disable unused services, tighten firewall rules
  - Hostinger firewall already restricted to SSH (22), HTTP (80), HTTPS (443)

**Data Flow:**
```
Dev Agent spawned
  → Runs under restricted VPS user (citadel_dev or similar)
  → File permissions prevent access outside project directory
  → Git branch protection prevents pushes to main
  → All activity logged to audit.log
  → Forge reviews logs in log viewer
```

**Decision:** Convention + OS-level enforcement for Phase 1. Full containerization/AppArmor in Phase 2.

---

## 3. Technology Stack

| Component | Technology | Why |
|-----------|-----------|-----|
| **Secrets Encryption** | Age | Lightweight, auditable, no heavy key infrastructure |
| **Key Derivation** | PBKDF2 | Standard, resistant to brute force, built-in Python |
| **Vault Database** | SQLCipher | Transparent encryption, battle-tested, simple |
| **Password Encryption** | AES-256 | Industry standard, built into SQLCipher |
| **File Monitoring** | Watchdog | Cross-platform, simple API, real-time |
| **Process Monitoring** | psutil | Standard Python, cross-platform |
| **REST API** | FastAPI | Modern, fast, built-in validation, WebSocket support |
| **Real-Time** | WebSocket | Standard, low latency, no polling |
| **Frontend** | Vanilla JS + Web Components | No dependencies, auditable, appropriate for security tool |
| **Audit Logging** | JSON Lines + plaintext | Simple, parseable, portable (encrypt Phase 2) |
| **CLI** | Click (Python) | Standard, user-friendly, scriptable |
| **Desktop App** | pywebview | Lightweight Python wrapper, single executable |

---

## 4. Security Architecture

### 4.1 Threat Model

**Assets to Protect:**
1. Secrets (Anthropic API keys, Telegram credentials, git tokens, etc.)
2. Agent credentials (git branch access, file system access)
3. User passwords in Vault
4. Audit logs (evidence of who did what)
5. VPS itself (not compromised by agents)

**Threats:**
- Agent code goes rogue → accesses secrets outside scope
- Attacker compromises VPS → steals plaintext .env secrets
- Agent session logs exposure → credentials in plaintext
- Unauthorized file modification → system compromise

### 4.2 Mitigations

**For Stolen Secrets:**
- Encrypted at rest (age encryption, PBKDF2 key derivation)
- Injected only at agent spawn, not stored in env
- Scoped access (agent only gets what it needs)
- Audit trail (who accessed what, when)
- Rotation: Simple CLI command, no downtime

**For Agent Code Rogue:**
- File permissions prevent access outside project directory
- Git branch protection prevents pushes to main/others
- Process monitoring detects suspicious activity (Sentinel level)
- Audit logging records all file/process changes
- Kill switch: Forge can terminate agent, review logs

**For Audit Log Exposure:**
- JSON Lines format (human + machine readable)
- Phase 1: Plaintext (but restricted to root/Forge)
- Phase 2: Encrypt logs themselves
- Append-only (immutable history)

**For VPS Compromise:**
- Separate encryption key location (Phase 2 design)
- Daily snapshots + weekly Hostinger backups
- Key recovery procedure (documented Phase 1)
- Hardening script limits attack surface

---

## 5. Phase 1 Scope

### In Phase 1 (Foundation)

✅ **Secrets Management:**
- Encrypted store (age)
- Scoped access at spawn time
- Audit trail
- Rotation CLI

✅ **Guardian Agent:**
- File monitoring (watchdog)
- Process monitoring (psutil)
- Basic threat rules (signatures, C2 blocklist)
- Security levels (Observer/Guardian/Sentinel)

✅ **Vault:**
- SQLCipher database
- Master password
- Password CRUD
- Auto-clear clipboard

✅ **Dashboard:**
- Dark mode, glassmorphic design
- Guardian status, real-time events
- Vault UI (view, add, edit, delete)
- Security level selector

✅ **Audit Logging:**
- Centralized append-only log
- JSON Lines format
- Log viewer CLI
- Anomaly flags (basic heuristics)

✅ **VPS Hardening:**
- Service/port audit
- Hardening script (idempotent, --dry-run mode)
- Baseline snapshot
- Firewall rules review

✅ **Agent Sandboxing:**
- Filesystem boundaries (file permissions)
- Git branch protection
- Access audit trail

### Out of Phase 1 (Phase 2+)

❌ **AI-Powered Threat Analysis** — Phase 2
❌ **Automatic Credential Rotation for External Services** — Phase 2
❌ **Advanced Forensics** — Phase 3
❌ **Multi-System Orchestration** — Phase 5
❌ **Full OS-Level Sandboxing (AppArmor/SELinux)** — Phase 2
❌ **Log Encryption at Rest** — Phase 2

---

## 6. Data Isolation & Access Control

**Forge (Liaison Agent):**
- Read: All project files, all audit logs, all system state
- Write: Project state files (SPEC, STATUS, TASKS, SESSION_LOG), audit log entries
- Secrets: Anthropic API key, Telegram token (to spawn agents, receive messages)
- Scope: Full VPS access (it's the coordinator)

**Dev Agent (Builder):**
- Read: Project SPEC, ARCHITECTURE, TASKS, citadel-watch source code
- Write: Code commits (feature branch only), TASKS.md updates, SESSION_LOG.md
- Secrets: Git token (push to feature branch only), maybe Anthropic API key (if running sub-tasks)
- Scope: `/projects/active/citadel-archer/` directory only

**Opus Lead (Tech Lead):**
- Read: All project files, all audit logs
- Write: None (read-only review role)
- Secrets: None
- Scope: Review + approval, not execution

**Scott (Decision-Maker):**
- Human oversight only
- Approves PRs before merge to main
- Views STATUS.md + audit logs for oversight
- Can override decisions (policy)

---

## 7. Integration Points

**Guardian → Dashboard:**
- File/process events via WebSocket
- Dashboard shows real-time threat level

**Secrets Module → Agent Spawn:**
- Forge requests secret
- Secrets module injects into environment
- Log event to audit

**Vault → Dashboard:**
- UI for password management
- Encryption/decryption via SQLCipher

**Guardian → Audit Logging:**
- All file/process events logged
- Security level determines logging detail

**Hardening Script → Audit Logging:**
- Changes logged for audit trail
- Allows rollback detection

---

## 8. Deployment (Phase 1)

**Target:** Linux VPS (srv938724.hstgr.cloud)

**Executable:** PyInstaller-built executable (for Windows desktop app, Phase 2)

**For Phase 1 (Team Use):**
- Python package: `pip install citadel-archer`
- Runs as service: `systemctl start citadel-archer`
- Listens on: localhost:8000 (FastAPI), WebSocket on same
- Desktop wrapper: pywebview (Phase 1 CLI, Phase 2 GUI)

**Initialization:**
1. Create vault directory: `/var/citadel/`
2. Generate master password (user input)
3. Initialize secrets store (empty at first)
4. Run audit baseline
5. Start Guardian monitoring
6. Dashboard accessible at http://localhost:8000

---

## 9. Success Criteria for Phase 1

✅ **Secrets encrypted, scoped, rotatable**
✅ **Guardian monitors files/processes in real-time**
✅ **Vault stores passwords securely**
✅ **Dashboard shows live status**
✅ **Audit log captures all activity**
✅ **Agent sandboxing prevents scope creep**
✅ **VPS hardening script works idempotently**
✅ **Scott can review agent activity in <5 minutes**
✅ **No critical bugs, all acceptance tests pass**
✅ **Entire system feels "my machine is more secure now"**

---

## 10. Known Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Key loss (secrets unrecoverable) | Critical | Backup key separately, test recovery procedure Phase 1 |
| Agent goes rogue | High | File permissions + audit trail, can kill process |
| Audit log corrupted | Medium | Append-only, test immutability, backup daily |
| Performance: Watchdog overhead | Low | Benchmark file monitoring, optimize if needed |
| Secrets leak in error messages | High | Sanitize all logging, never log secret values |

---

*Architecture defined: Forge + Scott + Opus-Level Thinking*
*Ready for Dev Agent to execute Phase 1 tasks.*
