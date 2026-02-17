# Citadel Archer - Asset Management & Remote Execution Addendum

**Version:** 1.0.0
**Date:** 2026-02-11
**Status:** Approved — Prerequisite for Panic Room remote operations
**Parent Document:** [PRD v0.2.5](PRD.md)

---

## Motivation

During Panic Room implementation, we discovered a critical architectural gap: **the Panic Room has no awareness of remote systems**. Credential rotation, network isolation, and other emergency playbooks only operate on the local machine. Meanwhile:

- **Assets** (T7, `intel/assets.py`) is an in-memory registry with no persistence, no CRUD API, and no frontend Add button.
- **Remote Shield** agents register and report threats, but don't create Asset records and can't receive commands from Panic Room.
- **Vault** stores user passwords but has no concept of "SSH credentials for managed host X."
- **There is no SSH connection manager** — no way to execute commands on remote servers.

These four disconnected systems must be unified before Panic Room can protect anything beyond localhost.

---

## Scope

This addendum specifies the work needed to close the asset management gap. It spans Phases 2, 3, and 4 of the roadmap and introduces one new module (SSH Connection Manager) while extending four existing ones (Assets, Remote Shield, Vault, Panic Room).

### Out of Scope
- SecureChat / encrypted messaging (remains Phase 4)
- Family computer auto-enrollment (remains Phase 5)
- GUI-based remote desktop or terminal emulator
- Multi-user RBAC for asset access

---

## 1. Asset Database Persistence

### Problem
`AssetInventory` (`intel/assets.py`) stores everything in a Python `dict`. Data is lost on restart. There are no API endpoints for creating or managing assets from the frontend.

### Solution
Add SQLite persistence to AssetInventory, mirroring the pattern used by `IntelStore` and `PanicDatabase`.

### Schema

```sql
CREATE TABLE IF NOT EXISTS managed_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id TEXT UNIQUE NOT NULL,          -- e.g. "asset_vps_prod_01"
    name TEXT NOT NULL,                      -- user-facing label
    hostname TEXT,                            -- DNS name or hostname
    ip_address TEXT,                          -- IPv4 or IPv6
    platform TEXT DEFAULT 'linux',            -- linux, windows, macos
    asset_type TEXT DEFAULT 'vps',            -- vps, lan, workstation, cloud
    status TEXT DEFAULT 'unknown',            -- online, offline, protected, compromised, unknown
    ssh_credential_id TEXT,                   -- FK → vault passwords.id (SSH key/password)
    ssh_port INTEGER DEFAULT 22,
    ssh_username TEXT DEFAULT 'root',
    remote_shield_agent_id TEXT,             -- FK → linked Remote Shield agent
    tags TEXT DEFAULT '[]',                   -- JSON array of user tags
    notes TEXT DEFAULT '',
    last_seen_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_managed_assets_status ON managed_assets(status);
CREATE INDEX idx_managed_assets_type ON managed_assets(asset_type);
```

### Changes to `intel/assets.py`

- Add `db_path` parameter to `AssetInventory.__init__()` (defaults to `data/assets.db`)
- Add `_init_database()` method to create table on first use
- Modify `register()`, `remove()`, `set_status()`, etc. to read/write from SQLite
- Keep the in-memory dict as a write-through cache for performance
- Add `update()` method for editing existing assets
- Add `link_remote_shield_agent()` method
- Add `link_ssh_credential()` method

### Migration
Existing in-memory assets are ephemeral (no data to migrate). The table is created on first use.

---

## 2. Asset CRUD API

### New File: `api/asset_routes.py`

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/assets` | `GET` | Session | List all managed assets (filterable by status, type, platform) |
| `/api/assets` | `POST` | Session | Create a new managed asset |
| `/api/assets/{asset_id}` | `GET` | Session | Get asset details (includes linked agent, vault ref, last events) |
| `/api/assets/{asset_id}` | `PUT` | Session | Update asset metadata |
| `/api/assets/{asset_id}` | `DELETE` | Session + Confirm | Delete asset (unlinks agent + vault credential) |
| `/api/assets/{asset_id}/test-connection` | `POST` | Session | Test SSH connectivity to asset |
| `/api/assets/{asset_id}/link-agent` | `POST` | Session | Link a Remote Shield agent to this asset |
| `/api/assets/{asset_id}/link-credential` | `POST` | Session | Link a Vault credential to this asset |

### Request/Response Examples

**POST /api/assets** (Create):
```json
{
    "name": "Production VPS",
    "hostname": "prod.example.com",
    "ip_address": "203.0.113.42",
    "platform": "linux",
    "asset_type": "vps",
    "ssh_port": 22,
    "ssh_username": "root",
    "tags": ["production", "web-server"],
    "notes": "Runs nginx + postgres"
}
```

Response:
```json
{
    "asset_id": "asset_a1b2c3d4",
    "name": "Production VPS",
    "status": "unknown",
    "ssh_credential_id": null,
    "remote_shield_agent_id": null,
    "created_at": "2026-02-11T12:00:00Z",
    "message": "Asset created. Link an SSH credential and test connection to enable remote operations."
}
```

**POST /api/assets/{asset_id}/test-connection**:
```json
{
    "asset_id": "asset_a1b2c3d4",
    "connection_status": "success",
    "ssh_fingerprint": "SHA256:abc123...",
    "remote_os": "Ubuntu 22.04.3 LTS",
    "uptime": "42 days",
    "remote_shield_detected": true,
    "agent_version": "1.0.0"
}
```

---

## 3. Frontend: Add Asset UI

### Changes to `frontend/assets.html`

Add an "Add Asset" button to the top-right of the assets page header. Currently the page has no way to create assets — it only displays the in-memory registry.

### New UI Elements

**Add Asset Button** (assets page header):
```
[+ Add Asset]
```

**Add Asset Modal** (overlay form):
| Field | Type | Required | Default |
|-------|------|----------|---------|
| Name | text | Yes | — |
| Hostname | text | No | — |
| IP Address | text | Yes | — |
| Platform | select | Yes | Linux |
| Type | select | Yes | VPS |
| SSH Port | number | No | 22 |
| SSH Username | text | No | root |
| SSH Credential | select (from Vault) | No | — |
| Tags | tag input | No | — |
| Notes | textarea | No | — |

**SSH Credential Selector**: Dropdown populated from `GET /api/vault/passwords?category=ssh`. If no SSH credentials exist, show a link: "No SSH credentials in Vault — [Add one first]".

**Post-Creation Flow**:
1. Asset created (status: `unknown`)
2. Prompt: "Test SSH connection now?" → calls `/api/assets/{id}/test-connection`
3. If connection succeeds, status changes to `online`
4. If Remote Shield agent is detected on remote host, auto-link it

### Changes to `frontend/js/assets.js`

- Add `createAsset()`, `updateAsset()`, `deleteAsset()` methods
- Add `testConnection()` method with progress indicator
- Add modal open/close handlers
- Populate SSH credential dropdown from Vault API
- Add edit/delete icons to each asset row

---

## 4. Remote Shield Auto-Linking

### Problem
When a Remote Shield agent registers via `POST /api/agents/register`, it provides its hostname and IP. But it does NOT create a managed asset, and there is no way to associate it with an existing one.

### Solution

#### On Agent Registration (`remote_shield_routes.py`)
After a successful agent registration:
1. Search `managed_assets` for a matching `ip_address` or `hostname`
2. If found: auto-link the agent → set `remote_shield_agent_id` on the asset, set asset status to `protected`
3. If NOT found: create a new managed asset with status `online` and the agent linked
4. Return the `asset_id` in the registration response so the agent knows its identity

#### On Agent Heartbeat
Update the linked asset's `last_seen_at` and `status` (if agent reports issues).

#### On Agent Disconnect (no heartbeat for >5 minutes)
Set linked asset status to `offline`.

### Changes to `remote_shield_routes.py`
- Import `AssetInventory` (with DB persistence)
- On registration: search-or-create asset, link agent
- On heartbeat: update asset `last_seen_at`
- Add heartbeat timeout checker (background task)

### Changes to `remote-shield-agent/lib/backend.js`
- Store returned `asset_id` in local config
- Include `asset_id` in heartbeat and threat report payloads

---

## 5. Vault Integration: SSH Credentials

### Problem
The Vault stores passwords with fields: `title`, `username`, `website`, `notes`, `encrypted_password`, `category`. There is no concept of SSH-specific credentials (private key, key passphrase, connection parameters).

### Solution
Add an `ssh` category to Vault with extended metadata, stored in the existing `notes` field as structured JSON.

### SSH Credential Structure

When `category = "ssh"`, the `notes` field contains JSON:
```json
{
    "auth_type": "key",
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
    "key_passphrase": "",
    "default_port": 22,
    "default_username": "root",
    "fingerprint": "SHA256:..."
}
```

For password-based SSH auth:
```json
{
    "auth_type": "password",
    "default_port": 22,
    "default_username": "root"
}
```

When `auth_type = "password"`, the standard `encrypted_password` field holds the SSH password. When `auth_type = "key"`, the `private_key` is stored inside the encrypted `notes` JSON (double-encrypted: once as part of the JSON blob via Vault's per-entry AES-256-GCM, and the Vault itself is behind the master password).

### Changes to `vault_routes.py`
- Add `GET /api/vault/passwords?category=ssh` filter (already supported)
- Add `POST /api/vault/ssh-credentials` convenience endpoint that validates SSH-specific fields
- Add `GET /api/vault/ssh-credentials/{id}/public-key` — extract and return public key from stored private key (for authorized_keys management)

### Changes to `vault/vault_manager.py`
- Add `get_ssh_credential(id)` method that parses the `notes` JSON and returns a structured SSH credential object
- Add `validate_ssh_key(private_key)` method to verify key format before storing

### Frontend
- Add "SSH Key" category option when adding a Vault entry
- Add private key paste area (textarea) when SSH Key category is selected
- Add "Import from file" button for `.pem` / `id_ed25519` / `id_rsa` files
- Add key type detection (ed25519, RSA, ECDSA) and fingerprint display

---

## 6. SSH Connection Manager

### New Module: `remote/ssh_manager.py`

This is the missing link between Panic Room playbooks and remote servers. It provides a high-level SSH client interface for executing commands on managed assets.

### Class: `SSHConnectionManager`

```python
class SSHConnectionManager:
    """Manage SSH connections to remote assets using Vault credentials."""

    def __init__(self, vault: VaultManager, asset_inventory: AssetInventory):
        self.vault = vault
        self.assets = asset_inventory
        self._connections: Dict[str, asyncssh.SSHClientConnection] = {}

    async def connect(self, asset_id: str) -> SSHConnection:
        """Establish SSH connection to asset using linked Vault credential."""

    async def execute(self, asset_id: str, command: str, timeout: int = 30) -> CommandResult:
        """Execute a command on a remote asset. Returns stdout, stderr, exit_code."""

    async def test_connection(self, asset_id: str) -> ConnectionTestResult:
        """Test SSH connectivity and return system info."""

    async def upload_file(self, asset_id: str, local_path: str, remote_path: str):
        """SCP upload a file to remote asset."""

    async def download_file(self, asset_id: str, remote_path: str, local_path: str):
        """SCP download a file from remote asset."""

    async def disconnect(self, asset_id: str):
        """Close SSH connection to asset."""

    async def disconnect_all(self):
        """Close all active connections."""
```

### Dependencies
- `asyncssh` — async SSH client library (pure Python, supports ed25519, RSA, ECDSA)
- No paramiko — asyncssh integrates cleanly with asyncio/FastAPI

### Connection Flow
1. Look up asset by `asset_id` in `AssetInventory`
2. Get `ssh_credential_id` from asset record
3. Unlock credential from `VaultManager.get_ssh_credential(id)`
4. Build asyncssh connection with credential (key or password)
5. Cache connection in `_connections` dict (reuse for multiple commands)
6. Auto-close idle connections after 5 minutes

### Error Handling
- `AssetNotFoundError` — asset_id doesn't exist
- `NoCredentialError` — asset has no linked SSH credential
- `VaultLockedError` — vault must be unlocked first
- `ConnectionFailedError` — SSH connection refused, timeout, auth failure
- `CommandTimeoutError` — remote command exceeded timeout

---

## 7. Panic Room: Remote Scope

### Problem
All Panic Room playbooks execute locally. `credential_rotation.py` rotates `~/.ssh/authorized_keys` on the server running Citadel Archer. It has no way to rotate credentials on managed VPS instances.

### Solution
Add an **asset scope selector** to Panic Room activation. When the user presses the Panic Button, they choose which assets to target (including "local machine" as a default).

### Changes to Panic Room Activation Flow

**Current flow:**
1. Press Panic Button
2. Select playbooks
3. Confirm → execute locally

**New flow:**
1. Press Panic Button
2. **Select target assets** (checkboxes, default: local + all `protected` assets)
3. Select playbooks
4. Confirm → execute on each selected asset

### Frontend Changes (`panic-room.html` / `panic-room.js`)

Add an **Asset Scope** section between the panic button and playbook selection:

```
Asset Scope:
[x] Local Machine (this computer)
[x] prod-vps (203.0.113.42) — Protected
[x] staging-vps (198.51.100.10) — Protected
[ ] dev-server (10.0.0.5) — Offline
```

- Only assets with status `online` or `protected` are selectable
- `offline` or `compromised` assets shown but grayed out with tooltip
- "Select All Online" / "Deselect All" buttons
- Asset count shown: "3 of 4 assets selected"

### Backend Changes

**`POST /api/panic/activate/v2`** — Add `target_assets` field:
```json
{
    "playbooks": ["IsolateNetwork", "RotateCredentials"],
    "target_assets": ["local", "asset_a1b2c3d4", "asset_e5f6g7h8"],
    "reason": "Suspected breach",
    "confirmation_token": "..."
}
```

If `target_assets` is omitted or empty, default to `["local"]` (backward compatible).

**Playbook Engine Changes** (`playbook_engine.py`):
- Accept `target_assets` list in execution context
- For each asset in scope:
  - If `"local"`: execute playbook actions locally (current behavior)
  - If remote `asset_id`: use `SSHConnectionManager` to execute on remote host
- Track per-asset progress in session logs
- If one asset fails, continue with others (don't abort entire panic)

**Credential Rotation Changes** (`credential_rotation.py`):
- `_rotate_ssh_keys()` gains an `asset_id` parameter
- For local: current behavior (read/write `~/.ssh/authorized_keys`)
- For remote: use `SSHConnectionManager.execute()` to:
  1. Read remote `authorized_keys`
  2. Preserve recovery key lines
  3. Replace operational keys
  4. Write back via SSH
  5. Verify recovery key still present

### Safety Invariants (Extended)
1. Recovery key must be present on EACH target asset before rotation
2. If any pre-flight check fails for an asset, skip that asset (don't block others)
3. Per-asset rollback: if rotation fails on asset X, roll back asset X only
4. Action log shows per-asset status: `asset_a1b2c3d4: SSH keys rotated`, `asset_e5f6g7h8: SKIPPED (no recovery key)`

---

## 8. Dependency & Implementation Order

The modules have strict dependencies. Building them out of order creates dead code or runtime errors.

```
Phase 2 (Prerequisite)                Phase 3 (Panic Room)
┌─────────────────────┐               ┌─────────────────────┐
│ 2A. Asset DB        │               │ 3A. Recovery Key    │ ✅ Done
│     Persistence     │               │     System          │
├─────────────────────┤               ├─────────────────────┤
│ 2B. Asset CRUD API  │──────────────→│ 3B. Panic Room      │ ✅ Done
├─────────────────────┤               │     Asset Scope     │
│ 2C. Asset Frontend  │               │     Selector        │
│     (Add/Edit)      │               ├─────────────────────┤
├─────────────────────┤               │ 3B+. Remote Action  │ ✅ Done
│ 2D. Remote Shield   │ ✅ Done       │      Execution      │
│     Auto-Link       │──────────────→├─────────────────────┤
├─────────────────────┤               │ 3C. Remote          │ ✅ Done
│ 2D+. Remote Shield  │ ✅ Done       │     Credential      │
│      DB Persistence │               │     Rotation        │
├─────────────────────┤               └─────────────────────┘
│ 2E. Vault SSH       │ ✅ Done
│     Credentials     │──────┐
├─────────────────────┤      │
│ 2F. SSH Connection  │←─────┘ ✅ Done
│     Manager         │
└─────────────────────┘

Implementation Order:
  2A✅ → 2B✅ → 2C✅ → 2E✅ → 2F✅ → 2D✅ → 3B✅ → 3C✅
```

### Estimated Work Per Step

| Step | Description | Files Changed | New Files | Complexity |
|------|-------------|---------------|-----------|------------|
| 2A | Asset DB persistence | `intel/assets.py` | — | Medium |
| 2B | Asset CRUD API | — | `api/asset_routes.py` | Medium |
| 2C | Asset frontend (Add/Edit) | `frontend/assets.html`, `frontend/js/assets.js` | — | Medium |
| 2D | Remote Shield auto-link | `api/remote_shield_routes.py` | — | Low |
| 2E | Vault SSH credentials | `vault/vault_manager.py`, `api/vault_routes.py` | — | Medium |
| 2F | SSH Connection Manager | — | `remote/ssh_manager.py` | High |
| 3B | Panic Room asset scope | `panic-room.html`, `panic-room.js`, `panic_routes.py`, `playbook_engine.py` | — | High |
| 3C | Remote credential rotation | `panic/actions/credential_rotation.py` | — | High |

---

## 9. Remote Shield Persistence (In-Memory Fix)

### Problem
`remote_shield_routes.py` stores all agent and threat data in Python dicts (`agents_db`, `remote_threats_db`). Everything is lost on server restart.

### Solution
Move agent and threat storage to SQLite, following the same pattern as PanicDatabase.

### New Tables (add to existing database or new `data/remote_shield.db`)

```sql
CREATE TABLE IF NOT EXISTS remote_shield_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT NOT NULL,
    ip_address TEXT,
    platform TEXT DEFAULT 'linux',
    version TEXT,
    api_token_hash TEXT NOT NULL,       -- bcrypt hash, never store raw token
    asset_id TEXT,                       -- FK → managed_assets.asset_id
    status TEXT DEFAULT 'active',
    last_heartbeat_at TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS remote_shield_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_id TEXT UNIQUE NOT NULL,
    agent_id TEXT NOT NULL,
    asset_id TEXT,
    threat_type TEXT NOT NULL,
    severity TEXT DEFAULT 'medium',
    title TEXT NOT NULL,
    description TEXT,
    details TEXT DEFAULT '{}',          -- JSON
    status TEXT DEFAULT 'active',       -- active, investigating, resolved, false_positive
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    FOREIGN KEY (agent_id) REFERENCES remote_shield_agents(agent_id)
);
```

---

## 10. PRD Roadmap Corrections

The following adjustments to the main PRD roadmap are needed to reflect the dependency chain discovered during implementation:

### Phase 2 Additions
Under "Remote Shield - VPS Protection", add:
- [x] **Asset database persistence** (SQLite storage for managed assets) — Already existed (intel/assets.py, write-through cache)
- [x] **Asset CRUD API** (`POST/PUT/DELETE /api/assets`) — Already existed (api/asset_routes.py, 8 endpoints)
- [x] **Asset management frontend** (Add/Edit/Delete assets from dashboard) — Already existed (assets.html + assets.js)
- [x] **Remote Shield agent auto-linking** (agents auto-register as managed assets) — Done (auto_link in remote_shield_routes.py)
- [x] **Remote Shield database persistence** (agent + threat data survives restart) — Done (shield_database.py, 34 tests)

### Phase 3 Additions
Under "Panic Room", add:
- [x] **Asset scope selector** (choose which assets panic playbooks target) — Done (frontend + backend wiring)
- [x] **Remote action execution** (playbook actions route to remote assets via SSH) — Done (BaseAction._run_command + PlaybookEngine SSH injection)
- [x] **Remote credential rotation** (rotate SSH keys on remote assets via SSH) — Done (credential_rotation.py: _rotate_ssh_keys_remote(), base64 atomic write, recovery key safety, 16 tests)
- [ ] **Per-asset rollback** (rollback failed assets independently)

### Phase 2/3 Bridge (New)
These items span Phase 2 and Phase 3 — they are Phase 2 infrastructure required by Phase 3:
- [x] **Vault SSH credential type** (store SSH keys/passwords with structured metadata) — Already existed (vault_manager.py, vault_routes.py)
- [x] **SSH Connection Manager** (asyncssh-based remote command execution) — Already existed (remote/ssh_manager.py)

### Phase 3 Milestone Update
**Current:** "One-click response to active attacks"
**Updated:** "One-click response to active attacks **across all managed assets** (local + remote)"

---

## 11. Security Considerations

### SSH Credential Storage
- SSH private keys are encrypted by Vault's per-entry AES-256-GCM (same as passwords)
- Vault must be unlocked for SSH connections — no background connections when vault is locked
- Private keys are held in memory only while connection is active, then zeroed

### Remote Command Execution
- All SSH commands executed via Panic Room are logged to audit trail
- Command allowlist: only specific commands per playbook action (no arbitrary shell access)
- SSH host key verification: first-connect stores fingerprint, subsequent connects verify
- Connection timeout: 30 seconds default, configurable per asset

### Agent Token Security
- Agent API tokens are SHA-256-hashed before storage (never stored in plaintext). SHA-256 is appropriate for high-entropy tokens (256-bit random); bcrypt would add unnecessary latency since these are not low-entropy passwords.
- Token rotation: agents can request new tokens via authenticated heartbeat. Re-registration atomically replaces the hash, invalidating old tokens.
- Revocation: deleting an asset or agent immediately invalidates the token

### Recovery Key on Remote Assets
- Before rotating SSH keys on a remote asset, a recovery key must exist on THAT asset's `authorized_keys`
- The same `RecoveryKeyManager` pattern applies: recovery key generated per-asset, private key shown to user once
- Per-asset recovery keys are stored in Vault (category: `recovery-key`, tagged with `asset_id`)

---

## 12. Testing Requirements

### Asset Persistence
- Unit: CRUD operations persist across AssetInventory reinstantiation
- Unit: Asset search by hostname, IP, status, type
- Unit: Link/unlink agent and credential

### Asset API
- Integration: Full CRUD cycle via HTTP endpoints
- Integration: Connection test with mock SSH server
- Integration: Credential linking from Vault

### Remote Shield Persistence
- Unit: Agent registration persists to SQLite
- Unit: Threat reports persist and query correctly
- Integration: Agent registration auto-creates asset

### SSH Connection Manager
- Unit: Connection with key auth (mock asyncssh)
- Unit: Connection with password auth (mock asyncssh)
- Unit: Command execution with timeout
- Unit: Connection caching and idle cleanup
- Integration: Connection test updates asset status

### Panic Room Remote Scope
- Unit: Activation with multiple target assets
- Unit: Per-asset pre-flight check (recovery key present)
- Unit: Per-asset rollback on failure
- Integration: Full panic activation across local + 1 remote asset (mocked SSH)
- E2E: Frontend asset scope selector enables/disables based on asset status

---

## Appendix: Current Module Status

| Module | Completion | What Exists | What's Missing |
|--------|------------|-------------|----------------|
| **Assets** | 45% | In-memory registry, AssetView, frontend table | DB persistence, CRUD API, Add/Edit UI |
| **Remote Shield** | 60% | Agent + API + threat reporting | DB persistence, auto-link to assets, command channel |
| **Vault** | 90% | Full encrypted storage, API, frontend | SSH credential type, key validation |
| **Panic Room** | 70% | Playbooks, engine, recovery keys | Remote scope, remote execution, per-asset rollback |
| **SSH Manager** | 0% | Nothing | Entire module |
| **Secure Comms** | 0% | Nothing | Entire module (Phase 4) |

---

*This addendum is a living document. It will be updated as implementation progresses.*
