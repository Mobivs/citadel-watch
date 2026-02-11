# Phase 3: Panic Room Architecture

## Overview

The Panic Room is Citadel Commander's emergency response system, designed to rapidly respond to active security threats. When triggered, it executes predefined playbooks to isolate systems, rotate credentials, and secure critical data.

## Core Components

### 1. Trigger System
- **Manual Trigger**: User-initiated panic button (requires confirmation)
- **AI Detection**: Automated triggers based on threat scoring (Phase 2 integration)
- **Remote Trigger**: API endpoint for external systems to initiate panic mode
- **Dead Man's Switch**: Automatic trigger if heartbeat fails

### 2. Playbook Engine
Playbooks are ordered sequences of actions executed during panic mode:

```python
class Playbook:
    id: str
    name: str
    description: str
    priority: int  # Execution order
    actions: List[Action]
    pre_checks: List[Check]  # Validate before execution
    rollback_actions: List[Action]  # How to undo
    requires_confirmation: bool
```

### 3. Response Actions
Core actions that playbooks can execute:

#### Network Isolation
- **Soft Isolation**: Whitelist essential IPs/ports only
- **Hard Isolation**: Complete network disconnect
- **Smart Isolation**: AI-guided isolation based on threat type

#### Credential Rotation
- Integrate with Vault API (Phase 2)
- Rotate: SSH keys, API tokens, database passwords
- Old credentials archived for forensics

#### Process Management
- Kill suspicious processes
- Freeze non-essential services
- Preserve memory dumps for analysis

#### Data Protection
- Emergency encrypted backup
- Snapshot system state
- Secure deletion of sensitive temp files

### 4. State Management
Track panic room state for forensics and rollback:

```sql
-- Panic session tracking
CREATE TABLE panic_sessions (
    id UUID PRIMARY KEY,
    triggered_at TIMESTAMP,
    trigger_source TEXT, -- manual/ai/remote/deadman
    trigger_reason TEXT,
    status TEXT, -- active/completed/rolled_back
    metadata JSONB
);

-- Action execution log
CREATE TABLE panic_logs (
    id UUID PRIMARY KEY,
    session_id UUID REFERENCES panic_sessions(id),
    playbook_id TEXT,
    action_name TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    status TEXT, -- pending/executing/success/failed/rolled_back
    result JSONB,
    error_message TEXT
);

-- Recovery state for rollback
CREATE TABLE recovery_states (
    id UUID PRIMARY KEY,
    session_id UUID REFERENCES panic_sessions(id),
    component TEXT, -- network/credentials/processes/data
    pre_panic_state JSONB,
    current_state JSONB,
    rollback_available BOOLEAN DEFAULT true
);
```

## Integration Points

### Phase 2 Integration
- **Guardian**: Process and file monitoring feeds threat detection
- **Threat Scoring**: AI analysis triggers automated panic mode
- **Vault**: Credential rotation during panic response
- **Remote Shield**: VPS agents execute isolation commands

### User Interface
- **Dashboard Widget**: Big red panic button with confirmation
- **Status Panel**: Real-time execution progress
- **Recovery Console**: Rollback controls and forensics viewer

## Security Considerations

### Pre-flight Checks
Before executing panic mode:
1. Verify system integrity (no rootkits)
2. Check network connectivity for C2
3. Validate backup destinations are accessible
4. Ensure rollback data can be stored

### Fail-Safe Mechanisms
- **Confirmation Required**: Prevent accidental triggers
- **Partial Execution**: Continue even if some actions fail
- **Audit Everything**: Complete forensic trail
- **Manual Override**: Admin can stop/rollback at any time

### Whitelist Protection
Critical services that should NEVER be isolated:
- Citadel Commander API (localhost:8888)
- VPS agent connections (configurable IPs)
- Backup destinations
- Recovery endpoints

## API Design

### Panic Activation
```http
POST /api/panic/activate
{
    "confirmation_token": "user_confirmed_action",
    "playbooks": ["isolate_network", "rotate_credentials"],
    "reason": "Suspicious activity detected",
    "metadata": {}
}

Response:
{
    "session_id": "uuid",
    "status": "executing",
    "playbooks_queued": 2,
    "estimated_duration": 45,
    "websocket_channel": "/ws/panic/{session_id}"
}
```

### Status Monitoring
```http
GET /api/panic/status/{session_id}

Response:
{
    "session_id": "uuid",
    "status": "executing",
    "progress": {
        "total_actions": 15,
        "completed": 8,
        "failed": 1,
        "current_action": "rotating_ssh_keys"
    },
    "logs": [...]
}
```

### Rollback
```http
POST /api/panic/rollback/{session_id}
{
    "components": ["network", "credentials"],
    "confirmation_token": "user_confirmed_rollback"
}
```

## Playbook Specifications

### Built-in Playbooks

#### 1. Network Isolation
```yaml
name: isolate_network
priority: 1
requires_confirmation: true
pre_checks:
  - verify_whitelist_ips
  - check_backup_connectivity
actions:
  - block_all_incoming
  - block_outgoing_except_whitelist
  - log_active_connections
  - snapshot_netstat
rollback:
  - restore_firewall_rules
  - restart_network_services
```

#### 2. Credential Rotation
```yaml
name: rotate_credentials
priority: 2
requires_confirmation: false
pre_checks:
  - verify_vault_access
  - check_credential_inventory
actions:
  - rotate_ssh_keys
  - rotate_api_tokens
  - rotate_database_passwords
  - archive_old_credentials
rollback:
  - restore_previous_credentials
  - update_authorized_keys
```

#### 3. Kill Suspicious
```yaml
name: kill_suspicious
priority: 3
requires_confirmation: false
pre_checks:
  - scan_process_tree
  - identify_suspicious_processes
actions:
  - capture_memory_dump
  - terminate_suspicious
  - block_persistence_mechanisms
rollback:
  - restore_killed_services
```

#### 4. System Snapshot
```yaml
name: snapshot_system
priority: 4
requires_confirmation: false
actions:
  - capture_process_list
  - dump_network_connections
  - snapshot_file_hashes
  - collect_system_logs
  - package_forensics_bundle
```

#### 5. Secure Backup
```yaml
name: secure_backup
priority: 5
requires_confirmation: false
pre_checks:
  - verify_backup_space
  - check_encryption_keys
actions:
  - identify_critical_data
  - encrypt_with_panic_key
  - transfer_to_secure_location
  - verify_backup_integrity
  - secure_delete_local_copy
```

## Implementation Timeline

### Sprint 1 (Current)
- [x] Architecture documentation
- [ ] Database schema creation
- [ ] Core panic module structure
- [ ] Basic API endpoints
- [ ] Manual trigger implementation

### Sprint 2
- [ ] Playbook engine
- [ ] Built-in playbooks implementation
- [ ] Integration with Phase 2 components
- [ ] WebSocket real-time updates

### Sprint 3
- [ ] Frontend UI (panic button, status panel)
- [ ] Rollback system
- [ ] Forensics viewer
- [ ] Testing and hardening

## Success Criteria
1. Panic mode activates within 2 seconds
2. All playbooks execute without blocking each other
3. Complete audit trail for forensics
4. Rollback restores system to pre-panic state
5. No accidental triggers (confirmation required)
6. Critical services remain accessible