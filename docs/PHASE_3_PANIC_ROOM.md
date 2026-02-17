# Phase 3: Panic Room Implementation

## Overview
The Panic Room is a comprehensive emergency response system for Citadel Archer, providing automated incident response through predefined playbooks.

> **Note (v0.2.5):** Asset scope selector, remote credential rotation, and per-asset rollback have been added to Phase 3 scope. See [ASSET_MANAGEMENT_ADDENDUM.md](ASSET_MANAGEMENT_ADDENDUM.md) for full specification of remote panic operations.

## Components

### Frontend
- **panic-room.html** - Main UI for panic room control
- **panic-room.js** - Client-side logic and WebSocket handling
- **panic-room.css** - Styling with glassmorphism effects

### Backend API
- **panic_routes.py** - FastAPI routes for panic operations
- **panic_database.py** - SQLite database for session persistence
- **playbooks.py** - Pre-configured response playbooks
- **playbook_engine.py** - Execution engine for playbooks

## Available Playbooks

### Network Security
1. **IsolateNetwork** - Block all network traffic except localhost
2. **LockdownAccess** - Disable remote access and lock accounts

### Data Protection
3. **RotateCredentials** - Rotate all stored credentials and API keys
4. **SecureBackup** - Backup and encrypt critical data

### System Defense
5. **KillProcesses** - Terminate suspicious processes
6. **QuarantineFiles** - Move suspicious files to quarantine

### Forensics
7. **SnapshotSystem** - Create comprehensive system state snapshot

## API Endpoints

### Core Operations
- `POST /api/panic/activate` - Activate panic mode
- `POST /api/panic/activate/v2` - Enhanced activation (Phase 3)
- `GET /api/panic/status/{session_id}` - Get session status
- `POST /api/panic/rollback/{session_id}` - Rollback actions
- `POST /api/panic/sessions/{session_id}/cancel` - Cancel active session

### Playbook Management
- `GET /api/panic/playbooks` - List available playbooks
- `GET /api/panic/playbooks/{playbook_id}` - Get playbook details
- `GET /api/panic/playbooks/categories` - Get playbook categories
- `POST /api/panic/plan` - Create execution plan

### Session History
- `GET /api/panic/sessions/history` - Get session history
- `GET /api/panic/sessions/active` - Get active sessions
- `GET /api/panic/sessions/{session_id}/logs` - Get session logs
- `GET /api/panic/sessions/{session_id}/recovery` - Get recovery snapshots

### WebSocket
- `WS /api/panic/ws/{session_id}` - Real-time session updates

## Database Schema

### Tables
1. **panic_sessions** - Main session records
2. **action_logs** - Detailed action execution logs
3. **recovery_snapshots** - Recovery state snapshots

## Security Features

### Confirmation Tokens
All destructive operations require confirmation tokens generated as:
```python
hashlib.sha256(f"panic_{user_id}_{date}".encode()).hexdigest()[:16]
```

### Audit Logging
All panic operations are logged to the audit system with severity levels:
- **critical** - Panic activation
- **warning** - Failed attempts, cancellations
- **info** - Configuration changes, status queries

### Recovery Mechanism
Each playbook action stores recovery data enabling rollback:
- Network configuration backups
- Credential snapshots
- System state preservation

## Usage Example

### Activating Panic Mode
```javascript
const response = await fetch('/api/panic/activate/v2', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + sessionToken
    },
    body: JSON.stringify({
        playbooks: ['IsolateNetwork', 'RotateCredentials'],
        reason: 'Suspected breach detected',
        confirmation_token: generateConfirmationToken()
    })
});
```

### Monitoring Session Progress
```javascript
const ws = new WebSocket(`wss://localhost:8000/api/panic/ws/${sessionId}`);
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Panic status update:', data);
};
```

## Testing

### Unit Tests
Run the test suite:
```bash
python -m pytest tests/test_panic_room.py -v
```

### Integration Tests
Execute E2E tests:
```bash
node frontend/tests/e2e-panic-room.test.js
```

## Deployment Notes

1. Ensure database directory exists: `/var/lib/citadel/panic/`
2. Configure process whitelist: `/etc/citadel/process_whitelist.json`
3. Set up recovery directory permissions
4. Install required system tools (iptables, tar, gpg)

## Phase 3 Completion Status

✅ **Completed:**
- Frontend UI implementation
- Backend API routes
- Database integration
- Playbook library
- WebSocket real-time updates
- Confirmation token security
- Audit logging
- Recovery snapshots

⏳ **Future Enhancements:**
- Machine learning anomaly detection
- Automated playbook suggestions
- Multi-factor authentication for panic mode
- Integration with external SIEM systems
- Custom playbook builder UI

🔜 **Planned (v0.2.5 Addendum):**
- Asset scope selector (choose which assets panic playbooks target)
- Remote credential rotation via SSH Connection Manager
- Per-asset rollback on failure
- Recovery key per remote asset
- See [ASSET_MANAGEMENT_ADDENDUM.md](ASSET_MANAGEMENT_ADDENDUM.md)