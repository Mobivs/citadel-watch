# Remote Shield Agent

Remote Shield Agent is a lightweight VPS threat detection and reporting system for Citadel Archer. It monitors VPS/cloud infrastructure for security threats and reports them to the central Intelligence Layer dashboard.

## Features

- **Real-time Threat Detection**: 5 detection modules scanning ports, processes, files, logs, and packages
- **Offline Resilience**: Queues threats locally if backend unavailable, syncs when reconnected
- **Lightweight**: Minimal resource usage, runs as background service
- **Secure**: Bearer token authentication, TLS support for future mTLS
- **Configurable**: Enable/disable modules, adjust scan intervals, set severity thresholds

## Threat Detection Modules

### 1. Port Scanner
Detects unexpected open ports on the system.
- Compares against baseline of expected ports (SSH, HTTP, HTTPS, etc.)
- Reports port anomalies as security events
- Helps identify unauthorized services

### 2. Process Monitor
Detects suspicious running processes.
- Flags processes with random/hash-like names (possible malware)
- Checks against whitelist of expected system services
- Reports unauthorized services

### 3. File Integrity Monitor
Monitors critical configuration files for unauthorized changes.
- Tracks `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config`, etc.
- Uses SHA256 hashing to detect modifications
- Reports file integrity violations

### 4. Log Analyzer
Analyzes system authentication logs for security events.
- Detects brute-force SSH attempts (>5 failed logins in 5 min from one IP)
- Identifies suspicious authentication patterns
- Reports security events from `/var/log/auth.log`

### 5. CVE Scanner
Checks installed packages for known vulnerabilities.
- Queries installed packages (via apt/rpm)
- Compares against known CVE database
- Reports vulnerable packages with severity

## Installation

### Prerequisites
- Node.js 16+
- Access to backend API (Citadel Archer)
- Linux/macOS system (support for Unix tools)

### Setup

1. **Clone the agent**:
```bash
git clone https://github.com/Mobivs/citadel-watch.git
cd remote-shield-agent
npm install
```

2. **Initialize agent**:
```bash
node index.js init http://citadel-archer.example.com vps-prod-1
```

This will:
- Register agent with backend
- Generate API token
- Initialize file integrity baseline
- Save configuration

3. **Verify status**:
```bash
node index.js status
```

## Usage

### Single Scan
Run threat detection once:
```bash
node index.js scan
```

Output shows detected threats with severity levels.

### Continuous Monitoring (Daemon)
Run agent as background service:
```bash
node index.js daemon
```

Logs saved to `./data/logs/`

### Systemd Service (Optional)

Create `/etc/systemd/system/remote-shield.service`:
```ini
[Unit]
Description=Remote Shield Agent - VPS Threat Detection
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/remote-shield-agent
ExecStart=/usr/bin/node index.js daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable remote-shield
sudo systemctl start remote-shield
```

Monitor logs:
```bash
sudo journalctl -u remote-shield -f
```

## Configuration

Edit `data/agent.config.json` to customize:

```json
{
  "backend_url": "http://localhost:8000",
  "hostname": "vps-production-1",
  "scan_interval_seconds": 300,
  "heartbeat_interval_seconds": 60,
  "modules": {
    "port_scanner": true,
    "process_monitor": true,
    "file_integrity": true,
    "log_analyzer": true,
    "cve_scanner": true
  },
  "min_severity": 5
}
```

### Key Settings

- **backend_url**: Central Citadel Archer API endpoint
- **hostname**: Agent identifier (visible in dashboard)
- **scan_interval_seconds**: How often to run threat detection (default: 5 min)
- **heartbeat_interval_seconds**: How often to ping backend (default: 1 min)
- **modules**: Enable/disable specific detection modules
- **min_severity**: Minimum threat severity to report (1-10, default: 5)

## API Communication

### Registration
```
POST /api/agents/register
Body: { hostname, ip, public_key }
Response: { agent_id, api_token }
```

### Threat Submission
```
POST /api/threats/remote-shield
Authorization: Bearer <token>
Body: { type, severity, title, details, hostname, timestamp }
Response: { id, status }
```

### Heartbeat
```
POST /api/agents/{id}/heartbeat
Authorization: Bearer <token>
Response: { status, next_scan_interval }
```

## Threat Types

Threats reported by the agent:

| Type | Severity | Description |
|------|----------|-------------|
| `port_scan_anomaly` | 5-8 | Unexpected open port detected |
| `process_anomaly` | 7 | Suspicious process running |
| `file_integrity` | 9 | Critical file modified |
| `brute_force_attempt` | 8 | Multiple failed SSH logins |
| `vulnerability` | 4-10 | Known CVE in installed package |

## Offline Mode

If backend is unavailable:
1. Agent queues threats locally (`data/threat-queue.json`)
2. Continues scanning and detecting threats
3. Syncs queued threats when backend reconnects
4. Automatic retry with exponential backoff (1s, 2s, 4s, 8s, 30s)

## Troubleshooting

### Agent not registering
- Check backend URL is accessible
- Verify network connectivity
- Check firewall rules

### Threats not appearing in dashboard
- Verify agent is running: `node index.js status`
- Check logs: `tail -f data/logs/info.log`
- Verify backend is receiving threats: `curl http://backend/api/threats/remote-shield`

### High CPU usage
- Reduce scan frequency (increase `scan_interval_seconds`)
- Disable unused modules
- Limit package scan with `--max-packages` (todo)

### Permission denied errors
- File monitor needs read access to `/etc`, `/root/.ssh`
- Log analyzer needs read access to `/var/log/auth.log`
- Run as root or grant appropriate permissions

### Port scanner not detecting ports
- Ensure netstat/ss command available on system
- Verify baseline ports are configured correctly

## Security

- API tokens stored securely in `data/.credentials.json` (mode 0600)
- TLS certificate verification enabled
- No plaintext credentials in logs
- Threats are encrypted in transit (HTTPS recommended)

## Development

Run tests:
```bash
npm test
```

Lint code:
```bash
npm run lint
```

## Support

For issues, questions, or suggestions:
- Create an issue on GitHub
- Check troubleshooting guide above
- Review logs in `data/logs/`

## License

MIT - Part of Citadel Archer project

## Architecture

```
Agent on VPS
    ↓
Threat Detection (5 modules)
    ↓
Format & Queue Threats
    ↓
Submit to Backend (with retry)
    ↓
Central Dashboard (real-time WebSocket)
```

The agent is stateless and scalable. Deploy one agent per VPS, and all threats aggregate in the central dashboard.
