# Remote Shield Deployment Guide

Complete guide for deploying and managing Remote Shield agents on VPS infrastructure.

## Architecture Overview

```
VPS Infrastructure (Multiple)
    ├── Agent 1 → Detect threats → Queue locally
    ├── Agent 2 → Detect threats → Queue locally
    └── Agent N → Detect threats → Queue locally
            ↓
All agents ── HTTP POST → Central Backend API
            ↓
Backend ingests & stores threats
            ↓
Real-time WebSocket broadcast
            ↓
Dashboard displays threats (Remote Shield tab)
```

## Prerequisites

### Backend Requirements
- Citadel Archer backend running (Phase 2.1)
- FastAPI server accessible from VPS
- Database for storing agent/threat data
- WebSocket support for real-time updates

### VPS Requirements
- Linux/macOS system
- Node.js 16+ installed
- Internet connectivity to backend
- Root or sudo access (for monitoring)
- 100 MB disk space

## Installation

### Step 1: Deploy Backend API

Backend already includes Remote Shield routes:

1. **Verify FastAPI server is running:**
```bash
curl http://localhost:8000/api/agents
# Should return 200 [] (empty agent list)
```

2. **Enable CORS for remote agents:**
Backend CORS already allows all origins in development. Update in production:
```python
# src/citadel_archer/api/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],  # Production
    allow_methods=["*"],
)
```

3. **Start backend if not running:**
```bash
cd /root/clawd/projects/active/citadel-archer
python3 -m uvicorn src.citadel_archer.api.main:app --host 0.0.0.0 --port 8000
```

### Step 2: Deploy Agent on VPS

#### Option A: Manual Deployment

1. **Clone agent code:**
```bash
git clone https://github.com/Mobivs/citadel-watch.git
cd citadel-watch/remote-shield-agent
npm install
```

2. **Initialize agent:**
```bash
node index.js init http://backend-ip:8000 vps-prod-1
```

This will:
- Register agent with backend
- Generate API token
- Create `data/` directory
- Initialize file baseline

3. **Verify installation:**
```bash
node index.js status
```

Output should show:
```
Configuration:
  Backend URL:  http://backend-ip:8000
  Hostname:     vps-prod-1
  Agent ID:     <uuid>
  Scan Interval: 300s
```

4. **Run first scan:**
```bash
node index.js scan
```

Should detect 0+ threats and show output.

#### Option B: Automated Deployment (Recommended)

Use Ansible/Terraform for multi-VPS deployment:

```bash
# Deploy to 10 VPS instances
ansible-playbook deploy-agents.yml \
  -i inventory.ini \
  -e "backend_url=http://backend-ip:8000"
```

Example `deploy-agents.yml`:
```yaml
---
- hosts: vps_servers
  tasks:
    - name: Install Node.js
      apt: name=nodejs state=present
    
    - name: Clone agent
      git:
        repo: https://github.com/Mobivs/citadel-watch.git
        dest: /opt/remote-shield-agent
    
    - name: Install dependencies
      npm:
        path: /opt/remote-shield-agent/remote-shield-agent
    
    - name: Initialize agent
      command: |
        node /opt/remote-shield-agent/remote-shield-agent/index.js init \
        {{ backend_url }} {{ inventory_hostname }}
```

### Step 3: Setup Systemd Service (Continuous Monitoring)

Create `/etc/systemd/system/remote-shield.service`:

```ini
[Unit]
Description=Remote Shield Agent - VPS Threat Detection
Documentation=https://github.com/Mobivs/citadel-watch
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/remote-shield-agent/remote-shield-agent
ExecStart=/usr/bin/node /opt/remote-shield-agent/remote-shield-agent/index.js daemon
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
MemoryLimit=256M
CPUQuota=20%
TasksMax=100

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable remote-shield
sudo systemctl start remote-shield
```

Check status:
```bash
sudo systemctl status remote-shield
sudo journalctl -u remote-shield -f
```

### Step 4: Verify Deployment

1. **Check agent registration:**
```bash
curl http://backend-ip:8000/api/agents
```

Should list deployed agents with status "active".

2. **Check threat submissions:**
```bash
curl http://backend-ip:8000/api/threats/remote-shield
```

Should show detected threats (may be empty if system is clean).

3. **Access dashboard:**
Open browser: `http://backend-ip:8000`
- Go to "Remote Shield" tab
- Should see agent(s) listed
- Check "Active Now" count

## Configuration

Edit `data/agent.config.json` after initialization:

```json
{
  "backend_url": "http://backend-ip:8000",
  "hostname": "vps-prod-1",
  "scan_interval_seconds": 300,
  "heartbeat_interval_seconds": 60,
  "modules": {
    "port_scanner": true,
    "process_monitor": true,
    "file_integrity": true,
    "log_analyzer": true,
    "cve_scanner": true
  },
  "min_severity": 5,
  "baseline_ports": [22, 80, 443, 53, 25, 587],
  "critical_files": [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys",
    "/etc/cron.d"
  ]
}
```

### Common Configuration Changes

**Reduce scan frequency (high-traffic servers):**
```json
"scan_interval_seconds": 600  // 10 minutes
```

**Disable file monitoring (to reduce overhead):**
```json
"modules": {
  "file_integrity": false
}
```

**Only report critical threats:**
```json
"min_severity": 8
```

**Custom baseline ports:**
```json
"baseline_ports": [22, 80, 443, 3000, 5432, 8080]
```

## Monitoring & Maintenance

### View Agent Logs

```bash
# Real-time
sudo journalctl -u remote-shield -f

# Or directly
tail -f /opt/remote-shield-agent/remote-shield-agent/data/logs/info.log
```

Log levels in `data/logs/`:
- `info.log` - Normal operations
- `warn.log` - Warnings
- `error.log` - Errors
- `debug.log` - Debug info (if enabled)

### Check Agent Health

From backend:
```bash
curl http://backend-ip:8000/api/agents
```

Look for:
- ✅ `status: "active"` - Agent is healthy
- ⚠️  `status: "inactive"` - Agent offline
- 🔴 No heartbeat in last 5 minutes - Agent may have crashed

### Restart Agent

```bash
# Via systemd
sudo systemctl restart remote-shield

# Or manually
sudo systemctl stop remote-shield
sudo systemctl start remote-shield
```

### Update Agent

```bash
cd /opt/remote-shield-agent
git pull origin main
npm install
sudo systemctl restart remote-shield
```

### Sync Offline Queue

If backend was unreachable, agent queues threats locally. When backend returns:

```bash
# Agent automatically syncs (next heartbeat)
# View queue:
cat /opt/remote-shield-agent/remote-shield-agent/data/threat-queue.json

# Force sync by restarting
sudo systemctl restart remote-shield
```

## Troubleshooting

### Agent fails to start

**Check logs:**
```bash
sudo journalctl -u remote-shield -n 50 -p err
```

**Common causes:**
- Node.js not installed: `sudo apt install nodejs`
- Port binding: Check if port used by another service
- Permissions: Ensure systemd user has permissions

### Agent shows "offline" in dashboard

**Check last heartbeat:**
```bash
curl http://backend-ip:8000/api/agents | jq '.[0].last_heartbeat'
```

**If heartbeat is old:**
1. SSH to VPS
2. Check agent status: `sudo systemctl status remote-shield`
3. View logs: `sudo journalctl -u remote-shield -f`
4. Restart: `sudo systemctl restart remote-shield`

### Backend connection error

**Verify connectivity:**
```bash
# From VPS
curl http://backend-ip:8000/api/agents
# Should get 200 response

# Check firewall
netstat -tln | grep 8000
```

**If 404 or 500 error:**
1. Check backend is running
2. Verify API routes are loaded
3. Check backend logs

### Threats not detected

**Check detection modules are enabled:**
```bash
cat data/agent.config.json | grep modules
```

**Run manual scan:**
```bash
node index.js scan
```

**If still no threats:**
1. System may genuinely be secure
2. Try to trigger a threat (test):
   - Open port: `nc -l 8888`
   - Create process: `sleep 999 &`
3. Rescan and check if detected

### High CPU/Memory usage

**Reduce scan frequency:**
```json
"scan_interval_seconds": 900  // 15 minutes
```

**Disable heavy modules:**
```json
"modules": {
  "cve_scanner": false  // Most resource intensive
}
```

**Check process list:**
```bash
ps aux | grep -i node
```

### Disk space issues

**Check logs:**
```bash
du -sh data/logs/

# If large, rotate logs
rm data/logs/*.log
```

**Configure log rotation:**
Create `/etc/logrotate.d/remote-shield`:
```
/opt/remote-shield-agent/remote-shield-agent/data/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

## Performance Tuning

### For Busy Production Servers

```json
{
  "scan_interval_seconds": 900,
  "modules": {
    "port_scanner": false,
    "process_monitor": true,
    "file_integrity": false,
    "log_analyzer": true,
    "cve_scanner": false
  },
  "min_severity": 7
}
```

This reduces overhead while keeping critical detections.

### For Security-Sensitive Systems

```json
{
  "scan_interval_seconds": 120,
  "modules": {
    "port_scanner": true,
    "process_monitor": true,
    "file_integrity": true,
    "log_analyzer": true,
    "cve_scanner": true
  },
  "min_severity": 3
}
```

This increases detection sensitivity for high-security environments.

## Scaling to Multiple VPS

### Master-Agent Architecture

1. **Deploy on N VPS systems:**
   - Each runs independent agent
   - Each has unique hostname

2. **Backend aggregates:**
   - Central storage of all threats
   - Real-time dashboard view

3. **Example 3-node setup:**
```bash
# VPS 1
node index.js init http://backend:8000 prod-web-1

# VPS 2
node index.js init http://backend:8000 prod-db-1

# VPS 3
node index.js init http://backend:8000 prod-cache-1

# All report to same backend
```

4. **View all threats:**
```bash
curl http://backend:8000/api/threats/remote-shield
```

5. **View by agent:**
```bash
curl "http://backend:8000/api/threats/remote-shield?agent_id=<id>"
```

## Backup & Recovery

### Backup Agent Configuration

```bash
# Backup credentials and config
tar -czf remote-shield-backup.tar.gz \
  /opt/remote-shield-agent/remote-shield-agent/data/

# Store securely
cp remote-shield-backup.tar.gz /backup/remote-shield-$(date +%Y%m%d).tar.gz
```

### Restore After Loss

```bash
# Extract backup
tar -xzf remote-shield-backup.tar.gz

# Restart agent
sudo systemctl restart remote-shield
```

## Security Best Practices

1. **Use HTTPS in production:**
```bash
node index.js init https://backend.example.com:443 vps-prod-1
```

2. **Restrict agent permissions:**
```bash
# Run as non-root user (requires sudo for some modules)
sudo useradd -r remote-shield
sudo chown -R remote-shield:remote-shield /opt/remote-shield-agent
```

3. **Rotate API tokens periodically:**
```bash
# Re-register agent (gets new token)
node index.js init http://backend:8000 vps-prod-1
```

4. **Firewall rules:**
```bash
# Only allow outbound HTTP to backend
sudo ufw allow out http to backend-ip
```

5. **Audit logs:**
```bash
# Monitor threat submissions
sudo tail -f /var/log/auth.log | grep remote-shield
```

## Undeployment

To remove agent from VPS:

```bash
# Stop service
sudo systemctl stop remote-shield
sudo systemctl disable remote-shield

# Remove service
sudo rm /etc/systemd/system/remote-shield.service

# Remove agent directory
sudo rm -rf /opt/remote-shield-agent

# Remove data
sudo rm -rf /home/remote-shield/data

# Daemon reload
sudo systemctl daemon-reload
```

## Support & Documentation

- **Deployment Guide**: This file
- **API Documentation**: `docs/API_REMOTE_SHIELD.md`
- **Agent README**: `remote-shield-agent/README.md`
- **GitHub Issues**: https://github.com/Mobivs/citadel-watch/issues
- **Logs**: Check `data/logs/` directory

## Version Information

| Component | Version | Status |
|-----------|---------|--------|
| Remote Shield Agent | 1.0 | ✅ Production |
| Backend API | 1.0 | ✅ Production |
| Dashboard UI | 1.0 | ✅ Production |

## Next Steps

1. Deploy agent on first VPS
2. Verify threats appear in dashboard
3. Configure scan intervals for your environment
4. Setup systemd service for production
5. Deploy to remaining VPS infrastructure
6. Monitor dashboard for threats
7. Establish incident response workflow
