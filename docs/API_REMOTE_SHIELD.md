# Remote Shield API Documentation

Remote Shield API provides endpoints for agent registration, threat submission, and status management. All endpoints are part of the `/api` namespace.

## Authentication

All Remote Shield endpoints (except agent registration) require Bearer token authentication:

```
Authorization: Bearer <api_token>
```

API tokens are issued during agent registration and must be included in all requests.

## Endpoints

### Agent Management

#### Register Agent
```http
POST /api/agents/register
Content-Type: application/json

{
  "hostname": "vps-prod-1",
  "ip": "192.168.1.100",
  "public_key": null
}
```

**Response (200 OK):**
```json
{
  "agent_id": "550e8400-e29b-41d4-a716-446655440000",
  "api_token": "sk-agent-...",
  "message": "Agent registered successfully"
}
```

**Errors:**
- `400 Bad Request`: Missing required fields
- `409 Conflict`: Agent already registered (returns existing token)

---

#### List All Agents
```http
GET /api/agents
Authorization: Bearer <api_token>
```

**Response (200 OK):**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "hostname": "vps-prod-1",
    "ip_address": "192.168.1.100",
    "status": "active",
    "last_heartbeat": "2026-02-07T18:30:00Z",
    "registered_at": "2026-02-01T10:00:00Z",
    "last_scan_at": "2026-02-07T18:25:00Z"
  }
]
```

---

#### Get Agent Details
```http
GET /api/agents/{agent_id}
Authorization: Bearer <api_token>
```

**Response (200 OK):**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "hostname": "vps-prod-1",
  "ip_address": "192.168.1.100",
  "status": "active",
  "last_heartbeat": "2026-02-07T18:30:00Z",
  "registered_at": "2026-02-01T10:00:00Z",
  "last_scan_at": "2026-02-07T18:25:00Z"
}
```

**Errors:**
- `404 Not Found`: Agent does not exist

---

#### Send Heartbeat
```http
POST /api/agents/{agent_id}/heartbeat
Authorization: Bearer <api_token>
```

**Response (200 OK):**
```json
{
  "status": "ok",
  "next_scan_interval": 300
}
```

**Notes:**
- Agent token must match agent_id
- Updates agent status to "active"
- Updates last_heartbeat timestamp

---

### Threat Management

#### Submit Threat
```http
POST /api/threats/remote-shield
Authorization: Bearer <api_token>
Content-Type: application/json

{
  "type": "vulnerability",
  "severity": 8,
  "title": "CVE-2024-1234: Critical RCE in OpenSSL",
  "details": {
    "package": "openssl",
    "installed_version": "1.1.1g",
    "fix_available": "1.1.1h",
    "cve_id": "CVE-2024-1234",
    "cvss_score": 9.8
  },
  "hostname": "vps-prod-1",
  "timestamp": "2026-02-07T18:30:00Z"
}
```

**Response (200 OK):**
```json
{
  "id": "threat-uuid-here",
  "status": "success",
  "message": "Threat recorded successfully"
}
```

**Threat Types:**
- `port_scan_anomaly` - Unexpected open port
- `process_anomaly` - Suspicious process
- `file_integrity` - Critical file modified
- `brute_force_attempt` - Brute-force attack detected
- `vulnerability` - Known CVE in package
- `config_change` - Configuration file changed
- `unauthorized_access` - Unauthorized access attempt

**Severity Levels:**
- 1-3: Low
- 4-6: Medium
- 7-8: High
- 9-10: Critical

**Errors:**
- `400 Bad Request`: Invalid threat data
- `401 Unauthorized`: Invalid token

---

#### List Threats
```http
GET /api/threats/remote-shield?agent_id={id}&threat_type={type}&status={status}&limit={n}&offset={n}
Authorization: Bearer <api_token>
```

**Query Parameters:**
- `agent_id` (optional): Filter by agent
- `threat_type` (optional): Filter by threat type
- `status` (optional): Filter by status (open, acknowledged, resolved)
- `limit` (optional, default=100): Max results
- `offset` (optional, default=0): Pagination offset

**Response (200 OK):**
```json
[
  {
    "id": "threat-uuid",
    "agent_id": "agent-uuid",
    "type": "vulnerability",
    "severity": 8,
    "title": "CVE-2024-1234: Critical RCE",
    "details": {...},
    "hostname": "vps-prod-1",
    "detected_at": "2026-02-07T18:30:00Z",
    "reported_at": "2026-02-07T18:30:05Z",
    "status": "open",
    "created_at": "2026-02-07T18:30:05Z"
  }
]
```

---

#### Get Threat Details
```http
GET /api/threats/remote-shield/{threat_id}
Authorization: Bearer <api_token>
```

**Response (200 OK):**
```json
{
  "id": "threat-uuid",
  "agent_id": "agent-uuid",
  "type": "vulnerability",
  "severity": 8,
  "title": "CVE-2024-1234: Critical RCE",
  "details": {...},
  "hostname": "vps-prod-1",
  "detected_at": "2026-02-07T18:30:00Z",
  "reported_at": "2026-02-07T18:30:05Z",
  "status": "open",
  "created_at": "2026-02-07T18:30:05Z"
}
```

**Errors:**
- `404 Not Found`: Threat does not exist

---

#### Update Threat Status
```http
PATCH /api/threats/remote-shield/{threat_id}/status
Authorization: Bearer <api_token>
Content-Type: application/json

{
  "new_status": "acknowledged"
}
```

**Valid Status Values:**
- `open` - Initial state
- `acknowledged` - Operator has seen the threat
- `resolved` - Threat has been resolved

**Response (200 OK):**
```json
{
  "id": "threat-uuid",
  "status": "acknowledged",
  "message": "Threat status updated"
}
```

---

## Response Formats

### Success Response
```json
{
  "id": "resource-id",
  "status": "success",
  "message": "Human-readable message",
  "data": {}
}
```

### Error Response
```json
{
  "detail": "Error description",
  "status_code": 400
}
```

---

## Rate Limiting

No rate limiting is currently implemented. For production, consider:
- Agent: 1 heartbeat per 60 seconds
- Agent: Batch threat submissions (max 100 per request)
- Dashboard: Standard API limits

---

## Threat Detection Data Model

### Threat Fields

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Threat category |
| `severity` | integer | 1-10 severity score |
| `title` | string | Human-readable threat title |
| `details` | object | Threat-specific data (flexible) |
| `hostname` | string | System hostname where detected |
| `timestamp` | ISO 8601 | When threat was detected |

### Example Threat Details by Type

**Port Scan Anomaly:**
```json
{
  "port": 8888,
  "allOpenPorts": [22, 80, 443, 8888],
  "expectedBaseline": [22, 80, 443],
  "anomalyCount": 1
}
```

**Process Anomaly:**
```json
{
  "processName": "weird-process",
  "pid": 12345,
  "user": "nobody",
  "reasons": ["suspicious-name", "non-whitelisted"],
  "commandLine": "/usr/bin/weird-process --malicious"
}
```

**File Integrity:**
```json
{
  "file": "/etc/passwd",
  "expectedHash": "abc123...",
  "currentHash": "def456...",
  "detected": "2026-02-07T18:30:00Z"
}
```

**Brute Force:**
```json
{
  "sourceIP": "192.168.1.50",
  "failedAttempts": 12,
  "threshold": 5,
  "timeWindow": "5 minutes",
  "firstAttempt": "2026-02-07T18:20:00Z",
  "lastAttempt": "2026-02-07T18:25:00Z"
}
```

**Vulnerability:**
```json
{
  "package": "openssl",
  "installedVersion": "1.1.1g",
  "cveId": "CVE-2024-1234",
  "cvssScore": 9.8,
  "description": "Critical RCE in OpenSSL",
  "updateAvailable": true
}
```

---

## Example Workflows

### Agent Registration & First Scan

1. Agent starts up
2. Calls `POST /api/agents/register` with hostname and IP
3. Receives `agent_id` and `api_token`
4. Saves credentials locally
5. Initializes file integrity baseline
6. Enters monitoring loop

### Continuous Monitoring

1. Agent runs threat detection scan (every 5 min)
2. For each threat detected, calls `POST /api/threats/remote-shield`
3. Agent sends heartbeat every 60 seconds
4. Backend broadcasts threats to WebSocket subscribers
5. Dashboard displays threats in real-time

### Offline Resilience

1. Agent submits threat, backend returns error
2. Agent queues threat locally
3. Continues scanning and detecting
4. Periodically attempts sync
5. On reconnection, submits queued threats
6. Dashboard shows threats once synced

---

## Security Considerations

1. **Token Security**
   - Store API tokens securely
   - Rotate tokens periodically
   - Don't log or transmit plaintext tokens

2. **TLS**
   - Always use HTTPS in production
   - Verify certificate validity

3. **mTLS (Future)**
   - Mutual TLS authentication available
   - Use public keys for agent identification

4. **Data Validation**
   - Backend validates all threat data
   - Sanitizes user inputs
   - Rejects malformed requests

---

## Troubleshooting

### Agent Fails to Register
- Check backend connectivity
- Verify backend is running
- Check firewall rules

### Threats Not Appearing
- Verify agent token is valid
- Check threat severity >= min_severity
- Review agent logs for errors

### Dashboard Shows Offline Agent
- Check last_heartbeat timestamp
- Agent may have crashed
- Check agent logs

### High API Latency
- Check network connectivity
- Monitor backend resource usage
- Consider batching threat submissions

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-07 | Initial Remote Shield API |

---

## Support

For issues or questions:
1. Check deployment guide
2. Review agent logs: `data/logs/`
3. Verify API endpoints with curl
4. Check GitHub issues
