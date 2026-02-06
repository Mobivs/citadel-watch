# Citadel Archer - API Reference

REST and WebSocket API documentation for the Citadel Archer dashboard backend.

## Authentication

All API endpoints require a session token passed as a query parameter:

```
GET /api/charts?token=<session_token>
```

The session token is auto-generated at server startup and printed to the console. It can also be retrieved programmatically via `get_session_token()`.

---

## Phase 1 Endpoints

### GET /api/status

System status overview.

**Response:**
```json
{
  "guardian_active": true,
  "security_level": "guardian",
  "threat_level": "low",
  "monitored_paths": ["/home/user"],
  "uptime": 3600
}
```

### GET /api/security-level

Returns the current security level.

### POST /api/security-level

Update the security level.

**Body:**
```json
{ "level": "sentinel" }
```

Valid levels: `observer`, `guardian`, `sentinel`.

### GET /api/processes

List running processes with suspicion indicators.

**Response:**
```json
[
  {
    "pid": 1234,
    "name": "python",
    "username": "user",
    "cpu_percent": 5.2,
    "memory_percent": 1.8
  }
]
```

### POST /api/processes/{pid}/kill

Kill a process by PID. Requires Guardian or Sentinel security level.

### GET /api/events

Recent security events (Phase 1 placeholder).

### GET /api/guardian/start

Start the Guardian file and process monitors.

### GET /api/guardian/stop

Stop the Guardian monitors.

### WebSocket /ws

Real-time event stream for Phase 1 dashboard updates.

**Message format:**
```json
{
  "type": "event",
  "event_type": "file.modified",
  "severity": "alert",
  "message": "Suspicious file change detected",
  "timestamp": "2025-01-15T14:30:00"
}
```

---

## Phase 2 Endpoints

All Phase 2 endpoints are prefixed with `/api/` and require session token authentication.

### GET /api/charts

Threat trend data bucketed by hour for charting.

**Query Parameters:**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `hours` | int | 24 | 1-168 | Lookback window |
| `bucket_hours` | int | 1 | 1-24 | Bucket size |

**Response:**
```json
{
  "period": "24h",
  "points": [
    {
      "timestamp": "2025-01-15T00:00:00",
      "low": 5,
      "medium": 2,
      "high": 1,
      "critical": 0,
      "total": 8
    }
  ],
  "generated_at": "2025-01-15T14:30:00"
}
```

**Caching:** 5-minute TTL. Subsequent requests within the window return cached data.

---

### GET /api/timeline

Alert history timeline with optional filtering.

**Query Parameters:**

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `limit` | int | 100 | 1-1000 | Max entries |
| `severity` | string | null | | Filter by severity |
| `asset_id` | string | null | | Filter by asset |

**Response:**
```json
{
  "entries": [
    {
      "event_id": "uuid-1234",
      "event_type": "file.modified",
      "severity": "alert",
      "message": "Suspicious file change",
      "asset_id": "srv-web-01",
      "timestamp": "2025-01-15T14:30:00",
      "category": "file"
    }
  ],
  "total": 42,
  "generated_at": "2025-01-15T14:30:00"
}
```

**Caching:** 5-minute TTL, keyed by `limit:severity:asset_id`.

---

### GET /api/threat-score

Risk metric summary from the ThreatScorer.

**Response:**
```json
{
  "total_scored": 150,
  "by_risk_level": {
    "low": 80,
    "medium": 45,
    "high": 20,
    "critical": 5
  },
  "recent_critical": 5,
  "recent_high": 20,
  "top_threats": [
    {
      "event_type": "file.created",
      "risk_level": "critical",
      "risk_score": 0.92,
      "asset_id": "srv-web-01",
      "timestamp": "2025-01-15T14:25:00"
    }
  ],
  "generated_at": "2025-01-15T14:30:00"
}
```

**Top threats:** Up to 10, combining the 5 most recent critical and 5 most recent alert events, scored and sorted by risk.

**Caching:** 5-minute TTL.

---

### GET /api/assets

Multi-asset inventory view with event counts.

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | null | Filter by status (online, offline, protected, compromised) |
| `platform` | string | null | Filter by platform (local, vps, windows, macos, linux) |

**Response:**
```json
{
  "assets": [
    {
      "asset_id": "srv-web-01",
      "name": "Web Server",
      "platform": "linux",
      "status": "online",
      "hostname": "web01.internal",
      "ip_address": "10.0.1.10",
      "guardian_active": true,
      "event_count": 42,
      "last_seen": "2025-01-15T14:30:00"
    }
  ],
  "total": 3,
  "by_status": { "online": 2, "protected": 1 },
  "generated_at": "2025-01-15T14:30:00"
}
```

**Caching:** 5-minute TTL, keyed by `status:platform`.

---

### GET /api/cache/stats

Cache statistics for monitoring.

**Response:**
```json
{
  "size": 4,
  "default_ttl": 300.0
}
```

### POST /api/cache/clear

Invalidate all cached responses. Use after configuration changes.

**Response:**
```json
{
  "cleared": 4
}
```

---

## WebSocket: /ws/events (Phase 2)

Real-time event streaming for the Phase 2 dashboard, managed by `EventBroadcaster`.

**Connection:**
```javascript
const ws = new WebSocket("ws://127.0.0.1:8000/ws/events");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

**Message format:**
```json
{
  "type": "threat",
  "event_id": "uuid-1234",
  "event_type": "file.created",
  "risk_level": "critical",
  "risk_score": 0.92,
  "asset_id": "srv-web-01",
  "timestamp": "2025-01-15T14:30:00"
}
```

---

## Error Handling

All endpoints return standard HTTP status codes:

| Code | Meaning |
|------|---------|
| 200 | Success |
| 401 | Invalid or missing session token |
| 422 | Validation error (invalid parameters) |
| 500 | Internal server error |

Error response body:
```json
{
  "detail": "Invalid session token"
}
```

---

## Rate Limiting

No rate limiting is applied. The 5-minute TTL cache naturally throttles expensive queries. For production deployments, add a reverse proxy (nginx) with rate limiting.

## CORS

CORS is configured to allow requests from `http://127.0.0.1` and `http://localhost` only. Adjust `allow_origins` in `main.py` for other deployments.
