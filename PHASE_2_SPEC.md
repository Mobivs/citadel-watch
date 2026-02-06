# Phase 2.1: Intelligence Layer - Specification

**Version:** 1.0
**Status:** Ready for Implementation
**Approved:** 2026-02-06 21:15 UTC

---

## Requirements

### Must-Haves (13 items)

1. **Intel Module**
   - [ ] Fetch from AlienVault OTX (CVEs, malware, IOCs)
   - [ ] Fetch from abuse.ch (botnets, phishing, malware)
   - [ ] Fetch from MITRE ATT&CK (techniques, TTPs)
   - [ ] Fetch from NVD (system vulnerabilities)
   - [ ] Deduplicate across feeds
   - [ ] Daily scheduled updates

2. **Watchtower**
   - [ ] Multi-asset inventory (local, VPS, other systems)
   - [ ] Event aggregation from all assets
   - [ ] Context engine learns baseline behavior
   - [ ] Anomaly detection (moderate, user-adjustable)
   - [ ] Threat scoring system
   - [ ] Auto-update Guardian rules from Intel

3. **Advanced Dashboard**
   - [ ] Threat trend charts
   - [ ] Alert timeline visualization
   - [ ] Risk metrics display
   - [ ] Multi-asset overview

### Nice-to-Haves (7 items)

- [ ] Custom threat feed integration (user-supplied feeds)
- [ ] Threat actor profiling UI
- [ ] Vulnerability scanner integration
- [ ] Community threat sharing (anonymized)
- [ ] Advanced reporting (PDF export)
- [ ] Threat correlation (attack chains)
- [ ] Machine learning model persistence

---

## Architecture

### Intel Module
```
┌─────────────────────────────────────┐
│    Threat Feed Aggregator           │
├─────────────────────────────────────┤
│ ├─ OTX Fetcher                      │
│ ├─ abuse.ch Fetcher                 │
│ ├─ MITRE Fetcher                    │
│ ├─ NVD Fetcher                      │
│ ├─ Deduplication Engine             │
│ └─ Scheduler (daily updates)         │
├─────────────────────────────────────┤
│ Database: threat_feeds (CVEs, IOCs) │
└─────────────────────────────────────┘
```

### Watchtower
```
┌──────────────────────────────────────┐
│      Watchtower Hub                  │
├──────────────────────────────────────┤
│ ├─ Asset Inventory (local, VPS...)   │
│ ├─ Event Aggregator                  │
│ ├─ Context Engine (behavior baseline)│
│ ├─ Anomaly Detector (IsolationForest)│
│ ├─ Threat Scorer (risk assessment)   │
│ └─ Guardian Updater (rule sync)      │
├──────────────────────────────────────┤
│ Database: assets, baselines, anomalies
└──────────────────────────────────────┘
```

### Advanced Dashboard
```
┌──────────────────────────────────────┐
│      Dashboard Backend               │
├──────────────────────────────────────┤
│ ├─ /api/charts (threat trends)       │
│ ├─ /api/timeline (alert history)     │
│ ├─ /api/threat-score (risk metrics)  │
│ ├─ /api/assets (multi-asset view)    │
│ └─ WebSocket (real-time updates)     │
├──────────────────────────────────────┤
│      Dashboard Frontend              │
├──────────────────────────────────────┤
│ ├─ Charts (Chart.js)                 │
│ ├─ Timeline (D3.js)                  │
│ ├─ Risk UI (visual scoring)          │
│ └─ Asset list (responsive)           │
└──────────────────────────────────────┘
```

---

## Data Models

### Threat Feed Item
```python
{
  "id": "unique_hash",
  "type": "CVE|IOC|TTP|VULNERABILITY",
  "title": "threat_name",
  "source": "OTX|abuse.ch|MITRE|NVD",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "description": "...",
  "indicators": {
    "cve_id": "CVE-2024-1234",
    "hash": "malware_hash",
    "ip": "attacker_ip",
    "domain": "c2_domain",
    "tactic": "MITRE_tactic",
    "technique": "MITRE_technique"
  },
  "updated_at": "2026-02-06T21:15:00Z",
  "ttl": 30  # days
}
```

### Asset
```python
{
  "id": "unique_id",
  "name": "local_machine|vps_1|family_pc",
  "type": "LOCAL|VPS|WINDOWS|MAC",
  "status": "ONLINE|OFFLINE|PROTECTED|COMPROMISED",
  "threat_level": "ALL_CLEAR|CAUTION|ALERT|CRITICAL",
  "last_event": "2026-02-06T21:15:00Z"
}
```

### Anomaly
```python
{
  "id": "unique_id",
  "asset_id": "asset_id",
  "event_type": "file_modified|process_spawned|network_connection",
  "baseline": "expected_behavior",
  "observed": "actual_behavior",
  "deviation_score": 0.0-1.0,  # 0 = normal, 1 = highly anomalous
  "threat_level": "LOW|MEDIUM|HIGH",
  "timestamp": "2026-02-06T21:15:00Z",
  "auto_action": "none|quarantine|alert|block"
}
```

---

## Success Criteria

- [ ] All 4 threat feeds operational (data flowing daily)
- [ ] Watchtower aggregates events from ≥2 assets
- [ ] Anomaly detection accuracy ≥80% (validated against test set)
- [ ] Context engine reduces false positives by ≥30%
- [ ] Dashboard displays charts, timeline, threat scores
- [ ] Guardian rules auto-update from Intel
- [ ] All components integrated and tested
- [ ] <1 second latency for dashboard queries
- [ ] Documentation complete

---

## Technical Decisions

1. **Anomaly Detection:** Isolation Forest (scikit-learn) + custom rules
2. **Behavior Baseline:** Time-series analysis (7-day rolling window)
3. **Threat Scoring:** Risk matrix (severity × confidence)
4. **Update Frequency:** Daily for threat feeds, real-time for events
5. **Database:** SQLite (Phase 1) or PostgreSQL (if scaling)
6. **Frontend:** Vanilla JS + Chart.js + D3.js (no external build tools)

---

## Constraints & Dependencies

- Phase 1 must be complete and operational
- Guardian rules engine must be active
- Dashboard backend (FastAPI) must be running
- EventBus must be operational
- Audit logging must be functional

---

Approved by Scott Vickrey, 2026-02-06 21:15 UTC

---

## Implementation Clarifications (2026-02-06 21:35 UTC)

### Anomaly Sensitivity Levels (Numerical Thresholds)

**Isolation Forest Anomaly Score Interpretation:**
- LOW: threshold = 0.4 (catches most deviations, ~10% false positive rate)
- MODERATE (default): threshold = 0.6 (balanced, ~5% false positive rate)
- HIGH: threshold = 0.8 (only obvious anomalies, <2% false positive rate, misses subtle threats)

**User Adjustment:** Via dashboard settings, affects /api/threat-score and Guardian rule triggers

### Feed Failure Handling (T6)

**Resilience Strategy:**
- If all feeds fail: Use cached data from last successful run (up to 7 days old)
- If 1-3 feeds fail: Proceed with successful feeds, log failures
- If 0 feeds succeed for 24h: Alert operator, escalate to manual check
- Retry logic: 3 attempts, exponential backoff (1s, 2s, 4s)

### Baseline Cold Start (T8: Context Engine)

**Days 0-6 (Before Full Baseline):**
- Use statistical defaults: assume all events have 0.3 anomaly score
- After day 1: Build partial baseline from accumulated events
- After day 7: Switch to full learned baseline (Isolation Forest ready)
- Decay schedule: Scale factor decreases from 1.0 to 0.0 over 7 days

**Impact:** Users see gentle warnings during cold start, not panic

### Guardian Rule Schema (T11)

**Rule Format:**
```json
{
  "id": "rule_20260206_001",
  "source": "intel_module|context_engine",
  "threat_type": "file_hash|c2_ip|c2_domain|tttp_pattern|vulnerability",
  "indicator": "abc123def456...|192.0.2.1|example.com|MITRE_T1234|CVE-2024-1234",
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.5-1.0,
  "action": "observe|alert|quarantine|block|rotate_credentials",
  "auto_execute": true|false,
  "created_at": "2026-02-06T21:35:00Z",
  "expires_at": "2026-02-13T21:35:00Z"
}
```

**Example Rules:**
```json
{
  "threat_type": "file_hash",
  "indicator": "e99a18c428cb38d5f260853678922e03",
  "severity": "CRITICAL",
  "action": "quarantine",
  "source": "intel_module",
  "confidence": 0.95
}

{
  "threat_type": "c2_ip",
  "indicator": "192.0.2.1",
  "severity": "HIGH",
  "action": "block",
  "source": "context_engine",
  "confidence": 0.75
}
```

### Cross-Asset Threat Correlation (Future: Phase 3)

**Design for Extensibility:**
- Each anomaly includes `asset_id` and `asset_type`
- Threat scorer already accepts multi-asset context
- Ready to add: "if same threat detected on 2+ assets, escalate to CRITICAL"
- Not required for Phase 2, but architecture supports it

---

Updated by: Forge
Approved: Scott Vickrey, 2026-02-06 21:35 UTC
