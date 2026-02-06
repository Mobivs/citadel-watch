# Phase 2: Intelligence Layer - Architecture

**Version:** 1.0
**Approved:** 2026-02-06 21:15 UTC

---

## System Overview

Phase 2 extends Citadel Archer from **local protection** (Phase 1) to **intelligent, multi-asset protection** with AI-powered threat analysis.

```
┌──────────────────────────────────────────────────────────────┐
│                   INTELLIGENCE LAYER (Phase 2)               │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────────┐  │
│  │         INTEL MODULE (Threat Feeds)                    │  │
│  │  ├─ AlienVault OTX (CVEs, malware, IOCs)              │  │
│  │  ├─ abuse.ch (botnets, phishing hashes)               │  │
│  │  ├─ MITRE ATT&CK (techniques, threat actors)          │  │
│  │  ├─ NVD (system vulnerabilities)                      │  │
│  │  └─ Deduplicate + Store (SQLite)                      │  │
│  └────────────────────────────────────────────────────────┘  │
│                          ↓                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │      WATCHTOWER (Central Intelligence Hub)            │  │
│  │                                                         │  │
│  │  ├─ Asset Inventory                                   │  │
│  │  │  └─ Track local, VPS, other systems               │  │
│  │  │                                                     │  │
│  │  ├─ Event Aggregation                                 │  │
│  │  │  └─ Collect events from all assets                │  │
│  │  │                                                     │  │
│  │  ├─ Context Engine (Behavior Baseline)                │  │
│  │  │  ├─ Build normal profile (7-day rolling window)    │  │
│  │  │  ├─ Detect deviations from baseline                │  │
│  │  │  └─ Reduce false positives by learning             │  │
│  │  │                                                     │  │
│  │  ├─ Anomaly Detector (Isolation Forest)               │  │
│  │  │  ├─ Score deviations (0.0-1.0)                     │  │
│  │  │  ├─ Adjustable sensitivity (default: moderate)     │  │
│  │  │  └─ Output: threat level (LOW/MEDIUM/HIGH)         │  │
│  │  │                                                     │  │
│  │  ├─ Threat Scorer (Risk Assessment)                   │  │
│  │  │  ├─ Severity × Confidence matrix                   │  │
│  │  │  ├─ Cross-reference with Intel feeds               │  │
│  │  │  └─ Output: prioritized threat list                │  │
│  │  │                                                     │  │
│  │  └─ Guardian Updater (Rule Synchronization)           │  │
│  │     ├─ Monitor Intel for new threats                  │  │
│  │     ├─ Auto-generate Guardian rules                   │  │
│  │     └─ Push updates to Guardian observer              │  │
│  │                                                         │  │
│  └────────────────────────────────────────────────────────┘  │
│                          ↓                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │       ADVANCED DASHBOARD (Visualization)              │  │
│  │                                                         │  │
│  │  Backend (FastAPI Extensions):                         │  │
│  │  ├─ /api/charts - Threat trends over time            │  │
│  │  ├─ /api/timeline - Alert timeline                   │  │
│  │  ├─ /api/threat-score - Risk metrics                 │  │
│  │  ├─ /api/assets - Multi-asset overview               │  │
│  │  └─ WebSocket /ws - Real-time updates                │  │
│  │                                                         │  │
│  │  Frontend (Vanilla JS):                                │  │
│  │  ├─ Threat Trend Chart (Chart.js)                     │  │
│  │  ├─ Alert Timeline (D3.js/custom)                     │  │
│  │  ├─ Risk Score Display (visual gauge)                 │  │
│  │  ├─ Asset List (responsive grid)                      │  │
│  │  └─ Real-time event stream (WebSocket)                │  │
│  │                                                         │  │
│  └────────────────────────────────────────────────────────┘  │
│                          ↓                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │       INTEGRATION WITH PHASE 1 MODULES                │  │
│  │                                                         │  │
│  │  ├─ Guardian (receives updated threat rules)          │  │
│  │  ├─ EventBus (publishes Intel & anomaly events)       │  │
│  │  ├─ Dashboard (displays Watchtower data)              │  │
│  │  ├─ Audit Logger (logs all Intel queries)             │  │
│  │  └─ SecretsStore (credential validation vs. breaches) │  │
│  │                                                         │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. Intel Module (`intel.py`)

**Responsibility:** Fetch, aggregate, and deduplicate threat intelligence

**Classes:**
- `IntelFetcher` - Abstract base for feed fetchers
- `OTXFetcher` - AlienVault OTX integration
- `AbuseChFetcher` - abuse.ch integration
- `MITREFetcher` - MITRE ATT&CK integration
- `NVDFetcher` - NVD CVE database integration
- `IntelAggregator` - Central coordinator (fetch, deduplicate, store)
- `IntelDB` - Threat feed storage & retrieval

**Database Schema:**
```sql
CREATE TABLE threat_feeds (
  id TEXT PRIMARY KEY,
  type TEXT,  -- CVE|IOC|TTP|VULNERABILITY
  title TEXT,
  source TEXT,  -- OTX|abuse.ch|MITRE|NVD
  severity TEXT,  -- LOW|MEDIUM|HIGH|CRITICAL
  description TEXT,
  indicators JSON,
  updated_at TIMESTAMP,
  ttl INTEGER  -- days
);
```

**Scheduling:** APScheduler (daily fetch at 02:00 UTC)

---

### 2. Watchtower (`watchtower.py`)

**Responsibility:** Central multi-asset monitoring, behavior analysis, anomaly detection

**Classes:**
- `Asset` - Represents monitored system (local, VPS, other)
- `AssetInventory` - Manage all monitored assets
- `EventAggregator` - Collect events from Phase 1 modules
- `ContextEngine` - Build behavior baselines, detect anomalies
- `AnomalyDetector` - Isolation Forest + custom rules
- `ThreatScorer` - Risk assessment matrix
- `GuardianUpdater` - Sync with Guardian module

**Key Features:**

**Asset Inventory:**
- Track local machine, VPS, family PCs
- Status: ONLINE|OFFLINE|PROTECTED|COMPROMISED
- Threat level: ALL_CLEAR|CAUTION|ALERT|CRITICAL

**Context Engine:**
- Build 7-day rolling baseline of normal behavior
- Track per-asset: process spawns, file modifications, network connections
- Learn patterns (e.g., "backup runs daily at 2 AM")
- Detect deviations (e.g., "unexpected process from System32")

**Anomaly Detector:**
- Isolation Forest from scikit-learn
- Sensitivity adjustable: LOW|MODERATE|HIGH (default: MODERATE)
- Output: anomaly_score (0.0-1.0), threat_level (LOW/MEDIUM/HIGH)
- Cross-reference with Intel feeds for known threats

**Threat Scorer:**
- Risk matrix: Severity × Confidence
- Examples:
  - HIGH severity + HIGH confidence = CRITICAL threat
  - MEDIUM severity + LOW confidence = CAUTION
- Prioritize for display in dashboard

**Guardian Updater:**
- Monitor Intel for new threats (malware hashes, C2 IPs, etc.)
- Generate Guardian rules automatically
- Example: "If file hash matches CVE-2024-1234 malware, quarantine"
- Push updates to Guardian observer without restarting

---

### 3. Advanced Dashboard Extensions

**Backend (`dashboard_v2.py`):**
- Extend Phase 1 dashboard with new endpoints
- `/api/charts` - Threat trends (last 7/30 days)
- `/api/timeline` - Alert timeline (filterable by asset, severity)
- `/api/threat-score` - Current risk metrics
- `/api/assets` - Multi-asset overview
- WebSocket updates on new threats/anomalies

**Frontend (`dashboard_v2.js`):**
- Threat Trend Chart (Chart.js line chart)
- Alert Timeline (D3.js or custom timeline)
- Risk Gauge (visual threat level indicator)
- Asset List (grid showing all systems)
- Responsive (works on desktop + tablet)

**Visualization Examples:**
- X-axis: Time (hourly/daily)
- Y-axis: Threat count, severity distribution
- Colors: Green (safe) → Yellow (caution) → Red (critical)
- Drill-down: Click alert → See details

---

## Data Flow

### Threat Intelligence Flow

```
1. Intel Module (scheduled daily)
   ├─ Fetch from OTX
   ├─ Fetch from abuse.ch
   ├─ Fetch from MITRE
   ├─ Fetch from NVD
   ├─ Deduplicate
   └─ Store in IntelDB

2. Watchtower queries IntelDB
   ├─ Load new/updated threats
   ├─ Extract indicators (hashes, IPs, domains, techniques)
   └─ Update threat scoring rules

3. Guardian receives updated rules
   ├─ Check files against malware hashes
   ├─ Check network connections against C2 IPs
   ├─ Check processes against known TTPs
   └─ Trigger alerts if matched
```

### Anomaly Detection Flow

```
1. Phase 1 modules emit events
   ├─ FileMonitor: file_modified, file_deleted
   ├─ ProcessMonitor: process_spawned, process_terminated
   ├─ NetworkMonitor (Phase 2): network_connection
   └─ EventBus: aggregate all

2. Watchtower receives events
   ├─ ContextEngine: compare to baseline
   ├─ AnomalyDetector: score deviation
   ├─ ThreatScorer: assess risk
   └─ EventBus: publish anomaly_detected

3. Dashboard displays anomaly
   ├─ Timeline: add to alert timeline
   ├─ Charts: increment threat count
   └─ WebSocket: real-time update to clients
```

---

## Integration Points with Phase 1

| Phase 1 Module | Integration | Data Flow |
|---|---|---|
| Guardian | Rule updates | Intel → Guardian Updater → Guardian rules |
| EventBus | Event source | All events → Watchtower aggregator |
| Dashboard | Display | Watchtower → Dashboard API → Charts |
| Audit Logger | Logging | All Intel queries & anomalies logged |
| SecretsStore | Validation | Check credentials vs. breach databases |

---

## Technology Choices

| Component | Technology | Rationale |
|---|---|---|
| Threat Feed Fetch | `requests` + `APScheduler` | Simple HTTP, reliable scheduling |
| Data Processing | `pandas` | Easy deduplication, aggregation |
| Anomaly Detection | `scikit-learn` (Isolation Forest) | Unsupervised, handles multi-dimensional data |
| Behavior Baseline | Numpy/SciPy | Time-series analysis, statistical |
| Dashboard Charts | `Chart.js` | Vanilla JS, no build step, responsive |
| Timeline | `D3.js` or custom | Rich data visualization, customizable |
| Real-time | WebSocket (Phase 1) | Low latency, already implemented |
| Storage | SQLite/PostgreSQL | Persistent threat feed storage |

---

## Operational Characteristics

**Latency:**
- Threat feed update: ~1-2 min (daily scheduled)
- Anomaly detection: <100ms (real-time)
- Dashboard query: <1 sec (cached)

**Storage:**
- Intel database: ~100-500 MB (depending on history retention)
- Baseline data: ~10-50 MB (7-day rolling window per asset)
- Anomaly records: ~100 MB/year (normal operation)

**Scalability:**
- Supports ≥10 monitored assets in Phase 2
- Phase 3 extends to 100+ assets

**Reliability:**
- Feed fetch failures: Retry with exponential backoff
- Watchtower crash: Restart, rebuild baselines from event log
- Dashboard queries: Cache with 5-min TTL

---

## Success Metrics

- **Intel Coverage:** ≥95% of known CVEs within 24h of publication
- **Anomaly Detection:** ≥80% true positive rate on test set
- **False Positive Rate:** <5% (after 7 days of baseline learning)
- **Dashboard Performance:** <1 sec query latency (p95)
- **Availability:** ≥99.9% uptime (excluding maintenance)

---

## Future Enhancements (Phase 3+)

- Machine learning model persistence (train once, load on restart)
- Threat correlation (detect attack chains across assets)
- Advanced reporting (PDF export, email digests)
- Custom threat feed integration (user-supplied sources)
- Vulnerability scanner integration (scan local system)

---

Designed by: Autonomous AI Development Team
Approved: Scott Vickrey, 2026-02-06 21:15 UTC
