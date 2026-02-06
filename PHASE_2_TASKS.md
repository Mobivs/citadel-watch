# Phase 2: Intelligence Layer - Task Breakdown

**Total Tasks:** 20
**Waves:** 3 (6 + 6 + 8)
**Estimated Duration:** 30-40 hours of autonomous work
**Status:** Ready for execution

---

## Wave 1: Intel Module Foundation (6 tasks)

### T1 - Intel Module Architecture & Schema

**Status:** 🟢 Ready
**Effort:** M (Medium)
**Depends On:** Nothing
**Owner:** Opus Lead

**Description:**
- Create `intel.py` module structure
- Define threat feed data models (CVE, IOC, TTP, VULNERABILITY)
- Create SQLite schema for threat_feeds table
- Define `IntelFetcher` abstract base class
- Create thread-safe queue for feed items
- Implement item deduplication (hash-based)

**Acceptance Criteria:**
- [ ] intel.py created with all base classes
- [ ] SQLite schema validated
- [ ] Deduplication works for duplicate feeds
- [ ] 20+ unit tests (schema, models, dedup)
- [ ] No external feed fetching yet (just structure)

**Blocking:** T2-T5 (feed integrations)

---

### T2 - AlienVault OTX Integration

**Status:** 🟡 Can start after T1
**Effort:** S (Small)
**Depends On:** T1
**Owner:** Dev Agent

**Description:**
- Create `OTXFetcher` class
- Fetch CVEs from OTX (using API key or public feed)
- Parse CVE entries (id, severity, description, affected software)
- Handle pagination
- Extract IoCs (malware hashes, IPs, domains)
- Full error handling + retry logic

**Acceptance Criteria:**
- [ ] OTXFetcher fetches >1000 CVE entries
- [ ] Parses all required fields
- [ ] Handles API rate limits
- [ ] Retries on failure (3 attempts, exponential backoff)
- [ ] 15+ unit tests (parsing, error handling, pagination)

**Blocking:** T6

---

### T3 - abuse.ch Integration

**Status:** 🟡 Can start after T1
**Effort:** S (Small)
**Depends On:** T1
**Owner:** Dev Agent

**Description:**
- Create `AbuseChFetcher` class
- Fetch botnets from abuse.ch (Zeus, Mirai, etc.)
- Fetch phishing domains
- Fetch malware hashes (MD5, SHA1, SHA256)
- Parse and normalize data
- Handle CSV/JSON formats from multiple endpoints

**Acceptance Criteria:**
- [ ] Fetches botnet IPs + domains
- [ ] Fetches phishing domains (>1000 entries)
- [ ] Fetches malware hashes (>10K entries)
- [ ] Normalizes hash formats
- [ ] 15+ unit tests

**Blocking:** T6

---

### T4 - MITRE ATT&CK Integration

**Status:** 🟡 Can start after T1
**Effort:** S (Small)
**Depends On:** T1
**Owner:** Dev Agent

**Description:**
- Create `MITREFetcher` class
- Fetch MITRE ATT&CK framework (techniques, tactics)
- Map to threat actors (APT groups)
- Extract TTPs (Techniques, Tactics, Procedures)
- Store malware families and tool signatures

**Acceptance Criteria:**
- [ ] Fetches all MITRE techniques (>400)
- [ ] Maps tactics to techniques correctly
- [ ] Links to threat actors
- [ ] Parses malware/tool metadata
- [ ] 15+ unit tests

**Blocking:** T6

---

### T5 - NVD CVE Feed Integration

**Status:** 🟡 Can start after T1
**Effort:** S (Small)
**Depends On:** T1
**Owner:** Dev Agent

**Description:**
- Create `NVDFetcher` class
- Fetch from NVD CVE database (json.nist.gov)
- Extract: CVE ID, severity (CVSS score), description, affected software
- Handle incremental/full feed updates
- Parse CVSS v3.0+ scores

**Acceptance Criteria:**
- [ ] Fetches >50K CVE entries
- [ ] Parses CVSS scores correctly
- [ ] Handles incremental updates
- [ ] Extracts affected software/versions
- [ ] 15+ unit tests

**Blocking:** T6

---

### T6 - Threat Feed Aggregation & Deduplication

**Status:** 🟡 Can start after T2-T5
**Effort:** M (Medium)
**Depends On:** T1, T2, T3, T4, T5
**Owner:** Dev Agent

**Description:**
- Create `IntelAggregator` coordinator class
- Schedule daily fetches at 02:00 UTC (APScheduler)
- Run all 4 fetchers in parallel (thread pool)
- Deduplicate across feeds (by hash/CVE ID)
- Merge entries (keep most recent, highest severity)
- Store in IntelDB with timestamp
- Log all fetch operations

**Acceptance Criteria:**
- [ ] All 4 fetchers run daily (scheduled)
- [ ] Parallel execution (concurrent threads)
- [ ] Deduplication working (verified on overlap)
- [ ] Merges entries correctly
- [ ] Logs all operations to audit trail
- [ ] 20+ unit tests (scheduling, aggregation, dedup)

**Blocking:** Wave 2 (T7)

---

## Wave 2: Watchtower & Context Engine (6 tasks)

### T7 - Asset Inventory & Event Aggregation

**Status:** 🟡 Can start after T6
**Effort:** M (Medium)
**Depends On:** T6
**Owner:** Opus Lead

**Description:**
- Create `Asset` class (local, VPS, Windows, Mac)
- Create `AssetInventory` manager
- Track asset status (ONLINE, OFFLINE, PROTECTED, COMPROMISED)
- Create `EventAggregator` to collect Phase 1 events
- Subscribe to EventBus for all events (file, process, network)
- Store event history with asset attribution

**Acceptance Criteria:**
- [ ] Asset registration working
- [ ] Asset status tracking (last heartbeat)
- [ ] Event aggregation from EventBus
- [ ] Event history queryable by asset/type/time
- [ ] Handles events from 2+ assets
- [ ] 25+ unit tests

**Blocking:** T8, T9

---

### T8 - Context Engine & Behavior Baseline

**Status:** 🟡 Can start after T7
**Effort:** M (Medium)
**Depends On:** T7
**Owner:** Dev Agent

**Description:**
- Create `ContextEngine` class
- Build behavior baseline from event history
- 7-day rolling window (configurable)
- Track per-asset: process spawns, file modifications, network connections
- Learn patterns (e.g., "backup runs 2 AM daily")
- Compare new events to baseline

**Acceptance Criteria:**
- [ ] Baseline built from 7-day event history
- [ ] Detects normal patterns (recurring events)
- [ ] Compares new events to baseline
- [ ] Outputs: baseline_match (true/false), confidence (0.0-1.0)
- [ ] Handles cold start (day 0-6 learning)
- [ ] 20+ unit tests (baseline, pattern detection)

**Blocking:** T9

---

### T9 - Anomaly Detector (Isolation Forest + Rules)

**Status:** 🟡 Can start after T8
**Effort:** M (Medium)
**Depends On:** T7, T8
**Owner:** Dev Agent

**Description:**
- Create `AnomalyDetector` class
- Implement Isolation Forest (scikit-learn) for multi-dimensional anomaly detection
- Add custom rules (e.g., "unsigned executable in System32")
- Score deviations: 0.0 (normal) to 1.0 (highly anomalous)
- Map scores to threat levels: LOW, MEDIUM, HIGH
- Adjustable sensitivity: LOW, MODERATE (default), HIGH
- Handle cold start gracefully

**Acceptance Criteria:**
- [ ] Isolation Forest model trains on baseline events
- [ ] Custom rules implemented
- [ ] Anomaly scores (0.0-1.0) computed correctly
- [ ] Threat level mapping (score → LOW/MEDIUM/HIGH)
- [ ] Sensitivity adjustable via config
- [ ] Default: MODERATE sensitivity
- [ ] 25+ unit tests (scoring, rules, sensitivity)

**Blocking:** T10

---

### T10 - Threat Scorer (Risk Assessment)

**Status:** 🟡 Can start after T9
**Effort:** S (Small)
**Depends On:** T6, T9
**Owner:** Dev Agent

**Description:**
- Create `ThreatScorer` class
- Risk matrix: Severity × Confidence
- Cross-reference anomalies with Intel feeds
- Examples:
  - File hash matches malware in Intel + HIGH confidence → CRITICAL
  - Process matches MITRE TTP + MEDIUM confidence → HIGH
  - Unusual network connection + MEDIUM anomaly score → MEDIUM
- Output: prioritized threat list

**Acceptance Criteria:**
- [ ] Risk matrix working (16 combinations tested)
- [ ] Cross-references Intel feeds
- [ ] Outputs prioritized threat list
- [ ] Handles missing data gracefully
- [ ] 15+ unit tests (scoring, priority)

**Blocking:** T11, T13

---

### T11 - Guardian Rule Synchronization

**Status:** 🟡 Can start after T10
**Effort:** M (Medium)
**Depends On:** T10
**Owner:** Opus Lead

**Description:**
- Create `GuardianUpdater` class
- Monitor Intel feeds for new threats
- Auto-generate Guardian rules (file hash, C2 IP/domain, TTP patterns)
- Format: threat_type, indicator, severity, action
- Publish to Guardian observer (via EventBus)
- Handle rule conflicts (prioritize by severity)
- Don't restart Guardian (hot reload)

**Acceptance Criteria:**
- [ ] Watches Intel for new threats
- [ ] Generates Guardian rules correctly
- [ ] Rules published to Guardian observer
- [ ] No Guardian restart required
- [ ] Conflicts resolved by severity
- [ ] Audit logging for all rule updates
- [ ] 20+ unit tests (rule generation, conflict resolution)

**Blocking:** Nothing (Wave 2 complete with this)

---

## Wave 3: Advanced Dashboard (8 tasks)

### T12 - Advanced Dashboard Backend Setup

**Status:** 🟡 Can start after T10
**Effort:** M (Medium)
**Depends On:** T10, T7
**Owner:** Opus Lead

**Description:**
- Extend Phase 1 dashboard backend (FastAPI)
- Create new endpoints: /api/charts, /api/timeline, /api/threat-score, /api/assets
- Connect to Watchtower + Intel modules
- Query historical threat data
- Implement WebSocket updates for real-time events
- Caching (5-min TTL for expensive queries)

**Acceptance Criteria:**
- [ ] All 4 endpoints implemented
- [ ] Queries return data in <1 second
- [ ] WebSocket broadcasts new threats
- [ ] Caching working (verified)
- [ ] 20+ unit tests (endpoints, caching, WebSocket)

**Blocking:** T13-T17

---

### T13 - Charts & Trend Visualization

**Status:** 🟡 Can start after T12
**Effort:** S (Small)
**Depends On:** T12
**Owner:** Dev Agent

**Description:**
- Add chart rendering (Chart.js)
- Threat trend chart: Time × Count (hourly/daily aggregation)
- Severity distribution chart: Pie chart (LOW/MEDIUM/HIGH breakdown)
- Timeline scatter plot: Events × severity over time
- Responsive (works on desktop, tablet, mobile)
- Dark theme (glassmorphic)

**Acceptance Criteria:**
- [ ] Charts render from /api/charts data
- [ ] Time range configurable (7/30/90 days)
- [ ] Updates in real-time via WebSocket
- [ ] Responsive design verified
- [ ] 15+ unit tests (data formatting, rendering)

**Blocking:** T17

---

### T14 - Alert Timeline UI

**Status:** 🟡 Can start after T12
**Effort:** M (Medium)
**Depends On:** T12
**Owner:** Dev Agent

**Description:**
- Create alert timeline component (D3.js or custom)
- Display events chronologically
- Each event: timestamp, asset, event type, severity, description
- Filterable by: asset, severity, event type
- Drill-down: click event → see details
- Sortable (by time, severity, asset)

**Acceptance Criteria:**
- [ ] Timeline renders 1000+ events smoothly
- [ ] Filtering working (asset, severity, type)
- [ ] Drill-down details displayed
- [ ] Scroll performance OK (virtualization if needed)
- [ ] 15+ unit tests (rendering, filtering, drill-down)

**Blocking:** T17

---

### T15 - Threat Score & Risk Metrics Display

**Status:** 🟡 Can start after T12
**Effort:** S (Small)
**Depends On:** T12
**Owner:** Dev Agent

**Description:**
- Create risk gauge/indicator UI
- Display: Current threat level (ALL_CLEAR, CAUTION, ALERT, CRITICAL)
- Color-coded: Green → Yellow → Orange → Red
- Sub-metrics: # threats detected, # anomalies, # blocked
- Trend arrow: ↑ increasing, ↓ decreasing, → stable
- Last updated timestamp

**Acceptance Criteria:**
- [ ] Risk gauge displays correctly
- [ ] Colors match threat levels
- [ ] Metrics update in real-time
- [ ] Responsive (works on all screen sizes)
- [ ] 10+ unit tests (display, updates, colors)

**Blocking:** T17

---

### T16 - Multi-Asset Overview & Asset Management

**Status:** 🟡 Can start after T12
**Effort:** S (Small)
**Depends On:** T12
**Owner:** Dev Agent

**Description:**
- Asset list view (grid/table)
- Each asset: name, type, status, threat level, last event
- Actions: view details, remove, edit config
- Register new asset (VPS, family PC, etc.)
- Status indicator (online/offline/compromised)
- Quick stats (event count, anomaly count)

**Acceptance Criteria:**
- [ ] Asset list displays correctly
- [ ] Add/remove assets working
- [ ] Status indicators accurate
- [ ] Responsive layout
- [ ] 15+ unit tests (CRUD, display)

**Blocking:** T17

---

### T17 - Dashboard Integration Tests & Polish

**Status:** 🟡 Can start after T13-T16
**Effort:** M (Medium)
**Depends On:** T13, T14, T15, T16
**Owner:** Opus Lead

**Description:**
- Integration tests for all dashboard components
- E2E test: Watchdog file → detected → anomaly → dashboard update
- Verify real-time updates (WebSocket)
- Performance testing (1000+ events, multiple assets)
- CSS polish (spacing, alignment, dark theme consistency)
- Accessibility (keyboard nav, ARIA labels)

**Acceptance Criteria:**
- [ ] All integration tests pass
- [ ] E2E test validated
- [ ] Real-time updates working
- [ ] Performance: <1 sec query (p95)
- [ ] Dark theme consistent
- [ ] Keyboard accessible
- [ ] 30+ integration tests

**Blocking:** T18

---

### T18 - Phase 2 Documentation

**Status:** 🟡 Can start after T17
**Effort:** S (Small)
**Depends On:** T17 (optional, can be parallel)
**Owner:** Opus Lead

**Description:**
- Update README.md with Phase 2 features
- Create INTELLIGENCE_LAYER.md guide
- API documentation (/api/charts, /api/timeline, etc.)
- Threat feed explanation (OTX, abuse.ch, MITRE, NVD)
- User guide: monitoring assets, interpreting threat scores
- Troubleshooting guide

**Acceptance Criteria:**
- [ ] All docs written + reviewed
- [ ] Examples for all endpoints
- [ ] Screenshots of dashboard
- [ ] Threat feed explanation clear to non-experts
- [ ] Troubleshooting covers common issues

**Blocking:** Nothing (end of Phase 2)

---

## Summary

| Wave | Tasks | Effort | Dependencies |
|------|-------|--------|--------------|
| Wave 1 | T1-T6 | 14-16h | None |
| Wave 2 | T7-T11 | 10-12h | Wave 1 complete |
| Wave 3 | T12-T18 | 12-16h | T10 complete |
| **Total** | **20** | **36-44h** | **Sequential waves** |

---

## Execution Strategy

**Approach:** Same as Phase 1
- Autonomous execution (Forge coordinates, Opus/Dev lead tasks)
- Task duration: ~12-15 minutes per task (includes testing + commit)
- Wave execution: Sequential (Wave 1 → Wave 2 → Wave 3)
- Within wave: Parallel where possible (e.g., T2-T5 in parallel after T1)
- Daily sync: Status updates + blocker resolution

**Expected Timeline:**
- Wave 1: ~90 minutes
- Wave 2: ~90 minutes
- Wave 3: ~120 minutes
- **Total: ~5-6 hours** (plus time for reviews/testing)

---

Prepared by: Forge
Approved: Scott Vickrey, 2026-02-06 21:15 UTC

---

## Wave Execution Clarifications (2026-02-06 21:35 UTC)

### Wave 1 Task T6 - Failure Handling

**Added Acceptance Criteria:**
- [ ] Handles partial feed failures (≥1 feed succeeds, proceed)
- [ ] Caches results for failed feeds (use up to 7 days old)
- [ ] Retries failed feeds (3 attempts, exponential backoff: 1s/2s/4s)
- [ ] Alerts operator if 0 feeds succeed for 24h
- [ ] Logs all failures to audit trail

### Wave 2 Task T8 - Cold Start Behavior

**Added Acceptance Criteria:**
- [ ] Days 0-6: Use statistical defaults (anomaly_score = 0.3)
- [ ] Day 1+: Build partial baseline from accumulated events
- [ ] Day 7+: Switch to full learned baseline (Isolation Forest active)
- [ ] Decay schedule: Scale factor 1.0 → 0.0 over 7 days
- [ ] Document cold start user experience (gentle warnings, not panic)

### Wave 3 Task T13 - Dashboard Timeline

**Clarification:** Use D3.js for rich visualization (worth the dependency)
- [ ] D3.js for timeline rendering
- [ ] Responsive performance: handles 1000+ events
- [ ] Virtualization if needed for large datasets

---

Updated by: Forge
Approved: Scott Vickrey, 2026-02-06 21:35 UTC
