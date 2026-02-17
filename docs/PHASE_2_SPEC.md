# Citadel Archer - Phase 2 Specification

**Version**: 1.0.0
**Status**: Implemented
**Modules**: 16 modules, 350+ unit tests, 48 integration tests

## Overview

Phase 2 adds threat intelligence, anomaly detection, and a monitoring dashboard to Citadel Archer. The system ingests external threat feeds, correlates them with local security events, scores threats, auto-generates Guardian rules, and displays everything on a real-time dashboard.

> **Note (v0.2.5):** Asset management persistence, CRUD API, Remote Shield database persistence, Vault SSH credentials, and the SSH Connection Manager have been added to Phase 2 scope. See [ASSET_MANAGEMENT_ADDENDUM.md](ASSET_MANAGEMENT_ADDENDUM.md) for full specification.

---

## Module Inventory

### Core Pipeline

| # | Module | File | Purpose |
|---|--------|------|---------|
| T1 | Intel Models | `intel/models.py` | CVE, IOC, TTP, Vulnerability, IntelItem data structures |
| T2 | Intel Store | `intel/store.py` | SQLite persistent storage with deduplication |
| T3 | Intel Queue | `intel/queue.py` | Thread-safe ingestion queue with dedup window |
| T4 | Intel Fetcher | `intel/fetcher.py` | Abstract feed fetcher interface |
| T5 | OTX Fetcher | `intel/otx_fetcher.py` | AlienVault OTX implementation with retry logic |
| T6 | Intel Aggregator | `intel/aggregator.py` | Multi-feed orchestration with parallel fetch |
| T7 | Asset Inventory | `intel/assets.py` | Asset registry with status management |

### Analysis & Detection

| # | Module | File | Purpose |
|---|--------|------|---------|
| T8 | Event Aggregator | `intel/event_aggregator.py` | Cross-asset event collection and indexing |
| T9 | Context Engine | `intel/context_engine.py` | Per-asset behavioral baselines (7-day window) |
| T10 | Anomaly Detector | `intel/anomaly_detector.py` | Isolation Forest + 5 custom rules |
| T11 | Threat Scorer | `intel/threat_scorer.py` | 3-component risk matrix |

### Enforcement & Sync

| # | Module | File | Purpose |
|---|--------|------|---------|
| T12 | Guardian Updater | `intel/guardian_updater.py` | Intel-to-Guardian rule generation |

### Dashboard & Visualization

| # | Module | File | Purpose |
|---|--------|------|---------|
| T13 | Dashboard Extensions | `api/dashboard_ext.py` | FastAPI endpoints + caching + WebSocket |
| T14 | Chart Data | `intel/chart_data.py` | Chart.js-compatible data formatting |
| T15 | Alert Timeline | `intel/alert_timeline.py` | Timeline query, filter, sort, drill-down |
| T16 | Risk Metrics | `intel/risk_metrics.py` | Gauge, trends, asset breakdown |
| T17 | Asset View | `intel/asset_view.py` | Multi-asset table with drill-down |

### Quality Assurance

| # | Module | File | Purpose |
|---|--------|------|---------|
| T18 | Integration Tests | `tests/test_integration.py` | 48 E2E pipeline tests + load testing |

---

## Data Flow

```
External Feeds          Local Monitors
(OTX, NVD, MITRE)      (FileMonitor, ProcessMonitor)
       │                        │
       ▼                        ▼
  IntelAggregator         EventAggregator
  ├─ Parallel fetch       ├─ Categorise (8 categories)
  ├─ Cross-feed dedup     ├─ Index by asset/category/severity
  └─ SQLite storage       └─ Subscriber fan-out
       │                        │
       │                   ┌────┼────┐
       │                   ▼    ▼    ▼
       │              Context  Anomaly  (other
       │              Engine   Detector  subscribers)
       │                   │    │
       └───────────────────┼────┘
                           ▼
                     ThreatScorer
              ┌────────────┼────────────┐
              ▼            ▼            ▼
        GuardianUpdater  RiskMetrics  AlertTimeline
        (hot-reload      (gauge,      (filter, sort,
         rules)           trends)      drill-down)
                           │            │
                     ┌─────┼────────────┘
                     ▼
                 AssetView
              (multi-asset table)
                     │
                     ▼
               Dashboard API
          (/api/charts, /api/timeline,
           /api/threat-score, /api/assets)
```

---

## Design Decisions

### Conventions

- **Enums**: All use `(str, Enum)` pattern for JSON-friendly serialisation
- **Dataclasses**: All have `to_dict()` methods and `dedup_key` properties where applicable
- **Thread safety**: All stateful classes use `threading.RLock`
- **PRD comments**: Every file begins with a PRD reference header
- **Tests**: pytest with fixtures, one test file per module

### Architecture

- **sklearn optional**: Anomaly detector includes a Z-score fallback model when scikit-learn is not installed
- **No EventBus singleton**: Uses EventAggregator's `subscribe()` callback pattern for all pub/sub
- **Frontend-agnostic**: Chart/timeline modules output Chart.js/D3.js-compatible dict structures; no HTML rendering
- **Dashboard API**: FastAPI APIRouter with `Depends(verify_session_token)` authentication
- **Caching**: TTLCache (5-min default) prevents redundant expensive queries

### Scoring Formula

```
risk_score = 0.30 * severity_weight
           + 0.35 * anomaly_score
           + 0.35 * intel_cross_ref_score
```

Risk levels: LOW (< 0.30), MEDIUM (0.30-0.54), HIGH (0.55-0.79), CRITICAL (>= 0.80).

### Guardian Rule Generation

| Intel Type | Rule Type | Default Action |
|------------|-----------|---------------|
| IOC (hash) | FILE_HASH | BLOCK (HIGH), QUARANTINE (CRITICAL) |
| IOC (IP) | NETWORK_IP | BLOCK (MEDIUM+) |
| IOC (domain) | NETWORK_DOMAIN | BLOCK (MEDIUM+) |
| TTP | PROCESS_PATTERN | ALERT or BLOCK |
| CVE | CVE_SIGNATURE | ALERT or QUARANTINE |

Conflict resolution: higher severity wins; equal severity → more recent wins.

---

## Test Coverage

| Test File | Module | Tests |
|-----------|--------|-------|
| test_models.py | Intel models | ~20 |
| test_store.py | Intel store | ~25 |
| test_queue.py | Intel queue | ~20 |
| test_aggregator.py | Intel aggregator | ~25 |
| test_assets.py | Asset inventory | ~20 |
| test_event_aggregator.py | Event aggregator | ~25 |
| test_context_engine.py | Context engine | 35 |
| test_anomaly_detector.py | Anomaly detector | 45 |
| test_threat_scorer.py | Threat scorer | 30 |
| test_guardian_updater.py | Guardian updater | 42 |
| test_dashboard_ext.py | Dashboard API | 35 |
| test_chart_data.py | Chart data | 38 |
| test_alert_timeline.py | Alert timeline | 40 |
| test_risk_metrics.py | Risk metrics | 48 |
| test_asset_view.py | Asset view | 45 |
| test_integration.py | E2E pipeline | 48 |
| **Total** | | **~540** |

### Integration Test Sections

1. **Pipeline Wiring** (4 tests): Subscriber chain, error isolation
2. **Feed to Guardian** (9 tests): Intel → store → rule generation for all types
3. **Event to Scoring** (5 tests): Anomaly + severity → risk levels
4. **Cross-Referencing** (3 tests): Event artifacts matched against intel store
5. **Dashboard Services** (7 tests): API layer integration
6. **Visualization** (4 tests): Charts, timeline, metrics from real data
7. **Full Pipeline** (2 tests): 10-step end-to-end flow
8. **Performance** (5 tests): 1000-event load testing (< 30s pipeline, < 5s per viz)
9. **Edge Cases** (7 tests): Empty data, cold start, unknown assets, conflicts

---

## Performance Benchmarks

Tested with 1000 concurrent events:

| Operation | Time | Status |
|-----------|------|--------|
| Ingest + score 1000 events | < 30s | Pass |
| Risk metrics snapshot (1000) | < 5s | Pass |
| Chart generation (1000) | < 5s | Pass |
| Timeline query + sort (1000) | < 5s | Pass |
| Asset view query (1000) | < 5s | Pass |

---

## Dependencies

### Required
- Python 3.11+
- numpy (anomaly detector feature vectors)
- FastAPI + uvicorn (API backend)

### Optional
- scikit-learn (Isolation Forest, falls back to Z-score)
- APScheduler (scheduled feed aggregation)
