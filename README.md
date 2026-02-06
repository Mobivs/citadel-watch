# Citadel Archer

**Version**: 0.3.0 (Phase 2 - Threat Intelligence & Monitoring)

AI-centric defensive security platform for Windows 10/11. Proactive protection that acts first, informs after.

## Philosophy

> "If we're asking 'Should I block this malware?' we've already FAILED."

Citadel Archer is an AI-powered defensive security platform that protects individuals from persistent cyber threats. The AI acts autonomously (within your chosen security level), explains decisions clearly, and puts you back in control of your digital life.

## Project Status

- **Current Phase**: Phase 2 - Threat Intelligence & Monitoring
- **Platform**: Windows 10/11
- **Status**: In Development

## Features

### Phase 1 - Foundation

- **Guardian Agent**: Real-time file and process monitoring
- **Dashboard**: Dark glassmorphic UI with system status
- **Vault**: Encrypted password manager (AES-256 + SQLCipher)
- **Security Levels**: Observer, Guardian, Sentinel (you choose)
- **Audit Logging**: Immutable forensic logs

### Phase 2 - Threat Intelligence & Monitoring

- **Intel Feeds**: AlienVault OTX integration with deduplication and SQLite storage
- **Watchtower**: Centralised event aggregation across all assets
- **Anomaly Detection**: Isolation Forest + custom rule engine (5 built-in rules)
- **Context Engine**: Per-asset behavioral baselines with 7-day rolling window
- **Threat Scoring**: 3-component risk matrix (severity + anomaly + intel cross-ref)
- **Guardian Updater**: Auto-generated Guardian rules from IOC/TTP/CVE feeds with hot reload
- **Dashboard Extensions**: Chart trends, alert timeline, risk metrics, multi-asset view
- **Sensitivity Control**: LOW / MODERATE / HIGH adjustable detection thresholds
- **Performance**: Tested with 1000+ concurrent events under 30s full-pipeline

## Quick Start

### Prerequisites

- Windows 10/11 (or Linux/macOS for development)
- Python 3.11 or higher
- Git

### Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd citadel-archer
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python -m citadel_archer
   ```

5. **Run tests**:
   ```bash
   pytest tests/ -v
   ```

## Project Structure

```
citadel-archer/
├── docs/                        # Documentation
│   ├── PRD.md                   # Product requirements (v0.2.3)
│   ├── API.md                   # REST & WebSocket API reference
│   ├── DASHBOARD.md             # Dashboard & visualization guide
│   ├── TROUBLESHOOTING.md       # Common issues & solutions
│   ├── adr/                     # Architecture decision records
│   └── checklists/              # Compliance checklists
├── src/
│   └── citadel_archer/
│       ├── api/                 # FastAPI backend + dashboard extensions
│       │   ├── main.py          # Phase 1 endpoints + WebSocket
│       │   ├── dashboard_ext.py # Phase 2 chart/timeline/score/asset endpoints
│       │   └── security.py      # Session token authentication
│       ├── guardian/            # Local machine protection
│       │   ├── file_monitor.py  # Real-time file system monitoring
│       │   └── process_monitor.py # Process surveillance + kill
│       ├── intel/               # Threat intelligence pipeline
│       │   ├── models.py        # CVE, IOC, TTP, Vulnerability, IntelItem
│       │   ├── store.py         # SQLite persistent storage
│       │   ├── queue.py         # Thread-safe deduplication queue
│       │   ├── fetcher.py       # Abstract feed fetcher interface
│       │   ├── otx_fetcher.py   # AlienVault OTX implementation
│       │   ├── aggregator.py    # Multi-feed orchestration
│       │   ├── assets.py        # Asset inventory management
│       │   ├── event_aggregator.py  # Cross-asset event collection
│       │   ├── context_engine.py    # Behavioral baseline engine
│       │   ├── anomaly_detector.py  # Isolation Forest + rules
│       │   ├── threat_scorer.py     # Risk assessment engine
│       │   ├── guardian_updater.py  # Intel → Guardian rule sync
│       │   ├── chart_data.py        # Chart.js data formatting
│       │   ├── alert_timeline.py    # Timeline query & drill-down
│       │   ├── risk_metrics.py      # Gauge, trends, asset breakdown
│       │   └── asset_view.py        # Multi-asset overview table
│       ├── vault/               # Password manager
│       └── core/                # Shared utilities
├── tests/                       # Unit & integration tests
│   ├── test_integration.py      # Full pipeline E2E tests (48 tests)
│   ├── test_anomaly_detector.py # Isolation Forest + rules (45 tests)
│   ├── test_threat_scorer.py    # Risk scoring (30 tests)
│   └── ...                      # 350+ total tests
├── USAGE.md                     # Usage guide & configuration
├── ARCHITECTURE.md              # System architecture
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

## Architecture Overview

```
Threat Feeds (OTX, NVD)    Security Events (File, Process, Network)
         │                              │
         ▼                              ▼
   IntelAggregator              EventAggregator
   (fetch, dedup, store)        (categorize, index)
         │                              │
         ├──→ GuardianUpdater           ├──→ AnomalyDetector
         │    (auto-gen rules)          │    (Isolation Forest)
         │                              │
         └──────────┐    ┌──────────────┘
                    ▼    ▼
               ThreatScorer
         (severity × anomaly × intel)
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    RiskMetrics  AlertTimeline  AssetView
    (gauge,      (filter,       (table,
     trends)     drill-down)    drill-down)
         │          │          │
         └──────────┼──────────┘
                    ▼
              Dashboard API
         (/api/charts, /api/timeline,
          /api/threat-score, /api/assets)
```

## Security Levels

| Level | Behaviour | Use Case |
|-------|-----------|----------|
| **Observer** | Monitor and alert only | Learning, auditing |
| **Guardian** | Auto-respond to known threats (default) | Daily protection |
| **Sentinel** | Maximum AI autonomy within ethical bounds | High-risk environments |

## Documentation

- **[USAGE.md](USAGE.md)** - Configuration, intel feeds, sensitivity controls
- **[docs/API.md](docs/API.md)** - REST & WebSocket API reference
- **[docs/DASHBOARD.md](docs/DASHBOARD.md)** - Charts, timeline, metrics guide
- **[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)** - Common issues & fixes
- **[docs/PRD.md](docs/PRD.md)** - Product requirements document
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture
- **[docs/adr/](docs/adr/)** - Architecture decision records

## License

Proprietary - See LICENSE file

## Contact

For questions or support, open an issue on the repository.
