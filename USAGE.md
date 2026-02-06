# Citadel Archer - Usage Guide

Complete guide to configuring and using Citadel Archer's threat intelligence, monitoring, and dashboard systems.

## Table of Contents

- [Initial Setup](#initial-setup)
- [Intel Feeds](#intel-feeds)
- [Watchtower (Event Aggregation)](#watchtower-event-aggregation)
- [Anomaly Detection](#anomaly-detection)
- [Sensitivity Controls](#sensitivity-controls)
- [Threat Scoring](#threat-scoring)
- [Guardian Rules (Auto-Generated)](#guardian-rules-auto-generated)
- [Asset Management](#asset-management)
- [Dashboard](#dashboard)
- [Configuration Reference](#configuration-reference)

---

## Initial Setup

### 1. Install Dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the Backend

```bash
uvicorn citadel_archer.api.main:app --host 127.0.0.1 --port 8000
```

### 3. Access the Dashboard

Open `http://127.0.0.1:8000` in your browser. A session token is auto-generated at startup and required for all API calls.

---

## Intel Feeds

Citadel Archer ingests threat intelligence from external feeds and stores it in a local SQLite database with deduplication.

### Supported Feed Types

| Feed | Class | Data Types |
|------|-------|------------|
| AlienVault OTX | `OTXFetcher` | IOCs (hashes, IPs, domains), CVEs |
| Custom feeds | Extend `IntelFetcher` | Any `IntelItem` |

### Configuring OTX

```python
from citadel_archer.intel import OTXFetcher, IntelAggregator, IntelStore

store = IntelStore(db_path="/var/citadel/intel.db")
aggregator = IntelAggregator(store)

otx = OTXFetcher()
otx.configure(api_key="YOUR_OTX_API_KEY")
aggregator.register(otx)
```

### Running a Feed Cycle

```python
# Manual fetch (immediate)
report = aggregator.run_now()
print(f"Fetched: {report.total_fetched}")
print(f"After dedup: {report.total_after_dedup}")
print(f"Stored: {report.total_stored}")

# Scheduled (daily at 02:00 by default)
aggregator.start()
```

### Writing a Custom Fetcher

```python
from citadel_archer.intel import IntelFetcher, IntelItem, IntelType, IOC, IOCType

class MyFetcher(IntelFetcher):
    def __init__(self):
        super().__init__(name="my-feed")

    def configure(self, **kwargs):
        self.api_url = kwargs.get("api_url", "")

    def fetch(self, since=None):
        # Return a list of IntelItem objects
        ioc = IOC(ioc_type=IOCType.IP_ADDRESS, value="10.0.0.1", severity="high")
        return [IntelItem(intel_type=IntelType.IOC, payload=ioc, source_feed="my-feed")]

    def health_check(self):
        return True
```

### Data Models

| Type | Key Fields | Dedup Key |
|------|------------|-----------|
| `IOC` | ioc_type, value, severity | `ioc:{type}:{value}` |
| `CVE` | cve_id, cvss_score, severity | `cve:{cve_id}` |
| `TTP` | technique_id, tactic, severity | `ttp:{technique_id}` |
| `Vulnerability` | product, version, cve_id | `vuln:{product}:{version}` |

---

## Watchtower (Event Aggregation)

The EventAggregator is the central event hub. All security events (file, process, network, vault, system) flow through it.

### Ingesting Events

```python
from citadel_archer.intel import EventAggregator

aggregator = EventAggregator(max_history=10_000)

# Direct ingestion
event = aggregator.ingest(
    event_type="file.modified",
    severity="alert",
    asset_id="srv-web-01",
    message="Suspicious file modification",
    details={"file_path": "/etc/passwd", "sha256": "abc123"},
)

# From EventBus (dict-based)
aggregator.ingest_bus_event({
    "event_type": "process.started",
    "severity": "critical",
    "asset_id": "srv-web-01",
    "details": {"executable": "/tmp/backdoor"},
})
```

### Event Categories

Events are auto-categorised based on their `event_type` prefix:

| Category | Event Types |
|----------|-------------|
| FILE | file.created, file.modified, file.deleted |
| PROCESS | process.started, process.killed, process.suspicious |
| NETWORK | network.connection, network.blocked |
| VAULT | vault.unlocked, vault.locked, vault.error |
| SYSTEM | system.start, system.stop |
| AI | ai.decision, ai.alert |
| USER | user.login, user.logout |

### Querying Events

```python
recent = aggregator.recent(limit=50)
by_asset = aggregator.by_asset("srv-web-01")
by_severity = aggregator.by_severity("critical")
by_category = aggregator.by_category(EventCategory.NETWORK)
since_time = aggregator.since("2025-01-01T00:00:00")
```

### Subscriber Pattern

Wire downstream consumers to receive every event automatically:

```python
from citadel_archer.intel import AnomalyDetector, ContextEngine

detector = AnomalyDetector()
context = ContextEngine()

aggregator.subscribe(detector.on_event)       # anomaly scoring
aggregator.subscribe(context.ingest_aggregated)  # baseline learning
```

---

## Anomaly Detection

Dual-mode anomaly detection combining statistical modelling with rule-based evaluation.

### Detection Engine

| Component | Method | Output |
|-----------|--------|--------|
| Isolation Forest | Statistical outlier detection | Model score (0-1) |
| Z-Score fallback | Used when sklearn unavailable | Model score (0-1) |
| Custom rules | Pattern-matching evaluation | Rule score + hit IDs |
| **Combined** | `max(model_score, rule_score)` | **Final score (0-1)** |

### Feature Dimensions

The Isolation Forest model uses 5 feature dimensions:

1. **Hour of day** (normalised 0-1)
2. **Event category** (ordinal encoding)
3. **Severity** (ordinal encoding)
4. **Event-type frequency** (log-scaled)
5. **Asset event frequency** (log-scaled)

### Built-in Detection Rules

| Rule ID | Name | Score | Trigger |
|---------|------|-------|---------|
| R001 | unsigned_exe_system_dir | 0.9 | Unsigned executable in System32/sbin |
| R002 | process_from_tmp | 0.75 | Process spawned from /tmp or AppData\Temp |
| R003 | network_suspicious_port | 0.7 | Connection to ports 4444, 5555, 1337, etc. |
| R004 | critical_file_modification | 0.85 | Changes to /etc/passwd, shadow, sudoers |
| R005 | high_severity_event | 0.6 | Event already flagged alert/critical |

### Adding Custom Rules

```python
from citadel_archer.intel import AnomalyDetector, DetectionRule

detector = AnomalyDetector()
detector.add_rule(DetectionRule(
    rule_id="R100",
    name="large_file_upload",
    description="File upload over 100MB",
    score=0.7,
    evaluate=lambda evt: evt.details.get("size_mb", 0) > 100,
))
```

### Cold Start

Until `min_training_samples` events are collected (default: 20), the model returns `cold_start=True` with reduced confidence. Rule-based detection still works during cold start.

---

## Sensitivity Controls

Sensitivity affects both the anomaly detection thresholds and the Isolation Forest contamination parameter.

### Presets

| Preset | Contamination | Medium Threshold | High Threshold | Use Case |
|--------|--------------|-----------------|----------------|----------|
| **LOW** | 0.15 | 0.55 | 0.80 | Fewer alerts, higher bar |
| **MODERATE** | 0.10 | 0.40 | 0.70 | Balanced (default) |
| **HIGH** | 0.05 | 0.25 | 0.55 | More alerts, lower bar |

### Changing Sensitivity

```python
from citadel_archer.intel import AnomalyDetector, Sensitivity

detector = AnomalyDetector(sensitivity=Sensitivity.MODERATE)

# Change at runtime (resets the model)
detector.set_sensitivity(Sensitivity.HIGH)
```

Sensitivity can also be controlled from the RiskMetrics layer:

```python
from citadel_archer.intel import RiskMetrics

metrics = RiskMetrics(sensitivity=Sensitivity.MODERATE)
metrics.set_sensitivity(Sensitivity.HIGH)
```

---

## Threat Scoring

The ThreatScorer combines three weighted signals into a single risk score (0.0-1.0):

```
risk_score = 0.30 * severity_weight
           + 0.35 * anomaly_score
           + 0.35 * intel_cross_ref_score
```

### Risk Levels

| Level | Score Range | Meaning |
|-------|------------|---------|
| LOW | 0.00 - 0.29 | Normal activity |
| MEDIUM | 0.30 - 0.54 | Warrants investigation |
| HIGH | 0.55 - 0.79 | Active threat |
| CRITICAL | 0.80 - 1.00 | Immediate response needed |

### Intel Cross-Referencing

When scoring an event, the ThreatScorer automatically extracts artifacts from `event.details` and looks them up in the IntelStore:

| Artifact | Detail Keys Checked |
|----------|-------------------|
| File hashes | sha256, sha1, md5, file_hash, hash |
| IP addresses | ip, ip_address, src_ip, dst_ip, remote_ip |
| Domains | domain, host, hostname |
| CVE IDs | cve_id, cve |
| MITRE TTPs | technique_id, mitre_id, ttp |

If a match is found, the intel score uses the highest-severity match as the base, with a small boost per additional match (up to +0.15).

### Usage

```python
from citadel_archer.intel import ThreatScorer, IntelStore, AnomalyDetector

store = IntelStore()
detector = AnomalyDetector()
scorer = ThreatScorer(intel_store=store, anomaly_detector=detector)

scored = scorer.score_event(event)
print(f"Risk: {scored.risk_level.value} ({scored.risk_score:.2f})")
print(f"Intel matches: {len(scored.intel_matches)}")

# Batch scoring (returns sorted by risk, highest first)
threats = scorer.score_batch(events)

# Get only HIGH+ threats
critical = scorer.prioritised_threats(events, min_level=RiskLevel.HIGH)
```

---

## Guardian Rules (Auto-Generated)

The GuardianUpdater monitors the intel pipeline and auto-generates enforcement rules for the Guardian subsystem.

### Rule Types

| Type | Source | Action |
|------|--------|--------|
| FILE_HASH | IOC (md5/sha1/sha256) | BLOCK or QUARANTINE |
| NETWORK_IP | IOC (ip_address) | BLOCK |
| NETWORK_DOMAIN | IOC (domain/url) | BLOCK |
| PROCESS_PATTERN | TTP (technique_id) | ALERT or BLOCK |
| CVE_SIGNATURE | CVE (cve_id) | ALERT or QUARANTINE |

### Severity-to-Action Mapping

| Severity | Default Action |
|----------|---------------|
| LOW | ALERT |
| MEDIUM | ALERT |
| HIGH | BLOCK |
| CRITICAL | QUARANTINE |

### Conflict Resolution

When two rules share the same indicator (e.g., same IP from two feeds), the higher-severity rule wins. If equal severity, the more recent rule wins.

### Hot Reload

Guardian rules are published via callback — no restart needed:

```python
from citadel_archer.intel import GuardianUpdater

def on_new_rule(rule):
    print(f"New rule: {rule.threat_type.value} -> {rule.indicator}")

updater = GuardianUpdater(on_rule_published=on_new_rule)
updater.subscribe(another_callback)  # additional subscribers

# Process intel items (idempotent)
report = updater.process_batch(intel_items)
print(f"Generated: {report.rules_generated}, Added: {report.rules_added}")
```

---

## Asset Management

Track protected endpoints with the AssetInventory.

### Registering Assets

```python
from citadel_archer.intel import Asset, AssetInventory, AssetPlatform, AssetStatus

inventory = AssetInventory()
asset = Asset(
    asset_id="srv-web-01",
    name="Production Web Server",
    platform=AssetPlatform.LINUX,
    status=AssetStatus.ONLINE,
    hostname="web01.example.com",
    ip_address="10.0.1.10",
)
inventory.register(asset)
```

### Status Values

| Status | Description | Healthy |
|--------|------------|---------|
| ONLINE | Reachable and reporting | Yes |
| PROTECTED | Online with Guardian active | Yes |
| OFFLINE | Not responding | No |
| COMPROMISED | Flagged as compromised | No |

---

## Dashboard

See [docs/DASHBOARD.md](docs/DASHBOARD.md) for the full dashboard guide including:

- Threat trend charts (line, hourly/daily)
- Severity distribution (doughnut)
- Risk gauge (overall threat level)
- Alert timeline with filtering and drill-down
- Multi-asset overview table
- Real-time WebSocket updates

---

## Configuration Reference

### IntelStore

| Parameter | Default | Description |
|-----------|---------|-------------|
| `db_path` | `/var/citadel/intel.db` | SQLite database path |

### EventAggregator

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_history` | 10,000 | Maximum events in memory |

### AnomalyDetector

| Parameter | Default | Description |
|-----------|---------|-------------|
| `sensitivity` | MODERATE | Detection preset |
| `min_training_samples` | 20 | Cold-start threshold |

### ThreatScorer

| Parameter | Default | Description |
|-----------|---------|-------------|
| `severity_weight` | 0.30 | Weight of severity component |
| `anomaly_weight` | 0.35 | Weight of anomaly component |
| `intel_weight` | 0.35 | Weight of intel cross-ref |

### ContextEngine

| Parameter | Default | Description |
|-----------|---------|-------------|
| `window_days` | 7 | Rolling baseline window |
| `max_events` | 50,000 | Max events tracked |

### IntelAggregator

| Parameter | Default | Description |
|-----------|---------|-------------|
| `max_workers` | 4 | Parallel fetch threads |
| `schedule_hour` | 2 | Daily run hour (UTC) |
| `schedule_minute` | 0 | Daily run minute |

### TTLCache (Dashboard)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `default_ttl` | 300s | Cache expiration (5 min) |
