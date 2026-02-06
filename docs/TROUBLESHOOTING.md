# Citadel Archer - Troubleshooting

Common issues and their solutions.

## Table of Contents

- [Installation](#installation)
- [Intel Feeds](#intel-feeds)
- [Anomaly Detection](#anomaly-detection)
- [Threat Scoring](#threat-scoring)
- [Guardian Rules](#guardian-rules)
- [Dashboard & API](#dashboard--api)
- [Performance](#performance)
- [Database](#database)
- [Testing](#testing)

---

## Installation

### `ModuleNotFoundError: No module named 'citadel_archer'`

The package is not installed in the Python path.

**Fix:**
```bash
pip install -e .
# or ensure src/ is in PYTHONPATH:
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

### `ImportError: No module named 'sklearn'`

scikit-learn is optional. The anomaly detector falls back to a Z-score model automatically.

**To install sklearn (optional):**
```bash
pip install scikit-learn
```

The Z-score fallback is fully functional for development and testing. sklearn provides better accuracy with the Isolation Forest algorithm in production.

### `ModuleNotFoundError: No module named 'sqlcipher3'`

SQLCipher is required for the Vault module but not for the Intel pipeline.

**Fix (Linux):**
```bash
sudo apt-get install libsqlcipher-dev
pip install sqlcipher3
```

**Fix (macOS):**
```bash
brew install sqlcipher
pip install sqlcipher3
```

### numpy version conflicts

If you see numpy compatibility errors:

```bash
pip install --upgrade numpy
```

The anomaly detector requires numpy for feature vector operations.

---

## Intel Feeds

### OTX API key not working

**Symptoms:** `OTXFetchError`, 401 responses, empty fetch results.

**Checks:**
1. Verify your API key at [otx.alienvault.com](https://otx.alienvault.com)
2. Ensure the key is passed correctly:
   ```python
   otx.configure(api_key="your-actual-key")
   ```
3. Check network connectivity to `otx.alienvault.com`

### Deduplication is dropping too many items

The IntelQueue uses a dedup window (default 50,000 keys) to track seen items. If the same items are being re-fetched:

**Checks:**
1. Verify your `since` parameter is correct — pass the last successful fetch timestamp
2. Clear the dedup cache if stale: `queue.clear_dedup_cache()`
3. Each `IntelItem` dedup key is derived from the payload (e.g., `ioc:sha256:abc123`)

### IntelStore shows 0 items after fetch

**Checks:**
1. Verify the database path exists and is writable
2. Check the aggregation report: `report.total_stored` vs `report.total_fetched`
3. Items may be duplicates — `report.total_after_dedup` shows how many survived dedup
4. Inspect the store: `store.count()` and `store.stats()`

---

## Anomaly Detection

### All events scoring LOW (no anomalies detected)

**Possible causes:**

1. **Cold start**: The model needs `min_training_samples` events (default 20) before it produces meaningful scores. Check: `detector.is_cold_start`

2. **Low sensitivity**: Try increasing sensitivity:
   ```python
   detector.set_sensitivity(Sensitivity.HIGH)
   ```

3. **All events look the same**: If all events have the same category, severity, and timing, the model learns this as normal. Introduce variety in training data.

4. **No rules matching**: Check if built-in rules are relevant to your events:
   ```python
   detector.list_rules()  # returns rule metadata
   ```

### Model not fitting

The Isolation Forest (or Z-score model) auto-fits when `len(training_data) >= min_training_samples`.

**Check:**
```python
print(detector.stats())
# Look for: training_samples, model_fitted, cold_start
```

### Custom rule not triggering

**Checks:**
1. Ensure `enabled=True` on your rule
2. Verify your `evaluate` function receives an `AggregatedEvent` and returns `True` on match
3. Test the function directly:
   ```python
   result = my_rule.evaluate(test_event)
   print(result)  # Should be True
   ```

---

## Threat Scoring

### Intel cross-reference returning zero matches

**Checks:**
1. Verify intel items are in the store: `store.has_key("ioc:sha256:abc123")`
2. Check event details contain the right keys:
   ```python
   # These keys are checked for hashes:
   # sha256, sha1, md5, file_hash, hash
   event.details = {"sha256": "abc123"}  # correct
   event.details = {"filehash": "abc123"}  # NOT checked
   ```
3. Ensure the ThreatScorer was initialised with the store:
   ```python
   scorer = ThreatScorer(intel_store=store)
   ```

### Risk scores seem too low/high

The scoring formula is:
```
risk = 0.30 * severity + 0.35 * anomaly + 0.35 * intel
```

**Adjusting weights:**
```python
scorer = ThreatScorer(
    severity_weight=0.40,  # increase severity influence
    anomaly_weight=0.30,
    intel_weight=0.30,
)
```

### `_RISK_RANK` KeyError

Ensure you're using `RiskLevel` enum values, not raw strings:
```python
from citadel_archer.intel import RiskLevel
level = RiskLevel.HIGH  # correct
level = "high"          # may cause issues in some lookups
```

---

## Guardian Rules

### Rules not being generated

**Checks:**
1. Verify the `IntelItem` has the correct `intel_type`:
   ```python
   item.intel_type  # Must be IntelType.IOC, IntelType.TTP, or IntelType.CVE
   ```
2. `IntelType.VULNERABILITY` does not generate rules (no rule template)
3. Check if already processed (idempotent): `item.item_id in updater._processed_item_ids`

### Callback not firing

**Checks:**
1. Ensure the callback was registered before processing:
   ```python
   updater = GuardianUpdater(on_rule_published=my_callback)
   # or
   updater.subscribe(my_callback)
   ```
2. Callbacks are best-effort — exceptions inside callbacks are silently caught

### Conflict resolution behaving unexpectedly

When two rules share the same `conflict_key` (`{threat_type}:{indicator}`):
- Higher severity wins
- Equal severity: more recent `created_at` wins
- The losing rule is replaced, not kept

Check active rules: `updater.all_rules()`

---

## Dashboard & API

### 401 Unauthorized on all endpoints

**Fix:** Include the session token as a query parameter:
```
GET /api/charts?token=<your-token>
```

The token is printed to stdout when the server starts. You can also retrieve it:
```python
from citadel_archer.api.security import get_session_token
print(get_session_token())
```

### Stale data in dashboard

The TTL cache (5-minute default) may serve old data.

**Fix:**
```bash
curl -X POST "http://127.0.0.1:8000/api/cache/clear?token=<token>"
```

Or programmatically:
```python
from citadel_archer.api.dashboard_ext import cache
cache.clear()
```

### Charts showing empty data

**Checks:**
1. Verify events exist: `event_aggregator.size`
2. Check the time window — events older than `hours` parameter are excluded
3. Ensure `DashboardServices` has references wired:
   ```python
   services.event_aggregator = aggregator
   services.threat_scorer = scorer
   services.asset_inventory = inventory
   ```

### WebSocket connection drops

The `EventBroadcaster` automatically removes dead connections on send failure. Reconnect logic should be in the frontend:

```javascript
function connect() {
  const ws = new WebSocket("ws://127.0.0.1:8000/ws");
  ws.onclose = () => setTimeout(connect, 3000);
}
```

---

## Performance

### Pipeline is slow with many events

**Benchmarks** (from integration tests):
- 1000 events ingestion + scoring: < 30s
- 1000 events chart generation: < 5s
- 1000 events timeline query: < 5s
- 1000 events risk metrics snapshot: < 5s

**Optimisation tips:**
1. Reduce `max_history` on EventAggregator if you don't need deep history
2. Use the TTL cache — avoid re-computing expensive queries
3. Score in batches (`score_batch`) rather than one-by-one
4. For the AlertTimeline, use pagination (default 50 per page)

### Memory usage growing

The EventAggregator uses a bounded deque (`max_history=10,000` default). Old events are automatically evicted.

The AnomalyDetector accumulates training data. Call `detector.reset()` to clear if needed.

---

## Database

### SQLite database locked

**Cause:** Multiple processes accessing the same database file.

**Fix:** Ensure only one process uses the IntelStore at a time. The store uses `check_same_thread=False` and an RLock for thread safety within a single process.

### Database file too large

**Fix:** Purge old data:
```python
removed = store.purge_older_than(days=90)
print(f"Removed {removed} items")
```

### Database corruption

**Fix:** Delete and recreate:
```bash
rm /var/citadel/intel.db
# The IntelStore auto-creates tables on init
```

---

## Testing

### Running tests

```bash
# All tests
pytest tests/ -v

# Specific module
pytest tests/test_integration.py -v

# With coverage
pytest tests/ --cov=citadel_archer --cov-report=term-missing
```

### Tests fail with import errors

Ensure the project is in the Python path:
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

Or install in development mode:
```bash
pip install -e .
```

### Integration tests slow

The performance tests in `test_integration.py` process 1000 events. They have generous timeouts (30s) but may be slower on resource-constrained machines. Skip them with:

```bash
pytest tests/ -v -k "not TestPerformance"
```
