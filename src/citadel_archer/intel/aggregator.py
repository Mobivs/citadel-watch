# PRD: Intel Module - IntelAggregator Coordinator
# Reference: PHASE_2_SPEC.md
#
# Coordinates all registered threat feed fetchers:
#   - Schedules daily fetches at 02:00 UTC (APScheduler)
#   - Runs fetchers in parallel via ThreadPoolExecutor
#   - Deduplicates items across feeds by dedup_key
#   - Merges duplicates (keeps most recent timestamp, highest severity)
#   - Stores results in IntelStore
#   - Logs all fetch operations to audit trail
#   - Handles partial failures (succeeds if >= 1 feed returns data)

import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .fetcher import IntelFetcher
from .models import IntelItem, IntelSeverity, IntelType
from .queue import IntelQueue
from .store import IntelStore

logger = logging.getLogger(__name__)

# Severity ordering for merge (higher index = higher severity)
_SEVERITY_ORDER = [
    IntelSeverity.NONE,
    IntelSeverity.LOW,
    IntelSeverity.MEDIUM,
    IntelSeverity.HIGH,
    IntelSeverity.CRITICAL,
]

DEFAULT_AUDIT_LOG = "/var/citadel/audit.log"


def _severity_rank(sev: IntelSeverity) -> int:
    """Return numeric rank for a severity level."""
    try:
        return _SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


class FetchResult:
    """Outcome of a single fetcher run."""

    def __init__(self, fetcher_name: str):
        self.fetcher_name = fetcher_name
        self.items: List[IntelItem] = []
        self.error: Optional[str] = None
        self.duration_ms: float = 0.0

    @property
    def success(self) -> bool:
        return self.error is None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fetcher": self.fetcher_name,
            "success": self.success,
            "items_count": len(self.items),
            "error": self.error,
            "duration_ms": round(self.duration_ms, 1),
        }


class AggregationReport:
    """Summary of a full aggregation cycle."""

    def __init__(self):
        self.started = datetime.utcnow().isoformat()
        self.fetch_results: List[FetchResult] = []
        self.total_fetched: int = 0
        self.total_after_dedup: int = 0
        self.total_merged: int = 0
        self.total_stored: int = 0
        self.total_store_dupes: int = 0
        self.finished: Optional[str] = None

    @property
    def feeds_succeeded(self) -> int:
        return sum(1 for r in self.fetch_results if r.success)

    @property
    def feeds_failed(self) -> int:
        return sum(1 for r in self.fetch_results if not r.success)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "started": self.started,
            "finished": self.finished,
            "feeds_succeeded": self.feeds_succeeded,
            "feeds_failed": self.feeds_failed,
            "total_fetched": self.total_fetched,
            "total_after_dedup": self.total_after_dedup,
            "total_merged": self.total_merged,
            "total_stored": self.total_stored,
            "total_store_dupes": self.total_store_dupes,
            "fetch_results": [r.to_dict() for r in self.fetch_results],
        }


class IntelAggregator:
    """Coordinator that schedules and orchestrates threat feed fetches.

    Usage::

        agg = IntelAggregator(store)
        agg.register(otx_fetcher)
        agg.register(nvd_fetcher)
        agg.start()          # begins scheduled daily runs
        agg.run_now()         # trigger an immediate aggregation
        agg.stop()
    """

    def __init__(
        self,
        store: IntelStore,
        audit_log: str = DEFAULT_AUDIT_LOG,
        max_workers: int = 4,
        schedule_hour: int = 2,
        schedule_minute: int = 0,
    ):
        self._store = store
        self._audit_log = audit_log
        self._max_workers = max_workers
        self._schedule_hour = schedule_hour
        self._schedule_minute = schedule_minute

        self._fetchers: List[IntelFetcher] = []
        self._scheduler: Optional[BackgroundScheduler] = None
        self._lock = threading.RLock()
        self._last_report: Optional[AggregationReport] = None
        self._on_complete: Optional[Callable[[AggregationReport], None]] = None

    # ------------------------------------------------------------------
    # Fetcher registration
    # ------------------------------------------------------------------

    def register(self, fetcher: IntelFetcher) -> None:
        """Register a feed fetcher."""
        with self._lock:
            self._fetchers.append(fetcher)

    @property
    def fetcher_count(self) -> int:
        with self._lock:
            return len(self._fetchers)

    def set_on_complete(self, callback: Callable[[AggregationReport], None]) -> None:
        """Set a callback invoked after each aggregation cycle."""
        self._on_complete = callback

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background scheduler for daily fetches."""
        if self._scheduler is not None:
            return  # already running

        self._scheduler = BackgroundScheduler(daemon=True)
        trigger = CronTrigger(
            hour=self._schedule_hour,
            minute=self._schedule_minute,
            timezone="UTC",
        )
        self._scheduler.add_job(
            self.run_now,
            trigger=trigger,
            id="intel_aggregator_daily",
            name="Daily threat intel aggregation",
            replace_existing=True,
        )
        self._scheduler.start()
        logger.info(
            "IntelAggregator scheduler started: daily at %02d:%02d UTC",
            self._schedule_hour,
            self._schedule_minute,
        )

    def stop(self) -> None:
        """Stop the background scheduler."""
        if self._scheduler is not None:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
            logger.info("IntelAggregator scheduler stopped")

    @property
    def is_running(self) -> bool:
        return self._scheduler is not None and self._scheduler.running

    # ------------------------------------------------------------------
    # Core aggregation
    # ------------------------------------------------------------------

    def run_now(self, since: Optional[str] = None) -> AggregationReport:
        """Execute an immediate aggregation cycle.

        1. Run all fetchers in parallel (thread pool)
        2. Collect results, tolerate partial failures
        3. Deduplicate + merge across feeds
        4. Store in IntelStore
        5. Log and return report

        Args:
            since: ISO 8601 timestamp for incremental fetch.

        Returns:
            AggregationReport with full statistics.
        """
        report = AggregationReport()

        with self._lock:
            fetchers = list(self._fetchers)

        if not fetchers:
            report.finished = datetime.utcnow().isoformat()
            self._finalize(report)
            return report

        # Step 1: Parallel fetch
        fetch_results = self._fetch_all(fetchers, since)
        report.fetch_results = fetch_results

        # Check partial failure threshold
        if report.feeds_succeeded == 0:
            logger.error(
                "All %d feeds failed, no data to aggregate",
                len(fetchers),
            )
            report.finished = datetime.utcnow().isoformat()
            self._finalize(report)
            return report

        # Step 2: Collect all items
        all_items: List[IntelItem] = []
        for fr in fetch_results:
            all_items.extend(fr.items)
        report.total_fetched = len(all_items)

        # Step 3: Deduplicate + merge across feeds
        deduped = self._deduplicate_and_merge(all_items)
        report.total_after_dedup = len(deduped)
        report.total_merged = report.total_fetched - len(deduped)

        # Step 4: Store
        store_result = self._store.bulk_insert(deduped)
        report.total_stored = store_result["inserted"]
        report.total_store_dupes = store_result["duplicates"]

        report.finished = datetime.utcnow().isoformat()
        self._finalize(report)
        return report

    def _fetch_all(
        self,
        fetchers: List[IntelFetcher],
        since: Optional[str],
    ) -> List[FetchResult]:
        """Run all fetchers in parallel and collect results."""
        results: List[FetchResult] = []

        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            future_to_name = {}
            for f in fetchers:
                future = pool.submit(self._run_single_fetcher, f, since)
                future_to_name[future] = f.name

            for future in as_completed(future_to_name):
                result = future.result()  # FetchResult (never raises)
                results.append(result)

        return results

    def _run_single_fetcher(
        self,
        fetcher: IntelFetcher,
        since: Optional[str],
    ) -> FetchResult:
        """Run one fetcher, catching any exception."""
        result = FetchResult(fetcher.name)
        start = datetime.utcnow()
        try:
            items = fetcher.fetch(since=since)
            result.items = items
        except Exception as exc:
            result.error = str(exc)
            logger.warning("Fetcher %s failed: %s", fetcher.name, exc)
        result.duration_ms = (
            (datetime.utcnow() - start).total_seconds() * 1000
        )
        return result

    # ------------------------------------------------------------------
    # Deduplication & merge
    # ------------------------------------------------------------------

    def _deduplicate_and_merge(
        self, items: List[IntelItem]
    ) -> List[IntelItem]:
        """Deduplicate items by dedup_key.

        When duplicates exist across feeds:
          - Keep the item with the most recent ``ingested_at``
          - Upgrade to the highest severity across duplicates
        """
        best: Dict[str, IntelItem] = {}

        for item in items:
            key = item.dedup_key
            if key not in best:
                best[key] = item
                continue

            existing = best[key]

            # Keep the one with the more recent ingested_at timestamp
            if item.ingested_at > existing.ingested_at:
                winner = item
            else:
                winner = existing

            # Upgrade severity to the max of both
            winner_sev = _severity_rank(winner.severity)
            other = item if winner is existing else existing
            other_sev = _severity_rank(other.severity)

            if other_sev > winner_sev and hasattr(winner.payload, "severity"):
                winner.payload.severity = other.severity

            best[key] = winner

        return list(best.values())

    # ------------------------------------------------------------------
    # Logging & callbacks
    # ------------------------------------------------------------------

    def _finalize(self, report: AggregationReport) -> None:
        """Log the aggregation results and invoke callbacks."""
        self._last_report = report

        self._log_to_audit(report)

        logger.info(
            "Aggregation complete: %d fetched, %d deduped, "
            "%d stored, %d store-dupes, %d/%d feeds ok",
            report.total_fetched,
            report.total_merged,
            report.total_stored,
            report.total_store_dupes,
            report.feeds_succeeded,
            report.feeds_succeeded + report.feeds_failed,
        )

        if self._on_complete:
            try:
                self._on_complete(report)
            except Exception as exc:
                logger.warning("on_complete callback failed: %s", exc)

    def _log_to_audit(self, report: AggregationReport) -> None:
        """Append aggregation summary to the audit log (JSON Lines)."""
        log_path = Path(self._audit_log)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "event": "intel_aggregation",
                "action": "aggregate",
                "feeds_succeeded": report.feeds_succeeded,
                "feeds_failed": report.feeds_failed,
                "total_fetched": report.total_fetched,
                "total_stored": report.total_stored,
                "total_merged": report.total_merged,
            }
            with open(log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
        except OSError as exc:
            logger.warning("Failed to write audit log: %s", exc)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_last_report(self) -> Optional[Dict[str, Any]]:
        """Return the most recent aggregation report as a dict."""
        if self._last_report is None:
            return None
        return self._last_report.to_dict()

    def stats(self) -> Dict[str, Any]:
        """Return aggregator status summary."""
        with self._lock:
            fetcher_names = [f.name for f in self._fetchers]
            fetcher_stats = [f.get_stats() for f in self._fetchers]
        return {
            "running": self.is_running,
            "schedule": f"{self._schedule_hour:02d}:{self._schedule_minute:02d} UTC",
            "fetcher_count": len(fetcher_names),
            "fetchers": fetcher_names,
            "fetcher_stats": fetcher_stats,
            "last_report": self._last_report.to_dict() if self._last_report else None,
            "store_stats": self._store.stats(),
        }
