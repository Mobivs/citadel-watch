# PRD: AI Trigger 3b — Startup Catch-Up
# Reference: docs/PRD.md, Trigger Model — Category 3 (App-Initiated Processing)
#
# One-shot async task that runs once at startup. Reviews security events
# from persistent sources (audit log, Remote Shield DB, asset inventory)
# that occurred during the offline period (between last SYSTEM_STOP and now).
#
# AI Bridge coupling: The summary text MUST contain "critical" or "high"
# to trigger AI processing (ai_bridge.py:224-227).

import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.audit_log import AuditLogger
    from ..intel.assets import AssetInventory
    from ..remote.shield_database import RemoteShieldDatabase

from .message import MessageType

logger = logging.getLogger(__name__)

CATCHUP_DELAY = 30           # seconds — wait for services to warm up
MIN_OFFLINE_MINUTES = 5      # skip if offline < 5 min (just a restart)
DEFAULT_LOOKBACK_HOURS = 24  # fallback if no SYSTEM_STOP found (first run)
MAX_LOOKBACK_DAYS = 7        # never look back more than 7 days


class StartupCatchup:
    """One-shot startup security review (Trigger 3b).

    Runs once after app startup to review security events that occurred
    while the application was closed. Gathers data from persistent
    sources (audit log files, Remote Shield SQLite DB, asset inventory)
    and sends a summary to SecureChat for AI analysis.

    All data sources are optional — the catch-up runs with whatever
    is available and gracefully skips missing or failing components.
    """

    def __init__(
        self,
        chat_manager,
        audit_logger: Optional["AuditLogger"] = None,
        inventory: Optional["AssetInventory"] = None,
        shield_db: Optional["RemoteShieldDatabase"] = None,
        delay: Optional[int] = None,
    ):
        self._chat = chat_manager
        self._audit = audit_logger
        self._inventory = inventory
        self._shield_db = shield_db
        self._delay = delay if delay is not None else CATCHUP_DELAY

        self._completed = False
        self._skipped = False
        self._skip_reason: Optional[str] = None
        self._task: Optional[asyncio.Task] = None

    # ── Lifecycle ────────────────────────────────────────────────────

    async def run(self):
        """Launch the catch-up as a background task."""
        if self._completed or self._task is not None:
            return
        self._task = asyncio.create_task(self._execute())
        logger.info("Startup catch-up scheduled (delay=%ds)", self._delay)

    async def run_now(self):
        """Run catch-up immediately (convenience for testing)."""
        await self._execute_inner()

    @property
    def completed(self) -> bool:
        return self._completed

    @property
    def skipped(self) -> bool:
        return self._skipped

    @property
    def skip_reason(self) -> Optional[str]:
        return self._skip_reason

    # ── Execution ────────────────────────────────────────────────────

    async def _execute(self):
        """Wait for delay, then run catch-up."""
        if self._delay > 0:
            await asyncio.sleep(self._delay)
        try:
            await self._execute_inner()
        except Exception:
            logger.exception("Startup catch-up failed")

    async def _execute_inner(self):
        """Core logic: determine window, gather data, send summary."""
        now = datetime.now(timezone.utc)
        last_stop = self._find_last_stop()

        if last_stop is None:
            # First run — use default lookback
            start_time = now - timedelta(hours=DEFAULT_LOOKBACK_HOURS)
            is_first_run = True
        else:
            start_time = last_stop
            is_first_run = False

        # Cap at MAX_LOOKBACK_DAYS
        max_lookback = now - timedelta(days=MAX_LOOKBACK_DAYS)
        if start_time < max_lookback:
            start_time = max_lookback

        # Check minimum offline duration
        offline_seconds = (now - start_time).total_seconds()
        offline_minutes = offline_seconds / 60
        if not is_first_run and offline_minutes < MIN_OFFLINE_MINUTES:
            self._skipped = True
            self._skip_reason = (
                f"Offline duration too short ({offline_minutes:.1f}min "
                f"< {MIN_OFFLINE_MINUTES}min threshold)"
            )
            self._completed = True
            logger.info("Startup catch-up skipped: %s", self._skip_reason)
            return

        # Gather data from persistent sources
        report = self._gather_offline_events(start_time, now)
        report["offline_duration"] = _format_duration(now - start_time)
        report["is_first_run"] = is_first_run

        # Format and send summary
        summary = self._format_summary(report)

        try:
            await self._chat.send_system(summary, MessageType.EVENT)
        except Exception:
            logger.warning("Failed to send startup catch-up to chat")

        self._completed = True
        logger.info(
            "Startup catch-up complete (window=%s, first_run=%s)",
            report["offline_duration"],
            is_first_run,
        )

    # ── Offline Window Detection ─────────────────────────────────────

    def _find_last_stop(self) -> Optional[datetime]:
        """Find the most recent SYSTEM_STOP event from the audit log.

        Returns the timestamp as a tz-aware UTC datetime, or None if no
        SYSTEM_STOP event exists.
        """
        if not self._audit:
            return None

        try:
            from ..core.audit_log import EventType

            events = self._audit.query_events(
                event_types=[EventType.SYSTEM_STOP],
                limit=1,
            )
            if events:
                ts_str = events[0].get("timestamp")
                if ts_str:
                    ts = datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00")
                    )
                    # Normalize to tz-aware UTC
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=timezone.utc)
                    return ts
        except Exception:
            logger.debug("Failed to find last SYSTEM_STOP", exc_info=True)

        return None

    # ── Data Gathering ───────────────────────────────────────────────

    def _gather_offline_events(
        self, start_time: datetime, end_time: datetime,
    ) -> Dict[str, Any]:
        """Collect security data from persistent sources for the
        offline window.

        Each source is independently wrapped in try/except so a failure
        in one component never prevents the rest of the report.
        """
        report: Dict[str, Any] = {}

        # Normalize to naive UTC for audit_log.query_events compatibility
        start_naive = start_time.replace(tzinfo=None) if start_time.tzinfo else start_time
        end_naive = end_time.replace(tzinfo=None) if end_time.tzinfo else end_time

        # 1. Audit log events during offline period
        if self._audit:
            try:
                events = self._audit.query_events(
                    start_time=start_naive,
                    end_time=end_naive,
                    limit=500,
                )
                severity_counts: Dict[str, int] = Counter()
                type_counts: Dict[str, int] = Counter()
                notable_events: List[Dict] = []

                for ev in events:
                    sev = ev.get("severity", "info")
                    severity_counts[sev] += 1
                    type_counts[ev.get("event_type", "unknown")] += 1

                    if sev in ("alert", "critical", "investigate"):
                        notable_events.append({
                            "type": ev.get("event_type"),
                            "severity": sev,
                            "message": ev.get("message", "")[:120],
                            "timestamp": ev.get("timestamp"),
                        })

                report["audit"] = {
                    "total": len(events),
                    "by_severity": dict(severity_counts),
                    "by_type": dict(type_counts),
                    "notable": notable_events[:10],
                }
            except Exception:
                logger.debug("Failed to gather audit events", exc_info=True)

        # 2. Remote Shield threats during offline period
        if self._shield_db:
            try:
                all_threats = self._shield_db.list_threats(
                    status="open", limit=100,
                )
                offline_threats = []
                for t in all_threats:
                    detected_str = t.get("detected_at") or t.get("reported_at", "")
                    if detected_str:
                        detected_dt = _parse_ts(detected_str)
                        if detected_dt and detected_dt >= start_time:
                            offline_threats.append(t)

                agents = self._shield_db.list_agents()
                stale_agents = []
                for agent in agents:
                    hb_str = agent.get("last_heartbeat")
                    if hb_str:
                        hb_dt = _parse_ts(hb_str)
                        if hb_dt and hb_dt < start_time:
                            stale_agents.append(agent.get("hostname", "?"))

                report["remote_shield"] = {
                    "new_threats": len(offline_threats),
                    "total_open": len(all_threats),
                    "threat_details": [
                        {
                            "title": t.get("title", ""),
                            "severity": t.get("severity"),
                            "hostname": t.get("hostname", ""),
                        }
                        for t in offline_threats[:5]
                    ],
                    "agents_total": len(agents),
                    "agents_stale": stale_agents,
                }
            except Exception:
                logger.debug("Failed to gather Remote Shield data", exc_info=True)

        # 3. Asset inventory — current state snapshot
        if self._inventory:
            try:
                assets = self._inventory.all()
                compromised = [
                    a for a in assets if a.status.value == "compromised"
                ]
                offline_assets = [
                    a for a in assets if a.status.value == "offline"
                ]

                report["assets"] = {
                    "total": len(assets),
                    "compromised": [
                        {"name": a.name, "ip": a.ip_address}
                        for a in compromised
                    ],
                    "offline": [
                        {"name": a.name, "ip": a.ip_address}
                        for a in offline_assets
                    ],
                }
            except Exception:
                logger.debug("Failed to gather asset data", exc_info=True)

        return report

    # ── Summary Formatting ───────────────────────────────────────────

    def _format_summary(self, report: Dict[str, Any]) -> str:
        """Format the catch-up report as text for SecureChat.

        The text MUST contain "critical" and "high" keywords to trigger
        AI Bridge processing (ai_bridge.py:224-227).
        """
        duration = report.get("offline_duration", "unknown")
        is_first = report.get("is_first_run", False)

        if is_first:
            header = (
                f"[Startup Catch-Up] First run — reviewing last "
                f"{duration} of security history"
            )
        else:
            header = (
                f"[Startup Catch-Up] App was offline for {duration} "
                f"— reviewing events during that period"
            )

        lines: List[str] = [header]

        # Audit log summary
        if "audit" in report:
            audit = report["audit"]
            sev = audit.get("by_severity", {})
            lines.append(
                f"Audit events: {audit['total']} total — "
                f"{sev.get('critical', 0)} critical, "
                f"{sev.get('alert', 0)} alert, "
                f"{sev.get('investigate', 0)} investigate, "
                f"{sev.get('info', 0)} info"
            )
            notable = audit.get("notable", [])
            if notable:
                lines.append("Notable events:")
                for ev in notable[:5]:
                    lines.append(f"  - [{ev['severity']}] {ev['message']}")

        # Remote Shield summary
        if "remote_shield" in report:
            rs = report["remote_shield"]
            lines.append(
                f"Remote Shield: {rs['new_threats']} new threats "
                f"({rs['total_open']} total open), "
                f"{rs['agents_total']} agents"
            )
            if rs.get("agents_stale"):
                lines.append(
                    f"  Stale agents: {', '.join(rs['agents_stale'])}"
                )
            for td in rs.get("threat_details", [])[:3]:
                sev = _severity_label(td.get("severity"))
                lines.append(
                    f"  - [{sev}] {td['title']} on {td['hostname']}"
                )

        # Asset status
        if "assets" in report:
            a = report["assets"]
            issues = []
            if a["compromised"]:
                names = ", ".join(c["name"] for c in a["compromised"])
                issues.append(
                    f"{len(a['compromised'])} COMPROMISED ({names})"
                )
            if a["offline"]:
                names = ", ".join(o["name"] for o in a["offline"])
                issues.append(
                    f"{len(a['offline'])} offline ({names})"
                )
            if issues:
                lines.append(
                    f"Assets: {a['total']} managed — " + "; ".join(issues)
                )
            else:
                lines.append(f"Assets: {a['total']} managed — all healthy")

        # Always include trigger keywords
        lines.append(
            "Review any critical and high-priority findings from "
            "the offline period and advise on required actions."
        )

        return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────


def _severity_label(value) -> str:
    """Map numeric severity to a human-readable label."""
    if isinstance(value, int):
        if value >= 9:
            return "critical"
        if value >= 7:
            return "high"
        if value >= 5:
            return "medium"
        return "low"
    return str(value) if value is not None else "unknown"


def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse an ISO timestamp to tz-aware UTC datetime.

    Handles both naive (from shield_database) and tz-aware formats.
    """
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts
    except (ValueError, TypeError):
        return None


def _format_duration(delta: timedelta) -> str:
    """Format a timedelta as a human-readable string."""
    total_seconds = int(delta.total_seconds())
    if total_seconds < 0:
        return "0m"
    days = total_seconds // 86400
    hours = (total_seconds % 86400) // 3600
    minutes = (total_seconds % 3600) // 60
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"
