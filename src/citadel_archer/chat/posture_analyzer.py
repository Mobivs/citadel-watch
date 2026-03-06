# PRD: AI Trigger 3a — Scheduled Daily Security Posture Analysis
# Reference: Plan — Category 3 (App-Initiated Processing)
#
# Background asyncio task that runs a daily security posture review.
# Gathers data from EventAggregator, AssetInventory, RemoteShieldDatabase,
# and AnomalyDetector, then sends a structured summary to SecureChat.
#
# AI Bridge coupling: When significant findings exist, the summary is sent
# as MessageType.EVENT and triggers AI processing (ai_bridge.py).
# On clean days it is sent as MessageType.TEXT — no AI call, no token cost.

import asyncio
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..intel.event_aggregator import EventAggregator
    from ..intel.assets import AssetInventory
    from ..intel.anomaly_detector import AnomalyDetector
    from ..remote.shield_database import RemoteShieldDatabase

from .message import MessageType

logger = logging.getLogger(__name__)

ANALYSIS_INTERVAL = 86400  # 24 hours (seconds)
INITIAL_DELAY = 120        # 2 min after startup — lets sensors warm up

# Once-per-day dedup — prevents re-running when the app restarts mid-day
_DATE_FILE = Path("data/posture_last_date.txt")


def _ran_today() -> bool:
    """Return True if posture analysis already ran today (UTC)."""
    try:
        if _DATE_FILE.exists():
            return _DATE_FILE.read_text().strip() == datetime.now(timezone.utc).strftime("%Y-%m-%d")
    except Exception:
        pass
    return False


def _mark_ran_today() -> None:
    """Persist today's UTC date so restarts won't re-run posture analysis."""
    try:
        _DATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _DATE_FILE.write_text(datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    except Exception:
        logger.debug("Failed to write posture date marker", exc_info=True)


class PostureAnalyzer:
    """Scheduled daily security posture analysis (Trigger 3a).

    Background asyncio task that periodically gathers security data from
    multiple sources and sends a summary to SecureChat, triggering the AI
    to provide proactive analysis and recommendations.

    All data sources are optional — the analyzer runs with whatever is
    available and gracefully skips missing or failing components.
    """

    def __init__(
        self,
        chat_manager,
        aggregator: Optional["EventAggregator"] = None,
        inventory: Optional["AssetInventory"] = None,
        shield_db: Optional["RemoteShieldDatabase"] = None,
        anomaly_detector: Optional["AnomalyDetector"] = None,
        interval: Optional[int] = None,
        initial_delay: Optional[int] = None,
    ):
        self._chat = chat_manager
        self._aggregator = aggregator
        self._inventory = inventory
        self._shield_db = shield_db
        self._anomaly = anomaly_detector

        self._interval = interval if interval is not None else ANALYSIS_INTERVAL
        self._initial_delay = initial_delay if initial_delay is not None else INITIAL_DELAY
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._last_run: Optional[datetime] = None
        self._run_count = 0

    # ── Lifecycle ────────────────────────────────────────────────────

    async def start(self):
        """Start the analysis loop as a background task."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._analysis_loop())
        logger.info(
            "Posture analyzer started (interval=%ds, initial_delay=%ds)",
            self._interval,
            self._initial_delay,
        )

    async def stop(self):
        """Stop the analysis loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Posture analyzer stopped")

    async def run_now(self):
        """Run a single analysis immediately (convenience for testing)."""
        await self._run_analysis()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def last_run(self) -> Optional[datetime]:
        return self._last_run

    @property
    def run_count(self) -> int:
        return self._run_count

    # ── Analysis Loop ────────────────────────────────────────────────

    async def _analysis_loop(self):
        """Main loop: initial delay, then periodic analysis."""
        if self._initial_delay > 0:
            await asyncio.sleep(self._initial_delay)

        while self._running:
            try:
                await self._run_analysis()
            except Exception:
                logger.exception("Posture analysis cycle failed")
            await asyncio.sleep(self._interval)

    async def _run_analysis(self):
        """Gather posture data, format summary, send to AI."""
        # Once-per-day guard — prevents re-running when the app restarts mid-day.
        # The 24-hour interval already prevents double-runs in a stable session,
        # but a restart resets the in-memory timer.
        if _ran_today():
            logger.info("Posture analysis suppressed: already ran today (UTC)")
            return

        # Respect Do Not Disturb — skip entirely if Guardian is muted
        try:
            from ..core.user_preferences import get_user_preferences
            prefs = get_user_preferences()
            if prefs.get("guardian_muted", "false") == "true":
                logger.info("Posture analysis suppressed (Do Not Disturb active)")
                self._last_run = datetime.now(timezone.utc)
                self._run_count += 1
                return
            # Respect ai.posture_enabled — user can disable daily posture reports
            if prefs.get("ai.posture_enabled", "true") == "false":
                logger.info("Posture analysis suppressed (disabled in AI Context settings)")
                self._last_run = datetime.now(timezone.utc)
                self._run_count += 1
                return
        except Exception:
            pass  # preference unavailable — proceed normally

        report = self._gather_posture()

        # Only trigger an AI turn when there are actual findings worth analyzing.
        # On clean days the summary is logged as TEXT — no AI call, no token cost.
        has_findings = self._has_significant_findings(report)
        msg_type = MessageType.EVENT if has_findings else MessageType.TEXT
        summary = self._format_summary(report, has_findings)

        try:
            await self._chat.send_system(summary, msg_type)
        except Exception:
            logger.warning("Failed to send posture analysis to chat")

        _mark_ran_today()
        self._last_run = datetime.now(timezone.utc)
        self._run_count += 1
        logger.info(
            "Posture analysis #%d complete (ai_triggered=%s)",
            self._run_count,
            has_findings,
        )

    # ── Data Gathering ───────────────────────────────────────────────

    def _gather_posture(self) -> Dict[str, Any]:
        """Collect security posture data from all available sources.

        Each source is independently wrapped in try/except so a failure
        in one component never prevents the rest of the report.
        """
        report: Dict[str, Any] = {}

        # 1. Events from the last 24 hours
        if self._aggregator:
            try:
                cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
                events = self._aggregator.since(cutoff)
                severity_counts: Dict[str, int] = Counter()
                for ev in events:
                    severity_counts[ev.severity.lower()] += 1
                report["events"] = {
                    "total": len(events),
                    "by_severity": dict(severity_counts),
                }
            except Exception:
                logger.debug("Failed to gather event data", exc_info=True)

        # 2. Asset inventory status
        if self._inventory:
            try:
                report["assets"] = self._inventory.stats()
            except Exception:
                logger.debug("Failed to gather asset data", exc_info=True)

        # 3. Remote Shield agent health + open threats
        if self._shield_db:
            try:
                agents = self._shield_db.list_agents()
                now = datetime.now(timezone.utc)
                active = 0
                stale = 0
                for agent in agents:
                    hb = agent.get("last_heartbeat")
                    if hb and _is_recent(hb, now, hours=1):
                        active += 1
                    else:
                        stale += 1

                threats = self._shield_db.list_threats(status="open")
                report["agents"] = {
                    "total": len(agents),
                    "active": active,
                    "stale": stale,
                    "open_threats": len(threats),
                }
            except Exception:
                logger.debug("Failed to gather agent data", exc_info=True)

        # 4. Anomaly detection status
        if self._anomaly:
            try:
                report["anomaly"] = self._anomaly.stats()
            except Exception:
                logger.debug("Failed to gather anomaly data", exc_info=True)

        return report

    # ── Findings Check ───────────────────────────────────────────────

    def _has_significant_findings(self, report: Dict[str, Any]) -> bool:
        """Return True only when there are actual findings worth an AI turn.

        On clean days this returns False so the summary is logged to chat
        as MessageType.TEXT — no AI call, no token cost.
        """
        if "events" in report:
            sev = report["events"].get("by_severity", {})
            if sev.get("critical", 0) + sev.get("alert", 0) > 0:
                return True
        if "agents" in report:
            ag = report["agents"]
            if ag.get("open_threats", 0) > 0:
                return True
            if ag.get("stale", 0) > 0:
                try:
                    from ..core.user_preferences import get_user_preferences
                    if get_user_preferences().get("ai.stale_triggers_ai", "true") == "true":
                        return True
                except Exception:
                    return True
        if "anomaly" in report:
            if report["anomaly"].get("anomalies_detected", 0) > 0:
                return True
        return False

    # ── Summary Formatting ───────────────────────────────────────────

    def _format_summary(self, report: Dict[str, Any], has_findings: bool = False) -> str:
        """Format the posture report as a text summary for SecureChat."""
        lines: List[str] = ["[Security Posture] Daily security review"]

        if "events" in report:
            ev = report["events"]
            sev = ev.get("by_severity", {})
            lines.append(
                f"Events (24h): {ev['total']} total — "
                f"{sev.get('critical', 0)} critical, "
                f"{sev.get('alert', 0)} alert, "
                f"{sev.get('investigate', 0)} investigate, "
                f"{sev.get('info', 0)} info"
            )

        if "assets" in report:
            a = report["assets"]
            by_status = a.get("by_status", {})
            lines.append(
                f"Assets: {a.get('total', 0)} managed — "
                f"{by_status.get('protected', 0)} protected, "
                f"{by_status.get('online', 0)} online, "
                f"{by_status.get('offline', 0)} offline"
            )

        if "agents" in report:
            ag = report["agents"]
            lines.append(
                f"Agents: {ag['total']} deployed — "
                f"{ag['active']} active, {ag['stale']} stale, "
                f"{ag['open_threats']} open threats"
            )

        if "anomaly" in report:
            an = report["anomaly"]
            model_status = "fitted" if an.get("model_fitted") else "cold start"
            lines.append(
                f"Anomaly detection: "
                f"{an.get('anomalies_detected', 0)} anomalies detected, "
                f"model {model_status}"
            )

        # Only include the AI instruction when there are findings to act on.
        # On clean days the message is sent as TEXT so no AI turn fires anyway,
        # but omitting the instruction keeps the chat log concise.
        if has_findings:
            lines.append(
                "Provide analysis of critical and high-priority findings."
            )
        else:
            lines.append("All systems nominal — no critical or high-priority findings.")

        return "\n".join(lines)


# ── Helpers ──────────────────────────────────────────────────────────


def _is_recent(timestamp_str: Optional[str], now: datetime, hours: int = 1) -> bool:
    """Check if an ISO 8601 timestamp is within the last N hours."""
    if not timestamp_str:
        return False
    try:
        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        # Normalize both to naive or both to aware for safe comparison
        if ts.tzinfo and not now.tzinfo:
            ts = ts.replace(tzinfo=None)
        elif now.tzinfo and not ts.tzinfo:
            ts = ts.replace(tzinfo=now.tzinfo)
        return (now - ts) < timedelta(hours=hours)
    except (ValueError, TypeError):
        return False
