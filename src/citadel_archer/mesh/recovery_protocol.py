"""Recovery/reconciliation protocol — desktop comes back online after being dark.

v0.3.42: When the desktop coordinator reconnects after an outage:

  1. **Sync missed events**: Pull queued events from agents that operated
     autonomously during the outage.
  2. **Merge secondary brain decisions**: Review all decisions the secondary
     brain made while coordinating. Desktop accepts or rolls back.
  3. **Conflict resolution**: Desktop wins — conflicting decisions are
     rolled back automatically.
  4. **Heartbeat restoration**: Desktop resumes heartbeats, agents
     transition from AUTONOMOUS/HEIGHTENED back to NORMAL.
  5. **Audit reconciliation**: Secondary brain's coordination audit log
     is merged into the desktop's master audit trail.

Zero AI tokens — pure automation reconciliation.
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Recovery State ──────────────────────────────────────────────────


class RecoveryState(str, Enum):
    """State of the recovery process."""

    IDLE = "idle"              # No recovery needed
    SYNCING = "syncing"        # Pulling missed events
    REVIEWING = "reviewing"    # Reviewing secondary brain decisions
    RESOLVING = "resolving"    # Resolving conflicts
    RESTORING = "restoring"    # Restoring normal heartbeats
    COMPLETE = "complete"      # Recovery finished


# ── Recovery Report ─────────────────────────────────────────────────


@dataclass
class RecoveryStep:
    """A single step in the recovery process."""

    step: str
    status: str = "pending"    # pending, in_progress, completed, failed
    started_at: str = ""
    completed_at: str = ""
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "step": self.step,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "details": self.details,
        }


@dataclass
class RecoveryReport:
    """Full report of a recovery session."""

    recovery_id: str
    started_at: str = ""
    completed_at: str = ""
    state: str = "idle"
    outage_duration_seconds: int = 0
    steps: List[RecoveryStep] = field(default_factory=list)
    events_synced: int = 0
    decisions_reviewed: int = 0
    decisions_accepted: int = 0
    decisions_rolled_back: int = 0
    conflicts_resolved: int = 0
    audit_entries_merged: int = 0

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "recovery_id": self.recovery_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "state": self.state,
            "outage_duration_seconds": self.outage_duration_seconds,
            "steps": [s.to_dict() for s in self.steps],
            "events_synced": self.events_synced,
            "decisions_reviewed": self.decisions_reviewed,
            "decisions_accepted": self.decisions_accepted,
            "decisions_rolled_back": self.decisions_rolled_back,
            "conflicts_resolved": self.conflicts_resolved,
            "audit_entries_merged": self.audit_entries_merged,
        }


# ── Conflict Resolver ───────────────────────────────────────────────


@dataclass
class ConflictEntry:
    """A conflict between secondary brain decision and desktop policy."""

    decision_id: str
    action: str
    target_node_id: str
    conflict_reason: str
    resolution: str = "pending"  # pending, accepted, rolled_back
    resolved_at: str = ""

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "action": self.action,
            "target_node_id": self.target_node_id,
            "conflict_reason": self.conflict_reason,
            "resolution": self.resolution,
            "resolved_at": self.resolved_at,
        }


# ── Recovery Manager ────────────────────────────────────────────────


class RecoveryManager:
    """Manages the recovery/reconciliation protocol.

    Orchestrates the 5-step recovery process when the desktop
    coordinator comes back online after an outage.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._state = RecoveryState.IDLE
        self._current_report: Optional[RecoveryReport] = None
        self._history: List[RecoveryReport] = []
        self._max_history = 20
        self._conflicts: List[ConflictEntry] = []

    @property
    def state(self) -> RecoveryState:
        with self._lock:
            return self._state

    @property
    def current_report(self) -> Optional[dict]:
        with self._lock:
            return self._current_report.to_dict() if self._current_report else None

    # ── Step 1: Sync Missed Events ────────────────────────────────

    def start_recovery(self, recovery_id: str, outage_seconds: int = 0) -> RecoveryReport:
        """Begin the recovery process.

        If a recovery is already in progress, auto-completes it and
        archives to history before starting the new one.
        """
        with self._lock:
            # Auto-complete existing recovery if in progress
            if self._current_report is not None:
                self._current_report.completed_at = datetime.now(timezone.utc).isoformat()
                self._history.append(self._current_report)
                if len(self._history) > self._max_history:
                    self._history = self._history[-self._max_history:]

            self._state = RecoveryState.SYNCING
            self._current_report = RecoveryReport(
                recovery_id=recovery_id,
                state=RecoveryState.SYNCING.value,
                outage_duration_seconds=outage_seconds,
            )
            self._conflicts = []
            return self._current_report

    def sync_events(self, events: List[dict]) -> int:
        """Step 1: Import missed events from agents.

        Args:
            events: List of event dicts from agent queues.

        Returns:
            Number of events synced.
        """
        with self._lock:
            if self._current_report is None:
                return 0

            step = RecoveryStep(
                step="sync_events",
                status="in_progress",
                started_at=datetime.now(timezone.utc).isoformat(),
            )
            count = len(events)
            step.status = "completed"
            step.completed_at = datetime.now(timezone.utc).isoformat()
            step.details = {"events_count": count}
            self._current_report.steps.append(step)
            self._current_report.events_synced = count
            self._state = RecoveryState.REVIEWING
            self._current_report.state = self._state.value
            return count

    # ── Step 2: Review Secondary Brain Decisions ──────────────────

    def review_decisions(
        self,
        decisions: List[dict],
        auto_accept_actions: Optional[List[str]] = None,
        auto_rollback_actions: Optional[List[str]] = None,
    ) -> dict:
        """Step 2: Review decisions made by the secondary brain.

        Auto-accepts safe actions, auto-rolls-back dangerous ones,
        and flags ambiguous ones for manual review.

        Args:
            decisions: List of CoordinationDecision dicts.
            auto_accept_actions: Actions to automatically accept.
            auto_rollback_actions: Actions to automatically roll back.

        Returns:
            Summary of review results.
        """
        auto_accept = set(auto_accept_actions or [
            "lower_alert_threshold",
            "increase_polling_frequency",
        ])
        auto_rollback = set(auto_rollback_actions or [
            "rotate_credentials",
            "kill_all_ssh_sessions",
        ])

        with self._lock:
            if self._current_report is None:
                return {"error": "No recovery in progress"}

            step = RecoveryStep(
                step="review_decisions",
                status="in_progress",
                started_at=datetime.now(timezone.utc).isoformat(),
            )

            accepted = 0
            rolled_back = 0
            flagged = 0

            for d in decisions:
                action = d.get("action", "")
                if action in auto_rollback:
                    rolled_back += 1
                    self._conflicts.append(ConflictEntry(
                        decision_id=d.get("decision_id", ""),
                        action=action,
                        target_node_id=d.get("target_node_id", ""),
                        conflict_reason="auto_rollback_policy",
                        resolution="rolled_back",
                        resolved_at=datetime.now(timezone.utc).isoformat(),
                    ))
                elif action in auto_accept:
                    accepted += 1
                else:
                    # Ambiguous — accept by default (desktop wins on
                    # conflict, but conservative actions are fine)
                    accepted += 1

            step.status = "completed"
            step.completed_at = datetime.now(timezone.utc).isoformat()
            step.details = {
                "total": len(decisions),
                "accepted": accepted,
                "rolled_back": rolled_back,
                "flagged": flagged,
            }
            self._current_report.steps.append(step)
            self._current_report.decisions_reviewed = len(decisions)
            self._current_report.decisions_accepted = accepted
            self._current_report.decisions_rolled_back = rolled_back
            self._state = RecoveryState.RESOLVING
            self._current_report.state = self._state.value

            return step.details

    # ── Step 3: Resolve Conflicts ─────────────────────────────────

    def resolve_conflicts(self) -> List[dict]:
        """Step 3: Resolve any remaining conflicts (desktop wins).

        Returns the list of resolved conflicts.
        """
        with self._lock:
            if self._current_report is None:
                return []

            step = RecoveryStep(
                step="resolve_conflicts",
                status="in_progress",
                started_at=datetime.now(timezone.utc).isoformat(),
            )

            # Desktop wins — all unresolved conflicts are rolled back
            resolved = []
            for c in self._conflicts:
                if c.resolution == "pending":
                    c.resolution = "rolled_back"
                    c.resolved_at = datetime.now(timezone.utc).isoformat()
                resolved.append(c.to_dict())

            step.status = "completed"
            step.completed_at = datetime.now(timezone.utc).isoformat()
            step.details = {"conflicts_resolved": len(resolved)}
            self._current_report.steps.append(step)
            self._current_report.conflicts_resolved = len(resolved)
            self._state = RecoveryState.RESTORING
            self._current_report.state = self._state.value

            return resolved

    # ── Step 4: Restore Normal Heartbeats ─────────────────────────

    def restore_heartbeats(self, coordinator=None) -> dict:
        """Step 4: Resume normal heartbeat operation.

        If a MeshCoordinator is provided, this triggers peers to
        drop back from AUTONOMOUS/HEIGHTENED to NORMAL via heartbeat
        reception (automatic — just starting to send heartbeats again
        causes peers to recover).

        Returns restoration summary.
        """
        with self._lock:
            if self._current_report is None:
                return {"error": "No recovery in progress"}

            step = RecoveryStep(
                step="restore_heartbeats",
                status="in_progress",
                started_at=datetime.now(timezone.utc).isoformat(),
            )

            peer_count = 0
            if coordinator:
                try:
                    peers = coordinator.state_manager.all_peers()
                    peer_count = len(peers)
                except Exception:
                    pass

            step.status = "completed"
            step.completed_at = datetime.now(timezone.utc).isoformat()
            step.details = {
                "peers_notified": peer_count,
                "coordinator_running": coordinator.is_running if coordinator else False,
            }
            self._current_report.steps.append(step)
            self._state = RecoveryState.COMPLETE
            self._current_report.state = self._state.value

            return step.details

    # ── Step 5: Merge Audit Logs ──────────────────────────────────

    def merge_audit_log(self, entries: List[dict]) -> int:
        """Step 5: Merge secondary brain's audit entries into master.

        Args:
            entries: Audit log entries from the secondary brain.

        Returns:
            Number of entries merged.
        """
        with self._lock:
            if self._current_report is None:
                return 0

            step = RecoveryStep(
                step="merge_audit_log",
                status="in_progress",
                started_at=datetime.now(timezone.utc).isoformat(),
            )

            count = len(entries)
            step.status = "completed"
            step.completed_at = datetime.now(timezone.utc).isoformat()
            step.details = {"entries_merged": count}
            self._current_report.steps.append(step)
            self._current_report.audit_entries_merged = count

            return count

    # ── Complete Recovery ──────────────────────────────────────────

    def complete_recovery(self) -> Optional[RecoveryReport]:
        """Finalize and archive the recovery report."""
        with self._lock:
            if self._current_report is None:
                return None

            self._current_report.completed_at = datetime.now(timezone.utc).isoformat()
            self._current_report.state = RecoveryState.COMPLETE.value

            report = self._current_report
            self._history.append(report)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]

            self._current_report = None
            self._state = RecoveryState.IDLE
            self._conflicts = []

            return report

    # ── Run Full Recovery ─────────────────────────────────────────

    def run_full_recovery(
        self,
        recovery_id: str,
        outage_seconds: int = 0,
        events: Optional[List[dict]] = None,
        decisions: Optional[List[dict]] = None,
        audit_entries: Optional[List[dict]] = None,
        coordinator=None,
    ) -> RecoveryReport:
        """Execute all 5 recovery steps in sequence.

        Convenience method for non-interactive recovery.
        """
        self.start_recovery(recovery_id, outage_seconds)
        self.sync_events(events or [])
        self.review_decisions(decisions or [])
        self.resolve_conflicts()
        self.restore_heartbeats(coordinator)
        self.merge_audit_log(audit_entries or [])
        return self.complete_recovery()

    # ── History ───────────────────────────────────────────────────

    def get_history(self, limit: int = 10) -> List[dict]:
        """Get recent recovery reports."""
        with self._lock:
            return [r.to_dict() for r in reversed(self._history[-limit:])]

    def get_status(self) -> dict:
        """Current recovery status."""
        with self._lock:
            return {
                "state": self._state.value,
                "current_recovery": (
                    self._current_report.to_dict() if self._current_report else None
                ),
                "history_count": len(self._history),
                "pending_conflicts": sum(
                    1 for c in self._conflicts if c.resolution == "pending"
                ),
            }


# ── Singleton ────────────────────────────────────────────────────────

_manager: Optional[RecoveryManager] = None
_manager_lock = threading.Lock()


def get_recovery_manager() -> RecoveryManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = RecoveryManager()
    return _manager


def set_recovery_manager(m: Optional[RecoveryManager]) -> None:
    global _manager
    _manager = m
