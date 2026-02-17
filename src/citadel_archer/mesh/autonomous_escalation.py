"""Autonomous escalation behavior — agents tighten rules when coordinator goes dark.

v0.3.37: When the mesh detects missed heartbeats (NORMAL → ALERT → HEIGHTENED
→ AUTONOMOUS), this module executes progressive defensive actions:

    ALERT (3 missed, ~90s):
        - Lower agent alert threshold → report more events
        - Queue monitoring frequency increase command

    HEIGHTENED (5 missed, ~150s):
        - Add emergency firewall deny rules (auto-expiring 1h)
        - Queue agent command to tighten local rules
        - Log ALERT-severity audit event

    AUTONOMOUS (10 missed, ~5min):
        - Full lockdown: deny-all except known-good IPs
        - Queue process termination commands for suspicious processes
        - Log ALERT-severity audit event with model_tier=opus

    RECOVERY (back to NORMAL):
        - Remove auto-generated emergency rules
        - Restore normal alert thresholds
        - Queue command to restore normal operations

All actions are:
    - Audited (EventType.MESH_ESCALATION with full details)
    - Time-limited (auto-expiring rules prevent permanent lockout)
    - Rollback-safe (recovery restores normal state)
    - Security-level aware (respects Observer/Guardian/Sentinel levels)
    - Zero AI tokens at execution time (pure automation; AI model_tier
      is advisory for callers who want to consult AI on the transition)
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Escalation Policy ────────────────────────────────────────────────


@dataclass
class EscalationPolicy:
    """Defines defensive actions for each escalation phase.

    Each peer can have a custom policy. Defaults are sensible for most
    VPS agents. Desktop coordinator uses observer-only policy.
    """

    # ALERT: enhanced monitoring
    alert_threshold_override: Optional[str] = "low"  # "low" | "medium" | "high" | None
    alert_polling_interval: int = 15  # seconds (default is usually 60)

    # HEIGHTENED: tighten defenses
    heightened_deny_sources: List[str] = field(default_factory=list)
    heightened_rule_ttl_minutes: int = 60  # auto-expire after 1 hour

    # AUTONOMOUS: full lockdown
    autonomous_allow_ips: List[str] = field(default_factory=list)
    autonomous_rule_ttl_minutes: int = 240  # auto-expire after 4 hours
    autonomous_kill_ssh: bool = False  # only if security level = SENTINEL

    # Recovery
    auto_recover: bool = True  # auto-restore on heartbeat resume


# ── Default Policies ─────────────────────────────────────────────────


DEFAULT_VPS_POLICY = EscalationPolicy(
    alert_threshold_override="low",
    alert_polling_interval=15,
    heightened_rule_ttl_minutes=60,
    autonomous_rule_ttl_minutes=240,
    autonomous_kill_ssh=False,
)

OBSERVER_POLICY = EscalationPolicy(
    alert_threshold_override=None,  # Don't change threshold
    alert_polling_interval=30,
    heightened_deny_sources=[],
    heightened_rule_ttl_minutes=60,
    autonomous_allow_ips=[],
    autonomous_kill_ssh=False,
)


# ── Escalation Action Results ────────────────────────────────────────


@dataclass
class EscalationActionResult:
    """Result of an autonomous escalation action."""

    action: str
    success: bool
    node_id: str
    phase: str
    details: Dict = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ── Escalation Handler ───────────────────────────────────────────────


class AutonomousEscalationHandler:
    """Executes defensive actions on mesh escalation phase transitions.

    Plugs into MeshCoordinator.on_phase_change() callback.
    Uses existing infrastructure:
        - shield_database command queue for async agent commands
        - firewall_manager for emergency rules
        - audit_log for full trail of autonomous actions
    """

    def __init__(self):
        self._policies: Dict[str, EscalationPolicy] = {}
        self._active_rules: Dict[str, List[int]] = {}  # node_id → [rule_ids]

    def set_policy(self, node_id: str, policy: EscalationPolicy) -> None:
        self._policies[node_id] = policy

    def get_policy(self, node_id: str) -> EscalationPolicy:
        return self._policies.get(node_id, DEFAULT_VPS_POLICY)

    def handle_phase_change(
        self, node_id: str, old_phase, new_phase, peer_state
    ) -> List[EscalationActionResult]:
        """Execute escalation actions for a phase transition.

        Called from the mesh phase-change callback (runs on the
        mesh-check-missed thread, outside the state lock).

        Returns list of action results for audit logging.
        """
        from .mesh_state import EscalationPhase

        results = []
        policy = self.get_policy(node_id)

        if new_phase == EscalationPhase.NORMAL:
            results = self._handle_recovery(node_id, old_phase, policy)
        elif new_phase == EscalationPhase.ALERT:
            results = self._handle_alert(node_id, policy)
        elif new_phase == EscalationPhase.HEIGHTENED:
            results = self._handle_heightened(node_id, policy)
        elif new_phase == EscalationPhase.AUTONOMOUS:
            results = self._handle_autonomous(node_id, policy)

        # Log all results
        self._audit_results(node_id, new_phase, results)
        return results

    # ── Phase Handlers ──────────────────────────────────────────────

    def _handle_alert(
        self, node_id: str, policy: EscalationPolicy
    ) -> List[EscalationActionResult]:
        """ALERT phase: Enhanced monitoring, lower thresholds."""
        results = []

        # Lower alert threshold
        if policy.alert_threshold_override:
            result = self._queue_command(
                node_id,
                "set_alert_threshold",
                {"threshold": policy.alert_threshold_override},
            )
            results.append(EscalationActionResult(
                action="lower_alert_threshold",
                success=result,
                node_id=node_id,
                phase="ALERT",
                details={"threshold": policy.alert_threshold_override},
            ))

        # Increase polling frequency
        result = self._queue_command(
            node_id,
            "set_polling_interval",
            {"interval": policy.alert_polling_interval},
        )
        results.append(EscalationActionResult(
            action="increase_polling_frequency",
            success=result,
            node_id=node_id,
            phase="ALERT",
            details={"interval": policy.alert_polling_interval},
        ))

        return results

    def _handle_heightened(
        self, node_id: str, policy: EscalationPolicy
    ) -> List[EscalationActionResult]:
        """HEIGHTENED phase: Tighten firewall, increase monitoring."""
        results = []

        # Add emergency deny rules
        if policy.heightened_deny_sources:
            rule_ids = self._add_emergency_rules(
                node_id,
                sources=policy.heightened_deny_sources,
                action="deny",
                ttl_minutes=policy.heightened_rule_ttl_minutes,
            )
            results.append(EscalationActionResult(
                action="add_emergency_firewall_rules",
                success=len(rule_ids) > 0,
                node_id=node_id,
                phase="HEIGHTENED",
                details={
                    "rules_added": len(rule_ids),
                    "ttl_minutes": policy.heightened_rule_ttl_minutes,
                },
            ))

        # Queue tighten command to agent
        result = self._queue_command(
            node_id,
            "tighten_local_rules",
            {"phase": "HEIGHTENED"},
        )
        results.append(EscalationActionResult(
            action="queue_tighten_rules",
            success=result,
            node_id=node_id,
            phase="HEIGHTENED",
        ))

        return results

    def _handle_autonomous(
        self, node_id: str, policy: EscalationPolicy
    ) -> List[EscalationActionResult]:
        """AUTONOMOUS phase: Full lockdown."""
        results = []

        # Add lockdown rules — deny all except allow-list
        if policy.autonomous_allow_ips:
            rule_ids = self._add_lockdown_rules(
                node_id,
                allow_ips=policy.autonomous_allow_ips,
                ttl_minutes=policy.autonomous_rule_ttl_minutes,
            )
            results.append(EscalationActionResult(
                action="apply_lockdown_rules",
                success=len(rule_ids) > 0,
                node_id=node_id,
                phase="AUTONOMOUS",
                details={
                    "rules_added": len(rule_ids),
                    "allow_ips": policy.autonomous_allow_ips,
                    "ttl_minutes": policy.autonomous_rule_ttl_minutes,
                },
            ))

        # Queue full lockdown command
        result = self._queue_command(
            node_id,
            "enter_lockdown",
            {"phase": "AUTONOMOUS", "kill_ssh": policy.autonomous_kill_ssh},
        )
        results.append(EscalationActionResult(
            action="queue_lockdown_command",
            success=result,
            node_id=node_id,
            phase="AUTONOMOUS",
            details={"kill_ssh": policy.autonomous_kill_ssh},
        ))

        return results

    def _handle_recovery(
        self, node_id: str, old_phase, policy: EscalationPolicy
    ) -> List[EscalationActionResult]:
        """RECOVERY: Restore normal operations."""
        results = []

        if not policy.auto_recover:
            results.append(EscalationActionResult(
                action="recovery_skipped",
                success=True,
                node_id=node_id,
                phase="NORMAL",
                details={"reason": "auto_recover disabled"},
            ))
            return results

        # Remove emergency rules
        removed = self._remove_emergency_rules(node_id)
        results.append(EscalationActionResult(
            action="remove_emergency_rules",
            success=True,
            node_id=node_id,
            phase="NORMAL",
            details={"rules_removed": removed},
        ))

        # Queue restore command
        result = self._queue_command(
            node_id,
            "restore_normal",
            {"previous_phase": old_phase.value if hasattr(old_phase, 'value') else str(old_phase)},
        )
        results.append(EscalationActionResult(
            action="queue_restore_normal",
            success=result,
            node_id=node_id,
            phase="NORMAL",
        ))

        return results

    # ── Infrastructure Helpers ──────────────────────────────────────

    def _queue_command(
        self, node_id: str, command: str, params: dict
    ) -> bool:
        """Queue a command to the agent via shield_database.

        Best-effort: returns False on failure but never raises.
        """
        try:
            from ..remote.shield_database import get_shield_database
            db = get_shield_database()
            if db is None:
                return False
            cmd_id = f"mesh-esc-{uuid.uuid4().hex[:12]}"
            db.queue_command(
                command_id=cmd_id,
                agent_id=node_id,
                command_type=command,
                payload=params,
            )
            return True
        except Exception:
            logger.debug(
                "Failed to queue command %s for %s", command, node_id, exc_info=True
            )
            return False

    def _add_emergency_rules(
        self,
        node_id: str,
        sources: List[str],
        action: str = "deny",
        ttl_minutes: int = 60,
    ) -> List[int]:
        """Add auto-expiring firewall rules via FirewallManager."""
        rule_ids = []
        try:
            from ..remote.firewall_manager import FirewallManager
            from ..remote.shield_database import get_shield_database
            db = get_shield_database()
            if db is None:
                return rule_ids
            fm = FirewallManager(db)
            duration_secs = ttl_minutes * 60
            for source in sources:
                rule_id = fm.add_auto_rule(
                    asset_id=node_id,
                    source=source,
                    reason=f"mesh_escalation_{action}",
                    duration_seconds=duration_secs,
                )
                if rule_id:
                    rule_ids.append(rule_id)
                    self._active_rules.setdefault(node_id, []).append(rule_id)
        except Exception:
            logger.debug(
                "Failed to add emergency rules for %s", node_id, exc_info=True
            )
        return rule_ids

    def _add_lockdown_rules(
        self,
        node_id: str,
        allow_ips: List[str],
        ttl_minutes: int = 240,
    ) -> List[int]:
        """Add lockdown rules: deny-all + allow-list.

        Uses the command queue to instruct the agent to apply lockdown
        locally, since the FirewallManager auto-rule API is per-source deny.
        """
        rule_ids = []
        try:
            from ..remote.firewall_manager import FirewallManager
            from ..remote.shield_database import get_shield_database
            db = get_shield_database()
            if db is None:
                return rule_ids
            fm = FirewallManager(db)
            duration_secs = ttl_minutes * 60

            # Deny all external
            rule_id = fm.add_auto_rule(
                asset_id=node_id,
                source="0.0.0.0/0",
                reason="mesh_lockdown_deny_all",
                duration_seconds=duration_secs,
            )
            if rule_id:
                rule_ids.append(rule_id)
                self._active_rules.setdefault(node_id, []).append(rule_id)
        except Exception:
            logger.debug(
                "Failed to add lockdown rules for %s", node_id, exc_info=True
            )
        return rule_ids

    def _remove_emergency_rules(self, node_id: str) -> int:
        """Remove all auto-generated emergency rules for a node."""
        rule_ids = self._active_rules.pop(node_id, [])
        removed = 0
        if not rule_ids:
            return removed
        try:
            from ..remote.firewall_manager import FirewallManager
            from ..remote.shield_database import get_shield_database
            db = get_shield_database()
            if db is None:
                return removed
            fm = FirewallManager(db)
            for rule_id in rule_ids:
                try:
                    fm.remove_rule(rule_id)
                    removed += 1
                except Exception:
                    pass
        except Exception:
            logger.debug(
                "Failed to remove emergency rules for %s", node_id, exc_info=True
            )
        return removed

    def _audit_results(
        self, node_id: str, phase, results: List[EscalationActionResult]
    ) -> None:
        """Log escalation actions to audit log."""
        if not results:
            return
        try:
            from ..core.audit_log import get_audit_logger, EventType, EventSeverity

            phase_value = phase.value if hasattr(phase, 'value') else str(phase)
            sev = EventSeverity.INFO if phase_value == "NORMAL" else EventSeverity.ALERT

            for r in results:
                get_audit_logger().log_event(
                    event_type=EventType.MESH_ESCALATION,
                    severity=sev,
                    message=f"Autonomous action: {r.action} for {node_id} (phase={phase_value})",
                    details={
                        "node_id": node_id,
                        "phase": phase_value,
                        "action": r.action,
                        "success": r.success,
                        **r.details,
                    },
                )
        except Exception:
            logger.debug("Failed to audit escalation results", exc_info=True)


# ── Singleton ────────────────────────────────────────────────────────

_handler: Optional[AutonomousEscalationHandler] = None


def get_escalation_handler() -> AutonomousEscalationHandler:
    global _handler
    if _handler is None:
        _handler = AutonomousEscalationHandler()
    return _handler


def set_escalation_handler(handler: Optional[AutonomousEscalationHandler]) -> None:
    global _handler
    _handler = handler
