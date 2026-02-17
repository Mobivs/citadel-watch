"""Secondary brain designation — fallback VPS coordinator.

v0.3.39: When the desktop coordinator goes dark, a designated VPS peer
can assume coordination duties:
  - Receives a sanitized asset registry (no raw secrets)
  - Can run a lightweight AI Bridge for command-level decisions
  - Takes over event collection and strategic analysis
  - Relinquishes control when desktop comes back online

The secondary brain is **designated**, not elected — the desktop owner
explicitly chooses which VPS (if any) acts as fallback.

Zero AI tokens at NORMAL — the designation data structure is pure config.
AI is only invoked when the secondary brain actually activates.
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Brain State ─────────────────────────────────────────────────────


class BrainRole(str, Enum):
    """Role of a node in the coordination hierarchy."""

    PRIMARY = "primary"        # Desktop — full authority
    SECONDARY = "secondary"    # Designated fallback VPS
    AGENT = "agent"            # Regular shield agent (no coordination)


class BrainState(str, Enum):
    """Activation state of the secondary brain."""

    STANDBY = "standby"        # Desktop is online — secondary is dormant
    ACTIVATING = "activating"  # Desktop lost — secondary taking over
    ACTIVE = "active"          # Secondary is coordinating
    DEACTIVATING = "deactivating"  # Desktop returned — handing back
    DISABLED = "disabled"      # No secondary brain designated


# ── Designation Config ──────────────────────────────────────────────


@dataclass
class SecondaryBrainConfig:
    """Configuration for the secondary brain designation.

    Stored in mesh database and synced to the designated VPS.
    """

    node_id: str = ""                    # Which VPS is the secondary brain
    activation_threshold: int = 10       # Missed heartbeats before activation
    api_key_encrypted: str = ""          # Encrypted API key for AI Bridge
    rate_limit_rpm: int = 10             # Max AI requests per minute
    allowed_actions: List[str] = field(default_factory=lambda: [
        "lower_alert_threshold",
        "increase_polling_frequency",
        "queue_tighten_rules",
        "add_emergency_firewall_rules",
    ])
    denied_actions: List[str] = field(default_factory=lambda: [
        "rotate_credentials",     # Too dangerous for automated failover
        "kill_all_ssh_sessions",  # Could lock out legitimate users
    ])
    max_coordination_hours: int = 24     # Auto-deactivate after this long
    require_desktop_approval: bool = True  # Desktop reviews decisions on return

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "activation_threshold": self.activation_threshold,
            "api_key_configured": bool(self.api_key_encrypted),
            "rate_limit_rpm": self.rate_limit_rpm,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "max_coordination_hours": self.max_coordination_hours,
            "require_desktop_approval": self.require_desktop_approval,
        }


# ── Sanitized Asset Registry ────────────────────────────────────────


@dataclass
class SanitizedAsset:
    """Asset info shared with the secondary brain.

    Contains connection info but NO raw secrets (passwords, private keys).
    Only public keys and fingerprints for verification.
    """

    asset_id: str
    hostname: str
    ip_address: str
    port: int = 22
    agent_version: str = ""
    last_status: str = "unknown"
    public_key_fingerprint: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "port": self.port,
            "agent_version": self.agent_version,
            "last_status": self.last_status,
            "public_key_fingerprint": self.public_key_fingerprint,
            "tags": self.tags,
        }


# ── Coordination Decision Log ───────────────────────────────────────


@dataclass
class CoordinationDecision:
    """A decision made by the secondary brain while coordinating.

    Logged for desktop review on reconnection (recovery protocol).
    """

    decision_id: str
    timestamp: str = ""
    action: str = ""
    target_node_id: str = ""
    reason: str = ""
    parameters: Dict = field(default_factory=dict)
    outcome: str = "pending"  # pending, executed, failed, rolled_back
    reviewed: bool = False
    reviewed_by: str = ""     # "desktop" on reconciliation

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "target_node_id": self.target_node_id,
            "reason": self.reason,
            "parameters": self.parameters,
            "outcome": self.outcome,
            "reviewed": self.reviewed,
            "reviewed_by": self.reviewed_by,
        }


# ── Secondary Brain Manager ─────────────────────────────────────────


class SecondaryBrainManager:
    """Manages secondary brain designation, activation, and deactivation.

    Lifecycle:
    1. Desktop admin designates a VPS as secondary brain
    2. Sanitized asset registry is prepared and synced
    3. When desktop goes AUTONOMOUS (10+ missed heartbeats), the
       secondary brain enters ACTIVATING state
    4. On confirmation, it transitions to ACTIVE and begins coordination
    5. When desktop returns (heartbeat resumes), secondary enters
       DEACTIVATING → STANDBY
    6. Desktop reviews all decisions made during the outage
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._config = SecondaryBrainConfig()
        self._state = BrainState.DISABLED
        self._activated_at: Optional[str] = None
        self._deactivated_at: Optional[str] = None
        self._decision_log: List[CoordinationDecision] = []
        self._asset_registry: List[SanitizedAsset] = []
        self._max_decisions = 500

    # ── Configuration ─────────────────────────────────────────────

    def designate(self, config: SecondaryBrainConfig) -> None:
        """Designate a VPS as the secondary brain."""
        with self._lock:
            self._config = config
            if config.node_id:
                self._state = BrainState.STANDBY
            else:
                self._state = BrainState.DISABLED
            logger.info(
                "Secondary brain designated: %s (state: %s)",
                config.node_id or "none",
                self._state.value,
            )

    def remove_designation(self) -> None:
        """Remove secondary brain designation."""
        with self._lock:
            if self._state == BrainState.ACTIVE:
                logger.warning(
                    "Removing secondary brain designation while ACTIVE — "
                    "forcing deactivation"
                )
            self._config = SecondaryBrainConfig()
            self._state = BrainState.DISABLED
            self._activated_at = None

    def get_config(self) -> SecondaryBrainConfig:
        with self._lock:
            return self._config

    @property
    def state(self) -> BrainState:
        with self._lock:
            return self._state

    @property
    def designated_node_id(self) -> Optional[str]:
        with self._lock:
            return self._config.node_id if self._config.node_id else None

    def get_status(self) -> dict:
        """Full status snapshot."""
        with self._lock:
            return {
                "state": self._state.value,
                "config": self._config.to_dict(),
                "activated_at": self._activated_at,
                "deactivated_at": self._deactivated_at,
                "pending_decisions": sum(
                    1 for d in self._decision_log if not d.reviewed
                ),
                "total_decisions": len(self._decision_log),
                "asset_count": len(self._asset_registry),
            }

    # ── Asset Registry ────────────────────────────────────────────

    def update_asset_registry(self, assets: List[SanitizedAsset]) -> None:
        """Update the sanitized asset registry for the secondary brain."""
        with self._lock:
            self._asset_registry = list(assets)

    def get_asset_registry(self) -> List[dict]:
        """Get sanitized asset registry (no raw secrets)."""
        with self._lock:
            return [a.to_dict() for a in self._asset_registry]

    def sanitize_from_inventory(self, inventory) -> List[SanitizedAsset]:
        """Build sanitized asset list from the full AssetInventory.

        Strips all secrets — only includes connection info and public
        key fingerprints that the secondary brain needs for coordination.
        """
        assets = []
        try:
            for item in inventory.list_assets():
                asset = SanitizedAsset(
                    asset_id=item.get("asset_id", ""),
                    hostname=item.get("hostname", item.get("name", "")),
                    ip_address=item.get("ip_address", item.get("ip", "")),
                    port=item.get("port", 22),
                    agent_version=item.get("agent_version", ""),
                    last_status=item.get("status", "unknown"),
                    public_key_fingerprint=item.get(
                        "public_key_fingerprint", ""
                    ),
                    tags=item.get("tags", []),
                )
                assets.append(asset)
        except Exception:
            logger.debug("Failed to sanitize asset inventory", exc_info=True)
        return assets

    # ── Activation / Deactivation ─────────────────────────────────

    def handle_phase_change(
        self,
        node_id: str,
        old_phase,
        new_phase,
        peer_state,
    ) -> Optional[str]:
        """React to mesh escalation phase changes.

        Activates the secondary brain when the desktop peer enters
        AUTONOMOUS phase. Deactivates when it returns to NORMAL.

        Args:
            node_id: The peer whose phase changed.
            old_phase: Previous phase.
            new_phase: New phase.
            peer_state: The PeerState object.

        Returns:
            State transition description, or None if no change.
        """
        from .mesh_state import EscalationPhase

        with self._lock:
            if self._state == BrainState.DISABLED:
                return None

            # Only react to desktop peer going dark/returning
            if not (hasattr(peer_state, 'is_desktop') and peer_state.is_desktop):
                return None

            new_val = new_phase.value if hasattr(new_phase, 'value') else str(new_phase)

            # Desktop entered AUTONOMOUS → activate secondary brain
            if (
                new_phase == EscalationPhase.AUTONOMOUS
                and self._state == BrainState.STANDBY
            ):
                self._state = BrainState.ACTIVATING
                self._activated_at = datetime.now(timezone.utc).isoformat()
                logger.warning(
                    "Desktop peer AUTONOMOUS — activating secondary brain %s",
                    self._config.node_id,
                )
                # Transition to ACTIVE (in production, would confirm
                # the secondary VPS is reachable first)
                self._state = BrainState.ACTIVE
                return f"activated (desktop {new_val})"

            # Desktop returned to NORMAL → deactivate
            if (
                new_phase == EscalationPhase.NORMAL
                and self._state == BrainState.ACTIVE
            ):
                self._state = BrainState.DEACTIVATING
                self._deactivated_at = datetime.now(timezone.utc).isoformat()
                logger.info(
                    "Desktop peer recovered — deactivating secondary brain %s",
                    self._config.node_id,
                )
                self._state = BrainState.STANDBY
                return "deactivated (desktop recovered)"

        return None

    # ── Decision Logging ──────────────────────────────────────────

    def log_decision(self, decision: CoordinationDecision) -> None:
        """Log a coordination decision made by the secondary brain."""
        with self._lock:
            self._decision_log.append(decision)
            if len(self._decision_log) > self._max_decisions:
                self._decision_log = self._decision_log[-self._max_decisions:]

    def get_pending_decisions(self) -> List[dict]:
        """Get unreviewed decisions (for desktop reconciliation)."""
        with self._lock:
            return [
                d.to_dict()
                for d in self._decision_log
                if not d.reviewed
            ]

    def get_all_decisions(self, limit: int = 50) -> List[dict]:
        """Get recent decisions (newest first)."""
        with self._lock:
            return [
                d.to_dict()
                for d in reversed(self._decision_log[-limit:])
            ]

    def review_decision(
        self, decision_id: str, action: str = "accepted", reviewer: str = "desktop"
    ) -> bool:
        """Mark a decision as reviewed by the desktop.

        Args:
            decision_id: ID of the decision.
            action: "accepted" or "rolled_back".
            reviewer: Who reviewed (usually "desktop").

        Returns:
            True if the decision was found and updated.
        """
        with self._lock:
            for d in self._decision_log:
                if d.decision_id == decision_id:
                    d.reviewed = True
                    d.reviewed_by = reviewer
                    if action == "rolled_back":
                        d.outcome = "rolled_back"
                    return True
            return False

    def review_all_decisions(self, reviewer: str = "desktop") -> int:
        """Bulk-accept all pending decisions. Returns count."""
        with self._lock:
            count = 0
            for d in self._decision_log:
                if not d.reviewed:
                    d.reviewed = True
                    d.reviewed_by = reviewer
                    count += 1
            return count

    def is_action_allowed(self, action: str) -> bool:
        """Check if an action is permitted for the secondary brain."""
        with self._lock:
            if action in self._config.denied_actions:
                return False
            if self._config.allowed_actions:
                return action in self._config.allowed_actions
            return True


# ── Singleton ────────────────────────────────────────────────────────

_manager: Optional[SecondaryBrainManager] = None


def get_secondary_brain_manager() -> SecondaryBrainManager:
    global _manager
    if _manager is None:
        _manager = SecondaryBrainManager()
    return _manager


def set_secondary_brain_manager(m: Optional[SecondaryBrainManager]) -> None:
    global _manager
    _manager = m
