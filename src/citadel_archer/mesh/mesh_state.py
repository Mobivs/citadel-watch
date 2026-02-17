"""Defense Mesh state manager — peer tracking and escalation state machine.

v0.3.35: Each escalation phase carries a `model_tier` that controls which
AI model (if any) handles the escalation event:

    NORMAL     → None   (pure automation, zero tokens)
    ALERT      → haiku  (quick triage, ~$0.001)
    HEIGHTENED → sonnet (context analysis)
    AUTONOMOUS → opus   (critical decision-making)

Recovery transitions (back to NORMAL) consume zero tokens — just a log entry.
This ensures a stable mesh costs nothing, and even brief outages only touch
the cheapest model.
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional, Tuple

from .heartbeat_protocol import HeartbeatPacket

logger = logging.getLogger(__name__)


# ── Escalation Phases ────────────────────────────────────────────────


class EscalationPhase(str, Enum):
    """Mesh escalation phases with AI model tier graduation.

    The model_tier property controls cost: most heartbeat cycles consume
    zero tokens. AI is only invoked on phase *transitions*, not on every beat.
    """

    NORMAL = "NORMAL"          # All good — pure automation
    ALERT = "ALERT"            # 3 missed (~90s) — Haiku triage
    HEIGHTENED = "HEIGHTENED"  # 5 missed (~150s) — Sonnet analysis
    AUTONOMOUS = "AUTONOMOUS"  # 10 missed (~5min) — Opus decision

    @property
    def model_tier(self) -> Optional[str]:
        """AI model tier for this phase. None = no AI invocation."""
        return _MODEL_TIERS[self.value]


_MODEL_TIERS = {
    "NORMAL": None,
    "ALERT": "haiku",
    "HEIGHTENED": "sonnet",
    "AUTONOMOUS": "opus",
}


# ── Thresholds ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class EscalationThresholds:
    """Number of missed heartbeats before each phase transition."""

    alert_after: int = 3
    heightened_after: int = 5
    autonomous_after: int = 10


# ── Peer State ───────────────────────────────────────────────────────


@dataclass
class PeerState:
    """Tracked state for a single mesh peer."""

    node_id: str
    ip_address: str
    port: int = 9378
    last_seen: Optional[str] = None  # ISO 8601
    last_sequence: int = 0
    missed_count: int = 0
    escalation_phase: EscalationPhase = EscalationPhase.NORMAL
    registered_at: str = ""
    is_desktop: bool = False
    label: str = ""
    last_payload: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "ip_address": self.ip_address,
            "port": self.port,
            "last_seen": self.last_seen,
            "last_sequence": self.last_sequence,
            "missed_count": self.missed_count,
            "escalation_phase": self.escalation_phase.value,
            "model_tier": self.escalation_phase.model_tier,
            "registered_at": self.registered_at,
            "is_desktop": self.is_desktop,
            "label": self.label,
            "last_payload": self.last_payload,
        }


# ── State Manager ────────────────────────────────────────────────────


class MeshStateManager:
    """Thread-safe peer state tracker with escalation state machine.

    Follows the RLock pattern from GuardianUpdater for subscriber safety.
    """

    def __init__(self, thresholds: Optional[EscalationThresholds] = None):
        self._peers: Dict[str, PeerState] = {}
        self._lock = threading.RLock()
        self._thresholds = thresholds or EscalationThresholds()
        self._phase_callbacks: List[
            Callable[[str, EscalationPhase, EscalationPhase, PeerState], None]
        ] = []

    # ── Peer CRUD ────────────────────────────────────────────────────

    def register_peer(
        self,
        node_id: str,
        ip_address: str,
        port: int = 9378,
        is_desktop: bool = False,
        label: str = "",
    ) -> PeerState:
        with self._lock:
            now = datetime.now(timezone.utc).isoformat()
            peer = PeerState(
                node_id=node_id,
                ip_address=ip_address,
                port=port,
                is_desktop=is_desktop,
                label=label,
                registered_at=now,
            )
            self._peers[node_id] = peer
            return peer

    def remove_peer(self, node_id: str) -> bool:
        with self._lock:
            return self._peers.pop(node_id, None) is not None

    def get_peer(self, node_id: str) -> Optional[PeerState]:
        with self._lock:
            return self._peers.get(node_id)

    def all_peers(self) -> List[PeerState]:
        with self._lock:
            return list(self._peers.values())

    # ── Heartbeat Processing ─────────────────────────────────────────

    def record_heartbeat(self, packet: HeartbeatPacket) -> None:
        """Process an incoming heartbeat. Resets missed count and fires
        recovery callback if the peer was in an escalated phase.

        Callbacks are fired *outside* the lock to prevent deadlocks
        when callbacks call audit log or other locked subsystems.
        """
        pending_transition = None
        with self._lock:
            peer = self._peers.get(packet.node_id)
            if peer is None:
                return  # Unknown peer — ignore

            old_phase = peer.escalation_phase
            peer.last_seen = packet.timestamp
            peer.last_sequence = packet.sequence
            peer.last_payload = packet.payload or {}
            peer.missed_count = 0

            if old_phase != EscalationPhase.NORMAL:
                peer.escalation_phase = EscalationPhase.NORMAL
                pending_transition = (
                    packet.node_id, old_phase, EscalationPhase.NORMAL, peer
                )

        if pending_transition:
            self._fire_phase_change(*pending_transition)

    # ── Missed-Heartbeat Check ───────────────────────────────────────

    def check_missed(self, interval: int = 30) -> None:
        """Increment missed counts and transition escalation phases.

        Called periodically (every `interval` seconds) by the coordinator.
        Only increments if the peer has been seen at least once (last_seen is set),
        preventing false escalations on freshly registered peers.

        Transitions are collected under the lock, then callbacks are fired
        outside the lock to prevent deadlocks with external subsystems.
        """
        pending_transitions = []
        with self._lock:
            now_ts = time.time()
            for peer in self._peers.values():
                if peer.last_seen is None:
                    continue  # Never heard from — don't escalate

                # Parse last_seen to epoch
                try:
                    last = datetime.fromisoformat(peer.last_seen)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    elapsed = now_ts - last.timestamp()
                except (ValueError, TypeError):
                    continue

                # Only count a miss if elapsed > 1.5x interval
                threshold_secs = interval * 1.5
                expected_missed = int(elapsed / threshold_secs) if elapsed > threshold_secs else 0

                if expected_missed <= peer.missed_count:
                    continue  # No new misses

                old_phase = peer.escalation_phase
                peer.missed_count = expected_missed
                new_phase = self._compute_phase(peer.missed_count)

                if new_phase != old_phase:
                    peer.escalation_phase = new_phase
                    pending_transitions.append(
                        (peer.node_id, old_phase, new_phase, peer)
                    )

        for transition in pending_transitions:
            self._fire_phase_change(*transition)

    def _compute_phase(self, missed: int) -> EscalationPhase:
        t = self._thresholds
        if missed >= t.autonomous_after:
            return EscalationPhase.AUTONOMOUS
        if missed >= t.heightened_after:
            return EscalationPhase.HEIGHTENED
        if missed >= t.alert_after:
            return EscalationPhase.ALERT
        return EscalationPhase.NORMAL

    # ── Callbacks ────────────────────────────────────────────────────

    def on_phase_change(
        self,
        callback: Callable[[str, EscalationPhase, EscalationPhase, PeerState], None],
    ) -> None:
        """Register a subscriber for phase transitions.

        Callback signature: (node_id, old_phase, new_phase, peer_state)
        The new_phase.model_tier tells the caller which AI model to use.
        """
        with self._lock:
            self._phase_callbacks.append(callback)

    def _fire_phase_change(
        self,
        node_id: str,
        old_phase: EscalationPhase,
        new_phase: EscalationPhase,
        peer: PeerState,
    ) -> None:
        """Best-effort delivery to all subscribers."""
        for cb in self._phase_callbacks:
            try:
                cb(node_id, old_phase, new_phase, peer)
            except Exception:
                logger.debug(
                    "Phase change callback failed for %s", node_id, exc_info=True
                )

    # ── Summary ──────────────────────────────────────────────────────

    def mesh_summary(self) -> dict:
        """Aggregate peer counts by phase."""
        with self._lock:
            counts = {phase.value: 0 for phase in EscalationPhase}
            for peer in self._peers.values():
                counts[peer.escalation_phase.value] += 1
            return {
                "total_peers": len(self._peers),
                "by_phase": counts,
            }


# ── Coordinator ──────────────────────────────────────────────────────


class MeshCoordinator:
    """Top-level mesh lifecycle manager.

    Owns a HeartbeatSender, HeartbeatReceiver, and MeshStateManager.
    Single start()/stop() for the entire mesh subsystem.
    """

    def __init__(
        self,
        node_id: str = "desktop",
        port: int = 9378,
        interval: int = 30,
        bind_address: str = "0.0.0.0",
        thresholds: Optional[EscalationThresholds] = None,
        payload_callback: Optional[Callable[[], dict]] = None,
        psk: Optional[bytes] = None,
    ):
        from .heartbeat_protocol import HeartbeatSender, HeartbeatReceiver

        self.node_id = node_id
        self._interval = interval
        self._psk = psk

        self.state_manager = MeshStateManager(thresholds=thresholds)

        self._sender = HeartbeatSender(
            node_id=node_id,
            interval=interval,
            payload_callback=payload_callback,
            psk=psk,
        )
        self._receiver = HeartbeatReceiver(
            bind_address=bind_address,
            port=port,
            on_heartbeat=self._on_heartbeat,
            psk=psk,
        )

        self._check_stop = threading.Event()
        self._check_thread: Optional[threading.Thread] = None

    @property
    def is_running(self) -> bool:
        return (
            self._sender.is_running
            and self._receiver.is_running
            and self._check_thread is not None
            and self._check_thread.is_alive()
        )

    def start(self) -> None:
        self._receiver.start()
        self._sender.start()
        self._check_stop.clear()
        self._check_thread = threading.Thread(
            target=self._check_loop, name="mesh-check-missed", daemon=True
        )
        self._check_thread.start()

    def stop(self) -> None:
        self._check_stop.set()
        if self._check_thread is not None:
            self._check_thread.join(timeout=5)
            self._check_thread = None
        self._sender.stop()
        self._receiver.stop()

    def add_peer(
        self,
        node_id: str,
        ip_address: str,
        port: int = 9378,
        is_desktop: bool = False,
        label: str = "",
    ) -> PeerState:
        peer = self.state_manager.register_peer(
            node_id, ip_address, port, is_desktop, label
        )
        self._rebuild_sender_peers()
        return peer

    def remove_peer(self, node_id: str) -> bool:
        removed = self.state_manager.remove_peer(node_id)
        if removed:
            self._rebuild_sender_peers()
        return removed

    def update_interval(self, interval: int) -> None:
        self._interval = max(5, min(interval, 300))
        self._sender.update_interval(self._interval)

    def update_psk(self, psk: Optional[bytes]) -> None:
        """Rotate the pre-shared key on both sender and receiver."""
        self._psk = psk
        self._sender.update_psk(psk)
        self._receiver.update_psk(psk)

    @property
    def psk_fingerprint(self) -> Optional[str]:
        """Short fingerprint of the active PSK, or None if unsigned."""
        if self._psk is None:
            return None
        from .mesh_keys import get_psk_fingerprint
        return get_psk_fingerprint(self._psk)

    def on_phase_change(self, callback) -> None:
        self.state_manager.on_phase_change(callback)

    @property
    def interval(self) -> int:
        return self._interval

    @property
    def port(self) -> int:
        return self._receiver._port

    @property
    def receiver_stats(self) -> dict:
        return {
            "packets_received": self._receiver.packets_received,
            "packets_invalid": self._receiver.packets_invalid,
            "packets_rejected": self._receiver.packets_rejected,
        }

    def _on_heartbeat(self, packet: HeartbeatPacket, addr: Tuple[str, int]) -> None:
        self.state_manager.record_heartbeat(packet)

        # Persist heartbeat to database (best-effort, non-blocking)
        try:
            from .mesh_database import get_mesh_database
            db = get_mesh_database()
            db.log_heartbeat(
                node_id=packet.node_id,
                sequence=packet.sequence,
                payload=packet.payload,
            )
            db.update_peer_heartbeat(
                node_id=packet.node_id,
                escalation_phase="NORMAL",
            )
        except Exception:
            logger.debug(
                "Failed to persist heartbeat for %s", packet.node_id, exc_info=True
            )

    def _rebuild_sender_peers(self) -> None:
        peers = [
            (p.ip_address, p.port) for p in self.state_manager.all_peers()
        ]
        self._sender.update_peers(peers)

    def _check_loop(self) -> None:
        while not self._check_stop.is_set():
            self.state_manager.check_missed(interval=self._interval)
            self._check_stop.wait(self._interval)
