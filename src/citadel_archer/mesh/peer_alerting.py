"""Peer alerting — surviving nodes notify each other of failures.

v0.3.38: When the mesh detects a peer has gone silent (escalation to
ALERT or higher), the coordinator broadcasts an alert to all remaining
healthy peers.  This ensures every node in the mesh knows about the
failure even if it hasn't detected the silence itself (e.g., the
failing node only communicated with the coordinator).

Alert messages are carried as heartbeat payloads with a special
``mesh_alert`` key, keeping the protocol minimal — no new packet types,
just enriched payloads.

Zero AI tokens consumed — pure automation.
"""

import json
import logging
import socket
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Alert Types ──────────────────────────────────────────────────────


class AlertType:
    """Well-known peer alert types."""

    PEER_UNREACHABLE = "peer_unreachable"
    PEER_ESCALATED = "peer_escalated"
    PEER_RECOVERED = "peer_recovered"


# ── Alert Message ────────────────────────────────────────────────────


@dataclass
class PeerAlert:
    """An alert about a peer's status change."""

    alert_type: str
    subject_node_id: str  # The node the alert is about
    reporter_node_id: str  # The node reporting the alert
    phase: str
    previous_phase: str
    missed_count: int = 0
    timestamp: str = ""
    details: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "alert_type": self.alert_type,
            "subject_node_id": self.subject_node_id,
            "reporter_node_id": self.reporter_node_id,
            "phase": self.phase,
            "previous_phase": self.previous_phase,
            "missed_count": self.missed_count,
            "timestamp": self.timestamp,
            "details": self.details,
        }


# ── Alert Broadcaster ────────────────────────────────────────────────


class PeerAlertBroadcaster:
    """Broadcasts peer alerts to all surviving mesh nodes.

    Attaches to MeshCoordinator.on_phase_change() callback.
    Sends alert messages as UDP packets to all known peers that are
    NOT the subject of the alert.

    Uses the same UDP transport as heartbeats — lightweight and
    non-blocking.
    """

    def __init__(self, node_id: str, psk: Optional[bytes] = None):
        self._node_id = node_id
        self._psk = psk
        self._alert_log: List[PeerAlert] = []
        self._max_log_size = 100
        self._lock = threading.Lock()

    def update_psk(self, psk: Optional[bytes]) -> None:
        self._psk = psk

    def handle_phase_change(
        self,
        node_id: str,
        old_phase,
        new_phase,
        peer_state,
        all_peers: Optional[list] = None,
    ) -> Optional[PeerAlert]:
        """Create and broadcast a peer alert on phase transitions.

        Args:
            node_id: The node whose phase changed.
            old_phase: Previous escalation phase.
            new_phase: New escalation phase.
            peer_state: The PeerState object.
            all_peers: List of all PeerState objects (for broadcast targets).

        Returns:
            The PeerAlert created, or None if no alert was needed.
        """
        from .mesh_state import EscalationPhase

        old_val = old_phase.value if hasattr(old_phase, 'value') else str(old_phase)
        new_val = new_phase.value if hasattr(new_phase, 'value') else str(new_phase)

        if new_phase == EscalationPhase.NORMAL:
            alert_type = AlertType.PEER_RECOVERED
        elif new_phase in (EscalationPhase.HEIGHTENED, EscalationPhase.AUTONOMOUS):
            alert_type = AlertType.PEER_ESCALATED
        else:
            alert_type = AlertType.PEER_UNREACHABLE

        alert = PeerAlert(
            alert_type=alert_type,
            subject_node_id=node_id,
            reporter_node_id=self._node_id,
            phase=new_val,
            previous_phase=old_val,
            missed_count=peer_state.missed_count,
        )

        # Store in local log
        with self._lock:
            self._alert_log.append(alert)
            if len(self._alert_log) > self._max_log_size:
                self._alert_log = self._alert_log[-self._max_log_size:]

        # Broadcast to surviving peers
        if all_peers:
            self._broadcast(alert, all_peers, exclude_node=node_id)

        return alert

    def get_recent_alerts(self, limit: int = 20) -> List[dict]:
        """Return recent alerts (newest first)."""
        with self._lock:
            return [a.to_dict() for a in reversed(self._alert_log[-limit:])]

    def _broadcast(
        self,
        alert: PeerAlert,
        peers: list,
        exclude_node: Optional[str] = None,
    ) -> int:
        """Send alert to all peers except the subject.

        Encodes the alert as a special heartbeat packet with
        ``mesh_alert`` in the payload. Returns count of peers notified.
        """
        from .heartbeat_protocol import HeartbeatPacket

        packet = HeartbeatPacket(
            node_id=self._node_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=0,  # Alert packets use sequence 0
            payload={"mesh_alert": alert.to_dict()},
        )
        if self._psk:
            packet.sign(self._psk)

        data = packet.to_bytes()
        sent = 0
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for peer in peers:
                if hasattr(peer, 'node_id') and peer.node_id == exclude_node:
                    continue
                ip = peer.ip_address if hasattr(peer, 'ip_address') else str(peer)
                port = peer.port if hasattr(peer, 'port') else 9378
                try:
                    sock.sendto(data, (ip, port))
                    sent += 1
                except OSError:
                    pass
        except Exception:
            logger.debug("Alert broadcast failed", exc_info=True)
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

        return sent


# ── Singleton ────────────────────────────────────────────────────────

_broadcaster: Optional[PeerAlertBroadcaster] = None


def get_peer_alert_broadcaster() -> Optional[PeerAlertBroadcaster]:
    return _broadcaster


def set_peer_alert_broadcaster(b: Optional[PeerAlertBroadcaster]) -> None:
    global _broadcaster
    _broadcaster = b
