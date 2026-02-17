"""Defense Mesh heartbeat protocol — UDP packet format, sender, and receiver.

v0.3.36: HMAC-SHA256 signed heartbeats with pre-shared keys.
Packets are lightweight JSON over UDP, sent at configurable intervals.
When a PSK is configured, packets are signed on send and verified on receive.
Unsigned packets are accepted when no PSK is set (backwards-compatible).
Pure automation layer — zero AI tokens consumed here.
"""

import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────

MESH_VERSION = "1.0"
DEFAULT_PORT = 9378
DEFAULT_INTERVAL = 30  # seconds
MAX_PACKET_SIZE = 1024
SOCKET_TIMEOUT = 1.0  # recv timeout for clean shutdown loop


# ── Packet ───────────────────────────────────────────────────────────


@dataclass
class HeartbeatPacket:
    """A single mesh heartbeat packet.

    Lightweight JSON-serialized UDP datagram sent between mesh nodes.
    All fields are simple types for fast serialize/deserialize.
    """

    node_id: str
    timestamp: str  # ISO 8601 UTC
    sequence: int
    mesh_version: str = MESH_VERSION
    signature: str = ""  # HMAC-SHA256 hex; empty when PSK not configured
    payload: Dict = field(default_factory=dict)

    def sign(self, psk: bytes) -> None:
        """Sign this packet in-place using HMAC-SHA256 with the given PSK."""
        from .mesh_keys import sign_packet
        self.signature = sign_packet(self.to_dict(), psk)

    def verify(self, psk: bytes) -> bool:
        """Verify this packet's signature. Returns True if valid."""
        from .mesh_keys import verify_signature
        return verify_signature(self.to_dict(), self.signature, psk)

    def to_bytes(self) -> bytes:
        """Serialize to JSON bytes for UDP transmission."""
        return json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "HeartbeatPacket":
        """Deserialize from JSON bytes. Raises ValueError on bad data."""
        try:
            obj = json.loads(data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid heartbeat packet: {exc}") from exc

        required = {"node_id", "timestamp", "sequence"}
        missing = required - set(obj.keys())
        if missing:
            raise ValueError(f"Missing required fields: {missing}")

        return cls(
            node_id=str(obj["node_id"]),
            timestamp=str(obj["timestamp"]),
            sequence=int(obj["sequence"]),
            mesh_version=str(obj.get("mesh_version", MESH_VERSION)),
            signature=str(obj.get("signature", "")),
            payload=obj.get("payload") or {},
        )

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "timestamp": self.timestamp,
            "sequence": self.sequence,
            "mesh_version": self.mesh_version,
            "signature": self.signature,
            "payload": self.payload,
        }


# ── Sender ───────────────────────────────────────────────────────────


class HeartbeatSender:
    """Background daemon thread that sends UDP heartbeats to configured peers.

    Uses threading.Event.wait(interval) for interruptible sleep,
    matching the pattern in desktop.py._start_heartbeat_watchdog().
    """

    def __init__(
        self,
        node_id: str,
        peers: Optional[List[Tuple[str, int]]] = None,
        interval: int = DEFAULT_INTERVAL,
        payload_callback: Optional[Callable[[], dict]] = None,
        psk: Optional[bytes] = None,
    ):
        self.node_id = node_id
        self._peers: List[Tuple[str, int]] = list(peers or [])
        self._interval = interval
        self._payload_callback = payload_callback
        self._psk = psk  # Pre-shared key for HMAC signing (None = unsigned)
        self._psk_lock = threading.Lock()

        self._sequence = 0
        self._seq_lock = threading.Lock()
        self._peers_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_event.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._thread = threading.Thread(
            target=self._run, name="mesh-heartbeat-sender", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def update_peers(self, peers: List[Tuple[str, int]]) -> None:
        with self._peers_lock:
            self._peers = list(peers)

    def update_psk(self, psk: Optional[bytes]) -> None:
        with self._psk_lock:
            self._psk = psk

    def update_interval(self, interval: int) -> None:
        self._interval = max(5, min(interval, 300))

    def _next_sequence(self) -> int:
        with self._seq_lock:
            self._sequence += 1
            return self._sequence

    def _run(self) -> None:
        while not self._stop_event.is_set():
            self._send_one()
            self._stop_event.wait(self._interval)

    def _send_one(self) -> None:
        """Build packet and send to all peers. Per-peer failures are non-fatal."""
        payload = {}
        if self._payload_callback:
            try:
                payload = self._payload_callback() or {}
            except Exception:
                pass  # best-effort payload

        # Snapshot PSK under lock to avoid TOCTOU with update_psk()
        with self._psk_lock:
            current_psk = self._psk

        packet = HeartbeatPacket(
            node_id=self.node_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            sequence=self._next_sequence(),
            payload=payload,
        )
        if current_psk:
            packet.sign(current_psk)
        data = packet.to_bytes()

        with self._peers_lock:
            peers_snapshot = list(self._peers)

        for host, port in peers_snapshot:
            try:
                self._sock.sendto(data, (host, port))
            except OSError as exc:
                logger.debug("Mesh send failed to %s:%d: %s", host, port, exc)


# ── Receiver ─────────────────────────────────────────────────────────


class HeartbeatReceiver:
    """Background daemon thread that listens for UDP heartbeat packets.

    Calls on_heartbeat(packet, addr) for every valid packet received.
    Invalid packets are counted but silently dropped.
    """

    def __init__(
        self,
        bind_address: str = "0.0.0.0",
        port: int = DEFAULT_PORT,
        on_heartbeat: Optional[Callable[[HeartbeatPacket, Tuple[str, int]], None]] = None,
        psk: Optional[bytes] = None,
    ):
        self._bind_address = bind_address
        self._port = port
        self._on_heartbeat = on_heartbeat
        self._psk = psk  # Pre-shared key for HMAC verification (None = accept unsigned)
        self._psk_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

        # Stats (thread-safe — written on receiver thread, read from API thread)
        self._stats_lock = threading.Lock()
        self._packets_received = 0
        self._packets_invalid = 0
        self._packets_rejected = 0  # Failed HMAC verification

    @property
    def packets_received(self) -> int:
        with self._stats_lock:
            return self._packets_received

    @property
    def packets_invalid(self) -> int:
        with self._stats_lock:
            return self._packets_invalid

    @property
    def packets_rejected(self) -> int:
        with self._stats_lock:
            return self._packets_rejected

    def update_psk(self, psk: Optional[bytes]) -> None:
        with self._psk_lock:
            self._psk = psk

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def bound_port(self) -> Optional[int]:
        """Actual port bound (useful when port=0 for ephemeral)."""
        if self._sock is not None:
            try:
                return self._sock.getsockname()[1]
            except OSError:
                pass
        return None

    def start(self) -> None:
        if self.is_running:
            return
        self._stop_event.clear()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._bind_address, self._port))
        self._sock.settimeout(SOCKET_TIMEOUT)
        self._thread = threading.Thread(
            target=self._run, name="mesh-heartbeat-receiver", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(MAX_PACKET_SIZE)
            except socket.timeout:
                continue
            except OSError:
                if self._stop_event.is_set():
                    break
                continue

            try:
                packet = HeartbeatPacket.from_bytes(data)
            except (ValueError, KeyError):
                with self._stats_lock:
                    self._packets_invalid += 1
                continue

            # Snapshot PSK under lock to avoid TOCTOU with update_psk()
            with self._psk_lock:
                current_psk = self._psk

            # HMAC verification: if PSK is set, reject unsigned/bad-sig packets
            if current_psk:
                if not packet.signature or not packet.verify(current_psk):
                    with self._stats_lock:
                        self._packets_rejected += 1
                    continue

            with self._stats_lock:
                self._packets_received += 1

            if self._on_heartbeat:
                try:
                    self._on_heartbeat(packet, addr)
                except Exception:
                    pass  # callback exceptions are non-fatal
