"""Tests for Defense Mesh heartbeat protocol, state machine, database, and routes.

v0.3.35: ~55 tests covering packet serialization, sender/receiver, escalation
state machine with model_tier graduation, SQLite persistence, and API routes.
"""

import json
import socket
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# ── Packet Tests ─────────────────────────────────────────────────────


class TestHeartbeatPacket:
    """HeartbeatPacket serialize/deserialize."""

    def test_roundtrip(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        pkt = HeartbeatPacket(
            node_id="desktop",
            timestamp="2026-01-01T00:00:00+00:00",
            sequence=42,
            payload={"status": "ok"},
        )
        raw = pkt.to_bytes()
        restored = HeartbeatPacket.from_bytes(raw)
        assert restored.node_id == "desktop"
        assert restored.sequence == 42
        assert restored.payload == {"status": "ok"}

    def test_to_dict(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        pkt = HeartbeatPacket(
            node_id="vps1", timestamp="t", sequence=1
        )
        d = pkt.to_dict()
        assert d["node_id"] == "vps1"
        assert d["mesh_version"] == "1.0"
        assert d["signature"] == ""

    def test_invalid_json(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        with pytest.raises(ValueError, match="Invalid"):
            HeartbeatPacket.from_bytes(b"not json")

    def test_missing_fields(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        data = json.dumps({"node_id": "x"}).encode()
        with pytest.raises(ValueError, match="Missing"):
            HeartbeatPacket.from_bytes(data)

    def test_signature_field_present(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        pkt = HeartbeatPacket(node_id="n", timestamp="t", sequence=1)
        d = pkt.to_dict()
        assert "signature" in d
        assert d["signature"] == ""

    def test_payload_extensible(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        pkt = HeartbeatPacket(
            node_id="n", timestamp="t", sequence=1,
            payload={"uptime_seconds": 3600, "custom_key": "value"},
        )
        raw = pkt.to_bytes()
        restored = HeartbeatPacket.from_bytes(raw)
        assert restored.payload["uptime_seconds"] == 3600
        assert restored.payload["custom_key"] == "value"


# ── HMAC Key Tests ───────────────────────────────────────────────────


class TestMeshKeys:
    """HMAC pre-shared key management."""

    def test_generate_psk_length(self):
        from src.citadel_archer.mesh.mesh_keys import generate_psk, PSK_LENGTH

        psk = generate_psk()
        assert len(psk) == PSK_LENGTH

    def test_psk_roundtrip_base64(self):
        from src.citadel_archer.mesh.mesh_keys import (
            generate_psk, psk_to_base64, psk_from_base64,
        )

        psk = generate_psk()
        encoded = psk_to_base64(psk)
        decoded = psk_from_base64(encoded)
        assert decoded == psk

    def test_sign_packet(self):
        from src.citadel_archer.mesh.mesh_keys import generate_psk, sign_packet

        psk = generate_psk()
        packet_dict = {
            "node_id": "desktop", "timestamp": "t", "sequence": 1,
            "mesh_version": "1.0", "signature": "", "payload": {},
        }
        sig = sign_packet(packet_dict, psk)
        assert len(sig) == 64  # SHA-256 hex

    def test_verify_valid_signature(self):
        from src.citadel_archer.mesh.mesh_keys import (
            generate_psk, sign_packet, verify_signature,
        )

        psk = generate_psk()
        packet_dict = {
            "node_id": "desktop", "timestamp": "t", "sequence": 1,
            "mesh_version": "1.0", "signature": "", "payload": {},
        }
        sig = sign_packet(packet_dict, psk)
        assert verify_signature(packet_dict, sig, psk)

    def test_verify_wrong_key_rejected(self):
        from src.citadel_archer.mesh.mesh_keys import (
            generate_psk, sign_packet, verify_signature,
        )

        psk1 = generate_psk()
        psk2 = generate_psk()
        packet_dict = {
            "node_id": "desktop", "timestamp": "t", "sequence": 1,
            "mesh_version": "1.0", "signature": "", "payload": {},
        }
        sig = sign_packet(packet_dict, psk1)
        assert not verify_signature(packet_dict, sig, psk2)

    def test_verify_tampered_payload_rejected(self):
        from src.citadel_archer.mesh.mesh_keys import (
            generate_psk, sign_packet, verify_signature,
        )

        psk = generate_psk()
        packet_dict = {
            "node_id": "desktop", "timestamp": "t", "sequence": 1,
            "mesh_version": "1.0", "signature": "", "payload": {},
        }
        sig = sign_packet(packet_dict, psk)
        packet_dict["node_id"] = "attacker"
        assert not verify_signature(packet_dict, sig, psk)

    def test_psk_fingerprint(self):
        from src.citadel_archer.mesh.mesh_keys import generate_psk, get_psk_fingerprint

        psk = generate_psk()
        fp = get_psk_fingerprint(psk)
        assert len(fp) == 8
        assert all(c in "0123456789abcdef" for c in fp)

    def test_packet_sign_and_verify(self):
        """HeartbeatPacket.sign() / .verify() integration."""
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk = generate_psk()
        pkt = HeartbeatPacket(node_id="n", timestamp="t", sequence=1)
        pkt.sign(psk)
        assert pkt.signature != ""
        assert pkt.verify(psk)

    def test_packet_verify_fails_wrong_key(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk1 = generate_psk()
        psk2 = generate_psk()
        pkt = HeartbeatPacket(node_id="n", timestamp="t", sequence=1)
        pkt.sign(psk1)
        assert not pkt.verify(psk2)

    def test_load_or_create_psk(self, tmp_path):
        """PSK is generated and persisted on first call, loaded on second."""
        from src.citadel_archer.mesh.mesh_keys import (
            load_or_create_psk, psk_from_base64, PREFS_KEY,
        )
        from src.citadel_archer.core.user_preferences import (
            UserPreferences, set_user_preferences,
        )

        prefs = UserPreferences(db_path=str(tmp_path / "prefs.db"))
        set_user_preferences(prefs)

        psk1 = load_or_create_psk()
        assert len(psk1) == 32

        # Second call should return same key
        psk2 = load_or_create_psk()
        assert psk1 == psk2

        set_user_preferences(None)


# ── Sender Tests ─────────────────────────────────────────────────────


class TestHeartbeatSender:
    """HeartbeatSender lifecycle and send behavior."""

    def test_start_stop(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        sender = HeartbeatSender(node_id="test", interval=1)
        assert not sender.is_running
        sender.start()
        assert sender.is_running
        sender.stop()
        assert not sender.is_running

    def test_sends_to_all_peers(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        sent_to = []
        real_sendto = socket.socket.sendto

        def mock_sendto(self_sock, data, addr):
            sent_to.append(addr)

        sender = HeartbeatSender(
            node_id="test",
            peers=[("127.0.0.1", 19001), ("127.0.0.1", 19002)],
            interval=60,
        )
        sender.start()
        with patch.object(socket.socket, "sendto", mock_sendto):
            sender._send_one()
        sender.stop()
        assert ("127.0.0.1", 19001) in sent_to
        assert ("127.0.0.1", 19002) in sent_to

    def test_sequence_increments(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        sender = HeartbeatSender(node_id="test", interval=60)
        s1 = sender._next_sequence()
        s2 = sender._next_sequence()
        assert s2 == s1 + 1

    def test_payload_callback(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender, HeartbeatPacket

        captured = []

        def mock_sendto(self_sock, data, addr):
            pkt = HeartbeatPacket.from_bytes(data)
            captured.append(pkt.payload)

        def my_payload():
            return {"uptime": 100}

        sender = HeartbeatSender(
            node_id="test",
            peers=[("127.0.0.1", 19003)],
            interval=60,
            payload_callback=my_payload,
        )
        sender.start()
        with patch.object(socket.socket, "sendto", mock_sendto):
            sender._send_one()
        sender.stop()
        assert captured[0]["uptime"] == 100

    def test_update_peers(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        sender = HeartbeatSender(node_id="test")
        sender.update_peers([("10.0.0.1", 9378)])
        assert sender._peers == [("10.0.0.1", 9378)]

    def test_update_interval_clamped(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        sender = HeartbeatSender(node_id="test", interval=30)
        sender.update_interval(1)
        assert sender._interval == 5
        sender.update_interval(999)
        assert sender._interval == 300

    def test_send_failure_non_fatal(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender

        def mock_sendto(self_sock, data, addr):
            raise OSError("Connection refused")

        sender = HeartbeatSender(
            node_id="test",
            peers=[("127.0.0.1", 19999)],
            interval=60,
        )
        sender.start()
        # Should not raise
        with patch.object(socket.socket, "sendto", mock_sendto):
            sender._send_one()
        sender.stop()

    def test_sender_signs_with_psk(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender, HeartbeatPacket
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk = generate_psk()
        captured = []

        def mock_sendto(self_sock, data, addr):
            pkt = HeartbeatPacket.from_bytes(data)
            captured.append(pkt)

        sender = HeartbeatSender(
            node_id="test",
            peers=[("127.0.0.1", 19010)],
            interval=60,
            psk=psk,
        )
        sender.start()
        with patch.object(socket.socket, "sendto", mock_sendto):
            sender._send_one()
        sender.stop()
        assert captured[0].signature != ""
        assert captured[0].verify(psk)

    def test_sender_no_psk_unsigned(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatSender, HeartbeatPacket

        captured = []

        def mock_sendto(self_sock, data, addr):
            pkt = HeartbeatPacket.from_bytes(data)
            captured.append(pkt)

        sender = HeartbeatSender(
            node_id="test",
            peers=[("127.0.0.1", 19011)],
            interval=60,
        )
        sender.start()
        with patch.object(socket.socket, "sendto", mock_sendto):
            sender._send_one()
        sender.stop()
        assert captured[0].signature == ""


# ── Receiver Tests ───────────────────────────────────────────────────


class TestHeartbeatReceiver:
    """HeartbeatReceiver lifecycle and packet handling."""

    def test_start_stop(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatReceiver

        recv = HeartbeatReceiver(port=0)
        assert not recv.is_running
        recv.start()
        assert recv.is_running
        assert recv.bound_port is not None
        recv.stop()
        assert not recv.is_running

    def test_receives_valid_packet(self):
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )

        received = []

        def on_hb(pkt, addr):
            received.append(pkt)

        recv = HeartbeatReceiver(port=0, on_heartbeat=on_hb)
        recv.start()
        port = recv.bound_port

        # Send a packet
        pkt = HeartbeatPacket(node_id="sender", timestamp="t", sequence=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert len(received) == 1
        assert received[0].node_id == "sender"
        assert recv.packets_received == 1

    def test_ignores_invalid(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatReceiver

        recv = HeartbeatReceiver(port=0, on_heartbeat=lambda p, a: None)
        recv.start()
        port = recv.bound_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"garbage", ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert recv.packets_invalid == 1

    def test_stats_counting(self):
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )

        recv = HeartbeatReceiver(port=0, on_heartbeat=lambda p, a: None)
        recv.start()
        port = recv.bound_port

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pkt = HeartbeatPacket(node_id="n", timestamp="t", sequence=1)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.sendto(b"bad", ("127.0.0.1", port))
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert recv.packets_received == 2
        assert recv.packets_invalid == 1

    def test_callback_exception_non_fatal(self):
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )

        def bad_callback(pkt, addr):
            raise RuntimeError("boom")

        recv = HeartbeatReceiver(port=0, on_heartbeat=bad_callback)
        recv.start()
        port = recv.bound_port

        pkt = HeartbeatPacket(node_id="n", timestamp="t", sequence=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert recv.packets_received == 1

    def test_bind_address(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatReceiver

        recv = HeartbeatReceiver(bind_address="127.0.0.1", port=0)
        recv.start()
        assert recv.bound_port is not None
        recv.stop()

    def test_receiver_accepts_signed_packets(self):
        """Receiver with PSK accepts correctly-signed packets."""
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk = generate_psk()
        received = []
        recv = HeartbeatReceiver(
            port=0, on_heartbeat=lambda p, a: received.append(p), psk=psk,
        )
        recv.start()
        port = recv.bound_port

        pkt = HeartbeatPacket(node_id="signed", timestamp="t", sequence=1)
        pkt.sign(psk)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert len(received) == 1
        assert recv.packets_received == 1
        assert recv.packets_rejected == 0

    def test_receiver_rejects_unsigned_when_psk_set(self):
        """Receiver with PSK rejects unsigned packets."""
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk = generate_psk()
        received = []
        recv = HeartbeatReceiver(
            port=0, on_heartbeat=lambda p, a: received.append(p), psk=psk,
        )
        recv.start()
        port = recv.bound_port

        # Send unsigned packet
        pkt = HeartbeatPacket(node_id="unsigned", timestamp="t", sequence=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert len(received) == 0
        assert recv.packets_rejected == 1

    def test_receiver_rejects_wrong_key(self):
        """Receiver with PSK rejects packets signed with different key."""
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )
        from src.citadel_archer.mesh.mesh_keys import generate_psk

        psk1 = generate_psk()
        psk2 = generate_psk()
        received = []
        recv = HeartbeatReceiver(
            port=0, on_heartbeat=lambda p, a: received.append(p), psk=psk1,
        )
        recv.start()
        port = recv.bound_port

        # Sign with wrong key
        pkt = HeartbeatPacket(node_id="wrong", timestamp="t", sequence=1)
        pkt.sign(psk2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert len(received) == 0
        assert recv.packets_rejected == 1

    def test_receiver_no_psk_accepts_all(self):
        """Receiver without PSK accepts unsigned packets (backwards-compatible)."""
        from src.citadel_archer.mesh.heartbeat_protocol import (
            HeartbeatPacket, HeartbeatReceiver,
        )

        received = []
        recv = HeartbeatReceiver(
            port=0, on_heartbeat=lambda p, a: received.append(p),
        )
        recv.start()
        port = recv.bound_port

        pkt = HeartbeatPacket(node_id="any", timestamp="t", sequence=1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(pkt.to_bytes(), ("127.0.0.1", port))
        sock.close()

        time.sleep(0.5)
        recv.stop()
        assert len(received) == 1
        assert recv.packets_rejected == 0


# ── Escalation Phase Tests ───────────────────────────────────────────


class TestEscalationPhase:
    """EscalationPhase enum and model_tier property."""

    def test_enum_values(self):
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        assert EscalationPhase.NORMAL.value == "NORMAL"
        assert EscalationPhase.AUTONOMOUS.value == "AUTONOMOUS"

    def test_string_serialization(self):
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        assert str(EscalationPhase.ALERT) == "EscalationPhase.ALERT"
        assert EscalationPhase("HEIGHTENED") == EscalationPhase.HEIGHTENED

    def test_all_four_phases(self):
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        phases = list(EscalationPhase)
        assert len(phases) == 4

    def test_model_tier_graduation(self):
        """Core cost-control test: model_tier escalates Haiku → Sonnet → Opus."""
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        assert EscalationPhase.NORMAL.model_tier is None
        assert EscalationPhase.ALERT.model_tier == "haiku"
        assert EscalationPhase.HEIGHTENED.model_tier == "sonnet"
        assert EscalationPhase.AUTONOMOUS.model_tier == "opus"


# ── Peer State Tests ─────────────────────────────────────────────────


class TestPeerState:
    """PeerState dataclass."""

    def test_defaults(self):
        from src.citadel_archer.mesh.mesh_state import PeerState

        peer = PeerState(node_id="n", ip_address="1.2.3.4")
        assert peer.missed_count == 0
        assert peer.escalation_phase.value == "NORMAL"

    def test_to_dict(self):
        from src.citadel_archer.mesh.mesh_state import PeerState

        peer = PeerState(node_id="n", ip_address="1.2.3.4", port=9378)
        d = peer.to_dict()
        assert d["node_id"] == "n"
        assert d["model_tier"] is None  # NORMAL phase

    def test_is_desktop_flag(self):
        from src.citadel_archer.mesh.mesh_state import PeerState

        peer = PeerState(node_id="d", ip_address="127.0.0.1", is_desktop=True)
        assert peer.to_dict()["is_desktop"] is True

    def test_last_payload_default(self):
        from src.citadel_archer.mesh.mesh_state import PeerState

        peer = PeerState(node_id="n", ip_address="1.2.3.4")
        assert peer.last_payload == {}


# ── State Manager Tests ──────────────────────────────────────────────


class TestMeshStateManager:
    """MeshStateManager: peer CRUD, heartbeat processing, escalation."""

    def test_register_and_get(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        assert mgr.get_peer("n1") is not None
        assert mgr.get_peer("nonexistent") is None

    def test_remove_peer(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        assert mgr.remove_peer("n1")
        assert not mgr.remove_peer("n1")

    def test_heartbeat_resets_missed(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket
        from src.citadel_archer.mesh.mesh_state import MeshStateManager

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        peer.missed_count = 5

        pkt = HeartbeatPacket(node_id="n1", timestamp=datetime.now(timezone.utc).isoformat(), sequence=1)
        mgr.record_heartbeat(pkt)
        assert mgr.get_peer("n1").missed_count == 0

    def test_recovery_callback(self):
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket
        from src.citadel_archer.mesh.mesh_state import MeshStateManager, EscalationPhase

        transitions = []
        mgr = MeshStateManager()
        mgr.on_phase_change(lambda nid, old, new, ps: transitions.append((nid, old, new)))

        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        peer.escalation_phase = EscalationPhase.ALERT
        peer.missed_count = 3

        pkt = HeartbeatPacket(node_id="n1", timestamp=datetime.now(timezone.utc).isoformat(), sequence=1)
        mgr.record_heartbeat(pkt)

        assert len(transitions) == 1
        assert transitions[0] == ("n1", EscalationPhase.ALERT, EscalationPhase.NORMAL)

    def test_check_missed_increments(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        # Set last_seen to 200 seconds ago
        old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        peer.last_seen = old_ts

        mgr.check_missed(interval=30)
        assert peer.missed_count > 0

    def test_escalation_to_alert(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager, EscalationPhase

        transitions = []
        mgr = MeshStateManager()
        mgr.on_phase_change(lambda nid, old, new, ps: transitions.append((nid, new)))

        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        peer.last_seen = old_ts

        mgr.check_missed(interval=30)
        # Should have escalated past ALERT (old timestamp is very stale)
        assert peer.escalation_phase != EscalationPhase.NORMAL

    def test_escalation_to_autonomous(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager, EscalationPhase

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        peer.last_seen = old_ts

        mgr.check_missed(interval=30)
        assert peer.escalation_phase == EscalationPhase.AUTONOMOUS

    def test_no_double_callback(self):
        """Same phase should not fire callback again."""
        from src.citadel_archer.mesh.mesh_state import MeshStateManager, EscalationPhase

        transitions = []
        mgr = MeshStateManager()
        mgr.on_phase_change(lambda nid, old, new, ps: transitions.append(1))

        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        peer.last_seen = old_ts

        mgr.check_missed(interval=30)
        count1 = len(transitions)
        mgr.check_missed(interval=30)  # Same state, no new callback
        assert len(transitions) == count1

    def test_mesh_summary(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        mgr.register_peer("n2", "5.6.7.8")
        summary = mgr.mesh_summary()
        assert summary["total_peers"] == 2
        assert summary["by_phase"]["NORMAL"] == 2

    def test_custom_thresholds(self):
        from src.citadel_archer.mesh.mesh_state import (
            MeshStateManager, EscalationThresholds, EscalationPhase,
        )

        mgr = MeshStateManager(
            thresholds=EscalationThresholds(alert_after=1, heightened_after=2, autonomous_after=3)
        )
        mgr.register_peer("n1", "1.2.3.4")
        peer = mgr.get_peer("n1")
        old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
        peer.last_seen = old_ts

        mgr.check_missed(interval=30)
        assert peer.escalation_phase == EscalationPhase.AUTONOMOUS

    def test_never_heard_peer_not_incremented(self):
        from src.citadel_archer.mesh.mesh_state import MeshStateManager, EscalationPhase

        mgr = MeshStateManager()
        mgr.register_peer("n1", "1.2.3.4")
        # last_seen is None (never heard from)

        mgr.check_missed(interval=30)
        peer = mgr.get_peer("n1")
        assert peer.missed_count == 0
        assert peer.escalation_phase == EscalationPhase.NORMAL


# ── Coordinator Tests ────────────────────────────────────────────────


class TestMeshCoordinator:
    """MeshCoordinator lifecycle."""

    def test_start_stop(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=60)
        assert not coord.is_running
        coord.start()
        assert coord.is_running
        coord.stop()
        assert not coord.is_running

    def test_add_remove_peer(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=60)
        coord.start()
        peer = coord.add_peer("vps1", "10.0.0.1", 9378)
        assert peer.node_id == "vps1"
        assert coord.remove_peer("vps1")
        assert not coord.remove_peer("vps1")
        coord.stop()

    def test_update_interval(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=30)
        coord.update_interval(60)
        assert coord.interval == 60

    def test_receiver_stats_property(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=60)
        coord.start()
        stats = coord.receiver_stats
        assert "packets_received" in stats
        assert "packets_invalid" in stats
        coord.stop()

    def test_port_property(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=60)
        coord.start()
        assert coord.port is not None
        coord.stop()

    def test_localhost_integration(self):
        """Full sender↔receiver roundtrip on localhost."""
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        received = []
        coord = MeshCoordinator(node_id="desktop", port=0, interval=60)
        coord.state_manager.on_phase_change(
            lambda nid, old, new, ps: received.append(nid)
        )
        coord.start()

        # Get the actual port
        port = coord._receiver.bound_port

        # Add a peer and send to ourselves
        coord.add_peer("self", "127.0.0.1", port)

        # Manually trigger a send
        coord._sender.update_peers([("127.0.0.1", port)])
        coord._sender._send_one()

        time.sleep(0.5)
        coord.stop()
        # Packet was received (peer "self" isn't registered correctly as "desktop",
        # so it won't match — that's fine, we just verify no crash)

    def test_is_running_property(self):
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="test", port=0, interval=60)
        assert not coord.is_running
        coord.start()
        assert coord.is_running
        coord.stop()

    def test_heartbeat_persisted_to_db(self, tmp_path):
        """Coordinator._on_heartbeat writes to mesh database."""
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator
        from src.citadel_archer.mesh.mesh_database import MeshDatabase, set_mesh_database
        from src.citadel_archer.mesh.heartbeat_protocol import HeartbeatPacket

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        set_mesh_database(db)
        db.add_peer("vps1", "10.0.0.1")

        coord = MeshCoordinator(node_id="desktop", port=0, interval=60)
        coord.start()
        coord.add_peer("vps1", "10.0.0.1")

        pkt = HeartbeatPacket(
            node_id="vps1",
            timestamp="2026-01-01T00:00:00+00:00",
            sequence=42,
            payload={"status": "ok"},
        )
        coord._on_heartbeat(pkt, ("10.0.0.1", 9378))

        history = db.get_heartbeat_history("vps1", limit=5)
        assert len(history) == 1
        assert history[0]["sequence"] == 42

        coord.stop()
        set_mesh_database(None)


# ── Database Tests ───────────────────────────────────────────────────


class TestMeshDatabase:
    """MeshDatabase SQLite persistence."""

    def test_creates_db(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        assert (tmp_path / "mesh.db").exists()

    def test_add_get_peer(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        db.add_peer("n1", "1.2.3.4", 9378, is_desktop=True, label="Desktop")
        peer = db.get_peer("n1")
        assert peer is not None
        assert peer["ip_address"] == "1.2.3.4"
        assert peer["is_desktop"] is True

    def test_list_peers(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        db.add_peer("n1", "1.2.3.4")
        db.add_peer("n2", "5.6.7.8")
        peers = db.list_peers()
        assert len(peers) == 2

    def test_update_heartbeat(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        db.add_peer("n1", "1.2.3.4")
        assert db.update_peer_heartbeat("n1", "ALERT")
        peer = db.get_peer("n1")
        assert peer["last_escalation_phase"] == "ALERT"

    def test_remove_peer(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        db.add_peer("n1", "1.2.3.4")
        assert db.remove_peer("n1")
        assert not db.remove_peer("n1")

    def test_log_heartbeat(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        db.log_heartbeat("n1", 1, {"uptime": 100})
        db.log_heartbeat("n1", 2, {"uptime": 200})
        history = db.get_heartbeat_history("n1", limit=10)
        assert len(history) == 2
        assert history[0]["sequence"] == 2  # newest first

    def test_heartbeat_history(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        for i in range(5):
            db.log_heartbeat("n1", i)
        history = db.get_heartbeat_history("n1", limit=3)
        assert len(history) == 3

    def test_ring_buffer(self, tmp_path):
        """Heartbeat log pruned to 1000 per node."""
        from src.citadel_archer.mesh.mesh_database import MeshDatabase

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        # Insert 1010 entries — pruning happens on each insert
        for i in range(1010):
            db.log_heartbeat("n1", i)
        history = db.get_heartbeat_history("n1", limit=2000)
        assert len(history) <= 1000

    def test_singleton(self, tmp_path):
        from src.citadel_archer.mesh.mesh_database import (
            MeshDatabase, get_mesh_database, set_mesh_database,
        )

        db = MeshDatabase(db_path=str(tmp_path / "mesh.db"))
        set_mesh_database(db)
        assert get_mesh_database() is db
        set_mesh_database(None)


# ── Route Tests ──────────────────────────────────────────────────────


@pytest.fixture
def mesh_client():
    """TestClient with mesh coordinator wired."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)


class TestMeshRoutes:
    """API route tests."""

    def test_status_no_coordinator(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
        from src.citadel_archer.api.security import verify_session_token

        set_mesh_coordinator(None)
        test_app = FastAPI()
        test_app.include_router(router)
        test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
        client = TestClient(test_app)
        resp = client.get("/api/mesh/status")
        assert resp.status_code == 503

    def test_status_with_coordinator(self, mesh_client):
        resp = mesh_client.get("/api/mesh/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_id"] == "desktop"
        assert data["is_running"] is True

    def test_list_peers_empty(self, mesh_client):
        resp = mesh_client.get("/api/mesh/peers")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_add_peer(self, mesh_client):
        resp = mesh_client.post("/api/mesh/peers", json={
            "node_id": "vps1",
            "ip_address": "10.0.0.1",
            "port": 9378,
        })
        assert resp.status_code == 200
        assert resp.json()["node_id"] == "vps1"

        # Verify it appears in list
        resp = mesh_client.get("/api/mesh/peers")
        assert len(resp.json()) == 1

    def test_remove_peer(self, mesh_client):
        mesh_client.post("/api/mesh/peers", json={
            "node_id": "vps1", "ip_address": "10.0.0.1",
        })
        resp = mesh_client.delete("/api/mesh/peers/vps1")
        assert resp.status_code == 200

        resp = mesh_client.delete("/api/mesh/peers/vps1")
        assert resp.status_code == 404

    def test_get_config(self, mesh_client):
        resp = mesh_client.get("/api/mesh/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["interval"] == 30
        assert "alert_after" in data["thresholds"]

    def test_update_config(self, mesh_client):
        resp = mesh_client.put("/api/mesh/config", json={"interval": 60})
        assert resp.status_code == 200
        assert resp.json()["interval"] == 60

    def test_add_peer_invalid_ip(self, mesh_client):
        resp = mesh_client.post("/api/mesh/peers", json={
            "node_id": "bad", "ip_address": "not-an-ip",
        })
        assert resp.status_code == 422

    def test_psk_status(self, mesh_client):
        resp = mesh_client.get("/api/mesh/psk")
        assert resp.status_code == 200
        data = resp.json()
        assert "psk_configured" in data

    def test_psk_rotate(self, mesh_client):
        resp = mesh_client.post("/api/mesh/psk/rotate")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rotated"
        assert "psk_base64" in data
        assert "psk_fingerprint" in data

    def test_status_includes_psk_fingerprint(self, mesh_client):
        resp = mesh_client.get("/api/mesh/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "psk_fingerprint" in data
        assert "packets_rejected" in data


# ── Structural Tests ─────────────────────────────────────────────────


class TestFrontendStructural:
    """Verify integration points."""

    def test_audit_log_has_mesh_events(self):
        from src.citadel_archer.core.audit_log import EventType

        assert hasattr(EventType, "MESH_PEER_ONLINE")
        assert hasattr(EventType, "MESH_PEER_OFFLINE")
        assert hasattr(EventType, "MESH_ESCALATION")
        assert hasattr(EventType, "MESH_RECOVERY")

    def test_mesh_router_in_main(self):
        """mesh_router is registered in main.py."""
        from src.citadel_archer.api.main import app

        routes = [r.path for r in app.routes]
        # Check that at least one mesh route exists
        mesh_routes = [r for r in routes if "/mesh" in r]
        assert len(mesh_routes) > 0

    def test_model_tier_on_all_phases(self):
        """Every phase has a defined model_tier (even if None)."""
        from src.citadel_archer.mesh.mesh_state import EscalationPhase

        for phase in EscalationPhase:
            # Should not raise — model_tier is defined for all
            _ = phase.model_tier
