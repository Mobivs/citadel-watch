"""Tests for escalation deduplication — correlate same-attack events from multiple agents.

v0.3.43: Tests for EscalationDeduplicator (merge window, multi-agent correlation,
single-agent passthrough, history, pending, flush, API routes).
"""

import time
from unittest.mock import MagicMock

import pytest


# ── EscalationEvent Tests ────────────────────────────────────────────


class TestEscalationEvent:

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.escalation_dedup import EscalationEvent

        evt = EscalationEvent(agent_id="vps1", rule_id="ssh_brute", event_type="auth_log")
        assert evt.timestamp != ""

    def test_explicit_fields(self):
        from src.citadel_archer.mesh.escalation_dedup import EscalationEvent

        evt = EscalationEvent(
            agent_id="vps1",
            rule_id="ssh_brute",
            event_type="remote.auth_log",
            severity="high",
            event_count=50,
            message="50 SSH failures",
            details={"ip": "1.2.3.4"},
        )
        assert evt.agent_id == "vps1"
        assert evt.rule_id == "ssh_brute"
        assert evt.event_count == 50


# ── MergedEscalation Tests ──────────────────────────────────────────


class TestMergedEscalation:

    def test_to_dict(self):
        from src.citadel_archer.mesh.escalation_dedup import MergedEscalation

        m = MergedEscalation(
            signature="ssh_brute:remote.auth_log",
            rule_id="ssh_brute",
            event_type="remote.auth_log",
            severity="high",
            agents=["vps1", "vps2", "vps3"],
            total_event_count=150,
        )
        d = m.to_dict()
        assert d["signature"] == "ssh_brute:remote.auth_log"
        assert d["agent_count"] == 3
        assert d["total_event_count"] == 150

    def test_empty_agents(self):
        from src.citadel_archer.mesh.escalation_dedup import MergedEscalation

        m = MergedEscalation(
            signature="test",
            rule_id="test",
            event_type="test",
            severity="low",
        )
        assert m.to_dict()["agent_count"] == 0


# ── Signature Builder Tests ──────────────────────────────────────────


class TestBuildSignature:

    def test_rule_only(self):
        from src.citadel_archer.mesh.escalation_dedup import build_signature

        sig = build_signature("ssh_brute")
        assert sig == "ssh_brute"

    def test_rule_and_type(self):
        from src.citadel_archer.mesh.escalation_dedup import build_signature

        sig = build_signature("ssh_brute", "remote.auth_log")
        assert sig == "ssh_brute:remote.auth_log"

    def test_empty_type_ignored(self):
        from src.citadel_archer.mesh.escalation_dedup import build_signature

        sig = build_signature("rule1", "")
        assert sig == "rule1"


# ── Severity Tests ──────────────────────────────────────────────────


class TestMaxSeverity:

    def test_critical_wins(self):
        from src.citadel_archer.mesh.escalation_dedup import _max_severity

        assert _max_severity("critical", "high") == "critical"
        assert _max_severity("low", "critical") == "critical"

    def test_same_severity(self):
        from src.citadel_archer.mesh.escalation_dedup import _max_severity

        assert _max_severity("medium", "medium") == "medium"


# ── Deduplicator Core Tests ─────────────────────────────────────────


class TestEscalationDeduplicator:

    def test_submit_returns_signature(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        sig = dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="ssh_brute", event_type="auth_log",
        ))
        assert sig == "ssh_brute:auth_log"

    def test_pending_after_submit(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="ssh_brute", event_type="auth_log",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps2", rule_id="ssh_brute", event_type="auth_log",
        ))

        pending = dedup.get_pending()
        assert len(pending) == 1
        assert pending[0]["agent_count"] == 2
        assert set(pending[0]["agents"]) == {"vps1", "vps2"}

    def test_different_rules_separate_buckets(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="ssh_brute", event_type="auth_log",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="file_integrity", event_type="file_mod",
        ))

        pending = dedup.get_pending()
        assert len(pending) == 2

    def test_force_flush_merges_multi_agent(self):
        """Force flush produces a merged escalation with all contributing agents."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        # 3 agents detect the same brute force
        for agent_id in ["vps1", "vps2", "vps3"]:
            dedup.submit(EscalationEvent(
                agent_id=agent_id,
                rule_id="ssh_brute",
                event_type="auth_log",
                severity="high",
                event_count=50,
                message=f"50 SSH failures on {agent_id}",
            ))

        # Force flush (simulates merge window expiration)
        dedup._flush_expired(force_all=True)

        assert len(merged_results) == 1
        merged = merged_results[0]
        assert len(merged.agents) == 3
        assert merged.total_event_count == 150
        assert merged.severity == "high"
        assert "Distributed Attack" in merged.message

    def test_single_agent_no_distributed_label(self):
        """Single-agent escalation doesn't say 'Distributed Attack'."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        dedup.submit(EscalationEvent(
            agent_id="vps1",
            rule_id="ssh_brute",
            event_type="auth_log",
            event_count=50,
        ))

        dedup._flush_expired(force_all=True)

        assert len(merged_results) == 1
        assert "Distributed Attack" not in merged_results[0].message
        assert "Escalation" in merged_results[0].message

    def test_severity_elevation(self):
        """Merged escalation takes the highest severity from contributing agents."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1", severity="medium",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps2", rule_id="r1", event_type="t1", severity="critical",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps3", rule_id="r1", event_type="t1", severity="high",
        ))

        dedup._flush_expired(force_all=True)
        assert merged_results[0].severity == "critical"

    def test_history_populated_after_flush(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        dedup._flush_expired(force_all=True)

        history = dedup.get_history()
        assert len(history) == 1
        assert history[0]["rule_id"] == "r1"

    def test_history_newest_first(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=0)  # Immediate flush
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        dedup._flush_expired(force_all=True)

        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r2", event_type="t2",
        ))
        dedup._flush_expired(force_all=True)

        history = dedup.get_history()
        assert len(history) == 2
        assert history[0]["rule_id"] == "r2"  # Newest first

    def test_status_counters(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps2", rule_id="r1", event_type="t1",
        ))

        status = dedup.get_status()
        assert status["events_received"] == 2
        assert status["pending_signatures"] == 1

        dedup._flush_expired(force_all=True)

        status = dedup.get_status()
        assert status["merges_completed"] == 1
        assert status["events_deduplicated"] == 1  # 2 agents → 1 saved

    def test_dedup_agent_counted(self):
        """events_deduplicated counts N-1 per multi-agent merge."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        for i in range(5):
            dedup.submit(EscalationEvent(
                agent_id=f"vps{i}", rule_id="r1", event_type="t1",
            ))

        dedup._flush_expired(force_all=True)
        assert dedup.get_status()["events_deduplicated"] == 4  # 5 agents → 4 saved

    def test_subscriber_callback_error_non_fatal(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        dedup.on_merged(lambda m: (_ for _ in ()).throw(ValueError("boom")))

        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        # Should not raise
        dedup._flush_expired(force_all=True)

    def test_max_pending_cap(self):
        """Safety cap: oldest bucket flushed when MAX_PENDING_SIGNATURES reached."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent, MAX_PENDING_SIGNATURES,
        )

        dedup = EscalationDeduplicator(merge_window=9999)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        # Submit MAX_PENDING_SIGNATURES different rules
        for i in range(MAX_PENDING_SIGNATURES):
            dedup.submit(EscalationEvent(
                agent_id="vps1", rule_id=f"r{i}", event_type="t1",
            ))

        assert len(merged_results) == 0  # Not yet flushed

        # One more should force-flush the oldest
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="overflow", event_type="t1",
        ))
        assert len(merged_results) == 1  # Oldest was flushed

    def test_start_stop_lifecycle(self):
        from src.citadel_archer.mesh.escalation_dedup import EscalationDeduplicator

        dedup = EscalationDeduplicator(merge_window=60, flush_interval=1)
        assert not dedup.is_running
        dedup.start()
        assert dedup.is_running
        dedup.stop()
        assert not dedup.is_running

    def test_background_flush(self):
        """Background thread flushes expired buckets."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        # merge_window=0 means immediate flush; flush_interval=0.2s
        dedup = EscalationDeduplicator(merge_window=0, flush_interval=0.2)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        dedup.start()
        try:
            dedup.submit(EscalationEvent(
                agent_id="vps1", rule_id="r1", event_type="t1",
            ))
            # Wait for background flush
            time.sleep(0.5)
            assert len(merged_results) == 1
        finally:
            dedup.stop()

    def test_duplicate_agent_counted_once(self):
        """Same agent submitting twice counted as one agent in merge."""
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator, EscalationEvent,
        )

        dedup = EscalationDeduplicator(merge_window=60)
        merged_results = []
        dedup.on_merged(lambda m: merged_results.append(m))

        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1", event_count=10,
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1", event_count=20,
        ))

        dedup._flush_expired(force_all=True)
        assert len(merged_results) == 1
        assert len(merged_results[0].agents) == 1  # Same agent
        assert merged_results[0].total_event_count == 30  # But counts add up


# ── Singleton Tests ──────────────────────────────────────────────────


class TestDedupSingleton:

    def test_get_set(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationDeduplicator,
            get_escalation_deduplicator,
            set_escalation_deduplicator,
        )

        dedup = EscalationDeduplicator()
        set_escalation_deduplicator(dedup)
        assert get_escalation_deduplicator() is dedup
        set_escalation_deduplicator(None)

    def test_default_none(self):
        from src.citadel_archer.mesh.escalation_dedup import (
            get_escalation_deduplicator,
            set_escalation_deduplicator,
        )

        set_escalation_deduplicator(None)
        assert get_escalation_deduplicator() is None


# ── Route Tests ──────────────────────────────────────────────────────


@pytest.fixture
def dedup_client():
    """TestClient for dedup routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.escalation_dedup import (
        EscalationDeduplicator, set_escalation_deduplicator,
    )
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    dedup = EscalationDeduplicator(merge_window=60)
    set_escalation_deduplicator(dedup)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_escalation_deduplicator(None)


class TestDedupRoutes:

    def test_get_status(self, dedup_client):
        resp = dedup_client.get("/api/mesh/dedup/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "events_received" in data

    def test_get_pending_empty(self, dedup_client):
        resp = dedup_client.get("/api/mesh/dedup/pending")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_get_pending_after_submit(self, dedup_client):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationEvent, get_escalation_deduplicator,
        )

        dedup = get_escalation_deduplicator()
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        dedup.submit(EscalationEvent(
            agent_id="vps2", rule_id="r1", event_type="t1",
        ))

        resp = dedup_client.get("/api/mesh/dedup/pending")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["pending"][0]["agent_count"] == 2

    def test_get_history_after_flush(self, dedup_client):
        from src.citadel_archer.mesh.escalation_dedup import (
            EscalationEvent, get_escalation_deduplicator,
        )

        dedup = get_escalation_deduplicator()
        dedup.submit(EscalationEvent(
            agent_id="vps1", rule_id="r1", event_type="t1",
        ))
        dedup._flush_expired(force_all=True)

        resp = dedup_client.get("/api/mesh/dedup/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["history"][0]["rule_id"] == "r1"

    def test_status_no_dedup(self):
        """When deduplicator is None, return not-initialized status."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
        from src.citadel_archer.api.security import verify_session_token
        from src.citadel_archer.mesh.escalation_dedup import set_escalation_deduplicator
        from src.citadel_archer.mesh.mesh_state import MeshCoordinator

        coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
        coord.start()
        set_mesh_coordinator(coord)
        set_escalation_deduplicator(None)

        test_app = FastAPI()
        test_app.include_router(router)
        test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
        client = TestClient(test_app)

        resp = client.get("/api/mesh/dedup/status")
        assert resp.status_code == 200
        assert resp.json()["running"] is False

        coord.stop()
        set_mesh_coordinator(None)
