"""
Citadel Archer — Smoke Test Suite
==================================
Fast sanity check (~30s) covering one critical path per functional area.
Run with:  python -m pytest tests/test_smoke.py -v

When a section fails, run the full suite for that area:

  Section                   Full test file(s)
  ---------                 -----------------
  S1 API Health             tests/test_integration.py, test_phase2_alerts.py
  S2 Guardian File Monitor  tests/test_guardian_escalation.py
  S3 Dashboard Ext          tests/test_dashboard_ext.py
  S4 Alert System           tests/test_phase2_alerts.py
  S5 Audit Log              tests/test_ai_audit.py
  S6 Asset Inventory        tests/test_asset_aggregator.py, test_asset_view.py
  S7 Agent System           tests/test_agent_registry.py, test_agent_invitation.py
  S8 Guardian Escalation    tests/test_guardian_escalation.py
  S9 Risk / Threat Intel    tests/test_risk_metrics.py, test_threat_scorer.py
  S10 Remote Shield         tests/test_remote_shield_escalation.py
  S11 Event Aggregator      tests/test_aggregator.py
  S12 Panic Room            tests/test_remote_panic.py
"""

import pytest


# ---------------------------------------------------------------------------
# S1 — API Health
# One TestClient call proves FastAPI starts and returns 200 on /api/health.
# ---------------------------------------------------------------------------
class TestS1_APIHealth:
    """S1: Server starts and health endpoint responds."""

    def test_health_returns_ok(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app

        with TestClient(app) as client:
            r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# S2 — Guardian File Monitor
# Checks the trusted-vendor-path logic that suppresses Edge/Windows noise.
# ---------------------------------------------------------------------------
class TestS2_GuardianFileMonitor:
    """S2: File analysis logic (trusted paths, malware patterns)."""

    def test_trusted_vendor_path_not_flagged(self):
        from citadel_archer.guardian.file_monitor import SuspiciousFilePatterns
        edge = r"C:\Program Files (x86)\Microsoft\EdgeCore\Optimized\shell.dll"
        assert SuspiciousFilePatterns.is_trusted_vendor_path(edge) is True

    def test_downloads_dll_not_trusted(self):
        from citadel_archer.guardian.file_monitor import SuspiciousFilePatterns
        downloads = r"C:\Users\John\Downloads\evil.dll"
        assert SuspiciousFilePatterns.is_trusted_vendor_path(downloads) is False

    def test_double_extension_always_suspicious(self):
        from citadel_archer.guardian.file_monitor import SuspiciousFilePatterns
        assert SuspiciousFilePatterns.is_suspicious_extension("invoice.pdf.exe") is True

    def test_mimikatz_always_suspicious(self):
        from citadel_archer.guardian.file_monitor import SuspiciousFilePatterns
        assert SuspiciousFilePatterns.is_suspicious_name("mimikatz.exe") is True


# ---------------------------------------------------------------------------
# S3 — Dashboard Ext (charts, timeline, assets)
# DashboardServices takes no args — uses module-level singletons.
# ---------------------------------------------------------------------------
class TestS3_DashboardExt:
    """S3: Dashboard data services return valid structure."""

    def test_chart_data_has_points(self):
        from citadel_archer.api.dashboard_ext import DashboardServices
        svc = DashboardServices()
        result = svc.get_chart_data()
        # Returns ChartResponse Pydantic model
        assert hasattr(result, "period")
        assert hasattr(result, "points")

    def test_timeline_has_entries(self):
        from citadel_archer.api.dashboard_ext import DashboardServices
        svc = DashboardServices()
        result = svc.get_timeline()
        # Returns TimelineResponse Pydantic model
        assert hasattr(result, "entries")
        assert hasattr(result, "total")

    def test_assets_has_assets(self):
        from citadel_archer.api.dashboard_ext import DashboardServices
        svc = DashboardServices()
        result = svc.get_assets()
        # Returns AssetsResponse Pydantic model
        assert hasattr(result, "assets")
        assert hasattr(result, "total")


# ---------------------------------------------------------------------------
# S4 — Alert System
# One threat submission through the real endpoint.
# ---------------------------------------------------------------------------
class TestS4_AlertSystem:
    """S4: Threat submission creates an alert."""

    def test_submit_threat_creates_alert(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app

        with TestClient(app) as client:
            r = client.post("/api/threats/submit", json={
                "threat_type": "smoke_test",
                "severity": 7,
                "source": "smoke",
                "description": "Smoke test threat"
            })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("created", "deduplicated")
        assert "alert_id" in data


# ---------------------------------------------------------------------------
# S5 — Audit Log
# Writes one event and queries it back (uses tmp_path for isolation).
# ---------------------------------------------------------------------------
class TestS5_AuditLog:
    """S5: Audit logger write/query round-trip."""

    def test_log_and_query(self, tmp_path):
        from citadel_archer.core.audit_log import AuditLogger, EventType, EventSeverity
        log = AuditLogger(log_dir=tmp_path / "audit")
        eid = log.log_event(EventType.SYSTEM_START, EventSeverity.INFO, "smoke test event")
        assert eid

        events = log.query_events(limit=5)
        messages = [e.get("message", "") for e in events]
        assert "smoke test event" in messages


# ---------------------------------------------------------------------------
# S6 — Asset Inventory
# Memory-mode inventory (db_path=None): register → get.
# ---------------------------------------------------------------------------
class TestS6_AssetInventory:
    """S6: Asset CRUD with in-memory inventory."""

    def test_register_get(self):
        from citadel_archer.intel.assets import AssetInventory, Asset
        inv = AssetInventory(db_path=None)
        asset = Asset(
            name="smoke-vps",
            platform="linux",
            hostname="smoke.local",
            ip_address="10.9.8.7",
        )
        inv.register(asset)
        got = inv.get(asset.asset_id)
        assert got is not None
        assert got.name == "smoke-vps"


# ---------------------------------------------------------------------------
# S7 — Agent System
# InvitationStore: create invitation → verify token stored.
# ---------------------------------------------------------------------------
class TestS7_AgentSystem:
    """S7: Agent invitation creation."""

    def test_create_invitation(self, tmp_path):
        from citadel_archer.chat.agent_invitation import InvitationStore, InvitationStatus
        from citadel_archer.api import security
        # InvitationStore uses HMAC keyed by the session token
        old_token = security._SESSION_TOKEN
        security._SESSION_TOKEN = "smoke-test-hmac-key"
        try:
            store = InvitationStore(db_path=str(tmp_path / "invitations.db"))
            invitation, token = store.create_invitation(
                agent_name="smoke-agent",
                agent_type="claude_code",
                created_by="smoke-test",
            )
            assert token
            # get_invitation takes the invitation_id, not the compact token string
            inv = store.get_invitation(invitation.invitation_id)
            assert inv is not None
            assert inv.agent_name == "smoke-agent"
            assert inv.status == InvitationStatus.PENDING
        finally:
            security._SESSION_TOKEN = old_token


# ---------------------------------------------------------------------------
# S8 — Guardian Escalation Filter
# Verifies severity + category gating without async machinery.
# ---------------------------------------------------------------------------
class TestS8_GuardianEscalation:
    """S8: Escalation filters events by severity and category."""

    def _make_event(self, severity, category):
        from citadel_archer.intel.event_aggregator import AggregatedEvent
        return AggregatedEvent(
            event_type="file.modified",
            message="test event",
            severity=severity,
            category=category,
        )

    def test_alert_file_event_buffered(self):
        from unittest.mock import MagicMock
        from citadel_archer.intel.event_aggregator import EventAggregator, EventCategory
        from citadel_archer.chat.guardian_escalation import GuardianEscalation

        ge = GuardianEscalation(MagicMock(spec=EventAggregator), MagicMock())
        ge._on_event(self._make_event("alert", EventCategory.FILE))
        assert ge.buffer_size == 1

    def test_info_file_event_ignored(self):
        from unittest.mock import MagicMock
        from citadel_archer.intel.event_aggregator import EventAggregator, EventCategory
        from citadel_archer.chat.guardian_escalation import GuardianEscalation

        ge = GuardianEscalation(MagicMock(spec=EventAggregator), MagicMock())
        ge._on_event(self._make_event("info", EventCategory.FILE))
        assert ge.buffer_size == 0

    def test_alert_network_event_ignored(self):
        from unittest.mock import MagicMock
        from citadel_archer.intel.event_aggregator import EventAggregator, EventCategory
        from citadel_archer.chat.guardian_escalation import GuardianEscalation

        ge = GuardianEscalation(MagicMock(spec=EventAggregator), MagicMock())
        ge._on_event(self._make_event("alert", EventCategory.NETWORK))
        assert ge.buffer_size == 0


# ---------------------------------------------------------------------------
# S9 — Risk Metrics
# RiskMetrics.overall_risk() returns a float in [0, 100].
# ---------------------------------------------------------------------------
class TestS9_RiskMetrics:
    """S9: Risk score computation."""

    def test_risk_score_in_range(self):
        from citadel_archer.intel.risk_metrics import RiskMetrics
        from citadel_archer.intel.threat_scorer import ThreatScorer
        rm = RiskMetrics(scorer=ThreatScorer())
        score = rm.overall_risk()
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# S10 — Remote Shield (VPS agent database)
# ---------------------------------------------------------------------------
class TestS10_RemoteShield:
    """S10: Remote shield DB stores and retrieves agents."""

    def test_create_and_get_agent(self, tmp_path):
        from citadel_archer.remote.shield_database import RemoteShieldDatabase
        db = RemoteShieldDatabase(db_path=str(tmp_path / "shield.db"))
        db.create_agent(
            agent_id="shield_smoke",
            hostname="smoke.vps.local",
            ip_address="10.0.0.99",
            api_token="tok_smoke",
        )
        agent = db.get_agent("shield_smoke")
        assert agent is not None
        assert agent["hostname"] == "smoke.vps.local"


# ---------------------------------------------------------------------------
# S11 — Event Aggregator
# Ingest one event, verify it appears via .recent().
# ---------------------------------------------------------------------------
class TestS11_EventAggregator:
    """S11: EventAggregator ingests and returns events."""

    def test_ingest_and_recent(self):
        from citadel_archer.intel.event_aggregator import EventAggregator
        agg = EventAggregator()
        agg.ingest(
            event_type="file.modified",
            severity="alert",
            message="smoke aggregator event",
        )
        events = agg.recent(limit=10)
        messages = [e.message for e in events]
        assert "smoke aggregator event" in messages


# ---------------------------------------------------------------------------
# S12 — Panic Room
# Config endpoint must not 500 (auth may 401 — that's fine).
# ---------------------------------------------------------------------------
class TestS12_PanicRoom:
    """S12: Panic room endpoints respond without 500."""

    def test_panic_config_not_500(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app

        with TestClient(app) as client:
            r = client.get("/api/panic/config")
        assert r.status_code != 500
