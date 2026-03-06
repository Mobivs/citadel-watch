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
  S15 LAN Sentinel          tests/test_lan_sentinel.py
  S16 SSH Key Rotation      (unit tests only — requires live VPS for full test)
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


# ---------------------------------------------------------------------------
# S13 — Local Host Defender
# Verifies localhost auto-registration and safe-command whitelist.
# ---------------------------------------------------------------------------
class TestS13_LocalHostDefender:
    """S13: Local host protection — auto-registration and command safety."""

    def test_localhost_asset_auto_registers(self):
        """ensure_localhost_asset creates an asset with id='localhost'."""
        from citadel_archer.local.local_defender import ensure_localhost_asset
        from citadel_archer.intel.assets import AssetInventory, AssetPlatform

        inv = AssetInventory(db_path=None)  # memory-only
        result = ensure_localhost_asset(inv)
        assert result is True
        asset = inv.get("localhost")
        assert asset is not None
        assert asset.asset_id == "localhost"
        assert asset.platform == AssetPlatform.LOCAL
        assert asset.guardian_active is True

    def test_localhost_auto_register_is_idempotent(self):
        """Calling twice does not create a duplicate."""
        from citadel_archer.local.local_defender import ensure_localhost_asset
        from citadel_archer.intel.assets import AssetInventory

        inv = AssetInventory(db_path=None)
        first = ensure_localhost_asset(inv)
        second = ensure_localhost_asset(inv)
        assert first is True
        assert second is False

    def test_windows_powershell_commands_whitelisted(self):
        """PowerShell read-only commands are in the safe-command set."""
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Get-Process") is True
        assert _is_safe_read_only("Get-FileHash C:\\Windows\\notepad.exe") is True
        assert _is_safe_read_only("Get-AuthenticodeSignature 'C:\\file.exe'") is True

    def test_windows_cmd_tools_with_paths_whitelisted(self):
        """Windows cmd tools with backslash paths must auto-execute (not prompt approval)."""
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("dir C:\\Windows\\System32") is True
        assert _is_safe_read_only("type C:\\Windows\\System32\\drivers\\etc\\hosts") is True

    def test_powershell_write_commands_blocked(self):
        """Destructive PowerShell commands must NOT be auto-executed."""
        from citadel_archer.chat.ai_bridge import _is_safe_read_only
        assert _is_safe_read_only("Stop-Process -Id 1234") is False
        assert _is_safe_read_only("Remove-Item C:\\evil.exe -Force") is False


# ---------------------------------------------------------------------------
# S14 — Event Resolution Store
# Verifies resolve/unresolve/get/get_many with an in-memory DB.
# ---------------------------------------------------------------------------
class TestS14_ResolutionStore:
    """S14: Event resolution persistence — resolve, unresolve, bulk fetch."""

    def _store(self, tmp_path):
        from pathlib import Path
        from citadel_archer.intel.resolution_store import ResolutionStore
        return ResolutionStore(db_path=Path(tmp_path) / "resolutions.db")

    def test_resolve_creates_record(self, tmp_path):
        store = self._store(tmp_path)
        rec = store.resolve("local", "evt-001", "block_ip")
        assert rec["external_id"] == "evt-001"
        assert rec["action_taken"] == "block_ip"
        assert rec["resolved_by"] == "user"

    def test_get_returns_record(self, tmp_path):
        store = self._store(tmp_path)
        store.resolve("local", "evt-002", "kill_process", notes="test")
        row = store.get("local", "evt-002")
        assert row is not None
        assert row["action_taken"] == "kill_process"
        assert row["notes"] == "test"

    def test_unresolve_deletes_record(self, tmp_path):
        store = self._store(tmp_path)
        store.resolve("remote-shield", "thr-001", "apply_patches")
        deleted = store.unresolve("remote-shield", "thr-001")
        assert deleted is True
        assert store.get("remote-shield", "thr-001") is None

    def test_unresolve_missing_returns_false(self, tmp_path):
        store = self._store(tmp_path)
        assert store.unresolve("local", "nonexistent") is False

    def test_resolve_upserts(self, tmp_path):
        store = self._store(tmp_path)
        store.resolve("local", "evt-003", "block_ip")
        store.resolve("local", "evt-003", "quarantine_file")
        row = store.get("local", "evt-003")
        assert row["action_taken"] == "quarantine_file"

    def test_get_many_bulk_fetch(self, tmp_path):
        store = self._store(tmp_path)
        store.resolve("local", "a1", "block_ip")
        store.resolve("remote-shield", "b1", "kill_process")
        result = store.get_many([("local", "a1"), ("remote-shield", "b1"), ("local", "missing")])
        assert "local:a1" in result
        assert "remote-shield:b1" in result
        assert "local:missing" not in result

    def test_resolution_route_resolve(self, tmp_path):
        """REST endpoint returns 200 and resolution record."""
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app
        with TestClient(app) as client:
            r = client.post(
                "/api/events/local/smoke-evt-001/resolve",
                json={"action_taken": "block_ip"},
                headers={"X-Session-Token": "test"},
            )
        # 401 is expected without a real session token — just verify no 500
        assert r.status_code != 500


# ---------------------------------------------------------------------------
# S15 — LAN Sentinel
# Verifies LanDeviceStore CRUD and REST endpoint health with an in-memory DB.
# ---------------------------------------------------------------------------
class TestS15_LanSentinel:
    """S15: LAN device store — upsert, mark_known, get_new, endpoint health."""

    def _make_store(self, tmp_path):
        from pathlib import Path
        from citadel_archer.local.lan_scanner import LanDeviceStore
        return LanDeviceStore(db_path=Path(tmp_path) / "lan_test.db")

    def test_lan_device_store_upsert(self, tmp_path):
        """Upsert a device then get_all returns it."""
        store = self._make_store(tmp_path)
        is_new = store.upsert({
            "mac": "AA:BB:CC:DD:EE:FF",
            "ip": "192.168.1.10",
            "hostname": "testhost",
            "manufacturer": "TestCo",
        })
        assert is_new is True
        devices = store.get_all()
        assert len(devices) == 1
        assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert devices[0]["ip"] == "192.168.1.10"

    def test_mark_known(self, tmp_path):
        """After mark_known, is_known is 1 and label is saved."""
        store = self._make_store(tmp_path)
        store.upsert({"mac": "11:22:33:44:55:66", "ip": "192.168.1.20"})
        result = store.mark_known("11:22:33:44:55:66", label="My Laptop")
        assert result is True
        device = store.get_by_mac("11:22:33:44:55:66")
        assert device["is_known"] == 1
        assert device["label"] == "My Laptop"

    def test_get_new_devices(self, tmp_path):
        """get_new() returns only unknown (is_known=0) devices."""
        store = self._make_store(tmp_path)
        store.upsert({"mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.2"})
        store.upsert({"mac": "AA:BB:CC:00:00:02", "ip": "192.168.1.3"})
        store.mark_known("AA:BB:CC:00:00:01")
        new = store.get_new()
        assert len(new) == 1
        assert new[0]["mac"] == "AA:BB:CC:00:00:02"

    def test_lan_status_endpoint_not_500(self):
        """GET /api/lan/status returns something other than 500."""
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app
        with TestClient(app) as client:
            r = client.get(
                "/api/lan/status",
                headers={"X-Session-Token": "test"},
            )
        assert r.status_code != 500

# ---------------------------------------------------------------------------
# S16 — SSH Key Rotation Store
# Verifies SSHRotationStore CRUD and state transitions with an in-memory DB.
# ---------------------------------------------------------------------------
class TestS16_SshRotationStore:
    """S16: SSH key rotation state store — create, update, get_active, get_all_in_progress."""

    def _make_store(self, tmp_path):
        from pathlib import Path
        from citadel_archer.remote.ssh_rotation import SSHRotationStore
        return SSHRotationStore(db_path=Path(tmp_path) / "ssh_rot_test.db")

    def test_create_rotation(self, tmp_path):
        """create() returns a UUID and persists the record."""
        store = self._make_store(tmp_path)
        rotation_id = store.create("asset-123", old_cred_id="cred-abc")
        assert rotation_id
        rec = store.get(rotation_id)
        assert rec is not None
        assert rec["asset_id"] == "asset-123"
        assert rec["old_cred_id"] == "cred-abc"
        assert rec["status"] == "pending"

    def test_update_status(self, tmp_path):
        """update() transitions status and persists extra fields."""
        store = self._make_store(tmp_path)
        rid = store.create("asset-456")
        store.update(rid, "generating", new_cred_id="cred-xyz", new_pub_key="ssh-ed25519 AAAA test")
        rec = store.get(rid)
        assert rec["status"] == "generating"
        assert rec["new_cred_id"] == "cred-xyz"
        assert rec["new_pub_key"] == "ssh-ed25519 AAAA test"

    def test_get_active_returns_in_progress(self, tmp_path):
        """get_active() finds non-terminal rotation for an asset."""
        store = self._make_store(tmp_path)
        rid = store.create("asset-789")
        store.update(rid, "key_written")
        active = store.get_active("asset-789")
        assert active is not None
        assert active["rotation_id"] == rid
        assert active["status"] == "key_written"

    def test_get_active_returns_none_for_completed(self, tmp_path):
        """get_active() returns None after rotation completes."""
        store = self._make_store(tmp_path)
        rid = store.create("asset-done")
        store.update(rid, "completed")
        assert store.get_active("asset-done") is None

    def test_get_all_in_progress_filters_terminal(self, tmp_path):
        """get_all_in_progress() excludes terminal statuses."""
        store = self._make_store(tmp_path)
        rid_active = store.create("asset-A")
        store.update(rid_active, "verified")
        rid_done = store.create("asset-B")
        store.update(rid_done, "completed")
        rid_failed = store.create("asset-C")
        store.update(rid_failed, "failed")

        in_progress = store.get_all_in_progress()
        ids = [r["rotation_id"] for r in in_progress]
        assert rid_active in ids
        assert rid_done not in ids
        assert rid_failed not in ids
