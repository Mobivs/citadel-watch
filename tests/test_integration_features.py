"""Tests for newly integrated features.

Covers:
  - Audit log query_events() parsing log files
  - Threat level calculation (green/yellow/red)
  - Uptime formatting
  - Panic config save/load via PanicDatabase
  - Confirmation token endpoint
  - SSH Manager cache invalidation
  - Vault integration in credential rotation (graceful fallback when locked)
"""

import json
import asyncio
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.core.audit_log import AuditLogger, EventType, EventSeverity
from citadel_archer.panic.panic_database import PanicDatabase


# ── Audit Log: query_events() ────────────────────────────────────────

class TestQueryEvents:
    """query_events should parse JSON log files and filter by criteria."""

    def _make_logger(self, tmp_path, events):
        """Create an AuditLogger with pre-written log entries."""
        logger = AuditLogger(log_dir=tmp_path, encrypt=False)

        # Write events to a log file
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = tmp_path / f"audit_{today}.log"

        with open(log_file, 'a', encoding='utf-8') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')

        return logger

    def test_returns_matching_events(self, tmp_path):
        events = [
            {"event": "security_event", "event_type": "ai.alert", "severity": "alert",
             "message": "test alert", "timestamp": datetime.utcnow().isoformat(), "event_id": "e1"},
            {"event": "security_event", "event_type": "file.created", "severity": "info",
             "message": "file created", "timestamp": datetime.utcnow().isoformat(), "event_id": "e2"},
        ]
        logger = self._make_logger(tmp_path, events)

        results = logger.query_events(limit=50)
        assert len(results) >= 2

    def test_filters_by_event_type(self, tmp_path):
        events = [
            {"event": "security_event", "event_type": "ai.alert", "severity": "alert",
             "message": "alert 1", "timestamp": datetime.utcnow().isoformat(), "event_id": "e1"},
            {"event": "security_event", "event_type": "file.created", "severity": "info",
             "message": "file event", "timestamp": datetime.utcnow().isoformat(), "event_id": "e2"},
        ]
        logger = self._make_logger(tmp_path, events)

        results = logger.query_events(event_types=[EventType.AI_ALERT])
        assert all(e["event_type"] == "ai.alert" for e in results)

    def test_filters_by_severity(self, tmp_path):
        events = [
            {"event": "security_event", "event_type": "ai.alert", "severity": "critical",
             "message": "critical!", "timestamp": datetime.utcnow().isoformat(), "event_id": "e1"},
            {"event": "security_event", "event_type": "file.created", "severity": "info",
             "message": "info", "timestamp": datetime.utcnow().isoformat(), "event_id": "e2"},
        ]
        logger = self._make_logger(tmp_path, events)

        results = logger.query_events(severity=EventSeverity.CRITICAL)
        assert all(e["severity"] == "critical" for e in results)

    def test_respects_limit(self, tmp_path):
        events = [
            {"event": "security_event", "event_type": "ai.alert", "severity": "info",
             "message": f"event {i}", "timestamp": datetime.utcnow().isoformat(), "event_id": f"e{i}"}
            for i in range(20)
        ]
        logger = self._make_logger(tmp_path, events)

        results = logger.query_events(limit=5)
        assert len(results) <= 5

    def test_skips_non_security_events(self, tmp_path):
        events = [
            {"event": "security_event", "event_type": "ai.alert", "severity": "info",
             "message": "real event", "timestamp": datetime.utcnow().isoformat(), "event_id": "e1"},
            {"event": "throttle_summary", "message": "suppressed 5 events"},
        ]
        logger = self._make_logger(tmp_path, events)

        results = logger.query_events()
        assert all(e.get("event") == "security_event" for e in results)

    def test_empty_log_dir(self, tmp_path):
        logger = AuditLogger(log_dir=tmp_path)
        results = logger.query_events()
        assert results == []


# ── Threat Level Calculation ──────────────────────────────────────────

class TestThreatLevel:
    """_calculate_threat_level should return green/yellow/red."""

    def test_green_when_no_events(self):
        from citadel_archer.api.main import _calculate_threat_level
        with patch("citadel_archer.api.main.get_audit_logger") as mock_logger:
            mock_logger.return_value.query_events.return_value = []
            assert _calculate_threat_level() == "green"

    def test_yellow_on_single_alert(self):
        from citadel_archer.api.main import _calculate_threat_level
        events = [{"severity": "alert", "event_type": "ai.alert"}]
        with patch("citadel_archer.api.main.get_audit_logger") as mock_logger:
            mock_logger.return_value.query_events.return_value = events
            assert _calculate_threat_level() == "yellow"

    def test_red_on_critical(self):
        from citadel_archer.api.main import _calculate_threat_level
        events = [{"severity": "critical", "event_type": "ai.alert"}]
        with patch("citadel_archer.api.main.get_audit_logger") as mock_logger:
            mock_logger.return_value.query_events.return_value = events
            assert _calculate_threat_level() == "red"

    def test_red_on_many_alerts(self):
        from citadel_archer.api.main import _calculate_threat_level
        events = [
            {"severity": "alert", "event_type": "ai.alert"},
            {"severity": "alert", "event_type": "ai.alert"},
            {"severity": "alert", "event_type": "ai.alert"},
        ]
        with patch("citadel_archer.api.main.get_audit_logger") as mock_logger:
            mock_logger.return_value.query_events.return_value = events
            assert _calculate_threat_level() == "red"


# ── Uptime Formatting ────────────────────────────────────────────────

class TestUptimeFormatting:
    def test_format_minutes(self):
        from citadel_archer.api.main import _format_uptime, _server_start_time
        import citadel_archer.api.main as m
        original = m._server_start_time
        try:
            m._server_start_time = datetime.now(timezone.utc) - timedelta(minutes=45)
            result = _format_uptime()
            assert "0h 45m" == result
        finally:
            m._server_start_time = original

    def test_format_hours(self):
        import citadel_archer.api.main as m
        original = m._server_start_time
        try:
            m._server_start_time = datetime.now(timezone.utc) - timedelta(hours=3, minutes=15)
            result = m._format_uptime()
            assert "3h 15m" == result
        finally:
            m._server_start_time = original

    def test_format_days(self):
        import citadel_archer.api.main as m
        original = m._server_start_time
        try:
            m._server_start_time = datetime.now(timezone.utc) - timedelta(days=2, hours=5, minutes=30)
            result = m._format_uptime()
            assert "2d 5h 30m" == result
        finally:
            m._server_start_time = original

    def test_format_none(self):
        import citadel_archer.api.main as m
        original = m._server_start_time
        try:
            m._server_start_time = None
            assert m._format_uptime() == "0h 0m"
        finally:
            m._server_start_time = original


# ── Panic Config Save/Load ────────────────────────────────────────────

class TestPanicConfig:
    """PanicDatabase.get_config / save_config round-trip."""

    def test_save_and_load(self, tmp_path):
        db = PanicDatabase(tmp_path / "test.db")

        db.save_config({
            "ipWhitelist": ["10.0.0.1", "192.168.1.1"],
            "processWhitelist": ["ssh", "nginx"],
            "isolationMode": "strict",
        })

        config = db.get_config()
        assert config["ipWhitelist"] == ["10.0.0.1", "192.168.1.1"]
        assert config["processWhitelist"] == ["ssh", "nginx"]
        assert config["isolationMode"] == "strict"

    def test_overwrite_existing(self, tmp_path):
        db = PanicDatabase(tmp_path / "test.db")
        db.save_config({"ipWhitelist": ["1.2.3.4"]})
        db.save_config({"ipWhitelist": ["5.6.7.8"]})

        config = db.get_config()
        assert config["ipWhitelist"] == ["5.6.7.8"]

    def test_empty_config(self, tmp_path):
        db = PanicDatabase(tmp_path / "test.db")
        config = db.get_config()
        assert config == {}


# ── SSH Manager Cache Invalidation ────────────────────────────────────

class TestSSHCacheInvalidation:

    @pytest.mark.asyncio
    async def test_invalidate_cache_disconnects(self):
        from citadel_archer.remote.ssh_manager import SSHConnectionManager, _CachedConnection

        vault = MagicMock()
        vault.is_unlocked = True
        inventory = MagicMock()

        with patch("citadel_archer.remote.ssh_manager.asyncssh", MagicMock()):
            mgr = SSHConnectionManager(vault, inventory)

        # Add a fake cached connection
        fake_conn = MagicMock()
        fake_conn.close = MagicMock()
        fake_conn.wait_closed = AsyncMock()
        mgr._connections["asset1"] = _CachedConnection(conn=fake_conn, asset_id="asset1")

        await mgr.invalidate_cache("asset1")

        assert "asset1" not in mgr._connections
        fake_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalidate_cache_noop_for_unknown(self):
        from citadel_archer.remote.ssh_manager import SSHConnectionManager

        vault = MagicMock()
        vault.is_unlocked = True
        inventory = MagicMock()

        with patch("citadel_archer.remote.ssh_manager.asyncssh", MagicMock()):
            mgr = SSHConnectionManager(vault, inventory)

        # Should not raise for unknown asset
        await mgr.invalidate_cache("nonexistent")

    @pytest.mark.asyncio
    async def test_invalidate_all_caches(self):
        from citadel_archer.remote.ssh_manager import SSHConnectionManager, _CachedConnection

        vault = MagicMock()
        vault.is_unlocked = True
        inventory = MagicMock()

        with patch("citadel_archer.remote.ssh_manager.asyncssh", MagicMock()):
            mgr = SSHConnectionManager(vault, inventory)

        for i in range(3):
            fake = MagicMock()
            fake.close = MagicMock()
            fake.wait_closed = AsyncMock()
            mgr._connections[f"a{i}"] = _CachedConnection(conn=fake, asset_id=f"a{i}")

        await mgr.invalidate_all_caches()

        assert len(mgr._connections) == 0


# ── Vault Integration Graceful Fallback ───────────────────────────────

class TestVaultIntegrationFallback:
    """Credential rotation vault methods should handle locked vault gracefully."""

    @pytest.mark.asyncio
    async def test_get_credentials_returns_empty_when_locked(self, tmp_path):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation

        db = PanicDatabase(tmp_path / "test.db")
        rot = CredentialRotation(db, {"api_services": []})

        # Patch _get_vault_manager to return None (locked)
        with patch.object(rot, '_get_vault_manager', return_value=None):
            result = await rot._get_vault_credentials()
            assert result == []

    @pytest.mark.asyncio
    async def test_get_passwords_returns_empty_when_locked(self, tmp_path):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation

        db = PanicDatabase(tmp_path / "test.db")
        rot = CredentialRotation(db, {"api_services": []})

        with patch.object(rot, '_get_vault_manager', return_value=None):
            result = await rot._get_vault_passwords()
            assert result == []

    @pytest.mark.asyncio
    async def test_update_credential_fails_when_locked(self, tmp_path):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation

        db = PanicDatabase(tmp_path / "test.db")
        rot = CredentialRotation(db, {"api_services": []})

        with patch.object(rot, '_get_vault_manager', return_value=None):
            result = await rot._update_vault_credential("test", "value")
            assert result is False

    @pytest.mark.asyncio
    async def test_get_credentials_with_unlocked_vault(self, tmp_path):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation

        db = PanicDatabase(tmp_path / "test.db")
        rot = CredentialRotation(db, {"api_services": []})

        mock_vm = MagicMock()
        mock_vm.is_unlocked = True
        mock_vm.list_passwords.return_value = [
            {"id": "1", "title": "SSH Key", "category": "ssh"},
            {"id": "2", "title": "API Token", "category": "api"},
            {"id": "3", "title": "DB Password", "category": "general"},
        ]

        with patch.object(rot, '_get_vault_manager', return_value=mock_vm):
            result = await rot._get_vault_credentials()

        assert len(result) == 3
        assert result[0]["type"] == "ssh_key"
        assert result[1]["type"] == "api_token"
        assert result[2]["type"] == "password"


# ── Confirmation Token Endpoint Source Check ──────────────────────────

class TestConfirmationTokenEndpoint:
    """Verify the confirmation-token endpoint exists in panic_routes."""

    def test_endpoint_registered(self):
        import inspect
        import citadel_archer.api.panic_routes as pr
        source = inspect.getsource(pr)
        assert "/confirmation-token" in source
        assert "ConfirmationTokenRequest" in source

    def test_config_endpoints_registered(self):
        import inspect
        import citadel_archer.api.panic_routes as pr
        source = inspect.getsource(pr)
        assert '"/config"' in source or "'/config'" in source
        assert "PanicConfigRequest" in source
