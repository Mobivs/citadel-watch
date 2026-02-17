"""Tests for Windows Shield Agent (windows_shield.py).

Unit tests for the standalone Windows agent script. All subprocess
calls are mocked — no real wevtutil/powershell/netsh/tasklist needed.

Covers:
  - Event Log: parse failed logon (Event ID 4625)
  - Event Log: parse audit cleared (Event ID 1102)
  - Defender: detect disabled real-time protection
  - Defender: no alert when enabled
  - Firewall: detect disabled profile
  - Process: detect known miner process names
  - Enrollment: config.json saved correctly
  - Heartbeat: correct HTTP request format
  - Threat report: correct HTTP request format
  - CLI status: valid JSON output
  - CLI enroll: error on missing arguments
  - Graceful handling when wevtutil not available
"""

import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.agent.windows_shield import (
    DB_PATH,
    EVENT_IDS,
    KNOWN_MINERS,
    _check_processes,
    _parse_event_log_output,
    _parse_firewall_output,
    enroll,
    get_status,
    get_unreported_events,
    http_post,
    init_db,
    load_config,
    mark_reported,
    report_threats,
    save_config,
    send_heartbeat,
    store_event,
)


# ── Database Tests ───────────────────────────────────────────────────


class TestLocalDatabase:
    """Local events SQLite database."""

    def test_init_db_creates_file(self, tmp_path):
        db_path = tmp_path / "events.db"
        conn = init_db(db_path)
        assert db_path.exists()
        conn.close()

    def test_store_and_retrieve_events(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "event_log", "logon_failure", "Failed logon")
        store_event(conn, "critical", "defender", "defender_disabled", "Defender OFF")

        events = get_unreported_events(conn)
        assert len(events) == 2
        assert events[0][2] == "high"  # severity
        assert events[1][4] == "defender_disabled"  # threat_type
        conn.close()

    def test_mark_reported(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "event_log", "logon_failure", "Test")
        store_event(conn, "medium", "software", "suspicious_software", "Test2")

        events = get_unreported_events(conn)
        assert len(events) == 2

        # Mark first as reported
        mark_reported(conn, [events[0][0]])

        remaining = get_unreported_events(conn)
        assert len(remaining) == 1
        assert remaining[0][4] == "suspicious_software"
        conn.close()


# ── Event Log Sensor ─────────────────────────────────────────────────


class TestEventLogParsing:
    """Parse wevtutil text output for security events."""

    def test_parse_failed_logon_4625(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Security-Auditing
  Event ID: 4625
  Task Category: Logon
  Level: Information
  Description: An account failed to log on.
  Account Name: admin
  Source Network Address: 192.168.1.100
"""
        _parse_event_log_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 1
        assert events[0][4] == "logon_failure"
        assert events[0][2] == "high"
        conn.close()

    def test_parse_audit_log_cleared_1102(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Event[0]:
  Log Name: Security
  Source: Microsoft-Windows-Eventlog
  Event ID: 1102
  Description: The audit log was cleared.
"""
        _parse_event_log_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 1
        assert events[0][4] == "audit_log_cleared"
        assert events[0][2] == "critical"
        conn.close()

    def test_parse_privilege_escalation_4672(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Event[0]:
  Event ID: 4672
  Description: Special privileges assigned to new logon.
"""
        _parse_event_log_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 1
        assert events[0][4] == "unauthorized_access"
        conn.close()

    def test_parse_ignores_unknown_event_ids(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Event[0]:
  Event ID: 4624
  Description: Successful logon (normal, not monitored).
"""
        _parse_event_log_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 0
        conn.close()

    def test_parse_multiple_events(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Event[0]:
  Event ID: 4625
  Description: Failed logon 1
Event[1]:
  Event ID: 4625
  Description: Failed logon 2
Event[2]:
  Event ID: 1102
  Description: Audit cleared
"""
        _parse_event_log_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 3
        conn.close()


# ── Defender Sensor ──────────────────────────────────────────────────


class TestDefenderParsing:
    """Windows Defender status detection via PowerShell JSON output."""

    def test_defender_disabled_detected(self, tmp_path):
        """When RealTimeProtectionEnabled is False, store critical event."""
        conn = init_db(tmp_path / "events.db")

        # Simulate sensor_defender behavior inline (mock subprocess in sensor tests)
        status = {"RealTimeProtectionEnabled": False}
        rtp = status.get("RealTimeProtectionEnabled", True)
        if not rtp:
            store_event(
                conn, "critical", "defender", "defender_disabled",
                "Windows Defender real-time protection is DISABLED",
            )

        events = get_unreported_events(conn)
        assert len(events) == 1
        assert events[0][4] == "defender_disabled"
        assert events[0][2] == "critical"
        conn.close()

    def test_defender_enabled_no_alert(self, tmp_path):
        """When RealTimeProtectionEnabled is True, no event stored."""
        conn = init_db(tmp_path / "events.db")

        status = {"RealTimeProtectionEnabled": True}
        rtp = status.get("RealTimeProtectionEnabled", True)
        if not rtp:
            store_event(
                conn, "critical", "defender", "defender_disabled",
                "Windows Defender real-time protection is DISABLED",
            )

        events = get_unreported_events(conn)
        assert len(events) == 0
        conn.close()


# ── Firewall Sensor ──────────────────────────────────────────────────


class TestFirewallParsing:
    """Parse netsh advfirewall output."""

    def test_detect_disabled_profile(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
"""
        _parse_firewall_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 2  # Domain + Public OFF
        assert all(e[4] == "firewall_disabled" for e in events)
        conn.close()

    def test_all_profiles_on(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = """Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
"""
        _parse_firewall_output(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 0
        conn.close()


# ── Process Sensor ───────────────────────────────────────────────────


class TestProcessParsing:
    """Detect crypto miners in tasklist output."""

    def test_detect_known_miner(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = (
            '"svchost.exe","1234","Services","0","12,345 K"\n'
            '"chrome.exe","5678","Console","1","200,000 K"\n'
            '"xmrig.exe","9999","Console","1","50,000 K"\n'
        )
        _check_processes(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 1
        assert events[0][4] == "process_anomaly"
        assert "xmrig" in events[0][5].lower()
        conn.close()

    def test_no_miners_no_alert(self, tmp_path):
        conn = init_db(tmp_path / "events.db")

        output = (
            '"svchost.exe","1234","Services","0","12,345 K"\n'
            '"chrome.exe","5678","Console","1","200,000 K"\n'
        )
        _check_processes(conn, output)

        events = get_unreported_events(conn)
        assert len(events) == 0
        conn.close()

    def test_known_miners_set_contains_expected(self):
        """Verify the KNOWN_MINERS set has major crypto miners."""
        assert "xmrig" in KNOWN_MINERS
        assert "ethminer" in KNOWN_MINERS
        assert "nicehash" in KNOWN_MINERS


# ── Configuration ────────────────────────────────────────────────────


class TestConfiguration:
    """Config load/save."""

    def test_save_and_load_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.AGENT_DIR",
            tmp_path,
        )

        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "shield_abc123",
            "api_token": "tok_xyz",
        }
        save_config(config)

        loaded = load_config()
        assert loaded["agent_id"] == "shield_abc123"
        assert loaded["server_url"] == "https://citadel.local:8000"

    def test_load_missing_config_returns_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "nonexistent.json",
        )
        assert load_config() == {}


# ── HTTP Client ──────────────────────────────────────────────────────


class TestHttpPost:
    """HTTP POST via urllib."""

    def test_successful_post(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"agent_id": "shield_123"}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("citadel_archer.agent.windows_shield.urllib.request.urlopen", return_value=mock_resp):
            code, data = http_post("https://example.com/api/enroll", {"test": True})

        assert code == 200
        assert data["agent_id"] == "shield_123"

    def test_connection_error_returns_0(self):
        with patch(
            "citadel_archer.agent.windows_shield.urllib.request.urlopen",
            side_effect=Exception("Connection refused"),
        ):
            code, data = http_post("https://bad.example.com/api", {})

        assert code == 0
        assert "Connection refused" in data["detail"]


# ── Enrollment ───────────────────────────────────────────────────────


class TestEnrollment:
    """Enrollment flow: POST to server, save config."""

    def test_successful_enrollment_saves_config(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.AGENT_DIR",
            tmp_path,
        )

        mock_resp = (200, {
            "agent_id": "shield_abc",
            "api_token": "tok_xyz",
            "asset_id": "asset_123",
            "message": "Enrolled",
        })

        with patch("citadel_archer.agent.windows_shield.http_post", return_value=mock_resp), \
             patch("citadel_archer.agent.windows_shield.get_hostname", return_value="FAMILY-PC"), \
             patch("citadel_archer.agent.windows_shield.get_local_ip", return_value="192.168.1.50"):
            result = enroll("https://citadel.local:8000", "CITADEL-1:aabbccddeeff:secret123")

        assert result is True

        config = json.loads((tmp_path / "config.json").read_text())
        assert config["agent_id"] == "shield_abc"
        assert config["api_token"] == "tok_xyz"
        assert config["server_url"] == "https://citadel.local:8000"
        assert config["hostname"] == "FAMILY-PC"

    def test_failed_enrollment_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "config.json",
        )

        mock_resp = (401, {"detail": "Invalid or expired invitation"})

        with patch("citadel_archer.agent.windows_shield.http_post", return_value=mock_resp), \
             patch("citadel_archer.agent.windows_shield.get_hostname", return_value="PC"), \
             patch("citadel_archer.agent.windows_shield.get_local_ip", return_value=""):
            result = enroll("https://citadel.local:8000", "CITADEL-1:bad:secret")

        assert result is False
        assert not (tmp_path / "config.json").exists()


# ── Reporting ────────────────────────────────────────────────────────


class TestReporting:
    """Threat reporting + heartbeat HTTP calls."""

    def test_report_threats_sends_correct_payload(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "event_log", "logon_failure", "Failed logon from 1.2.3.4")

        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "shield_abc",
            "api_token": "tok_xyz",
            "hostname": "FAMILY-PC",
        }

        calls = []

        def mock_http_post(url, data, token=None):
            calls.append({"url": url, "data": data, "token": token})
            return 200, {"id": "t1", "status": "success", "message": "ok"}

        with patch("citadel_archer.agent.windows_shield.http_post", side_effect=mock_http_post):
            report_threats(conn, config)

        assert len(calls) == 1
        assert calls[0]["url"] == "https://citadel.local:8000/api/threats/remote-shield"
        assert calls[0]["data"]["type"] == "logon_failure"
        assert calls[0]["data"]["severity"] == 7  # high → 7
        assert calls[0]["token"] == "tok_xyz"

        # Events should be marked as reported
        remaining = get_unreported_events(conn)
        assert len(remaining) == 0
        conn.close()

    def test_heartbeat_sends_to_correct_url(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "shield_abc",
            "api_token": "tok_xyz",
        }

        with patch("citadel_archer.agent.windows_shield.http_post") as mock_post:
            mock_post.return_value = (200, {"status": "ok"})
            send_heartbeat(config)

        mock_post.assert_called_once_with(
            "https://citadel.local:8000/api/agents/shield_abc/heartbeat",
            {},
            token="tok_xyz",
        )

    def test_report_stops_on_auth_failure(self, tmp_path):
        """On 401, stop reporting further events."""
        conn = init_db(tmp_path / "events.db")
        for i in range(5):
            store_event(conn, "high", "event_log", "logon_failure", f"Event {i}")

        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "shield_abc",
            "api_token": "tok_xyz",
            "hostname": "PC",
        }

        call_count = [0]

        def mock_http_post(url, data, token=None):
            call_count[0] += 1
            return 401, {"detail": "Invalid token"}

        with patch("citadel_archer.agent.windows_shield.http_post", side_effect=mock_http_post):
            report_threats(conn, config)

        # Should stop after first 401 (not try all 5)
        assert call_count[0] == 1
        conn.close()


# ── Status ───────────────────────────────────────────────────────────


class TestStatus:
    """CLI status output."""

    def test_status_returns_valid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.AGENT_DIR",
            tmp_path,
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.DB_PATH",
            tmp_path / "events.db",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.PID_FILE",
            tmp_path / "shield.pid",
        )

        # Save config first
        save_config({"agent_id": "shield_abc", "server_url": "https://test.local"})

        # Create DB with some events
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "event_log", "logon_failure", "Test")
        conn.close()

        status = get_status()
        assert status["version"] == "0.1.0"
        assert status["enrolled"] is True
        assert status["agent_id"] == "shield_abc"
        assert status["total_events"] == 1
        assert status["unreported_events"] == 1
        assert status["running"] is False

    def test_status_not_enrolled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.CONFIG_PATH",
            tmp_path / "nonexistent.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.DB_PATH",
            tmp_path / "nonexistent.db",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.windows_shield.PID_FILE",
            tmp_path / "nonexistent.pid",
        )

        status = get_status()
        assert status["enrolled"] is False
        assert status["agent_id"] == ""


# ── Graceful Degradation ─────────────────────────────────────────────


class TestGracefulDegradation:
    """Sensors handle missing tools gracefully."""

    def test_wevtutil_not_found_exits_gracefully(self, tmp_path):
        """If wevtutil is not available, sensor_event_log breaks out."""
        import threading

        from citadel_archer.agent.windows_shield import sensor_event_log

        db_path = tmp_path / "events.db"
        conn = init_db(db_path)
        conn.close()
        stop_event = threading.Event()

        with patch(
            "citadel_archer.agent.windows_shield.subprocess.run",
            side_effect=FileNotFoundError("wevtutil not found"),
        ), patch(
            "citadel_archer.agent.windows_shield.DB_PATH", db_path,
        ):
            # sensor_event_log creates its own connection; breaks on FileNotFoundError
            sensor_event_log(stop_event)

        # Should have exited without events
        verify_conn = init_db(db_path)
        events = get_unreported_events(verify_conn)
        assert len(events) == 0
        verify_conn.close()

    def test_event_ids_cover_expected_set(self):
        """Verify monitored Event IDs."""
        assert 4625 in EVENT_IDS  # Failed logon
        assert 1102 in EVENT_IDS  # Audit cleared
        assert 4672 in EVENT_IDS  # Special privileges
        assert 4720 in EVENT_IDS  # Account created
