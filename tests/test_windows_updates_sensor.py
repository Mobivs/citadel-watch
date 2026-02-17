"""Tests for Windows Update sensor and command execution (windows_shield.py).

Covers:
  - _query_windows_updates: PowerShell output parsing
  - _query_windows_updates: fallback to wmic on PS failure
  - _query_windows_updates: returns None on total failure
  - sensor_windows_updates: stores threat when overdue
  - sensor_windows_updates: stores threat when reboot required
  - sensor_windows_updates: no threat when up to date
  - _execute_command: check_updates runs wuauclt
  - _execute_command: unknown type acknowledges with error
  - _report_patch_status: POSTs to server
  - send_heartbeat: processes pending_commands from response
"""

import json
import threading
from unittest.mock import MagicMock, call, patch

import pytest

from citadel_archer.agent.windows_shield import (
    OVERDUE_DAYS_THRESHOLD,
    _execute_command,
    _query_updates_wmic_fallback,
    _query_windows_updates,
    _report_patch_status,
    init_db,
    send_heartbeat,
    sensor_windows_updates,
    store_event,
)


# ── _query_windows_updates ────────────────────────────────────────────


class TestQueryWindowsUpdates:
    """PowerShell COM query and wmic fallback."""

    def test_parses_powershell_json_output(self):
        """Successful PowerShell output → parsed dict."""
        ps_output = json.dumps({
            "check_status": "ok",
            "pending_count": 3,
            "installed_count": 10,
            "reboot_required": False,
            "oldest_pending_days": 5,
            "pending_titles": ["KB001", "KB002", "KB003"],
            "last_check_date": "2026-02-15T08:00:00",
            "last_install_date": "2026-02-10T12:00:00",
        })

        mock_result = MagicMock(returncode=0, stdout=ps_output, stderr="")
        with patch("citadel_archer.agent.windows_shield.subprocess.run", return_value=mock_result):
            data = _query_windows_updates()

        assert data is not None
        assert data["pending_count"] == 3
        assert data["check_status"] == "ok"
        assert len(data["pending_titles"]) == 3

    def test_fallback_to_wmic_on_powershell_failure(self):
        """PowerShell fails → calls wmic fallback."""
        ps_fail = MagicMock(returncode=1, stdout="", stderr="error")
        wmic_output = "Node,Description,HotFixID,InstalledBy,InstalledOn\nPC,,KB001,SYSTEM,2/10/2026"
        wmic_ok = MagicMock(returncode=0, stdout=wmic_output, stderr="")

        def side_effect(args, **kwargs):
            if args[0] == "powershell":
                return ps_fail
            return wmic_ok

        with patch("citadel_archer.agent.windows_shield.subprocess.run", side_effect=side_effect):
            data = _query_windows_updates()

        assert data is not None
        assert data["check_status"] == "ok"
        assert data["installed_count"] >= 1

    def test_returns_none_on_total_failure(self):
        """Both PS and wmic fail → None."""
        with patch(
            "citadel_archer.agent.windows_shield.subprocess.run",
            side_effect=FileNotFoundError("not found"),
        ):
            data = _query_windows_updates()

        assert data is None


# ── _query_updates_wmic_fallback ──────────────────────────────────────


class TestWmicFallback:
    def test_parses_csv_lines(self):
        output = (
            "Node,Description,HotFixID,InstalledBy,InstalledOn\n"
            "PC,,KB001,SYSTEM,2/1/2026\n"
            "PC,,KB002,SYSTEM,2/5/2026\n"
        )
        mock_result = MagicMock(returncode=0, stdout=output, stderr="")
        with patch("citadel_archer.agent.windows_shield.subprocess.run", return_value=mock_result):
            data = _query_updates_wmic_fallback()

        assert data is not None
        assert data["installed_count"] == 2
        assert data["pending_count"] == 0

    def test_returns_none_when_wmic_missing(self):
        with patch(
            "citadel_archer.agent.windows_shield.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            data = _query_updates_wmic_fallback()
        assert data is None


# ── sensor_windows_updates ────────────────────────────────────────────


class TestSensorWindowsUpdates:
    """Sensor thread logic."""

    def _run_sensor_once(self, patch_data, tmp_path):
        """Helper: run sensor for one iteration and return stored events."""
        stop = threading.Event()
        db_path = tmp_path / "events.db"

        # Pre-create tables
        conn = init_db(db_path)
        conn.close()

        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
        }

        with (
            patch("citadel_archer.agent.windows_shield.DB_PATH", db_path),
            patch("citadel_archer.agent.windows_shield.load_config", return_value=config),
            patch("citadel_archer.agent.windows_shield._query_windows_updates", return_value=patch_data),
            patch("citadel_archer.agent.windows_shield._report_patch_status") as mock_report,
        ):
            # Make the sensor run once then stop
            def stop_after_one_pass(timeout):
                stop.set()
                return True

            stop.wait = stop_after_one_pass
            sensor_windows_updates(stop)

        # Read stored events
        import sqlite3
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events WHERE reported = 0").fetchall()
        conn.close()
        return rows, mock_report

    def test_stores_threat_when_overdue(self, tmp_path):
        patch_data = {
            "check_status": "ok",
            "pending_count": 5,
            "oldest_pending_days": 14,
            "reboot_required": False,
        }
        events, _ = self._run_sensor_once(patch_data, tmp_path)
        assert len(events) >= 1
        assert any("windows_update_overdue" in e["threat_type"] for e in events)

    def test_stores_threat_when_reboot_required(self, tmp_path):
        patch_data = {
            "check_status": "ok",
            "pending_count": 0,
            "oldest_pending_days": 0,
            "reboot_required": True,
        }
        events, _ = self._run_sensor_once(patch_data, tmp_path)
        assert len(events) >= 1
        assert any("restart" in (e["detail"] or "").lower() for e in events)

    def test_no_threat_when_up_to_date(self, tmp_path):
        patch_data = {
            "check_status": "ok",
            "pending_count": 0,
            "oldest_pending_days": 0,
            "reboot_required": False,
        }
        events, _ = self._run_sensor_once(patch_data, tmp_path)
        assert len(events) == 0

    def test_reports_patch_status_to_server(self, tmp_path):
        patch_data = {"check_status": "ok", "pending_count": 2}
        _, mock_report = self._run_sensor_once(patch_data, tmp_path)
        mock_report.assert_called_once()
        args = mock_report.call_args
        assert args[0][1] == patch_data  # second positional arg


# ── _execute_command ──────────────────────────────────────────────────


class TestExecuteCommand:
    """Command dispatch and acknowledgement."""

    def test_check_updates_calls_wuauclt(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
        }
        cmd = {"command_id": "cmd-99", "command_type": "check_updates"}

        with (
            patch("citadel_archer.agent.windows_shield.subprocess.run") as mock_run,
            patch("citadel_archer.agent.windows_shield.http_post") as mock_post,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            mock_post.return_value = (200, {})
            _execute_command(config, cmd)

        # Verify wuauclt called
        mock_run.assert_called_once()
        assert mock_run.call_args[0][0] == ["wuauclt", "/detectnow"]

        # Verify acknowledgement posted
        mock_post.assert_called_once()
        ack_url = mock_post.call_args[0][0]
        ack_data = mock_post.call_args[0][1]
        assert "/commands/ack" in ack_url
        assert ack_data["command_id"] == "cmd-99"
        assert ack_data["result"] == "triggered_update_check"

    def test_unknown_command_type_acknowledges(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
        }
        cmd = {"command_id": "cmd-bad", "command_type": "do_evil_things"}

        with patch("citadel_archer.agent.windows_shield.http_post") as mock_post:
            mock_post.return_value = (200, {})
            _execute_command(config, cmd)

        mock_post.assert_called_once()
        ack_data = mock_post.call_args[0][1]
        assert ack_data["command_id"] == "cmd-bad"
        assert ack_data["result"] == "unknown_command"

    def test_wuauclt_not_found_still_acknowledges(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
        }
        cmd = {"command_id": "cmd-nf", "command_type": "check_updates"}

        with (
            patch("citadel_archer.agent.windows_shield.subprocess.run", side_effect=FileNotFoundError),
            patch("citadel_archer.agent.windows_shield.http_post") as mock_post,
        ):
            mock_post.return_value = (200, {})
            _execute_command(config, cmd)

        ack_data = mock_post.call_args[0][1]
        assert ack_data["result"] == "wuauclt_not_found"


# ── _report_patch_status ──────────────────────────────────────────────


class TestReportPatchStatus:
    def test_posts_to_correct_url(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
        }
        patch_data = {"pending_count": 2, "check_status": "ok"}

        with patch("citadel_archer.agent.windows_shield.http_post") as mock_post:
            mock_post.return_value = (200, {})
            _report_patch_status(config, patch_data)

        mock_post.assert_called_once_with(
            "https://citadel.local:8000/api/agents/agent-1/patch-status",
            patch_data,
            token="tok-abc",
        )

    def test_skips_when_no_server_url(self):
        config = {"server_url": "", "agent_id": "agent-1", "api_token": "tok"}
        with patch("citadel_archer.agent.windows_shield.http_post") as mock_post:
            _report_patch_status(config, {"pending_count": 0})
        mock_post.assert_not_called()


# ── send_heartbeat: pending commands ──────────────────────────────────


class TestHeartbeatCommands:
    def test_heartbeat_processes_pending_commands(self):
        config = {
            "server_url": "https://citadel.local:8000",
            "agent_id": "agent-1",
            "api_token": "tok-abc",
            "alert_threshold": 0,
        }

        heartbeat_response = {
            "status": "ok",
            "alert_threshold": 0,
            "pending_commands": [
                {"command_id": "cmd-1", "command_type": "check_updates"},
                {"command_id": "cmd-2", "command_type": "check_updates"},
            ],
        }

        with (
            patch("citadel_archer.agent.windows_shield.http_post") as mock_post,
            patch("citadel_archer.agent.windows_shield._execute_command") as mock_exec,
            patch("citadel_archer.agent.windows_shield.save_config"),
        ):
            # Heartbeat call returns our test response
            mock_post.return_value = (200, heartbeat_response)
            send_heartbeat(config)

        # Should have executed 2 commands
        assert mock_exec.call_count == 2
        assert mock_exec.call_args_list[0][0][1]["command_id"] == "cmd-1"
        assert mock_exec.call_args_list[1][0][1]["command_id"] == "cmd-2"
