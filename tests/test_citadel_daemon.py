"""Tests for Citadel Daemon (citadel_daemon.py) — Linux VPS Security Agent.

Unit tests for the standalone Linux daemon script. All subprocess
calls, file I/O, and network calls are mocked — no real Linux system needed.

Covers:
  - Database: init_db, store_event, get_unreported_events, mark_reported
  - Configuration: load_config, save_config, file permissions
  - HTTP client: http_post, Bearer auth
  - Enrollment: config saved correctly, error handling
  - Threat reporting: correct HTTP request format
  - Heartbeat: correct HTTP request format, command processing
  - Auth log: parse failed SSH lines, brute force detection
  - Process sensor: detect known miners
  - File integrity: baseline hashing, change detection
  - Systemd service: content verification
  - CLI status: valid JSON output
  - Download endpoints: GET /api/ext-agents/setup.sh, daemon.py
"""

import json
import os
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from citadel_archer.agent.citadel_daemon import (
    CRITICAL_FILES,
    DB_PATH,
    KNOWN_MINERS,
    SUSPICIOUS_PORTS,
    VERSION,
    _block_ip,
    _hash_crontabs,
    enroll,
    get_local_ip,
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

    def test_init_db_creates_events_table(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_store_and_retrieve_events(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "auth_log", "brute_force_attempt", "Failed SSH")
        store_event(conn, "critical", "processes", "process_anomaly", "Miner detected")

        events = get_unreported_events(conn)
        assert len(events) == 2
        assert events[0][2] == "high"  # severity
        assert events[1][4] == "process_anomaly"  # threat_type
        conn.close()

    def test_mark_reported(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "auth_log", "brute_force_attempt", "Test")
        store_event(conn, "medium", "cron", "config_change", "Test2")

        events = get_unreported_events(conn)
        assert len(events) == 2

        mark_reported(conn, [events[0][0]])
        remaining = get_unreported_events(conn)
        assert len(remaining) == 1
        assert remaining[0][2] == "medium"
        conn.close()

    def test_mark_reported_empty_list(self, tmp_path):
        """Mark reported with empty list should be a no-op."""
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "info", "system", "test", "test")
        mark_reported(conn, [])
        events = get_unreported_events(conn)
        assert len(events) == 1
        conn.close()

    def test_get_unreported_events_limit(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        for i in range(10):
            store_event(conn, "info", "system", "test", f"Event {i}")
        events = get_unreported_events(conn, limit=3)
        assert len(events) == 3
        conn.close()


# ── Configuration Tests ──────────────────────────────────────────────


class TestConfiguration:
    """Agent config load/save."""

    def test_config_save_load_roundtrip(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        agent_dir = tmp_path
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH", config_path
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", agent_dir
        )
        original = {
            "server_url": "http://100.68.75.8:8000",
            "agent_id": "abc123",
            "api_token": "secret-token",
        }
        save_config(original)
        loaded = load_config()
        assert loaded == original

    def test_config_load_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "nonexistent.json",
        )
        assert load_config() == {}

    def test_config_file_permissions(self, tmp_path, monkeypatch):
        """Config file should have 0o600 permissions on supported platforms."""
        config_path = tmp_path / "config.json"
        agent_dir = tmp_path
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH", config_path
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", agent_dir
        )
        save_config({"agent_id": "test"})
        if os.name != "nt":
            mode = config_path.stat().st_mode & 0o777
            assert mode == 0o600


# ── HTTP Client Tests ────────────────────────────────────────────────


class TestHTTPClient:
    """http_post helper."""

    def test_http_post_success(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            code, data = http_post("http://test/api", {"key": "val"})
        assert code == 200
        assert data == {"ok": True}

    def test_http_post_with_token(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            http_post("http://test/api", {}, token="secret-token")
            req = mock_open.call_args[0][0]
            assert req.get_header("Authorization") == "Bearer secret-token"

    def test_http_post_http_error(self):
        import urllib.error

        err = urllib.error.HTTPError(
            "http://test", 401, "Unauthorized", {}, None
        )
        err.read = MagicMock(return_value=b'{"detail": "Invalid token"}')
        with patch("urllib.request.urlopen", side_effect=err):
            code, data = http_post("http://test/api", {})
        assert code == 401
        assert data["detail"] == "Invalid token"

    def test_http_post_connection_error(self):
        with patch(
            "urllib.request.urlopen",
            side_effect=ConnectionError("Connection refused"),
        ):
            code, data = http_post("http://unreachable/api", {})
        assert code == 0
        assert "Connection refused" in data["detail"]


# ── Enrollment Tests ─────────────────────────────────────────────────


class TestEnrollment:
    """Agent enrollment via invitation string."""

    def test_enroll_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", tmp_path
        )

        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(200, {
                "agent_id": "abc123",
                "api_token": "secret-token",
                "asset_id": "asset-456",
            }),
        ), patch(
            "citadel_archer.agent.citadel_daemon.get_hostname",
            return_value="test-vps",
        ), patch(
            "citadel_archer.agent.citadel_daemon.get_local_ip",
            return_value="100.1.2.3",
        ):
            result = enroll("http://coordinator:8000", "CITADEL-1:abc:xyz")

        assert result is True
        config = json.loads((tmp_path / "config.json").read_text())
        assert config["agent_id"] == "abc123"
        assert config["api_token"] == "secret-token"
        assert config["server_url"] == "http://coordinator:8000"

    def test_enroll_failure(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", tmp_path
        )

        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(401, {"detail": "Invalid or expired invitation"}),
        ), patch(
            "citadel_archer.agent.citadel_daemon.get_hostname",
            return_value="test-vps",
        ), patch(
            "citadel_archer.agent.citadel_daemon.get_local_ip",
            return_value="100.1.2.3",
        ):
            result = enroll("http://coordinator:8000", "CITADEL-1:bad:bad")

        assert result is False
        assert not (tmp_path / "config.json").exists()

    def test_enroll_strips_trailing_slash(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "config.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", tmp_path
        )

        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(200, {
                "agent_id": "abc",
                "api_token": "tok",
            }),
        ) as mock_post, patch(
            "citadel_archer.agent.citadel_daemon.get_hostname",
            return_value="test-vps",
        ), patch(
            "citadel_archer.agent.citadel_daemon.get_local_ip",
            return_value="",
        ):
            enroll("http://coordinator:8000/", "CITADEL-1:abc:xyz")

        # URL should not have double slash
        call_url = mock_post.call_args[0][0]
        assert call_url == "http://coordinator:8000/api/ext-agents/enroll"


# ── Reporting Tests ──────────────────────────────────────────────────


class TestReporting:
    """Threat reporting and heartbeat."""

    def test_report_threats_success(self, tmp_path):
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "high", "auth_log", "brute_force_attempt", "10 failed SSH")
        store_event(conn, "critical", "processes", "process_anomaly", "xmrig detected")

        config = {
            "server_url": "http://coordinator:8000",
            "agent_id": "abc123",
            "api_token": "secret-token",
            "hostname": "test-vps",
        }

        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(200, {}),
        ) as mock_post:
            report_threats(conn, config)

        # Both events reported
        assert mock_post.call_count == 2
        # All events now marked as reported
        assert len(get_unreported_events(conn)) == 0
        conn.close()

    def test_report_threats_empty(self, tmp_path):
        """No events to report — should not make any HTTP calls."""
        conn = init_db(tmp_path / "events.db")
        config = {
            "server_url": "http://coordinator:8000",
            "agent_id": "abc123",
            "api_token": "secret-token",
        }
        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
        ) as mock_post:
            report_threats(conn, config)
        mock_post.assert_not_called()
        conn.close()

    def test_send_heartbeat(self):
        config = {
            "server_url": "http://coordinator:8000",
            "agent_id": "abc123",
            "api_token": "secret-token",
        }
        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(200, {"alert_threshold": 0, "pending_commands": []}),
        ) as mock_post:
            send_heartbeat(config)

        call_url = mock_post.call_args[0][0]
        assert "/api/ext-agents/abc123/heartbeat" in call_url
        assert mock_post.call_args[1].get("token") == "secret-token" or \
               mock_post.call_args[0][2] == "secret-token"

    def test_report_threats_severity_threshold(self, tmp_path):
        """Events below alert_threshold should be suppressed."""
        conn = init_db(tmp_path / "events.db")
        store_event(conn, "info", "system", "test", "Low priority event")
        store_event(conn, "critical", "processes", "process_anomaly", "Important")

        config = {
            "server_url": "http://coordinator:8000",
            "agent_id": "abc123",
            "api_token": "secret-token",
            "hostname": "test-vps",
            "alert_threshold": 7,  # Only severity >= 7 (high, critical)
        }

        with patch(
            "citadel_archer.agent.citadel_daemon.http_post",
            return_value=(200, {}),
        ) as mock_post:
            report_threats(conn, config)

        # Only 1 HTTP call (critical=9 passes, info=3 suppressed)
        assert mock_post.call_count == 1
        # Both events should be marked reported (suppressed ones too)
        assert len(get_unreported_events(conn)) == 0
        conn.close()


# ── Sensor Tests ─────────────────────────────────────────────────────


class TestSensors:
    """Individual sensor logic tests (non-threaded)."""

    def test_known_miners_set(self):
        """Verify the daemon has a comprehensive miner list."""
        assert "xmrig" in KNOWN_MINERS
        assert "minerd" in KNOWN_MINERS
        assert "cpuminer" in KNOWN_MINERS
        assert "kswapd0" in KNOWN_MINERS  # common disguise

    def test_suspicious_ports_set(self):
        assert 4444 in SUSPICIOUS_PORTS  # metasploit default
        assert 1337 in SUSPICIOUS_PORTS
        assert 31337 in SUSPICIOUS_PORTS

    def test_critical_files_list(self):
        assert "/etc/passwd" in CRITICAL_FILES
        assert "/etc/shadow" in CRITICAL_FILES
        assert "/etc/ssh/sshd_config" in CRITICAL_FILES
        assert "/etc/sudoers" in CRITICAL_FILES

    def test_block_ip_ufw(self):
        """_block_ip should try ufw first."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            result = _block_ip("1.2.3.4")
        assert "ufw deny from 1.2.3.4" in result

    def test_block_ip_iptables_fallback(self):
        """_block_ip should fallback to iptables if ufw not found."""
        from subprocess import CalledProcessError

        def side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd[0] == "ufw":
                raise FileNotFoundError("ufw not found")
            return MagicMock(returncode=0)

        with patch("subprocess.run", side_effect=side_effect):
            result = _block_ip("1.2.3.4")
        assert "iptables drop 1.2.3.4" in result

    def test_hash_crontabs_empty(self):
        """On a system with no crontabs, returns empty dict."""
        with patch("os.path.exists", return_value=False), \
             patch("os.path.isdir", return_value=False):
            result = _hash_crontabs()
        assert result == {}


# ── Status Tests ─────────────────────────────────────────────────────


class TestStatus:
    """get_status() JSON output."""

    def test_status_unenrolled(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "nonexistent.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.DB_PATH",
            tmp_path / "nonexistent.db",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.PID_FILE",
            tmp_path / "nonexistent.pid",
        )
        with patch(
            "citadel_archer.agent.citadel_daemon.get_local_ip",
            return_value="192.168.1.1",
        ):
            status = get_status()
        assert status["version"] == VERSION
        assert status["enrolled"] is False
        assert status["agent_id"] == ""

    def test_status_enrolled(self, tmp_path, monkeypatch):
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({
            "agent_id": "abc123",
            "server_url": "http://coordinator:8000",
            "api_token": "secret",
        }))
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH", config_path
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.DB_PATH",
            tmp_path / "nonexistent.db",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.PID_FILE",
            tmp_path / "nonexistent.pid",
        )
        with patch(
            "citadel_archer.agent.citadel_daemon.get_local_ip",
            return_value="100.1.2.3",
        ):
            status = get_status()
        assert status["enrolled"] is True
        assert status["agent_id"] == "abc123"


# ── Systemd Service Tests ───────────────────────────────────────────


class TestSystemdService:
    """install_service() creates valid systemd unit file."""

    def test_service_content(self, tmp_path, monkeypatch):
        from citadel_archer.agent.citadel_daemon import install_service, AGENT_DIR

        service_path = tmp_path / "citadel-daemon.service"
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.AGENT_DIR", tmp_path
        )

        with patch("subprocess.run") as mock_run, \
             patch(
                 "citadel_archer.agent.citadel_daemon.Path",
             ) as mock_path_cls:
            mock_run.return_value = MagicMock(
                stdout="/usr/bin/python3\n", returncode=0
            )
            # Mock the service path write
            mock_service_path = MagicMock()
            mock_path_cls.return_value = mock_service_path

            install_service()

            # Verify write_text was called with valid service content
            written = mock_service_path.write_text.call_args[0][0]
            assert "[Unit]" in written
            assert "[Service]" in written
            assert "[Install]" in written
            assert "Restart=always" in written
            assert "citadel_daemon.py daemon" in written
            assert "WantedBy=multi-user.target" in written


# ── IP Detection Tests ───────────────────────────────────────────────


class TestIPDetection:
    """get_local_ip() Tailscale-first strategy."""

    def test_tailscale_ip_preferred(self):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="100.1.2.3\n"
            )
            ip = get_local_ip()
        assert ip == "100.1.2.3"

    def test_fallback_to_socket(self):
        with patch("subprocess.run", side_effect=FileNotFoundError), \
             patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.getsockname.return_value = ("192.168.1.10", 0)
            mock_socket.return_value = mock_sock
            ip = get_local_ip()
        assert ip == "192.168.1.10"


# ── Download Endpoint Tests ──────────────────────────────────────────


class TestDownloadEndpoints:
    """Test the /api/ext-agents/setup.sh and daemon.py endpoints."""

    @pytest.fixture
    def client(self):
        """Create a test client for the download endpoints."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from citadel_archer.api.agent_api_routes import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_serve_setup_script(self, client):
        resp = client.get("/api/ext-agents/setup.sh")
        assert resp.status_code == 200
        assert "#!/bin/bash" in resp.text
        assert "Citadel Daemon" in resp.text
        assert "curl" in resp.text

    def test_serve_daemon_script(self, client):
        resp = client.get("/api/ext-agents/daemon.py")
        assert resp.status_code == 200
        assert "citadel_daemon" in resp.text.lower() or "Citadel Daemon" in resp.text
        assert "def main()" in resp.text
        assert "def enroll(" in resp.text


# ── CLI Tests ────────────────────────────────────────────────────────


class TestCLI:
    """CLI entry point tests."""

    def test_cli_no_args(self):
        from citadel_archer.agent.citadel_daemon import main

        with patch("sys.argv", ["citadel_daemon.py"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_cli_enroll_missing_args(self):
        from citadel_archer.agent.citadel_daemon import main

        with patch("sys.argv", ["citadel_daemon.py", "enroll"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_cli_unknown_command(self):
        from citadel_archer.agent.citadel_daemon import main

        with patch("sys.argv", ["citadel_daemon.py", "bogus"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_cli_status(self, tmp_path, monkeypatch):
        from citadel_archer.agent.citadel_daemon import main

        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.CONFIG_PATH",
            tmp_path / "nonexistent.json",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.DB_PATH",
            tmp_path / "nonexistent.db",
        )
        monkeypatch.setattr(
            "citadel_archer.agent.citadel_daemon.PID_FILE",
            tmp_path / "nonexistent.pid",
        )

        with patch("sys.argv", ["citadel_daemon.py", "status"]), \
             patch(
                 "citadel_archer.agent.citadel_daemon.get_local_ip",
                 return_value="192.168.1.1",
             ), \
             patch("builtins.print") as mock_print:
            main()

        # Should print valid JSON
        printed = mock_print.call_args[0][0]
        data = json.loads(printed)
        assert data["version"] == VERSION
        assert data["enrolled"] is False


# ── Active Defense / _execute_command Tests ─────────────────────────────────


class TestExecuteCommand:
    """Tests for _execute_command, ALLOWED_ACTIONS whitelist, and ack URL."""

    def _make_config(self):
        return {
            "server_url": "http://10.0.0.1:8000",
            "agent_id": "abc123",
            "api_token": "tok",
        }

    def test_allowed_actions_whitelist(self):
        from citadel_archer.agent.citadel_daemon import ALLOWED_ACTIONS
        for action in ("kill_process", "block_ip", "disable_cron_job",
                       "collect_forensics", "restart_service", "apply_patches",
                       "check_updates", "threat_alert", "apply_policy"):
            assert action in ALLOWED_ACTIONS

    def test_unknown_command_silently_rejected(self):
        from citadel_archer.agent.citadel_daemon import _execute_command
        cfg = self._make_config()
        with patch("citadel_archer.agent.citadel_daemon.http_post") as mock_post:
            result = _execute_command(cfg, {
                "action_id": "rm_rf_slash",
                "action_uuid": "uuid1",
                "parameters": {},
            })
        assert result is None
        mock_post.assert_not_called()

    def test_kill_process_uses_ext_agents_url(self):
        """ack must go to /api/ext-agents/, never /api/agents/."""
        from citadel_archer.agent.citadel_daemon import _execute_command
        cfg = self._make_config()
        with patch("citadel_archer.agent.citadel_daemon.http_post") as mock_post, \
             patch("citadel_archer.agent.citadel_daemon._cmd_kill_process",
                   return_value={"status": "killed", "action_id": "kill_process"}):
            _execute_command(cfg, {
                "action_id": "kill_process",
                "action_uuid": "deadbeef",
                "parameters": {"pid": 1234},
            })
        assert mock_post.called
        url_used = mock_post.call_args[0][0]
        assert "/api/ext-agents/" in url_used
        assert "/api/agents/" not in url_used
        assert "action-result" in url_used

    def test_no_ack_when_no_uuid(self):
        """Commands without an action_uuid do not trigger result reporting."""
        from citadel_archer.agent.citadel_daemon import _execute_command
        cfg = self._make_config()
        with patch("citadel_archer.agent.citadel_daemon.http_post") as mock_post, \
             patch("citadel_archer.agent.citadel_daemon._cmd_collect_forensics",
                   return_value={"status": "ok"}):
            _execute_command(cfg, {
                "action_id": "collect_forensics",
                "parameters": {},
            })
        mock_post.assert_not_called()

    def test_failed_command_reports_failed_status(self):
        """When a command raises, exec_status='failed' is reported."""
        from citadel_archer.agent.citadel_daemon import _execute_command
        cfg = self._make_config()
        with patch("citadel_archer.agent.citadel_daemon.http_post") as mock_post, \
             patch("citadel_archer.agent.citadel_daemon._cmd_block_ip",
                   side_effect=RuntimeError("iptables missing")):
            _execute_command(cfg, {
                "action_id": "block_ip",
                "action_uuid": "failuuid",
                "parameters": {"source_ip": "1.2.3.4"},
            })
        assert mock_post.called
        payload = mock_post.call_args[0][1]
        assert payload["status"] == "failed"
