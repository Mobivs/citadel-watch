"""
Tests for shield.py fail2ban++ enhancements.

Covers: progressive banning, ban expiry, configurable thresholds,
whitelist, config loading, ip_bans table.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from citadel_archer.agent.shield import (
    BanExpiryManager,
    _load_config,
    block_ip,
    init_db,
    log_event,
    unblock_ip,
)


@pytest.fixture
def db_conn(tmp_path):
    """Fresh shield database with ip_bans table."""
    conn = init_db(db_path=str(tmp_path / "events.db"))
    return conn


class TestProgressiveBanning:
    """Progressive ban durations escalate with each offense."""

    @patch("citadel_archer.agent.shield._apply_firewall_block", return_value="mock blocked")
    @patch("citadel_archer.agent.shield._load_config", return_value={})
    def test_first_offense_5min(self, _cfg, _fw, db_conn):
        result = block_ip("1.2.3.4", conn=db_conn)
        assert "300s" in result
        assert "offense #1" in result

        # Verify DB record
        row = db_conn.execute("SELECT * FROM ip_bans WHERE ip = '1.2.3.4'").fetchone()
        assert row is not None
        assert row[3] is not None  # expires_at is set

    @patch("citadel_archer.agent.shield._apply_firewall_block", return_value="mock blocked")
    @patch("citadel_archer.agent.shield._load_config", return_value={})
    def test_second_offense_1hr(self, _cfg, _fw, db_conn):
        # First offense
        block_ip("1.2.3.4", conn=db_conn)
        # Second offense
        result = block_ip("1.2.3.4", conn=db_conn)
        assert "3600s" in result
        assert "offense #2" in result

    @patch("citadel_archer.agent.shield._apply_firewall_block", return_value="mock blocked")
    @patch("citadel_archer.agent.shield._load_config", return_value={})
    def test_permanent_after_threshold(self, _cfg, _fw, db_conn):
        # 5 offenses → permanent
        for _ in range(5):
            block_ip("5.5.5.5", conn=db_conn)
        result = block_ip("5.5.5.5", conn=db_conn)
        assert "permanent" in result
        assert "offense #6" in result

        # Verify no expires_at
        rows = db_conn.execute(
            "SELECT expires_at FROM ip_bans WHERE ip = '5.5.5.5' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert rows[0] is None

    @patch("citadel_archer.agent.shield._apply_firewall_block", return_value="mock blocked")
    @patch("citadel_archer.agent.shield._load_config", return_value={"ip_whitelist": ["10.0.0.1"]})
    def test_whitelisted_ip_skipped(self, _cfg, _fw, db_conn):
        result = block_ip("10.0.0.1", conn=db_conn)
        assert "skipped (whitelisted)" in result

        # No DB record
        count = db_conn.execute("SELECT COUNT(*) FROM ip_bans").fetchone()[0]
        assert count == 0


class TestBanExpiryManager:
    """Ban expiry unblocks IPs whose ban has expired."""

    def test_expired_ban_unblocked(self, db_conn):
        # Insert an already-expired ban
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        db_conn.execute(
            "INSERT INTO ip_bans (ip, ban_count, banned_at, expires_at, is_active) "
            "VALUES (?, 1, ?, ?, 1)",
            ("9.9.9.9", past, past),
        )
        db_conn.commit()

        mgr = BanExpiryManager(db_conn)
        with patch("citadel_archer.agent.shield.unblock_ip", return_value="unblocked"):
            count = mgr.check_expired_bans()

        assert count == 1
        row = db_conn.execute("SELECT is_active FROM ip_bans WHERE ip = '9.9.9.9'").fetchone()
        assert row[0] == 0

    def test_permanent_ban_never_expires(self, db_conn):
        now = datetime.now(timezone.utc).isoformat()
        db_conn.execute(
            "INSERT INTO ip_bans (ip, ban_count, banned_at, expires_at, is_active) "
            "VALUES (?, 1, ?, NULL, 1)",
            ("8.8.8.8", now),
        )
        db_conn.commit()

        mgr = BanExpiryManager(db_conn)
        with patch("citadel_archer.agent.shield.unblock_ip") as mock_unblock:
            count = mgr.check_expired_bans()

        assert count == 0
        mock_unblock.assert_not_called()

    def test_no_expired_bans_is_noop(self, db_conn):
        mgr = BanExpiryManager(db_conn)
        count = mgr.check_expired_bans()
        assert count == 0


class TestEnhancedAuthLogSensor:
    """AuthLogSensor uses configurable thresholds."""

    @patch("citadel_archer.agent.shield._load_config", return_value={"fail_threshold": 3, "fail_window": 120})
    def test_config_overrides_default_threshold(self, _cfg, db_conn):
        from citadel_archer.agent.shield import AuthLogSensor
        sensor = AuthLogSensor(db_conn)
        assert sensor._threshold == 3
        assert sensor._window == 120

    @patch("citadel_archer.agent.shield._load_config", return_value={})
    def test_defaults_when_no_config(self, _cfg, db_conn):
        from citadel_archer.agent.shield import AuthLogSensor, SSH_FAIL_THRESHOLD, SSH_FAIL_WINDOW
        sensor = AuthLogSensor(db_conn)
        assert sensor._threshold == SSH_FAIL_THRESHOLD
        assert sensor._window == SSH_FAIL_WINDOW

    @patch("citadel_archer.agent.shield._apply_firewall_block", return_value="mock blocked")
    @patch("citadel_archer.agent.shield._load_config", return_value={"fail_threshold": 2, "ip_whitelist": ["10.0.0.1"]})
    def test_whitelist_prevents_ban_via_sensor(self, _cfg, _fw, db_conn):
        result = block_ip("10.0.0.1", conn=db_conn)
        assert "skipped" in result


class TestConfigLoading:
    """config.json loading."""

    def test_load_valid_config(self, tmp_path):
        config = {"fail_threshold": 3, "ip_whitelist": ["1.2.3.4"]}
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps(config))

        with patch("citadel_archer.agent.shield.CONFIG_PATH", config_path):
            loaded = _load_config()

        assert loaded == config

    def test_missing_config_returns_defaults(self):
        from pathlib import Path
        fake_path = Path("/nonexistent/config.json")
        with patch("citadel_archer.agent.shield.CONFIG_PATH", fake_path):
            loaded = _load_config()
        assert loaded == {}
