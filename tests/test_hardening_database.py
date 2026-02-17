"""
Tests for SSH hardening config CRUD in RemoteShieldDatabase.

Covers: save, get, update status, list, delete, upsert.
"""

import pytest

from citadel_archer.remote.shield_database import RemoteShieldDatabase


@pytest.fixture
def db(tmp_path):
    return RemoteShieldDatabase(db_path=str(tmp_path / "shield.db"))


class TestHardeningConfigCRUD:
    """CRUD operations for ssh_hardening_configs table."""

    def test_save_and_get_config(self, db):
        config = {"disable_password_auth": True, "max_auth_tries": 3}
        db.save_hardening_config("vps_1", config)
        result = db.get_hardening_config("vps_1")
        assert result is not None
        assert result["asset_id"] == "vps_1"
        assert result["config"] == config
        assert result["status"] == "pending"

    def test_update_status_to_applied(self, db):
        db.save_hardening_config("vps_2", {"foo": "bar"})
        ok = db.update_hardening_status(
            "vps_2", "applied", backup_path="/etc/ssh/sshd_config.bak"
        )
        assert ok is True
        result = db.get_hardening_config("vps_2")
        assert result["status"] == "applied"
        assert result["applied_at"] is not None
        assert result["backup_path"] == "/etc/ssh/sshd_config.bak"

    def test_list_configs_filtered(self, db):
        db.save_hardening_config("a1", {}, status="pending")
        db.save_hardening_config("a2", {}, status="applied")
        db.save_hardening_config("a3", {}, status="pending")

        all_configs = db.list_hardening_configs()
        assert len(all_configs) == 3

        pending = db.list_hardening_configs(status="pending")
        assert len(pending) == 2
        assert all(c["status"] == "pending" for c in pending)

        applied = db.list_hardening_configs(status="applied")
        assert len(applied) == 1

    def test_delete_config(self, db):
        db.save_hardening_config("vps_del", {"x": 1})
        assert db.get_hardening_config("vps_del") is not None
        ok = db.delete_hardening_config("vps_del")
        assert ok is True
        assert db.get_hardening_config("vps_del") is None

    def test_upsert_existing_config(self, db):
        db.save_hardening_config("vps_up", {"v": 1})
        db.save_hardening_config("vps_up", {"v": 2}, status="applied")
        result = db.get_hardening_config("vps_up")
        assert result["config"] == {"v": 2}
        assert result["status"] == "applied"

    def test_get_nonexistent_returns_none(self, db):
        assert db.get_hardening_config("no_such_asset") is None
