"""Tests for UserPreferences SQLite key/value store (v0.3.25).

Covers:
  - Database file creation
  - get / set / get_all / delete operations
  - Default values
  - Upsert (overwrite existing)
  - Singleton management
"""

import pytest
from pathlib import Path

from citadel_archer.core.user_preferences import (
    UserPreferences,
    PREF_DASHBOARD_MODE,
    get_user_preferences,
    set_user_preferences,
)


class TestUserPreferences:
    """Core preference store operations."""

    @pytest.fixture
    def prefs(self, tmp_path):
        return UserPreferences(db_path=tmp_path / "prefs.db")

    def test_creates_db_file(self, tmp_path):
        UserPreferences(db_path=tmp_path / "prefs.db")
        assert (tmp_path / "prefs.db").exists()

    def test_creates_parent_dirs(self, tmp_path):
        UserPreferences(db_path=tmp_path / "sub" / "dir" / "prefs.db")
        assert (tmp_path / "sub" / "dir" / "prefs.db").exists()

    def test_get_returns_default_when_missing(self, prefs):
        assert prefs.get("nonexistent") is None
        assert prefs.get("nonexistent", "fallback") == "fallback"

    def test_set_and_get(self, prefs):
        prefs.set("theme", "dark")
        assert prefs.get("theme") == "dark"

    def test_set_upsert_overwrites(self, prefs):
        prefs.set("mode", "technical")
        prefs.set("mode", "simplified")
        assert prefs.get("mode") == "simplified"

    def test_get_all_empty(self, prefs):
        assert prefs.get_all() == {}

    def test_get_all_returns_dict(self, prefs):
        prefs.set("a", "1")
        prefs.set("b", "2")
        result = prefs.get_all()
        assert result == {"a": "1", "b": "2"}

    def test_delete_existing_key(self, prefs):
        prefs.set("x", "val")
        assert prefs.delete("x") is True
        assert prefs.get("x") is None

    def test_delete_nonexistent_key(self, prefs):
        assert prefs.delete("nope") is False

    def test_pref_dashboard_mode_constant(self):
        assert PREF_DASHBOARD_MODE == "dashboard_mode"


class TestSingleton:
    """Singleton get/set helpers."""

    def test_singleton_roundtrip(self, tmp_path):
        instance = UserPreferences(db_path=tmp_path / "singleton.db")
        set_user_preferences(instance)
        assert get_user_preferences() is instance
        # Reset global
        set_user_preferences(None)
