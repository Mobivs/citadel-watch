"""Tests for panic_routes.py code review fixes.

Covers:
  - Issue #1: init_panic_manager writes to _panic_manager (not panic_manager)
  - Issue #2: v1 audit calls use EventType/EventSeverity enums + message param
  - Issue #3: WebSocket handler initializes session_uuid before try block
"""

import hashlib
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest

from citadel_archer.core.audit_log import EventType, EventSeverity


# ── Issue #1: init_panic_manager global ──────────────────────────────

class TestInitPanicManager:
    """init_panic_manager should set _panic_manager, not panic_manager."""

    @pytest.fixture(autouse=True)
    def _save_and_restore_globals(self):
        """Save and restore panic_routes globals to prevent test leakage."""
        import citadel_archer.api.panic_routes as pr
        original_manager = pr._panic_manager
        original_db = pr._panic_db
        yield
        pr._panic_manager = original_manager
        pr._panic_db = original_db

    def test_sets_private_global(self):
        """After init, get_panic_manager() returns the instance."""
        import citadel_archer.api.panic_routes as pr

        mock_db = MagicMock()
        mock_config = {"test": True}

        with patch("citadel_archer.api.panic_routes.PanicManager") as MockPM:
            MockPM.return_value = MagicMock()
            pr.init_panic_manager(mock_db, mock_config)

        assert pr._panic_manager is not None
        manager = pr.get_panic_manager()
        assert manager is pr._panic_manager

    def test_get_panic_manager_auto_creates_when_uninitialized(self):
        """get_panic_manager should auto-create when _panic_manager is None.

        We mock PanicManager and PanicDatabase to avoid filesystem access
        (SecretsStore tries to create /var/citadel/ which may block on Windows).
        """
        import citadel_archer.api.panic_routes as pr

        pr._panic_manager = None
        pr._panic_db = None

        mock_pm_instance = MagicMock()
        mock_db_instance = MagicMock()

        with patch("citadel_archer.api.panic_routes.PanicManager", return_value=mock_pm_instance) as PM_cls, \
             patch("citadel_archer.api.panic_routes.PanicDatabase", return_value=mock_db_instance):
            manager = pr.get_panic_manager()

        assert manager is mock_pm_instance
        assert pr._panic_manager is mock_pm_instance
        PM_cls.assert_called_once()


# ── Issue #2: v1 audit calls use enums ───────────────────────────────

class TestAuditEnumUsage:
    """v1 routes should use EventType/EventSeverity enums, not raw strings."""

    def test_source_uses_enums(self):
        """Verify that the source code references EventType and EventSeverity."""
        import inspect
        import citadel_archer.api.panic_routes as pr

        source = inspect.getsource(pr)

        # The module should import EventType and EventSeverity
        assert "EventType" in source
        assert "EventSeverity" in source

        # Audit calls should use enum members, not string literals like "user.override"
        # Search for log_event calls and verify they use event_type= keyword
        import re
        log_calls = re.findall(r'audit\.log_event\((.*?)\)', source, re.DOTALL)

        for call in log_calls:
            # Each call should use event_type= keyword
            assert "event_type=" in call, f"log_event call missing event_type= keyword: {call[:80]}"
            # Each call should use severity= keyword
            assert "severity=" in call, f"log_event call missing severity= keyword: {call[:80]}"
            # Each call should use message= keyword
            assert "message=" in call, f"log_event call missing message= keyword: {call[:80]}"


# ── Issue #3: WebSocket session_uuid safety ──────────────────────────

class TestWebSocketSessionSafety:
    """WebSocket handler must init session_uuid = None before try block."""

    def test_source_initializes_session_uuid(self):
        """session_uuid should be initialized to None before the main try block."""
        import inspect
        import citadel_archer.api.panic_routes as pr

        source = inspect.getsource(pr.panic_websocket)

        # session_uuid = None should appear before the try block that uses it
        session_init_pos = source.find("session_uuid = None")
        assert session_init_pos != -1, "session_uuid = None not found"

        # Find the try block AFTER session_uuid = None (which contains the main logic)
        try_pos = source.find("try:", session_init_pos)
        assert try_pos != -1, "try: block not found after session_uuid = None"
        assert session_init_pos < try_pos, (
            "session_uuid = None must come before the try block"
        )

    def test_finally_guards_session_uuid(self):
        """finally block should check 'if session_uuid is not None'."""
        import inspect
        import citadel_archer.api.panic_routes as pr

        source = inspect.getsource(pr.panic_websocket)

        finally_pos = source.find("finally:")
        assert finally_pos != -1, "finally: block not found"

        # The guard should be in the finally section
        after_finally = source[finally_pos:]
        assert "session_uuid is not None" in after_finally, (
            "finally block must guard against None session_uuid"
        )


# ── Enum values sanity check ─────────────────────────────────────────

class TestEnumValidity:
    """EventType and EventSeverity used in panic_routes should be valid."""

    def test_user_override_exists(self):
        assert EventType.USER_OVERRIDE.value == "user.override"

    def test_ai_alert_exists(self):
        assert EventType.AI_ALERT.value == "ai.alert"

    def test_severity_alert_exists(self):
        assert EventSeverity.ALERT.value == "alert"

    def test_severity_critical_exists(self):
        assert EventSeverity.CRITICAL.value == "critical"


# ── Issue #37: Coverage for HMAC token system ─────────────────────────

class TestHMACTokenSystem:
    """Verify the HMAC-based confirmation token helpers."""

    def test_make_and_verify_token(self):
        """A freshly made token should verify successfully."""
        import citadel_archer.api.panic_routes as pr
        token = pr._make_confirmation_token("panic", "root", "sess1")
        assert isinstance(token, str)
        assert len(token) > 0
        assert pr._verify_confirmation_token("panic", "root", token, "sess1")

    def test_wrong_action_fails(self):
        import citadel_archer.api.panic_routes as pr
        token = pr._make_confirmation_token("panic", "root", "sess1")
        assert not pr._verify_confirmation_token("cancel", "root", token, "sess1")

    def test_wrong_user_fails(self):
        import citadel_archer.api.panic_routes as pr
        token = pr._make_confirmation_token("panic", "root", "sess1")
        assert not pr._verify_confirmation_token("panic", "attacker", token, "sess1")

    def test_wrong_session_fails(self):
        import citadel_archer.api.panic_routes as pr
        token = pr._make_confirmation_token("cancel", "root", "sess1")
        assert not pr._verify_confirmation_token("cancel", "root", token, "sess_other")

    def test_bogus_token_fails(self):
        import citadel_archer.api.panic_routes as pr
        assert not pr._verify_confirmation_token("panic", "root", "bogus", "sess1")

    def test_rollback_uses_distinct_action(self):
        """Rollback and panic tokens are not interchangeable."""
        import citadel_archer.api.panic_routes as pr
        panic_token = pr._make_confirmation_token("panic", "root", "s1")
        rollback_token = pr._make_confirmation_token("rollback", "root", "s1")
        assert panic_token != rollback_token
        assert not pr._verify_confirmation_token("rollback", "root", panic_token, "s1")


# ── Issue #37: Coverage for column whitelist ──────────────────────────

class TestColumnWhitelist:
    """PanicDatabase.update_session rejects invalid column names."""

    def test_rejects_invalid_column(self, tmp_path):
        from citadel_archer.panic.panic_database import PanicDatabase, PanicSession

        db = PanicDatabase(tmp_path / "test.db")
        session = PanicSession(
            session_id="test1", status="active", playbooks=["IsolateNetwork"],
            started_at=datetime.utcnow(),
        )
        db.create_session(session)

        with pytest.raises(ValueError, match="Invalid column names"):
            db.update_session("test1", {"status": "completed", "DROP TABLE panic_sessions--": "x"})

    def test_accepts_valid_columns(self, tmp_path):
        from citadel_archer.panic.panic_database import PanicDatabase, PanicSession

        db = PanicDatabase(tmp_path / "test.db")
        session = PanicSession(
            session_id="test2", status="active", playbooks=["RotateCredentials"],
            started_at=datetime.utcnow(),
        )
        db.create_session(session)

        result = db.update_session("test2", {"status": "completed", "progress": 100})
        assert result is True

        updated = db.get_session("test2")
        assert updated["status"] == "completed"
        assert updated["progress"] == 100


# ── Issue #37: Coverage for session ID sanitization ───────────────────

class TestSessionIdSanitization:
    """CredentialRotation._sanitize_session_id rejects dangerous inputs."""

    def test_valid_session_id(self):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        assert CredentialRotation._sanitize_session_id("sess_001") == "sess_001"
        assert CredentialRotation._sanitize_session_id("abc-def-123") == "abc-def-123"

    def test_rejects_path_traversal(self):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        with pytest.raises(ValueError, match="Invalid session_id"):
            CredentialRotation._sanitize_session_id("../../etc/passwd")

    def test_rejects_shell_injection(self):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        with pytest.raises(ValueError, match="Invalid session_id"):
            CredentialRotation._sanitize_session_id("sess; rm -rf /")

    def test_rejects_empty(self):
        from citadel_archer.panic.actions.credential_rotation import CredentialRotation
        with pytest.raises(ValueError, match="Invalid session_id"):
            CredentialRotation._sanitize_session_id("")


# ── Issue #37: Coverage for private key redaction ─────────────────────

class TestPrivateKeyRedaction:
    """_log_action should redact sensitive fields before DB storage."""

    @pytest.mark.asyncio
    async def test_redacts_private_key_from_result(self, tmp_path):
        from citadel_archer.panic.panic_manager import PanicManager
        from citadel_archer.panic.panic_database import PanicDatabase

        db = PanicDatabase(tmp_path / "test.db")

        # Create a parent session so the FK on panic_logs is satisfied
        import sqlite3 as _sq
        with _sq.connect(str(db.db_path)) as _c:
            _c.execute(
                "INSERT INTO panic_sessions (session_id, status, playbooks, started_at) "
                "VALUES ('s1', 'active', '[]', datetime('now'))"
            )
            _c.commit()

        mgr = PanicManager.__new__(PanicManager)
        mgr.db = db
        mgr.websocket_handlers = {}

        result = {
            "action": "rotate_ssh_keys",
            "status": "success",
            "result": {
                "new_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nSECRET\n-----END-----",
                "recovery_keys_preserved": 1,
            }
        }

        with patch.object(mgr, '_notify_websocket', new=AsyncMock()):
            await mgr._log_action(
                session_id="s1", playbook_id="pb1", playbook_name="RotateCredentials",
                action_name="rotate_ssh_keys", action_type="credentials",
                status="success", result=result,
            )

        # Verify the stored result has redacted key
        import sqlite3
        with sqlite3.connect(str(db.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT result FROM panic_logs WHERE session_id = 's1'").fetchone()

        import json
        stored = json.loads(row["result"])
        assert stored["result"]["new_private_key"] == "[REDACTED]"
        assert stored["result"]["recovery_keys_preserved"] == 1


# ── Issue #37: Coverage for _convert_query boolean compat ─────────────

class TestConvertQueryBooleans:
    """_convert_query should convert true/false to 1/0 for SQLite."""

    def test_false_to_zero(self):
        from citadel_archer.panic.panic_database import _convert_query
        q, a = _convert_query("WHERE archived = false", [])
        assert "0" in q
        assert "false" not in q.lower()

    def test_true_to_one(self):
        from citadel_archer.panic.panic_database import _convert_query
        q, a = _convert_query("WHERE is_active = true", [])
        assert "1" in q
        assert "true" not in q.lower()

    def test_any_expansion(self):
        from citadel_archer.panic.panic_database import _convert_query
        q, a = _convert_query("WHERE id = ANY($1)", [["a", "b", "c"]])
        assert "IN (?, ?, ?)" in q
        assert a == ["a", "b", "c"]

    def test_positional_params(self):
        from citadel_archer.panic.panic_database import _convert_query
        q, a = _convert_query("SELECT * FROM t WHERE a = $1 AND b = $2", ["x", "y"])
        assert q == "SELECT * FROM t WHERE a = ? AND b = ?"
        assert a == ["x", "y"]
