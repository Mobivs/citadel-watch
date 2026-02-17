"""
Tests for SCS Rate Limiting — per-participant token quotas.

Covers: participant resolution, quota checks, token recording,
sliding window eviction, per-participant isolation, quota overrides,
token estimation, reset, get_all_usage, and the REST endpoint.
"""

import time
from unittest.mock import patch

import pytest

from citadel_archer.chat.scs_quota import (
    DEFAULT_QUOTAS,
    MAX_CALL_ESTIMATE,
    MIN_CALL_ESTIMATE,
    SCSQuotaTracker,
    TOKENS_PER_CHAR_ESTIMATE,
    WINDOW_SECONDS,
    get_scs_quota_tracker,
)


# ===================================================================
# Helpers
# ===================================================================


def _make_tracker(**kwargs) -> SCSQuotaTracker:
    """Create a fresh tracker for testing."""
    return SCSQuotaTracker(**kwargs)


# ===================================================================
# TestParticipantResolution
# ===================================================================


class TestParticipantResolution:
    """Verify participant ID to type mapping."""

    def test_user_resolves_to_user(self):
        assert SCSQuotaTracker.resolve_participant_type("user") == "user"

    def test_ext_agent_resolves_to_ext_agent(self):
        assert SCSQuotaTracker.resolve_participant_type("ext-agent:forge-abc") == "ext-agent"

    def test_citadel_resolves_to_citadel(self):
        assert SCSQuotaTracker.resolve_participant_type("citadel") == "citadel"

    def test_unknown_resolves_to_citadel(self):
        # Unknown participants default to citadel (system) type
        assert SCSQuotaTracker.resolve_participant_type("agent:vps-1") == "citadel"


# ===================================================================
# TestQuotaCheck
# ===================================================================


class TestQuotaCheck:
    """Verify pre-call quota gating."""

    def test_under_quota_allowed(self):
        tracker = _make_tracker()
        allowed, info = tracker.check("user", estimated_tokens=2000)
        assert allowed is True
        assert info["reason"] == "ok"
        assert info["remaining"] == DEFAULT_QUOTAS["user"]

    def test_at_quota_denied(self):
        tracker = _make_tracker(quotas={"user": 5000})
        # Record tokens up to quota
        tracker.record("user", 5000)
        # Next check should be denied
        allowed, info = tracker.check("user", estimated_tokens=2000)
        assert allowed is False
        assert "exceeded" in info["reason"].lower()
        assert info["used"] == 5000
        assert info["remaining"] == 0

    def test_remaining_decreases(self):
        tracker = _make_tracker(quotas={"user": 10000})
        tracker.record("user", 3000)
        allowed, info = tracker.check("user", estimated_tokens=2000)
        assert allowed is True
        assert info["remaining"] == 7000
        assert info["used"] == 3000

    def test_zero_estimated_always_allowed(self):
        tracker = _make_tracker(quotas={"user": 100})
        tracker.record("user", 100)
        # Zero estimate means "just checking" — remaining is 0 but 0 <= 0
        # Actually 0 > 0 is False, so check passes
        allowed, info = tracker.check("user", estimated_tokens=0)
        assert allowed is True

    def test_exact_remaining_allowed(self):
        tracker = _make_tracker(quotas={"user": 10000})
        tracker.record("user", 8000)
        # Exactly 2000 remaining, estimate 2000 — should be denied
        # because estimated(2000) > remaining(2000) is False
        allowed, info = tracker.check("user", estimated_tokens=2000)
        assert allowed is True

    def test_one_over_denied(self):
        tracker = _make_tracker(quotas={"user": 10000})
        tracker.record("user", 8001)
        # 1999 remaining, estimate 2000 — denied
        allowed, info = tracker.check("user", estimated_tokens=2000)
        assert allowed is False


# ===================================================================
# TestTokenRecording
# ===================================================================


class TestTokenRecording:
    """Verify post-call token recording."""

    def test_record_accumulates(self):
        tracker = _make_tracker()
        tracker.record("user", 1000)
        tracker.record("user", 2000)
        _, info = tracker.check("user")
        assert info["used"] == 3000

    def test_record_zero_ignored(self):
        tracker = _make_tracker()
        tracker.record("user", 0)
        _, info = tracker.check("user")
        assert info["used"] == 0

    def test_record_negative_ignored(self):
        tracker = _make_tracker()
        tracker.record("user", -100)
        _, info = tracker.check("user")
        assert info["used"] == 0


# ===================================================================
# TestSlidingWindow
# ===================================================================


class TestSlidingWindow:
    """Verify rolling window eviction with time mocking."""

    def test_window_evicts_old_entries(self):
        tracker = _make_tracker(quotas={"user": 5000})
        tracker.record("user", 5000)

        # Verify denied now
        allowed, _ = tracker.check("user", estimated_tokens=2000)
        assert allowed is False

        # Advance past the window
        future = time.monotonic() + WINDOW_SECONDS + 1
        with patch("citadel_archer.chat.scs_quota.time.monotonic", return_value=future):
            allowed, info = tracker.check("user", estimated_tokens=2000)
            assert allowed is True
            assert info["used"] == 0

    def test_partial_eviction(self):
        tracker = _make_tracker(quotas={"user": 10000})
        now = time.monotonic()

        # Record old entry (will be evicted)
        with patch("citadel_archer.chat.scs_quota.time.monotonic", return_value=now):
            tracker.record("user", 3000)

        # Record recent entry (will survive)
        recent = now + WINDOW_SECONDS - 100
        with patch("citadel_archer.chat.scs_quota.time.monotonic", return_value=recent):
            tracker.record("user", 2000)

        # Check at a time where old entry expired but recent survives
        check_time = now + WINDOW_SECONDS + 1
        with patch("citadel_archer.chat.scs_quota.time.monotonic", return_value=check_time):
            _, info = tracker.check("user")
            assert info["used"] == 2000  # only recent entry remains


# ===================================================================
# TestPerParticipantIsolation
# ===================================================================


class TestPerParticipantIsolation:
    """Verify independent windows per participant."""

    def test_independent_windows(self):
        tracker = _make_tracker(quotas={"user": 5000, "ext-agent": 5000})
        tracker.record("user", 4000)
        tracker.record("ext-agent:forge", 1000)

        _, user_info = tracker.check("user")
        _, agent_info = tracker.check("ext-agent:forge")

        assert user_info["used"] == 4000
        assert agent_info["used"] == 1000

    def test_two_ext_agents_separate_windows(self):
        tracker = _make_tracker(quotas={"ext-agent": 5000})
        tracker.record("ext-agent:forge", 3000)
        tracker.record("ext-agent:openclaw", 2000)

        _, forge_info = tracker.check("ext-agent:forge")
        _, openclaw_info = tracker.check("ext-agent:openclaw")

        assert forge_info["used"] == 3000
        assert openclaw_info["used"] == 2000


# ===================================================================
# TestQuotaOverrides
# ===================================================================


class TestQuotaOverrides:
    """Verify quota customization."""

    def test_set_quota_for_type(self):
        tracker = _make_tracker()
        tracker.set_quota("user", 1000)
        tracker.record("user", 999)
        allowed, _ = tracker.check("user", estimated_tokens=2000)
        assert allowed is False

    def test_set_quota_for_specific_id(self):
        tracker = _make_tracker()
        # Override specific agent to have a higher quota
        tracker.set_quota("ext-agent:forge", 100_000)
        tracker.record("ext-agent:forge", 60_000)

        # forge should use the per-ID override (100K), not type default (50K)
        allowed, info = tracker.check("ext-agent:forge", estimated_tokens=2000)
        assert allowed is True
        assert info["quota"] == 100_000

        # openclaw should still use the type default (50K)
        _, other_info = tracker.check("ext-agent:openclaw")
        assert other_info["quota"] == DEFAULT_QUOTAS["ext-agent"]


# ===================================================================
# TestEstimation
# ===================================================================


class TestEstimation:
    """Verify token estimation for pre-call gating."""

    def test_short_text_gets_min_estimate(self):
        result = SCSQuotaTracker.estimate_tokens("hi")
        assert result == MIN_CALL_ESTIMATE

    def test_long_text_capped_at_max(self):
        result = SCSQuotaTracker.estimate_tokens("A" * 50000)
        assert result == MAX_CALL_ESTIMATE

    def test_moderate_text_proportional(self):
        text = "A" * 5000  # 5000 chars * 0.3 = 1500 + 2000 overhead = 3500
        result = SCSQuotaTracker.estimate_tokens(text)
        expected = int(5000 * TOKENS_PER_CHAR_ESTIMATE) + MIN_CALL_ESTIMATE
        assert result == expected

    def test_empty_text_gets_min(self):
        assert SCSQuotaTracker.estimate_tokens("") == MIN_CALL_ESTIMATE

    def test_none_text_gets_min(self):
        assert SCSQuotaTracker.estimate_tokens(None) == MIN_CALL_ESTIMATE


# ===================================================================
# TestReset
# ===================================================================


class TestReset:
    """Verify window reset operations."""

    def test_reset_single_participant(self):
        tracker = _make_tracker()
        tracker.record("user", 5000)
        tracker.reset("user")
        _, info = tracker.check("user")
        assert info["used"] == 0

    def test_reset_all(self):
        tracker = _make_tracker()
        tracker.record("user", 5000)
        tracker.record("ext-agent:forge", 3000)
        tracker.reset_all()
        _, user_info = tracker.check("user")
        _, agent_info = tracker.check("ext-agent:forge")
        assert user_info["used"] == 0
        assert agent_info["used"] == 0

    def test_reset_nonexistent_no_crash(self):
        tracker = _make_tracker()
        tracker.reset("nonexistent")  # should not raise


# ===================================================================
# TestGetAllUsage
# ===================================================================


class TestGetAllUsage:
    """Verify the usage summary for REST endpoint."""

    def test_returns_tracked_participants(self):
        tracker = _make_tracker()
        tracker.record("user", 1000)
        tracker.record("ext-agent:forge", 500)
        usage = tracker.get_all_usage()

        assert "user" in usage
        assert usage["user"]["used"] == 1000
        assert usage["user"]["participant_type"] == "user"

        assert "ext-agent:forge" in usage
        assert usage["ext-agent:forge"]["used"] == 500

    def test_includes_default_types(self):
        tracker = _make_tracker()
        # No recording — all types should appear as defaults
        usage = tracker.get_all_usage()
        default_types = {v["participant_type"] for v in usage.values()}
        assert "user" in default_types
        assert "ext-agent" in default_types
        assert "citadel" in default_types


# ===================================================================
# TestSingleton
# ===================================================================


class TestSingleton:
    """Verify module-level singleton."""

    def test_same_instance(self):
        import citadel_archer.chat.scs_quota as mod
        old = mod._scs_quota_tracker
        try:
            mod._scs_quota_tracker = None
            a = get_scs_quota_tracker()
            b = get_scs_quota_tracker()
            assert a is b
        finally:
            mod._scs_quota_tracker = old


# ===================================================================
# TestSCSQuotaEndpoint
# ===================================================================


class TestSCSQuotaEndpoint:
    """Test the GET /api/scs-quota endpoint."""

    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient
        from citadel_archer.api.main import app
        return TestClient(app)

    @pytest.fixture(autouse=True)
    def _set_session_token(self):
        from citadel_archer.api.security import initialize_session_token, get_session_token
        initialize_session_token()
        self._token = get_session_token()

    def test_requires_auth(self, client):
        resp = client.get("/api/scs-quota")
        assert resp.status_code in (401, 403)

    def test_returns_quota_data(self, client):
        resp = client.get(
            "/api/scs-quota",
            headers={"X-Session-Token": self._token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "participants" in data
        assert "defaults" in data
        assert "window_seconds" in data
        assert data["window_seconds"] == WINDOW_SECONDS

    def test_reflects_recorded_usage(self, client):
        # Record some usage
        tracker = get_scs_quota_tracker()
        tracker.record("user", 1234)

        resp = client.get(
            "/api/scs-quota",
            headers={"X-Session-Token": self._token},
        )
        data = resp.json()
        participants = data["participants"]
        # User should show usage
        if "user" in participants:
            assert participants["user"]["used"] >= 1234
