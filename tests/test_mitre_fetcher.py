"""
Tests for MITRE ATT&CK Feed Fetcher.

All HTTP calls are mocked — no external network access required.
Covers: configuration, STIX bundle parsing, attack-pattern extraction,
tactic mapping, platform filtering, time filtering, retry logic, health check.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from citadel_archer.intel.models import (
    TTP,
    IntelItem,
    IntelSeverity,
    IntelType,
)
from citadel_archer.intel.mitre_fetcher import (
    DEFAULT_STIX_URL,
    MitreFetchError,
    MitreFetcher,
)


# ===================================================================
# Fixtures & helpers
# ===================================================================

@pytest.fixture
def fetcher():
    f = MitreFetcher()
    f.configure()
    return f


def _mock_response(status_code=200, json_data=None, headers=None):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    resp.headers = headers or {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    return resp


def _attack_pattern(
    stix_id="attack-pattern--1234",
    technique_id="T1059",
    name="Command and Scripting Interpreter",
    tactic="execution",
    description="Adversaries may abuse command interpreters.",
    platforms=None,
    data_sources=None,
    revoked=False,
    deprecated=False,
    modified="2026-01-15T00:00:00Z",
    created="2024-01-01T00:00:00Z",
    references=None,
):
    """Build a minimal STIX attack-pattern object."""
    obj = {
        "type": "attack-pattern",
        "id": stix_id,
        "name": name,
        "description": description,
        "x_mitre_platforms": platforms or ["Windows", "Linux"],
        "x_mitre_data_sources": data_sources or [],
        "revoked": revoked,
        "x_mitre_deprecated": deprecated,
        "modified": modified,
        "created": created,
        "kill_chain_phases": [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": tactic,
            }
        ],
        "external_references": references or [
            {
                "source_name": "mitre-attack",
                "external_id": technique_id,
                "url": f"https://attack.mitre.org/techniques/{technique_id}",
            }
        ],
    }
    return obj


def _stix_bundle(objects=None):
    """Build a minimal STIX 2.1 bundle."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": objects or [],
    }


# ===================================================================
# Configuration
# ===================================================================

class TestMitreConfiguration:
    def test_default_name(self):
        f = MitreFetcher()
        assert f.name == "mitre-attack"

    def test_configure_url(self):
        f = MitreFetcher()
        f.configure(stix_url="https://custom.mitre.local/bundle.json")
        assert f._stix_url == "https://custom.mitre.local/bundle.json"

    def test_configure_max_techniques(self):
        f = MitreFetcher()
        f.configure(max_techniques=500)
        assert f._max_techniques == 500

    def test_configure_platforms_filter(self):
        f = MitreFetcher()
        f.configure(platforms=["windows"])
        assert f._platforms_filter == ["windows"]

    def test_default_stix_url(self, fetcher):
        assert fetcher._stix_url == DEFAULT_STIX_URL


# ===================================================================
# Attack Pattern Parsing
# ===================================================================

class TestAttackPatternParsing:
    def test_parse_basic_technique(self, fetcher):
        bundle = _stix_bundle([_attack_pattern()])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 1
        item = items[0]
        assert item.intel_type == IntelType.TTP
        assert item.payload.technique_id == "T1059"
        assert item.payload.name == "Command and Scripting Interpreter"
        assert item.payload.tactic == "execution"

    def test_technique_platforms(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(platforms=["Windows", "Linux", "macOS"]),
        ])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.platforms == ["Windows", "Linux", "macOS"]

    def test_technique_references(self, fetcher):
        bundle = _stix_bundle([_attack_pattern()])
        items = fetcher._parse_bundle(bundle)
        refs = items[0].payload.references
        assert any("attack.mitre.org" in r for r in refs)

    def test_sub_technique_high_severity(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(technique_id="T1059.001", name="PowerShell"),
        ])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.severity == IntelSeverity.HIGH

    def test_technique_medium_severity(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(technique_id="T1059", name="Command Interpreter"),
        ])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.severity == IntelSeverity.MEDIUM

    def test_revoked_technique_skipped(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(revoked=True),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 0

    def test_deprecated_technique_skipped(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(deprecated=True),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 0

    def test_no_technique_id_skipped(self, fetcher):
        obj = _attack_pattern()
        obj["external_references"] = []  # no mitre-attack reference
        bundle = _stix_bundle([obj])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 0

    def test_description_truncated(self, fetcher):
        long_desc = "A" * 1000
        bundle = _stix_bundle([
            _attack_pattern(description=long_desc),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items[0].payload.description) <= 503  # 500 + "..."

    def test_non_attack_pattern_ignored(self, fetcher):
        bundle = _stix_bundle([
            {"type": "malware", "id": "malware--1234", "name": "Emotet"},
            _attack_pattern(),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 1

    def test_multiple_techniques(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", technique_id="T1059"),
            _attack_pattern(stix_id="ap--2", technique_id="T1053"),
            _attack_pattern(stix_id="ap--3", technique_id="T1078"),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 3
        ids = {i.payload.technique_id for i in items}
        assert ids == {"T1059", "T1053", "T1078"}


# ===================================================================
# Tactic Mapping
# ===================================================================

class TestTacticMapping:
    def test_tactic_from_kill_chain(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(tactic="persistence"),
        ])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.tactic == "persistence"

    def test_multiple_tactics_uses_first(self, fetcher):
        obj = _attack_pattern()
        obj["kill_chain_phases"] = [
            {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
            {"kill_chain_name": "mitre-attack", "phase_name": "persistence"},
        ]
        bundle = _stix_bundle([obj])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.tactic == "execution"

    def test_no_kill_chain_defaults_unknown(self, fetcher):
        obj = _attack_pattern()
        obj["kill_chain_phases"] = []
        bundle = _stix_bundle([obj])
        items = fetcher._parse_bundle(bundle)
        assert items[0].payload.tactic == "unknown"


# ===================================================================
# Platform Filtering
# ===================================================================

class TestPlatformFiltering:
    def test_filter_windows_only(self):
        f = MitreFetcher()
        f.configure(platforms=["windows"])
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", platforms=["Windows", "Linux"]),
            _attack_pattern(stix_id="ap--2", platforms=["macOS"]),
        ])
        items = f._parse_bundle(bundle)
        assert len(items) == 1
        assert items[0].payload.technique_id == "T1059"

    def test_filter_linux_only(self):
        f = MitreFetcher()
        f.configure(platforms=["linux"])
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", platforms=["Windows"]),
            _attack_pattern(stix_id="ap--2", platforms=["Linux"]),
        ])
        items = f._parse_bundle(bundle)
        assert len(items) == 1

    def test_no_filter_returns_all(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", platforms=["Windows"]),
            _attack_pattern(stix_id="ap--2", platforms=["macOS"]),
        ])
        items = fetcher._parse_bundle(bundle)
        assert len(items) == 2


# ===================================================================
# Time Filtering
# ===================================================================

class TestTimeFiltering:
    def test_since_filter_excludes_old(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", modified="2025-01-01T00:00:00Z"),
            _attack_pattern(stix_id="ap--2", modified="2026-02-01T00:00:00Z"),
        ])
        items = fetcher._parse_bundle(bundle, since="2026-01-01T00:00:00Z")
        assert len(items) == 1

    def test_no_since_returns_all(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(stix_id="ap--1", modified="2024-01-01T00:00:00Z"),
            _attack_pattern(stix_id="ap--2", modified="2026-01-01T00:00:00Z"),
        ])
        items = fetcher._parse_bundle(bundle, since=None)
        assert len(items) == 2


# ===================================================================
# Max Techniques Limit
# ===================================================================

class TestMaxTechniques:
    def test_max_techniques_cap(self):
        f = MitreFetcher()
        f.configure(max_techniques=2)
        objects = [
            _attack_pattern(stix_id=f"ap--{i}", technique_id=f"T{i}")
            for i in range(5)
        ]
        bundle = _stix_bundle(objects)
        items = f._parse_bundle(bundle)
        assert len(items) == 2


# ===================================================================
# Raw Data
# ===================================================================

class TestRawData:
    def test_raw_data_fields(self, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(stix_id="attack-pattern--abc", technique_id="T1059"),
        ])
        items = fetcher._parse_bundle(bundle)
        raw = items[0].raw_data
        assert raw["stix_id"] == "attack-pattern--abc"
        assert raw["technique_id"] == "T1059"
        assert "tactics" in raw
        assert "modified" in raw

    def test_source_feed(self, fetcher):
        bundle = _stix_bundle([_attack_pattern()])
        items = fetcher._parse_bundle(bundle)
        assert items[0].source_feed == "mitre-attack"


# ===================================================================
# Retry Logic
# ===================================================================

class TestRetryLogic:
    @patch("citadel_archer.intel.mitre_fetcher.time.sleep")
    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_retry_on_500(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(500),
            _mock_response(200, _stix_bundle([_attack_pattern()])),
        ]
        resp = fetcher._request("GET", DEFAULT_STIX_URL)
        assert resp.status_code == 200
        assert mock_request.call_count == 2

    @patch("citadel_archer.intel.mitre_fetcher.time.sleep")
    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_exhausted_retries_raises(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(MitreFetchError, match="failed after 3 attempts"):
            fetcher._request("GET", DEFAULT_STIX_URL)


# ===================================================================
# Health Check
# ===================================================================

class TestHealthCheck:
    @patch("citadel_archer.intel.mitre_fetcher.httpx.head")
    def test_healthy(self, mock_head, fetcher):
        resp = MagicMock()
        resp.status_code = 200
        mock_head.return_value = resp
        assert fetcher.health_check() is True

    @patch("citadel_archer.intel.mitre_fetcher.httpx.head")
    def test_unhealthy(self, mock_head, fetcher):
        mock_head.side_effect = httpx.ConnectError("down")
        assert fetcher.health_check() is False


# ===================================================================
# Full fetch() integration
# ===================================================================

class TestFetchIntegration:
    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_fetch_returns_ttp_items(self, mock_request, fetcher):
        bundle = _stix_bundle([
            _attack_pattern(technique_id="T1059"),
            _attack_pattern(stix_id="ap--2", technique_id="T1053"),
        ])
        mock_request.return_value = _mock_response(200, bundle)
        items = fetcher.fetch()
        assert len(items) == 2
        assert all(i.intel_type == IntelType.TTP for i in items)

    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_fetch_records_stats(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, _stix_bundle([_attack_pattern()]))
        fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_fetched"] == 1
        assert stats["total_errors"] == 0

    @patch("citadel_archer.intel.mitre_fetcher.time.sleep")
    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_fetch_records_error(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(MitreFetchError):
            fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_errors"] == 1

    @patch("citadel_archer.intel.mitre_fetcher.httpx.request")
    def test_fetch_empty_bundle(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, _stix_bundle([]))
        items = fetcher.fetch()
        assert items == []
