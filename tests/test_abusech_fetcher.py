"""
Tests for abuse.ch Feed Fetcher (URLhaus + ThreatFox).

All HTTP calls are mocked — no external network access required.
Covers: configuration, URLhaus parsing, ThreatFox parsing, time filtering,
retry logic, health check, IOC type mapping, severity mapping.
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import httpx
import pytest

from citadel_archer.intel.models import (
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
)
from citadel_archer.intel.abusech_fetcher import (
    URLHAUS_API_URL,
    THREATFOX_API_URL,
    AbuseChFetchError,
    AbuseChFetcher,
    _THREATFOX_TYPE_MAP,
    _URLHAUS_THREAT_MAP,
)


# ===================================================================
# Fixtures & helpers
# ===================================================================

@pytest.fixture
def fetcher():
    f = AbuseChFetcher()
    f.configure()
    return f


def _mock_response(status_code=200, json_data=None, headers=None):
    """Create a mock httpx.Response."""
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


def _urlhaus_entry(
    url="https://evil.com/malware.exe",
    threat="malware_download",
    date_added="2026-02-10 12:00:00",
    entry_id="12345",
    tags=None,
    host="evil.com",
    url_status="online",
):
    return {
        "id": entry_id,
        "url": url,
        "threat": threat,
        "date_added": date_added,
        "tags": tags,
        "host": host,
        "url_status": url_status,
    }


def _threatfox_entry(
    ioc_type="ip:port",
    ioc_value="1.2.3.4:443",
    malware="Cobalt Strike",
    threat_type="botnet_cc",
    confidence=75,
    first_seen="2026-02-10 12:00:00",
    entry_id="99999",
    tags=None,
    reporter="testuser",
):
    return {
        "id": entry_id,
        "ioc_type": ioc_type,
        "ioc": ioc_value,
        "malware_printable": malware,
        "threat_type_desc": threat_type,
        "confidence_level": confidence,
        "first_seen_utc": first_seen,
        "tags": tags,
        "reporter": reporter,
    }


# ===================================================================
# Configuration
# ===================================================================

class TestAbuseChConfiguration:
    def test_default_name(self):
        f = AbuseChFetcher()
        assert f.name == "abuse-ch"

    def test_default_feeds_enabled(self, fetcher):
        assert fetcher._enabled_feeds["urlhaus"] is True
        assert fetcher._enabled_feeds["threatfox"] is True

    def test_configure_urls(self):
        f = AbuseChFetcher()
        f.configure(
            urlhaus_url="https://custom-urlhaus.local",
            threatfox_url="https://custom-threatfox.local",
        )
        assert f._urlhaus_url == "https://custom-urlhaus.local"
        assert f._threatfox_url == "https://custom-threatfox.local"

    def test_configure_limits(self):
        f = AbuseChFetcher()
        f.configure(max_urlhaus=100, max_threatfox=200, days_back=14)
        assert f._max_urlhaus == 100
        assert f._max_threatfox == 200
        assert f._days_back == 14

    def test_disable_feeds(self):
        f = AbuseChFetcher()
        f.configure(enable_urlhaus=False, enable_threatfox=False)
        assert f._enabled_feeds["urlhaus"] is False
        assert f._enabled_feeds["threatfox"] is False


# ===================================================================
# URLhaus Parsing
# ===================================================================

class TestURLhausParsing:
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_urlhaus_entry(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry()],
        })
        items = fetcher._fetch_urlhaus()
        assert len(items) == 1
        item = items[0]
        assert item.intel_type == IntelType.IOC
        assert item.payload.ioc_type == IOCType.URL
        assert item.payload.value == "https://evil.com/malware.exe"
        assert item.source_feed == "abuse-ch"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_severity_mapping_malware_download(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(threat="malware_download")],
        })
        items = fetcher._fetch_urlhaus()
        assert items[0].payload.severity == IntelSeverity.HIGH

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_severity_mapping_distribution(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(threat="malware_distribution")],
        })
        items = fetcher._fetch_urlhaus()
        assert items[0].payload.severity == IntelSeverity.CRITICAL

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_severity_mapping_unknown_threat(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(threat="unknown_type")],
        })
        items = fetcher._fetch_urlhaus()
        assert items[0].payload.severity == IntelSeverity.MEDIUM

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_empty_url_skipped(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(url="")],
        })
        items = fetcher._fetch_urlhaus()
        assert len(items) == 0

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_tags_as_string_split(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(tags="emotet,malware")],
        })
        items = fetcher._fetch_urlhaus()
        assert items[0].payload.tags == ["emotet", "malware"]

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_tags_as_list(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(tags=["emotet", "malware"])],
        })
        items = fetcher._fetch_urlhaus()
        assert items[0].payload.tags == ["emotet", "malware"]

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_time_filter_excludes_old(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [
                _urlhaus_entry(date_added="2026-01-01 00:00:00"),
                _urlhaus_entry(url="https://new.com", date_added="2026-02-14 12:00:00"),
            ],
        })
        items = fetcher._fetch_urlhaus(since="2026-02-01T00:00:00")
        assert len(items) == 1
        assert items[0].payload.value == "https://new.com"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_raw_data_fields(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "urls": [_urlhaus_entry(entry_id="42", threat="phishing", host="bad.com")],
        })
        items = fetcher._fetch_urlhaus()
        raw = items[0].raw_data
        assert raw["urlhaus_id"] == "42"
        assert raw["threat"] == "phishing"
        assert raw["host"] == "bad.com"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_empty_response(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {"urls": []})
        items = fetcher._fetch_urlhaus()
        assert items == []


# ===================================================================
# ThreatFox Parsing
# ===================================================================

class TestThreatFoxParsing:
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_ip_port_entry(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="ip:port", ioc_value="1.2.3.4:443")],
        })
        items = fetcher._fetch_threatfox()
        assert len(items) == 1
        assert items[0].payload.ioc_type == IOCType.IP_ADDRESS
        assert items[0].payload.value == "1.2.3.4"  # Port stripped

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_ipv6_port_entry(self, mock_request, fetcher):
        """IPv6 bracketed ip:port should extract IP without brackets."""
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="ip:port", ioc_value="[2001:db8::1]:443")],
        })
        items = fetcher._fetch_threatfox()
        assert len(items) == 1
        assert items[0].payload.value == "2001:db8::1"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_domain_entry(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="domain", ioc_value="evil.example.com")],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.ioc_type == IOCType.DOMAIN
        assert items[0].payload.value == "evil.example.com"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_url_entry(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="url", ioc_value="https://evil.com/payload")],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.ioc_type == IOCType.URL

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_parse_sha256_entry(self, mock_request, fetcher):
        h = "a" * 64
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="sha256_hash", ioc_value=h)],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.ioc_type == IOCType.FILE_HASH_SHA256

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_unknown_type_skipped(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(ioc_type="unknown_type", ioc_value="foo")],
        })
        items = fetcher._fetch_threatfox()
        assert len(items) == 0

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_confidence_high_severity(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(confidence=90)],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.severity == IntelSeverity.HIGH

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_confidence_medium_severity(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(confidence=50)],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.severity == IntelSeverity.MEDIUM

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_confidence_low_severity(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(confidence=10)],
        })
        items = fetcher._fetch_threatfox()
        assert items[0].payload.severity == IntelSeverity.LOW

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_no_result_status(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "no_result",
        })
        items = fetcher._fetch_threatfox()
        assert items == []

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_time_filter_excludes_old(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [
                _threatfox_entry(first_seen="2026-01-01 00:00:00", ioc_value="1.2.3.4:80"),
                _threatfox_entry(first_seen="2026-02-14 12:00:00", ioc_value="5.6.7.8:443"),
            ],
        })
        items = fetcher._fetch_threatfox(since="2026-02-01T00:00:00")
        assert len(items) == 1
        assert items[0].payload.value == "5.6.7.8"

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_malware_in_description(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(malware="Emotet")],
        })
        items = fetcher._fetch_threatfox()
        assert "Emotet" in items[0].payload.description

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_raw_data_fields(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry(entry_id="777", malware="Agent Tesla", reporter="bob")],
        })
        items = fetcher._fetch_threatfox()
        raw = items[0].raw_data
        assert raw["threatfox_id"] == "777"
        assert raw["malware"] == "Agent Tesla"
        assert raw["reporter"] == "bob"


# ===================================================================
# Full fetch() integration
# ===================================================================

class TestFetchIntegration:
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_fetch_combines_both_feeds(self, mock_request, fetcher):
        # First call: URLhaus, Second call: ThreatFox
        mock_request.side_effect = [
            _mock_response(200, {
                "urls": [_urlhaus_entry()],
            }),
            _mock_response(200, {
                "query_status": "ok",
                "data": [_threatfox_entry()],
            }),
        ]
        items = fetcher.fetch()
        assert len(items) == 2
        assert all(i.intel_type == IntelType.IOC for i in items)

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_fetch_only_urlhaus(self, mock_request):
        f = AbuseChFetcher()
        f.configure(enable_threatfox=False)
        mock_request.return_value = _mock_response(200, {"urls": [_urlhaus_entry()]})
        items = f.fetch()
        assert len(items) == 1
        assert mock_request.call_count == 1

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_fetch_only_threatfox(self, mock_request):
        f = AbuseChFetcher()
        f.configure(enable_urlhaus=False)
        mock_request.return_value = _mock_response(200, {
            "query_status": "ok",
            "data": [_threatfox_entry()],
        })
        items = f.fetch()
        assert len(items) == 1
        assert mock_request.call_count == 1

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_fetch_records_stats(self, mock_request, fetcher):
        mock_request.side_effect = [
            _mock_response(200, {"urls": [_urlhaus_entry()]}),
            _mock_response(200, {"query_status": "ok", "data": [_threatfox_entry()]}),
        ]
        fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_fetched"] == 2
        assert stats["total_errors"] == 0

    @patch("citadel_archer.intel.abusech_fetcher.time.sleep")
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_fetch_records_error(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(AbuseChFetchError):
            fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_errors"] == 1


# ===================================================================
# Retry Logic
# ===================================================================

class TestRetryLogic:
    @patch("citadel_archer.intel.abusech_fetcher.time.sleep")
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_retry_on_500(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(500),
            _mock_response(200, {"urls": []}),
        ]
        resp = fetcher._request("POST", f"{URLHAUS_API_URL}/urls/recent/")
        assert resp.status_code == 200
        assert mock_request.call_count == 2

    @patch("citadel_archer.intel.abusech_fetcher.time.sleep")
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_retry_on_429(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(429, headers={"Retry-After": "3"}),
            _mock_response(200, {"query_status": "ok", "data": []}),
        ]
        resp = fetcher._request("POST", f"{THREATFOX_API_URL}/")
        assert resp.status_code == 200
        mock_sleep.assert_called_with(3.0)

    @patch("citadel_archer.intel.abusech_fetcher.time.sleep")
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_exhausted_retries_raises(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(AbuseChFetchError, match="failed after 3 attempts"):
            fetcher._request("POST", f"{URLHAUS_API_URL}/urls/recent/")


# ===================================================================
# Health Check
# ===================================================================

class TestHealthCheck:
    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_healthy_both_feeds(self, mock_request, fetcher):
        """Both URLhaus and ThreatFox must be reachable."""
        mock_request.return_value = _mock_response(200, {"query_status": "ok"})
        assert fetcher.health_check() is True
        assert mock_request.call_count == 2  # one for each feed

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_unhealthy(self, mock_request, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        assert fetcher.health_check() is False

    @patch("citadel_archer.intel.abusech_fetcher.httpx.request")
    def test_healthy_single_feed(self, mock_request):
        """When only one feed is enabled, only that one is checked."""
        f = AbuseChFetcher()
        f.configure(enable_urlhaus=False)
        mock_request.return_value = _mock_response(200, {"query_status": "ok"})
        assert f.health_check() is True
        assert mock_request.call_count == 1


# ===================================================================
# Type Mapping
# ===================================================================

class TestTypeMapping:
    def test_threatfox_types_mapped(self):
        expected = {"ip:port", "domain", "url", "md5_hash", "sha1_hash", "sha256_hash"}
        assert set(_THREATFOX_TYPE_MAP.keys()) == expected

    def test_urlhaus_threat_types_mapped(self):
        assert "malware_download" in _URLHAUS_THREAT_MAP
        assert "phishing" in _URLHAUS_THREAT_MAP
        assert "malware_distribution" in _URLHAUS_THREAT_MAP


# ===================================================================
# Time parsing
# ===================================================================

class TestTimeParsing:
    def test_parse_since_valid(self, fetcher):
        result = fetcher._parse_since("2026-02-01T00:00:00")
        assert result is not None
        assert result.year == 2026
        assert result.month == 2

    def test_parse_since_none(self, fetcher):
        assert fetcher._parse_since(None) is None

    def test_parse_since_invalid(self, fetcher):
        assert fetcher._parse_since("not-a-date") is None

    def test_parse_since_with_z(self, fetcher):
        result = fetcher._parse_since("2026-02-01T00:00:00Z")
        assert result is not None
