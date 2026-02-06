"""
Tests for T2: AlienVault OTX Feed Fetcher.

All HTTP calls are mocked — no external network access required.
Covers: configuration, pulse fetching, CVE/IOC parsing, pagination,
retry logic with exponential backoff, error handling.
"""

import json
import time
from unittest.mock import MagicMock, patch, call

import httpx
import pytest

from citadel_archer.intel.models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
)
from citadel_archer.intel.otx_fetcher import (
    DEFAULT_BASE_URL,
    MAX_RETRIES,
    OTXFetchError,
    OTXFetcher,
    _OTX_TYPE_MAP,
)


# ===================================================================
# Fixtures & helpers
# ===================================================================

@pytest.fixture
def fetcher():
    f = OTXFetcher()
    f.configure(api_key="test-key-123")
    return f


def _pulse(
    pulse_id="abc123",
    name="Test Pulse",
    tags=None,
    references=None,
    description="",
    indicators=None,
    created="2024-06-01T00:00:00",
):
    """Build a minimal OTX pulse dict."""
    return {
        "id": pulse_id,
        "name": name,
        "tags": tags or [],
        "references": references or [],
        "description": description,
        "indicators": indicators or [],
        "created": created,
        "modified": created,
    }


def _indicator(ind_type="IPv4", value="10.0.0.1", ind_id="ind1", description=""):
    """Build a minimal OTX indicator dict."""
    return {
        "id": ind_id,
        "type": ind_type,
        "indicator": value,
        "description": description,
        "created": "2024-06-01T00:00:00",
    }


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


# ===================================================================
# Configuration
# ===================================================================

class TestOTXConfiguration:
    def test_default_name(self):
        f = OTXFetcher()
        assert f.name == "alienvault-otx"

    def test_configure_api_key(self, fetcher):
        assert fetcher._api_key == "test-key-123"

    def test_configure_base_url(self):
        f = OTXFetcher()
        f.configure(base_url="https://custom.otx.local")
        assert f._base_url == "https://custom.otx.local"

    def test_configure_max_pages(self):
        f = OTXFetcher()
        f.configure(max_pages=5)
        assert f._max_pages == 5

    def test_default_base_url(self):
        f = OTXFetcher()
        f.configure()
        assert f._base_url == DEFAULT_BASE_URL

    def test_no_api_key(self):
        f = OTXFetcher()
        f.configure()
        assert f._api_key is None


# ===================================================================
# Headers
# ===================================================================

class TestHeaders:
    def test_headers_with_key(self, fetcher):
        h = fetcher._build_headers()
        assert h["X-OTX-API-KEY"] == "test-key-123"
        assert h["Accept"] == "application/json"
        assert "User-Agent" in h

    def test_headers_without_key(self):
        f = OTXFetcher()
        f.configure()
        h = f._build_headers()
        assert "X-OTX-API-KEY" not in h


# ===================================================================
# CVE Extraction
# ===================================================================

class TestCVEExtraction:
    def test_cve_from_tags(self, fetcher):
        pulse = _pulse(tags=["CVE-2024-1234", "malware"])
        items = fetcher._extract_cves(pulse, "Test")
        assert len(items) == 1
        assert items[0].payload.cve_id == "CVE-2024-1234"
        assert items[0].intel_type == IntelType.CVE

    def test_cve_from_references(self, fetcher):
        pulse = _pulse(references=["https://nvd.nist.gov/vuln/detail/CVE-2024-5678"])
        items = fetcher._extract_cves(pulse, "Test")
        assert len(items) == 1
        assert items[0].payload.cve_id == "CVE-2024-5678"

    def test_cve_from_description(self, fetcher):
        pulse = _pulse(description="Exploiting CVE-2023-44487 in the wild")
        items = fetcher._extract_cves(pulse, "Test")
        assert len(items) == 1
        assert items[0].payload.cve_id == "CVE-2023-44487"

    def test_multiple_cves_deduped(self, fetcher):
        pulse = _pulse(
            tags=["CVE-2024-1234"],
            description="Also references CVE-2024-1234 and CVE-2024-9999",
        )
        items = fetcher._extract_cves(pulse, "Test")
        cve_ids = {i.payload.cve_id for i in items}
        assert cve_ids == {"CVE-2024-1234", "CVE-2024-9999"}

    def test_no_cves(self, fetcher):
        pulse = _pulse(tags=["malware"], description="No CVEs here")
        items = fetcher._extract_cves(pulse, "Test")
        assert items == []

    def test_cve_case_insensitive(self, fetcher):
        pulse = _pulse(tags=["cve-2024-0001"])
        items = fetcher._extract_cves(pulse, "Test")
        assert len(items) == 1
        assert items[0].payload.cve_id == "CVE-2024-0001"

    def test_cve_source_feed(self, fetcher):
        pulse = _pulse(tags=["CVE-2024-1234"])
        items = fetcher._extract_cves(pulse, "Test")
        assert items[0].source_feed == "alienvault-otx"

    def test_cve_raw_data(self, fetcher):
        pulse = _pulse(pulse_id="p1", tags=["CVE-2024-1234"])
        items = fetcher._extract_cves(pulse, "Test")
        assert items[0].raw_data["pulse_id"] == "p1"
        assert items[0].raw_data["cve_id"] == "CVE-2024-1234"


# ===================================================================
# IOC Extraction
# ===================================================================

class TestIOCExtraction:
    def test_ipv4_indicator(self, fetcher):
        indicators = [_indicator("IPv4", "192.168.1.1")]
        items = fetcher._extract_iocs(indicators, "Test", ["apt"], "p1")
        assert len(items) == 1
        assert items[0].payload.ioc_type == IOCType.IP_ADDRESS
        assert items[0].payload.value == "192.168.1.1"
        assert items[0].intel_type == IntelType.IOC

    def test_domain_indicator(self, fetcher):
        indicators = [_indicator("domain", "evil.example.com")]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items[0].payload.ioc_type == IOCType.DOMAIN

    def test_url_indicator(self, fetcher):
        indicators = [_indicator("URL", "https://evil.com/payload")]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items[0].payload.ioc_type == IOCType.URL

    def test_sha256_hash(self, fetcher):
        h = "a" * 64
        indicators = [_indicator("FileHash-SHA256", h)]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items[0].payload.ioc_type == IOCType.FILE_HASH_SHA256
        assert items[0].payload.value == h

    def test_md5_hash(self, fetcher):
        indicators = [_indicator("FileHash-MD5", "d41d8cd98f00b204e9800998ecf8427e")]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items[0].payload.ioc_type == IOCType.FILE_HASH_MD5

    def test_unknown_type_skipped(self, fetcher):
        indicators = [_indicator("YARA", "rule test {}")]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items == []

    def test_empty_value_skipped(self, fetcher):
        indicators = [_indicator("IPv4", "")]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert items == []

    def test_tags_propagated(self, fetcher):
        indicators = [_indicator("IPv4", "10.0.0.1")]
        items = fetcher._extract_iocs(indicators, "Test", ["c2", "apt28"], "p1")
        assert items[0].payload.tags == ["c2", "apt28"]

    def test_description_fallback(self, fetcher):
        indicators = [_indicator("IPv4", "10.0.0.1", description="")]
        items = fetcher._extract_iocs(indicators, "Test Pulse", [], "p1")
        assert "Test Pulse" in items[0].payload.description

    def test_multiple_indicators(self, fetcher):
        indicators = [
            _indicator("IPv4", "1.2.3.4"),
            _indicator("domain", "evil.com"),
            _indicator("FileHash-SHA1", "a" * 40),
        ]
        items = fetcher._extract_iocs(indicators, "Test", [], "p1")
        assert len(items) == 3

    def test_raw_data_includes_otx_type(self, fetcher):
        indicators = [_indicator("IPv4", "1.2.3.4", ind_id="ind99")]
        items = fetcher._extract_iocs(indicators, "Test", [], "pulse1")
        assert items[0].raw_data["pulse_id"] == "pulse1"
        assert items[0].raw_data["indicator_id"] == "ind99"
        assert items[0].raw_data["otx_type"] == "IPv4"


# ===================================================================
# Full Pulse Parsing
# ===================================================================

class TestPulseParsing:
    def test_parse_pulse_with_cves_and_iocs(self, fetcher):
        pulse = _pulse(
            tags=["CVE-2024-1234"],
            indicators=[
                _indicator("IPv4", "10.0.0.1"),
                _indicator("domain", "bad.com"),
            ],
        )
        items = fetcher._parse_pulses([pulse])
        types = {i.intel_type for i in items}
        assert IntelType.CVE in types
        assert IntelType.IOC in types
        assert len(items) == 3  # 1 CVE + 2 IOC

    def test_parse_empty_pulses(self, fetcher):
        assert fetcher._parse_pulses([]) == []

    def test_parse_multiple_pulses(self, fetcher):
        pulses = [
            _pulse(pulse_id="p1", tags=["CVE-2024-0001"]),
            _pulse(pulse_id="p2", tags=["CVE-2024-0002"]),
        ]
        items = fetcher._parse_pulses(pulses)
        cve_ids = {i.payload.cve_id for i in items if i.intel_type == IntelType.CVE}
        assert cve_ids == {"CVE-2024-0001", "CVE-2024-0002"}


# ===================================================================
# Pagination
# ===================================================================

class TestPagination:
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_single_page(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "results": [_pulse()],
            "next": None,
        })
        pulses = fetcher._fetch_pulses()
        assert len(pulses) == 1
        assert mock_request.call_count == 1

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_two_pages(self, mock_request, fetcher):
        mock_request.side_effect = [
            _mock_response(200, {
                "results": [_pulse(pulse_id="p1")],
                "next": f"{DEFAULT_BASE_URL}/api/v1/pulses/subscribed?page=2",
            }),
            _mock_response(200, {
                "results": [_pulse(pulse_id="p2")],
                "next": None,
            }),
        ]
        pulses = fetcher._fetch_pulses()
        assert len(pulses) == 2
        assert mock_request.call_count == 2

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_max_pages_limit(self, mock_request, fetcher):
        fetcher._max_pages = 2
        # Every page returns a next link
        mock_request.return_value = _mock_response(200, {
            "results": [_pulse()],
            "next": f"{DEFAULT_BASE_URL}/api/v1/pulses/subscribed?page=99",
        })
        pulses = fetcher._fetch_pulses()
        assert mock_request.call_count == 2  # stopped at max_pages

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_since_parameter(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "results": [],
            "next": None,
        })
        fetcher._fetch_pulses(since="2024-01-01T00:00:00")
        _, kwargs = mock_request.call_args
        assert kwargs["params"]["modified_since"] == "2024-01-01T00:00:00"


# ===================================================================
# Retry Logic
# ===================================================================

class TestRetryLogic:
    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_retry_on_500(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(500),
            _mock_response(500),
            _mock_response(200, {"results": [], "next": None}),
        ]
        resp = fetcher._request("GET", "/api/v1/test")
        assert resp.status_code == 200
        assert mock_request.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_retry_on_429_rate_limit(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(429, headers={"Retry-After": "2"}),
            _mock_response(200, {"ok": True}),
        ]
        resp = fetcher._request("GET", "/api/v1/test")
        assert resp.status_code == 200
        # Should sleep for the Retry-After value
        mock_sleep.assert_called_with(2.0)

    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_retry_on_network_error(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            httpx.ConnectError("connection refused"),
            httpx.ConnectError("connection refused"),
            _mock_response(200, {"ok": True}),
        ]
        resp = fetcher._request("GET", "/api/v1/test")
        assert resp.status_code == 200
        assert mock_sleep.call_count == 2

    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_exhausted_retries_raises(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(OTXFetchError, match="failed after 3 attempts"):
            fetcher._request("GET", "/api/v1/test")
        assert mock_request.call_count == MAX_RETRIES

    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_exponential_backoff(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = [
            _mock_response(500),
            _mock_response(500),
            _mock_response(200),
        ]
        fetcher._request("GET", "/api/v1/test")
        # Backoff: 1.0, then 2.0
        assert mock_sleep.call_args_list == [call(1.0), call(2.0)]

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_4xx_fails_immediately(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(403)
        with pytest.raises(httpx.HTTPStatusError):
            fetcher._request("GET", "/api/v1/test")
        assert mock_request.call_count == 1  # no retries


# ===================================================================
# Health Check
# ===================================================================

class TestHealthCheck:
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_healthy_with_key(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200)
        assert fetcher.health_check() is True

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_healthy_without_key(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(403)
        assert fetcher.health_check() is True  # 403 = API is up, just no auth

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_unhealthy(self, mock_request, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        assert fetcher.health_check() is False


# ===================================================================
# Full fetch() integration
# ===================================================================

class TestFetchIntegration:
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_fetch_returns_intel_items(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "results": [
                _pulse(
                    tags=["CVE-2024-1234"],
                    indicators=[_indicator("IPv4", "10.0.0.1")],
                ),
            ],
            "next": None,
        })
        items = fetcher.fetch()
        assert len(items) == 2  # 1 CVE + 1 IOC
        types = {i.intel_type for i in items}
        assert types == {IntelType.CVE, IntelType.IOC}

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_fetch_records_stats(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "results": [_pulse(tags=["CVE-2024-1234"])],
            "next": None,
        })
        fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_fetched"] == 1
        assert stats["total_errors"] == 0
        assert stats["last_fetch"] is not None

    @patch("citadel_archer.intel.otx_fetcher.time.sleep")
    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_fetch_records_error_on_failure(self, mock_request, mock_sleep, fetcher):
        mock_request.side_effect = httpx.ConnectError("down")
        with pytest.raises(OTXFetchError):
            fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_errors"] == 1
        assert stats["total_fetched"] == 0

    @patch("citadel_archer.intel.otx_fetcher.httpx.request")
    def test_fetch_empty_feed(self, mock_request, fetcher):
        mock_request.return_value = _mock_response(200, {
            "results": [],
            "next": None,
        })
        items = fetcher.fetch()
        assert items == []


# ===================================================================
# URL path extraction
# ===================================================================

class TestExtractPath:
    def test_standard_url(self, fetcher):
        url = f"{DEFAULT_BASE_URL}/api/v1/pulses/subscribed?page=2"
        assert fetcher._extract_path(url) == "/api/v1/pulses/subscribed?page=2"

    def test_custom_base(self):
        f = OTXFetcher()
        f.configure(base_url="https://custom.local")
        assert f._extract_path("https://custom.local/api/v1/test") == "/api/v1/test"

    def test_fallback_regex(self, fetcher):
        url = "https://other-host.com/api/v1/data?page=3"
        assert fetcher._extract_path(url) == "/api/v1/data?page=3"


# ===================================================================
# OTX type mapping
# ===================================================================

class TestTypeMapping:
    def test_all_expected_types_mapped(self):
        expected = {"IPv4", "IPv6", "domain", "hostname", "URL", "URI",
                    "FileHash-MD5", "FileHash-SHA1", "FileHash-SHA256",
                    "email", "filepath", "FilePath"}
        assert set(_OTX_TYPE_MAP.keys()) == expected

    def test_ipv6_maps_to_ip(self):
        assert _OTX_TYPE_MAP["IPv6"] == IOCType.IP_ADDRESS

    def test_hostname_maps_to_domain(self):
        assert _OTX_TYPE_MAP["hostname"] == IOCType.DOMAIN
