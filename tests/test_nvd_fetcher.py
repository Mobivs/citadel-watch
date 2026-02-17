"""
Tests for NVD (National Vulnerability Database) Feed Fetcher.

All HTTP calls are mocked — no external network access required.
Covers: configuration, CVE parsing, CVSS extraction, affected product parsing,
vulnerability entries, pagination, time filtering, retry logic, health check.
"""

from unittest.mock import MagicMock, patch, call

import httpx
import pytest

from citadel_archer.intel.models import (
    CVE,
    Vulnerability,
    IntelItem,
    IntelSeverity,
    IntelType,
)
from citadel_archer.intel.nvd_fetcher import (
    DEFAULT_BASE_URL,
    NVDFetchError,
    NVDFetcher,
)


# ===================================================================
# Fixtures & helpers
# ===================================================================

@pytest.fixture
def fetcher():
    f = NVDFetcher()
    f.configure()
    return f


@pytest.fixture
def fetcher_with_key():
    f = NVDFetcher()
    f.configure(api_key="test-nvd-key")
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


def _nvd_cve(
    cve_id="CVE-2026-1234",
    description="A test vulnerability",
    base_score=7.5,
    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    published="2026-02-01T00:00:00",
    last_modified="2026-02-10T00:00:00",
    references=None,
    configurations=None,
    descriptions=None,
    vuln_status="Analyzed",
):
    """Build a minimal NVD CVE item."""
    cve = {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": last_modified,
            "vulnStatus": vuln_status,
            "sourceIdentifier": "nvd@nist.gov",
            "descriptions": descriptions or [
                {"lang": "en", "value": description},
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseScore": base_score,
                            "vectorString": vector_string,
                        },
                    }
                ],
            },
            "references": references or [
                {"url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"},
            ],
            "configurations": configurations or [],
        },
    }
    return cve


def _nvd_response(vulnerabilities=None, total_results=None):
    """Build an NVD API response."""
    vulns = vulnerabilities or []
    return {
        "vulnerabilities": vulns,
        "totalResults": total_results if total_results is not None else len(vulns),
        "resultsPerPage": 100,
        "startIndex": 0,
    }


def _cpe_config(cpe_uri="cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*", vulnerable=True, version_end=None):
    """Build a CPE configuration node."""
    match = {
        "vulnerable": vulnerable,
        "criteria": cpe_uri,
    }
    if version_end:
        match["versionEndExcluding"] = version_end
    return {
        "nodes": [
            {
                "cpeMatch": [match],
            }
        ],
    }


# ===================================================================
# Configuration
# ===================================================================

class TestNVDConfiguration:
    def test_default_name(self):
        f = NVDFetcher()
        assert f.name == "nvd"

    def test_configure_api_key(self, fetcher_with_key):
        assert fetcher_with_key._api_key == "test-nvd-key"

    def test_configure_base_url(self):
        f = NVDFetcher()
        f.configure(base_url="https://custom.nvd.local")
        assert f._base_url == "https://custom.nvd.local"

    def test_configure_max_pages(self):
        f = NVDFetcher()
        f.configure(max_pages=3)
        assert f._max_pages == 3

    def test_configure_results_per_page_capped(self):
        f = NVDFetcher()
        f.configure(results_per_page=5000)
        assert f._results_per_page == 2000  # max cap

    def test_configure_keyword_search(self):
        f = NVDFetcher()
        f.configure(keyword_search="openssh")
        assert f._keyword_search == "openssh"

    def test_configure_cvss_min(self):
        f = NVDFetcher()
        f.configure(cvss_min=7.0)
        assert f._cvss_min == 7.0

    def test_default_base_url(self, fetcher):
        assert fetcher._base_url == DEFAULT_BASE_URL

    def test_no_api_key(self, fetcher):
        assert fetcher._api_key is None


# ===================================================================
# Headers
# ===================================================================

class TestHeaders:
    def test_headers_with_key(self, fetcher_with_key):
        h = fetcher_with_key._build_headers()
        assert h["apiKey"] == "test-nvd-key"

    def test_headers_without_key(self, fetcher):
        h = fetcher._build_headers()
        assert "apiKey" not in h
        assert h["Accept"] == "application/json"


# ===================================================================
# CVE Parsing
# ===================================================================

class TestCVEParsing:
    def test_parse_basic_cve(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve()])
        cve_items = [i for i in items if i.intel_type == IntelType.CVE]
        assert len(cve_items) == 1
        cve = cve_items[0].payload
        assert cve.cve_id == "CVE-2026-1234"
        assert cve.cvss_score == 7.5
        assert cve.description == "A test vulnerability"

    def test_severity_from_cvss(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve(base_score=9.8)])
        assert items[0].payload.severity == IntelSeverity.CRITICAL

    def test_severity_high(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve(base_score=7.5)])
        assert items[0].payload.severity == IntelSeverity.HIGH

    def test_severity_medium(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve(base_score=5.0)])
        assert items[0].payload.severity == IntelSeverity.MEDIUM

    def test_severity_low(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve(base_score=2.0)])
        assert items[0].payload.severity == IntelSeverity.LOW

    def test_description_english_preferred(self, fetcher):
        cve = _nvd_cve(descriptions=[
            {"lang": "es", "value": "Vulnerabilidad de prueba"},
            {"lang": "en", "value": "English description"},
        ])
        items = fetcher._parse_cve_items([cve])
        assert items[0].payload.description == "English description"

    def test_description_truncated(self, fetcher):
        long_desc = "A" * 1000
        cve = _nvd_cve(descriptions=[{"lang": "en", "value": long_desc}])
        items = fetcher._parse_cve_items([cve])
        assert len(items[0].payload.description) <= 503

    def test_references_extracted(self, fetcher):
        cve = _nvd_cve(references=[
            {"url": "https://example.com/advisory1"},
            {"url": "https://example.com/advisory2"},
        ])
        items = fetcher._parse_cve_items([cve])
        assert len(items[0].payload.references) == 2

    def test_empty_cve_id_skipped(self, fetcher):
        cve = _nvd_cve()
        cve["cve"]["id"] = ""
        items = fetcher._parse_cve_items([cve])
        assert len(items) == 0

    def test_source_feed(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve()])
        assert items[0].source_feed == "nvd"

    def test_raw_data_fields(self, fetcher):
        items = fetcher._parse_cve_items([_nvd_cve()])
        raw = items[0].raw_data
        assert raw["cve_id"] == "CVE-2026-1234"
        assert "cvss_vector" in raw
        assert "vuln_status" in raw


# ===================================================================
# CVSS Extraction
# ===================================================================

class TestCVSSExtraction:
    def test_cvss_v31_preferred(self, fetcher):
        cve_data = {
            "metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 8.0, "vectorString": "v31"}}],
                "cvssMetricV30": [{"cvssData": {"baseScore": 7.0, "vectorString": "v30"}}],
            }
        }
        score, vector = fetcher._extract_cvss(cve_data)
        assert score == 8.0
        assert vector == "v31"

    def test_cvss_v30_fallback(self, fetcher):
        cve_data = {
            "metrics": {
                "cvssMetricV30": [{"cvssData": {"baseScore": 7.0, "vectorString": "v30"}}],
            }
        }
        score, vector = fetcher._extract_cvss(cve_data)
        assert score == 7.0

    def test_cvss_v2_fallback(self, fetcher):
        cve_data = {
            "metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "v2"}}],
            }
        }
        score, vector = fetcher._extract_cvss(cve_data)
        assert score == 5.0

    def test_no_metrics(self, fetcher):
        cve_data = {"metrics": {}}
        score, vector = fetcher._extract_cvss(cve_data)
        assert score == 0.0
        assert vector == ""


# ===================================================================
# Affected Products
# ===================================================================

class TestAffectedProducts:
    def test_extract_from_cpe(self, fetcher):
        cve = _nvd_cve(configurations=[
            _cpe_config("cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*"),
        ])
        items = fetcher._parse_cve_items([cve])
        cve_item = [i for i in items if i.intel_type == IntelType.CVE][0]
        assert any("apache" in p for p in cve_item.payload.affected_products)

    def test_cpe_to_product_readable(self, fetcher):
        result = fetcher._cpe_to_product("cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*")
        assert "apache" in result
        assert "httpd" in result
        assert "2.4.49" in result

    def test_cpe_wildcard_version(self, fetcher):
        result = fetcher._cpe_to_product("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
        assert "vendor product" in result
        assert "*" not in result

    def test_non_vulnerable_skipped(self, fetcher):
        config = _cpe_config(vulnerable=False)
        cve = _nvd_cve(configurations=[config])
        items = fetcher._parse_cve_items([cve])
        cve_item = [i for i in items if i.intel_type == IntelType.CVE][0]
        assert len(cve_item.payload.affected_products) == 0


# ===================================================================
# Vulnerability Entries
# ===================================================================

class TestVulnerabilityEntries:
    def test_vulnerability_created_for_specific_version(self, fetcher):
        cve = _nvd_cve(configurations=[
            _cpe_config("cpe:2.3:a:openssh:openssh:8.9:*:*:*:*:*:*:*"),
        ])
        items = fetcher._parse_cve_items([cve])
        vuln_items = [i for i in items if i.intel_type == IntelType.VULNERABILITY]
        assert len(vuln_items) == 1
        assert vuln_items[0].payload.product == "openssh"
        assert vuln_items[0].payload.version == "8.9"
        assert vuln_items[0].payload.cve_id == "CVE-2026-1234"

    def test_vulnerability_with_fix_version(self, fetcher):
        cve = _nvd_cve(configurations=[
            _cpe_config(
                "cpe:2.3:a:openssh:openssh:8.9:*:*:*:*:*:*:*",
                version_end="9.0",
            ),
        ])
        items = fetcher._parse_cve_items([cve])
        vuln_items = [i for i in items if i.intel_type == IntelType.VULNERABILITY]
        assert vuln_items[0].payload.fix_version == "9.0"
        assert vuln_items[0].payload.patch_available is True

    def test_wildcard_version_no_vulnerability(self, fetcher):
        cve = _nvd_cve(configurations=[
            _cpe_config("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
        ])
        items = fetcher._parse_cve_items([cve])
        vuln_items = [i for i in items if i.intel_type == IntelType.VULNERABILITY]
        assert len(vuln_items) == 0


# ===================================================================
# CVSS Min Filter
# ===================================================================

class TestCVSSMinFilter:
    def test_cvss_min_filters_low(self):
        f = NVDFetcher()
        f.configure(cvss_min=7.0)
        items = f._parse_cve_items([
            _nvd_cve(cve_id="CVE-2026-0001", base_score=3.0),
            _nvd_cve(cve_id="CVE-2026-0002", base_score=8.5),
        ])
        cve_items = [i for i in items if i.intel_type == IntelType.CVE]
        assert len(cve_items) == 1
        assert cve_items[0].payload.cve_id == "CVE-2026-0002"


# ===================================================================
# Pagination
# ===================================================================

class TestPagination:
    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_single_page(self, mock_get, mock_sleep, fetcher):
        mock_get.return_value = _mock_response(200, _nvd_response(
            [_nvd_cve()], total_results=1,
        ))
        items = fetcher._fetch_cves()
        assert len(items) == 1
        assert mock_get.call_count == 1

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_two_pages(self, mock_get, mock_sleep, fetcher):
        fetcher._results_per_page = 1
        mock_get.side_effect = [
            _mock_response(200, {
                "vulnerabilities": [_nvd_cve(cve_id="CVE-2026-0001")],
                "totalResults": 2,
                "resultsPerPage": 1,
                "startIndex": 0,
            }),
            _mock_response(200, {
                "vulnerabilities": [_nvd_cve(cve_id="CVE-2026-0002")],
                "totalResults": 2,
                "resultsPerPage": 1,
                "startIndex": 1,
            }),
        ]
        items = fetcher._fetch_cves()
        assert len(items) == 2
        assert mock_get.call_count == 2

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_max_pages_limit(self, mock_get, mock_sleep, fetcher):
        fetcher._max_pages = 1
        fetcher._results_per_page = 1
        mock_get.return_value = _mock_response(200, {
            "vulnerabilities": [_nvd_cve()],
            "totalResults": 100,
            "resultsPerPage": 1,
            "startIndex": 0,
        })
        items = fetcher._fetch_cves()
        assert mock_get.call_count == 1  # only 1 page


# ===================================================================
# Query Parameters
# ===================================================================

class TestQueryParams:
    def test_since_parameter(self, fetcher):
        params = fetcher._build_query_params(since="2026-02-01T00:00:00")
        assert "lastModStartDate" in params
        assert "lastModEndDate" in params
        assert "2026-02-01" in params["lastModStartDate"]

    def test_date_format_includes_timezone(self, fetcher):
        """NVD API requires UTC timezone offset in date parameters."""
        params = fetcher._build_query_params(since="2026-02-01T00:00:00")
        assert params["lastModStartDate"].endswith("+00:00")
        assert params["lastModEndDate"].endswith("+00:00")

    def test_default_days_back(self, fetcher):
        params = fetcher._build_query_params()
        assert "lastModStartDate" in params

    def test_keyword_search(self):
        f = NVDFetcher()
        f.configure(keyword_search="apache")
        params = f._build_query_params()
        assert params["keywordSearch"] == "apache"

    def test_cvss_severity_param(self, fetcher):
        assert fetcher._cvss_severity_param(9.0) == "CRITICAL"
        assert fetcher._cvss_severity_param(7.0) == "HIGH"
        assert fetcher._cvss_severity_param(4.0) == "MEDIUM"
        assert fetcher._cvss_severity_param(1.0) == "LOW"


# ===================================================================
# Retry Logic
# ===================================================================

class TestRetryLogic:
    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_retry_on_500(self, mock_get, mock_sleep, fetcher):
        mock_get.side_effect = [
            _mock_response(500),
            _mock_response(200, _nvd_response([])),
        ]
        resp = fetcher._request()
        assert resp.status_code == 200
        assert mock_get.call_count == 2

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_retry_on_403(self, mock_get, mock_sleep, fetcher):
        """NVD returns 403 for rate limit violations."""
        mock_get.side_effect = [
            _mock_response(403),
            _mock_response(200, _nvd_response([])),
        ]
        resp = fetcher._request()
        assert resp.status_code == 200

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_retry_on_429(self, mock_get, mock_sleep, fetcher):
        mock_get.side_effect = [
            _mock_response(429, headers={"Retry-After": "5"}),
            _mock_response(200, _nvd_response([])),
        ]
        resp = fetcher._request()
        assert resp.status_code == 200
        mock_sleep.assert_any_call(5.0)

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_exhausted_retries_raises(self, mock_get, mock_sleep, fetcher):
        mock_get.side_effect = httpx.ConnectError("down")
        with pytest.raises(NVDFetchError, match="failed after 3 attempts"):
            fetcher._request()


# ===================================================================
# Health Check
# ===================================================================

class TestHealthCheck:
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_healthy(self, mock_get, fetcher):
        mock_get.return_value = _mock_response(200, _nvd_response([]))
        assert fetcher.health_check() is True

    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_unhealthy(self, mock_get, fetcher):
        mock_get.side_effect = httpx.ConnectError("down")
        assert fetcher.health_check() is False


# ===================================================================
# Full fetch() integration
# ===================================================================

class TestFetchIntegration:
    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_fetch_returns_cve_items(self, mock_get, mock_sleep, fetcher):
        mock_get.return_value = _mock_response(200, _nvd_response([
            _nvd_cve(cve_id="CVE-2026-0001"),
            _nvd_cve(cve_id="CVE-2026-0002"),
        ]))
        items = fetcher.fetch()
        cve_items = [i for i in items if i.intel_type == IntelType.CVE]
        assert len(cve_items) == 2

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_fetch_with_vulnerabilities(self, mock_get, mock_sleep, fetcher):
        cve = _nvd_cve(configurations=[
            _cpe_config("cpe:2.3:a:openssh:openssh:8.9:*:*:*:*:*:*:*"),
        ])
        mock_get.return_value = _mock_response(200, _nvd_response([cve]))
        items = fetcher.fetch()
        types = {i.intel_type for i in items}
        assert IntelType.CVE in types
        assert IntelType.VULNERABILITY in types

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_fetch_records_stats(self, mock_get, mock_sleep, fetcher):
        mock_get.return_value = _mock_response(200, _nvd_response([_nvd_cve()]))
        fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_fetched"] >= 1
        assert stats["total_errors"] == 0

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_fetch_records_error(self, mock_get, mock_sleep, fetcher):
        mock_get.side_effect = httpx.ConnectError("down")
        with pytest.raises(NVDFetchError):
            fetcher.fetch()
        stats = fetcher.get_stats()
        assert stats["total_errors"] == 1

    @patch("citadel_archer.intel.nvd_fetcher.time.sleep")
    @patch("citadel_archer.intel.nvd_fetcher.httpx.get")
    def test_fetch_empty(self, mock_get, mock_sleep, fetcher):
        mock_get.return_value = _mock_response(200, _nvd_response([]))
        items = fetcher.fetch()
        assert items == []
