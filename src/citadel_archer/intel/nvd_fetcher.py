# PRD: Intel Module - NVD (National Vulnerability Database) Feed Fetcher
# Reference: docs/PRD.md v0.3.13
#
# Concrete IntelFetcher for NIST NVD CVE API v2.0.
# Fetches CVE entries and extracts:
#   - CVE entries (cve_id, description, CVSS score, severity, affected products)
#   - Vulnerability entries (product/version-specific vulns with fix info)
#
# NVD API v2.0:
#   - Base URL: https://services.nvd.nist.gov/rest/json/cves/2.0
#   - No API key required (but rate-limited to 5 requests/30s without key)
#   - With API key: 50 requests/30s
#   - Pagination via startIndex + resultsPerPage
#   - Supports pubStartDate/pubEndDate and lastModStartDate/lastModEndDate
#
# Design mirrors OTXFetcher: retry with backoff, rate-limit awareness.

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from .fetcher import IntelFetcher
from .models import (
    CVE,
    Vulnerability,
    IntelItem,
    IntelSeverity,
    IntelType,
)

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Retry configuration (matches OTX pattern)
MAX_RETRIES = 3
INITIAL_BACKOFF_SEC = 2.0  # NVD is stricter on rate limits
BACKOFF_MULTIPLIER = 2.0
REQUEST_TIMEOUT_SEC = 30

# NVD rate limits: 5 req/30s without API key, 50 req/30s with key
# We add a per-request delay to stay under limits
DELAY_NO_KEY_SEC = 6.5  # ~5 requests per 30 seconds
DELAY_WITH_KEY_SEC = 0.7  # ~50 requests per 30 seconds

# Default max pages to fetch (100 CVEs/page)
DEFAULT_MAX_PAGES = 5
DEFAULT_RESULTS_PER_PAGE = 100


class NVDFetcher(IntelFetcher):
    """NIST National Vulnerability Database (NVD) CVE feed fetcher.

    Usage::

        fetcher = NVDFetcher()
        fetcher.configure(api_key="your-nvd-api-key")  # optional
        items = fetcher.fetch(since="2024-01-01T00:00:00")
    """

    def __init__(self):
        super().__init__("nvd")
        self._api_key: Optional[str] = None
        self._base_url: str = DEFAULT_BASE_URL
        self._max_pages: int = DEFAULT_MAX_PAGES
        self._results_per_page: int = DEFAULT_RESULTS_PER_PAGE
        self._days_back: int = 7
        self._keyword_search: Optional[str] = None
        self._cvss_min: Optional[float] = None

    # ------------------------------------------------------------------
    # IntelFetcher interface
    # ------------------------------------------------------------------

    def configure(self, **kwargs) -> None:
        """Configure the NVD fetcher.

        Keyword Args:
            api_key: NVD API key (optional, increases rate limit).
            base_url: Override the default NVD API base URL.
            max_pages: Maximum pages to fetch (default 5).
            results_per_page: Results per page (default 100, max 2000).
            days_back: Days to look back when since is not provided (default 7).
            keyword_search: Filter CVEs by keyword (e.g., "openssh").
            cvss_min: Minimum CVSS v3 score to include (e.g., 7.0).
        """
        self._api_key = kwargs.get("api_key")
        self._base_url = kwargs.get("base_url", DEFAULT_BASE_URL)
        self._max_pages = kwargs.get("max_pages", DEFAULT_MAX_PAGES)
        self._results_per_page = min(
            kwargs.get("results_per_page", DEFAULT_RESULTS_PER_PAGE), 2000
        )
        self._days_back = kwargs.get("days_back", 7)
        self._keyword_search = kwargs.get("keyword_search")
        self._cvss_min = kwargs.get("cvss_min")

    def fetch(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch CVEs from NVD.

        Args:
            since: ISO 8601 timestamp — fetch CVEs modified after this
                   time. None defaults to days_back days ago.

        Returns:
            List of IntelItem wrappers (CVE and VULNERABILITY types).
        """
        try:
            cve_items = self._fetch_cves(since=since)
            items = self._parse_cve_items(cve_items)
            self.record_fetch(len(items))
            return items
        except Exception:
            self.record_error()
            raise

    def health_check(self) -> bool:
        """Verify that the NVD API is reachable."""
        try:
            resp = self._request(
                params={"resultsPerPage": "1", "startIndex": "0"}
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _build_headers(self) -> Dict[str, str]:
        """Build HTTP headers, including API key if configured."""
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "CitadelArcher/0.1",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def _request(
        self,
        params: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Execute an HTTP GET request with retry + exponential backoff."""
        backoff = INITIAL_BACKOFF_SEC
        last_exc: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = httpx.get(
                    self._base_url,
                    headers=self._build_headers(),
                    params=params,
                    timeout=REQUEST_TIMEOUT_SEC,
                )

                if resp.status_code < 400:
                    return resp

                if resp.status_code == 403:
                    logger.warning(
                        "NVD API returned 403 (rate limit or key issue), "
                        "retrying in %.1fs (attempt %d/%d)",
                        backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    logger.warning(
                        "NVD rate limited (429), retrying in %.1fs "
                        "(attempt %d/%d)",
                        wait, attempt, MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                if resp.status_code >= 500:
                    logger.warning(
                        "NVD server error %d, retrying in %.1fs "
                        "(attempt %d/%d)",
                        resp.status_code, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                resp.raise_for_status()

            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    logger.warning(
                        "NVD request failed (%s), retrying in %.1fs "
                        "(attempt %d/%d)",
                        exc, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER

        raise NVDFetchError(
            f"NVD request failed after {MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # CVE fetching with pagination
    # ------------------------------------------------------------------

    def _fetch_cves(
        self, since: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch CVE items from NVD, handling pagination."""
        params = self._build_query_params(since)

        all_items: List[Dict[str, Any]] = []
        start_index = 0
        delay = DELAY_WITH_KEY_SEC if self._api_key else DELAY_NO_KEY_SEC

        for page in range(self._max_pages):
            params["startIndex"] = str(start_index)
            params["resultsPerPage"] = str(self._results_per_page)

            if page > 0:
                time.sleep(delay)  # Rate limit compliance

            resp = self._request(params=params)
            data = resp.json()

            vulnerabilities = data.get("vulnerabilities", [])
            all_items.extend(vulnerabilities)

            total_results = data.get("totalResults", 0)
            start_index += self._results_per_page

            if start_index >= total_results:
                break

        return all_items

    def _build_query_params(
        self, since: Optional[str] = None
    ) -> Dict[str, str]:
        """Build NVD API query parameters."""
        params: Dict[str, str] = {}

        # Time range filter
        if since:
            try:
                since_dt = datetime.fromisoformat(
                    since.replace("Z", "+00:00")
                ).replace(tzinfo=None)
            except (ValueError, TypeError):
                since_dt = datetime.utcnow() - timedelta(days=self._days_back)
        else:
            since_dt = datetime.utcnow() - timedelta(days=self._days_back)

        # NVD requires ISO 8601 with explicit UTC timezone offset
        params["lastModStartDate"] = since_dt.strftime(
            "%Y-%m-%dT%H:%M:%S.000+00:00"
        )
        params["lastModEndDate"] = datetime.utcnow().strftime(
            "%Y-%m-%dT%H:%M:%S.000+00:00"
        )

        if self._keyword_search:
            params["keywordSearch"] = self._keyword_search

        if self._cvss_min is not None:
            params["cvssV3Severity"] = self._cvss_severity_param(
                self._cvss_min
            )

        return params

    def _cvss_severity_param(self, min_score: float) -> str:
        """Convert a minimum CVSS score to NVD severity parameter."""
        if min_score >= 9.0:
            return "CRITICAL"
        if min_score >= 7.0:
            return "HIGH"
        if min_score >= 4.0:
            return "MEDIUM"
        return "LOW"

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_cve_items(
        self, cve_items: List[Dict[str, Any]]
    ) -> List[IntelItem]:
        """Parse NVD CVE items into CVE and Vulnerability IntelItems."""
        items: List[IntelItem] = []

        for vuln_wrapper in cve_items:
            cve_data = vuln_wrapper.get("cve", {})
            if not cve_data:
                continue

            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Extract description (prefer English)
            description = self._extract_description(cve_data)

            # Extract CVSS score
            cvss_score, cvss_vector = self._extract_cvss(cve_data)

            # Extract references
            references = self._extract_references(cve_data)

            # Extract affected products
            affected = self._extract_affected_products(cve_data)

            # Determine severity from CVSS
            severity = IntelSeverity.from_cvss(cvss_score)

            # Apply CVSS minimum filter
            if self._cvss_min is not None and cvss_score < self._cvss_min:
                continue

            # Create CVE item
            cve = CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=cvss_score,
                severity=severity,
                affected_products=affected,
                references=references[:10],  # Cap references
                published_date=cve_data.get("published"),
                modified_date=cve_data.get("lastModified"),
            )

            items.append(IntelItem(
                intel_type=IntelType.CVE,
                payload=cve,
                source_feed=self.name,
                raw_data={
                    "cve_id": cve_id,
                    "cvss_vector": cvss_vector,
                    "source_identifier": cve_data.get("sourceIdentifier", ""),
                    "vuln_status": cve_data.get("vulnStatus", ""),
                },
            ))

            # Create Vulnerability items for specific affected products
            for product_entry in self._extract_vulnerability_entries(
                cve_data, cve_id, severity
            ):
                items.append(product_entry)

        return items

    def _extract_description(self, cve_data: Dict[str, Any]) -> str:
        """Extract the English description from CVE data."""
        descriptions = cve_data.get("descriptions", [])
        for desc in descriptions:
            if desc.get("lang") == "en":
                text = desc.get("value", "")
                if len(text) > 500:
                    return text[:497] + "..."
                return text
        return ""

    def _extract_cvss(self, cve_data: Dict[str, Any]) -> tuple:
        """Extract the best CVSS score and vector from metrics."""
        metrics = cve_data.get("metrics", {})

        # Prefer CVSS v3.1, then v3.0, then v2.0
        for key in ("cvssMetricV31", "cvssMetricV30"):
            metric_list = metrics.get(key, [])
            if metric_list:
                primary = metric_list[0]
                cvss = primary.get("cvssData", {})
                return (
                    cvss.get("baseScore", 0.0),
                    cvss.get("vectorString", ""),
                )

        # Fall back to CVSS v2
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            primary = v2_list[0]
            cvss = primary.get("cvssData", {})
            return (
                cvss.get("baseScore", 0.0),
                cvss.get("vectorString", ""),
            )

        return (0.0, "")

    def _extract_references(self, cve_data: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from CVE data."""
        refs = cve_data.get("references", [])
        return [r.get("url", "") for r in refs if r.get("url")]

    def _extract_affected_products(
        self, cve_data: Dict[str, Any]
    ) -> List[str]:
        """Extract affected product CPE strings from configurations."""
        products: List[str] = []
        configurations = cve_data.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        cpe = match.get("criteria", "")
                        if cpe:
                            # Extract human-readable product name from CPE
                            readable = self._cpe_to_product(cpe)
                            if readable and readable not in products:
                                products.append(readable)

        return products[:20]  # Cap at 20

    def _cpe_to_product(self, cpe: str) -> str:
        """Convert a CPE 2.3 URI to a human-readable product string.

        CPE format: cpe:2.3:a:vendor:product:version:...
        Returns: "vendor product version"
        """
        parts = cpe.split(":")
        if len(parts) >= 6:
            vendor = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
            version = parts[5] if parts[5] != "*" else ""
            result = f"{vendor} {product}"
            if version:
                result += f" {version}"
            return result
        return cpe

    def _extract_vulnerability_entries(
        self,
        cve_data: Dict[str, Any],
        cve_id: str,
        severity: IntelSeverity,
    ) -> List[IntelItem]:
        """Extract per-product Vulnerability items from CVE configurations."""
        items: List[IntelItem] = []
        configurations = cve_data.get("configurations", [])

        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable"):
                        continue

                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) < 6:
                        continue

                    product = parts[4].replace("_", " ")
                    version = parts[5] if parts[5] != "*" else ""
                    if not version:
                        continue  # Skip wildcard versions

                    version_end = match.get(
                        "versionEndExcluding",
                        match.get("versionEndIncluding", ""),
                    )

                    vuln = Vulnerability(
                        product=product,
                        version=version,
                        cve_id=cve_id,
                        description=f"Affected: {product} {version}",
                        severity=severity,
                        fix_version=version_end or None,
                        patch_available=bool(version_end),
                    )

                    items.append(IntelItem(
                        intel_type=IntelType.VULNERABILITY,
                        payload=vuln,
                        source_feed=self.name,
                        raw_data={
                            "cve_id": cve_id,
                            "cpe": cpe,
                        },
                    ))

        return items


class NVDFetchError(Exception):
    """Raised when NVD API requests fail after all retries."""
