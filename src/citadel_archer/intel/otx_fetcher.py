# PRD: Intel Module - AlienVault OTX Feed Fetcher
# Reference: PHASE_2_SPEC.md
#
# Concrete IntelFetcher for AlienVault Open Threat Exchange (OTX).
# Fetches pulses (threat reports) and extracts:
#   - CVE entries (from pulse CVE references)
#   - IOCs (IP, domain, URL, file hash indicators)
#
# Supports:
#   - API key authentication (optional — public feeds work without)
#   - Pagination (OTX uses next-page URL pattern)
#   - Retry with exponential backoff (3 attempts)
#   - Rate limiting awareness

import logging
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from .fetcher import IntelFetcher
from .models import (
    CVE,
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
)

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://otx.alienvault.com"

# OTX indicator type -> our IOCType mapping
_OTX_TYPE_MAP: Dict[str, IOCType] = {
    "IPv4": IOCType.IP_ADDRESS,
    "IPv6": IOCType.IP_ADDRESS,
    "domain": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "URL": IOCType.URL,
    "URI": IOCType.URL,
    "FileHash-MD5": IOCType.FILE_HASH_MD5,
    "FileHash-SHA1": IOCType.FILE_HASH_SHA1,
    "FileHash-SHA256": IOCType.FILE_HASH_SHA256,
    "email": IOCType.EMAIL,
    "filepath": IOCType.FILENAME,
    "FilePath": IOCType.FILENAME,
}

# Retry configuration
MAX_RETRIES = 3
INITIAL_BACKOFF_SEC = 1.0
BACKOFF_MULTIPLIER = 2.0
REQUEST_TIMEOUT_SEC = 30


class OTXFetcher(IntelFetcher):
    """AlienVault OTX threat intelligence feed fetcher.

    Usage::

        fetcher = OTXFetcher()
        fetcher.configure(api_key="your-otx-api-key")
        items = fetcher.fetch(since="2024-01-01T00:00:00")
    """

    def __init__(self):
        super().__init__("alienvault-otx")
        self._api_key: Optional[str] = None
        self._base_url: str = DEFAULT_BASE_URL
        self._max_pages: int = 10

    # ------------------------------------------------------------------
    # IntelFetcher interface
    # ------------------------------------------------------------------

    def configure(self, **kwargs) -> None:
        """Configure the OTX fetcher.

        Keyword Args:
            api_key: OTX API key (optional for public feeds).
            base_url: Override the default OTX API base URL.
            max_pages: Maximum number of pages to fetch (default 10).
        """
        self._api_key = kwargs.get("api_key")
        self._base_url = kwargs.get("base_url", DEFAULT_BASE_URL)
        self._max_pages = kwargs.get("max_pages", 10)

    def fetch(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch pulses from OTX and extract CVEs + IOCs.

        Args:
            since: ISO 8601 timestamp — fetch pulses modified after
                   this time.  None fetches the most recent pulses.

        Returns:
            List of IntelItem wrappers (CVE and IOC types).
        """
        try:
            pulses = self._fetch_pulses(since=since)
            items = self._parse_pulses(pulses)
            self.record_fetch(len(items))
            return items
        except Exception:
            self.record_error()
            raise

    def health_check(self) -> bool:
        """Verify that the OTX API is reachable."""
        try:
            resp = self._request("GET", "/api/v1/user/me")
            return resp.status_code in (200, 403)  # 403 = no key but API is up
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
            headers["X-OTX-API-KEY"] = self._api_key
        return headers

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Execute an HTTP request with retry + exponential backoff.

        Retries on network errors, 429 (rate limit), and 5xx errors.
        Raises on 4xx client errors (except 429) immediately.
        """
        url = f"{self._base_url}{path}"
        backoff = INITIAL_BACKOFF_SEC
        last_exc: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = httpx.request(
                    method,
                    url,
                    headers=self._build_headers(),
                    params=params,
                    timeout=REQUEST_TIMEOUT_SEC,
                )

                # Success
                if resp.status_code < 400:
                    return resp

                # Rate limited — retry after backoff
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    logger.warning(
                        "OTX rate limited (429), retrying in %.1fs "
                        "(attempt %d/%d)",
                        wait, attempt, MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                # Server error — retry
                if resp.status_code >= 500:
                    logger.warning(
                        "OTX server error %d, retrying in %.1fs "
                        "(attempt %d/%d)",
                        resp.status_code, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                # Client error (4xx except 429) — fail fast
                resp.raise_for_status()

            except httpx.HTTPStatusError:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    logger.warning(
                        "OTX request failed (%s), retrying in %.1fs "
                        "(attempt %d/%d)",
                        exc, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER

        raise OTXFetchError(
            f"OTX request failed after {MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # Pulse fetching with pagination
    # ------------------------------------------------------------------

    def _fetch_pulses(
        self, since: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch pulse list from OTX, handling pagination."""
        params: Dict[str, str] = {}
        if since:
            params["modified_since"] = since

        pulses: List[Dict[str, Any]] = []
        path = "/api/v1/pulses/subscribed"
        page = 0

        while path and page < self._max_pages:
            resp = self._request("GET", path, params=params if page == 0 else None)
            data = resp.json()

            results = data.get("results", [])
            pulses.extend(results)

            # OTX returns a full URL for the next page
            next_url = data.get("next")
            if next_url:
                # Extract path from full URL for our _request helper
                path = self._extract_path(next_url)
            else:
                path = None

            page += 1

        return pulses

    def _extract_path(self, url: str) -> str:
        """Extract the path+query from a full OTX URL."""
        # e.g. "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2"
        # -> "/api/v1/pulses/subscribed?page=2"
        if url.startswith(self._base_url):
            return url[len(self._base_url):]
        # Fallback: strip scheme+host
        match = re.match(r"https?://[^/]+(/.*)$", url)
        return match.group(1) if match else url

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_pulses(self, pulses: List[Dict[str, Any]]) -> List[IntelItem]:
        """Parse OTX pulses into CVE and IOC IntelItems."""
        items: List[IntelItem] = []

        for pulse in pulses:
            pulse_name = pulse.get("name", "")
            pulse_tags = pulse.get("tags", [])
            pulse_created = pulse.get("created")
            pulse_id = pulse.get("id", "")

            # Extract CVEs from the pulse
            items.extend(self._extract_cves(pulse, pulse_name))

            # Extract IOCs from indicators
            indicators = pulse.get("indicators", [])
            items.extend(
                self._extract_iocs(indicators, pulse_name, pulse_tags, pulse_id)
            )

        return items

    def _extract_cves(
        self, pulse: Dict[str, Any], pulse_name: str
    ) -> List[IntelItem]:
        """Extract CVE items from a pulse's references and tags."""
        items: List[IntelItem] = []
        cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)

        # Collect CVE IDs from tags, references, and description
        cve_ids: set = set()
        for tag in pulse.get("tags", []):
            for m in cve_pattern.finditer(tag):
                cve_ids.add(m.group(1).upper())

        for ref in pulse.get("references", []):
            for m in cve_pattern.finditer(ref):
                cve_ids.add(m.group(1).upper())

        description = pulse.get("description", "")
        for m in cve_pattern.finditer(description):
            cve_ids.add(m.group(1).upper())

        for cve_id in cve_ids:
            cve = CVE(
                cve_id=cve_id,
                description=f"From OTX pulse: {pulse_name}",
                references=pulse.get("references", []),
                published_date=pulse.get("created"),
                modified_date=pulse.get("modified"),
            )
            items.append(IntelItem(
                intel_type=IntelType.CVE,
                payload=cve,
                source_feed=self.name,
                raw_data={"pulse_id": pulse.get("id", ""), "cve_id": cve_id},
            ))

        return items

    def _extract_iocs(
        self,
        indicators: List[Dict[str, Any]],
        pulse_name: str,
        pulse_tags: List[str],
        pulse_id: str,
    ) -> List[IntelItem]:
        """Extract IOC items from OTX pulse indicators."""
        items: List[IntelItem] = []

        for ind in indicators:
            otx_type = ind.get("type", "")
            ioc_type = _OTX_TYPE_MAP.get(otx_type)
            if ioc_type is None:
                continue  # unsupported indicator type

            value = ind.get("indicator", "").strip()
            if not value:
                continue

            ioc = IOC(
                ioc_type=ioc_type,
                value=value,
                description=ind.get("description", "") or f"From pulse: {pulse_name}",
                severity=IntelSeverity.MEDIUM,
                tags=list(pulse_tags),
                source=self.name,
                first_seen=ind.get("created"),
            )

            items.append(IntelItem(
                intel_type=IntelType.IOC,
                payload=ioc,
                source_feed=self.name,
                raw_data={
                    "pulse_id": pulse_id,
                    "indicator_id": ind.get("id", ""),
                    "otx_type": otx_type,
                },
            ))

        return items


class OTXFetchError(Exception):
    """Raised when OTX API requests fail after all retries."""
