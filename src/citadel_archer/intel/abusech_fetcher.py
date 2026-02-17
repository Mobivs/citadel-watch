# PRD: Intel Module - abuse.ch Feed Fetcher
# Reference: docs/PRD.md v0.3.13
#
# Concrete IntelFetcher for abuse.ch threat feeds:
#   - URLhaus: Malicious URL tracking (payloads, malware distribution)
#   - ThreatFox: IOC sharing platform (IPs, domains, URLs, hashes)
#
# Both APIs are free, no API key required.
# URLhaus provides CSV/JSON bulk exports + a recent-additions API.
# ThreatFox provides a JSON query API with IOC search by days.
#
# Design mirrors OTXFetcher: retry with backoff, rate-limit awareness,
# configurable max results.

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from .fetcher import IntelFetcher
from .models import (
    IOC,
    IOCType,
    IntelItem,
    IntelSeverity,
    IntelType,
)

logger = logging.getLogger(__name__)

# API endpoints
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1"
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1"

# ThreatFox IOC type -> our IOCType mapping
_THREATFOX_TYPE_MAP: Dict[str, IOCType] = {
    "ip:port": IOCType.IP_ADDRESS,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5_hash": IOCType.FILE_HASH_MD5,
    "sha1_hash": IOCType.FILE_HASH_SHA1,
    "sha256_hash": IOCType.FILE_HASH_SHA256,
}

# URLhaus threat level -> IntelSeverity
_URLHAUS_THREAT_MAP: Dict[str, IntelSeverity] = {
    "malware_download": IntelSeverity.HIGH,
    "phishing": IntelSeverity.HIGH,
    "malware_distribution": IntelSeverity.CRITICAL,
}

# Retry configuration (matches OTX pattern)
MAX_RETRIES = 3
INITIAL_BACKOFF_SEC = 1.0
BACKOFF_MULTIPLIER = 2.0
REQUEST_TIMEOUT_SEC = 30


class AbuseChFetcher(IntelFetcher):
    """abuse.ch threat intelligence feed fetcher (URLhaus + ThreatFox).

    Usage::

        fetcher = AbuseChFetcher()
        fetcher.configure()  # no API key needed
        items = fetcher.fetch(since="2024-01-01T00:00:00")
    """

    def __init__(self):
        super().__init__("abuse-ch")
        self._urlhaus_url: str = URLHAUS_API_URL
        self._threatfox_url: str = THREATFOX_API_URL
        self._max_urlhaus: int = 500
        self._max_threatfox: int = 500
        self._days_back: int = 7
        self._enabled_feeds: Dict[str, bool] = {
            "urlhaus": True,
            "threatfox": True,
        }

    # ------------------------------------------------------------------
    # IntelFetcher interface
    # ------------------------------------------------------------------

    def configure(self, **kwargs) -> None:
        """Configure the abuse.ch fetcher.

        Keyword Args:
            urlhaus_url: Override URLhaus API URL.
            threatfox_url: Override ThreatFox API URL.
            max_urlhaus: Max URLhaus results per fetch (default 500).
            max_threatfox: Max ThreatFox results per fetch (default 500).
            days_back: Number of days to look back (default 7).
            enable_urlhaus: Enable/disable URLhaus feed (default True).
            enable_threatfox: Enable/disable ThreatFox feed (default True).
        """
        self._urlhaus_url = kwargs.get("urlhaus_url", URLHAUS_API_URL)
        self._threatfox_url = kwargs.get("threatfox_url", THREATFOX_API_URL)
        self._max_urlhaus = kwargs.get("max_urlhaus", 500)
        self._max_threatfox = kwargs.get("max_threatfox", 500)
        self._days_back = kwargs.get("days_back", 7)
        self._enabled_feeds["urlhaus"] = kwargs.get("enable_urlhaus", True)
        self._enabled_feeds["threatfox"] = kwargs.get("enable_threatfox", True)

    def fetch(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch IOCs from URLhaus and ThreatFox.

        Args:
            since: ISO 8601 timestamp — fetch items after this time.
                   None defaults to days_back days ago.

        Returns:
            List of IntelItem wrappers (IOC type).
        """
        try:
            items: List[IntelItem] = []

            if self._enabled_feeds.get("urlhaus"):
                items.extend(self._fetch_urlhaus(since))

            if self._enabled_feeds.get("threatfox"):
                items.extend(self._fetch_threatfox(since))

            self.record_fetch(len(items))
            return items
        except Exception:
            self.record_error()
            raise

    def health_check(self) -> bool:
        """Verify that enabled abuse.ch APIs are reachable."""
        try:
            healthy = True
            if self._enabled_feeds.get("urlhaus"):
                resp = self._request(
                    "POST",
                    f"{self._urlhaus_url}/urls/recent/",
                    data={"limit": "1"},
                )
                healthy = healthy and resp.status_code == 200
            if self._enabled_feeds.get("threatfox"):
                resp = self._request(
                    "POST",
                    f"{self._threatfox_url}/",
                    json_body={"query": "get_iocs", "days": 1},
                )
                healthy = healthy and resp.status_code == 200
            return healthy
        except Exception:
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Execute an HTTP request with retry + exponential backoff."""
        backoff = INITIAL_BACKOFF_SEC
        last_exc: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = httpx.request(
                    method,
                    url,
                    headers={
                        "Accept": "application/json",
                        "User-Agent": "CitadelArcher/0.1",
                    },
                    params=params,
                    json=json_body,
                    data=data,
                    timeout=REQUEST_TIMEOUT_SEC,
                )

                if resp.status_code < 400:
                    return resp

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    logger.warning(
                        "abuse.ch rate limited (429), retrying in %.1fs "
                        "(attempt %d/%d)",
                        wait, attempt, MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                if resp.status_code >= 500:
                    logger.warning(
                        "abuse.ch server error %d, retrying in %.1fs "
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
                        "abuse.ch request failed (%s), retrying in %.1fs "
                        "(attempt %d/%d)",
                        exc, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER

        raise AbuseChFetchError(
            f"abuse.ch request failed after {MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # URLhaus
    # ------------------------------------------------------------------

    def _fetch_urlhaus(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch recent malicious URLs from URLhaus."""
        resp = self._request(
            "POST",
            f"{self._urlhaus_url}/urls/recent/",
            data={"limit": str(self._max_urlhaus)},
        )
        data = resp.json()

        urls = data.get("urls", [])
        if not urls:
            return []

        items: List[IntelItem] = []
        cutoff = self._parse_since(since)

        for entry in urls[:self._max_urlhaus]:
            # Apply time filter
            date_added = entry.get("date_added")
            if cutoff and date_added:
                try:
                    entry_dt = datetime.strptime(
                        date_added, "%Y-%m-%d %H:%M:%S"
                    )
                    if entry_dt < cutoff:
                        continue
                except ValueError:
                    pass

            url_value = entry.get("url", "").strip()
            if not url_value:
                continue

            threat = entry.get("threat", "")
            severity = _URLHAUS_THREAT_MAP.get(threat, IntelSeverity.MEDIUM)
            tags = entry.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            ioc = IOC(
                ioc_type=IOCType.URL,
                value=url_value,
                description=f"URLhaus: {threat or 'malicious URL'}",
                severity=severity,
                tags=tags,
                source="abuse-ch-urlhaus",
                first_seen=date_added,
                confidence=0.8,
            )

            items.append(IntelItem(
                intel_type=IntelType.IOC,
                payload=ioc,
                source_feed=self.name,
                raw_data={
                    "urlhaus_id": entry.get("id", ""),
                    "url_status": entry.get("url_status", ""),
                    "threat": threat,
                    "host": entry.get("host", ""),
                },
            ))

        return items

    # ------------------------------------------------------------------
    # ThreatFox
    # ------------------------------------------------------------------

    def _fetch_threatfox(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch IOCs from ThreatFox."""
        days = self._days_back
        if since:
            try:
                since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                delta = datetime.utcnow() - since_dt.replace(tzinfo=None)
                days = max(1, min(int(delta.days) + 1, 30))
            except (ValueError, TypeError):
                pass

        resp = self._request(
            "POST",
            f"{self._threatfox_url}/",
            json_body={"query": "get_iocs", "days": days},
        )
        data = resp.json()

        query_status = data.get("query_status", "")
        if query_status != "ok":
            if query_status == "no_result":
                return []
            logger.warning("ThreatFox query returned status: %s", query_status)
            return []

        iocs_data = data.get("data", [])
        if not iocs_data:
            return []

        items: List[IntelItem] = []
        cutoff = self._parse_since(since)

        for entry in iocs_data[:self._max_threatfox]:
            # Apply time filter
            first_seen = entry.get("first_seen_utc")
            if cutoff and first_seen:
                try:
                    entry_dt = datetime.strptime(
                        first_seen, "%Y-%m-%d %H:%M:%S"
                    )
                    if entry_dt < cutoff:
                        continue
                except ValueError:
                    pass

            ioc_type_str = entry.get("ioc_type", "")
            our_type = _THREATFOX_TYPE_MAP.get(ioc_type_str)
            if our_type is None:
                continue

            value = entry.get("ioc", "").strip()
            if not value:
                continue

            # For ip:port, extract just the IP
            if ioc_type_str == "ip:port" and ":" in value:
                if value.startswith("["):
                    # IPv6 bracketed: [2001:db8::1]:443
                    bracket_end = value.find("]")
                    if bracket_end != -1:
                        value = value[1:bracket_end]
                else:
                    # IPv4: 1.2.3.4:443
                    value = value.rsplit(":", 1)[0]

            # Map confidence to severity
            confidence = entry.get("confidence_level", 50)
            if confidence >= 75:
                severity = IntelSeverity.HIGH
            elif confidence >= 25:
                severity = IntelSeverity.MEDIUM
            else:
                severity = IntelSeverity.LOW

            tags = entry.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]

            malware = entry.get("malware_printable", "")
            threat_type = entry.get("threat_type_desc", "")

            ioc = IOC(
                ioc_type=our_type,
                value=value,
                description=f"ThreatFox: {malware or threat_type or 'IOC'}",
                severity=severity,
                tags=tags,
                source="abuse-ch-threatfox",
                first_seen=first_seen,
                confidence=confidence / 100.0,
            )

            items.append(IntelItem(
                intel_type=IntelType.IOC,
                payload=ioc,
                source_feed=self.name,
                raw_data={
                    "threatfox_id": entry.get("id", ""),
                    "ioc_type": ioc_type_str,
                    "malware": malware,
                    "threat_type": threat_type,
                    "reporter": entry.get("reporter", ""),
                },
            ))

        return items

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_since(self, since: Optional[str]) -> Optional[datetime]:
        """Parse an ISO 8601 since string to a datetime for filtering."""
        if not since:
            return None
        try:
            return datetime.fromisoformat(since.replace("Z", "+00:00")).replace(
                tzinfo=None
            )
        except (ValueError, TypeError):
            return None


class AbuseChFetchError(Exception):
    """Raised when abuse.ch API requests fail after all retries."""
