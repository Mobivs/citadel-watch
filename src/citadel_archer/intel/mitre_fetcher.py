# PRD: Intel Module - MITRE ATT&CK Feed Fetcher
# Reference: docs/PRD.md v0.3.13
#
# Concrete IntelFetcher for MITRE ATT&CK framework.
# Fetches the Enterprise ATT&CK STIX 2.1 JSON bundle from the
# official MITRE CTI GitHub repository and extracts:
#   - TTP entries (attack-pattern objects → technique_id, name, tactic, platforms)
#
# The STIX bundle is ~15MB. We parse it in-memory, extracting only
# attack-pattern objects and their tactic relationships.
#
# Design mirrors OTXFetcher: retry with backoff, configurable endpoint.
# No API key required — the STIX JSON is publicly hosted.

import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from .fetcher import IntelFetcher
from .models import (
    TTP,
    IntelItem,
    IntelSeverity,
    IntelType,
)

logger = logging.getLogger(__name__)

# Default: MITRE ATT&CK Enterprise STIX 2.1 bundle
DEFAULT_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# STIX object types we care about
ATTACK_PATTERN_TYPE = "attack-pattern"
RELATIONSHIP_TYPE = "relationship"

# MITRE ATT&CK external reference source name
MITRE_SOURCE = "mitre-attack"

# Retry configuration (matches OTX pattern)
MAX_RETRIES = 3
INITIAL_BACKOFF_SEC = 1.0
BACKOFF_MULTIPLIER = 2.0
REQUEST_TIMEOUT_SEC = 120  # STIX bundle is large (~15MB)


class MitreFetcher(IntelFetcher):
    """MITRE ATT&CK threat intelligence feed fetcher.

    Fetches the Enterprise ATT&CK STIX 2.1 bundle and extracts
    attack-pattern objects as TTP IntelItems.

    Usage::

        fetcher = MitreFetcher()
        fetcher.configure()
        items = fetcher.fetch()
    """

    def __init__(self):
        super().__init__("mitre-attack")
        self._stix_url: str = DEFAULT_STIX_URL
        self._max_techniques: int = 2000
        self._platforms_filter: Optional[List[str]] = None

    # ------------------------------------------------------------------
    # IntelFetcher interface
    # ------------------------------------------------------------------

    def configure(self, **kwargs) -> None:
        """Configure the MITRE ATT&CK fetcher.

        Keyword Args:
            stix_url: Override the STIX bundle URL.
            max_techniques: Max techniques to extract (default 2000).
            platforms: Filter to specific platforms (e.g. ["windows", "linux"]).
        """
        self._stix_url = kwargs.get("stix_url", DEFAULT_STIX_URL)
        self._max_techniques = kwargs.get("max_techniques", 2000)
        self._platforms_filter = kwargs.get("platforms")

    def fetch(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch ATT&CK techniques from the STIX bundle.

        Args:
            since: ISO 8601 timestamp — only return techniques modified
                   after this time. None fetches all.

        Returns:
            List of IntelItem wrappers (TTP type).
        """
        try:
            bundle = self._fetch_stix_bundle()
            items = self._parse_bundle(bundle, since=since)
            self.record_fetch(len(items))
            return items
        except Exception:
            self.record_error()
            raise

    def health_check(self) -> bool:
        """Verify that the STIX bundle URL is reachable."""
        try:
            resp = httpx.head(
                self._stix_url,
                headers={"User-Agent": "CitadelArcher/0.1"},
                timeout=15,
                follow_redirects=True,
            )
            return resp.status_code == 200
        except Exception:
            return False

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _request(self, method: str, url: str) -> httpx.Response:
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
                    timeout=REQUEST_TIMEOUT_SEC,
                    follow_redirects=True,
                )

                if resp.status_code < 400:
                    return resp

                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    wait = float(retry_after) if retry_after else backoff
                    logger.warning(
                        "MITRE rate limited (429), retrying in %.1fs "
                        "(attempt %d/%d)",
                        wait, attempt, MAX_RETRIES,
                    )
                    time.sleep(wait)
                    backoff *= BACKOFF_MULTIPLIER
                    continue

                if resp.status_code >= 500:
                    logger.warning(
                        "MITRE server error %d, retrying in %.1fs "
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
                        "MITRE request failed (%s), retrying in %.1fs "
                        "(attempt %d/%d)",
                        exc, backoff, attempt, MAX_RETRIES,
                    )
                    time.sleep(backoff)
                    backoff *= BACKOFF_MULTIPLIER

        raise MitreFetchError(
            f"MITRE request failed after {MAX_RETRIES} attempts: {last_exc}"
        )

    # ------------------------------------------------------------------
    # STIX bundle fetch + parse
    # ------------------------------------------------------------------

    def _fetch_stix_bundle(self) -> Dict[str, Any]:
        """Download the STIX 2.1 JSON bundle."""
        resp = self._request("GET", self._stix_url)
        return resp.json()

    def _parse_bundle(
        self,
        bundle: Dict[str, Any],
        since: Optional[str] = None,
    ) -> List[IntelItem]:
        """Parse STIX bundle into TTP IntelItems.

        Extracts attack-pattern objects and maps them to TTP models
        with technique ID, name, tactic(s), platforms, and references.
        """
        objects = bundle.get("objects", [])

        # First pass: collect tactic names from x-mitre-tactic objects
        # and relationship (attack-pattern uses x-mitre-tactic)
        tactic_map = self._build_tactic_map(objects)

        # Second pass: extract attack-patterns
        items: List[IntelItem] = []
        count = 0

        for obj in objects:
            if obj.get("type") != ATTACK_PATTERN_TYPE:
                continue

            # Skip revoked/deprecated techniques
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            # Time filter (proper datetime comparison for timezone variants)
            if since:
                modified = obj.get("modified", "")
                if modified:
                    try:
                        mod_dt = datetime.fromisoformat(
                            modified.replace("Z", "+00:00")
                        ).replace(tzinfo=None)
                        since_dt = datetime.fromisoformat(
                            since.replace("Z", "+00:00")
                        ).replace(tzinfo=None)
                        if mod_dt < since_dt:
                            continue
                    except (ValueError, TypeError):
                        pass

            technique = self._parse_attack_pattern(obj, tactic_map)
            if technique is None:
                continue

            # Platform filter
            if self._platforms_filter:
                technique_platforms = [p.lower() for p in technique.payload.platforms]
                if not any(
                    p.lower() in technique_platforms
                    for p in self._platforms_filter
                ):
                    continue

            items.append(technique)
            count += 1
            if count >= self._max_techniques:
                break

        return items

    def _build_tactic_map(
        self, objects: List[Dict[str, Any]]
    ) -> Dict[str, List[str]]:
        """Build a map of attack-pattern STIX ID -> list of tactic names.

        Uses kill_chain_phases in attack-pattern objects directly.
        """
        # ATT&CK embeds tactics directly in kill_chain_phases
        # No separate relationship lookup needed
        tactic_map: Dict[str, List[str]] = {}

        for obj in objects:
            if obj.get("type") != ATTACK_PATTERN_TYPE:
                continue

            stix_id = obj.get("id", "")
            phases = obj.get("kill_chain_phases", [])
            tactics = []
            for phase in phases:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name", ""))
            if tactics:
                tactic_map[stix_id] = tactics

        return tactic_map

    def _parse_attack_pattern(
        self,
        obj: Dict[str, Any],
        tactic_map: Dict[str, List[str]],
    ) -> Optional[IntelItem]:
        """Parse a single STIX attack-pattern into a TTP IntelItem."""
        # Extract technique ID from external references
        technique_id = ""
        references: List[str] = []

        for ref in obj.get("external_references", []):
            if ref.get("source_name") == MITRE_SOURCE:
                technique_id = ref.get("external_id", "")
                url = ref.get("url", "")
                if url:
                    references.append(url)
            elif ref.get("url"):
                references.append(ref["url"])

        if not technique_id:
            return None

        name = obj.get("name", "")
        description = obj.get("description", "")
        # Truncate long descriptions
        if len(description) > 500:
            description = description[:497] + "..."

        platforms = obj.get("x_mitre_platforms", [])
        data_sources = obj.get("x_mitre_data_sources", [])

        # Get tactics from the map
        stix_id = obj.get("id", "")
        tactics = tactic_map.get(stix_id, [])
        tactic = tactics[0] if tactics else "unknown"

        # Map severity based on sub-technique vs technique
        # Sub-techniques (e.g., T1059.001) are more specific = higher signal
        if "." in technique_id:
            severity = IntelSeverity.HIGH
        else:
            severity = IntelSeverity.MEDIUM

        ttp = TTP(
            technique_id=technique_id,
            name=name,
            tactic=tactic,
            description=description,
            severity=severity,
            platforms=platforms,
            data_sources=data_sources,
            mitigations=[],  # Would require separate STIX relationship lookup
            references=references[:5],  # Cap references
        )

        return IntelItem(
            intel_type=IntelType.TTP,
            payload=ttp,
            source_feed=self.name,
            raw_data={
                "stix_id": stix_id,
                "technique_id": technique_id,
                "tactics": tactics,
                "modified": obj.get("modified", ""),
                "created": obj.get("created", ""),
            },
        )


class MitreFetchError(Exception):
    """Raised when MITRE ATT&CK fetch fails after all retries."""
