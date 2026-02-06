# PRD: Intel Module - Abstract Feed Fetcher
# Reference: PHASE_2_SPEC.md
#
# Defines the IntelFetcher abstract base class that all concrete
# feed integrations (NVD, AlienVault OTX, MITRE ATT&CK, etc.)
# must implement.  No external fetching is performed here — this
# is the contract only.

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional

from .models import IntelItem


class IntelFetcher(ABC):
    """Abstract base class for threat intelligence feed fetchers.

    Concrete implementations will handle API keys, rate limiting,
    pagination, and feed-specific parsing.  Each fetcher produces
    a list of ``IntelItem`` objects that the pipeline can deduplicate
    and store.

    Lifecycle:
        1. ``configure()`` — set API keys, base URLs, intervals
        2. ``fetch()`` — pull new data and return ``IntelItem`` list
        3. ``health_check()`` — verify the feed is reachable
    """

    def __init__(self, name: str):
        self.name = name
        self._last_fetch: Optional[str] = None
        self._fetch_count: int = 0
        self._error_count: int = 0

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    def configure(self, **kwargs) -> None:
        """Configure the fetcher (API keys, endpoints, etc.).

        Called once before the first ``fetch()``.  Concrete fetchers
        store whatever parameters they need.

        Keyword Args:
            api_key: API key for the feed (if required)
            base_url: Override default base URL
            interval_seconds: Polling interval
        """

    @abstractmethod
    def fetch(self, since: Optional[str] = None) -> List[IntelItem]:
        """Fetch new threat intel items from the feed.

        Args:
            since: ISO 8601 timestamp — only return items published
                   after this time.  ``None`` means fetch all available.

        Returns:
            List of ``IntelItem`` wrappers ready for the pipeline.
        """

    @abstractmethod
    def health_check(self) -> bool:
        """Return True if the feed source is reachable and healthy."""

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def record_fetch(self, count: int) -> None:
        """Record a successful fetch for stats tracking."""
        self._last_fetch = datetime.utcnow().isoformat()
        self._fetch_count += count

    def record_error(self) -> None:
        """Record a fetch error for stats tracking."""
        self._error_count += 1

    def get_stats(self) -> Dict[str, object]:
        """Return fetcher statistics."""
        return {
            "name": self.name,
            "last_fetch": self._last_fetch,
            "total_fetched": self._fetch_count,
            "total_errors": self._error_count,
        }
