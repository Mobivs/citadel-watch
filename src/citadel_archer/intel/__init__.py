# PRD: Intel Module - Threat Intelligence Foundation
# Reference: docs/PRD.md v0.2.3, PHASE_2_SPEC.md
#
# Provides threat intelligence data models, storage, ingestion queue,
# deduplication, and abstract base for feed fetchers.

from .models import (
    IntelType,
    IntelSeverity,
    CVE,
    IOC,
    TTP,
    Vulnerability,
    IntelItem,
)
from .store import IntelStore
from .fetcher import IntelFetcher
from .otx_fetcher import OTXFetcher, OTXFetchError
from .queue import IntelQueue
from .aggregator import IntelAggregator, AggregationReport, FetchResult

__all__ = [
    # Data models
    "IntelType",
    "IntelSeverity",
    "CVE",
    "IOC",
    "TTP",
    "Vulnerability",
    "IntelItem",
    # Storage
    "IntelStore",
    # Fetcher
    "IntelFetcher",
    "OTXFetcher",
    "OTXFetchError",
    # Queue
    "IntelQueue",
    # Aggregator
    "IntelAggregator",
    "AggregationReport",
    "FetchResult",
]
