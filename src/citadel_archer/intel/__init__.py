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
from .queue import IntelQueue

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
    # Queue
    "IntelQueue",
]
