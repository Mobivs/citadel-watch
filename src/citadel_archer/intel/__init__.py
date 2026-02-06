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
from .assets import Asset, AssetPlatform, AssetStatus, AssetInventory
from .event_aggregator import (
    EventAggregator,
    EventCategory,
    AggregatedEvent,
    categorize_event,
)
from .context_engine import (
    ContextEngine,
    AssetBaseline,
    BaselineResult,
    BehaviorType,
    PatternEntry,
)
from .anomaly_detector import (
    AnomalyDetector,
    AnomalyScore,
    DetectionRule,
    ThreatLevel,
    Sensitivity,
)

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
    # Assets
    "Asset",
    "AssetPlatform",
    "AssetStatus",
    "AssetInventory",
    # Event Aggregator
    "EventAggregator",
    "EventCategory",
    "AggregatedEvent",
    "categorize_event",
    # Context Engine
    "ContextEngine",
    "AssetBaseline",
    "BaselineResult",
    "BehaviorType",
    "PatternEntry",
    # Anomaly Detector
    "AnomalyDetector",
    "AnomalyScore",
    "DetectionRule",
    "ThreatLevel",
    "Sensitivity",
]
