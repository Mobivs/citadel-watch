# PRD: Intel Module - Threat Feed Data Models
# Reference: docs/PRD.md v0.2.3, PHASE_2_SPEC.md
#
# Defines structured data models for threat intelligence:
#   CVE  - Common Vulnerabilities and Exposures
#   IOC  - Indicators of Compromise (hashes, IPs, domains, URLs)
#   TTP  - Tactics, Techniques, and Procedures (MITRE ATT&CK)
#   VULNERABILITY - Software vulnerability affecting a specific product/version
#
# All models share a common IntelItem wrapper for unified handling.

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class IntelType(str, Enum):
    """Classification of threat intelligence data."""

    CVE = "cve"
    IOC = "ioc"
    TTP = "ttp"
    VULNERABILITY = "vulnerability"


class IntelSeverity(str, Enum):
    """Severity rating for threat intel items.

    Aligned with CVSS qualitative ratings.
    """

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> "IntelSeverity":
        """Map a CVSS 3.x score (0.0-10.0) to a severity level."""
        if score <= 0.0:
            return cls.NONE
        if score <= 3.9:
            return cls.LOW
        if score <= 6.9:
            return cls.MEDIUM
        if score <= 8.9:
            return cls.HIGH
        return cls.CRITICAL


class IOCType(str, Enum):
    """Sub-classification of Indicators of Compromise."""

    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH_MD5 = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL = "email"
    FILENAME = "filename"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class CVE:
    """Common Vulnerabilities and Exposures entry.

    Represents a publicly disclosed security vulnerability with a
    standard CVE identifier (e.g. CVE-2024-1234).
    """

    cve_id: str  # e.g. "CVE-2024-1234"
    description: str
    cvss_score: float = 0.0  # CVSS 3.x base score (0.0 - 10.0)
    severity: IntelSeverity = IntelSeverity.NONE
    affected_products: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None  # ISO 8601
    modified_date: Optional[str] = None  # ISO 8601

    def __post_init__(self):
        if self.severity == IntelSeverity.NONE and self.cvss_score > 0:
            self.severity = IntelSeverity.from_cvss(self.cvss_score)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def dedup_key(self) -> str:
        """Unique deduplication key."""
        return f"cve:{self.cve_id}"


@dataclass
class IOC:
    """Indicator of Compromise.

    A technical artifact (IP, domain, hash, etc.) associated with
    malicious activity.
    """

    ioc_type: IOCType
    value: str
    description: str = ""
    severity: IntelSeverity = IntelSeverity.MEDIUM
    tags: List[str] = field(default_factory=list)
    source: str = ""
    first_seen: Optional[str] = None  # ISO 8601
    last_seen: Optional[str] = None  # ISO 8601
    confidence: float = 0.5  # 0.0 - 1.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["ioc_type"] = self.ioc_type.value
        return d

    @property
    def dedup_key(self) -> str:
        """Unique deduplication key."""
        return f"ioc:{self.ioc_type.value}:{self.value}"


@dataclass
class TTP:
    """Tactics, Techniques, and Procedures (MITRE ATT&CK aligned).

    Describes adversary behaviour patterns, mapped to MITRE ATT&CK
    technique IDs where applicable.
    """

    technique_id: str  # e.g. "T1059.001" (MITRE ATT&CK)
    name: str
    tactic: str  # e.g. "execution", "persistence", "lateral-movement"
    description: str = ""
    severity: IntelSeverity = IntelSeverity.MEDIUM
    platforms: List[str] = field(default_factory=list)  # windows, linux, macos
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def dedup_key(self) -> str:
        """Unique deduplication key."""
        return f"ttp:{self.technique_id}"


@dataclass
class Vulnerability:
    """Software vulnerability affecting a specific product/version.

    More granular than CVE — tracks the intersection of a CVE with
    a particular software installation relevant to this system.
    """

    product: str  # e.g. "openssh"
    version: str  # e.g. "8.9p1"
    cve_id: Optional[str] = None  # linked CVE if available
    description: str = ""
    severity: IntelSeverity = IntelSeverity.MEDIUM
    fix_version: Optional[str] = None  # version that fixes the vuln
    is_exploited: bool = False  # known exploitation in the wild
    patch_available: bool = False
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def dedup_key(self) -> str:
        """Unique deduplication key."""
        base = f"vuln:{self.product}:{self.version}"
        if self.cve_id:
            base += f":{self.cve_id}"
        return base


# ---------------------------------------------------------------------------
# Unified wrapper
# ---------------------------------------------------------------------------


@dataclass
class IntelItem:
    """Unified wrapper for all threat intel types.

    Provides a common envelope with metadata, timestamps, and the
    type-specific payload. This is the primary unit of data flowing
    through the intel pipeline (queue -> dedup -> store).
    """

    intel_type: IntelType
    payload: Any  # CVE | IOC | TTP | Vulnerability
    source_feed: str = ""
    item_id: str = field(default_factory=lambda: str(uuid4()))
    ingested_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    raw_data: Optional[Dict[str, Any]] = None  # original feed data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "intel_type": self.intel_type.value,
            "source_feed": self.source_feed,
            "ingested_at": self.ingested_at,
            "payload": self.payload.to_dict() if hasattr(self.payload, "to_dict") else str(self.payload),
        }

    @property
    def dedup_key(self) -> str:
        """Deduplication key derived from the payload."""
        if hasattr(self.payload, "dedup_key"):
            return self.payload.dedup_key
        # Fallback: hash the string representation
        return hashlib.sha256(str(self.payload).encode()).hexdigest()

    @property
    def severity(self) -> IntelSeverity:
        """Severity from the payload."""
        if hasattr(self.payload, "severity"):
            return self.payload.severity
        return IntelSeverity.NONE
