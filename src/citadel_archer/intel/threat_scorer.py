# PRD: Intel Module - Threat Scorer (Risk Assessment)
# Reference: PHASE_2_SPEC.md
#
# Produces a prioritised threat assessment for security events by
# combining:
#   1. Risk matrix: Severity × Confidence
#   2. Intel cross-reference: matches event artifacts against the
#      IntelStore (IOC hashes, CVE IDs, MITRE TTP technique IDs)
#   3. Anomaly score from the AnomalyDetector
#
# Output: a ``ScoredThreat`` with a ``RiskLevel`` (LOW / MEDIUM /
# HIGH / CRITICAL) and a numeric ``risk_score`` (0.0 – 1.0).
# Multiple threats are returned as a priority-sorted list.

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from .anomaly_detector import AnomalyDetector, AnomalyScore, ThreatLevel
from .event_aggregator import AggregatedEvent, EventCategory
from .models import IOCType, IntelSeverity, IntelType
from .store import IntelStore


# ── Enums ────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    """Final risk classification after scoring."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Numeric rank for sorting (higher = worse)
_RISK_RANK: Dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}

# Severity string → numeric weight (0-1)
_SEVERITY_WEIGHT: Dict[str, float] = {
    "info": 0.1,
    "investigate": 0.35,
    "alert": 0.65,
    "critical": 1.0,
    # IntelSeverity values
    "none": 0.0,
    "low": 0.2,
    "medium": 0.5,
    "high": 0.8,
}

# Risk matrix thresholds — (medium, high, critical)
_RISK_THRESHOLDS = (0.30, 0.55, 0.80)


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class IntelMatch:
    """Record of a match between an event artifact and the Intel Store."""

    intel_type: str = ""       # "ioc", "cve", "ttp", "vulnerability"
    dedup_key: str = ""
    severity: str = ""
    source_feed: str = ""
    payload_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScoredThreat:
    """A fully scored threat combining all signals."""

    event_id: str = ""
    event_type: str = ""
    asset_id: str = ""
    risk_score: float = 0.0        # 0.0 (benign) → 1.0 (critical)
    risk_level: RiskLevel = RiskLevel.LOW
    severity_weight: float = 0.0
    anomaly_score: float = 0.0
    intel_score: float = 0.0       # boost from intel cross-ref
    intel_matches: List[IntelMatch] = field(default_factory=list)
    anomaly_detail: Optional[AnomalyScore] = None
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        if self.anomaly_detail:
            d["anomaly_detail"]["threat_level"] = self.anomaly_detail.threat_level.value
        d["intel_matches"] = [m.to_dict() for m in self.intel_matches]
        return d


# ── ThreatScorer ─────────────────────────────────────────────────────

class ThreatScorer:
    """Risk-assessment engine combining severity, anomaly detection,
    and intel-feed cross-referencing.

    Args:
        intel_store: Optional ``IntelStore`` for cross-referencing
            event artifacts against known threats.
        anomaly_detector: Optional ``AnomalyDetector`` for statistical
            anomaly scoring.
        severity_weight: Weight of the event severity component (0-1).
        anomaly_weight: Weight of the anomaly score component (0-1).
        intel_weight: Weight of the intel cross-ref component (0-1).
    """

    def __init__(
        self,
        intel_store: Optional[IntelStore] = None,
        anomaly_detector: Optional[AnomalyDetector] = None,
        severity_weight: float = 0.30,
        anomaly_weight: float = 0.35,
        intel_weight: float = 0.35,
    ):
        self._store = intel_store
        self._detector = anomaly_detector
        self._w_severity = severity_weight
        self._w_anomaly = anomaly_weight
        self._w_intel = intel_weight
        self._lock = threading.RLock()

        # Stats
        self._total_scored = 0
        self._by_risk: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Intel cross-referencing
    # ------------------------------------------------------------------

    def _extract_artifacts(self, event: AggregatedEvent) -> Dict[str, List[str]]:
        """Pull searchable artifacts from event details.

        Returns a dict mapping artifact type to a list of values:
        ``{"hash": [...], "ip": [...], "domain": [...], "cve": [...],
          "technique_id": [...]}``
        """
        details = event.details or {}
        artifacts: Dict[str, List[str]] = {
            "hash": [],
            "ip": [],
            "domain": [],
            "cve": [],
            "technique_id": [],
        }

        # Hashes
        for key in ("sha256", "sha1", "md5", "file_hash", "hash"):
            val = details.get(key)
            if val:
                artifacts["hash"].append(str(val))

        # IPs
        for key in ("ip", "ip_address", "src_ip", "dst_ip", "remote_ip"):
            val = details.get(key)
            if val:
                artifacts["ip"].append(str(val))

        # Domains
        for key in ("domain", "host", "hostname"):
            val = details.get(key)
            if val:
                artifacts["domain"].append(str(val))

        # CVE IDs
        for key in ("cve_id", "cve"):
            val = details.get(key)
            if val:
                artifacts["cve"].append(str(val))

        # MITRE technique IDs
        for key in ("technique_id", "mitre_id", "ttp"):
            val = details.get(key)
            if val:
                artifacts["technique_id"].append(str(val))

        return artifacts

    def _cross_reference(self, event: AggregatedEvent) -> List[IntelMatch]:
        """Look up event artifacts in the IntelStore."""
        if self._store is None:
            return []

        artifacts = self._extract_artifacts(event)
        matches: List[IntelMatch] = []

        # Hash → IOC lookup
        hash_type_map = {
            "md5": IOCType.FILE_HASH_MD5,
            "sha1": IOCType.FILE_HASH_SHA1,
            "sha256": IOCType.FILE_HASH_SHA256,
        }
        for h in artifacts["hash"]:
            for suffix, ioc_type in hash_type_map.items():
                dedup = f"ioc:{ioc_type.value}:{h}"
                if self._store.has_key(dedup):
                    row = self._lookup_by_dedup(dedup)
                    matches.append(IntelMatch(
                        intel_type="ioc",
                        dedup_key=dedup,
                        severity=row.get("severity", "medium") if row else "medium",
                        source_feed=row.get("source_feed", "") if row else "",
                        payload_summary=f"File hash match ({suffix}): {h}",
                    ))

        # IP → IOC lookup
        for ip in artifacts["ip"]:
            dedup = f"ioc:ip:{ip}"
            if self._store.has_key(dedup):
                row = self._lookup_by_dedup(dedup)
                matches.append(IntelMatch(
                    intel_type="ioc",
                    dedup_key=dedup,
                    severity=row.get("severity", "medium") if row else "medium",
                    source_feed=row.get("source_feed", "") if row else "",
                    payload_summary=f"IP address match: {ip}",
                ))

        # Domain → IOC lookup
        for domain in artifacts["domain"]:
            dedup = f"ioc:domain:{domain}"
            if self._store.has_key(dedup):
                row = self._lookup_by_dedup(dedup)
                matches.append(IntelMatch(
                    intel_type="ioc",
                    dedup_key=dedup,
                    severity=row.get("severity", "medium") if row else "medium",
                    source_feed=row.get("source_feed", "") if row else "",
                    payload_summary=f"Domain match: {domain}",
                ))

        # CVE → CVE lookup
        for cve_id in artifacts["cve"]:
            dedup = f"cve:{cve_id}"
            if self._store.has_key(dedup):
                row = self._lookup_by_dedup(dedup)
                matches.append(IntelMatch(
                    intel_type="cve",
                    dedup_key=dedup,
                    severity=row.get("severity", "high") if row else "high",
                    source_feed=row.get("source_feed", "") if row else "",
                    payload_summary=f"CVE match: {cve_id}",
                ))

        # TTP → TTP lookup
        for tid in artifacts["technique_id"]:
            dedup = f"ttp:{tid}"
            if self._store.has_key(dedup):
                row = self._lookup_by_dedup(dedup)
                matches.append(IntelMatch(
                    intel_type="ttp",
                    dedup_key=dedup,
                    severity=row.get("severity", "medium") if row else "medium",
                    source_feed=row.get("source_feed", "") if row else "",
                    payload_summary=f"MITRE TTP match: {tid}",
                ))

        return matches

    def _lookup_by_dedup(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        """Fetch a row from the store by dedup_key (best-effort)."""
        if self._store is None:
            return None
        try:
            rows = self._store._conn.execute(
                "SELECT * FROM intel_items WHERE dedup_key = ? LIMIT 1",
                (dedup_key,),
            ).fetchone()
            return dict(rows) if rows else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_to_weight(severity: str) -> float:
        return _SEVERITY_WEIGHT.get(severity.lower(), 0.1)

    @staticmethod
    def _intel_match_score(matches: List[IntelMatch]) -> float:
        """Compute an intel score from matches (0-1).

        Uses the highest-severity match as the base, boosted slightly
        by additional matches.
        """
        if not matches:
            return 0.0
        max_sev = max(
            _SEVERITY_WEIGHT.get(m.severity.lower(), 0.3) for m in matches
        )
        # Small boost per additional match (up to 0.15 extra)
        extra = min(0.15, (len(matches) - 1) * 0.05)
        return min(1.0, max_sev + extra)

    @staticmethod
    def _map_risk_level(score: float) -> RiskLevel:
        med, high, crit = _RISK_THRESHOLDS
        if score >= crit:
            return RiskLevel.CRITICAL
        if score >= high:
            return RiskLevel.HIGH
        if score >= med:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def score_event(self, event: AggregatedEvent) -> ScoredThreat:
        """Produce a full risk assessment for a single event."""
        with self._lock:
            # 1. Severity component
            sev_w = self._severity_to_weight(event.severity)

            # 2. Anomaly component
            anomaly_result: Optional[AnomalyScore] = None
            anomaly_val = 0.0
            if self._detector is not None:
                anomaly_result = self._detector.score_event(event)
                anomaly_val = anomaly_result.score

            # 3. Intel cross-ref component
            intel_matches = self._cross_reference(event)
            intel_val = self._intel_match_score(intel_matches)

            # Weighted combination
            risk_score = (
                self._w_severity * sev_w
                + self._w_anomaly * anomaly_val
                + self._w_intel * intel_val
            )
            risk_score = round(min(1.0, max(0.0, risk_score)), 4)
            risk_level = self._map_risk_level(risk_score)

            self._total_scored += 1
            self._by_risk[risk_level.value] = (
                self._by_risk.get(risk_level.value, 0) + 1
            )

        return ScoredThreat(
            event_id=event.event_id,
            event_type=event.event_type,
            asset_id=event.asset_id or "",
            risk_score=risk_score,
            risk_level=risk_level,
            severity_weight=sev_w,
            anomaly_score=anomaly_val,
            intel_score=intel_val,
            intel_matches=intel_matches,
            anomaly_detail=anomaly_result,
            timestamp=event.timestamp,
        )

    # ------------------------------------------------------------------
    # Batch & priority list
    # ------------------------------------------------------------------

    def score_batch(
        self, events: List[AggregatedEvent]
    ) -> List[ScoredThreat]:
        """Score multiple events and return sorted by risk (highest first)."""
        threats = [self.score_event(e) for e in events]
        threats.sort(
            key=lambda t: _RISK_RANK.get(t.risk_level, 0),
            reverse=True,
        )
        return threats

    def prioritised_threats(
        self,
        events: List[AggregatedEvent],
        min_level: RiskLevel = RiskLevel.MEDIUM,
    ) -> List[ScoredThreat]:
        """Return only threats at or above ``min_level``, priority-sorted."""
        threshold = _RISK_RANK[min_level]
        scored = self.score_batch(events)
        return [
            t for t in scored
            if _RISK_RANK.get(t.risk_level, 0) >= threshold
        ]

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_scored": self._total_scored,
                "by_risk_level": dict(self._by_risk),
                "has_intel_store": self._store is not None,
                "has_anomaly_detector": self._detector is not None,
                "weights": {
                    "severity": self._w_severity,
                    "anomaly": self._w_anomaly,
                    "intel": self._w_intel,
                },
            }
