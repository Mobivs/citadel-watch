# PRD: Intel Module - Anomaly Detector (Isolation Forest + Rules)
# Reference: PHASE_2_SPEC.md
#
# Multi-dimensional anomaly detection combining:
#   1. Isolation Forest (scikit-learn) for statistical anomaly scoring
#   2. Custom rule engine for known-bad patterns (e.g. unsigned
#      executables in system directories)
#
# Outputs a deviation score 0.0 (normal) to 1.0 (highly anomalous),
# mapped to threat levels LOW / MEDIUM / HIGH.
# Supports adjustable sensitivity: LOW, MODERATE (default), HIGH.
# Handles cold start: returns LOW threat with reduced confidence
# until sufficient training samples are collected.

import math
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from .event_aggregator import AggregatedEvent, EventCategory

# Attempt to import sklearn; fall back to a lightweight Z-score
# approach if unavailable.
try:
    from sklearn.ensemble import IsolationForest as _SKLearnIF

    _HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    _HAS_SKLEARN = False


# ── Enums ────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    """Mapped threat level from anomaly score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Sensitivity(str, Enum):
    """Detector sensitivity preset."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


# Contamination parameter per sensitivity (used by Isolation Forest)
_SENSITIVITY_CONTAMINATION: Dict[Sensitivity, float] = {
    Sensitivity.LOW: 0.15,
    Sensitivity.MODERATE: 0.10,
    Sensitivity.HIGH: 0.05,
}

# Score thresholds for threat level mapping per sensitivity
_THREAT_THRESHOLDS: Dict[Sensitivity, Tuple[float, float]] = {
    # (medium_threshold, high_threshold)
    Sensitivity.LOW: (0.55, 0.80),
    Sensitivity.MODERATE: (0.40, 0.70),
    Sensitivity.HIGH: (0.25, 0.55),
}

# Minimum training samples before the model is considered ready
_MIN_TRAINING_SAMPLES = 20


# ── Data structures ──────────────────────────────────────────────────

@dataclass
class AnomalyScore:
    """Result of anomaly analysis on a single event."""

    score: float = 0.0               # 0.0 (normal) → 1.0 (anomalous)
    threat_level: ThreatLevel = ThreatLevel.LOW
    cold_start: bool = False
    rule_hits: List[str] = field(default_factory=list)
    model_score: float = 0.0         # raw isolation forest score
    rule_score: float = 0.0          # max score from rule matches
    event_key: str = ""
    asset_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["threat_level"] = self.threat_level.value
        return d


@dataclass
class DetectionRule:
    """A custom detection rule evaluated against event details."""

    rule_id: str = ""
    name: str = ""
    description: str = ""
    score: float = 0.8               # score assigned when rule matches
    enabled: bool = True
    # The evaluator receives the AggregatedEvent and returns True on match
    evaluate: Callable[[AggregatedEvent], bool] = field(
        default_factory=lambda: (lambda _e: False)
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "score": self.score,
            "enabled": self.enabled,
        }


# ── Built-in rules ──────────────────────────────────────────────────

def _rule_unsigned_exe_system32(event: AggregatedEvent) -> bool:
    """Flag unsigned executables in system directories."""
    details = event.details or {}
    path = (
        details.get("file_path", "")
        or details.get("path", "")
        or details.get("target", "")
    ).lower()
    signed = details.get("signed", True)
    system_dirs = ("system32", "syswow64", "/usr/bin", "/usr/sbin", "/sbin")
    if not signed and any(sd in path for sd in system_dirs):
        return True
    return False


def _rule_process_from_tmp(event: AggregatedEvent) -> bool:
    """Flag processes spawned from temp directories."""
    if event.category != EventCategory.PROCESS:
        return False
    details = event.details or {}
    path = (
        details.get("file_path", "")
        or details.get("path", "")
        or details.get("executable", "")
    ).lower()
    tmp_dirs = ("/tmp", "\\temp", "\\tmp", "/var/tmp", "appdata\\local\\temp")
    return any(td in path for td in tmp_dirs)


def _rule_network_high_port(event: AggregatedEvent) -> bool:
    """Flag outbound connections to unusual high ports."""
    if event.category != EventCategory.NETWORK:
        return False
    details = event.details or {}
    port = details.get("port", details.get("dst_port", 0))
    try:
        port = int(port)
    except (ValueError, TypeError):
        return False
    # Uncommon high ports often used for C2
    suspicious_ports = {4444, 5555, 6666, 8888, 9999, 1337, 31337}
    return port in suspicious_ports


def _rule_critical_file_modification(event: AggregatedEvent) -> bool:
    """Flag modifications to critical system files."""
    if event.category != EventCategory.FILE:
        return False
    details = event.details or {}
    path = (
        details.get("file_path", "")
        or details.get("path", "")
    ).lower()
    critical_paths = (
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "\\windows\\system32\\config",
        "/etc/ssh/sshd_config",
    )
    return any(cp in path for cp in critical_paths)


def _rule_suspicious_severity(event: AggregatedEvent) -> bool:
    """Flag events already marked as suspicious or critical."""
    return event.severity in ("alert", "critical")


def _default_rules() -> List[DetectionRule]:
    """Return the built-in rule set."""
    return [
        DetectionRule(
            rule_id="R001",
            name="unsigned_exe_system_dir",
            description="Unsigned executable in system directory",
            score=0.9,
            evaluate=_rule_unsigned_exe_system32,
        ),
        DetectionRule(
            rule_id="R002",
            name="process_from_tmp",
            description="Process spawned from temp directory",
            score=0.75,
            evaluate=_rule_process_from_tmp,
        ),
        DetectionRule(
            rule_id="R003",
            name="network_suspicious_port",
            description="Connection to suspicious high port",
            score=0.7,
            evaluate=_rule_network_high_port,
        ),
        DetectionRule(
            rule_id="R004",
            name="critical_file_modification",
            description="Modification to critical system file",
            score=0.85,
            evaluate=_rule_critical_file_modification,
        ),
        DetectionRule(
            rule_id="R005",
            name="high_severity_event",
            description="Event already flagged as alert/critical",
            score=0.6,
            evaluate=_rule_suspicious_severity,
        ),
    ]


# ── Feature extraction ───────────────────────────────────────────────

# Feature dimensions (order matters — must match training & scoring)
_FEATURE_NAMES = [
    "hour_of_day",          # 0-23 normalised to 0-1
    "category_ordinal",     # ordinal encoding of EventCategory
    "severity_ordinal",     # ordinal encoding of severity
    "event_type_freq",      # how often this event_type has been seen (log)
    "asset_event_freq",     # how many events this asset has generated (log)
]

_CATEGORY_ORDINAL: Dict[str, float] = {
    "file": 0.0, "process": 0.2, "network": 0.4,
    "vault": 0.5, "system": 0.6, "ai": 0.7, "user": 0.8, "intel": 1.0,
}

_SEVERITY_ORDINAL: Dict[str, float] = {
    "info": 0.0, "investigate": 0.33, "alert": 0.66, "critical": 1.0,
}


# ── Lightweight fallback model ───────────────────────────────────────

class _ZScoreModel:
    """Simple Z-score anomaly model used when sklearn is unavailable."""

    def __init__(self, contamination: float = 0.1):
        self._contamination = contamination
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._fitted = False

    def fit(self, X: np.ndarray) -> "_ZScoreModel":
        self._mean = np.mean(X, axis=0)
        self._std = np.std(X, axis=0)
        # Prevent division by zero
        self._std[self._std == 0] = 1.0
        self._fitted = True
        return self

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted:
            return np.zeros(X.shape[0])
        z = np.abs((X - self._mean) / self._std)
        # Average Z-score across features, negate (sklearn convention:
        # more negative = more anomalous)
        return -np.mean(z, axis=1)


# ── AnomalyDetector ─────────────────────────────────────────────────

class AnomalyDetector:
    """Multi-dimensional anomaly detector combining Isolation Forest
    and custom rule evaluation.

    Args:
        sensitivity: Detection sensitivity preset (LOW / MODERATE / HIGH).
        min_training_samples: Number of events needed before the
            statistical model produces scores (cold-start threshold).
    """

    def __init__(
        self,
        sensitivity: Sensitivity = Sensitivity.MODERATE,
        min_training_samples: int = _MIN_TRAINING_SAMPLES,
    ):
        self._sensitivity = sensitivity
        self._min_samples = min_training_samples
        self._lock = threading.RLock()

        # Rules
        self._rules: List[DetectionRule] = _default_rules()

        # Feature / training state
        self._training_data: List[np.ndarray] = []
        self._event_type_counts: Dict[str, int] = defaultdict(int)
        self._asset_event_counts: Dict[str, int] = defaultdict(int)
        self._model_fitted = False

        # Model
        contamination = _SENSITIVITY_CONTAMINATION[sensitivity]
        if _HAS_SKLEARN:
            self._model = _SKLearnIF(
                n_estimators=100,
                contamination=contamination,
                random_state=42,
            )
        else:
            self._model = _ZScoreModel(contamination=contamination)

        # Stats
        self._total_scored = 0
        self._anomalies_detected = 0

    # ------------------------------------------------------------------
    # Sensitivity
    # ------------------------------------------------------------------

    @property
    def sensitivity(self) -> Sensitivity:
        return self._sensitivity

    def set_sensitivity(self, sensitivity: Sensitivity) -> None:
        """Change sensitivity (resets the model so it must be retrained)."""
        with self._lock:
            self._sensitivity = sensitivity
            contamination = _SENSITIVITY_CONTAMINATION[sensitivity]
            if _HAS_SKLEARN:
                self._model = _SKLearnIF(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42,
                )
            else:
                self._model = _ZScoreModel(contamination=contamination)
            self._model_fitted = False

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def add_rule(self, rule: DetectionRule) -> None:
        """Register a custom detection rule."""
        with self._lock:
            self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if found."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.rule_id != rule_id]
            return len(self._rules) < before

    def list_rules(self) -> List[Dict[str, Any]]:
        """Return rule metadata."""
        with self._lock:
            return [r.to_dict() for r in self._rules]

    def _evaluate_rules(self, event: AggregatedEvent) -> Tuple[float, List[str]]:
        """Run all enabled rules; return (max_score, [matched_rule_ids])."""
        max_score = 0.0
        hits: List[str] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            try:
                if rule.evaluate(event):
                    hits.append(rule.rule_id)
                    if rule.score > max_score:
                        max_score = rule.score
            except Exception:
                pass  # rules must not crash the detector
        return max_score, hits

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------

    def _extract_features(self, event: AggregatedEvent) -> np.ndarray:
        """Convert an event to a feature vector."""
        try:
            ts = datetime.fromisoformat(event.timestamp)
            hour_norm = ts.hour / 23.0
        except (ValueError, TypeError):
            hour_norm = 0.5

        cat_ord = _CATEGORY_ORDINAL.get(event.category.value, 0.5)
        sev_ord = _SEVERITY_ORDINAL.get(event.severity.lower(), 0.0)

        et_count = self._event_type_counts.get(event.event_type, 0)
        et_freq = math.log1p(et_count) / 10.0  # normalise roughly

        asset_id = event.asset_id or "_global"
        ae_count = self._asset_event_counts.get(asset_id, 0)
        ae_freq = math.log1p(ae_count) / 10.0

        return np.array([hour_norm, cat_ord, sev_ord, et_freq, ae_freq])

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    @property
    def is_cold_start(self) -> bool:
        with self._lock:
            return len(self._training_data) < self._min_samples

    @property
    def training_size(self) -> int:
        with self._lock:
            return len(self._training_data)

    def train(self, events: List[AggregatedEvent]) -> int:
        """Bulk-train the model on historical (assumed normal) events.

        Returns the number of events added to the training set.
        """
        with self._lock:
            for event in events:
                self._event_type_counts[event.event_type] += 1
                asset_id = event.asset_id or "_global"
                self._asset_event_counts[asset_id] += 1
                self._training_data.append(self._extract_features(event))

            if len(self._training_data) >= self._min_samples:
                self._fit_model()

        return len(events)

    def _fit_model(self) -> None:
        """Fit the isolation forest on current training data (must hold lock)."""
        X = np.vstack(self._training_data)
        self._model.fit(X)
        self._model_fitted = True

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _model_anomaly_score(self, features: np.ndarray) -> float:
        """Get anomaly score from the model (0 = normal, 1 = anomalous)."""
        if not self._model_fitted:
            return 0.0
        raw = self._model.decision_function(features.reshape(1, -1))[0]
        # sklearn IF decision_function: negative = anomalous
        # Map to 0-1 where 1 = most anomalous
        score = max(0.0, min(1.0, 0.5 - raw))
        return round(score, 4)

    def _map_threat_level(self, score: float) -> ThreatLevel:
        """Map a 0-1 score to a threat level using sensitivity thresholds."""
        med, high = _THREAT_THRESHOLDS[self._sensitivity]
        if score >= high:
            return ThreatLevel.HIGH
        if score >= med:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def score_event(self, event: AggregatedEvent) -> AnomalyScore:
        """Score a single event for anomalousness.

        Combines the Isolation Forest model score with rule-based
        evaluation.  The final score is ``max(model_score, rule_score)``.
        """
        with self._lock:
            # Update frequency counters
            self._event_type_counts[event.event_type] += 1
            asset_id = event.asset_id or "_global"
            self._asset_event_counts[asset_id] += 1

            features = self._extract_features(event)
            cold = self.is_cold_start

            # Model score
            model_score = self._model_anomaly_score(features)

            # Rule score
            rule_score, rule_hits = self._evaluate_rules(event)

            # Combined score
            combined = max(model_score, rule_score)
            threat = self._map_threat_level(combined)

            # Accumulate training data (online learning)
            self._training_data.append(features)
            if (
                not self._model_fitted
                and len(self._training_data) >= self._min_samples
            ):
                self._fit_model()

            self._total_scored += 1
            if threat != ThreatLevel.LOW:
                self._anomalies_detected += 1

        return AnomalyScore(
            score=round(combined, 4),
            threat_level=threat,
            cold_start=cold,
            rule_hits=rule_hits,
            model_score=model_score,
            rule_score=rule_score,
            event_key=event.event_type,
            asset_id=asset_id,
        )

    # ------------------------------------------------------------------
    # Batch / subscription
    # ------------------------------------------------------------------

    def score_batch(
        self, events: List[AggregatedEvent]
    ) -> List[AnomalyScore]:
        """Score multiple events."""
        return [self.score_event(e) for e in events]

    def on_event(self, event: AggregatedEvent) -> None:
        """Callback for ``EventAggregator.subscribe()`` — fire-and-forget."""
        self.score_event(event)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "sensitivity": self._sensitivity.value,
                "model_fitted": self._model_fitted,
                "training_samples": len(self._training_data),
                "min_training_samples": self._min_samples,
                "cold_start": self.is_cold_start,
                "total_scored": self._total_scored,
                "anomalies_detected": self._anomalies_detected,
                "rules_count": len(self._rules),
                "has_sklearn": _HAS_SKLEARN,
            }

    def reset(self) -> None:
        """Reset all state (model, training data, counters)."""
        with self._lock:
            self._training_data.clear()
            self._event_type_counts.clear()
            self._asset_event_counts.clear()
            self._model_fitted = False
            self._total_scored = 0
            self._anomalies_detected = 0
            contamination = _SENSITIVITY_CONTAMINATION[self._sensitivity]
            if _HAS_SKLEARN:
                self._model = _SKLearnIF(
                    n_estimators=100,
                    contamination=contamination,
                    random_state=42,
                )
            else:
                self._model = _ZScoreModel(contamination=contamination)
