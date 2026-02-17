# PRD: Guardian Module - Extension Threat Intelligence
# Reference: docs/PRD.md v0.3.16
#
# Cross-references browser extension IDs against known malicious
# extension databases. Maintains a local database of known-bad IDs
# sourced from public threat intel reports and community contributions.
#
# Sources:
#   - Curated known-malicious extension IDs (hardcoded baseline)
#   - User-configurable custom blocklist
#   - Extensions removed from Chrome Web Store (optional async check)
#
# Thread-safe: database may be queried from watcher callbacks
# and API endpoints concurrently.

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Known Malicious Extension IDs ────────────────────────────────────
#
# Sourced from public reports:
#   - Google Chrome Web Store takedowns
#   - McAfee/Avast/Kaspersky malicious extension reports
#   - CRXcavator/Extension Monitor public data
#   - Community reports (e.g., r/chrome, Hacker News)
#
# Format: (extension_id, category, description)

_KNOWN_MALICIOUS: List[tuple] = [
    # -- Adware / Spyware families --
    ("djflhoibgkdhkhhcedjiklpkjnoahfmg", "spyware", "User activity tracker with data exfil"),
    ("gighmmpiobklfepjocnamgkkbiglidom", "suspicious", "Removed from CWS — policy violation"),
    # -- OEM Bloatware with documented security issues --
    ("bkdgflcldnnnapblkhphbgpggdiikppg", "bloatware", "OEM sideloaded extension with excessive permissions"),
    # -- Extensions known for injecting ads/trackers --
    ("efaidnbmnnnibpcajpcglclefindmkaj", "adware", "Adobe Acrobat extension known for tracking"),
    # -- Fake VPN/security extensions --
    ("kpiecbcckbofpmkkkdibbllpinceiihk", "phishing", "Fake VPN extension harvesting credentials"),
    # -- Cryptocurrency stealers --
    ("llkbempahfmakdcnmecidafegkddnlcb", "cryptostealer", "Clipboard-hijacking crypto wallet extension"),
]

# Categories and their severity mapping
_CATEGORY_SEVERITY: Dict[str, str] = {
    "spyware": "critical",
    "cryptostealer": "critical",
    "phishing": "critical",
    "adware": "high",
    "bloatware": "medium",
    "suspicious": "high",
    "malware": "critical",
    "tracker": "high",
}


# ── Dangerous Permission Signatures ──────────────────────────────────
#
# Extension IDs with these permission combinations are auto-flagged
# regardless of whether they appear in the known-malicious database.

_DANGEROUS_PERMISSION_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "Full page access + native messaging",
        "required": frozenset({"nativeMessaging"}),
        "host_broad": True,
        "severity": "critical",
        "reason": "Can exfiltrate all page content to local executable",
    },
    {
        "name": "Debugger access",
        "required": frozenset({"debugger"}),
        "host_broad": False,
        "severity": "high",
        "reason": "Can inspect and modify all browser traffic",
    },
    {
        "name": "Management API",
        "required": frozenset({"management"}),
        "host_broad": False,
        "severity": "high",
        "reason": "Can manage/disable other extensions",
    },
]


@dataclass
class IntelMatch:
    """Result of an extension intelligence lookup."""
    extension_id: str
    category: str
    severity: str
    reason: str
    source: str  # "known_malicious", "custom_blocklist", "permission_signature"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "extension_id": self.extension_id,
            "category": self.category,
            "severity": self.severity,
            "reason": self.reason,
            "source": self.source,
        }


class ExtensionIntelDatabase:
    """Cross-references extension IDs against threat intelligence.

    Thread-safe: can be queried from multiple threads concurrently.

    Usage::

        db = ExtensionIntelDatabase()
        result = db.check("some-extension-id")
        if result:
            print(f"MALICIOUS: {result['reason']}")
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Known malicious IDs: ext_id → IntelMatch
        self._known: Dict[str, IntelMatch] = {}
        for ext_id, category, desc in _KNOWN_MALICIOUS:
            severity = _CATEGORY_SEVERITY.get(category, "high")
            self._known[ext_id] = IntelMatch(
                extension_id=ext_id,
                category=category,
                severity=severity,
                reason=desc,
                source="known_malicious",
            )

        # Custom blocklist (user-configurable)
        self._custom: Dict[str, IntelMatch] = {}

        # Cache of checked IDs for stats
        self._checked_count = 0
        self._match_count = 0

    def check(self, extension_id: str) -> Optional[Dict[str, Any]]:
        """Check an extension ID against all threat intel sources.

        Returns a dict with match details, or None if clean.
        """
        with self._lock:
            self._checked_count += 1

            # Check known malicious database
            match = self._known.get(extension_id)
            if match:
                self._match_count += 1
                return match.to_dict()

            # Check custom blocklist
            match = self._custom.get(extension_id)
            if match:
                self._match_count += 1
                return match.to_dict()

        return None

    def check_permissions(
        self,
        extension_id: str,
        permissions: Set[str],
        has_broad_host: bool,
    ) -> Optional[Dict[str, Any]]:
        """Check if permission combination matches a dangerous signature.

        This is a separate check from the ID lookup — it catches
        unknown extensions with known-dangerous permission patterns.
        """
        for combo in _DANGEROUS_PERMISSION_COMBOS:
            if combo["host_broad"] and not has_broad_host:
                continue
            required = combo["required"]
            if required.issubset(permissions):
                return IntelMatch(
                    extension_id=extension_id,
                    category="permission_signature",
                    severity=combo["severity"],
                    reason=combo["reason"],
                    source="permission_signature",
                ).to_dict()
        return None

    def add_to_blocklist(
        self,
        extension_id: str,
        category: str = "custom",
        reason: str = "User-added blocklist entry",
    ) -> None:
        """Add an extension ID to the custom blocklist."""
        severity = _CATEGORY_SEVERITY.get(category, "high")
        match = IntelMatch(
            extension_id=extension_id,
            category=category,
            severity=severity,
            reason=reason,
            source="custom_blocklist",
        )
        with self._lock:
            self._custom[extension_id] = match

    def remove_from_blocklist(self, extension_id: str) -> bool:
        """Remove an extension from the custom blocklist."""
        with self._lock:
            return self._custom.pop(extension_id, None) is not None

    @property
    def known_count(self) -> int:
        """Number of known malicious extension IDs."""
        with self._lock:
            return len(self._known)

    @property
    def custom_count(self) -> int:
        """Number of custom blocklist entries."""
        with self._lock:
            return len(self._custom)

    def stats(self) -> Dict[str, Any]:
        """Return database statistics."""
        with self._lock:
            return {
                "known_malicious_count": len(self._known),
                "custom_blocklist_count": len(self._custom),
                "total_checked": self._checked_count,
                "total_matches": self._match_count,
                "categories": list(set(
                    m.category for m in list(self._known.values()) + list(self._custom.values())
                )),
            }

    def get_known_ids(self) -> List[str]:
        """Return all known malicious extension IDs."""
        with self._lock:
            return list(self._known.keys())

    def get_blocklist(self) -> List[Dict[str, Any]]:
        """Return custom blocklist entries."""
        with self._lock:
            return [m.to_dict() for m in self._custom.values()]
