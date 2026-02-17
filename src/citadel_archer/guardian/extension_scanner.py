# PRD: Guardian Module - Browser Extension Inventory Scanner
# Reference: docs/PRD.md v0.3.15
#
# Enumerates installed browser extensions across Chromium-based browsers
# (Chrome, Edge, Brave, Vivaldi) on Windows.
#
# For each extension:
#   - Parses manifest.json (permissions, content scripts, host permissions)
#   - Analyzes permission risk (dangerous combos flagged)
#   - Detects sideloaded/dev extensions via non-CWS ID formats
#   - Determines install source (web store, sideloaded, enterprise policy)
#   - Computes an overall risk score (low/medium/high/critical)
#
# Emits events to EventAggregator for cross-asset correlation and
# AI analysis via the SecureChat escalation pipeline.

import json
import logging
import os
import re
import time
import threading
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..intel.event_aggregator import EventAggregator

logger = logging.getLogger(__name__)


# ── Browser Profile Paths (Windows) ──────────────────────────────────

# Chromium browsers store extensions under:
#   <profile_root>/Extensions/<extension_id>/<version>/manifest.json
# Profile root is the Default profile or numbered profiles (Profile 1, etc.)

def _default_browser_roots() -> Dict[str, str]:
    """Return default extension root dirs keyed by browser name.

    Resolves LOCALAPPDATA for the current user.
    """
    local = os.environ.get("LOCALAPPDATA", "")
    if not local:
        return {}

    return {
        "chrome": os.path.join(local, "Google", "Chrome", "User Data"),
        "edge": os.path.join(local, "Microsoft", "Edge", "User Data"),
        "brave": os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
        "vivaldi": os.path.join(local, "Vivaldi", "User Data"),
    }


# ── Permission Risk Classification ───────────────────────────────────

# Dangerous individual permissions
_DANGEROUS_PERMISSIONS: FrozenSet[str] = frozenset({
    "clipboardRead",
    "clipboardWrite",
    "nativeMessaging",
    "debugger",
    "proxy",
    "webRequestBlocking",
    "management",           # can manage other extensions
    "privacy",
    "desktopCapture",
    "tabCapture",
    "pageCapture",
    "browsingData",
})

# High-risk permissions (not immediately dangerous alone)
_HIGH_RISK_PERMISSIONS: FrozenSet[str] = frozenset({
    "webRequest",
    "tabs",
    "activeTab",
    "webNavigation",
    "cookies",
    "history",
    "bookmarks",
    "downloads",
    "topSites",
    "sessions",
    "identity",
})

# Host patterns that indicate broad access
_BROAD_HOST_PATTERNS: FrozenSet[str] = frozenset({
    "<all_urls>",
    "*://*/*",
    "http://*/*",
    "https://*/*",
})


class ExtensionRisk(str, Enum):
    """Risk level for a browser extension."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InstallSource(str, Enum):
    """How the extension was installed."""
    WEB_STORE = "web_store"
    SIDELOADED = "sideloaded"
    ENTERPRISE_POLICY = "enterprise_policy"
    DEVELOPMENT = "development"
    UNKNOWN = "unknown"


# ── Extension Data Model ─────────────────────────────────────────────

@dataclass
class BrowserExtension:
    """Parsed metadata for a single browser extension."""

    extension_id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    browser: str = ""
    profile: str = ""
    manifest_version: int = 2

    # Permissions
    permissions: List[str] = field(default_factory=list)
    optional_permissions: List[str] = field(default_factory=list)
    host_permissions: List[str] = field(default_factory=list)
    content_script_matches: List[str] = field(default_factory=list)

    # Risk analysis
    risk_level: ExtensionRisk = ExtensionRisk.LOW
    risk_reasons: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    has_broad_host_access: bool = False

    # Install source
    install_source: InstallSource = InstallSource.UNKNOWN

    # Paths
    manifest_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["risk_level"] = self.risk_level.value
        d["install_source"] = self.install_source.value
        return d


# ── Manifest Parser ──────────────────────────────────────────────────


def parse_manifest(manifest_path: str) -> Optional[Dict[str, Any]]:
    """Parse a manifest.json file, returning None on failure."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _extract_host_patterns(manifest: Dict[str, Any]) -> List[str]:
    """Extract all host/URL patterns from manifest fields."""
    patterns: List[str] = []

    # MV3 host_permissions
    patterns.extend(manifest.get("host_permissions", []))

    # MV2: permissions often contain URL patterns
    for perm in manifest.get("permissions", []):
        if "://" in perm or perm == "<all_urls>":
            patterns.append(perm)

    # Content script matches
    for cs in manifest.get("content_scripts", []):
        patterns.extend(cs.get("matches", []))

    return patterns


def _check_broad_access(patterns: List[str]) -> bool:
    """Check if any host pattern grants very broad page access."""
    for p in patterns:
        if p in _BROAD_HOST_PATTERNS:
            return True
        # Catch patterns like *://*.com/* or *://*/* which are overly broad
        # but NOT *://specific-domain.com/* which targets a single site
        if p.startswith("*://"):
            host_part = p[4:].split("/")[0]  # extract host from *://host/path
            if "*" in host_part:
                return True
    return False


def _classify_install_source(ext_id: str, manifest_path: str) -> InstallSource:
    """Guess the install source from extension ID format and path.

    Chrome Web Store IDs are 32 lowercase a-p characters (base-16 in a-p).
    UUID-style or mixed-case IDs indicate sideloaded/dev extensions.
    Extensions under ManagedStorage or policy paths are enterprise.
    """
    # Enterprise policy indicators
    path_lower = manifest_path.lower()
    if "managed" in path_lower or "policy" in path_lower:
        return InstallSource.ENTERPRISE_POLICY

    # CWS IDs: exactly 32 characters from [a-p]
    if re.fullmatch(r"[a-p]{32}", ext_id):
        return InstallSource.WEB_STORE

    # UUID format (sideloaded on Edge often)
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ext_id, re.IGNORECASE,
    ):
        return InstallSource.SIDELOADED

    # Dev mode extensions typically have non-standard length or mixed chars
    if len(ext_id) != 32 or not ext_id.isalpha():
        return InstallSource.DEVELOPMENT

    return InstallSource.UNKNOWN


# ── Risk Analyzer ────────────────────────────────────────────────────

def analyze_risk(ext: BrowserExtension) -> BrowserExtension:
    """Analyze an extension's permissions and populate risk fields.

    Mutates and returns the same BrowserExtension object.
    """
    reasons: List[str] = []
    dangerous: List[str] = []
    risk = ExtensionRisk.LOW

    all_perms = set(ext.permissions + ext.optional_permissions)

    # Check dangerous permissions
    for perm in sorted(all_perms & _DANGEROUS_PERMISSIONS):
        dangerous.append(perm)
        reasons.append(f"Dangerous permission: {perm}")

    # Check high-risk permissions
    high_risk_found = all_perms & _HIGH_RISK_PERMISSIONS

    # Check broad host access
    host_patterns = ext.host_permissions + ext.content_script_matches
    ext.has_broad_host_access = _check_broad_access(host_patterns)
    if ext.has_broad_host_access:
        reasons.append("Broad host access (<all_urls> or equivalent)")

    # Dangerous combos
    if ext.has_broad_host_access and "webRequest" in all_perms:
        reasons.append("Combo: broad host + webRequest (can intercept all traffic)")
    if "tabs" in all_perms and "activeTab" in all_perms and ext.has_broad_host_access:
        reasons.append("Combo: tabs + activeTab + broad host (full page access)")
    if "nativeMessaging" in all_perms and ext.has_broad_host_access:
        reasons.append("Combo: nativeMessaging + broad host (data exfil to local exe)")
    if "clipboardRead" in all_perms and ext.has_broad_host_access:
        reasons.append("Combo: clipboardRead + broad host (clipboard sniffing)")

    # Sideloaded extensions are inherently riskier
    if ext.install_source in (InstallSource.SIDELOADED, InstallSource.DEVELOPMENT):
        reasons.append(f"Install source: {ext.install_source.value}")

    # Determine overall risk level
    if dangerous:
        if ext.has_broad_host_access or len(dangerous) >= 2:
            risk = ExtensionRisk.CRITICAL
        else:
            risk = ExtensionRisk.HIGH
    elif ext.has_broad_host_access:
        if high_risk_found:
            risk = ExtensionRisk.HIGH
        else:
            risk = ExtensionRisk.MEDIUM
    elif high_risk_found and len(high_risk_found) >= 3:
        risk = ExtensionRisk.MEDIUM
    elif ext.install_source in (InstallSource.SIDELOADED, InstallSource.DEVELOPMENT):
        risk = max(risk, ExtensionRisk.MEDIUM, key=lambda r: list(ExtensionRisk).index(r))

    ext.risk_level = risk
    ext.risk_reasons = reasons
    ext.dangerous_permissions = dangerous
    return ext


# ── Extension Scanner ────────────────────────────────────────────────


class ExtensionScanner:
    """Scans Chromium browser extension directories and analyzes risk.

    Usage::

        scanner = ExtensionScanner()
        results = scanner.scan_all()
        # results.extensions — list of BrowserExtension
        # results.summary — dict with counts by risk level
    """

    def __init__(
        self,
        browser_roots: Optional[Dict[str, str]] = None,
        aggregator: Optional["EventAggregator"] = None,
    ):
        self._browser_roots = browser_roots if browser_roots is not None else _default_browser_roots()
        self._aggregator = aggregator
        self._last_scan: Optional["ScanResult"] = None
        self._lock = threading.Lock()

    @property
    def last_scan(self) -> Optional["ScanResult"]:
        with self._lock:
            return self._last_scan

    def scan_all(self) -> "ScanResult":
        """Scan all configured browsers and return results."""
        start = time.monotonic()
        extensions: List[BrowserExtension] = []

        for browser, user_data in self._browser_roots.items():
            if not os.path.isdir(user_data):
                continue

            profiles = self._find_profiles(user_data)
            for profile_name, profile_path in profiles:
                ext_dir = os.path.join(profile_path, "Extensions")
                if not os.path.isdir(ext_dir):
                    continue

                found = self._scan_extensions_dir(ext_dir, browser, profile_name)
                extensions.extend(found)

        # Analyze risk for all extensions
        for ext in extensions:
            analyze_risk(ext)

        elapsed = time.monotonic() - start
        result = ScanResult(
            extensions=extensions,
            scan_duration_ms=round(elapsed * 1000),
        )

        with self._lock:
            self._last_scan = result

        # Emit events for flagged extensions
        if self._aggregator:
            self._emit_events(result)

        logger.info(
            "Extension scan complete: %d extensions, %d flagged "
            "(%.1fms)",
            result.total,
            result.flagged,
            elapsed * 1000,
        )

        return result

    def _find_profiles(self, user_data: str) -> List[Tuple[str, str]]:
        """Find browser profile directories under User Data."""
        profiles: List[Tuple[str, str]] = []

        # Default profile
        default = os.path.join(user_data, "Default")
        if os.path.isdir(default):
            profiles.append(("Default", default))

        # Numbered profiles (Profile 1, Profile 2, ...)
        try:
            for entry in os.scandir(user_data):
                if entry.is_dir() and entry.name.startswith("Profile "):
                    profiles.append((entry.name, entry.path))
        except OSError:
            pass

        return profiles

    def _scan_extensions_dir(
        self, ext_dir: str, browser: str, profile: str
    ) -> List[BrowserExtension]:
        """Scan a single Extensions directory."""
        extensions: List[BrowserExtension] = []

        try:
            for ext_entry in os.scandir(ext_dir):
                if not ext_entry.is_dir():
                    continue

                ext_id = ext_entry.name

                # Each extension has version subdirectories
                # We want the latest version
                manifest, version_dir = self._find_latest_manifest(ext_entry.path)
                if manifest is None:
                    continue

                ext = self._parse_extension(
                    ext_id, manifest, browser, profile,
                    os.path.join(version_dir, "manifest.json"),
                )
                if ext:
                    extensions.append(ext)
        except OSError:
            logger.debug("Cannot read extension dir: %s", ext_dir)

        return extensions

    def _find_latest_manifest(
        self, ext_path: str
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """Find the manifest.json from the latest version directory."""
        candidates: List[Tuple[str, str, Dict[str, Any]]] = []

        try:
            for version_entry in os.scandir(ext_path):
                if not version_entry.is_dir():
                    continue
                manifest_file = os.path.join(version_entry.path, "manifest.json")
                if os.path.isfile(manifest_file):
                    manifest = parse_manifest(manifest_file)
                    if manifest:
                        candidates.append(
                            (version_entry.name, version_entry.path, manifest)
                        )
        except OSError:
            pass

        if not candidates:
            return None, ""

        # Sort by version tuple descending (e.g., "1.2.3" → (1, 2, 3))
        def _version_key(item: Tuple[str, str, Dict[str, Any]]):
            try:
                return tuple(int(x) for x in item[0].split("."))
            except (ValueError, AttributeError):
                return (0,)

        candidates.sort(key=_version_key, reverse=True)
        _, latest_dir, latest_manifest = candidates[0]
        return latest_manifest, latest_dir

    def _parse_extension(
        self,
        ext_id: str,
        manifest: Dict[str, Any],
        browser: str,
        profile: str,
        manifest_path: str,
    ) -> Optional[BrowserExtension]:
        """Build a BrowserExtension from parsed manifest data."""
        name = manifest.get("name", "")
        # Skip Chrome internal component extensions (no user-facing name)
        if not name or name.startswith("__MSG_"):
            # __MSG_ is a localization placeholder — still a real extension
            # but use a fallback name
            name = name or ext_id

        # Extract permissions (MV2 vs MV3 differences)
        permissions = list(manifest.get("permissions", []))
        # Filter out host patterns from permissions (MV2 puts them here)
        api_permissions = [p for p in permissions if "://" not in p and p != "<all_urls>"]

        host_permissions = list(manifest.get("host_permissions", []))
        # MV2: host patterns are in permissions
        host_permissions += [p for p in permissions if "://" in p or p == "<all_urls>"]

        optional_permissions = list(manifest.get("optional_permissions", []))

        # Content script URL matches
        content_script_matches: List[str] = []
        for cs in manifest.get("content_scripts", []):
            content_script_matches.extend(cs.get("matches", []))

        version = manifest.get("version", "")
        description = manifest.get("description", "")
        if len(description) > 200:
            description = description[:197] + "..."

        install_source = _classify_install_source(ext_id, manifest_path)

        return BrowserExtension(
            extension_id=ext_id,
            name=name,
            version=version,
            description=description,
            browser=browser,
            profile=profile,
            manifest_version=manifest.get("manifest_version", 2),
            permissions=api_permissions,
            optional_permissions=optional_permissions,
            host_permissions=host_permissions,
            content_script_matches=content_script_matches,
            install_source=install_source,
            manifest_path=manifest_path,
        )

    def _emit_events(self, result: "ScanResult") -> None:
        """Emit events to EventAggregator for flagged extensions."""
        if not self._aggregator:
            return

        # Summary event
        self._aggregator.ingest(
            event_type="system.extension_scan",
            severity="info",
            asset_id="local",
            message=(
                f"Browser extension scan: {result.total} found, "
                f"{result.flagged} flagged "
                f"({result.by_risk.get('critical', 0)} critical, "
                f"{result.by_risk.get('high', 0)} high)"
            ),
            details={
                "total": result.total,
                "flagged": result.flagged,
                "by_risk": result.by_risk,
                "by_browser": result.by_browser,
                "scan_duration_ms": result.scan_duration_ms,
            },
        )

        # Individual events for high/critical extensions
        for ext in result.extensions:
            if ext.risk_level in (ExtensionRisk.HIGH, ExtensionRisk.CRITICAL):
                severity = (
                    "critical" if ext.risk_level == ExtensionRisk.CRITICAL
                    else "alert"
                )
                self._aggregator.ingest(
                    event_type="system.extension_risk",
                    severity=severity,
                    asset_id="local",
                    message=(
                        f"[{ext.risk_level.value.upper()}] {ext.browser}/{ext.name} "
                        f"({ext.extension_id}): "
                        f"{'; '.join(ext.risk_reasons[:3])}"
                    ),
                    details={
                        "extension_id": ext.extension_id,
                        "name": ext.name,
                        "browser": ext.browser,
                        "version": ext.version,
                        "risk_level": ext.risk_level.value,
                        "risk_reasons": ext.risk_reasons,
                        "dangerous_permissions": ext.dangerous_permissions,
                        "has_broad_host_access": ext.has_broad_host_access,
                        "install_source": ext.install_source.value,
                    },
                )


# ── Scan Result ───────────────────────────────────────────────────────


@dataclass
class ScanResult:
    """Result of a browser extension scan."""

    extensions: List[BrowserExtension] = field(default_factory=list)
    scan_duration_ms: int = 0

    @property
    def total(self) -> int:
        return len(self.extensions)

    @property
    def flagged(self) -> int:
        return sum(
            1 for e in self.extensions
            if e.risk_level in (ExtensionRisk.MEDIUM, ExtensionRisk.HIGH, ExtensionRisk.CRITICAL)
        )

    @property
    def by_risk(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.extensions:
            level = e.risk_level.value
            counts[level] = counts.get(level, 0) + 1
        return counts

    @property
    def by_browser(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.extensions:
            counts[e.browser] = counts.get(e.browser, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "extensions": [e.to_dict() for e in self.extensions],
            "total": self.total,
            "flagged": self.flagged,
            "by_risk": self.by_risk,
            "by_browser": self.by_browser,
            "scan_duration_ms": self.scan_duration_ms,
        }
