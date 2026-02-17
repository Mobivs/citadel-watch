# PRD: Guardian Module - Browser Extension Directory Watcher
# Reference: docs/PRD.md v0.3.16
#
# Monitors browser extension directories for new installs, removals,
# and updates using the watchdog filesystem observer (same library
# used by file_monitor.py).
#
# When a new extension is detected:
#   1. Parses manifest.json immediately
#   2. Runs permission risk analysis (via extension_scanner)
#   3. Checks against known-malicious extension database (via extension_intel)
#   4. Emits events to EventAggregator (new-install, unauthorized, malicious)
#
# Design mirrors FileMonitor: watchdog Observer + custom EventHandler.

import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING

from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    DirCreatedEvent,
)

from .extension_scanner import (
    BrowserExtension,
    ExtensionRisk,
    ExtensionScanner,
    analyze_risk,
    parse_manifest,
    _classify_install_source,
    _default_browser_roots,
)

if TYPE_CHECKING:
    from ..intel.event_aggregator import EventAggregator
    from .extension_intel import ExtensionIntelDatabase

logger = logging.getLogger(__name__)

# Debounce: ignore duplicate events within this window (seconds)
_DEBOUNCE_SECONDS = 5.0


class ExtensionInstallHandler(FileSystemEventHandler):
    """Watchdog handler that detects new extension installs.

    Watches for manifest.json creation/modification inside
    browser extension directories. When detected, parses the
    manifest and runs risk analysis + threat intel checks.
    """

    def __init__(
        self,
        watcher: "ExtensionWatcher",
        browser: str,
    ):
        super().__init__()
        self._watcher = watcher
        self._browser = browser
        # Debounce: ext_id → last_event_time
        self._recent: Dict[str, float] = {}
        self._lock = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            # New version directory could mean extension install/update
            self._check_parent_manifest(event.src_path)
            return
        self._handle_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._handle_file(event.src_path)

    def _handle_file(self, path: str) -> None:
        """Process a file event, looking for manifest.json files."""
        if not os.path.basename(path).lower() == "manifest.json":
            return
        self._process_manifest(path)

    def _check_parent_manifest(self, dir_path: str) -> None:
        """When a new directory appears, check for manifest.json inside it."""
        manifest_path = os.path.join(dir_path, "manifest.json")
        if os.path.isfile(manifest_path):
            self._process_manifest(manifest_path)

    def _process_manifest(self, manifest_path: str) -> None:
        """Parse and analyze a detected manifest.json."""
        # Extract extension ID from path
        # Path format: .../Extensions/<ext_id>/<version>/manifest.json
        parts = manifest_path.replace("\\", "/").split("/")
        try:
            ext_idx = parts.index("Extensions")
            if ext_idx + 2 < len(parts):
                ext_id = parts[ext_idx + 1]
            else:
                return
        except (ValueError, IndexError):
            return

        # Debounce
        now = time.monotonic()
        with self._lock:
            last = self._recent.get(ext_id, 0.0)
            if now - last < _DEBOUNCE_SECONDS:
                return
            self._recent[ext_id] = now

            # Prune expired entries to prevent unbounded growth
            if len(self._recent) > 200:
                expired = [
                    k for k, v in self._recent.items()
                    if now - v >= _DEBOUNCE_SECONDS
                ]
                for k in expired:
                    del self._recent[k]

        # Parse manifest
        manifest = parse_manifest(manifest_path)
        if manifest is None:
            return

        # Build BrowserExtension object
        name = manifest.get("name", ext_id)
        version = manifest.get("version", "")
        permissions = list(manifest.get("permissions", []))
        api_perms = [p for p in permissions if "://" not in p and p != "<all_urls>"]
        host_perms = list(manifest.get("host_permissions", []))
        host_perms += [p for p in permissions if "://" in p or p == "<all_urls>"]
        optional_perms = list(manifest.get("optional_permissions", []))

        content_script_matches: List[str] = []
        for cs in manifest.get("content_scripts", []):
            content_script_matches.extend(cs.get("matches", []))

        # Determine profile from path
        profile = "Default"
        if "User Data" in manifest_path:
            try:
                ud_idx = parts.index("User Data")
                if ud_idx + 1 < len(parts):
                    profile = parts[ud_idx + 1]
            except ValueError:
                pass

        install_source = _classify_install_source(ext_id, manifest_path)
        description = manifest.get("description", "")
        if len(description) > 200:
            description = description[:197] + "..."

        ext = BrowserExtension(
            extension_id=ext_id,
            name=name,
            version=version,
            description=description,
            browser=self._browser,
            profile=profile,
            manifest_version=manifest.get("manifest_version", 2),
            permissions=api_perms,
            optional_permissions=optional_perms,
            host_permissions=host_perms,
            content_script_matches=content_script_matches,
            install_source=install_source,
            manifest_path=manifest_path,
        )

        # Risk analysis
        analyze_risk(ext)

        # Notify the watcher
        self._watcher._on_extension_detected(ext)


class ExtensionWatcher:
    """Monitors browser extension directories for new installs.

    Uses watchdog to detect filesystem changes in Chromium extension
    directories and runs risk analysis + threat intel checks on
    newly detected extensions.

    Args:
        browser_roots: Override browser paths (for testing).
        aggregator: EventAggregator for event emission.
        intel_db: Optional ExtensionIntelDatabase for malicious ID checks.
    """

    def __init__(
        self,
        browser_roots: Optional[Dict[str, str]] = None,
        aggregator: Optional["EventAggregator"] = None,
        intel_db: Optional["ExtensionIntelDatabase"] = None,
    ):
        self._browser_roots = browser_roots if browser_roots is not None else _default_browser_roots()
        self._aggregator = aggregator
        self._intel_db = intel_db
        self._observer: Optional[Observer] = None
        self._running = False
        self._known_ids: Set[str] = set()
        self._lock = threading.Lock()
        self._detected_count = 0

    @property
    def running(self) -> bool:
        return self._running

    @property
    def detected_count(self) -> int:
        with self._lock:
            return self._detected_count

    def set_known_extensions(self, ext_ids: Set[str]) -> None:
        """Set the baseline of known extensions from initial scan.

        Extensions not in this set will be flagged as new installs.
        """
        with self._lock:
            self._known_ids = set(ext_ids)

    def start(self) -> None:
        """Start watching browser extension directories."""
        if self._running:
            return

        self._observer = Observer()
        watched = 0

        for browser, user_data in self._browser_roots.items():
            if not os.path.isdir(user_data):
                continue

            # Watch the entire User Data directory for extension changes
            # (recursive=True catches all profile/extension dirs)
            handler = ExtensionInstallHandler(self, browser)
            try:
                self._observer.schedule(handler, user_data, recursive=True)
                watched += 1
            except OSError as exc:
                logger.warning("Cannot watch %s (%s): %s", browser, user_data, exc)

        if watched == 0:
            logger.info("ExtensionWatcher: no browser directories found")
            return

        self._observer.start()
        self._running = True
        logger.info(
            "ExtensionWatcher started: watching %d browser(s)", watched
        )

    def stop(self) -> None:
        """Stop watching."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self._running = False
        logger.info("ExtensionWatcher stopped")

    def _on_extension_detected(self, ext: BrowserExtension) -> None:
        """Called by the handler when a new/updated extension is found."""
        with self._lock:
            self._detected_count += 1
            is_new = ext.extension_id not in self._known_ids
            self._known_ids.add(ext.extension_id)

        # Check threat intel database
        is_malicious = False
        intel_reason = ""
        if self._intel_db:
            result = self._intel_db.check(ext.extension_id)
            if result:
                is_malicious = True
                intel_reason = result.get("reason", "Known malicious extension")
            else:
                # Check dangerous permission signatures
                perm_result = self._intel_db.check_permissions(
                    ext.extension_id,
                    permissions=set(ext.permissions),
                    has_broad_host=ext.has_broad_host_access,
                )
                if perm_result:
                    is_malicious = True
                    intel_reason = perm_result.get("reason", "Dangerous permission signature")

        # Emit events
        if self._aggregator:
            self._emit_event(ext, is_new, is_malicious, intel_reason)

        if is_malicious:
            logger.warning(
                "MALICIOUS extension detected: %s/%s (%s) — %s",
                ext.browser, ext.name, ext.extension_id, intel_reason,
            )
        elif is_new and ext.risk_level in (ExtensionRisk.HIGH, ExtensionRisk.CRITICAL):
            logger.warning(
                "New HIGH-RISK extension installed: %s/%s (%s) — %s",
                ext.browser, ext.name, ext.extension_id,
                "; ".join(ext.risk_reasons[:2]),
            )
        elif is_new:
            logger.info(
                "New extension installed: %s/%s (%s) risk=%s",
                ext.browser, ext.name, ext.extension_id, ext.risk_level.value,
            )

    def _emit_event(
        self,
        ext: BrowserExtension,
        is_new: bool,
        is_malicious: bool,
        intel_reason: str,
    ) -> None:
        """Emit events to EventAggregator."""
        if not self._aggregator:
            return

        if is_malicious:
            self._aggregator.ingest(
                event_type="system.extension_malicious",
                severity="critical",
                asset_id="local",
                message=(
                    f"[MALICIOUS] Known malicious extension detected: "
                    f"{ext.browser}/{ext.name} ({ext.extension_id}). "
                    f"{intel_reason}"
                ),
                details={
                    "extension_id": ext.extension_id,
                    "name": ext.name,
                    "browser": ext.browser,
                    "version": ext.version,
                    "risk_level": ext.risk_level.value,
                    "install_source": ext.install_source.value,
                    "intel_reason": intel_reason,
                    "is_new": is_new,
                },
            )
        elif is_new:
            severity = "info"
            if ext.risk_level == ExtensionRisk.CRITICAL:
                severity = "critical"
            elif ext.risk_level == ExtensionRisk.HIGH:
                severity = "alert"
            elif ext.risk_level == ExtensionRisk.MEDIUM:
                severity = "alert"

            self._aggregator.ingest(
                event_type="system.extension_install",
                severity=severity,
                asset_id="local",
                message=(
                    f"New extension installed: {ext.browser}/{ext.name} "
                    f"({ext.extension_id}) risk={ext.risk_level.value}"
                ),
                details={
                    "extension_id": ext.extension_id,
                    "name": ext.name,
                    "browser": ext.browser,
                    "version": ext.version,
                    "risk_level": ext.risk_level.value,
                    "risk_reasons": ext.risk_reasons,
                    "install_source": ext.install_source.value,
                    "permissions": ext.permissions,
                    "has_broad_host_access": ext.has_broad_host_access,
                },
            )
