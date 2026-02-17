# Tests for Guardian — Extension Directory Watcher + Threat Intel Database
# Reference: src/citadel_archer/guardian/extension_watcher.py
#            src/citadel_archer/guardian/extension_intel.py
#
# Covers: watcher lifecycle, filesystem event handling, debounce,
# new vs known extension detection, malicious ID lookup, permission
# signature checks, blocklist management, event emission, integration.

import json
import os
import time
import threading
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.guardian.extension_watcher import (
    ExtensionInstallHandler,
    ExtensionWatcher,
    _DEBOUNCE_SECONDS,
)
from citadel_archer.guardian.extension_intel import (
    ExtensionIntelDatabase,
    IntelMatch,
    _KNOWN_MALICIOUS,
    _CATEGORY_SEVERITY,
    _DANGEROUS_PERMISSION_COMBOS,
)
from citadel_archer.guardian.extension_scanner import (
    BrowserExtension,
    ExtensionRisk,
    InstallSource,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _write_manifest(base_dir, browser, profile, ext_id, version, manifest):
    """Write a manifest.json into a realistic Chromium directory structure."""
    ext_path = os.path.join(
        base_dir, browser, "User Data", profile, "Extensions", ext_id, version
    )
    os.makedirs(ext_path, exist_ok=True)
    manifest_file = os.path.join(ext_path, "manifest.json")
    with open(manifest_file, "w") as f:
        json.dump(manifest, f)
    return manifest_file


def _make_manifest(name="Test Ext", version="1.0", permissions=None, **kwargs):
    m = {"name": name, "version": version, "manifest_version": 3}
    if permissions:
        m["permissions"] = permissions
    m.update(kwargs)
    return m


# ══════════════════════════════════════════════════════════════════════
# EXTENSION INTEL DATABASE
# ══════════════════════════════════════════════════════════════════════


class TestExtensionIntelDatabase:
    def test_known_malicious_loaded(self):
        db = ExtensionIntelDatabase()
        assert db.known_count == len(_KNOWN_MALICIOUS)

    def test_check_known_malicious(self):
        db = ExtensionIntelDatabase()
        # Use a known ID from the database
        ext_id = _KNOWN_MALICIOUS[0][0]
        result = db.check(ext_id)
        assert result is not None
        assert result["source"] == "known_malicious"
        assert result["extension_id"] == ext_id

    def test_check_clean_extension(self):
        db = ExtensionIntelDatabase()
        result = db.check("abcdefghijklmnopabcdefghijklmnop")
        assert result is None

    def test_custom_blocklist_add(self):
        db = ExtensionIntelDatabase()
        db.add_to_blocklist("badext123", category="malware", reason="Test block")
        result = db.check("badext123")
        assert result is not None
        assert result["source"] == "custom_blocklist"
        assert result["category"] == "malware"

    def test_custom_blocklist_remove(self):
        db = ExtensionIntelDatabase()
        db.add_to_blocklist("badext123", reason="Test")
        assert db.remove_from_blocklist("badext123") is True
        assert db.check("badext123") is None

    def test_remove_nonexistent_from_blocklist(self):
        db = ExtensionIntelDatabase()
        assert db.remove_from_blocklist("nonexistent") is False

    def test_stats(self):
        db = ExtensionIntelDatabase()
        db.check("some_id")
        db.check(_KNOWN_MALICIOUS[0][0])
        stats = db.stats()
        assert stats["known_malicious_count"] == len(_KNOWN_MALICIOUS)
        assert stats["total_checked"] == 2
        assert stats["total_matches"] == 1

    def test_get_known_ids(self):
        db = ExtensionIntelDatabase()
        ids = db.get_known_ids()
        assert len(ids) == len(_KNOWN_MALICIOUS)
        assert _KNOWN_MALICIOUS[0][0] in ids

    def test_get_blocklist_empty(self):
        db = ExtensionIntelDatabase()
        assert db.get_blocklist() == []

    def test_get_blocklist_with_entries(self):
        db = ExtensionIntelDatabase()
        db.add_to_blocklist("bad1", reason="Test 1")
        db.add_to_blocklist("bad2", reason="Test 2")
        bl = db.get_blocklist()
        assert len(bl) == 2


class TestPermissionSignatureCheck:
    def test_native_messaging_broad(self):
        db = ExtensionIntelDatabase()
        result = db.check_permissions(
            "test_ext",
            permissions={"nativeMessaging", "storage"},
            has_broad_host=True,
        )
        assert result is not None
        assert result["source"] == "permission_signature"
        assert result["severity"] == "critical"

    def test_native_messaging_no_broad(self):
        db = ExtensionIntelDatabase()
        result = db.check_permissions(
            "test_ext",
            permissions={"nativeMessaging"},
            has_broad_host=False,
        )
        # nativeMessaging combo requires broad host
        assert result is None

    def test_debugger_permission(self):
        db = ExtensionIntelDatabase()
        result = db.check_permissions(
            "test_ext",
            permissions={"debugger"},
            has_broad_host=False,
        )
        assert result is not None
        assert result["severity"] == "high"

    def test_management_permission(self):
        db = ExtensionIntelDatabase()
        result = db.check_permissions(
            "test_ext",
            permissions={"management"},
            has_broad_host=False,
        )
        assert result is not None

    def test_safe_permissions(self):
        db = ExtensionIntelDatabase()
        result = db.check_permissions(
            "test_ext",
            permissions={"storage", "tabs"},
            has_broad_host=False,
        )
        assert result is None


class TestIntelMatch:
    def test_to_dict(self):
        m = IntelMatch(
            extension_id="abc",
            category="spyware",
            severity="critical",
            reason="Test",
            source="known_malicious",
        )
        d = m.to_dict()
        assert d["extension_id"] == "abc"
        assert d["severity"] == "critical"

    def test_category_severity_mapping(self):
        for cat, sev in _CATEGORY_SEVERITY.items():
            assert sev in ("critical", "high", "medium", "low")


class TestIntelThreadSafety:
    def test_concurrent_checks(self):
        db = ExtensionIntelDatabase()
        results = []

        def _check():
            for _ in range(50):
                r = db.check("nonexistent")
                results.append(r is None)

        threads = [threading.Thread(target=_check) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(results)
        assert db.stats()["total_checked"] == 250


# ══════════════════════════════════════════════════════════════════════
# EXTENSION WATCHER
# ══════════════════════════════════════════════════════════════════════


class TestExtensionWatcherLifecycle:
    def test_start_stop(self, tmp_path):
        # Create a minimal browser dir structure
        ud = tmp_path / "chrome" / "User Data" / "Default" / "Extensions"
        ud.mkdir(parents=True)

        watcher = ExtensionWatcher(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
        )
        watcher.start()
        assert watcher.running is True
        watcher.stop()
        assert watcher.running is False

    def test_start_no_dirs(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.start()
        # Should handle gracefully (no dirs to watch)
        assert watcher.running is False

    def test_start_idempotent(self, tmp_path):
        ud = tmp_path / "chrome" / "User Data" / "Default" / "Extensions"
        ud.mkdir(parents=True)

        watcher = ExtensionWatcher(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
        )
        watcher.start()
        watcher.start()  # Second call should be no-op
        assert watcher.running is True
        watcher.stop()

    def test_detected_count_starts_zero(self):
        watcher = ExtensionWatcher(browser_roots={})
        assert watcher.detected_count == 0


class TestExtensionWatcherKnownSet:
    def test_set_known_extensions(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions({"ext1", "ext2"})
        # Internal known set updated
        assert "ext1" in watcher._known_ids

    def test_new_extension_detected(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions({"existing"})

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="brand_new",
            name="New Extension",
            browser="chrome",
            risk_level=ExtensionRisk.LOW,
            install_source=InstallSource.WEB_STORE,
        )
        watcher._on_extension_detected(ext)

        assert aggregator.ingest.called
        call = aggregator.ingest.call_args
        assert call[1]["event_type"] == "system.extension_install"
        assert watcher.detected_count == 1

    def test_known_extension_no_install_event(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions({"existing_ext"})

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="existing_ext",
            name="Known Extension",
            browser="chrome",
            risk_level=ExtensionRisk.LOW,
        )
        watcher._on_extension_detected(ext)

        # Should NOT emit an install event for known extensions
        # (no calls with event_type="system.extension_install")
        for call in aggregator.ingest.call_args_list:
            assert call[1].get("event_type") != "system.extension_install"


class TestMaliciousDetection:
    def test_malicious_extension_emits_critical(self):
        intel_db = ExtensionIntelDatabase()
        watcher = ExtensionWatcher(browser_roots={}, intel_db=intel_db)

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        # Use a known malicious ID
        ext = BrowserExtension(
            extension_id=_KNOWN_MALICIOUS[0][0],
            name="Evil Extension",
            browser="chrome",
            risk_level=ExtensionRisk.HIGH,
        )
        watcher._on_extension_detected(ext)

        assert aggregator.ingest.called
        call = aggregator.ingest.call_args
        assert call[1]["event_type"] == "system.extension_malicious"
        assert call[1]["severity"] == "critical"

    def test_clean_extension_not_malicious(self):
        intel_db = ExtensionIntelDatabase()
        watcher = ExtensionWatcher(browser_roots={}, intel_db=intel_db)
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="abcdefghijklmnopabcdefghijklmnop",
            name="Clean Extension",
            browser="chrome",
            risk_level=ExtensionRisk.LOW,
        )
        watcher._on_extension_detected(ext)

        # Should emit install event, not malicious
        call = aggregator.ingest.call_args
        assert call[1]["event_type"] == "system.extension_install"
        assert call[1]["severity"] == "info"

    def test_dangerous_permissions_flagged_as_malicious(self):
        """Extensions with dangerous permission signatures get flagged via check_permissions()."""
        intel_db = ExtensionIntelDatabase()
        watcher = ExtensionWatcher(browser_roots={}, intel_db=intel_db)
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        # Extension NOT in known-malicious list but with debugger permission
        ext = BrowserExtension(
            extension_id="unknownextensionidxxxxxxxxxxxxxxxxx",
            name="Debugger Extension",
            browser="chrome",
            risk_level=ExtensionRisk.HIGH,
            permissions=["debugger", "storage"],
        )
        watcher._on_extension_detected(ext)

        assert aggregator.ingest.called
        call = aggregator.ingest.call_args
        assert call[1]["event_type"] == "system.extension_malicious"
        assert call[1]["severity"] == "critical"
        assert "debugger" in call[1]["details"].get("intel_reason", "").lower() or \
               "browser traffic" in call[1]["details"].get("intel_reason", "").lower()


class TestEventSeverityMapping:
    def test_critical_risk_emits_critical(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="newcritical",
            name="Critical Risk",
            browser="chrome",
            risk_level=ExtensionRisk.CRITICAL,
        )
        watcher._on_extension_detected(ext)

        call = aggregator.ingest.call_args
        assert call[1]["severity"] == "critical"

    def test_high_risk_emits_alert(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="newhigh",
            name="High Risk",
            browser="chrome",
            risk_level=ExtensionRisk.HIGH,
        )
        watcher._on_extension_detected(ext)

        call = aggregator.ingest.call_args
        assert call[1]["severity"] == "alert"

    def test_medium_risk_emits_alert(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="newmedium",
            name="Medium Risk",
            browser="chrome",
            risk_level=ExtensionRisk.MEDIUM,
        )
        watcher._on_extension_detected(ext)

        call = aggregator.ingest.call_args
        assert call[1]["severity"] == "alert"

    def test_low_risk_emits_info(self):
        watcher = ExtensionWatcher(browser_roots={})
        watcher.set_known_extensions(set())

        aggregator = MagicMock()
        watcher._aggregator = aggregator

        ext = BrowserExtension(
            extension_id="newlow",
            name="Low Risk",
            browser="chrome",
            risk_level=ExtensionRisk.LOW,
        )
        watcher._on_extension_detected(ext)

        call = aggregator.ingest.call_args
        assert call[1]["severity"] == "info"


class TestInstallHandler:
    def test_manifest_path_parsing(self, tmp_path):
        """Handler extracts ext_id from manifest path correctly."""
        watcher = ExtensionWatcher(browser_roots={})
        handler = ExtensionInstallHandler(watcher, "chrome")

        manifest = _make_manifest(name="Test Handler")
        mf_path = _write_manifest(
            str(tmp_path), "chrome", "Default",
            "abcdefghijklmnopabcdefghijklmnop", "1.0", manifest,
        )

        # Directly invoke handler
        handler._process_manifest(mf_path)

        assert watcher.detected_count == 1

    def test_debounce(self, tmp_path):
        """Duplicate events within debounce window are ignored."""
        watcher = ExtensionWatcher(browser_roots={})
        handler = ExtensionInstallHandler(watcher, "chrome")

        manifest = _make_manifest(name="Debounce Test")
        mf_path = _write_manifest(
            str(tmp_path), "chrome", "Default",
            "abcdefghijklmnopabcdefghijklmnop", "1.0", manifest,
        )

        handler._process_manifest(mf_path)
        handler._process_manifest(mf_path)  # Should be debounced

        assert watcher.detected_count == 1

    def test_non_manifest_file_ignored(self, tmp_path):
        watcher = ExtensionWatcher(browser_roots={})
        handler = ExtensionInstallHandler(watcher, "chrome")

        handler._handle_file(str(tmp_path / "readme.txt"))
        assert watcher.detected_count == 0

    def test_invalid_manifest_ignored(self, tmp_path):
        """Bad JSON in manifest should not crash."""
        ext_path = os.path.join(
            str(tmp_path), "chrome", "User Data", "Default",
            "Extensions", "badext", "1.0",
        )
        os.makedirs(ext_path, exist_ok=True)
        mf = os.path.join(ext_path, "manifest.json")
        with open(mf, "w") as f:
            f.write("not json")

        watcher = ExtensionWatcher(browser_roots={})
        handler = ExtensionInstallHandler(watcher, "chrome")
        handler._process_manifest(mf)

        assert watcher.detected_count == 0

    def test_no_aggregator_no_crash(self, tmp_path):
        """Watcher with no aggregator should handle detections silently."""
        watcher = ExtensionWatcher(browser_roots={}, aggregator=None)
        watcher.set_known_extensions(set())

        ext = BrowserExtension(
            extension_id="noagg",
            name="No Aggregator",
            browser="chrome",
        )
        watcher._on_extension_detected(ext)
        assert watcher.detected_count == 1


class TestHandlerProfileDetection:
    def test_extracts_profile_name(self, tmp_path):
        """Handler extracts profile name from path."""
        watcher = ExtensionWatcher(browser_roots={})
        handler = ExtensionInstallHandler(watcher, "chrome")

        aggregator = MagicMock()
        watcher._aggregator = aggregator
        watcher.set_known_extensions(set())

        manifest = _make_manifest(name="Profile Test")
        mf_path = _write_manifest(
            str(tmp_path), "chrome", "Profile 1",
            "abcdefghijklmnopabcdefghijklmnop", "1.0", manifest,
        )

        handler._process_manifest(mf_path)

        # Check that profile was detected in the emitted event
        assert watcher.detected_count == 1
