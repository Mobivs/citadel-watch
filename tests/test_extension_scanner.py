# Tests for Guardian — Browser Extension Inventory Scanner
# Reference: src/citadel_archer/guardian/extension_scanner.py
#
# Covers: manifest parsing, permission risk analysis, install source
# classification, broad host detection, risk combos, extension scanner
# with filesystem mocks, event emission, scan result model, API endpoints.

import json
import os
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.guardian.extension_scanner import (
    BrowserExtension,
    ExtensionRisk,
    ExtensionScanner,
    InstallSource,
    ScanResult,
    _BROAD_HOST_PATTERNS,
    _DANGEROUS_PERMISSIONS,
    _HIGH_RISK_PERMISSIONS,
    _check_broad_access,
    _classify_install_source,
    _default_browser_roots,
    _extract_host_patterns,
    analyze_risk,
    parse_manifest,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _make_manifest(
    name="Test Extension",
    version="1.0",
    permissions=None,
    host_permissions=None,
    content_scripts=None,
    manifest_version=3,
    optional_permissions=None,
    description="A test extension",
):
    """Build a minimal manifest.json dict."""
    m = {
        "name": name,
        "version": version,
        "manifest_version": manifest_version,
        "description": description,
    }
    if permissions is not None:
        m["permissions"] = permissions
    if host_permissions is not None:
        m["host_permissions"] = host_permissions
    if content_scripts is not None:
        m["content_scripts"] = content_scripts
    if optional_permissions is not None:
        m["optional_permissions"] = optional_permissions
    return m


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


# ── Test: parse_manifest ──────────────────────────────────────────────


class TestParseManifest:
    def test_valid_manifest(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text(json.dumps({"name": "Test", "version": "1.0"}))
        result = parse_manifest(str(mf))
        assert result is not None
        assert result["name"] == "Test"

    def test_invalid_json(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text("not json {{{")
        assert parse_manifest(str(mf)) is None

    def test_missing_file(self):
        assert parse_manifest("/nonexistent/manifest.json") is None

    def test_empty_file(self, tmp_path):
        mf = tmp_path / "manifest.json"
        mf.write_text("")
        assert parse_manifest(str(mf)) is None


# ── Test: _extract_host_patterns ──────────────────────────────────────


class TestExtractHostPatterns:
    def test_mv3_host_permissions(self):
        m = {"host_permissions": ["https://example.com/*", "<all_urls>"]}
        patterns = _extract_host_patterns(m)
        assert "https://example.com/*" in patterns
        assert "<all_urls>" in patterns

    def test_mv2_urls_in_permissions(self):
        m = {"permissions": ["tabs", "https://example.com/*", "<all_urls>"]}
        patterns = _extract_host_patterns(m)
        assert "https://example.com/*" in patterns
        assert "<all_urls>" in patterns

    def test_content_script_matches(self):
        m = {"content_scripts": [{"matches": ["*://*.google.com/*"]}]}
        patterns = _extract_host_patterns(m)
        assert "*://*.google.com/*" in patterns

    def test_empty_manifest(self):
        assert _extract_host_patterns({}) == []


# ── Test: _check_broad_access ────────────────────────────────────────


class TestCheckBroadAccess:
    def test_all_urls(self):
        assert _check_broad_access(["<all_urls>"]) is True

    def test_wildcard_pattern(self):
        assert _check_broad_access(["*://*/*"]) is True

    def test_http_wildcard(self):
        assert _check_broad_access(["http://*/*"]) is True

    def test_https_wildcard(self):
        assert _check_broad_access(["https://*/*"]) is True

    def test_specific_url_not_broad(self):
        assert _check_broad_access(["https://example.com/*"]) is False

    def test_empty(self):
        assert _check_broad_access([]) is False

    def test_broad_star_prefix_pattern(self):
        # *://*.com/* is overly broad
        assert _check_broad_access(["*://*.com/*"]) is True

    def test_star_scheme_specific_domain_not_broad(self):
        # *://example.com/* targets one domain, not broad
        assert _check_broad_access(["*://example.com/*"]) is False


# ── Test: _classify_install_source ───────────────────────────────────


class TestClassifyInstallSource:
    def test_cws_id(self):
        # Standard CWS 32 lowercase a-p chars
        cws_id = "abcdefghijklmnopabcdefghijklmnop"
        result = _classify_install_source(cws_id, "/path/Extensions/abc/1.0/manifest.json")
        assert result == InstallSource.WEB_STORE

    def test_uuid_sideloaded(self):
        uuid_id = "12345678-abcd-1234-abcd-123456789abc"
        result = _classify_install_source(uuid_id, "/path/manifest.json")
        assert result == InstallSource.SIDELOADED

    def test_policy_path(self):
        result = _classify_install_source("anythinghere", "/ManagedStorage/ext/manifest.json")
        assert result == InstallSource.ENTERPRISE_POLICY

    def test_dev_mode_mixed_case(self):
        result = _classify_install_source("ABCdef123mixed456", "/path/manifest.json")
        assert result == InstallSource.DEVELOPMENT

    def test_unknown_lowercase_32(self):
        # 32 lowercase but not all a-p = UNKNOWN (falls through all checks)
        result = _classify_install_source("abcdefghijklmnopqrstuvwxyzabcdef", "/path/manifest.json")
        assert result == InstallSource.UNKNOWN


# ── Test: analyze_risk ────────────────────────────────────────────────


class TestAnalyzeRisk:
    def test_no_permissions_is_low(self):
        ext = BrowserExtension(name="Simple", permissions=[])
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.LOW
        assert ext.dangerous_permissions == []

    def test_dangerous_permission_high(self):
        ext = BrowserExtension(name="Debugger", permissions=["debugger"])
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.HIGH
        assert "debugger" in ext.dangerous_permissions

    def test_dangerous_with_broad_host_is_critical(self):
        ext = BrowserExtension(
            name="Interceptor",
            permissions=["webRequestBlocking"],
            host_permissions=["<all_urls>"],
        )
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.CRITICAL

    def test_broad_host_alone_is_medium(self):
        ext = BrowserExtension(
            name="Broad",
            host_permissions=["<all_urls>"],
        )
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.MEDIUM

    def test_broad_host_with_high_risk_perm_is_high(self):
        ext = BrowserExtension(
            name="Tabs+Broad",
            permissions=["tabs"],
            host_permissions=["<all_urls>"],
        )
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.HIGH

    def test_content_script_broad_match(self):
        ext = BrowserExtension(
            name="CS",
            content_script_matches=["*://*/*"],
        )
        analyze_risk(ext)
        assert ext.has_broad_host_access is True

    def test_two_dangerous_permissions_is_critical(self):
        ext = BrowserExtension(
            name="Multi",
            permissions=["clipboardRead", "nativeMessaging"],
        )
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.CRITICAL

    def test_sideloaded_bumps_to_medium(self):
        ext = BrowserExtension(
            name="Sideloaded",
            permissions=["storage"],
            install_source=InstallSource.SIDELOADED,
        )
        analyze_risk(ext)
        assert ext.risk_level >= ExtensionRisk.MEDIUM

    def test_combo_native_messaging_broad(self):
        ext = BrowserExtension(
            name="NM+Broad",
            permissions=["nativeMessaging"],
            host_permissions=["<all_urls>"],
        )
        analyze_risk(ext)
        assert any("nativeMessaging + broad host" in r for r in ext.risk_reasons)

    def test_combo_webrequest_broad(self):
        ext = BrowserExtension(
            name="WR+Broad",
            permissions=["webRequest"],
            host_permissions=["<all_urls>"],
        )
        analyze_risk(ext)
        assert any("webRequest" in r for r in ext.risk_reasons)

    def test_optional_permissions_count(self):
        ext = BrowserExtension(
            name="OptDangerous",
            optional_permissions=["debugger"],
        )
        analyze_risk(ext)
        assert "debugger" in ext.dangerous_permissions

    def test_three_high_risk_is_medium(self):
        ext = BrowserExtension(
            name="ManyHigh",
            permissions=["tabs", "cookies", "history"],
        )
        analyze_risk(ext)
        assert ext.risk_level == ExtensionRisk.MEDIUM


# ── Test: BrowserExtension.to_dict ───────────────────────────────────


class TestBrowserExtensionModel:
    def test_to_dict_serializes_enums(self):
        ext = BrowserExtension(
            name="Test",
            risk_level=ExtensionRisk.HIGH,
            install_source=InstallSource.WEB_STORE,
        )
        d = ext.to_dict()
        assert d["risk_level"] == "high"
        assert d["install_source"] == "web_store"

    def test_to_dict_contains_all_fields(self):
        ext = BrowserExtension(
            extension_id="abc",
            name="Test",
            browser="chrome",
        )
        d = ext.to_dict()
        assert "extension_id" in d
        assert "permissions" in d
        assert "risk_reasons" in d


# ── Test: ScanResult ──────────────────────────────────────────────────


class TestScanResult:
    def test_empty_result(self):
        r = ScanResult()
        assert r.total == 0
        assert r.flagged == 0
        assert r.by_risk == {}
        assert r.by_browser == {}

    def test_counts(self):
        exts = [
            BrowserExtension(name="A", risk_level=ExtensionRisk.LOW, browser="chrome"),
            BrowserExtension(name="B", risk_level=ExtensionRisk.HIGH, browser="chrome"),
            BrowserExtension(name="C", risk_level=ExtensionRisk.CRITICAL, browser="edge"),
            BrowserExtension(name="D", risk_level=ExtensionRisk.MEDIUM, browser="edge"),
        ]
        r = ScanResult(extensions=exts)
        assert r.total == 4
        assert r.flagged == 3  # medium + high + critical
        assert r.by_risk == {"low": 1, "high": 1, "critical": 1, "medium": 1}
        assert r.by_browser == {"chrome": 2, "edge": 2}

    def test_to_dict(self):
        exts = [BrowserExtension(name="A", risk_level=ExtensionRisk.LOW)]
        r = ScanResult(extensions=exts, scan_duration_ms=42)
        d = r.to_dict()
        assert d["total"] == 1
        assert d["scan_duration_ms"] == 42
        assert len(d["extensions"]) == 1

    def test_flagged_only_counts_medium_plus(self):
        exts = [
            BrowserExtension(name="A", risk_level=ExtensionRisk.LOW),
            BrowserExtension(name="B", risk_level=ExtensionRisk.LOW),
        ]
        r = ScanResult(extensions=exts)
        assert r.flagged == 0


# ── Test: ExtensionScanner with fake filesystem ──────────────────────


class TestExtensionScanner:
    def test_scan_empty_roots(self):
        scanner = ExtensionScanner(browser_roots={})
        result = scanner.scan_all()
        assert result.total == 0

    def test_scan_nonexistent_dir(self, tmp_path):
        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "nonexistent")}
        )
        result = scanner.scan_all()
        assert result.total == 0

    def test_scan_finds_extension(self, tmp_path):
        # Build realistic directory structure
        manifest = _make_manifest(
            name="Good Extension",
            permissions=["storage"],
        )
        user_data = str(tmp_path / "chrome" / "User Data")
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": user_data}
        )
        result = scanner.scan_all()
        assert result.total == 1
        ext = result.extensions[0]
        assert ext.name == "Good Extension"
        assert ext.browser == "chrome"
        assert ext.profile == "Default"
        assert ext.install_source == InstallSource.WEB_STORE

    def test_scan_multiple_browsers(self, tmp_path):
        for browser in ("chrome", "edge"):
            manifest = _make_manifest(name=f"{browser} Ext")
            _write_manifest(
                str(tmp_path), browser, "Default",
                "abcdefghijklmnopabcdefghijklmnop", "1.0.0", manifest,
            )

        scanner = ExtensionScanner(
            browser_roots={
                "chrome": str(tmp_path / "chrome" / "User Data"),
                "edge": str(tmp_path / "edge" / "User Data"),
            }
        )
        result = scanner.scan_all()
        assert result.total == 2
        browsers = {e.browser for e in result.extensions}
        assert browsers == {"chrome", "edge"}

    def test_scan_multiple_profiles(self, tmp_path):
        for profile in ("Default", "Profile 1"):
            manifest = _make_manifest(name=f"Ext in {profile}")
            _write_manifest(
                str(tmp_path), "chrome", profile,
                "abcdefghijklmnopabcdefghijklmnop", "1.0.0", manifest,
            )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 2
        profiles = {e.profile for e in result.extensions}
        assert profiles == {"Default", "Profile 1"}

    def test_scan_skips_bad_manifest(self, tmp_path):
        # Write a valid extension
        manifest = _make_manifest(name="Valid")
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )
        # Write a bad manifest
        bad_path = os.path.join(
            str(tmp_path), "chrome", "User Data", "Default", "Extensions",
            "badext123456789012345678901234", "1.0.0",
        )
        os.makedirs(bad_path, exist_ok=True)
        with open(os.path.join(bad_path, "manifest.json"), "w") as f:
            f.write("not json")

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 1  # Only the valid one

    def test_scan_analyzes_risk(self, tmp_path):
        manifest = _make_manifest(
            name="Risky",
            permissions=["clipboardRead", "nativeMessaging"],
            host_permissions=["<all_urls>"],
        )
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 1
        ext = result.extensions[0]
        assert ext.risk_level == ExtensionRisk.CRITICAL
        assert ext.has_broad_host_access is True

    def test_last_scan_preserved(self, tmp_path):
        scanner = ExtensionScanner(browser_roots={})
        assert scanner.last_scan is None
        result = scanner.scan_all()
        assert scanner.last_scan is result

    def test_scan_latest_version(self, tmp_path):
        """When multiple versions exist, the scanner picks the latest."""
        for ver in ("1.0.0", "2.0.0"):
            manifest = _make_manifest(name="Multi", version=ver)
            _write_manifest(
                str(tmp_path), "chrome", "Default",
                "abcdefghijklmnopabcdefghijklmnop", ver, manifest,
            )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        # Should find exactly 1 extension (latest version wins)
        assert result.total == 1
        assert result.extensions[0].version == "2.0.0"


# ── Test: Event Emission ─────────────────────────────────────────────


class TestEventEmission:
    def test_emits_summary_event(self, tmp_path):
        manifest = _make_manifest(name="Simple", permissions=["storage"])
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        aggregator = MagicMock()
        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
            aggregator=aggregator,
        )
        scanner.scan_all()

        # Should have called ingest at least once (summary event)
        assert aggregator.ingest.called
        call_args = aggregator.ingest.call_args_list[0]
        assert call_args[1]["event_type"] == "system.extension_scan"
        assert call_args[1]["asset_id"] == "local"

    def test_emits_risk_events_for_critical(self, tmp_path):
        manifest = _make_manifest(
            name="Dangerous",
            permissions=["clipboardRead", "nativeMessaging"],
            host_permissions=["<all_urls>"],
        )
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        aggregator = MagicMock()
        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
            aggregator=aggregator,
        )
        scanner.scan_all()

        # Should have 2 calls: summary + critical extension
        assert aggregator.ingest.call_count == 2
        risk_call = aggregator.ingest.call_args_list[1]
        assert risk_call[1]["event_type"] == "system.extension_risk"
        assert risk_call[1]["severity"] == "critical"

    def test_no_risk_events_for_low(self, tmp_path):
        manifest = _make_manifest(name="Safe", permissions=["storage"])
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        aggregator = MagicMock()
        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
            aggregator=aggregator,
        )
        scanner.scan_all()

        # Only summary event, no individual risk events
        assert aggregator.ingest.call_count == 1

    def test_no_events_without_aggregator(self, tmp_path):
        manifest = _make_manifest(name="Safe")
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
            aggregator=None,
        )
        # Should not raise
        result = scanner.scan_all()
        assert result.total == 1

    def test_high_risk_emits_alert_severity(self, tmp_path):
        manifest = _make_manifest(
            name="HighRisk",
            permissions=["debugger"],
        )
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        aggregator = MagicMock()
        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")},
            aggregator=aggregator,
        )
        scanner.scan_all()

        assert aggregator.ingest.call_count == 2
        risk_call = aggregator.ingest.call_args_list[1]
        assert risk_call[1]["severity"] == "alert"  # high → alert severity


# ── Test: _default_browser_roots ─────────────────────────────────────


class TestDefaultBrowserRoots:
    def test_returns_dict(self):
        roots = _default_browser_roots()
        assert isinstance(roots, dict)
        # On Windows with LOCALAPPDATA set, should have entries
        if os.environ.get("LOCALAPPDATA"):
            assert "chrome" in roots
            assert "edge" in roots

    def test_no_localappdata(self):
        with patch.dict(os.environ, {}, clear=True):
            roots = _default_browser_roots()
            assert roots == {}


# ── Test: MV2 vs MV3 Parsing ────────────────────────────────────────


class TestMV2vsMV3:
    def test_mv2_permissions_contain_hosts(self, tmp_path):
        """MV2 puts host patterns in permissions, not host_permissions."""
        manifest = _make_manifest(
            manifest_version=2,
            permissions=["tabs", "https://example.com/*", "<all_urls>"],
        )
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        ext = result.extensions[0]
        # Host patterns should be in host_permissions, not api permissions
        assert "<all_urls>" in ext.host_permissions
        assert "https://example.com/*" in ext.host_permissions
        assert "tabs" in ext.permissions
        assert "<all_urls>" not in ext.permissions

    def test_mv3_separate_host_permissions(self, tmp_path):
        manifest = _make_manifest(
            manifest_version=3,
            permissions=["tabs"],
            host_permissions=["https://example.com/*"],
        )
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        ext = result.extensions[0]
        assert "https://example.com/*" in ext.host_permissions
        assert "tabs" in ext.permissions


# ── Test: Edge Cases ─────────────────────────────────────────────────


class TestEdgeCases:
    def test_msg_placeholder_name(self, tmp_path):
        """Extensions with __MSG_ names should still be parsed."""
        manifest = _make_manifest(name="__MSG_app_name__")
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 1
        assert result.extensions[0].name == "__MSG_app_name__"

    def test_long_description_truncated(self, tmp_path):
        manifest = _make_manifest(description="A" * 300)
        _write_manifest(
            str(tmp_path), "chrome", "Default", "abcdefghijklmnopabcdefghijklmnop",
            "1.0.0", manifest,
        )

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        ext = result.extensions[0]
        assert len(ext.description) <= 200
        assert ext.description.endswith("...")

    def test_no_extensions_dir(self, tmp_path):
        """Profile exists but no Extensions directory."""
        default = tmp_path / "chrome" / "User Data" / "Default"
        default.mkdir(parents=True)

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 0

    def test_extension_dir_without_version_subdir(self, tmp_path):
        """Extension ID dir exists but no version subdirectories."""
        ext_dir = tmp_path / "chrome" / "User Data" / "Default" / "Extensions" / "someid"
        ext_dir.mkdir(parents=True)
        # No version subdirectory

        scanner = ExtensionScanner(
            browser_roots={"chrome": str(tmp_path / "chrome" / "User Data")}
        )
        result = scanner.scan_all()
        assert result.total == 0

    def test_thread_safety_of_last_scan(self, tmp_path):
        """last_scan property uses a lock."""
        scanner = ExtensionScanner(browser_roots={})
        scanner.scan_all()
        # Accessing from multiple threads shouldn't crash
        results = []

        def _read():
            results.append(scanner.last_scan is not None)

        threads = [threading.Thread(target=_read) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert all(results)
