"""Tests for WebSocket connectivity and live badge behavior.

Covers:
  - Backend WebSocket /ws endpoint accepts connections and echoes
  - Static file no-cache headers (prevents Edge from serving stale JS)
  - Frontend JS modules have wsHandler.connected check after connect()
  - Dashboard-nav imports wsHandler for badge updates
  - Tab modules don't auto-init (tab-loader manages lifecycle)
"""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from citadel_archer.api.main import app
from citadel_archer.api.security import initialize_session_token


FRONTEND_JS = Path(__file__).parent.parent / "frontend" / "js"


# ── Backend WebSocket Tests ──────────────────────────────────────────

class TestWebSocketEndpoint:
    """The /ws endpoint must accept connections and stay open."""

    def test_websocket_connects(self):
        with TestClient(app) as client:
            with client.websocket_connect("/ws") as ws:
                ws.send_text("ping")
                data = ws.receive_text()
                assert "Server received: ping" in data

    def test_websocket_stays_open(self):
        """Multiple messages on the same connection."""
        with TestClient(app) as client:
            with client.websocket_connect("/ws") as ws:
                for i in range(3):
                    ws.send_text(f"msg-{i}")
                    data = ws.receive_text()
                    assert f"msg-{i}" in data

    def test_multiple_concurrent_connections(self):
        """Backend handles multiple simultaneous WS clients."""
        with TestClient(app) as client:
            with client.websocket_connect("/ws") as ws1:
                with client.websocket_connect("/ws") as ws2:
                    ws1.send_text("from-1")
                    ws2.send_text("from-2")
                    assert "from-1" in ws1.receive_text()
                    assert "from-2" in ws2.receive_text()


# ── Static File Cache Headers ────────────────────────────────────────

class TestNoCacheHeaders:
    """JS/CSS files must be served with no-cache to prevent stale Edge cache."""

    def test_js_files_have_no_cache(self):
        with TestClient(app) as client:
            resp = client.get("/js/main.js")
            if resp.status_code == 200:
                cc = resp.headers.get("cache-control", "")
                assert "no-cache" in cc or "no-store" in cc, (
                    f"JS files should have no-cache header, got: {cc}"
                )

    def test_css_files_have_no_cache(self):
        with TestClient(app) as client:
            resp = client.get("/css/styles.css")
            if resp.status_code == 200:
                cc = resp.headers.get("cache-control", "")
                assert "no-cache" in cc or "no-store" in cc


# ── Session Token ────────────────────────────────────────────────────

class TestSessionEndpoint:
    """The /api/session endpoint must work after startup initialization."""

    def test_session_token_available_after_startup(self):
        with TestClient(app) as client:
            resp = client.get("/api/session")
            assert resp.status_code == 200
            data = resp.json()
            assert "session_token" in data
            assert len(data["session_token"]) > 0


# ── Frontend JS Source Checks ────────────────────────────────────────

class TestLiveBadgeJSPattern:
    """Each tab module must check wsHandler.connected after wsHandler.connect()."""

    TAB_MODULES = ["charts.js", "timeline.js", "risk-metrics.js", "assets.js"]

    @pytest.mark.parametrize("module", TAB_MODULES)
    def test_has_connected_check(self, module):
        """Module must have `if (wsHandler.connected)` after connect()."""
        source = (FRONTEND_JS / module).read_text(encoding="utf-8")
        assert "wsHandler.connected" in source, (
            f"{module} missing wsHandler.connected check — "
            "badge will stay 'Offline' on tab switch"
        )

    @pytest.mark.parametrize("module", TAB_MODULES)
    def test_no_auto_init(self, module):
        """Module must NOT auto-init — tab-loader manages the lifecycle."""
        source = (FRONTEND_JS / module).read_text(encoding="utf-8")
        # Check for the problematic readyState auto-init pattern
        assert "document.readyState" not in source, (
            f"{module} has auto-init code (document.readyState check). "
            "This causes double-init when loaded via tab-loader."
        )


class TestDashboardNavImportsWsHandler:
    """dashboard-nav.js must import wsHandler for badge updates."""

    def test_imports_websocket_handler(self):
        source = (FRONTEND_JS / "dashboard-nav.js").read_text(encoding="utf-8")
        assert "from './websocket-handler.js'" in source or \
               'from "./websocket-handler.js"' in source, (
            "dashboard-nav.js must import wsHandler from websocket-handler.js "
            "to receive ws-connected events on page load"
        )

    def test_polls_wshandler_connected(self):
        source = (FRONTEND_JS / "dashboard-nav.js").read_text(encoding="utf-8")
        assert "wsHandler.connected" in source, (
            "dashboard-nav.js must poll wsHandler.connected for "
            "continuous badge status updates"
        )

    def test_checks_connected_state(self):
        source = (FRONTEND_JS / "dashboard-nav.js").read_text(encoding="utf-8")
        assert "wsHandler.connected" in source, (
            "dashboard-nav.js must check wsHandler.connected for immediate "
            "badge update"
        )


class TestWebSocketHandlerSingleton:
    """websocket-handler.js must export a singleton and auto-connect."""

    def test_exports_singleton(self):
        source = (FRONTEND_JS / "websocket-handler.js").read_text(encoding="utf-8")
        assert "const wsHandler = new WebSocketHandler()" in source

    def test_has_connected_getter(self):
        source = (FRONTEND_JS / "websocket-handler.js").read_text(encoding="utf-8")
        assert "get connected()" in source

    def test_broadcasts_window_events(self):
        source = (FRONTEND_JS / "websocket-handler.js").read_text(encoding="utf-8")
        assert "ws-connected" in source
        assert "ws-disconnected" in source
