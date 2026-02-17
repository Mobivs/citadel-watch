# PRD: Tests - WebSocket Real-Time Integration (P2.1.5-T7)
# Reference: PHASE_2_SPEC.md
#
# 40+ tests covering:
#   - websocket-handler.js file structure & exports
#   - WebSocketHandler class API
#   - Exponential backoff computation
#   - Subscribe / unsubscribe / wildcard pattern
#   - Constants (MAX_RETRIES, BASE_DELAY_MS, MAX_DELAY_MS, MESSAGE_TYPES)
#   - Singleton pattern & auto-connect
#   - Memory leak prevention (clearSubscribers, disconnect cleanup)
#   - Component integration (charts.js, risk-metrics.js, timeline.js, assets.js)
#   - Old inline WebSocket removal

import re
from pathlib import Path

import pytest


FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
JS_DIR = FRONTEND_DIR / "js"
WS_HANDLER_PATH = JS_DIR / "websocket-handler.js"
CHARTS_PATH = JS_DIR / "charts.js"
RISK_METRICS_PATH = JS_DIR / "risk-metrics.js"
TIMELINE_PATH = JS_DIR / "timeline.js"
ASSETS_PATH = JS_DIR / "assets.js"

COMPONENT_FILES = {
    "charts": CHARTS_PATH,
    "risk-metrics": RISK_METRICS_PATH,
    "timeline": TIMELINE_PATH,
    "assets": ASSETS_PATH,
}


# =====================================================================
# Section 1: websocket-handler.js Exists & Structure
# =====================================================================

class TestWSHandlerFileStructure:
    """Verify websocket-handler.js exists and has correct structure."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_file_exists(self):
        assert WS_HANDLER_PATH.exists(), "websocket-handler.js must exist"

    def test_file_is_es_module(self, src):
        assert "export" in src, "Must be an ES module with exports"

    def test_has_header_comment(self, src):
        assert "P2.1.5-T7" in src or "WebSocket" in src[:200], \
            "Should have a header comment referencing the task"

    def test_has_class_definition(self, src):
        assert "class WebSocketHandler" in src

    def test_has_singleton_instance(self, src):
        assert re.search(r"const\s+wsHandler\s*=\s*new\s+WebSocketHandler", src), \
            "Must create singleton wsHandler instance"


# =====================================================================
# Section 2: Constants
# =====================================================================

class TestWSHandlerConstants:
    """Verify reconnection and message type constants."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_max_retries_defined(self, src):
        assert re.search(r"MAX_RETRIES\s*=\s*5", src), \
            "MAX_RETRIES must be 5"

    def test_base_delay_defined(self, src):
        assert re.search(r"BASE_DELAY_MS\s*=\s*1000", src), \
            "BASE_DELAY_MS must be 1000"

    def test_max_delay_defined(self, src):
        assert re.search(r"MAX_DELAY_MS\s*=\s*30000", src), \
            "MAX_DELAY_MS must be 30000"

    def test_message_types_array(self, src):
        assert "MESSAGE_TYPES" in src, "MESSAGE_TYPES constant must exist"

    def test_message_type_threat_detected(self, src):
        assert "'threat_detected'" in src or '"threat_detected"' in src

    def test_message_type_asset_status_changed(self, src):
        assert "'asset_status_changed'" in src or '"asset_status_changed"' in src

    def test_message_type_alert_created(self, src):
        assert "'alert_created'" in src or '"alert_created"' in src

    def test_message_type_event(self, src):
        assert "'event'" in src or '"event"' in src

    def test_message_type_security_level_changed(self, src):
        assert "'security_level_changed'" in src or '"security_level_changed"' in src

    def test_constants_exported(self, src):
        for name in ["MAX_RETRIES", "BASE_DELAY_MS", "MAX_DELAY_MS", "MESSAGE_TYPES"]:
            assert name in src, f"{name} must be exported"


# =====================================================================
# Section 3: WebSocketHandler Class API
# =====================================================================

class TestWSHandlerClassAPI:
    """Verify the WebSocketHandler class has all required methods."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_connect_method(self, src):
        assert re.search(r"connect\s*\(", src), "Must have connect() method"

    def test_disconnect_method(self, src):
        assert re.search(r"disconnect\s*\(", src), "Must have disconnect() method"

    def test_reset_method(self, src):
        assert re.search(r"reset\s*\(", src), "Must have reset() method"

    def test_subscribe_method(self, src):
        assert re.search(r"subscribe\s*\(\s*type", src), "Must have subscribe(type, cb) method"

    def test_unsubscribe_method(self, src):
        assert re.search(r"unsubscribe\s*\(\s*type", src), "Must have unsubscribe(type, cb) method"

    def test_clear_subscribers_method(self, src):
        assert re.search(r"clearSubscribers\s*\(", src), \
            "Must have clearSubscribers() for leak prevention"

    def test_connected_getter(self, src):
        assert re.search(r"get\s+connected", src), "Must have connected getter"

    def test_retry_count_getter(self, src):
        assert re.search(r"get\s+retryCount", src), "Must have retryCount getter"

    def test_subscriber_count_getter(self, src):
        assert re.search(r"get\s+subscriberCount", src), "Must have subscriberCount getter"


# =====================================================================
# Section 4: Exponential Backoff
# =====================================================================

class TestExponentialBackoff:
    """Verify exponential backoff with jitter."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_compute_backoff_function_exists(self, src):
        assert re.search(r"function\s+computeBackoff", src), \
            "computeBackoff() must be a standalone function"

    def test_compute_backoff_exported(self, src):
        assert "computeBackoff" in src.split("export")[-1], \
            "computeBackoff must be exported (for testing)"

    def test_uses_math_pow(self, src):
        assert "Math.pow" in src, "Backoff must use Math.pow for exponential growth"

    def test_has_jitter(self, src):
        assert "jitter" in src.lower() or "Math.random" in src, \
            "Backoff must include jitter to prevent thundering herd"

    def test_has_max_cap(self, src):
        assert "Math.min" in src, "Backoff must cap at MAX_DELAY_MS"

    def test_schedule_reconnect_uses_backoff(self, src):
        assert re.search(r"computeBackoff\s*\(", src), \
            "_scheduleReconnect must call computeBackoff()"

    def test_max_retries_check(self, src):
        assert re.search(r"_retryCount\s*>=\s*MAX_RETRIES", src), \
            "Must check retry count against MAX_RETRIES"


# =====================================================================
# Section 5: Subscribe / Unsubscribe / Wildcard
# =====================================================================

class TestSubscriptionPattern:
    """Verify subscribe/unsubscribe and wildcard support."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_subscribers_map(self, src):
        assert re.search(r"_subscribers\s*=\s*new\s+Map", src), \
            "Must use Map for subscriber storage"

    def test_subscribe_returns_unsubscribe_function(self, src):
        # The subscribe method should return a cleanup function
        subscribe_section = src[src.index("subscribe(type"):src.index("unsubscribe(type")]
        assert "return" in subscribe_section, \
            "subscribe() must return an unsubscribe function"

    def test_wildcard_support(self, src):
        assert "'*'" in src or '"*"' in src, \
            "Must support wildcard '*' subscriptions"

    def test_wildcard_notified_on_message(self, src):
        on_message = src[src.index("_onMessage"):]
        assert "wildcard" in on_message.lower() or "'*'" in on_message or '"*"' in on_message, \
            "_onMessage must notify wildcard subscribers"

    def test_subscriber_error_handling(self, src):
        assert re.search(r"catch\s*\(\s*err", src), \
            "Subscriber dispatch must catch errors to prevent cascade"


# =====================================================================
# Section 6: Connection Status Broadcasting
# =====================================================================

class TestConnectionStatusBroadcasting:
    """Verify window event broadcasting."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_broadcasts_ws_connected(self, src):
        assert "'ws-connected'" in src or '"ws-connected"' in src

    def test_broadcasts_ws_disconnected(self, src):
        assert "'ws-disconnected'" in src or '"ws-disconnected"' in src

    def test_uses_custom_event(self, src):
        assert "CustomEvent" in src, "Must use CustomEvent for broadcasting"

    def test_broadcast_includes_detail(self, src):
        assert "detail:" in src or "detail :" in src, \
            "CustomEvent must include detail payload"


# =====================================================================
# Section 7: Memory Leak Prevention
# =====================================================================

class TestMemoryLeakPrevention:
    """Verify cleanup mechanisms."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_disconnect_clears_retry_timer(self, src):
        disconnect_section = src[src.index("disconnect()"):src.index("reset()")]
        assert "clearTimeout" in disconnect_section or "_clearRetryTimer" in disconnect_section, \
            "disconnect() must clear retry timer"

    def test_disconnect_sets_disposed_flag(self, src):
        disconnect_section = src[src.index("disconnect()"):src.index("reset()")]
        assert "_disposed" in disconnect_section, \
            "disconnect() must set _disposed = true"

    def test_disconnect_nulls_ws(self, src):
        disconnect_section = src[src.index("disconnect()"):src.index("reset()")]
        assert "this._ws = null" in disconnect_section or \
               "this._ws=null" in disconnect_section, \
            "disconnect() must null out _ws reference"

    def test_connect_checks_disposed(self, src):
        connect_section = src[src.index("connect("):src.index("disconnect()")]
        assert "_disposed" in connect_section, \
            "connect() must check _disposed flag"

    def test_clear_retry_timer_method(self, src):
        assert re.search(r"_clearRetryTimer\s*\(", src), \
            "Must have _clearRetryTimer() helper"


# =====================================================================
# Section 8: Auto-connect at module level
# =====================================================================

class TestAutoConnect:
    """Verify auto-connect behavior."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    def test_auto_connect_at_module_level(self, src):
        """wsHandler.connect() must be called at module level (not gated by an event)."""
        # Find the singleton creation line and check connect() follows it
        singleton_idx = src.index("const wsHandler")
        after_singleton = src[singleton_idx:]
        assert "wsHandler.connect()" in after_singleton


# =====================================================================
# Section 9: Exports
# =====================================================================

class TestWSHandlerExports:
    """Verify all required symbols are exported."""

    @pytest.fixture
    def src(self):
        if not WS_HANDLER_PATH.exists():
            pytest.skip("websocket-handler.js not found")
        return WS_HANDLER_PATH.read_text(encoding='utf-8')

    @pytest.fixture
    def export_block(self, src):
        # Find the last export statement
        idx = src.rfind("export")
        return src[idx:]

    def test_exports_websocket_handler_class(self, export_block):
        assert "WebSocketHandler" in export_block

    def test_exports_ws_handler_instance(self, export_block):
        assert "wsHandler" in export_block

    def test_exports_compute_backoff(self, export_block):
        assert "computeBackoff" in export_block

    def test_exports_max_retries(self, export_block):
        assert "MAX_RETRIES" in export_block

    def test_exports_message_types(self, export_block):
        assert "MESSAGE_TYPES" in export_block


# =====================================================================
# Section 10: Component Integration - Import
# =====================================================================

class TestComponentImportWSHandler:
    """Verify all component JS files import from websocket-handler.js."""

    @pytest.fixture(params=["charts", "risk-metrics", "timeline", "assets"])
    def component(self, request):
        path = COMPONENT_FILES[request.param]
        if not path.exists():
            pytest.skip(f"{request.param}.js not found")
        return request.param, path.read_text(encoding='utf-8')

    def test_imports_ws_handler(self, component):
        name, src = component
        assert re.search(
            r"import\s*\{[^}]*wsHandler[^}]*\}\s*from\s*['\"]\.\/websocket-handler\.js['\"]",
            src
        ), f"{name}.js must import wsHandler from websocket-handler.js"


# =====================================================================
# Section 11: Component Integration - Subscriptions
# =====================================================================

class TestComponentSubscriptions:
    """Verify component connectWebSocket() uses wsHandler.subscribe()."""

    @pytest.fixture(params=["charts", "risk-metrics", "timeline", "assets"])
    def component(self, request):
        path = COMPONENT_FILES[request.param]
        if not path.exists():
            pytest.skip(f"{request.param}.js not found")
        return request.param, path.read_text(encoding='utf-8')

    def test_connect_uses_ws_handler_subscribe(self, component):
        name, src = component
        assert "wsHandler.subscribe(" in src, \
            f"{name}.js connectWebSocket() must call wsHandler.subscribe()"

    def test_polls_ws_handler_connected(self, component):
        name, src = component
        assert "wsHandler.connected" in src, \
            f"{name}.js must poll wsHandler.connected for badge status"

    def test_listens_for_ws_connected_event(self, component):
        name, src = component
        assert "'ws-connected'" in src or '"ws-connected"' in src, \
            f"{name}.js must listen for ws-connected event"

    def test_listens_for_ws_disconnected_event(self, component):
        name, src = component
        assert "'ws-disconnected'" in src or '"ws-disconnected"' in src, \
            f"{name}.js must listen for ws-disconnected event"


# =====================================================================
# Section 12: Old Inline WebSocket Removal
# =====================================================================

class TestOldWebSocketRemoved:
    """Verify old inline WebSocket code is removed from components."""

    @pytest.fixture(params=["charts", "risk-metrics", "timeline", "assets"])
    def component(self, request):
        path = COMPONENT_FILES[request.param]
        if not path.exists():
            pytest.skip(f"{request.param}.js not found")
        return request.param, path.read_text(encoding='utf-8')

    def test_no_new_websocket(self, component):
        name, src = component
        # Should not create WebSocket directly (only wsHandler does that)
        assert "new WebSocket(" not in src, \
            f"{name}.js must NOT create WebSocket directly — use wsHandler"

    def test_no_flat_reconnect_timeout(self, component):
        name, src = component
        # Old pattern: setTimeout(connectWebSocket, 5000)
        assert "setTimeout(connectWebSocket" not in src, \
            f"{name}.js must NOT use flat setTimeout reconnect — wsHandler handles backoff"

    def test_no_ws_onopen(self, component):
        name, src = component
        assert "ws.onopen" not in src, \
            f"{name}.js must NOT set ws.onopen — wsHandler manages the connection"

    def test_no_ws_onclose(self, component):
        name, src = component
        assert "ws.onclose" not in src, \
            f"{name}.js must NOT set ws.onclose — wsHandler manages reconnection"

    def test_no_ws_onmessage(self, component):
        name, src = component
        assert "ws.onmessage" not in src, \
            f"{name}.js must NOT set ws.onmessage — wsHandler dispatches messages"

    def test_no_unused_ws_variable(self, component):
        name, src = component
        # Should not have a standalone `let ws = null` since wsHandler manages it
        assert not re.search(r"^let\s+ws\s*=\s*null", src, re.MULTILINE), \
            f"{name}.js must NOT have unused 'let ws = null' variable"


# =====================================================================
# Section 13: Page-specific Subscription Types
# =====================================================================

class TestPageSpecificSubscriptions:
    """Verify each page subscribes to the correct message types."""

    def _get_src(self, path):
        if not path.exists():
            pytest.skip(f"{path.name} not found")
        return path.read_text(encoding='utf-8')

    def test_charts_subscribes_to_event(self):
        src = self._get_src(CHARTS_PATH)
        assert "subscribe('event'" in src or 'subscribe("event"' in src

    def test_charts_subscribes_to_threat_detected(self):
        src = self._get_src(CHARTS_PATH)
        assert "subscribe('threat_detected'" in src or 'subscribe("threat_detected"' in src

    def test_charts_subscribes_to_security_level_changed(self):
        src = self._get_src(CHARTS_PATH)
        assert "subscribe('security_level_changed'" in src or \
               'subscribe("security_level_changed"' in src

    def test_risk_metrics_subscribes_to_threat_detected(self):
        src = self._get_src(RISK_METRICS_PATH)
        assert "subscribe('threat_detected'" in src or 'subscribe("threat_detected"' in src

    def test_risk_metrics_subscribes_to_security_level_changed(self):
        src = self._get_src(RISK_METRICS_PATH)
        assert "subscribe('security_level_changed'" in src or \
               'subscribe("security_level_changed"' in src

    def test_timeline_subscribes_to_event(self):
        src = self._get_src(TIMELINE_PATH)
        assert "subscribe('event'" in src or 'subscribe("event"' in src

    def test_timeline_subscribes_to_threat_detected(self):
        src = self._get_src(TIMELINE_PATH)
        assert "subscribe('threat_detected'" in src or 'subscribe("threat_detected"' in src

    def test_timeline_subscribes_to_alert_created(self):
        src = self._get_src(TIMELINE_PATH)
        assert "subscribe('alert_created'" in src or 'subscribe("alert_created"' in src

    def test_assets_subscribes_to_asset_status_changed(self):
        src = self._get_src(ASSETS_PATH)
        assert "subscribe('asset_status_changed'" in src or \
               'subscribe("asset_status_changed"' in src

    def test_assets_subscribes_to_threat_detected(self):
        src = self._get_src(ASSETS_PATH)
        assert "subscribe('threat_detected'" in src or 'subscribe("threat_detected"' in src

    def test_assets_subscribes_to_security_level_changed(self):
        src = self._get_src(ASSETS_PATH)
        assert "subscribe('security_level_changed'" in src or \
               'subscribe("security_level_changed"' in src
