"""Tests for Cross-System Threat Correlation: Alert Bridging & Propagation (v0.3.29).

Covers:
  - Threat bridge: Remote Shield threats → EventAggregator (ingest call, asset resolution, severity normalization)
  - AlertPropagator: queues threat_alert commands to affected agents
  - CrossAssetCorrelator: alert propagation callback wiring
  - ALLOWED_COMMAND_TYPES includes threat_alert
  - windows_shield.py handles threat_alert command
  - Structural checks: source code wiring in main.py, remote_shield_routes.py
"""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest


# ── Paths ────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent
REMOTE_SHIELD_ROUTES = ROOT / "src" / "citadel_archer" / "api" / "remote_shield_routes.py"
MAIN_PY = ROOT / "src" / "citadel_archer" / "api" / "main.py"
CROSS_ASSET_CORR = ROOT / "src" / "citadel_archer" / "intel" / "cross_asset_correlation.py"
ALERT_PROP = ROOT / "src" / "citadel_archer" / "remote" / "alert_propagator.py"
WINDOWS_SHIELD = ROOT / "src" / "citadel_archer" / "agent" / "windows_shield.py"


# ── AlertPropagator Unit Tests ───────────────────────────────────────


@dataclass
class _FakeCorrelatedThreat:
    """Minimal CorrelatedThreat-like object for testing."""
    correlation_id: str = "corr-001"
    correlation_type: Any = None
    severity: str = "high"
    affected_assets: List[str] = field(default_factory=lambda: ["asset-1", "asset-2"])
    indicator: str = "192.168.1.100"
    event_count: int = 3
    description: str = "Same IP on two hosts"

    def __post_init__(self):
        if self.correlation_type is None:
            self.correlation_type = MagicMock(value="shared_ioc")


class TestAlertPropagator:
    """AlertPropagator unit tests."""

    def _make_propagator(self, agents=None):
        from citadel_archer.remote.alert_propagator import AlertPropagator
        db = MagicMock()
        if agents is None:
            agents = []
        db.list_agents.return_value = agents
        db.queue_command.return_value = {"command_id": "cmd-1", "status": "pending"}
        return AlertPropagator(shield_db=db), db

    def test_queues_commands_for_matching_agents(self):
        agents = [
            {"id": "agent-1", "asset_id": "asset-1"},
            {"id": "agent-2", "asset_id": "asset-2"},
        ]
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(affected_assets=["asset-1", "asset-2"])

        count = prop.propagate(threat)

        assert count == 2
        assert db.queue_command.call_count == 2

    def test_resolves_agent_from_asset_id(self):
        agents = [{"id": "agent-win-1", "asset_id": "family-pc-asset"}]
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(affected_assets=["family-pc-asset"])

        count = prop.propagate(threat)

        assert count == 1
        call_args = db.queue_command.call_args
        assert call_args[1]["agent_id"] == "agent-win-1" or call_args[0][1] == "agent-win-1"

    def test_skips_unknown_assets(self):
        agents = [{"id": "agent-1", "asset_id": "asset-1"}]
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(affected_assets=["unknown-asset", "asset-1"])

        count = prop.propagate(threat)

        assert count == 1  # only asset-1 matched

    def test_command_payload_shape(self):
        agents = [{"id": "agent-1", "asset_id": "asset-1"}]
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(
            correlation_id="c-42",
            severity="critical",
            indicator="10.0.0.5",
            description="Attack propagation detected",
            affected_assets=["asset-1"],
        )

        prop.propagate(threat)

        call_kwargs = db.queue_command.call_args
        # queue_command(command_id, agent_id, command_type, payload=...)
        if call_kwargs[1]:
            payload = call_kwargs[1].get("payload", call_kwargs[0][3] if len(call_kwargs[0]) > 3 else {})
        else:
            payload = call_kwargs[0][3] if len(call_kwargs[0]) > 3 else {}
        assert payload.get("correlation_id") == "c-42" or "c-42" in str(call_kwargs)
        assert "threat_alert" in str(call_kwargs)

    def test_empty_affected_assets(self):
        agents = [{"id": "agent-1", "asset_id": "asset-1"}]
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(affected_assets=[])

        count = prop.propagate(threat)

        assert count == 0
        db.queue_command.assert_not_called()

    def test_agents_without_asset_id_ignored(self):
        agents = [{"id": "agent-1"}]  # no asset_id key
        prop, db = self._make_propagator(agents)
        threat = _FakeCorrelatedThreat(affected_assets=["some-asset"])

        count = prop.propagate(threat)

        assert count == 0

    def test_cache_reused_on_second_call(self):
        agents = [{"id": "agent-1", "asset_id": "asset-1"}]
        prop, db = self._make_propagator(agents)

        prop.propagate(_FakeCorrelatedThreat(affected_assets=["asset-1"]))
        prop.propagate(_FakeCorrelatedThreat(affected_assets=["asset-1"]))

        # list_agents called only once (first miss populates cache)
        assert db.list_agents.call_count == 1

    def test_clear_cache(self):
        agents = [{"id": "agent-1", "asset_id": "asset-1"}]
        prop, db = self._make_propagator(agents)

        prop.propagate(_FakeCorrelatedThreat(affected_assets=["asset-1"]))
        prop.clear_cache()
        prop.propagate(_FakeCorrelatedThreat(affected_assets=["asset-1"]))

        # list_agents called twice: once before cache, once after clear
        assert db.list_agents.call_count == 2


# ── CrossAssetCorrelator Propagation Callback ────────────────────────


class TestCorrelatorAlertPropagation:
    """CrossAssetCorrelator.set_alert_propagation() wiring."""

    def test_set_alert_propagation_method_exists(self):
        from citadel_archer.intel.cross_asset_correlation import CrossAssetCorrelator
        assert hasattr(CrossAssetCorrelator, "set_alert_propagation")

    def test_emit_threat_calls_propagation_callback(self):
        from citadel_archer.intel.cross_asset_correlation import (
            CrossAssetCorrelator, CorrelatedThreat, CorrelationType,
        )

        agg = MagicMock()
        correlator = CrossAssetCorrelator(aggregator=agg)
        callback = MagicMock()
        correlator.set_alert_propagation(callback)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            severity="high",
            affected_assets=["asset-1", "asset-2"],
            indicator="1.2.3.4",
            description="test",
        )
        correlator._emit_threat(threat)

        callback.assert_called_once_with(threat)

    def test_propagation_not_called_when_no_affected_assets(self):
        from citadel_archer.intel.cross_asset_correlation import (
            CrossAssetCorrelator, CorrelatedThreat, CorrelationType,
        )

        agg = MagicMock()
        correlator = CrossAssetCorrelator(aggregator=agg)
        callback = MagicMock()
        correlator.set_alert_propagation(callback)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            affected_assets=[],
        )
        correlator._emit_threat(threat)

        callback.assert_not_called()

    def test_propagation_failure_does_not_break_emit(self):
        from citadel_archer.intel.cross_asset_correlation import (
            CrossAssetCorrelator, CorrelatedThreat, CorrelationType,
        )

        agg = MagicMock()
        correlator = CrossAssetCorrelator(aggregator=agg)
        callback = MagicMock(side_effect=RuntimeError("DB down"))
        correlator.set_alert_propagation(callback)

        threat = CorrelatedThreat(
            correlation_type=CorrelationType.SHARED_IOC,
            affected_assets=["a1"],
        )

        # Should not raise
        correlator._emit_threat(threat)

        # Threat should still be in history
        assert len(correlator.recent_correlations(limit=10)) == 1


# ── Severity Normalization in Bridge ──────────────────────────────────


class TestBridgeSeverityNormalization:
    """Verify _normalize_remote_severity is used in the bridge."""

    def test_normalize_used_in_bridge(self):
        source = REMOTE_SHIELD_ROUTES.read_text(encoding="utf-8")
        assert "_normalize_remote_severity" in source
        assert "remote.{threat.type.value}" in source or 'f"remote.{threat.type.value}"' in source


# ── ALLOWED_COMMAND_TYPES ────────────────────────────────────────────


class TestAllowedCommandTypes:
    """Verify threat_alert is allowed."""

    def test_threat_alert_in_allowed_types(self):
        from citadel_archer.api.remote_shield_routes import ALLOWED_COMMAND_TYPES
        assert "threat_alert" in ALLOWED_COMMAND_TYPES

    def test_check_updates_still_allowed(self):
        from citadel_archer.api.remote_shield_routes import ALLOWED_COMMAND_TYPES
        assert "check_updates" in ALLOWED_COMMAND_TYPES


# ── Windows Shield Command Handler ──────────────────────────────────


class TestWindowsShieldThreatAlert:
    """Verify windows_shield.py handles threat_alert command."""

    def test_source_has_threat_alert_handler(self):
        source = WINDOWS_SHIELD.read_text(encoding="utf-8")
        assert '"threat_alert"' in source or "'threat_alert'" in source
        assert "CROSS-SYSTEM ALERT" in source
        assert '"alert_received"' in source or "'alert_received'" in source


# ── Structural / Wiring Tests ────────────────────────────────────────


class TestStructuralWiring:
    """Verify source-level wiring is correct."""

    def test_remote_shield_routes_has_aggregator_bridge(self):
        source = REMOTE_SHIELD_ROUTES.read_text(encoding="utf-8")
        assert "services.event_aggregator" in source or "_svc.event_aggregator" in source
        assert ".ingest(" in source

    def test_main_py_wires_alert_propagator(self):
        source = MAIN_PY.read_text(encoding="utf-8")
        assert "AlertPropagator" in source
        assert "set_alert_propagation" in source

    def test_correlator_has_alert_propagation_attribute(self):
        source = CROSS_ASSET_CORR.read_text(encoding="utf-8")
        assert "_alert_propagation_callback" in source
        assert "def set_alert_propagation" in source

    def test_alert_propagator_module_exists(self):
        assert ALERT_PROP.exists()
        source = ALERT_PROP.read_text(encoding="utf-8")
        assert "class AlertPropagator" in source
        assert "def propagate" in source
        assert "def _resolve_agent" in source
