"""
Tests for v0.3.12: AI Bridge VPS tool enhancements.

Covers: Enhanced get_agent_events return format (severity breakdown,
agent health info), get_vps_summary tool (overview of all agents),
empty agents case, tool dispatch map.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.chat.ai_bridge import AIBridge, TOOLS


@pytest.fixture
def bridge():
    chat_mgr = MagicMock()
    chat_mgr.send_system = AsyncMock()
    chat_mgr.subscribe = MagicMock()
    # Create bridge without API key (disabled mode) — we test tools directly
    b = AIBridge(chat_manager=chat_mgr)
    return b


class TestToolDefinitions:
    """get_vps_summary tool is properly defined."""

    def test_vps_summary_tool_exists(self):
        names = {t["name"] for t in TOOLS}
        assert "get_vps_summary" in names

    def test_vps_summary_tool_schema(self):
        tool = next(t for t in TOOLS if t["name"] == "get_vps_summary")
        assert tool["input_schema"]["type"] == "object"

    def test_all_tools_present(self):
        names = {t["name"] for t in TOOLS}
        expected = {"get_system_status", "get_asset_list", "get_agent_events",
                    "deploy_agent", "get_vps_summary"}
        assert expected == names


class TestToolDispatch:
    """Tool dispatch map includes new tools."""

    @pytest.mark.asyncio
    async def test_dispatch_vps_summary(self, bridge):
        with patch.object(bridge, "_tool_vps_summary", new_callable=AsyncMock) as mock:
            mock.return_value = {"total_agents": 0}
            result = await bridge._execute_tool("get_vps_summary", {})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_agent_events(self, bridge):
        with patch.object(bridge, "_tool_agent_events", new_callable=AsyncMock) as mock:
            mock.return_value = {"threats": []}
            result = await bridge._execute_tool("get_agent_events", {"asset_id": "vps1"})
            mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_dispatch_unknown_tool(self, bridge):
        result = await bridge._execute_tool("nonexistent_tool", {})
        assert "error" in result


class TestEnhancedAgentEvents:
    """get_agent_events returns enriched data."""

    @pytest.mark.asyncio
    async def test_returns_dict_with_agent_info(self, bridge):
        mock_db = MagicMock()
        mock_db.list_threats.return_value = [
            {"severity": 9, "agent_id": "shield_vps1", "threat_type": "malware"},
            {"severity": 7, "agent_id": "shield_vps1", "threat_type": "auth"},
            {"severity": 3, "agent_id": "shield_vps1", "threat_type": "info"},
        ]
        mock_db.get_agent.return_value = {
            "agent_id": "shield_vps1",
            "hostname": "my-vps",
            "version": "0.2.0",
            "last_heartbeat": "2026-01-01T00:00:00",
        }

        with patch("citadel_archer.remote.shield_database.RemoteShieldDatabase", return_value=mock_db):
            result = await bridge._tool_agent_events({"asset_id": "vps1"})

        assert result["asset_id"] == "vps1"
        assert result["total_threats"] == 3
        assert result["agent"]["hostname"] == "my-vps"
        assert result["agent"]["status"] == "online"
        assert result["severity_breakdown"]["critical"] == 1
        assert result["severity_breakdown"]["high"] == 1
        assert result["severity_breakdown"]["low"] == 1

    @pytest.mark.asyncio
    async def test_unknown_agent_status(self, bridge):
        mock_db = MagicMock()
        mock_db.list_threats.return_value = []
        mock_db.get_agent.return_value = None

        with patch("citadel_archer.remote.shield_database.RemoteShieldDatabase", return_value=mock_db):
            result = await bridge._tool_agent_events({"asset_id": "missing"})

        assert result["agent"]["status"] == "unknown"
        assert result["total_threats"] == 0

    @pytest.mark.asyncio
    async def test_severity_breakdown_ranges(self, bridge):
        mock_db = MagicMock()
        mock_db.list_threats.return_value = [
            {"severity": 10},  # critical
            {"severity": 9},   # critical
            {"severity": 8},   # high
            {"severity": 7},   # high
            {"severity": 5},   # medium
            {"severity": 4},   # medium
            {"severity": 2},   # low
        ]
        mock_db.get_agent.return_value = None

        with patch("citadel_archer.remote.shield_database.RemoteShieldDatabase", return_value=mock_db):
            result = await bridge._tool_agent_events({"asset_id": "x"})

        bd = result["severity_breakdown"]
        assert bd["critical"] == 2
        assert bd["high"] == 2
        assert bd["medium"] == 2
        assert bd["low"] == 1


class TestVPSSummaryTool:
    """get_vps_summary returns overview of all agents."""

    @pytest.mark.asyncio
    async def test_empty_agents(self, bridge):
        mock_db = MagicMock()
        mock_db.list_agents.return_value = []
        mock_db.list_threats.return_value = []

        with patch("citadel_archer.remote.shield_database.RemoteShieldDatabase", return_value=mock_db):
            result = await bridge._tool_vps_summary({})

        assert result["total_agents"] == 0
        assert result["total_open_threats"] == 0
        assert result["agents"] == {}

    @pytest.mark.asyncio
    async def test_multiple_agents_with_threats(self, bridge):
        mock_db = MagicMock()
        mock_db.list_agents.return_value = [
            {"agent_id": "shield_vps1", "hostname": "web-server",
             "version": "0.2.0", "last_heartbeat": "2026-01-01"},
            {"agent_id": "shield_vps2", "hostname": "db-server",
             "version": "0.2.0", "last_heartbeat": "2026-01-01"},
        ]
        mock_db.list_threats.return_value = [
            {"agent_id": "shield_vps1", "severity": 9, "status": "open"},
            {"agent_id": "shield_vps1", "severity": 7, "status": "open"},
            {"agent_id": "shield_vps2", "severity": 3, "status": "open"},
        ]

        with patch("citadel_archer.remote.shield_database.RemoteShieldDatabase", return_value=mock_db):
            result = await bridge._tool_vps_summary({})

        assert result["total_agents"] == 2
        assert result["total_open_threats"] == 3
        assert result["agents"]["web-server"]["open_threats"] == 2
        assert result["agents"]["web-server"]["critical"] == 1
        assert result["agents"]["web-server"]["high"] == 1
        assert result["agents"]["db-server"]["open_threats"] == 1
        assert result["agents"]["db-server"]["critical"] == 0
