"""
Tests for port knocking — PortKnockGuard (iptables rules) and KnockClient (sender).

iptables calls are mocked since tests don't run as root.
"""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from citadel_archer.agent.shield import PortKnockGuard
from citadel_archer.remote.knock_client import KnockClient, knock_and_connect


class TestPortKnockGuard:
    """iptables-based port-knocking rules."""

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_apply_rules_creates_chain(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        guard = PortKnockGuard(config={
            "knock_sequence": [7000, 8000, 9000],
            "ssh_port": 22,
        })
        result = guard.apply_rules()
        assert result is True
        assert guard.is_active is True

        # Should have called iptables multiple times:
        # flush(2) + create chain(1) + accept rule(1) + 3 knock rules + 1 INPUT jump
        assert mock_run.call_count >= 7

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_remove_rules(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        guard = PortKnockGuard(config={
            "knock_sequence": [7000, 8000, 9000],
            "ssh_port": 22,
        })
        guard._applied = True
        guard.remove_rules()
        assert guard.is_active is False

    def test_no_sequence_returns_false(self):
        guard = PortKnockGuard(config={})
        result = guard.apply_rules()
        assert result is False
        assert guard.is_active is False

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_custom_sequence_and_port(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        guard = PortKnockGuard(config={
            "knock_sequence": [1111, 2222],
            "ssh_port": 2222,
            "knock_open_time": 60,
        })
        guard.apply_rules()
        assert guard.is_active is True
        assert guard.ssh_port == 2222
        assert guard.open_time == 60

    @patch("citadel_archer.agent.shield.subprocess.run")
    def test_apply_is_idempotent(self, mock_run):
        """Calling apply_rules twice should flush first, then re-apply."""
        mock_run.return_value = MagicMock(returncode=0)
        guard = PortKnockGuard(config={"knock_sequence": [7000, 8000, 9000]})
        guard.apply_rules()
        first_count = mock_run.call_count
        mock_run.reset_mock()
        guard.apply_rules()
        # Second call should also work (flush + re-apply)
        assert mock_run.call_count >= 5


class TestKnockClient:
    """Client-side knock sender."""

    @patch("citadel_archer.remote.knock_client.socket.socket")
    def test_knock_sequence_sends_tcp(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        client = KnockClient("192.168.1.1", [7000, 8000, 9000], delay=0)
        result = client.knock()

        assert result is True
        assert mock_sock.connect_ex.call_count == 3
        mock_sock.connect_ex.assert_any_call(("192.168.1.1", 7000))
        mock_sock.connect_ex.assert_any_call(("192.168.1.1", 8000))
        mock_sock.connect_ex.assert_any_call(("192.168.1.1", 9000))

    @patch("citadel_archer.remote.knock_client.socket.socket")
    def test_knock_failure_returns_false(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.side_effect = OSError("Connection refused")
        mock_socket_cls.return_value = mock_sock

        client = KnockClient("192.168.1.1", [7000, 8000])
        result = client.knock()
        assert result is False

    @pytest.mark.asyncio
    @patch("citadel_archer.remote.knock_client.KnockClient.knock", return_value=True)
    async def test_knock_and_connect_success(self, mock_knock):
        mock_ssh = AsyncMock()
        mock_ssh.connect = AsyncMock()

        result = await knock_and_connect(
            mock_ssh, "vps_1", [7000, 8000, 9000], "10.0.0.1"
        )
        assert result is True
        mock_knock.assert_called_once()
        mock_ssh.connect.assert_called_once_with("vps_1")
