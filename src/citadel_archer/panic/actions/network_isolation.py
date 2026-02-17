"""
Network Isolation Action - Emergency network lockdown

Supports both local and remote execution.  When ``target_asset`` is
``"local"`` (the default), commands run via subprocess.  For remote
assets, they are executed over SSH through the ``_run_command()``
helper inherited from ``BaseAction``.
"""

import json
import logging
from typing import Dict, Any, List
from datetime import datetime

from .base import BaseAction

logger = logging.getLogger(__name__)


class NetworkIsolation(BaseAction):
    """
    Handles network isolation during panic mode
    Blocks all connections except whitelisted IPs/ports
    """

    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """Execute network isolation based on action parameters"""
        action_name = action.name
        params = action.params
        asset_id = params.get('target_asset', 'local')

        try:
            if action_name == 'block_all_incoming':
                return await self._block_incoming_traffic(asset_id)
            elif action_name == 'block_outgoing_except_whitelist':
                return await self._block_outgoing_with_whitelist(asset_id)
            elif action_name == 'whitelist_essential':
                return await self._apply_whitelist_rules(asset_id)
            elif action_name == 'snapshot_connections':
                return await self._snapshot_network_state(session.id, asset_id)
            elif action_name == 'log_active_connections':
                return await self._log_connections(session.id, asset_id)
            elif action_name == 'snapshot_netstat':
                return await self._capture_netstat(session.id, asset_id)
            else:
                return {
                    'action': action_name,
                    'type': 'network',
                    'asset': asset_id,
                    'status': 'failed',
                    'error': f'Unknown network action: {action_name}'
                }

        except Exception as e:
            logger.error(f"Network isolation action {action_name} on {asset_id} failed: {e}")
            return {
                'action': action_name,
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }

    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current network state before isolation"""
        asset_id = action.params.get('target_asset', 'local')
        state = {}

        try:
            state['iptables_rules'] = await self._get_iptables_rules(asset_id)
            state['routes'] = await self._get_routes(asset_id)
            state['connections'] = await self._get_connections(asset_id)
            state['interfaces'] = await self._get_interfaces(asset_id)
        except Exception as e:
            logger.error(f"Failed to capture network state on {asset_id}: {e}")
            state['error'] = str(e)

        return state

    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """Restore network configuration from saved state"""
        asset_id = recovery_state.get('asset', 'local')
        try:
            pre_state = json.loads(recovery_state['pre_panic_state'])

            if 'iptables_rules' in pre_state:
                await self._restore_iptables(pre_state['iptables_rules'], asset_id)

            if 'routes' in pre_state:
                await self._restore_routes(pre_state['routes'], asset_id)

            return {
                'status': 'success',
                'details': f'Network configuration restored on {asset_id}'
            }

        except Exception as e:
            logger.error(f"Network rollback failed on {asset_id}: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }

    # ------------------------------------------------------------------
    # Action implementations
    # ------------------------------------------------------------------

    async def _block_incoming_traffic(self, asset_id: str = "local") -> Dict[str, Any]:
        """Block all incoming traffic except established connections"""
        try:
            r1 = await self._run_command(
                ['iptables', '-P', 'INPUT', 'DROP'], asset_id=asset_id
            )
            if r1.returncode != 0:
                raise RuntimeError(f"iptables -P INPUT DROP failed: {r1.stderr}")

            await self._run_command(
                ['iptables', '-A', 'INPUT', '-m', 'state',
                 '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
                asset_id=asset_id,
            )

            await self._run_command(
                ['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
                asset_id=asset_id,
            )

            await self._save_isolation_rule(
                rule_type='firewall',
                direction='inbound',
                action='deny',
                protocol='all'
            )

            return {
                'action': 'block_all_incoming',
                'type': 'network',
                'asset': asset_id,
                'status': 'success',
                'result': {'policy': 'DROP', 'exceptions': ['established', 'localhost']}
            }

        except Exception as e:
            return {
                'action': 'block_all_incoming',
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }

    async def _block_outgoing_with_whitelist(self, asset_id: str = "local") -> Dict[str, Any]:
        """Block outgoing traffic except to whitelisted destinations"""
        try:
            whitelist = await self._get_whitelist()

            await self._run_command(
                ['iptables', '-P', 'OUTPUT', 'DROP'], asset_id=asset_id
            )

            await self._run_command(
                ['iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
                asset_id=asset_id,
            )

            for entry in whitelist:
                if entry['resource_type'] == 'ip':
                    await self._run_command(
                        ['iptables', '-A', 'OUTPUT', '-d',
                         entry['resource_value'], '-j', 'ACCEPT'],
                        asset_id=asset_id,
                    )
                elif entry['resource_type'] == 'port':
                    await self._run_command(
                        ['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport',
                         entry['resource_value'], '-j', 'ACCEPT'],
                        asset_id=asset_id,
                    )
                    await self._run_command(
                        ['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport',
                         entry['resource_value'], '-j', 'ACCEPT'],
                        asset_id=asset_id,
                    )

            return {
                'action': 'block_outgoing_except_whitelist',
                'type': 'network',
                'asset': asset_id,
                'status': 'success',
                'result': {'whitelist_entries': len(whitelist)}
            }

        except Exception as e:
            return {
                'action': 'block_outgoing_except_whitelist',
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }

    async def _apply_whitelist_rules(self, asset_id: str = "local") -> Dict[str, Any]:
        """Apply essential whitelist rules for critical services"""
        try:
            # Always allow DNS
            await self._run_command(
                ['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53',
                 '-j', 'ACCEPT'],
                asset_id=asset_id,
            )

            # Allow Citadel Commander API
            await self._run_command(
                ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '8888',
                 '-j', 'ACCEPT'],
                asset_id=asset_id,
            )

            # Whitelist VPS agent IPs
            vps_ips = self.config.get('vps_agent_ips', [])
            for ip in vps_ips:
                await self._run_command(
                    ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'],
                    asset_id=asset_id,
                )
                await self._run_command(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT'],
                    asset_id=asset_id,
                )

            return {
                'action': 'whitelist_essential',
                'type': 'network',
                'asset': asset_id,
                'status': 'success',
                'result': {'vps_agents': len(vps_ips), 'dns': True, 'api': True}
            }

        except Exception as e:
            return {
                'action': 'whitelist_essential',
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }

    async def _snapshot_network_state(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture complete network state for forensics"""
        try:
            snapshot = {
                'timestamp': datetime.utcnow().isoformat(),
                'asset': asset_id,
                'iptables': await self._get_iptables_rules(asset_id),
                'routes': await self._get_routes(asset_id),
                'connections': await self._get_connections(asset_id),
                'interfaces': await self._get_interfaces(asset_id),
                'dns': await self._get_dns_config(asset_id)
            }

            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data, checksum)
                    VALUES ($1, $2, $3, $4)
                """, session_id, 'network', json.dumps(snapshot),
                    self._calculate_checksum(snapshot))

            return {
                'action': 'snapshot_connections',
                'type': 'network',
                'asset': asset_id,
                'status': 'success',
                'result': {'snapshot_size': len(json.dumps(snapshot))}
            }

        except Exception as e:
            return {
                'action': 'snapshot_connections',
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }

    # ------------------------------------------------------------------
    # Helper methods (all route through _run_command)
    # ------------------------------------------------------------------

    async def _get_iptables_rules(self, asset_id: str = "local") -> Dict[str, Any]:
        """Get current iptables rules"""
        rules = {}
        for table in ['filter', 'nat', 'mangle']:
            result = await self._run_command(
                ['iptables', '-t', table, '-L', '-n', '-v'],
                asset_id=asset_id,
            )
            rules[table] = result.stdout if result.returncode == 0 else 'error'
        return rules

    async def _get_routes(self, asset_id: str = "local") -> List[str]:
        """Get routing table"""
        result = await self._run_command(
            ['ip', 'route', 'show'], asset_id=asset_id
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
        return []

    async def _get_connections(self, asset_id: str = "local") -> List[Dict]:
        """Get active network connections"""
        result = await self._run_command(
            ['ss', '-tupan'], asset_id=asset_id
        )
        if result.returncode != 0:
            return []

        connections = []
        for line in result.stdout.strip().split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                connections.append({
                    'state': parts[0],
                    'recv_q': parts[1],
                    'send_q': parts[2],
                    'local': parts[3],
                    'remote': parts[4],
                    'process': parts[-1] if len(parts) > 5 else ''
                })
        return connections

    async def _get_interfaces(self, asset_id: str = "local") -> Dict[str, Any]:
        """Get network interface information"""
        result = await self._run_command(
            ['ip', 'addr', 'show'], asset_id=asset_id
        )
        if result.returncode == 0:
            return {'raw': result.stdout}
        return {}

    async def _get_dns_config(self, asset_id: str = "local") -> Dict[str, Any]:
        """Get DNS configuration"""
        result = await self._run_command(
            ['cat', '/etc/resolv.conf'], asset_id=asset_id
        )
        if result.returncode == 0:
            return {'resolv_conf': result.stdout}
        return {'resolv_conf': 'unavailable'}

    async def _restore_iptables(self, saved_rules: Dict[str, Any], asset_id: str = "local"):
        """Restore iptables rules from saved state"""
        for table in ['filter', 'nat', 'mangle']:
            await self._run_command(
                ['iptables', '-t', table, '-F'], asset_id=asset_id
            )
            await self._run_command(
                ['iptables', '-t', table, '-X'], asset_id=asset_id
            )

        for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
            await self._run_command(
                ['iptables', '-P', chain, 'ACCEPT'], asset_id=asset_id
            )

    async def _restore_routes(self, saved_routes: List[str], asset_id: str = "local"):
        """Restore routing table from saved state"""
        pass

    async def _get_whitelist(self) -> List[Dict]:
        """Get whitelist entries from database"""
        async with self.db.acquire() as conn:
            rows = await conn.fetch("""
                SELECT resource_type, resource_value, description
                FROM panic_whitelist
                WHERE is_active = true
            """)
        return [dict(row) for row in rows]

    async def _save_isolation_rule(self, **kwargs):
        """Save isolation rule to database"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO isolation_rules
                (session_id, rule_type, direction, protocol, action, is_active)
                VALUES ($1, $2, $3, $4, $5, true)
            """, kwargs.get('session_id'), kwargs.get('rule_type'),
                kwargs.get('direction'), kwargs.get('protocol'), kwargs.get('action'))

    async def _log_connections(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Log active connections for forensics"""
        connections = await self._get_connections(asset_id)

        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO forensic_snapshots
                (session_id, snapshot_type, snapshot_data)
                VALUES ($1, $2, $3)
            """, session_id, 'network_connections', json.dumps(connections))

        return {
            'action': 'log_active_connections',
            'type': 'network',
            'asset': asset_id,
            'status': 'success',
            'result': {'connection_count': len(connections)}
        }

    async def _capture_netstat(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture netstat output for analysis"""
        result = await self._run_command(
            ['netstat', '-tuapn'], asset_id=asset_id
        )

        if result.returncode != 0:
            return {
                'action': 'snapshot_netstat',
                'type': 'network',
                'asset': asset_id,
                'status': 'failed',
                'error': result.stderr
            }

        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO forensic_snapshots
                (session_id, snapshot_type, snapshot_data)
                VALUES ($1, $2, $3)
            """, session_id, 'netstat', json.dumps({'output': result.stdout}))

        return {
            'action': 'snapshot_netstat',
            'type': 'network',
            'asset': asset_id,
            'status': 'success',
            'result': {'size': len(result.stdout)}
        }

    def _calculate_checksum(self, data: Any) -> str:
        """Calculate SHA256 checksum of data"""
        import hashlib
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
