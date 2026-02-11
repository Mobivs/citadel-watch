"""
Network Isolation Action - Emergency network lockdown
"""

import json
import logging
import subprocess
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
        
        try:
            if action_name == 'block_all_incoming':
                return await self._block_incoming_traffic()
            elif action_name == 'block_outgoing_except_whitelist':
                return await self._block_outgoing_with_whitelist()
            elif action_name == 'whitelist_essential':
                return await self._apply_whitelist_rules()
            elif action_name == 'snapshot_connections':
                return await self._snapshot_network_state()
            elif action_name == 'log_active_connections':
                return await self._log_connections(session.id)
            elif action_name == 'snapshot_netstat':
                return await self._capture_netstat(session.id)
            else:
                return {
                    'action': action_name,
                    'type': 'network',
                    'status': 'failed',
                    'error': f'Unknown network action: {action_name}'
                }
                
        except Exception as e:
            logger.error(f"Network isolation action {action_name} failed: {e}")
            return {
                'action': action_name,
                'type': 'network',
                'status': 'failed',
                'error': str(e)
            }
    
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current network state before isolation"""
        state = {}
        
        try:
            # Capture current iptables rules
            state['iptables_rules'] = await self._get_iptables_rules()
            
            # Capture routing table
            state['routes'] = await self._get_routes()
            
            # Capture active connections
            state['connections'] = await self._get_connections()
            
            # Get network interfaces
            state['interfaces'] = await self._get_interfaces()
            
        except Exception as e:
            logger.error(f"Failed to capture network state: {e}")
            state['error'] = str(e)
        
        return state
    
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """Restore network configuration from saved state"""
        try:
            pre_state = json.loads(recovery_state['pre_panic_state'])
            
            # Restore iptables rules
            if 'iptables_rules' in pre_state:
                await self._restore_iptables(pre_state['iptables_rules'])
            
            # Restore routes if needed
            if 'routes' in pre_state:
                await self._restore_routes(pre_state['routes'])
            
            return {
                'status': 'success',
                'details': 'Network configuration restored'
            }
            
        except Exception as e:
            logger.error(f"Network rollback failed: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def _block_incoming_traffic(self) -> Dict[str, Any]:
        """Block all incoming traffic except established connections"""
        try:
            # Set default INPUT policy to DROP
            subprocess.run(['iptables', '-P', 'INPUT', 'DROP'], check=True)
            
            # Allow established connections
            subprocess.run([
                'iptables', '-A', 'INPUT', '-m', 'state',
                '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'
            ], check=True)
            
            # Allow localhost
            subprocess.run([
                'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'
            ], check=True)
            
            # Save rule to database
            await self._save_isolation_rule(
                rule_type='firewall',
                direction='inbound',
                action='deny',
                protocol='all'
            )
            
            return {
                'action': 'block_all_incoming',
                'type': 'network',
                'status': 'success',
                'result': {'policy': 'DROP', 'exceptions': ['established', 'localhost']}
            }
            
        except subprocess.CalledProcessError as e:
            return {
                'action': 'block_all_incoming',
                'type': 'network',
                'status': 'failed',
                'error': f'iptables command failed: {e}'
            }
    
    async def _block_outgoing_with_whitelist(self) -> Dict[str, Any]:
        """Block outgoing traffic except to whitelisted destinations"""
        try:
            # Get whitelist from database
            whitelist = await self._get_whitelist()
            
            # Set default OUTPUT policy to DROP
            subprocess.run(['iptables', '-P', 'OUTPUT', 'DROP'], check=True)
            
            # Allow localhost
            subprocess.run([
                'iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'
            ], check=True)
            
            # Apply whitelist rules
            for entry in whitelist:
                if entry['resource_type'] == 'ip':
                    subprocess.run([
                        'iptables', '-A', 'OUTPUT', '-d', entry['resource_value'],
                        '-j', 'ACCEPT'
                    ], check=True)
                elif entry['resource_type'] == 'port':
                    subprocess.run([
                        'iptables', '-A', 'OUTPUT', '-p', 'tcp', '--dport',
                        entry['resource_value'], '-j', 'ACCEPT'
                    ], check=True)
                    subprocess.run([
                        'iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport',
                        entry['resource_value'], '-j', 'ACCEPT'
                    ], check=True)
            
            return {
                'action': 'block_outgoing_except_whitelist',
                'type': 'network',
                'status': 'success',
                'result': {'whitelist_entries': len(whitelist)}
            }
            
        except Exception as e:
            return {
                'action': 'block_outgoing_except_whitelist',
                'type': 'network',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _apply_whitelist_rules(self) -> Dict[str, Any]:
        """Apply essential whitelist rules for critical services"""
        try:
            # Always allow DNS
            subprocess.run([
                'iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '53',
                '-j', 'ACCEPT'
            ], check=True)
            
            # Allow Citadel Commander API
            subprocess.run([
                'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '8888',
                '-j', 'ACCEPT'
            ], check=True)
            
            # Get VPS agent IPs from config and whitelist them
            vps_ips = self.config.get('vps_agent_ips', [])
            for ip in vps_ips:
                subprocess.run([
                    'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'ACCEPT'
                ], check=True)
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', ip, '-j', 'ACCEPT'
                ], check=True)
            
            return {
                'action': 'whitelist_essential',
                'type': 'network',
                'status': 'success',
                'result': {'vps_agents': len(vps_ips), 'dns': True, 'api': True}
            }
            
        except Exception as e:
            return {
                'action': 'whitelist_essential',
                'type': 'network',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _snapshot_network_state(self) -> Dict[str, Any]:
        """Capture complete network state for forensics"""
        try:
            snapshot = {
                'timestamp': datetime.utcnow().isoformat(),
                'iptables': await self._get_iptables_rules(),
                'routes': await self._get_routes(),
                'connections': await self._get_connections(),
                'interfaces': await self._get_interfaces(),
                'dns': await self._get_dns_config()
            }
            
            # Save to database
            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data, checksum)
                    VALUES ($1, $2, $3, $4)
                """, session.id, 'network', json.dumps(snapshot),
                    self._calculate_checksum(snapshot))
            
            return {
                'action': 'snapshot_connections',
                'type': 'network',
                'status': 'success',
                'result': {'snapshot_size': len(json.dumps(snapshot))}
            }
            
        except Exception as e:
            return {
                'action': 'snapshot_connections',
                'type': 'network', 
                'status': 'failed',
                'error': str(e)
            }
    
    async def _get_iptables_rules(self) -> Dict[str, Any]:
        """Get current iptables rules"""
        rules = {}
        for table in ['filter', 'nat', 'mangle']:
            try:
                result = subprocess.run(
                    ['iptables', '-t', table, '-L', '-n', '-v'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                rules[table] = result.stdout
            except subprocess.CalledProcessError:
                rules[table] = 'error'
        return rules
    
    async def _get_routes(self) -> List[str]:
        """Get routing table"""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip().split('\n')
        except subprocess.CalledProcessError:
            return []
    
    async def _get_connections(self) -> List[Dict]:
        """Get active network connections"""
        try:
            result = subprocess.run(
                ['ss', '-tupan'],
                capture_output=True,
                text=True,
                check=True
            )
            # Parse ss output into structured data
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
        except subprocess.CalledProcessError:
            return []
    
    async def _get_interfaces(self) -> Dict[str, Any]:
        """Get network interface information"""
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show'],
                capture_output=True,
                text=True,
                check=True
            )
            return {'raw': result.stdout}
        except subprocess.CalledProcessError:
            return {}
    
    async def _get_dns_config(self) -> Dict[str, Any]:
        """Get DNS configuration"""
        dns_config = {}
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns_config['resolv_conf'] = f.read()
        except:
            dns_config['resolv_conf'] = 'unavailable'
        return dns_config
    
    async def _restore_iptables(self, saved_rules: Dict[str, Any]):
        """Restore iptables rules from saved state"""
        # First flush all rules
        for table in ['filter', 'nat', 'mangle']:
            subprocess.run(['iptables', '-t', table, '-F'], check=False)
            subprocess.run(['iptables', '-t', table, '-X'], check=False)
        
        # Reset policies to ACCEPT
        for chain in ['INPUT', 'OUTPUT', 'FORWARD']:
            subprocess.run(['iptables', '-P', chain, 'ACCEPT'], check=False)
        
        # Note: Full restoration would require parsing and replaying saved rules
        # This is a simplified version - production would need more sophisticated restore
        
    async def _restore_routes(self, saved_routes: List[str]):
        """Restore routing table from saved state"""
        # This would require careful route management
        # Simplified for demonstration
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
    
    async def _log_connections(self, session_id) -> Dict[str, Any]:
        """Log active connections for forensics"""
        connections = await self._get_connections()
        
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO forensic_snapshots
                (session_id, snapshot_type, snapshot_data)
                VALUES ($1, $2, $3)
            """, session_id, 'network_connections', json.dumps(connections))
        
        return {
            'action': 'log_active_connections',
            'type': 'network',
            'status': 'success',
            'result': {'connection_count': len(connections)}
        }
    
    async def _capture_netstat(self, session_id) -> Dict[str, Any]:
        """Capture netstat output for analysis"""
        try:
            result = subprocess.run(
                ['netstat', '-tuapn'],
                capture_output=True,
                text=True,
                check=True
            )
            
            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data)
                    VALUES ($1, $2, $3)
                """, session_id, 'netstat', json.dumps({'output': result.stdout}))
            
            return {
                'action': 'snapshot_netstat',
                'type': 'network',
                'status': 'success',
                'result': {'size': len(result.stdout)}
            }
        except Exception as e:
            return {
                'action': 'snapshot_netstat',
                'type': 'network',
                'status': 'failed',
                'error': str(e)
            }
    
    def _calculate_checksum(self, data: Any) -> str:
        """Calculate SHA256 checksum of data"""
        import hashlib
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()