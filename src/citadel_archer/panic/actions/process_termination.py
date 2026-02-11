"""
Process Termination Action - Kill suspicious processes
"""

import json
import logging
import psutil
import subprocess
from typing import Dict, Any, List
from datetime import datetime

from .base import BaseAction

logger = logging.getLogger(__name__)


class ProcessTermination(BaseAction):
    """
    Handles termination of suspicious processes during panic mode
    Identifies and kills processes based on threat signatures
    """
    
    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """Execute process termination based on action parameters"""
        action_name = action.name
        params = action.params
        
        try:
            if action_name == 'identify_threats':
                return await self._identify_threat_processes(session.id)
            elif action_name == 'capture_memory':
                return await self._capture_process_memory(session.id)
            elif action_name == 'terminate_processes':
                return await self._terminate_suspicious_processes(session.id)
            elif action_name == 'kill_by_signature':
                return await self._kill_by_signature(params.get('signatures', []))
            elif action_name == 'kill_unauthorized_network':
                return await self._kill_unauthorized_network_processes()
            elif action_name == 'restart_services':
                return await self._restart_critical_services()
            else:
                return {
                    'action': action_name,
                    'type': 'processes',
                    'status': 'failed',
                    'error': f'Unknown process action: {action_name}'
                }
                
        except Exception as e:
            logger.error(f"Process termination action {action_name} failed: {e}")
            return {
                'action': action_name,
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current process state before termination"""
        state = {}
        
        try:
            # Get process tree
            state['processes'] = await self._get_process_tree()
            
            # Get network connections per process
            state['connections'] = await self._get_process_connections()
            
            # Get critical service status
            state['services'] = await self._get_service_status()
            
        except Exception as e:
            logger.error(f"Failed to capture process state: {e}")
            state['error'] = str(e)
        
        return state
    
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """Restart terminated processes/services if needed"""
        try:
            pre_state = json.loads(recovery_state['pre_panic_state'])
            
            # Restart critical services that were stopped
            if 'services' in pre_state:
                await self._restart_stopped_services(pre_state['services'])
            
            return {
                'status': 'success',
                'details': 'Critical services restarted'
            }
            
        except Exception as e:
            logger.error(f"Process rollback failed: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def _identify_threat_processes(self, session_id) -> Dict[str, Any]:
        """Identify processes that match threat signatures"""
        try:
            suspicious_processes = []
            threat_signatures = await self._get_threat_signatures()
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'connections']):
                try:
                    proc_info = proc.info
                    
                    # Check against threat signatures
                    for signature in threat_signatures:
                        if await self._matches_signature(proc_info, signature):
                            suspicious_processes.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'cmdline': ' '.join(proc_info.get('cmdline', [])),
                                'signature': signature['name'],
                                'threat_level': signature.get('level', 'medium')
                            })
                            break
                    
                    # Check for suspicious behavior patterns
                    if await self._is_suspicious_behavior(proc_info):
                        suspicious_processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cmdline': ' '.join(proc_info.get('cmdline', [])),
                            'signature': 'behavior_analysis',
                            'threat_level': 'low'
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Save to database for forensics
            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data)
                    VALUES ($1, $2, $3)
                """, session_id, 'suspicious_processes',
                    json.dumps(suspicious_processes))
            
            return {
                'action': 'identify_threats',
                'type': 'processes',
                'status': 'success',
                'result': {
                    'suspicious_count': len(suspicious_processes),
                    'high_threat': len([p for p in suspicious_processes if p['threat_level'] == 'high'])
                }
            }
            
        except Exception as e:
            return {
                'action': 'identify_threats',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _capture_process_memory(self, session_id) -> Dict[str, Any]:
        """Capture memory dump of suspicious processes"""
        try:
            captured_count = 0
            dump_path = f"/var/backups/panic/memory/{session_id}"
            
            # Create dump directory
            import os
            os.makedirs(dump_path, mode=0o700, exist_ok=True)
            
            # Get suspicious processes from database
            async with self.db.acquire() as conn:
                snapshot = await conn.fetchval("""
                    SELECT snapshot_data FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'suspicious_processes'
                    ORDER BY captured_at DESC LIMIT 1
                """, session_id)
            
            if snapshot:
                suspicious = json.loads(snapshot)
                
                for proc in suspicious[:5]:  # Limit to top 5 to avoid filling disk
                    try:
                        # Use gcore to dump process memory
                        dump_file = f"{dump_path}/process_{proc['pid']}.core"
                        result = subprocess.run(
                            ['gcore', '-o', dump_file, str(proc['pid'])],
                            capture_output=True,
                            timeout=30
                        )
                        
                        if result.returncode == 0:
                            captured_count += 1
                            
                            # Compress the dump
                            subprocess.run(
                                ['gzip', dump_file],
                                check=False
                            )
                    except Exception as e:
                        logger.warning(f"Failed to dump process {proc['pid']}: {e}")
            
            return {
                'action': 'capture_memory',
                'type': 'processes',
                'status': 'success',
                'result': {
                    'captured': captured_count,
                    'path': dump_path
                }
            }
            
        except Exception as e:
            return {
                'action': 'capture_memory',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _terminate_suspicious_processes(self, session_id) -> Dict[str, Any]:
        """Terminate processes identified as threats"""
        try:
            terminated = []
            failed = []
            
            # Get suspicious processes
            async with self.db.acquire() as conn:
                snapshot = await conn.fetchval("""
                    SELECT snapshot_data FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'suspicious_processes'
                    ORDER BY captured_at DESC LIMIT 1
                """, session_id)
            
            if snapshot:
                suspicious = json.loads(snapshot)
                
                # Sort by threat level (high first)
                suspicious.sort(key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['threat_level'], 3))
                
                for proc in suspicious:
                    if proc['threat_level'] in ['high', 'medium']:
                        try:
                            # Check if process is whitelisted
                            if await self._is_whitelisted_process(proc['name']):
                                logger.info(f"Skipping whitelisted process: {proc['name']}")
                                continue
                            
                            # Terminate the process
                            p = psutil.Process(proc['pid'])
                            p.terminate()
                            
                            # Wait briefly for graceful termination
                            try:
                                p.wait(timeout=3)
                            except psutil.TimeoutExpired:
                                # Force kill if still running
                                p.kill()
                            
                            terminated.append({
                                'pid': proc['pid'],
                                'name': proc['name'],
                                'method': 'killed'
                            })
                            
                        except psutil.NoSuchProcess:
                            # Process already gone
                            pass
                        except Exception as e:
                            failed.append({
                                'pid': proc['pid'],
                                'name': proc['name'],
                                'error': str(e)
                            })
            
            return {
                'action': 'terminate_processes',
                'type': 'processes',
                'status': 'success' if not failed else 'partial',
                'result': {
                    'terminated': len(terminated),
                    'failed': len(failed),
                    'details': {
                        'terminated': terminated[:10],  # Limit details
                        'failed': failed
                    }
                }
            }
            
        except Exception as e:
            return {
                'action': 'terminate_processes',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _kill_by_signature(self, signatures: List[str]) -> Dict[str, Any]:
        """Kill processes matching specific signatures"""
        try:
            killed = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    for signature in signatures:
                        if (signature in proc_info.get('name', '') or
                            signature in ' '.join(proc_info.get('cmdline', []))):
                            
                            proc.kill()
                            killed.append({
                                'pid': proc_info['pid'],
                                'name': proc_info['name'],
                                'signature': signature
                            })
                            break
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'action': 'kill_by_signature',
                'type': 'processes',
                'status': 'success',
                'result': {'killed': len(killed)}
            }
            
        except Exception as e:
            return {
                'action': 'kill_by_signature',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _kill_unauthorized_network_processes(self) -> Dict[str, Any]:
        """Kill processes with unauthorized network connections"""
        try:
            killed = []
            whitelist_ports = self.config.get('whitelist_ports', [22, 80, 443, 8888])
            
            for proc in psutil.process_iter(['pid', 'name', 'connections']):
                try:
                    proc_info = proc.info
                    connections = proc_info.get('connections', [])
                    
                    for conn in connections:
                        if conn.status == 'ESTABLISHED':
                            # Check if connection is to unauthorized port
                            if (conn.laddr.port not in whitelist_ports and
                                conn.raddr and conn.raddr.port not in whitelist_ports):
                                
                                # Kill the process
                                proc.kill()
                                killed.append({
                                    'pid': proc_info['pid'],
                                    'name': proc_info['name'],
                                    'connection': f"{conn.raddr.ip}:{conn.raddr.port}"
                                })
                                break
                                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'action': 'kill_unauthorized_network',
                'type': 'processes',
                'status': 'success',
                'result': {'killed': len(killed)}
            }
            
        except Exception as e:
            return {
                'action': 'kill_unauthorized_network',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _restart_critical_services(self) -> Dict[str, Any]:
        """Restart critical services after cleanup"""
        try:
            restarted = []
            critical_services = self.config.get('critical_services', [
                'postgresql', 'nginx', 'ssh'
            ])
            
            for service in critical_services:
                try:
                    # Check if service is running
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.stdout.strip() != 'active':
                        # Restart the service
                        subprocess.run(
                            ['systemctl', 'restart', service],
                            check=True
                        )
                        restarted.append(service)
                        
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to restart service {service}: {e}")
            
            return {
                'action': 'restart_services',
                'type': 'processes',
                'status': 'success',
                'result': {'restarted': restarted}
            }
            
        except Exception as e:
            return {
                'action': 'restart_services',
                'type': 'processes',
                'status': 'failed',
                'error': str(e)
            }
    
    # Helper methods
    
    async def _get_threat_signatures(self) -> List[Dict]:
        """Get threat signatures for process matching"""
        # In production, these would come from threat intelligence feeds
        return [
            {
                'name': 'cryptominer',
                'patterns': ['xmrig', 'minergate', 'cpuminer', 'ethminer'],
                'level': 'high'
            },
            {
                'name': 'backdoor',
                'patterns': ['nc -l', 'reverse', 'shell', '/dev/tcp/'],
                'level': 'high'
            },
            {
                'name': 'scanner',
                'patterns': ['nmap', 'masscan', 'zmap'],
                'level': 'medium'
            },
            {
                'name': 'suspicious_network',
                'patterns': ['tor', 'torify', 'proxychains'],
                'level': 'medium'
            }
        ]
    
    async def _matches_signature(self, proc_info: Dict, signature: Dict) -> bool:
        """Check if process matches threat signature"""
        proc_name = proc_info.get('name', '').lower()
        cmdline = ' '.join(proc_info.get('cmdline', [])).lower()
        
        for pattern in signature.get('patterns', []):
            pattern_lower = pattern.lower()
            if pattern_lower in proc_name or pattern_lower in cmdline:
                return True
        
        return False
    
    async def _is_suspicious_behavior(self, proc_info: Dict) -> bool:
        """Check for suspicious process behavior"""
        # Check for hidden processes (name doesn't match cmdline)
        if proc_info.get('cmdline'):
            cmdline = ' '.join(proc_info['cmdline'])
            if proc_info['name'] not in cmdline and '/usr/bin/' not in cmdline:
                return True
        
        # Check for processes with many connections
        connections = proc_info.get('connections', [])
        if len(connections) > 50:  # Arbitrary threshold
            return True
        
        # Check for processes running from /tmp or /dev/shm
        if proc_info.get('cmdline'):
            suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/']
            cmdline = ' '.join(proc_info['cmdline'])
            if any(path in cmdline for path in suspicious_paths):
                return True
        
        return False
    
    async def _is_whitelisted_process(self, process_name: str) -> bool:
        """Check if process is whitelisted"""
        async with self.db.acquire() as conn:
            count = await conn.fetchval("""
                SELECT COUNT(*) FROM panic_whitelist
                WHERE resource_type = 'process'
                AND resource_value = $1
                AND is_active = true
            """, process_name)
        
        return count > 0
    
    async def _get_process_tree(self) -> List[Dict]:
        """Get complete process tree"""
        processes = []
        
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cmdline']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return processes
    
    async def _get_process_connections(self) -> Dict[int, List]:
        """Get network connections per process"""
        connections = {}
        
        for proc in psutil.process_iter(['pid', 'connections']):
            try:
                proc_info = proc.info
                if proc_info.get('connections'):
                    connections[proc_info['pid']] = [
                        {
                            'local': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                            'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                            'status': c.status
                        }
                        for c in proc_info['connections']
                    ]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return connections
    
    async def _get_service_status(self) -> Dict[str, str]:
        """Get status of critical services"""
        services = {}
        critical_services = self.config.get('critical_services', [
            'postgresql', 'nginx', 'ssh', 'citadel_commander'
        ])
        
        for service in critical_services:
            try:
                result = subprocess.run(
                    ['systemctl', 'is-active', service],
                    capture_output=True,
                    text=True
                )
                services[service] = result.stdout.strip()
            except:
                services[service] = 'unknown'
        
        return services
    
    async def _restart_stopped_services(self, services: Dict[str, str]):
        """Restart services that were running before panic"""
        for service, status in services.items():
            if status == 'active':
                try:
                    # Check current status
                    result = subprocess.run(
                        ['systemctl', 'is-active', service],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.stdout.strip() != 'active':
                        subprocess.run(
                            ['systemctl', 'start', service],
                            check=True
                        )
                        logger.info(f"Restarted service: {service}")
                except Exception as e:
                    logger.error(f"Failed to restart {service}: {e}")