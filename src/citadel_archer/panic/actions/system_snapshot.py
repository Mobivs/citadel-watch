"""
System Snapshot Action - Capture system state for forensics
"""

import json
import logging
import hashlib
import subprocess
import psutil
import os
import gzip
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

from .base import BaseAction

logger = logging.getLogger(__name__)


class SystemSnapshot(BaseAction):
    """
    Captures comprehensive system snapshots for forensic analysis
    Includes processes, network, files, logs, and system configuration
    """
    
    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """Execute system snapshot based on action parameters"""
        action_name = action.name
        params = action.params
        asset_id = params.get('target_asset', 'local')

        try:
            if action_name == 'dump_processes':
                return await self._dump_process_state(session.id, asset_id)
            elif action_name == 'capture_network':
                return await self._capture_network_state(session.id, asset_id)
            elif action_name == 'hash_files':
                return await self._hash_critical_files(session.id, asset_id)
            elif action_name == 'collect_logs':
                return await self._collect_system_logs(session.id, asset_id)
            elif action_name == 'full_snapshot':
                return await self._capture_full_snapshot(session.id, asset_id)
            elif action_name == 'system_info':
                return await self._capture_system_info(session.id, asset_id)
            elif action_name == 'security_audit':
                return await self._security_audit_snapshot(session.id, asset_id)
            else:
                return {
                    'action': action_name,
                    'type': 'forensics',
                    'asset': asset_id,
                    'status': 'failed',
                    'error': f'Unknown forensics action: {action_name}'
                }

        except Exception as e:
            logger.error(f"System snapshot action {action_name} on {asset_id} failed: {e}")
            return {
                'action': action_name,
                'type': 'forensics',
                'asset': asset_id,
                'status': 'failed',
                'error': str(e)
            }
    
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current system state"""
        # For snapshots, we don't need pre-state since we're not modifying anything
        return {'snapshot_requested': action.name}
    
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """No rollback needed for snapshots"""
        return {
            'status': 'success',
            'details': 'No rollback needed for snapshot actions'
        }
    
    async def _dump_process_state(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Dump complete process state"""
        try:
            process_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'processes': [],
                'process_tree': {},
                'cpu_usage': {},
                'memory_usage': {}
            }
            
            # Collect process information
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 
                                             'cmdline', 'create_time', 'cpu_percent',
                                             'memory_info', 'connections', 'open_files']):
                try:
                    proc_info = proc.info
                    
                    # Get additional details
                    proc_dict = {
                        'pid': proc_info['pid'],
                        'ppid': proc_info['ppid'],
                        'name': proc_info['name'],
                        'username': proc_info.get('username'),
                        'cmdline': ' '.join(proc_info.get('cmdline', [])),
                        'create_time': proc_info.get('create_time'),
                        'cpu_percent': proc_info.get('cpu_percent'),
                        'memory_rss': proc_info.get('memory_info').rss if proc_info.get('memory_info') else 0,
                        'connections': len(proc_info.get('connections', [])),
                        'open_files': len(proc_info.get('open_files', []))
                    }
                    
                    process_data['processes'].append(proc_dict)
                    
                    # Build process tree
                    ppid = proc_info['ppid']
                    if ppid not in process_data['process_tree']:
                        process_data['process_tree'][ppid] = []
                    process_data['process_tree'][ppid].append(proc_info['pid'])
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Get system-wide CPU and memory usage
            process_data['cpu_usage'] = {
                'percent': psutil.cpu_percent(interval=1),
                'per_cpu': psutil.cpu_percent(interval=1, percpu=True),
                'load_avg': os.getloadavg()
            }
            
            process_data['memory_usage'] = dict(psutil.virtual_memory()._asdict())
            
            # Save to database
            await self._save_snapshot(
                session_id, 'processes', process_data,
                compress=True
            )
            
            return {
                'action': 'dump_processes',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'process_count': len(process_data['processes']),
                    'cpu_usage': process_data['cpu_usage']['percent'],
                    'memory_usage': process_data['memory_usage']['percent']
                }
            }
            
        except Exception as e:
            return {
                'action': 'dump_processes',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _capture_network_state(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture complete network state"""
        try:
            network_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'interfaces': {},
                'connections': [],
                'listening_ports': [],
                'routing_table': [],
                'arp_cache': [],
                'dns_servers': []
            }
            
            # Network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                network_data['interfaces'][interface] = [
                    {
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    for addr in addrs
                ]
            
            # Network connections
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_info = {
                        'fd': conn.fd,
                        'family': conn.family.name,
                        'type': conn.type.name,
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    network_data['connections'].append(conn_info)
                    
                    # Track listening ports
                    if conn.status == 'LISTEN':
                        network_data['listening_ports'].append({
                            'port': conn.laddr.port,
                            'address': conn.laddr.ip,
                            'pid': conn.pid
                        })
                        
                except (AttributeError, TypeError):
                    continue
            
            # Routing table
            try:
                result = subprocess.run(
                    ['ip', 'route', 'show'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                network_data['routing_table'] = result.stdout.strip().split('\n')
            except:
                pass
            
            # ARP cache
            try:
                result = subprocess.run(
                    ['arp', '-n'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                network_data['arp_cache'] = result.stdout.strip().split('\n')
            except:
                pass
            
            # DNS configuration
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            network_data['dns_servers'].append(line.split()[1])
            except:
                pass
            
            # Save to database
            await self._save_snapshot(
                session_id, 'network', network_data,
                compress=True
            )
            
            return {
                'action': 'capture_network',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'interfaces': len(network_data['interfaces']),
                    'connections': len(network_data['connections']),
                    'listening_ports': len(network_data['listening_ports'])
                }
            }
            
        except Exception as e:
            return {
                'action': 'capture_network',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _hash_critical_files(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Hash critical system files for integrity checking"""
        try:
            critical_paths = self.config.get('critical_paths', [
                '/etc',
                '/usr/bin',
                '/usr/sbin',
                '/root/.ssh',
                '/home'
            ])
            
            file_hashes = {
                'timestamp': datetime.utcnow().isoformat(),
                'files': {},
                'directories': {}
            }
            
            total_files = 0
            
            for base_path in critical_paths:
                if not os.path.exists(base_path):
                    continue
                
                path_obj = Path(base_path)
                
                # Limit depth to avoid huge snapshots
                for file_path in path_obj.glob('**/*'):
                    if total_files > 10000:  # Safety limit
                        break
                    
                    try:
                        if file_path.is_file() and not file_path.is_symlink():
                            # Skip large files
                            if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB
                                continue
                            
                            # Calculate hash
                            file_hash = await self._hash_file(str(file_path))
                            
                            file_hashes['files'][str(file_path)] = {
                                'hash': file_hash,
                                'size': file_path.stat().st_size,
                                'mtime': file_path.stat().st_mtime,
                                'mode': oct(file_path.stat().st_mode)
                            }
                            
                            total_files += 1
                            
                    except (PermissionError, OSError):
                        continue
            
            # Save to database
            await self._save_snapshot(
                session_id, 'files', file_hashes,
                compress=True
            )
            
            return {
                'action': 'hash_files',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'files_hashed': total_files,
                    'paths_scanned': len(critical_paths)
                }
            }
            
        except Exception as e:
            return {
                'action': 'hash_files',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _collect_system_logs(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Collect recent system logs"""
        try:
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'logs': {}
            }
            
            # Define log sources
            log_sources = {
                'syslog': '/var/log/syslog',
                'auth': '/var/log/auth.log',
                'kern': '/var/log/kern.log',
                'dpkg': '/var/log/dpkg.log',
                'apache': '/var/log/apache2/access.log',
                'nginx': '/var/log/nginx/access.log',
                'postgresql': '/var/log/postgresql/postgresql-*.log'
            }
            
            for log_name, log_path in log_sources.items():
                try:
                    # Handle wildcards
                    from glob import glob
                    paths = glob(log_path) if '*' in log_path else [log_path]
                    
                    for path in paths:
                        if os.path.exists(path):
                            # Get last 1000 lines
                            result = subprocess.run(
                                ['tail', '-n', '1000', path],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            
                            if result.returncode == 0:
                                log_data['logs'][log_name] = result.stdout
                                
                except Exception as e:
                    logger.warning(f"Failed to collect {log_name}: {e}")
            
            # Also collect systemd journal
            try:
                result = subprocess.run(
                    ['journalctl', '-n', '1000', '--no-pager'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    log_data['logs']['journal'] = result.stdout
            except:
                pass
            
            # Save to database
            await self._save_snapshot(
                session_id, 'logs', log_data,
                compress=True
            )
            
            return {
                'action': 'collect_logs',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'logs_collected': len(log_data['logs']),
                    'total_size': sum(len(v) for v in log_data['logs'].values())
                }
            }
            
        except Exception as e:
            return {
                'action': 'collect_logs',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _capture_full_snapshot(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture complete system snapshot"""
        try:
            results = []
            
            # Run all snapshot types
            snapshot_actions = [
                self._dump_process_state(session_id),
                self._capture_network_state(session_id),
                self._hash_critical_files(session_id),
                self._collect_system_logs(session_id),
                self._capture_system_info(session_id),
                self._security_audit_snapshot(session_id)
            ]
            
            import asyncio
            results = await asyncio.gather(*snapshot_actions, return_exceptions=True)
            
            # Count successes and failures
            successful = sum(1 for r in results if isinstance(r, dict) and r.get('status') == 'success')
            failed = sum(1 for r in results if isinstance(r, Exception) or (isinstance(r, dict) and r.get('status') == 'failed'))
            
            return {
                'action': 'full_snapshot',
                'type': 'forensics',
                'status': 'success' if failed == 0 else 'partial',
                'result': {
                    'snapshots_taken': successful,
                    'failed': failed,
                    'session_id': str(session_id)
                }
            }
            
        except Exception as e:
            return {
                'action': 'full_snapshot',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _capture_system_info(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture system information"""
        try:
            import platform
            
            system_info = {
                'timestamp': datetime.utcnow().isoformat(),
                'platform': {
                    'system': platform.system(),
                    'node': platform.node(),
                    'release': platform.release(),
                    'version': platform.version(),
                    'machine': platform.machine(),
                    'processor': platform.processor()
                },
                'python': {
                    'version': platform.python_version(),
                    'implementation': platform.python_implementation()
                },
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'users': [dict(u._asdict()) for u in psutil.users()],
                'disk_partitions': [dict(p._asdict()) for p in psutil.disk_partitions()],
                'disk_usage': {}
            }
            
            # Disk usage for each partition
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    system_info['disk_usage'][partition.mountpoint] = dict(usage._asdict())
                except:
                    continue
            
            # Environment variables (filtered)
            safe_env_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'LANG', 'LC_ALL']
            system_info['environment'] = {
                k: os.environ.get(k) for k in safe_env_vars if k in os.environ
            }
            
            # Save to database
            await self._save_snapshot(
                session_id, 'system', system_info,
                compress=False
            )
            
            return {
                'action': 'system_info',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'platform': system_info['platform']['system'],
                    'users': len(system_info['users']),
                    'partitions': len(system_info['disk_partitions'])
                }
            }
            
        except Exception as e:
            return {
                'action': 'system_info',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _security_audit_snapshot(self, session_id, asset_id: str = "local") -> Dict[str, Any]:
        """Capture security audit information"""
        try:
            audit_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'failed_logins': [],
                'sudo_usage': [],
                'ssh_logins': [],
                'firewall_rules': {},
                'suid_files': [],
                'world_writable': []
            }
            
            # Recent failed login attempts
            try:
                result = subprocess.run(
                    ['grep', 'authentication failure', '/var/log/auth.log'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    audit_data['failed_logins'] = result.stdout.strip().split('\n')[-100:]  # Last 100
            except:
                pass
            
            # Recent sudo usage
            try:
                result = subprocess.run(
                    ['grep', 'sudo:', '/var/log/auth.log'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    audit_data['sudo_usage'] = result.stdout.strip().split('\n')[-100:]
            except:
                pass
            
            # SSH login attempts
            try:
                result = subprocess.run(
                    ['grep', 'sshd', '/var/log/auth.log'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    audit_data['ssh_logins'] = result.stdout.strip().split('\n')[-100:]
            except:
                pass
            
            # Current firewall rules
            try:
                for table in ['filter', 'nat', 'mangle']:
                    result = subprocess.run(
                        ['iptables', '-t', table, '-L', '-n'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        audit_data['firewall_rules'][table] = result.stdout
            except:
                pass
            
            # Find SUID files (limited scope)
            try:
                result = subprocess.run(
                    ['find', '/usr/bin', '/usr/sbin', '-perm', '-4000', '-type', 'f'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    audit_data['suid_files'] = result.stdout.strip().split('\n')
            except:
                pass
            
            # Save to database
            await self._save_snapshot(
                session_id, 'security', audit_data,
                compress=True
            )
            
            return {
                'action': 'security_audit',
                'type': 'forensics',
                'status': 'success',
                'result': {
                    'failed_logins': len(audit_data['failed_logins']),
                    'sudo_events': len(audit_data['sudo_usage']),
                    'suid_files': len(audit_data['suid_files'])
                }
            }
            
        except Exception as e:
            return {
                'action': 'security_audit',
                'type': 'forensics',
                'status': 'failed',
                'error': str(e)
            }
    
    # Helper methods
    
    async def _hash_file(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except:
            return 'error'
    
    async def _save_snapshot(self, session_id, snapshot_type: str, data: Dict,
                            compress: bool = False) -> None:
        """Save snapshot to database and optionally to file"""
        try:
            # Convert to JSON
            json_data = json.dumps(data, default=str)
            
            # Calculate checksum
            checksum = hashlib.sha256(json_data.encode()).hexdigest()
            
            # Optionally compress
            if compress:
                json_data = gzip.compress(json_data.encode()).decode('latin-1')
                compression = 'gzip'
            else:
                compression = None
            
            # Save to database
            async with self.db.acquire() as conn:
                snapshot_id = await conn.fetchval("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data, checksum, compression)
                    VALUES ($1, $2, $3, $4, $5)
                    RETURNING id
                """, session_id, snapshot_type, json_data, checksum, compression)
            
            # Also save to file for large snapshots
            if len(json_data) > 1024 * 1024:  # > 1MB
                file_path = f"/var/backups/panic/snapshots/{session_id}/{snapshot_type}_{snapshot_id}.json.gz"
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                
                with gzip.open(file_path, 'wt') as f:
                    f.write(json.dumps(data, default=str))
                
                # Update database with file path
                async with self.db.acquire() as conn:
                    await conn.execute("""
                        UPDATE forensic_snapshots
                        SET file_path = $1, file_size_bytes = $2
                        WHERE id = $3
                    """, file_path, os.path.getsize(file_path), snapshot_id)
                    
        except Exception as e:
            logger.error(f"Failed to save snapshot: {e}")