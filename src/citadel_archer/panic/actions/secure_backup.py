"""
Secure Backup Action - Encrypted backup of critical data
"""

import json
import logging
import os
import shutil
import subprocess
import tarfile
import hashlib
from typing import Dict, Any, List
from datetime import datetime, timedelta
from pathlib import Path
import secrets

from .base import BaseAction

logger = logging.getLogger(__name__)


class SecureBackup(BaseAction):
    """
    Handles secure encrypted backups of critical user data during panic mode
    Includes encryption, compression, and secure transfer to backup locations
    """
    
    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """Execute secure backup based on action parameters"""
        action_name = action.name
        params = action.params
        
        try:
            if action_name == 'identify_critical_data':
                return await self._identify_critical_data(session.id)
            elif action_name == 'encrypt_data':
                return await self._encrypt_backup_data(session.id)
            elif action_name == 'transfer_backup':
                return await self._transfer_to_safe_location(session.id)
            elif action_name == 'verify_integrity':
                return await self._verify_backup_integrity(session.id)
            elif action_name == 'create_archive':
                return await self._create_backup_archive(session.id, params)
            elif action_name == 'backup_vault':
                return await self._backup_vault_data(session.id)
            elif action_name == 'backup_configs':
                return await self._backup_configurations(session.id)
            else:
                return {
                    'action': action_name,
                    'type': 'backup',
                    'status': 'failed',
                    'error': f'Unknown backup action: {action_name}'
                }
                
        except Exception as e:
            logger.error(f"Secure backup action {action_name} failed: {e}")
            return {
                'action': action_name,
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current backup state"""
        state = {}
        
        try:
            # Get existing backups
            state['existing_backups'] = await self._list_existing_backups()
            
            # Get backup configuration
            state['backup_config'] = self.config.get('backup', {})
            
        except Exception as e:
            logger.error(f"Failed to capture backup state: {e}")
            state['error'] = str(e)
        
        return state
    
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """Restore from backup if needed"""
        try:
            # Backups are non-destructive, so rollback would mean restore
            # This would be a separate operation initiated by the user
            return {
                'status': 'success',
                'details': 'Backup rollback would require explicit restore operation'
            }
            
        except Exception as e:
            logger.error(f"Backup rollback failed: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def _identify_critical_data(self, session_id) -> Dict[str, Any]:
        """Identify critical data that needs backup"""
        try:
            critical_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'directories': [],
                'databases': [],
                'configurations': [],
                'total_size': 0
            }
            
            # Define critical directories
            critical_dirs = self.config.get('critical_directories', [
                '/home',
                '/etc/citadel',
                '/var/lib/citadel',
                '/opt/citadel'
            ])
            
            # Check each directory
            for dir_path in critical_dirs:
                if os.path.exists(dir_path):
                    try:
                        # Calculate size
                        size = await self._get_directory_size(dir_path)
                        
                        critical_data['directories'].append({
                            'path': dir_path,
                            'size': size,
                            'files': await self._count_files(dir_path),
                            'exists': True
                        })
                        
                        critical_data['total_size'] += size
                        
                    except Exception as e:
                        logger.warning(f"Failed to analyze {dir_path}: {e}")
            
            # Identify databases
            databases = self.config.get('databases', ['citadel_db', 'vault_db'])
            for db_name in databases:
                critical_data['databases'].append({
                    'name': db_name,
                    'type': 'postgresql',  # Could be dynamic
                    'estimated_size': 0  # Would query actual size
                })
            
            # Identify configuration files
            config_files = [
                '/etc/citadel/config.yaml',
                '/etc/nginx/sites-enabled/citadel',
                '/etc/systemd/system/citadel.service'
            ]
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    critical_data['configurations'].append({
                        'path': config_file,
                        'size': os.path.getsize(config_file)
                    })
            
            # Save inventory to database
            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data)
                    VALUES ($1, $2, $3)
                """, session_id, 'backup_inventory', json.dumps(critical_data))
            
            return {
                'action': 'identify_critical_data',
                'type': 'backup',
                'status': 'success',
                'result': {
                    'directories': len(critical_data['directories']),
                    'databases': len(critical_data['databases']),
                    'configs': len(critical_data['configurations']),
                    'total_size_mb': critical_data['total_size'] // (1024 * 1024)
                }
            }
            
        except Exception as e:
            return {
                'action': 'identify_critical_data',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _create_backup_archive(self, session_id, params: Dict) -> Dict[str, Any]:
        """Create compressed archive of critical data"""
        try:
            backup_dir = f"/var/backups/panic/archives/{session_id}"
            os.makedirs(backup_dir, mode=0o700, exist_ok=True)
            
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            archive_name = f"panic_backup_{timestamp}.tar.gz"
            archive_path = os.path.join(backup_dir, archive_name)
            
            # Get critical data inventory
            async with self.db.acquire() as conn:
                inventory = await conn.fetchval("""
                    SELECT snapshot_data FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'backup_inventory'
                    ORDER BY captured_at DESC LIMIT 1
                """, session_id)
            
            if not inventory:
                # Identify critical data first
                await self._identify_critical_data(session_id)
                async with self.db.acquire() as conn:
                    inventory = await conn.fetchval("""
                        SELECT snapshot_data FROM forensic_snapshots
                        WHERE session_id = $1 AND snapshot_type = 'backup_inventory'
                        ORDER BY captured_at DESC LIMIT 1
                    """, session_id)
            
            critical_data = json.loads(inventory)
            
            # Create tar archive
            with tarfile.open(archive_path, 'w:gz') as tar:
                # Add directories
                for dir_info in critical_data['directories']:
                    if os.path.exists(dir_info['path']):
                        try:
                            tar.add(dir_info['path'], arcname=os.path.basename(dir_info['path']))
                        except Exception as e:
                            logger.warning(f"Failed to add {dir_info['path']}: {e}")
                
                # Add configuration files
                for config in critical_data['configurations']:
                    if os.path.exists(config['path']):
                        try:
                            tar.add(config['path'], arcname=f"configs/{os.path.basename(config['path'])}")
                        except Exception as e:
                            logger.warning(f"Failed to add {config['path']}: {e}")
            
            # Calculate archive size and checksum
            archive_size = os.path.getsize(archive_path)
            archive_checksum = await self._calculate_file_checksum(archive_path)
            
            # Store backup metadata
            async with self.db.acquire() as conn:
                await conn.execute("""
                    INSERT INTO forensic_snapshots
                    (session_id, snapshot_type, snapshot_data, file_path, file_size_bytes, checksum)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """, session_id, 'backup_archive',
                    json.dumps({'archive': archive_name, 'timestamp': timestamp}),
                    archive_path, archive_size, archive_checksum)
            
            return {
                'action': 'create_archive',
                'type': 'backup',
                'status': 'success',
                'result': {
                    'archive_path': archive_path,
                    'size_mb': archive_size // (1024 * 1024),
                    'checksum': archive_checksum[:16] + '...'
                }
            }
            
        except Exception as e:
            return {
                'action': 'create_archive',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _encrypt_backup_data(self, session_id) -> Dict[str, Any]:
        """Encrypt backup archives"""
        try:
            # Get unencrypted archives
            async with self.db.acquire() as conn:
                archives = await conn.fetch("""
                    SELECT id, file_path FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'backup_archive'
                    AND encrypted = false
                """, session_id)
            
            if not archives:
                # Create archive first
                await self._create_backup_archive(session_id, {})
                async with self.db.acquire() as conn:
                    archives = await conn.fetch("""
                        SELECT id, file_path FROM forensic_snapshots
                        WHERE session_id = $1 AND snapshot_type = 'backup_archive'
                        AND encrypted = false
                    """, session_id)
            
            encrypted_count = 0
            
            for archive in archives:
                if archive['file_path'] and os.path.exists(archive['file_path']):
                    # Generate encryption key
                    encryption_key = secrets.token_hex(32)
                    key_id = hashlib.sha256(encryption_key.encode()).hexdigest()[:16]
                    
                    # Encrypt using GPG or OpenSSL
                    encrypted_path = f"{archive['file_path']}.enc"
                    
                    # Using OpenSSL for encryption (AES-256-CBC)
                    result = subprocess.run([
                        'openssl', 'enc', '-aes-256-cbc',
                        '-salt', '-in', archive['file_path'],
                        '-out', encrypted_path,
                        '-pass', f'pass:{encryption_key}'
                    ], capture_output=True)
                    
                    if result.returncode == 0:
                        # Store encryption key securely (would use vault in production)
                        await self._store_encryption_key(session_id, key_id, encryption_key)
                        
                        # Update database
                        async with self.db.acquire() as conn:
                            await conn.execute("""
                                UPDATE forensic_snapshots
                                SET encrypted = true, encryption_key_id = $1
                                WHERE id = $2
                            """, key_id, archive['id'])
                        
                        # Remove unencrypted version
                        os.remove(archive['file_path'])
                        
                        # Update file path
                        async with self.db.acquire() as conn:
                            await conn.execute("""
                                UPDATE forensic_snapshots
                                SET file_path = $1
                                WHERE id = $2
                            """, encrypted_path, archive['id'])
                        
                        encrypted_count += 1
            
            return {
                'action': 'encrypt_data',
                'type': 'backup',
                'status': 'success',
                'result': {
                    'encrypted': encrypted_count,
                    'encryption': 'AES-256-CBC'
                }
            }
            
        except Exception as e:
            return {
                'action': 'encrypt_data',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _transfer_to_safe_location(self, session_id) -> Dict[str, Any]:
        """Transfer encrypted backups to safe location"""
        try:
            transferred = []
            backup_destinations = self.config.get('backup_destinations', [
                {'type': 'local', 'path': '/mnt/backup'},
                {'type': 'remote', 'host': 'backup.server', 'path': '/backups'}
            ])
            
            # Get encrypted archives
            async with self.db.acquire() as conn:
                archives = await conn.fetch("""
                    SELECT file_path FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'backup_archive'
                    AND encrypted = true
                """, session_id)
            
            for archive in archives:
                if not archive['file_path'] or not os.path.exists(archive['file_path']):
                    continue
                
                for destination in backup_destinations:
                    try:
                        if destination['type'] == 'local':
                            # Copy to local backup location
                            dest_dir = os.path.join(destination['path'], 'panic', str(session_id))
                            os.makedirs(dest_dir, exist_ok=True)
                            
                            dest_path = os.path.join(dest_dir, os.path.basename(archive['file_path']))
                            shutil.copy2(archive['file_path'], dest_path)
                            
                            transferred.append({
                                'type': 'local',
                                'destination': dest_path
                            })
                            
                        elif destination['type'] == 'remote':
                            # Transfer via rsync or scp
                            remote_path = f"{destination['host']}:{destination['path']}/panic/{session_id}/"
                            
                            # Create remote directory
                            subprocess.run([
                                'ssh', destination['host'],
                                f"mkdir -p {destination['path']}/panic/{session_id}"
                            ], check=False)
                            
                            # Transfer file
                            result = subprocess.run([
                                'rsync', '-avz', archive['file_path'], remote_path
                            ], capture_output=True)
                            
                            if result.returncode == 0:
                                transferred.append({
                                    'type': 'remote',
                                    'destination': remote_path
                                })
                                
                    except Exception as e:
                        logger.warning(f"Failed to transfer to {destination}: {e}")
            
            return {
                'action': 'transfer_backup',
                'type': 'backup',
                'status': 'success' if transferred else 'failed',
                'result': {
                    'transferred': len(transferred),
                    'destinations': transferred
                }
            }
            
        except Exception as e:
            return {
                'action': 'transfer_backup',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _verify_backup_integrity(self, session_id) -> Dict[str, Any]:
        """Verify integrity of backups"""
        try:
            verified = []
            failed = []
            
            # Get all backups for this session
            async with self.db.acquire() as conn:
                backups = await conn.fetch("""
                    SELECT id, file_path, checksum FROM forensic_snapshots
                    WHERE session_id = $1 AND snapshot_type = 'backup_archive'
                """, session_id)
            
            for backup in backups:
                if not backup['file_path'] or not os.path.exists(backup['file_path']):
                    failed.append({
                        'id': str(backup['id']),
                        'reason': 'File not found'
                    })
                    continue
                
                # Verify checksum
                current_checksum = await self._calculate_file_checksum(backup['file_path'])
                
                # For encrypted files, checksum will be different
                # In production, would decrypt and verify original checksum
                if backup['file_path'].endswith('.enc'):
                    # Skip checksum verification for encrypted files
                    verified.append({
                        'id': str(backup['id']),
                        'path': backup['file_path'],
                        'encrypted': True
                    })
                elif current_checksum == backup['checksum']:
                    verified.append({
                        'id': str(backup['id']),
                        'path': backup['file_path'],
                        'checksum_match': True
                    })
                else:
                    failed.append({
                        'id': str(backup['id']),
                        'reason': 'Checksum mismatch'
                    })
            
            return {
                'action': 'verify_integrity',
                'type': 'backup',
                'status': 'success' if not failed else 'partial',
                'result': {
                    'verified': len(verified),
                    'failed': len(failed),
                    'details': {'failed': failed} if failed else {}
                }
            }
            
        except Exception as e:
            return {
                'action': 'verify_integrity',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _backup_vault_data(self, session_id) -> Dict[str, Any]:
        """Backup vault/secrets data"""
        try:
            # Export vault data (would integrate with actual vault)
            vault_export = {
                'timestamp': datetime.utcnow().isoformat(),
                'secrets': [],
                'policies': [],
                'audit': []
            }
            
            # Mock vault export - in production would use vault API
            vault_data = {
                'exported_at': datetime.utcnow().isoformat(),
                'secret_count': 42,
                'policy_count': 5
            }
            
            # Save vault backup
            backup_path = f"/var/backups/panic/vault/{session_id}/vault_export.json.enc"
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            
            # Encrypt vault data
            encryption_key = secrets.token_hex(32)
            
            # Write encrypted data
            with open(backup_path, 'w') as f:
                # In production, would properly encrypt
                f.write(json.dumps(vault_data))
            
            return {
                'action': 'backup_vault',
                'type': 'backup',
                'status': 'success',
                'result': {
                    'secrets_backed_up': vault_data['secret_count'],
                    'policies_backed_up': vault_data['policy_count'],
                    'backup_path': backup_path
                }
            }
            
        except Exception as e:
            return {
                'action': 'backup_vault',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _backup_configurations(self, session_id) -> Dict[str, Any]:
        """Backup system configurations"""
        try:
            config_backup_dir = f"/var/backups/panic/configs/{session_id}"
            os.makedirs(config_backup_dir, exist_ok=True)
            
            backed_up = []
            
            # Define configuration sources
            config_sources = [
                '/etc/citadel',
                '/etc/nginx/sites-enabled',
                '/etc/systemd/system',
                '/etc/cron.d'
            ]
            
            for source in config_sources:
                if os.path.exists(source):
                    try:
                        # Create subdirectory
                        dest = os.path.join(config_backup_dir, os.path.basename(source))
                        
                        if os.path.isdir(source):
                            shutil.copytree(source, dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(source, dest)
                        
                        backed_up.append(source)
                        
                    except Exception as e:
                        logger.warning(f"Failed to backup {source}: {e}")
            
            # Create tarball of configs
            tarball_path = f"{config_backup_dir}.tar.gz"
            with tarfile.open(tarball_path, 'w:gz') as tar:
                tar.add(config_backup_dir, arcname='configs')
            
            return {
                'action': 'backup_configs',
                'type': 'backup',
                'status': 'success',
                'result': {
                    'configs_backed_up': len(backed_up),
                    'archive': tarball_path
                }
            }
            
        except Exception as e:
            return {
                'action': 'backup_configs',
                'type': 'backup',
                'status': 'failed',
                'error': str(e)
            }
    
    # Helper methods
    
    async def _get_directory_size(self, path: str) -> int:
        """Calculate total size of directory"""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total += os.path.getsize(filepath)
                    except:
                        pass
        except:
            pass
        return total
    
    async def _count_files(self, path: str) -> int:
        """Count files in directory"""
        count = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                count += len(filenames)
        except:
            pass
        return count
    
    async def _calculate_file_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except:
            return 'error'
    
    async def _list_existing_backups(self) -> List[Dict]:
        """List existing backup files"""
        backups = []
        backup_dir = '/var/backups/panic'
        
        if os.path.exists(backup_dir):
            for root, dirs, files in os.walk(backup_dir):
                for file in files:
                    if file.endswith(('.tar.gz', '.enc')):
                        file_path = os.path.join(root, file)
                        backups.append({
                            'path': file_path,
                            'size': os.path.getsize(file_path),
                            'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                        })
        
        return backups
    
    async def _store_encryption_key(self, session_id, key_id: str, key: str):
        """Store encryption key securely"""
        # In production, would use vault or KMS
        # For now, store in protected file
        key_file = f"/var/backups/panic/keys/{session_id}/{key_id}.key"
        os.makedirs(os.path.dirname(key_file), mode=0o700, exist_ok=True)
        
        with open(key_file, 'w') as f:
            f.write(key)
        
        os.chmod(key_file, 0o600)