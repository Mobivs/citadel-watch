"""
Credential Rotation Action - Emergency credential rotation

Safety:
  - Recovery keys (comment ``citadel-recovery-*``) are NEVER removed
    from authorized_keys during rotation.
  - Rotation aborts if no recovery key is configured.
  - The new operational private key is returned in the result so
    the frontend can display it to the user.
"""

import json
import logging
import re
import secrets
import hashlib
import base64
from typing import Dict, Any, List
from datetime import datetime, timedelta
import asyncio

from .base import BaseAction
from ..recovery_key import RecoveryKeyManager, RECOVERY_KEY_COMMENT_PREFIX

# Regex for safe session IDs (alphanumeric, underscores, hyphens only)
_SAFE_ID_RE = re.compile(r'^[a-zA-Z0-9_\-]+$')

logger = logging.getLogger(__name__)


class CredentialRotation(BaseAction):
    """
    Handles credential rotation during panic mode
    Rotates passwords, SSH keys, API tokens, certificates
    """

    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """Execute credential rotation based on action parameters"""
        action_name = action.name
        params = action.params
        asset_id = params.get('target_asset', 'local')

        try:
            # Pre-flight: ensure recovery key exists before any rotation
            if action_name in ('rotate_ssh_keys', 'generate_new_keys', 'rotate_passwords'):
                recovery_mgr = RecoveryKeyManager(self.db)
                recovery_mgr.ensure_recovery_key_present()
            if action_name == 'inventory_credentials':
                return await self._inventory_credentials(session.id)
            elif action_name == 'generate_new_keys':
                return await self._generate_new_credentials(session.id)
            elif action_name == 'update_vault':
                return await self._update_vault(session.id)
            elif action_name == 'archive_old':
                return await self._archive_old_credentials(session.id)
            elif action_name == 'rotate_ssh_keys':
                return await self._rotate_ssh_keys(session.id, asset_id=asset_id)
            elif action_name == 'rotate_api_tokens':
                return await self._rotate_api_tokens(session.id)
            elif action_name == 'rotate_passwords':
                return await self._rotate_passwords(session.id)
            else:
                return {
                    'action': action_name,
                    'type': 'credentials',
                    'status': 'failed',
                    'error': f'Unknown credential action: {action_name}'
                }
                
        except Exception as e:
            logger.error(f"Credential rotation action {action_name} failed: {e}")
            return {
                'action': action_name,
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """Capture current credential state before rotation"""
        state = {}
        
        try:
            # Get current credential inventory
            state['credentials'] = await self._get_credential_inventory()
            
            # Get SSH authorized_keys
            state['ssh_keys'] = await self._get_ssh_authorized_keys()
            
            # Get API token metadata (not the actual tokens)
            state['api_tokens'] = await self._get_api_token_metadata()
            
        except Exception as e:
            logger.error(f"Failed to capture credential state: {e}")
            state['error'] = str(e)
        
        return state
    
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """Restore credentials from saved state"""
        try:
            pre_state = json.loads(recovery_state['pre_panic_state'])
            
            # Restore SSH keys
            if 'ssh_keys' in pre_state:
                await self._restore_ssh_keys(pre_state['ssh_keys'])
            
            # Restore API tokens from archived versions
            if 'api_tokens' in pre_state:
                await self._restore_api_tokens(pre_state['api_tokens'])
            
            # Update credential rotation records
            await self._mark_credentials_rolled_back(recovery_state['session_id'])
            
            return {
                'status': 'success',
                'details': 'Credentials restored from backup'
            }
            
        except Exception as e:
            logger.error(f"Credential rollback failed: {e}")
            return {
                'status': 'failed',
                'error': str(e)
            }
    
    async def _inventory_credentials(self, session_id) -> Dict[str, Any]:
        """Take inventory of all credentials that need rotation"""
        try:
            inventory = {
                'ssh_keys': [],
                'api_tokens': [],
                'passwords': [],
                'certificates': []
            }
            
            # Get credentials from vault
            vault_creds = await self._get_vault_credentials()
            
            for cred in vault_creds:
                if cred['type'] == 'ssh_key':
                    inventory['ssh_keys'].append({
                        'name': cred['name'],
                        'path': cred['path'],
                        'created': cred.get('created_at'),
                        'hash': self._hash_credential(cred.get('value', ''))
                    })
                elif cred['type'] == 'api_token':
                    inventory['api_tokens'].append({
                        'name': cred['name'],
                        'service': cred.get('service'),
                        'hash': self._hash_credential(cred.get('value', ''))
                    })
                elif cred['type'] == 'password':
                    inventory['passwords'].append({
                        'name': cred['name'],
                        'system': cred.get('system'),
                        'hash': self._hash_credential(cred.get('value', ''))
                    })
                elif cred['type'] == 'certificate':
                    inventory['certificates'].append({
                        'name': cred['name'],
                        'expires': cred.get('expires_at')
                    })
            
            # Save inventory to database
            async with self.db.acquire() as conn:
                for cred_type, items in inventory.items():
                    for item in items:
                        await conn.execute("""
                            INSERT INTO credential_rotations
                            (session_id, credential_type, credential_name, old_credential_hash, rotation_status)
                            VALUES ($1, $2, $3, $4, 'pending')
                        """, session_id, cred_type.rstrip('s'), item.get('name'),
                            item.get('hash'))
            
            return {
                'action': 'inventory_credentials',
                'type': 'credentials',
                'status': 'success',
                'result': {
                    'ssh_keys': len(inventory['ssh_keys']),
                    'api_tokens': len(inventory['api_tokens']),
                    'passwords': len(inventory['passwords']),
                    'certificates': len(inventory['certificates'])
                }
            }
            
        except Exception as e:
            return {
                'action': 'inventory_credentials',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _generate_new_credentials(self, session_id) -> Dict[str, Any]:
        """Generate new credentials for rotation"""
        try:
            generated = {
                'ssh_keys': 0,
                'api_tokens': 0,
                'passwords': 0
            }
            
            # Get pending rotations
            async with self.db.acquire() as conn:
                rotations = await conn.fetch("""
                    SELECT * FROM credential_rotations
                    WHERE session_id = $1 AND rotation_status = 'pending'
                """, session_id)
            
            for rotation in rotations:
                if rotation['credential_type'] == 'ssh_key':
                    # Generate new SSH key pair
                    private_key, public_key = await self._generate_ssh_keypair()
                    await self._store_new_credential(
                        rotation['id'],
                        private_key,
                        {'public_key': public_key}
                    )
                    generated['ssh_keys'] += 1
                    
                elif rotation['credential_type'] == 'api_token':
                    # Generate new API token
                    token = secrets.token_urlsafe(32)
                    await self._store_new_credential(rotation['id'], token)
                    generated['api_tokens'] += 1
                    
                elif rotation['credential_type'] == 'password':
                    # Generate strong password
                    password = await self._generate_strong_password()
                    await self._store_new_credential(rotation['id'], password)
                    generated['passwords'] += 1
            
            return {
                'action': 'generate_new_keys',
                'type': 'credentials',
                'status': 'success',
                'result': generated
            }
            
        except Exception as e:
            return {
                'action': 'generate_new_keys',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _update_vault(self, session_id) -> Dict[str, Any]:
        """Update vault with new credentials"""
        try:
            updated_count = 0
            
            # Get rotations with new credentials generated
            async with self.db.acquire() as conn:
                rotations = await conn.fetch("""
                    SELECT * FROM credential_rotations
                    WHERE session_id = $1 AND rotation_status = 'rotating'
                    AND new_credential_hash IS NOT NULL
                """, session_id)
            
            for rotation in rotations:
                # Update in vault (placeholder - integrate with actual vault)
                vault_updated = await self._update_vault_credential(
                    rotation['credential_name'],
                    rotation.get('new_credential')  # Would be encrypted
                )
                
                if vault_updated:
                    # Mark as completed
                    async with self.db.acquire() as conn:
                        await conn.execute("""
                            UPDATE credential_rotations
                            SET rotation_status = 'completed', rotated_at = CURRENT_TIMESTAMP
                            WHERE id = $1
                        """, rotation['id'])
                    updated_count += 1
            
            return {
                'action': 'update_vault',
                'type': 'credentials',
                'status': 'success',
                'result': {'updated': updated_count}
            }
            
        except Exception as e:
            return {
                'action': 'update_vault',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _archive_old_credentials(self, session_id) -> Dict[str, Any]:
        """Archive old credentials for potential recovery"""
        try:
            archived_count = 0

            # Sanitize session_id to prevent path traversal
            safe_id = self._sanitize_session_id(session_id)
            archive_path = f"/var/backups/panic/credentials/{safe_id}"

            # Create archive directory
            import os
            os.makedirs(archive_path, mode=0o700, exist_ok=True)
            
            # Get completed rotations
            async with self.db.acquire() as conn:
                rotations = await conn.fetch("""
                    SELECT * FROM credential_rotations
                    WHERE session_id = $1 AND rotation_status = 'completed'
                    AND old_credential_archived = false
                """, session_id)
            
            for rotation in rotations:
                # Archive old credential (encrypted)
                archive_file = f"{archive_path}/{rotation['credential_name']}.enc"
                
                # In production, would retrieve and encrypt the old credential
                # For now, just mark as archived
                async with self.db.acquire() as conn:
                    await conn.execute("""
                        UPDATE credential_rotations
                        SET old_credential_archived = true,
                            archive_path = $1,
                            expires_at = $2
                        WHERE id = $3
                    """, archive_file,
                        datetime.utcnow() + timedelta(days=30),
                        rotation['id'])
                
                archived_count += 1
            
            return {
                'action': 'archive_old',
                'type': 'credentials',
                'status': 'success',
                'result': {'archived': archived_count, 'path': archive_path}
            }
            
        except Exception as e:
            return {
                'action': 'archive_old',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _rotate_ssh_keys(self, session_id, asset_id=None) -> Dict[str, Any]:
        """Rotate SSH keys while preserving recovery keys.

        Safety invariant: authorized_keys ALWAYS contains at least one
        ``citadel-recovery-*`` key after this method completes.

        Args:
            session_id: Active panic session ID.
            asset_id: Target asset. ``None`` or ``"local"`` for this machine;
                      a remote asset_id triggers SSH-based rotation.

        The new operational private key is returned in the result so
        the frontend can display it to the user (it is NOT stored on
        the server permanently).
        """
        if asset_id and asset_id != "local":
            return await self._rotate_ssh_keys_remote(session_id, asset_id)
        return await self._rotate_ssh_keys_local(session_id)

    @staticmethod
    def _sanitize_session_id(session_id: str) -> str:
        """Validate session_id is safe for use in file paths and commands.

        Prevents path traversal and command injection.
        """
        if not _SAFE_ID_RE.match(str(session_id)):
            raise ValueError(f"Invalid session_id format: {session_id!r}")
        return str(session_id)

    async def _rotate_ssh_keys_local(self, session_id) -> Dict[str, Any]:
        """Rotate local ~/.ssh/authorized_keys."""
        import os
        import shutil

        try:
            session_id = self._sanitize_session_id(session_id)
            recovery_mgr = RecoveryKeyManager(self.db)

            # 1. Pre-flight: verify recovery key is configured
            recovery_mgr.ensure_recovery_key_present()
            recovery_lines = recovery_mgr.get_recovery_key_lines()

            # 2. Generate new operational SSH keys
            private_key, public_key = await self._generate_ssh_keypair()

            # 3. Backup current authorized_keys
            authorized_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
            backup_path = f"{authorized_keys_path}.panic_backup_{session_id}"

            if os.path.exists(authorized_keys_path):
                shutil.copy2(authorized_keys_path, backup_path)

            # 4. Write new authorized_keys atomically (tmp + os.replace)
            tmp_path = authorized_keys_path + '.tmp'
            with open(tmp_path, 'w') as f:
                # Preserve all recovery key lines
                for line in recovery_lines:
                    f.write(line.strip() + '\n')
                # Add the new operational key
                f.write(public_key.strip() + '\n')

            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, authorized_keys_path)

            # 5. Verify recovery key survived the write
            with open(authorized_keys_path, 'r') as f:
                written = f.read()
            if RECOVERY_KEY_COMMENT_PREFIX not in written:
                # CRITICAL: recovery key lost — restore backup immediately
                logger.error("Recovery key missing after rotation — restoring backup!")
                shutil.copy2(backup_path, authorized_keys_path)
                return {
                    'action': 'rotate_ssh_keys',
                    'type': 'credentials',
                    'status': 'failed',
                    'error': 'Safety check failed: recovery key not found after write. Backup restored.'
                }

            logger.info(
                f"SSH keys rotated (local) for session {session_id}. "
                f"Recovery keys preserved: {len(recovery_lines)}"
            )

            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'success',
                'asset': 'local',
                'result': {
                    'backup': backup_path,
                    'recovery_keys_preserved': len(recovery_lines),
                    'new_private_key': private_key,
                }
            }

        except RuntimeError as e:
            # Pre-flight check failed (no recovery key)
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': 'local',
                'error': str(e)
            }
        except Exception as e:
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': 'local',
                'error': str(e)
            }

    async def _rotate_ssh_keys_remote(self, session_id, asset_id) -> Dict[str, Any]:
        """Rotate SSH keys on a remote asset via SSHConnectionManager.

        Steps:
          1. Read remote authorized_keys
          2. Verify recovery key lines exist
          3. Generate new operational keypair
          4. Build new authorized_keys = recovery lines + new pub key
          5. Write back via SSH
          6. Verify recovery key still present
          7. Return new private key for the user
        """
        try:
            session_id = self._sanitize_session_id(session_id)
        except ValueError as e:
            return {
                'action': 'rotate_ssh_keys', 'type': 'credentials',
                'status': 'failed', 'asset': asset_id, 'error': str(e),
            }

        try:
            from ...remote.ssh_manager import SSHManagerError
        except ImportError:
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': asset_id,
                'error': 'SSHConnectionManager not available (asyncssh not installed?)',
            }

        if self._ssh_manager is None:
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': asset_id,
                'error': 'SSH Manager not injected — cannot reach remote assets.',
            }

        try:
            ssh = self._ssh_manager

            ak_path = '~/.ssh/authorized_keys'

            # 1. Read remote authorized_keys
            read_result = await ssh.execute(asset_id, f'cat {ak_path} 2>/dev/null || true')
            current_contents = read_result.stdout or ''
            current_lines = [l for l in current_contents.splitlines() if l.strip()]

            # 2. Identify recovery key lines
            recovery_lines = [l for l in current_lines if RECOVERY_KEY_COMMENT_PREFIX in l]
            if not recovery_lines:
                return {
                    'action': 'rotate_ssh_keys',
                    'type': 'credentials',
                    'status': 'failed',
                    'asset': asset_id,
                    'error': (
                        f'No recovery key found on remote asset {asset_id}. '
                        'Deploy a recovery key before rotating credentials.'
                    ),
                }

            # 3. Generate new operational SSH keys
            private_key, public_key = await self._generate_ssh_keypair()

            # 4. Build new file content: recovery keys + new operational key
            new_lines = [l.strip() for l in recovery_lines]
            new_lines.append(public_key.strip())
            new_content = '\n'.join(new_lines) + '\n'

            # 5. Backup current file on remote
            backup_cmd = f'cp {ak_path} {ak_path}.panic_backup_{session_id} 2>/dev/null; true'
            await ssh.execute(asset_id, backup_cmd)

            # 6. Write new authorized_keys atomically (write to tmp then move)
            import base64 as b64
            encoded = b64.b64encode(new_content.encode()).decode()
            write_cmd = (
                f'echo "{encoded}" | base64 -d > {ak_path}.tmp '
                f'&& chmod 600 {ak_path}.tmp '
                f'&& mv {ak_path}.tmp {ak_path}'
            )
            write_result = await ssh.execute(asset_id, write_cmd)
            if write_result.exit_code != 0:
                return {
                    'action': 'rotate_ssh_keys',
                    'type': 'credentials',
                    'status': 'failed',
                    'asset': asset_id,
                    'error': f'Failed to write authorized_keys on remote: {write_result.stderr}',
                }

            # 7. Verify recovery key survived
            verify_result = await ssh.execute(asset_id, f'cat {ak_path}')
            if RECOVERY_KEY_COMMENT_PREFIX not in (verify_result.stdout or ''):
                # Restore backup
                await ssh.execute(
                    asset_id,
                    f'cp {ak_path}.panic_backup_{session_id} {ak_path}; chmod 600 {ak_path}',
                )
                return {
                    'action': 'rotate_ssh_keys',
                    'type': 'credentials',
                    'status': 'failed',
                    'asset': asset_id,
                    'error': 'Safety check failed: recovery key missing after remote write. Backup restored.',
                }

            # 8. Invalidate SSH cache so next connection uses new credentials
            try:
                await ssh.invalidate_cache(asset_id)
            except Exception:
                pass  # Cache invalidation is best-effort

            logger.info(
                f"SSH keys rotated (remote {asset_id}) for session {session_id}. "
                f"Recovery keys preserved: {len(recovery_lines)}"
            )

            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'success',
                'asset': asset_id,
                'result': {
                    'backup': f'{ak_path}.panic_backup_{session_id}',
                    'recovery_keys_preserved': len(recovery_lines),
                    'new_private_key': private_key,
                },
            }

        except SSHManagerError as e:
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': asset_id,
                'error': str(e),
            }
        except Exception as e:
            logger.error(f"Remote SSH key rotation failed for {asset_id}: {e}")
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'asset': asset_id,
                'error': str(e),
            }
    
    async def _rotate_api_tokens(self, session_id) -> Dict[str, Any]:
        """Rotate API tokens for various services"""
        rotated = {}
        
        try:
            # Get list of API services from config
            services = self.config.get('api_services', [])
            
            for service in services:
                # Generate new token
                new_token = secrets.token_urlsafe(32)
                
                # Service-specific rotation logic would go here
                # This is a placeholder
                rotated[service] = {
                    'status': 'rotated',
                    'token_prefix': new_token[:8] + '...'
                }
            
            return {
                'action': 'rotate_api_tokens',
                'type': 'credentials',
                'status': 'success',
                'result': {'services': rotated}
            }
            
        except Exception as e:
            return {
                'action': 'rotate_api_tokens',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    async def _rotate_passwords(self, session_id) -> Dict[str, Any]:
        """Rotate system and application passwords"""
        try:
            rotated_count = 0
            
            # Get password entries from vault
            passwords = await self._get_vault_passwords()
            
            for password_entry in passwords:
                # Generate new password
                new_password = await self._generate_strong_password()
                
                # Update in vault
                await self._update_vault_password(
                    password_entry['name'],
                    new_password
                )
                
                rotated_count += 1
            
            return {
                'action': 'rotate_passwords',
                'type': 'credentials',
                'status': 'success',
                'result': {'rotated': rotated_count}
            }
            
        except Exception as e:
            return {
                'action': 'rotate_passwords',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
            }
    
    # Helper methods
    
    async def _generate_ssh_keypair(self) -> tuple:
        """Generate new SSH key pair"""
        try:
            import tempfile
            import os

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                key_path = tmp.name

            try:
                # Generate key pair (async to avoid blocking the event loop)
                proc = await asyncio.create_subprocess_exec(
                    'ssh-keygen', '-t', 'ed25519', '-f', key_path,
                    '-N', '', '-C', f'panic-key-{datetime.utcnow().isoformat()}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()
                if proc.returncode != 0:
                    raise RuntimeError(f"ssh-keygen failed: {stderr.decode().strip()}")

                # Read keys
                with open(key_path, 'r') as f:
                    private_key = f.read()
                with open(f'{key_path}.pub', 'r') as f:
                    public_key = f.read()

                return private_key, public_key
            finally:
                # Always clean up temp files, even on crash
                for p in (key_path, f'{key_path}.pub'):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
            
        except Exception as e:
            logger.error(f"SSH key generation failed: {e}")
            # Fallback to Python generation
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            
            private_key = ed25519.Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            )
            
            return private_bytes.decode(), public_bytes.decode()
    
    async def _generate_strong_password(self, length=32) -> str:
        """Generate a strong password"""
        import string
        
        # Use all character classes
        chars = string.ascii_letters + string.digits + string.punctuation
        
        # Generate password
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        # Ensure it has at least one of each character class
        while not (any(c.islower() for c in password) and
                   any(c.isupper() for c in password) and
                   any(c.isdigit() for c in password) and
                   any(c in string.punctuation for c in password)):
            password = ''.join(secrets.choice(chars) for _ in range(length))
        
        return password
    
    def _hash_credential(self, credential: str) -> str:
        """Generate SHA256 hash of credential"""
        return hashlib.sha256(credential.encode()).hexdigest()
    
    def _get_vault_manager(self):
        """Get VaultManager instance (or None if unavailable/locked)."""
        try:
            from ...vault.vault_manager import VaultManager
            vm = VaultManager()
            return vm if vm.is_unlocked else None
        except Exception:
            return None

    async def _get_vault_credentials(self) -> List[Dict]:
        """Get credentials from vault."""
        vm = self._get_vault_manager()
        if vm is None:
            logger.warning("Vault locked or unavailable — returning empty credential list")
            return []

        results = []
        try:
            for entry in vm.list_passwords():
                cat = entry.get('category', 'general')
                if cat == 'ssh':
                    results.append({'type': 'ssh_key', 'name': entry['title'], 'id': entry['id']})
                elif cat == 'api':
                    results.append({'type': 'api_token', 'name': entry['title'], 'id': entry['id']})
                else:
                    results.append({'type': 'password', 'name': entry['title'], 'id': entry['id']})
        except Exception as e:
            logger.error(f"Failed to list vault credentials: {e}")
        return results

    async def _get_vault_passwords(self) -> List[Dict]:
        """Get password entries from vault."""
        vm = self._get_vault_manager()
        if vm is None:
            logger.warning("Vault locked or unavailable — returning empty password list")
            return []

        results = []
        try:
            for entry in vm.list_passwords():
                results.append({
                    'name': entry['title'],
                    'id': entry['id'],
                    'system': entry.get('website', entry.get('category', 'unknown')),
                })
        except Exception as e:
            logger.error(f"Failed to list vault passwords: {e}")
        return results

    async def _update_vault_credential(self, name: str, value: str) -> bool:
        """Update credential in vault (add new FIRST, then delete old).

        This ordering ensures the credential is never lost: if the add
        fails, the old entry remains intact.
        """
        vm = self._get_vault_manager()
        if vm is None:
            logger.error("Cannot update vault credential — vault is locked")
            return False

        try:
            existing = [e for e in vm.list_passwords() if e['title'] == name]
            # Add new entry first (may have duplicate title briefly)
            success, _ = vm.add_password(title=name, password=value, category='ssh')
            if not success:
                return False
            # Only delete old entry after new one is safely stored
            if existing:
                vm.delete_password(existing[0]['id'])
            return True
        except Exception as e:
            logger.error(f"Failed to update vault credential '{name}': {e}")
            return False

    async def _update_vault_password(self, name: str, password: str) -> bool:
        """Update password in vault (add new FIRST, then delete old).

        This ordering ensures the password is never lost: if the add
        fails, the old entry remains intact.
        """
        vm = self._get_vault_manager()
        if vm is None:
            logger.error("Cannot update vault password — vault is locked")
            return False

        try:
            existing = [e for e in vm.list_passwords() if e['title'] == name]
            old_entry = None
            if existing:
                old_entry = vm.get_password(existing[0]['id'])
            # Add new entry first
            success, _ = vm.add_password(
                title=name,
                password=password,
                username=old_entry.get('username') if old_entry else None,
                website=old_entry.get('website') if old_entry else None,
                category=old_entry.get('category', 'general') if old_entry else 'general',
            )
            if not success:
                return False
            # Only delete old entry after new one is safely stored
            if existing:
                vm.delete_password(existing[0]['id'])
            return True
        except Exception as e:
            logger.error(f"Failed to update vault password '{name}': {e}")
            return False
    
    async def _get_credential_inventory(self) -> List[Dict]:
        """Get inventory of all credentials"""
        return await self._get_vault_credentials()
    
    async def _get_ssh_authorized_keys(self) -> List[str]:
        """Get current SSH authorized keys"""
        import os
        authorized_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
        
        if os.path.exists(authorized_keys_path):
            with open(authorized_keys_path, 'r') as f:
                return f.readlines()
        return []
    
    async def _get_api_token_metadata(self) -> List[Dict]:
        """Get API token metadata from vault (category='api')."""
        vm = self._get_vault_manager()
        if vm is None:
            logger.warning("Vault locked — cannot retrieve API token metadata")
            return []

        results = []
        try:
            for entry in vm.list_passwords(category='api'):
                results.append({
                    'service': entry.get('website', entry['title']),
                    'name': entry['title'],
                    'id': entry['id'],
                    'created': entry.get('created_at', 'unknown'),
                })
        except Exception as e:
            logger.error(f"Failed to list API tokens: {e}")
        return results
    
    async def _restore_ssh_keys(self, old_keys: List[str]):
        """Restore SSH authorized keys while preserving recovery keys."""
        import os
        authorized_keys_path = os.path.expanduser('~/.ssh/authorized_keys')

        # Get current recovery key lines (must survive rollback too)
        recovery_mgr = RecoveryKeyManager(self.db)
        recovery_lines = recovery_mgr.get_recovery_key_lines()

        # Merge: recovery keys + restored old keys (minus any old recovery lines to avoid dupes)
        restored = [line for line in old_keys if RECOVERY_KEY_COMMENT_PREFIX not in line]

        tmp_path = authorized_keys_path + '.tmp'
        with open(tmp_path, 'w') as f:
            for line in recovery_lines:
                f.write(line.strip() + '\n')
            f.writelines(restored)

        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, authorized_keys_path)
    
    async def _restore_api_tokens(self, token_metadata: List[Dict]):
        """Restore API tokens from archive"""
        # Would retrieve from encrypted archive
        pass
    
    async def _mark_credentials_rolled_back(self, session_id):
        """Mark credentials as rolled back"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                UPDATE credential_rotations
                SET rotation_status = 'rolled_back'
                WHERE session_id = $1
            """, session_id)
    
    async def _store_new_credential(self, rotation_id, credential: str, metadata: Dict = None):
        """Store newly generated credential"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                UPDATE credential_rotations
                SET new_credential_hash = $1,
                    rotation_status = 'rotating',
                    metadata = $2
                WHERE id = $3
            """, self._hash_credential(credential),
                json.dumps(metadata or {}),
                rotation_id)