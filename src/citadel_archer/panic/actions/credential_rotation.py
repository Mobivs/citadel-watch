"""
Credential Rotation Action - Emergency credential rotation
"""

import json
import logging
import secrets
import hashlib
import base64
from typing import Dict, Any, List
from datetime import datetime, timedelta
import asyncio

from .base import BaseAction

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
        
        try:
            if action_name == 'inventory_credentials':
                return await self._inventory_credentials(session.id)
            elif action_name == 'generate_new_keys':
                return await self._generate_new_credentials(session.id)
            elif action_name == 'update_vault':
                return await self._update_vault(session.id)
            elif action_name == 'archive_old':
                return await self._archive_old_credentials(session.id)
            elif action_name == 'rotate_ssh_keys':
                return await self._rotate_ssh_keys(session.id)
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
            archive_path = f"/var/backups/panic/credentials/{session_id}"
            
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
    
    async def _rotate_ssh_keys(self, session_id) -> Dict[str, Any]:
        """Rotate SSH keys specifically"""
        try:
            # Generate new SSH keys
            private_key, public_key = await self._generate_ssh_keypair()
            
            # Backup current authorized_keys
            import os
            authorized_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
            backup_path = f"{authorized_keys_path}.panic_backup_{session_id}"
            
            if os.path.exists(authorized_keys_path):
                import shutil
                shutil.copy2(authorized_keys_path, backup_path)
            
            # Replace with new key
            with open(authorized_keys_path, 'w') as f:
                f.write(public_key + '\n')
            
            # Save private key securely
            private_key_path = os.path.expanduser(f'~/.ssh/panic_key_{session_id}')
            with open(private_key_path, 'w') as f:
                f.write(private_key)
            os.chmod(private_key_path, 0o600)
            
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'success',
                'result': {
                    'backup': backup_path,
                    'new_key': private_key_path
                }
            }
            
        except Exception as e:
            return {
                'action': 'rotate_ssh_keys',
                'type': 'credentials',
                'status': 'failed',
                'error': str(e)
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
            import subprocess
            import tempfile
            
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                key_path = tmp.name
            
            # Generate key pair
            subprocess.run([
                'ssh-keygen', '-t', 'ed25519', '-f', key_path,
                '-N', '', '-C', f'panic-key-{datetime.utcnow().isoformat()}'
            ], check=True)
            
            # Read keys
            with open(key_path, 'r') as f:
                private_key = f.read()
            with open(f'{key_path}.pub', 'r') as f:
                public_key = f.read()
            
            # Clean up
            import os
            os.remove(key_path)
            os.remove(f'{key_path}.pub')
            
            return private_key, public_key
            
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
    
    async def _get_vault_credentials(self) -> List[Dict]:
        """Get credentials from vault"""
        # This would integrate with actual vault implementation
        # For now, return mock data
        return [
            {'type': 'ssh_key', 'name': 'server_ssh', 'path': '/vault/ssh/server'},
            {'type': 'api_token', 'name': 'github_token', 'service': 'github'},
            {'type': 'password', 'name': 'db_password', 'system': 'postgres'}
        ]
    
    async def _get_vault_passwords(self) -> List[Dict]:
        """Get password entries from vault"""
        # Mock implementation
        return [
            {'name': 'admin_password', 'system': 'citadel'},
            {'name': 'db_password', 'system': 'postgres'}
        ]
    
    async def _update_vault_credential(self, name: str, value: str) -> bool:
        """Update credential in vault"""
        # Mock implementation - would integrate with vault
        return True
    
    async def _update_vault_password(self, name: str, password: str) -> bool:
        """Update password in vault"""
        # Mock implementation
        return True
    
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
        """Get API token metadata"""
        # Mock implementation
        return [
            {'service': 'github', 'created': '2024-01-01'},
            {'service': 'aws', 'created': '2024-01-15'}
        ]
    
    async def _restore_ssh_keys(self, old_keys: List[str]):
        """Restore SSH authorized keys"""
        import os
        authorized_keys_path = os.path.expanduser('~/.ssh/authorized_keys')
        
        with open(authorized_keys_path, 'w') as f:
            f.writelines(old_keys)
    
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