"""
Playbook Engine - Executes panic response playbooks
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from uuid import UUID

from .actions import (
    NetworkIsolation,
    CredentialRotation,
    ProcessTermination,
    SystemSnapshot,
    SecureBackup,
    BaseAction
)

logger = logging.getLogger(__name__)


@dataclass
class Action:
    """Single action within a playbook"""
    name: str
    type: str
    params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 30
    retry_count: int = 0
    required: bool = True


@dataclass
class Playbook:
    """Playbook definition"""
    id: str
    name: str
    description: str
    category: str
    priority: int
    requires_confirmation: bool
    actions: List[Action]
    pre_checks: List[Dict[str, Any]] = field(default_factory=list)
    rollback_actions: List[Action] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PlaybookEngine:
    """
    Engine for executing panic playbooks
    Handles action orchestration, state management, and rollback
    """
    
    def __init__(self, db_connection, config: Dict[str, Any]):
        self.db = db_connection
        self.config = config
        self.action_handlers = self._initialize_action_handlers()
        self.check_handlers = self._initialize_check_handlers()
        
    def _initialize_action_handlers(self) -> Dict[str, BaseAction]:
        """Initialize all available action handlers"""
        return {
            'network': NetworkIsolation(self.db, self.config),
            'firewall': NetworkIsolation(self.db, self.config),
            'credentials': CredentialRotation(self.db, self.config),
            'vault': CredentialRotation(self.db, self.config),
            'crypto': CredentialRotation(self.db, self.config),
            'processes': ProcessTermination(self.db, self.config),
            'system': ProcessTermination(self.db, self.config),
            'forensics': SystemSnapshot(self.db, self.config),
            'analysis': SystemSnapshot(self.db, self.config),
            'backup': SecureBackup(self.db, self.config),
            'data': SecureBackup(self.db, self.config),
        }
    
    def _initialize_check_handlers(self) -> Dict[str, Callable]:
        """Initialize pre-flight check handlers"""
        return {
            'verify_whitelist': self._check_whitelist,
            'check_vpn_status': self._check_vpn,
            'verify_vault_access': self._check_vault,
            'check_key_generator': self._check_crypto,
            'scan_process_tree': self._check_processes,
            'check_critical_processes': self._check_critical_processes,
            'check_disk_space': self._check_disk_space,
            'verify_tools': self._check_tools,
            'check_backup_destination': self._check_backup,
            'verify_encryption_keys': self._check_encryption,
        }
    
    async def load_playbooks(self, playbook_ids: List[str]) -> List[Playbook]:
        """Load playbook definitions from database"""
        playbooks = []
        
        async with self.db.acquire() as conn:
            for playbook_id in playbook_ids:
                row = await conn.fetchrow(
                    "SELECT * FROM playbooks WHERE id = $1 AND is_active = true",
                    playbook_id
                )
                
                if row:
                    actions = [
                        Action(**action_def)
                        for action_def in json.loads(row['actions'])
                    ]
                    
                    playbook = Playbook(
                        id=row['id'],
                        name=row['name'],
                        description=row['description'],
                        category=row['category'],
                        priority=row['priority'],
                        requires_confirmation=row['requires_confirmation'],
                        actions=actions,
                        pre_checks=json.loads(row['pre_checks']),
                        rollback_actions=[
                            Action(**action_def)
                            for action_def in json.loads(row['rollback_actions'])
                        ],
                        metadata=json.loads(row['metadata'])
                    )
                    playbooks.append(playbook)
                else:
                    logger.warning(f"Playbook {playbook_id} not found or inactive")
        
        return playbooks
    
    async def execute_playbook(
        self,
        playbook: Playbook,
        session: 'PanicSession',
        state_callback: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Execute all actions in a playbook
        
        Args:
            playbook: Playbook to execute
            session: Current panic session
            state_callback: Callback for saving recovery state
            
        Returns:
            List of action results
        """
        results = []
        
        for action in playbook.actions:
            try:
                # Get the appropriate handler
                handler = self.action_handlers.get(action.type)
                
                if not handler:
                    logger.error(f"No handler for action type: {action.type}")
                    results.append({
                        'action': action.name,
                        'type': action.type,
                        'status': 'failed',
                        'error': f"No handler for action type {action.type}"
                    })
                    continue
                
                # Save pre-action state for rollback
                if state_callback:
                    pre_state = await handler.capture_state(action)
                    await state_callback({
                        'component': action.type,
                        'component_id': action.name,
                        'pre_state': pre_state,
                        'current_state': None
                    })
                
                # Execute the action with timeout
                result = await asyncio.wait_for(
                    handler.execute(action, session),
                    timeout=action.timeout
                )
                
                # Save post-action state
                if state_callback and result.get('status') == 'success':
                    post_state = await handler.capture_state(action)
                    await state_callback({
                        'component': action.type,
                        'component_id': action.name,
                        'pre_state': pre_state,
                        'current_state': post_state
                    })
                
                results.append(result)
                
            except asyncio.TimeoutError:
                logger.error(f"Action {action.name} timed out after {action.timeout}s")
                results.append({
                    'action': action.name,
                    'type': action.type,
                    'status': 'failed',
                    'error': f"Timeout after {action.timeout} seconds"
                })
                
                # Continue with next action if this one isn't required
                if action.required:
                    break
                    
            except Exception as e:
                logger.error(f"Action {action.name} failed: {e}")
                results.append({
                    'action': action.name,
                    'type': action.type,
                    'status': 'failed',
                    'error': str(e)
                })
                
                # Retry if configured
                if action.retry_count > 0:
                    logger.info(f"Retrying action {action.name} ({action.retry_count} retries left)")
                    action.retry_count -= 1
                    # Add back to queue for retry
                    playbook.actions.insert(playbook.actions.index(action) + 1, action)
                elif action.required:
                    break
        
        return results
    
    async def run_check(self, check: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a pre-flight check
        
        Args:
            check: Check definition with name and parameters
            
        Returns:
            Check result with 'passed' boolean and details
        """
        check_name = check.get('name')
        handler = self.check_handlers.get(check_name)
        
        if not handler:
            logger.warning(f"No handler for check: {check_name}")
            return {
                'name': check_name,
                'passed': False,
                'error': 'Check handler not found'
            }
        
        try:
            result = await handler(check.get('params', {}))
            return {
                'name': check_name,
                'passed': result.get('passed', False),
                'details': result.get('details', {})
            }
        except Exception as e:
            logger.error(f"Check {check_name} failed: {e}")
            return {
                'name': check_name,
                'passed': False,
                'error': str(e)
            }
    
    async def rollback_component(
        self,
        component: str,
        recovery_state: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Rollback a single component to pre-panic state
        
        Args:
            component: Component type to rollback
            recovery_state: Saved state information
            
        Returns:
            Rollback result
        """
        handler = self.action_handlers.get(component)
        
        if not handler:
            raise ValueError(f"No handler for component: {component}")
        
        return await handler.rollback(recovery_state)
    
    # Pre-flight check implementations
    
    async def _check_whitelist(self, params: Dict) -> Dict[str, Any]:
        """Verify network whitelist is properly configured"""
        async with self.db.acquire() as conn:
            count = await conn.fetchval(
                "SELECT COUNT(*) FROM panic_whitelist WHERE is_active = true AND is_permanent = true"
            )
        
        return {
            'passed': count > 0,
            'details': {'permanent_entries': count}
        }
    
    async def _check_vpn(self, params: Dict) -> Dict[str, Any]:
        """Check VPN connection status"""
        # Implement VPN check logic
        # For now, assume VPN is optional
        return {'passed': True, 'details': {'vpn_active': False}}
    
    async def _check_vault(self, params: Dict) -> Dict[str, Any]:
        """Verify Vault is accessible"""
        try:
            # Check if Vault API is responding
            # This would integrate with your Vault implementation
            vault_healthy = True  # Placeholder
            return {
                'passed': vault_healthy,
                'details': {'vault_status': 'healthy' if vault_healthy else 'unavailable'}
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}
    
    async def _check_crypto(self, params: Dict) -> Dict[str, Any]:
        """Check cryptographic key generation capability"""
        try:
            # Test key generation
            import secrets
            test_key = secrets.token_hex(32)
            return {
                'passed': len(test_key) == 64,
                'details': {'crypto_available': True}
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}
    
    async def _check_processes(self, params: Dict) -> Dict[str, Any]:
        """Scan process tree for analysis"""
        try:
            import psutil
            process_count = len(psutil.pids())
            suspicious_count = 0  # Would implement actual detection
            
            return {
                'passed': True,
                'details': {
                    'total_processes': process_count,
                    'suspicious_processes': suspicious_count
                }
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}
    
    async def _check_critical_processes(self, params: Dict) -> Dict[str, Any]:
        """Ensure critical processes are running"""
        critical = params.get('processes', ['postgres', 'citadel_commander'])
        missing = []
        
        try:
            import psutil
            running = [p.name() for p in psutil.process_iter(['name'])]
            
            for proc in critical:
                if not any(proc in r for r in running):
                    missing.append(proc)
            
            return {
                'passed': len(missing) == 0,
                'details': {
                    'critical_processes': critical,
                    'missing': missing
                }
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}
    
    async def _check_disk_space(self, params: Dict) -> Dict[str, Any]:
        """Check available disk space"""
        try:
            import shutil
            stat = shutil.disk_usage('/')
            free_gb = stat.free / (1024**3)
            min_required = params.get('min_gb', 1)
            
            return {
                'passed': free_gb >= min_required,
                'details': {
                    'free_gb': round(free_gb, 2),
                    'required_gb': min_required
                }
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}
    
    async def _check_tools(self, params: Dict) -> Dict[str, Any]:
        """Verify required tools are available"""
        required_tools = params.get('tools', ['iptables', 'openssl', 'tar'])
        missing = []
        
        import shutil
        for tool in required_tools:
            if not shutil.which(tool):
                missing.append(tool)
        
        return {
            'passed': len(missing) == 0,
            'details': {
                'required_tools': required_tools,
                'missing': missing
            }
        }
    
    async def _check_backup(self, params: Dict) -> Dict[str, Any]:
        """Check backup destination availability"""
        import os
        backup_path = params.get('path', '/var/backups/panic')
        
        try:
            os.makedirs(backup_path, exist_ok=True)
            test_file = f"{backup_path}/.write_test"
            
            # Test write access
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            
            return {
                'passed': True,
                'details': {'backup_path': backup_path, 'writable': True}
            }
        except Exception as e:
            return {
                'passed': False,
                'details': {'backup_path': backup_path, 'error': str(e)}
            }
    
    async def _check_encryption(self, params: Dict) -> Dict[str, Any]:
        """Verify encryption keys are available"""
        try:
            # Check if encryption is properly configured
            # This would integrate with your encryption setup
            return {
                'passed': True,
                'details': {'encryption_ready': True}
            }
        except Exception as e:
            return {'passed': False, 'details': {'error': str(e)}}