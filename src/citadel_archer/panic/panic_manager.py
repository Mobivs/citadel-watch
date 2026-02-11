"""
Panic Manager - Main orchestrator for panic room functionality
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from enum import Enum

from ..core.audit_log import AuditLogger
from ..secrets import SecretsStore
from .playbook_engine import PlaybookEngine
from .models import PanicSession, PanicLog, RecoveryState
from .exceptions import (
    PanicException,
    ConfirmationTimeout,
    PreFlightCheckFailed,
    RollbackFailed
)

logger = logging.getLogger(__name__)
audit = AuditLogger()


class TriggerSource(Enum):
    """Types of panic triggers"""
    MANUAL = "manual"
    AI = "ai"
    REMOTE = "remote"
    DEADMAN = "deadman"


class PanicStatus(Enum):
    """Panic session status"""
    ACTIVE = "active"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PanicManager:
    """
    Main manager for panic room operations
    Handles triggering, execution, monitoring, and rollback
    """
    
    def __init__(self, db_connection, config: Dict[str, Any]):
        self.db = db_connection
        self.config = config
        self.playbook_engine = PlaybookEngine(db_connection, config)
        self.secrets_manager = SecretsStore()
        self.active_sessions: Dict[UUID, PanicSession] = {}
        self.websocket_handlers: Dict[UUID, List] = {}
        
    async def trigger_panic(
        self,
        trigger_source: TriggerSource,
        playbook_ids: List[str],
        reason: str,
        user_id: Optional[int] = None,
        confirmation_token: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> PanicSession:
        """
        Trigger panic mode with specified playbooks
        
        Args:
            trigger_source: How panic was triggered
            playbook_ids: List of playbook IDs to execute
            reason: Human-readable reason for panic
            user_id: User who triggered (if manual)
            confirmation_token: Token proving user confirmation
            metadata: Additional context data
            
        Returns:
            PanicSession object tracking the panic response
        """
        # Validate confirmation if required
        if trigger_source == TriggerSource.MANUAL:
            if not await self._validate_confirmation(confirmation_token, user_id):
                raise ConfirmationTimeout("User confirmation required for manual panic trigger")
        
        # Create panic session
        session = await self._create_session(
            trigger_source=trigger_source,
            reason=reason,
            user_id=user_id,
            metadata=metadata or {}
        )
        
        # Log the trigger
        await audit.log_event(
            event_type="panic_triggered",
            severity="critical",
            details={
                "session_id": str(session.id),
                "trigger_source": trigger_source.value,
                "reason": reason,
                "playbook_count": len(playbook_ids)
            }
        )
        
        # Start execution in background
        asyncio.create_task(
            self._execute_panic(session, playbook_ids)
        )
        
        return session
    
    async def _create_session(
        self,
        trigger_source: TriggerSource,
        reason: str,
        user_id: Optional[int],
        metadata: Dict
    ) -> PanicSession:
        """Create and persist a new panic session"""
        session = PanicSession(
            id=uuid4(),
            triggered_at=datetime.utcnow(),
            trigger_source=trigger_source.value,
            trigger_reason=reason,
            status=PanicStatus.ACTIVE.value,
            user_id=user_id,
            metadata=metadata
        )
        
        # Store in database
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO panic_sessions 
                (id, trigger_source, trigger_reason, status, user_id, metadata)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, session.id, session.trigger_source, session.trigger_reason,
                session.status, session.user_id, json.dumps(session.metadata))
        
        # Track active session
        self.active_sessions[session.id] = session
        
        return session
    
    async def _execute_panic(self, session: PanicSession, playbook_ids: List[str]):
        """
        Execute panic response playbooks
        Handles pre-flight checks, parallel execution, and logging
        """
        try:
            # Update status
            await self._update_session_status(session.id, PanicStatus.EXECUTING)
            
            # Load playbooks
            playbooks = await self.playbook_engine.load_playbooks(playbook_ids)
            
            # Sort by priority
            playbooks.sort(key=lambda p: p.priority)
            
            # Group by priority for parallel execution
            priority_groups = {}
            for playbook in playbooks:
                if playbook.priority not in priority_groups:
                    priority_groups[playbook.priority] = []
                priority_groups[playbook.priority].append(playbook)
            
            # Execute each priority group
            for priority in sorted(priority_groups.keys()):
                group_playbooks = priority_groups[priority]
                
                # Run pre-flight checks for this group
                for playbook in group_playbooks:
                    if not await self._run_preflight_checks(session, playbook):
                        logger.error(f"Pre-flight checks failed for {playbook.id}")
                        continue
                
                # Execute playbooks in parallel within priority group
                tasks = [
                    self._execute_playbook(session, playbook)
                    for playbook in group_playbooks
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Log any exceptions
                for playbook, result in zip(group_playbooks, results):
                    if isinstance(result, Exception):
                        await self._log_playbook_error(session, playbook, result)
            
            # Mark session as completed
            await self._update_session_status(session.id, PanicStatus.COMPLETED)
            
            # Notify completion
            await self._notify_completion(session)
            
        except Exception as e:
            logger.error(f"Panic execution failed for session {session.id}: {e}")
            await self._update_session_status(session.id, PanicStatus.FAILED)
            await self._notify_failure(session, str(e))
    
    async def _run_preflight_checks(
        self,
        session: PanicSession,
        playbook: 'Playbook'
    ) -> bool:
        """
        Run pre-flight checks for a playbook
        Returns True if all critical checks pass
        """
        if not playbook.pre_checks:
            return True
        
        all_passed = True
        critical_failed = False
        
        for check in playbook.pre_checks:
            try:
                result = await self.playbook_engine.run_check(check)
                
                if not result['passed']:
                    if check.get('critical', False):
                        critical_failed = True
                        logger.error(f"Critical check failed: {check['name']}")
                    else:
                        logger.warning(f"Non-critical check failed: {check['name']}")
                    all_passed = False
                    
            except Exception as e:
                logger.error(f"Check {check['name']} raised exception: {e}")
                if check.get('critical', False):
                    critical_failed = True
                all_passed = False
        
        # Block execution only if critical checks failed
        return not critical_failed
    
    async def _execute_playbook(
        self,
        session: PanicSession,
        playbook: 'Playbook'
    ):
        """Execute a single playbook and log all actions"""
        start_time = datetime.utcnow()
        
        try:
            # Log playbook start
            await self._log_action(
                session_id=session.id,
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                action_name="playbook_start",
                action_type="system",
                status="executing"
            )
            
            # Execute the playbook
            results = await self.playbook_engine.execute_playbook(
                playbook=playbook,
                session=session,
                state_callback=lambda state: self._save_recovery_state(session.id, state)
            )
            
            # Log results
            for action_result in results:
                await self._log_action(
                    session_id=session.id,
                    playbook_id=playbook.id,
                    playbook_name=playbook.name,
                    action_name=action_result['action'],
                    action_type=action_result['type'],
                    status=action_result['status'],
                    result=action_result.get('result', {}),
                    error_message=action_result.get('error')
                )
            
            # Log playbook completion
            duration = (datetime.utcnow() - start_time).total_seconds()
            await self._log_action(
                session_id=session.id,
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                action_name="playbook_complete",
                action_type="system",
                status="success",
                result={"duration_seconds": duration}
            )
            
        except Exception as e:
            logger.error(f"Playbook {playbook.id} failed: {e}")
            await self._log_action(
                session_id=session.id,
                playbook_id=playbook.id,
                playbook_name=playbook.name,
                action_name="playbook_error",
                action_type="system",
                status="failed",
                error_message=str(e)
            )
            raise
    
    async def _save_recovery_state(self, session_id: UUID, state: Dict):
        """Save recovery state for potential rollback"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO recovery_states
                (session_id, component, component_id, pre_panic_state, current_state)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (session_id, component, component_id)
                DO UPDATE SET current_state = $5
            """, session_id, state['component'], state['component_id'],
                json.dumps(state['pre_state']), json.dumps(state.get('current_state')))
    
    async def rollback_panic(
        self,
        session_id: UUID,
        components: Optional[List[str]] = None,
        confirmation_token: Optional[str] = None,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Rollback panic actions for specified components
        
        Args:
            session_id: Panic session to rollback
            components: Specific components to rollback (None = all)
            confirmation_token: User confirmation token
            user_id: User requesting rollback
            
        Returns:
            Dict with rollback results per component
        """
        # Validate confirmation
        if not await self._validate_confirmation(confirmation_token, user_id):
            raise ConfirmationTimeout("Rollback requires user confirmation")
        
        # Get recovery states
        states = await self._get_recovery_states(session_id, components)
        
        if not states:
            return {"error": "No recovery states found for rollback"}
        
        results = {}
        
        # Execute rollback for each component
        for state in states:
            component = state['component']
            try:
                # Get the appropriate rollback handler
                rollback_result = await self.playbook_engine.rollback_component(
                    component=component,
                    recovery_state=state
                )
                
                results[component] = {
                    "status": "success",
                    "details": rollback_result
                }
                
                # Mark as rolled back in database
                await self._mark_rolled_back(state['id'])
                
            except Exception as e:
                logger.error(f"Rollback failed for {component}: {e}")
                results[component] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Update session status if all components rolled back
        if all(r['status'] == 'success' for r in results.values()):
            await self._update_session_status(session_id, PanicStatus.ROLLED_BACK)
        
        return results
    
    async def get_status(self, session_id: UUID) -> Dict[str, Any]:
        """Get current status of a panic session"""
        session = self.active_sessions.get(session_id)
        
        if not session:
            # Load from database
            async with self.db.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM panic_sessions WHERE id = $1",
                    session_id
                )
                if not row:
                    return {"error": "Session not found"}
                session = PanicSession(**dict(row))
        
        # Get execution logs
        logs = await self._get_session_logs(session_id)
        
        # Calculate progress
        total_actions = len(logs)
        completed = len([l for l in logs if l['status'] in ['success', 'failed']])
        
        current_action = None
        for log in reversed(logs):
            if log['status'] == 'executing':
                current_action = log['action_name']
                break
        
        return {
            "session_id": str(session_id),
            "status": session.status,
            "triggered_at": session.triggered_at.isoformat(),
            "trigger_source": session.trigger_source,
            "reason": session.trigger_reason,
            "progress": {
                "total_actions": total_actions,
                "completed": completed,
                "failed": len([l for l in logs if l['status'] == 'failed']),
                "current_action": current_action
            },
            "logs": logs[-10:]  # Last 10 log entries
        }
    
    async def _validate_confirmation(
        self,
        token: Optional[str],
        user_id: Optional[int]
    ) -> bool:
        """Validate user confirmation token"""
        if not token:
            return False
        
        # Check if token is valid (implement your validation logic)
        # For now, simple check that token matches expected format
        expected = hashlib.sha256(f"panic_{user_id}_{datetime.utcnow().date()}".encode()).hexdigest()[:16]
        return token == expected or self.config.get('skip_confirmation', False)
    
    async def _update_session_status(self, session_id: UUID, status: PanicStatus):
        """Update panic session status"""
        async with self.db.acquire() as conn:
            await conn.execute(
                "UPDATE panic_sessions SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
                status.value, session_id
            )
        
        if session_id in self.active_sessions:
            self.active_sessions[session_id].status = status.value
        
        # Notify via WebSocket
        await self._notify_websocket(session_id, {
            "event": "status_update",
            "status": status.value
        })
    
    async def _log_action(
        self,
        session_id: UUID,
        playbook_id: str,
        playbook_name: str,
        action_name: str,
        action_type: str,
        status: str,
        result: Optional[Dict] = None,
        error_message: Optional[str] = None
    ):
        """Log a panic action to the database"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                INSERT INTO panic_logs
                (session_id, playbook_id, playbook_name, action_name, action_type, status, result, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, session_id, playbook_id, playbook_name, action_name, action_type,
                status, json.dumps(result or {}), error_message)
        
        # Notify via WebSocket
        await self._notify_websocket(session_id, {
            "event": "action_update",
            "playbook": playbook_name,
            "action": action_name,
            "status": status
        })
    
    async def _get_recovery_states(
        self,
        session_id: UUID,
        components: Optional[List[str]]
    ) -> List[Dict]:
        """Get recovery states for rollback"""
        async with self.db.acquire() as conn:
            if components:
                rows = await conn.fetch("""
                    SELECT * FROM recovery_states
                    WHERE session_id = $1 AND component = ANY($2)
                    AND rollback_available = true
                """, session_id, components)
            else:
                rows = await conn.fetch("""
                    SELECT * FROM recovery_states
                    WHERE session_id = $1 AND rollback_available = true
                """, session_id)
        
        return [dict(row) for row in rows]
    
    async def _mark_rolled_back(self, state_id: UUID):
        """Mark a recovery state as rolled back"""
        async with self.db.acquire() as conn:
            await conn.execute("""
                UPDATE recovery_states
                SET rollback_attempted = true,
                    rollback_succeeded = true,
                    rollback_at = CURRENT_TIMESTAMP
                WHERE id = $1
            """, state_id)
    
    async def _get_session_logs(self, session_id: UUID) -> List[Dict]:
        """Get all logs for a panic session"""
        async with self.db.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM panic_logs
                WHERE session_id = $1
                ORDER BY created_at ASC
            """, session_id)
        
        return [dict(row) for row in rows]
    
    async def _notify_websocket(self, session_id: UUID, message: Dict):
        """Send WebSocket notification for session updates"""
        if session_id in self.websocket_handlers:
            for handler in self.websocket_handlers[session_id]:
                try:
                    await handler.send_json(message)
                except Exception as e:
                    logger.warning(f"Failed to send WebSocket message: {e}")
    
    async def _notify_completion(self, session: PanicSession):
        """Send notifications when panic session completes"""
        # Implement your notification logic (email, SMS, etc.)
        logger.info(f"Panic session {session.id} completed successfully")
    
    async def _notify_failure(self, session: PanicSession, error: str):
        """Send notifications when panic session fails"""
        # Implement your notification logic
        logger.error(f"Panic session {session.id} failed: {error}")
    
    async def _log_playbook_error(self, session: PanicSession, playbook: 'Playbook', error: Exception):
        """Log playbook execution error"""
        await self._log_action(
            session_id=session.id,
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            action_name="playbook_error",
            action_type="system",
            status="failed",
            error_message=str(error)
        )