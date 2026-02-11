"""
Base class for panic room actions
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


class BaseAction(ABC):
    """
    Abstract base class for all panic room actions
    Each action must implement execute, capture_state, and rollback methods
    """
    
    def __init__(self, db_connection, config: Dict[str, Any]):
        self.db = db_connection
        self.config = config
        
    @abstractmethod
    async def execute(self, action: 'Action', session: 'PanicSession') -> Dict[str, Any]:
        """
        Execute the action
        
        Args:
            action: Action definition with parameters
            session: Current panic session
            
        Returns:
            Result dictionary with status and details
        """
        pass
    
    @abstractmethod
    async def capture_state(self, action: 'Action') -> Dict[str, Any]:
        """
        Capture current state before executing action
        Used for potential rollback
        
        Args:
            action: Action definition
            
        Returns:
            State dictionary
        """
        pass
    
    @abstractmethod
    async def rollback(self, recovery_state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rollback action to previous state
        
        Args:
            recovery_state: Previously captured state
            
        Returns:
            Rollback result
        """
        pass
    
    async def validate_params(self, params: Dict[str, Any], required: list) -> bool:
        """
        Validate action parameters
        
        Args:
            params: Action parameters
            required: List of required parameter names
            
        Returns:
            True if valid, False otherwise
        """
        for param in required:
            if param not in params:
                logger.error(f"Missing required parameter: {param}")
                return False
        return True
    
    async def log_execution(
        self,
        action_name: str,
        status: str,
        details: Optional[Dict] = None,
        error: Optional[str] = None
    ):
        """
        Log action execution details
        
        Args:
            action_name: Name of the action
            status: Execution status
            details: Additional details
            error: Error message if failed
        """
        log_entry = {
            'action': action_name,
            'status': status,
            'timestamp': 'now()'
        }
        
        if details:
            log_entry['details'] = details
        if error:
            log_entry['error'] = error
            
        if status == 'failed':
            logger.error(f"Action {action_name} failed: {error}")
        else:
            logger.info(f"Action {action_name} {status}")