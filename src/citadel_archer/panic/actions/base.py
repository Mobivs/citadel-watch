"""
Base class for panic room actions

Provides local/remote execution routing via ``_run_command()``.
When ``target_asset`` is ``"local"`` (the default), commands run via
``subprocess``.  For any other asset ID, commands are routed to the
asset's host over SSH through ``SSHConnectionManager``.
"""

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class CommandOutput:
    """Unified command result for local or remote execution."""
    stdout: str = ""
    stderr: str = ""
    returncode: int = -1
    asset_id: str = "local"


class BaseAction(ABC):
    """
    Abstract base class for all panic room actions
    Each action must implement execute, capture_state, and rollback methods
    """

    def __init__(self, db_connection, config: Dict[str, Any]):
        self.db = db_connection
        self.config = config
        # Set by PlaybookEngine when an SSH manager is available
        self._ssh_manager = None

    def set_ssh_manager(self, ssh_manager) -> None:
        """Inject the SSH connection manager for remote execution."""
        self._ssh_manager = ssh_manager

    # ------------------------------------------------------------------
    # Local / remote command routing
    # ------------------------------------------------------------------

    async def _run_command(
        self,
        command: list | str,
        asset_id: str = "local",
        timeout: int = 30,
        check: bool = False,
    ) -> CommandOutput:
        """Execute a command locally or on a remote asset via SSH.

        Args:
            command: Shell command.  For local execution a *list* is
                preferred (avoids shell injection).  For remote execution
                the list is joined into a single string.
            asset_id: ``"local"`` for this machine, otherwise an asset ID
                registered in the SSH Manager / Asset Inventory.
            timeout: Max seconds to wait.
            check: If True, raise on non-zero exit code (local only).

        Returns:
            ``CommandOutput`` with stdout, stderr, and return code.
        """
        if asset_id == "local":
            return await self._run_local(command, timeout=timeout, check=check)
        else:
            return await self._run_remote(asset_id, command, timeout=timeout)

    async def _run_local(
        self,
        command: list | str,
        timeout: int = 30,
        check: bool = False,
    ) -> CommandOutput:
        """Run a command on the local machine via subprocess."""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=check,
            )
            return CommandOutput(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.returncode,
                asset_id="local",
            )
        except subprocess.CalledProcessError as e:
            return CommandOutput(
                stdout=e.stdout or "",
                stderr=e.stderr or "",
                returncode=e.returncode,
                asset_id="local",
            )
        except subprocess.TimeoutExpired:
            return CommandOutput(
                stderr=f"Command timed out after {timeout}s",
                returncode=-1,
                asset_id="local",
            )

    async def _run_remote(
        self,
        asset_id: str,
        command: list | str,
        timeout: int = 30,
    ) -> CommandOutput:
        """Run a command on a remote asset via SSH Manager."""
        if self._ssh_manager is None:
            logger.error(
                f"Cannot execute on remote asset '{asset_id}': "
                "no SSH Manager configured"
            )
            return CommandOutput(
                stderr="SSH Manager not available for remote execution",
                returncode=-1,
                asset_id=asset_id,
            )

        # Convert list to shell string for remote execution
        if isinstance(command, list):
            cmd_str = " ".join(command)
        else:
            cmd_str = command

        try:
            result = await self._ssh_manager.execute(asset_id, cmd_str, timeout=timeout)
            return CommandOutput(
                stdout=result.stdout,
                stderr=result.stderr,
                returncode=result.exit_code,
                asset_id=asset_id,
            )
        except Exception as e:
            logger.error(f"Remote command failed on asset '{asset_id}': {e}")
            return CommandOutput(
                stderr=str(e),
                returncode=-1,
                asset_id=asset_id,
            )

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
