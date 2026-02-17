# Remote Operations Module
# Phase 2.6: SSH Connection Manager for managed assets
# Phase 2.9: Remote Shield persistent database

from .ssh_manager import SSHConnectionManager
from .shield_database import RemoteShieldDatabase

__all__ = ["SSHConnectionManager", "RemoteShieldDatabase"]
