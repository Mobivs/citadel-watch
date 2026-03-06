"""Citadel Archer — Local Host Protection module.

Provides LocalHostDefender: subprocess-based command execution for the
Windows machine running Citadel Guardian itself. No SSH required.
"""

from .local_defender import LocalHostDefender, LocalCommandResult

__all__ = ["LocalHostDefender", "LocalCommandResult"]
