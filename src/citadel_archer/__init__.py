# PRD: Citadel Archer - Main Package
# Reference: docs/PRD.md v0.2.2
#
# Citadel Archer: AI-centric defensive security platform
# Version: 0.2.2 (Phase 1 - Foundation)
#
# "If we're asking 'Should I block this malware?' we've already FAILED."
# - Proactive protection that acts first, informs after.

__version__ = "0.2.2"
__author__ = "Citadel Archer Team"
__description__ = "AI-centric defensive security platform"

from .core import (
    SecurityLevel,
    SecurityLevelManager,
    get_security_manager,
    EventType,
    EventSeverity,
    get_audit_logger,
)

__all__ = [
    "__version__",
    "SecurityLevel",
    "SecurityLevelManager",
    "get_security_manager",
    "EventType",
    "EventSeverity",
    "get_audit_logger",
]
