# PRD: Core Module - Shared Utilities
# Reference: docs/PRD.md v0.2.2, Section: Technical Architecture
#
# Core module provides shared functionality across all Citadel Archer modules:
# - Security level management
# - Audit logging
# - Configuration
# - Encryption utilities

from .audit_log import (
    AuditLogger,
    EventSeverity,
    EventType,
    get_audit_logger,
    log_security_event,
)
from .security_levels import (
    SecurityLevel,
    SecurityLevelManager,
    get_security_manager,
    require_security_level,
)

__all__ = [
    # Security Levels
    "SecurityLevel",
    "SecurityLevelManager",
    "get_security_manager",
    "require_security_level",
    # Audit Logging
    "AuditLogger",
    "EventType",
    "EventSeverity",
    "get_audit_logger",
    "log_security_event",
]
