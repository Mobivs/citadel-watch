# PRD: Core Architecture - Security Levels
# Reference: docs/PRD.md v0.2.2, Section: AI-Centric Architecture
#
# Implements the three security levels that determine AI autonomy:
# - Observer: Monitor and alert only, no autonomous actions
# - Guardian: Auto-respond to known threats (default, recommended)
# - Sentinel: Maximum AI autonomy within ethical bounds

from enum import Enum
from typing import Optional


class SecurityLevel(str, Enum):
    """
    Defines the level of autonomy granted to the AI agent.

    PRD Requirement: "Security levels control how much autonomy the AI has"

    Levels:
    - OBSERVER: AI monitors and alerts, takes NO autonomous actions
      Use case: Maximum user control, learning mode, paranoid users

    - GUARDIAN: AI auto-responds to known threats (RECOMMENDED)
      Use case: Balanced protection, blocks malware/C2, asks on ambiguity

    - SENTINEL: AI has maximum autonomy within ethical bounds
      Use case: Advanced users, trusted AI, proactive threat hunting
    """

    OBSERVER = "observer"
    GUARDIAN = "guardian"
    SENTINEL = "sentinel"

    @property
    def can_block_processes(self) -> bool:
        """Can the AI kill processes autonomously?"""
        return self in (SecurityLevel.GUARDIAN, SecurityLevel.SENTINEL)

    @property
    def can_quarantine_files(self) -> bool:
        """Can the AI quarantine suspicious files autonomously?"""
        return self in (SecurityLevel.GUARDIAN, SecurityLevel.SENTINEL)

    @property
    def can_modify_firewall(self) -> bool:
        """Can the AI modify firewall rules autonomously?"""
        return self == SecurityLevel.SENTINEL

    @property
    def can_install_updates(self) -> bool:
        """Can the AI install security updates autonomously?"""
        return self == SecurityLevel.SENTINEL

    @property
    def requires_user_confirmation(self) -> bool:
        """Does this level require user confirmation for actions?"""
        return self == SecurityLevel.OBSERVER

    @property
    def description(self) -> str:
        """User-friendly description of security level."""
        descriptions = {
            SecurityLevel.OBSERVER: (
                "Monitor only mode. I'll watch and alert you about threats, "
                "but you'll decide on all actions. Maximum user control."
            ),
            SecurityLevel.GUARDIAN: (
                "Balanced protection (recommended). I'll automatically block known threats "
                "like malware and C2 servers, but ask you about ambiguous situations."
            ),
            SecurityLevel.SENTINEL: (
                "Maximum AI autonomy. I'll proactively hunt threats, install updates, "
                "and take all defensive actions within ethical bounds. For advanced users."
            )
        }
        return descriptions[self]

    def can_take_action(self, action_type: str, confidence: float = 1.0) -> bool:
        """
        Determines if the AI can take a specific action at this security level.

        Args:
            action_type: Type of action (e.g., 'block_process', 'quarantine_file')
            confidence: AI confidence level (0.0 to 1.0)

        Returns:
            bool: True if action is permitted, False otherwise

        PRD Principle: "AI acts FIRST (>95% confidence), informs AFTER"
        """
        # Observer: No autonomous actions regardless of confidence
        if self == SecurityLevel.OBSERVER:
            return False

        # Guardian: High-confidence actions on known threats
        if self == SecurityLevel.GUARDIAN:
            high_confidence_actions = {
                'block_process', 'quarantine_file', 'block_network',
                'alert_user', 'log_event'
            }
            return action_type in high_confidence_actions and confidence >= 0.95

        # Sentinel: Maximum autonomy
        if self == SecurityLevel.SENTINEL:
            # Only restrict truly destructive actions
            forbidden_actions = {'delete_system_files', 'format_drive', 'expose_secrets'}
            return action_type not in forbidden_actions

        return False

    @classmethod
    def from_string(cls, level: str) -> "SecurityLevel":
        """Parse security level from string (case-insensitive)."""
        try:
            return cls(level.lower())
        except ValueError:
            # Default to Guardian if invalid
            return cls.GUARDIAN

    def __str__(self) -> str:
        return self.value.capitalize()


class SecurityLevelManager:
    """
    Manages security level configuration and validation.

    PRD Requirement: "User control - users explicitly choose security level during onboarding"
    """

    def __init__(self, initial_level: SecurityLevel = SecurityLevel.GUARDIAN):
        """
        Initialize with default Guardian level (recommended).

        Args:
            initial_level: Starting security level (default: Guardian)
        """
        self._level = initial_level
        self._change_history = []

    @property
    def current_level(self) -> SecurityLevel:
        """Get current security level."""
        return self._level

    def set_level(self, new_level: SecurityLevel, reason: str = "") -> None:
        """
        Change security level (requires explicit action).

        Args:
            new_level: New security level to apply
            reason: Reason for change (for audit log)
        """
        if new_level != self._level:
            self._change_history.append({
                'from': self._level,
                'to': new_level,
                'reason': reason,
                'timestamp': None  # Will be set by audit logger
            })
            self._level = new_level

    def can_escalate_privileges(self) -> bool:
        """
        Check if current level allows privilege escalation.

        PRD: "Sentinel can install updates and modify system settings"
        """
        return self._level == SecurityLevel.SENTINEL

    def get_recommended_level_for_user(self, user_experience: str) -> SecurityLevel:
        """
        Recommend security level based on user experience.

        Args:
            user_experience: 'beginner', 'intermediate', 'advanced'

        Returns:
            Recommended SecurityLevel
        """
        recommendations = {
            'beginner': SecurityLevel.GUARDIAN,
            'intermediate': SecurityLevel.GUARDIAN,
            'advanced': SecurityLevel.SENTINEL
        }
        return recommendations.get(user_experience.lower(), SecurityLevel.GUARDIAN)


# Global instance (will be initialized from config on app start)
_security_manager: Optional[SecurityLevelManager] = None


def get_security_manager() -> SecurityLevelManager:
    """Get global security level manager (singleton pattern)."""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityLevelManager()
    return _security_manager


def require_security_level(*required_levels: SecurityLevel):
    """
    Decorator to enforce security level requirements on functions.

    Usage:
        @require_security_level(SecurityLevel.GUARDIAN, SecurityLevel.SENTINEL)
        def block_malicious_process():
            ...

    PRD: "Security levels must be respected in ALL code"
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            current = get_security_manager().current_level
            if current not in required_levels:
                raise PermissionError(
                    f"Action requires security level {required_levels}, "
                    f"but current level is {current}"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
