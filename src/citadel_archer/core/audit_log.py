# PRD: Guardian - Logging & Forensics
# Reference: docs/PRD.md v0.2.2, Section: Guardian Module
#
# Implements immutable audit logging for all security events.
# PRD Requirement: "Immutable audit log (append-only, encrypted)"
# All Guardian events (file, process, network) must be logged with timestamps,
# user context, and AI decisions for forensic analysis.

import json
import logging
import sys
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

import structlog
from .log_throttle import get_log_throttler


class EventType(str, Enum):
    """
    Types of security events that can be logged.

    PRD: "All Guardian events logged (file, process, network)"
    """
    # Guardian Events
    FILE_CREATED = "file.created"
    FILE_MODIFIED = "file.modified"
    FILE_DELETED = "file.deleted"
    FILE_QUARANTINED = "file.quarantined"

    PROCESS_STARTED = "process.started"
    PROCESS_KILLED = "process.killed"
    PROCESS_SUSPICIOUS = "process.suspicious"

    NETWORK_CONNECTION = "network.connection"
    NETWORK_BLOCKED = "network.blocked"

    # AI Decisions
    AI_DECISION = "ai.decision"
    AI_ALERT = "ai.alert"

    # Vault Events
    VAULT_CREATED = "vault.created"
    VAULT_UNLOCKED = "vault.unlocked"
    VAULT_LOCKED = "vault.locked"
    VAULT_UNLOCK_FAILED = "vault.unlock.failed"
    VAULT_PASSWORD_ADDED = "vault.password.added"
    VAULT_PASSWORD_ACCESSED = "vault.password.accessed"
    VAULT_PASSWORD_DELETED = "vault.password.deleted"
    VAULT_ERROR = "vault.error"

    # System Events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    SECURITY_LEVEL_CHANGED = "security.level.changed"

    # User Actions
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_OVERRIDE = "user.override"

    # Backup Events
    BACKUP_CREATED = "backup.created"
    BACKUP_RESTORED = "backup.restored"
    BACKUP_DELETED = "backup.deleted"

    # Mesh Events (v0.3.35)
    MESH_PEER_ONLINE = "mesh.peer.online"
    MESH_PEER_OFFLINE = "mesh.peer.offline"
    MESH_ESCALATION = "mesh.escalation"
    MESH_RECOVERY = "mesh.recovery"


class EventSeverity(str, Enum):
    """
    Severity levels for security events.

    Maps to PRD alert levels:
    - 🟢 INFO: Normal activity, no alert needed (logged only)
    - 🟡 INVESTIGATE: AI is checking something unusual
    - 🟠 ALERT: AI took action (blocked, quarantined)
    - 🔴 CRITICAL: User decision required
    """
    INFO = "info"
    INVESTIGATE = "investigate"
    ALERT = "alert"
    CRITICAL = "critical"

    def to_emoji(self) -> str:
        """Convert severity to emoji for UI display."""
        emoji_map = {
            EventSeverity.INFO: "🟢",
            EventSeverity.INVESTIGATE: "🟡",
            EventSeverity.ALERT: "🟠",
            EventSeverity.CRITICAL: "🔴"
        }
        return emoji_map[self]


_structlog_configured = False
_file_handler_dates: set = set()


class AuditLogger:
    """
    Immutable, append-only audit logger for security events.

    PRD Requirements:
    - Immutable audit log (append-only)
    - Logs include timestamps, user context, AI decisions
    - Logs stored encrypted
    - All security decisions logged

    Features:
    - Structured JSON logging
    - Automatic timestamp and event ID
    - User and system context capture
    - Encryption support (TODO: Phase 1)
    - Forensic query support
    - Event callbacks for real-time forwarding (e.g. to EventAggregator)
    """

    def __init__(self, log_dir: Optional[Path] = None, encrypt: bool = False):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for audit logs (default: ./audit_logs)
            encrypt: Whether to encrypt logs (Phase 1: planned)
        """
        self.log_dir = log_dir or Path("./audit_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.encrypt = encrypt
        self._event_callbacks = []

        # Configure structlog only once per process
        global _structlog_configured
        if not _structlog_configured:
            structlog.configure(
                processors=[
                    structlog.stdlib.add_log_level,
                    structlog.stdlib.add_logger_name,
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                    structlog.processors.JSONRenderer()
                ],
                wrapper_class=structlog.stdlib.BoundLogger,
                context_class=dict,
                logger_factory=structlog.stdlib.LoggerFactory(),
                cache_logger_on_first_use=True,
            )
            _structlog_configured = True

        # Create daily log file (only add handler once per date)
        self._setup_file_handler()

        self.logger = structlog.get_logger("citadel_archer.audit")

    def on_event(self, callback) -> None:
        """Register a callback invoked after every logged event.

        The callback receives a dict with event_type, severity, message,
        timestamp, and details keys.
        """
        self._event_callbacks.append(callback)

    def _setup_file_handler(self):
        """Setup rotating file handler for daily logs.

        Only adds one handler per date per process to prevent
        duplicate log entries when multiple AuditLogger instances
        are created.
        """
        global _file_handler_dates
        today = datetime.now().strftime("%Y-%m-%d")
        handler_key = f"{self.log_dir}:{today}"

        if handler_key in _file_handler_dates:
            return  # Already configured for this date + dir

        log_file = self.log_dir / f"audit_{today}.log"

        # Configure Python's logging to write to file
        file_handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')  # structlog handles formatting
        file_handler.setFormatter(formatter)

        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)
        root_logger.setLevel(logging.INFO)

        _file_handler_dates.add(handler_key)

    def log_event(
        self,
        event_type: EventType,
        severity: EventSeverity,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        ai_decision: Optional[Dict[str, Any]] = None,
        user_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log a security event (immutable, append-only).

        Args:
            event_type: Type of event (from EventType enum)
            severity: Severity level (from EventSeverity enum)
            message: Human-readable event description
            details: Additional event details
            ai_decision: AI decision details (action, confidence, reasoning)
            user_context: User context (username, session_id, etc.)

        Returns:
            str: Event ID (UUID) for reference

        PRD: "Logs include timestamps, user context, AI decisions"
        """
        event_id = str(uuid4())
        
        # Check for throttling if this looks like a rate limit message
        throttler = get_log_throttler()
        
        # Identify agent ID from context or details
        agent_id = "system"
        if details and "agent_id" in details:
            agent_id = details["agent_id"]
        elif user_context and "agent_id" in user_context:
            agent_id = user_context["agent_id"]
        
        # Check if this message should be throttled
        should_log, summary_msg = throttler.should_log(
            agent_id=agent_id,
            message=message,
            severity=severity.value
        )
        
        # If throttled, return early (but still generate an event ID)
        if not should_log:
            if summary_msg:
                # Log the summary message
                self.logger.info("throttle_summary", message=summary_msg)
            return event_id

        event_data = {
            "event_id": event_id,
            "event_type": event_type.value,
            "severity": severity.value,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
            "ai_decision": ai_decision,
            "user_context": user_context or self._get_default_user_context(),
        }
        
        # Add summary of previously suppressed messages if any
        if summary_msg:
            event_data["throttle_note"] = summary_msg

        # Log to structured log
        self.logger.info(
            "security_event",
            **event_data
        )

        # Notify registered callbacks (e.g. EventAggregator)
        for cb in self._event_callbacks:
            try:
                cb(event_data)
            except Exception:
                pass  # best-effort — never break logging

        return event_id

    def log_ai_decision(
        self,
        action: str,
        confidence: float,
        reasoning: str,
        evidence: Optional[Dict[str, Any]] = None,
        security_level: str = "guardian"
    ) -> str:
        """
        Log an AI security decision.

        PRD Principle: "Every security decision goes through AI analysis"
        PRD Code Standard: "Audit logging for all security decisions"

        Args:
            action: Action taken by AI (e.g., "blocked_process", "quarantined_file")
            confidence: AI confidence level (0.0 to 1.0)
            reasoning: Plain-language explanation of decision
            evidence: Supporting evidence for decision
            security_level: Current security level

        Returns:
            str: Event ID
        """
        ai_decision = {
            "action": action,
            "confidence": confidence,
            "reasoning": reasoning,
            "evidence": evidence or {},
            "security_level": security_level,
            "autonomous": confidence >= 0.95  # PRD: "AI acts FIRST (>95% confidence)"
        }

        severity = EventSeverity.ALERT if confidence >= 0.95 else EventSeverity.INVESTIGATE

        return self.log_event(
            event_type=EventType.AI_DECISION,
            severity=severity,
            message=f"AI Decision: {action} (confidence: {confidence:.2%})",
            ai_decision=ai_decision
        )

    def log_guardian_event(
        self,
        event_type: EventType,
        target: str,
        action: Optional[str] = None,
        severity: EventSeverity = EventSeverity.INFO,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log a Guardian monitoring event (file, process, network).

        Args:
            event_type: Type of Guardian event
            target: Target of event (file path, process name, IP address)
            action: Action taken (if any)
            severity: Event severity
            details: Additional details

        Returns:
            str: Event ID
        """
        message = f"Guardian: {event_type.value} - {target}"
        if action:
            message += f" (action: {action})"

        event_details = details or {}
        event_details["target"] = target
        if action:
            event_details["action"] = action

        return self.log_event(
            event_type=event_type,
            severity=severity,
            message=message,
            details=event_details
        )

    def log_vault_event(
        self,
        event_type: EventType,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Log a Vault security event.

        Vault events are always logged (password access, unlock, etc.)

        Args:
            event_type: Type of Vault event
            message: Event description
            details: Additional details (never log actual passwords!)

        Returns:
            str: Event ID
        """
        return self.log_event(
            event_type=event_type,
            severity=EventSeverity.INFO,
            message=f"Vault: {message}",
            details=details
        )

    def _get_default_user_context(self) -> Dict[str, Any]:
        """Get default user context (OS user, hostname, etc.)."""
        import socket
        import os

        return {
            "os_user": os.getenv("USERNAME") or os.getenv("USER"),
            "hostname": socket.gethostname(),
            "platform": sys.platform,
        }

    def query_events(
        self,
        event_types: Optional[list] = None,
        severity: Optional[EventSeverity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        Query audit logs (forensic analysis).

        Reads daily JSON log files, filters by criteria, and returns
        matching events sorted newest-first.

        Args:
            event_types: Filter by event types
            severity: Filter by severity level
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Maximum number of events to return

        Returns:
            list: Matching events (newest first)
        """
        results = []
        # Over-read slightly so that after time-based filtering we still
        # have enough entries to satisfy the requested limit.
        read_cap = limit + 50

        # Determine which log files to scan
        log_files = sorted(self.log_dir.glob("audit_*.log"), reverse=True)

        # Convert event_types to string values for comparison
        type_values = None
        if event_types:
            type_values = set()
            for et in event_types:
                type_values.add(et.value if isinstance(et, EventType) else str(et))

        severity_value = None
        if severity:
            severity_value = severity.value if isinstance(severity, EventSeverity) else str(severity)

        for log_file in log_files:
            # Quick date-range filter based on filename (audit_YYYY-MM-DD.log)
            try:
                file_date_str = log_file.stem.replace("audit_", "")
                file_date = datetime.strptime(file_date_str, "%Y-%m-%d")
                if start_time and file_date.date() < start_time.date():
                    continue
                if end_time and file_date.date() > end_time.date():
                    continue
            except ValueError:
                pass  # Non-standard filename, scan anyway

            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        # Only include security_event entries
                        if entry.get("event") != "security_event":
                            continue

                        # Filter by event_type
                        if type_values and entry.get("event_type") not in type_values:
                            continue

                        # Filter by severity
                        if severity_value and entry.get("severity") != severity_value:
                            continue

                        # Filter by time range (strip tzinfo for comparison
                        # since stored timestamps are naive UTC)
                        ts = entry.get("timestamp")
                        if ts:
                            try:
                                event_time = datetime.fromisoformat(ts)
                                # Normalize to naive UTC for comparison
                                if event_time.tzinfo is not None:
                                    event_time = event_time.replace(tzinfo=None)
                                st = start_time.replace(tzinfo=None) if start_time and start_time.tzinfo else start_time
                                et = end_time.replace(tzinfo=None) if end_time and end_time.tzinfo else end_time
                                if st and event_time < st:
                                    continue
                                if et and event_time > et:
                                    continue
                            except (ValueError, TypeError):
                                pass

                        results.append(entry)

                        if len(results) >= read_cap:
                            break
            except OSError:
                continue

            if len(results) >= read_cap:
                break

        # Sort by timestamp descending and apply limit
        results.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return results[:limit]


# Global logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get global audit logger (singleton pattern)."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def log_security_event(
    event_type: EventType,
    severity: EventSeverity,
    message: str,
    **kwargs
) -> str:
    """
    Convenience function for logging security events.

    Usage:
        log_security_event(
            EventType.PROCESS_KILLED,
            EventSeverity.ALERT,
            "Blocked cryptocurrency miner",
            details={"process": "cryptominer.exe", "pid": 1234}
        )
    """
    return get_audit_logger().log_event(event_type, severity, message, **kwargs)
