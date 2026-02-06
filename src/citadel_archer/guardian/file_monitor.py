# PRD: Guardian Module - File Monitoring
# Reference: docs/PRD.md v0.2.2, Section: Guardian - Local Machine Protection
#
# Real-time filesystem monitoring (unauthorized changes, suspicious binaries)
# PRD Technical Approach: "Using watchdog library for real-time events"
#
# Monitors critical system directories:
# - System32, Program Files
# - User startup folders
# - Browser extension directories
# - Downloads folder (optional, user-configurable)

import os
import time
from pathlib import Path
from typing import List, Optional, Set
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from ..core import (
    EventType,
    EventSeverity,
    get_audit_logger,
    get_security_manager,
    SecurityLevel,
)


class SuspiciousFilePatterns:
    """
    Known suspicious file patterns and indicators.

    PRD: "Detects suspicious binaries (unsigned .exe, double extensions)"
    """

    # Double extensions (e.g., invoice.pdf.exe)
    DOUBLE_EXTENSIONS = [
        ".pdf.exe", ".doc.exe", ".xls.exe", ".jpg.exe", ".png.exe",
        ".txt.exe", ".zip.exe", ".rar.exe", ".scr", ".pif", ".com"
    ]

    # Suspicious file names (case-insensitive)
    SUSPICIOUS_NAMES = [
        "crack", "keygen", "patch", "loader", "injector",
        "cryptor", "miner", "backdoor", "shell", "payload",
        "mimikatz", "metasploit", "cobalt", "empire"
    ]

    # Executable extensions
    EXECUTABLE_EXTENSIONS = [
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd",
        ".ps1", ".vbs", ".js", ".jar", ".com", ".pif"
    ]

    @classmethod
    def is_suspicious_extension(cls, filename: str) -> bool:
        """Check if file has double or suspicious extension."""
        filename_lower = filename.lower()
        return any(ext in filename_lower for ext in cls.DOUBLE_EXTENSIONS)

    @classmethod
    def is_suspicious_name(cls, filename: str) -> bool:
        """Check if filename contains suspicious keywords."""
        filename_lower = filename.lower()
        return any(keyword in filename_lower for keyword in cls.SUSPICIOUS_NAMES)

    @classmethod
    def is_executable(cls, filename: str) -> bool:
        """Check if file is an executable."""
        return any(filename.lower().endswith(ext) for ext in cls.EXECUTABLE_EXTENSIONS)


class GuardianFileEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler for file system monitoring.

    PRD: "Real-time filesystem monitoring (unauthorized changes, suspicious binaries)"
    PRD UX: "AI acts FIRST (>95% confidence), informs AFTER"
    """

    def __init__(self, monitor: 'FileMonitor'):
        super().__init__()
        self.monitor = monitor
        self.audit_logger = get_audit_logger()
        self.security_manager = get_security_manager()

    def on_created(self, event: FileSystemEvent):
        """Handle file creation events."""
        if event.is_directory:
            return

        file_path = event.src_path
        self._analyze_file(file_path, EventType.FILE_CREATED)

    def on_modified(self, event: FileSystemEvent):
        """Handle file modification events."""
        if event.is_directory:
            return

        file_path = event.src_path
        self._analyze_file(file_path, EventType.FILE_MODIFIED)

    def on_deleted(self, event: FileSystemEvent):
        """Handle file deletion events."""
        if event.is_directory:
            return

        file_path = event.src_path
        self.audit_logger.log_guardian_event(
            event_type=EventType.FILE_DELETED,
            target=file_path,
            severity=EventSeverity.INFO,
            details={"monitored_path": self.monitor.get_monitored_paths()}
        )

    def _analyze_file(self, file_path: str, event_type: EventType):
        """
        Analyze file for suspicious characteristics.

        PRD Proactive Protection: "AI acts FIRST (>95% confidence), informs AFTER"
        """
        filename = os.path.basename(file_path)
        is_suspicious = False
        reasons = []
        confidence = 0.0

        # Check 1: Double extensions (high confidence malware indicator)
        if SuspiciousFilePatterns.is_suspicious_extension(filename):
            is_suspicious = True
            reasons.append("Double file extension (common malware technique)")
            confidence = max(confidence, 0.98)

        # Check 2: Suspicious filename keywords
        if SuspiciousFilePatterns.is_suspicious_name(filename):
            is_suspicious = True
            reasons.append("Suspicious filename detected")
            confidence = max(confidence, 0.85)

        # Check 3: Executable in sensitive directory
        if SuspiciousFilePatterns.is_executable(filename):
            if self._is_sensitive_directory(file_path):
                is_suspicious = True
                reasons.append("Executable created in sensitive directory")
                confidence = max(confidence, 0.90)

        # Log event
        severity = EventSeverity.ALERT if is_suspicious else EventSeverity.INFO

        event_id = self.audit_logger.log_guardian_event(
            event_type=event_type,
            target=file_path,
            severity=severity,
            details={
                "filename": filename,
                "is_suspicious": is_suspicious,
                "reasons": reasons,
                "confidence": confidence
            }
        )

        # Take action if suspicious and security level allows
        if is_suspicious and confidence >= 0.95:
            self._handle_suspicious_file(file_path, reasons, confidence, event_id)

    def _handle_suspicious_file(
        self,
        file_path: str,
        reasons: List[str],
        confidence: float,
        event_id: str
    ):
        """
        Handle suspicious file detection.

        PRD: "Auto-respond to known threats" (Guardian/Sentinel levels)
        PRD UX: "I blocked it. You're safe." NOT "Should I block this?"
        """
        security_level = self.security_manager.current_level

        # Observer: Alert only, no action
        if security_level == SecurityLevel.OBSERVER:
            self.audit_logger.log_ai_decision(
                action="alert_only",
                confidence=confidence,
                reasoning=f"Suspicious file detected: {', '.join(reasons)}",
                evidence={"file_path": file_path, "event_id": event_id},
                security_level=security_level.value
            )
            return

        # Guardian/Sentinel: Take action (quarantine)
        if security_level in (SecurityLevel.GUARDIAN, SecurityLevel.SENTINEL):
            try:
                # Quarantine file (move to quarantine directory)
                quarantine_path = self.monitor.quarantine_file(file_path)

                self.audit_logger.log_ai_decision(
                    action="quarantine_file",
                    confidence=confidence,
                    reasoning=(
                        f"I quarantined a suspicious file. {reasons[0]}. "
                        f"The file has been moved to a secure location and "
                        f"can't harm your system. You're safe."
                    ),
                    evidence={
                        "original_path": file_path,
                        "quarantine_path": quarantine_path,
                        "reasons": reasons,
                        "event_id": event_id
                    },
                    security_level=security_level.value
                )

                # Log quarantine action
                self.audit_logger.log_guardian_event(
                    event_type=EventType.FILE_QUARANTINED,
                    target=file_path,
                    action="quarantined",
                    severity=EventSeverity.ALERT,
                    details={
                        "quarantine_path": quarantine_path,
                        "reasons": reasons,
                        "confidence": confidence
                    }
                )

            except Exception as e:
                # Log failure
                self.audit_logger.log_event(
                    event_type=EventType.AI_DECISION,
                    severity=EventSeverity.CRITICAL,
                    message=f"Failed to quarantine suspicious file: {str(e)}",
                    details={
                        "file_path": file_path,
                        "error": str(e)
                    }
                )

    def _is_sensitive_directory(self, file_path: str) -> bool:
        """Check if file is in a sensitive system directory."""
        sensitive_paths = [
            "\\Windows\\System32",
            "\\Windows\\SysWOW64",
            "\\Program Files",
            "\\Program Files (x86)",
            "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
        ]
        file_path_upper = file_path.upper()
        return any(sensitive in file_path_upper for sensitive in sensitive_paths)


class FileMonitor:
    """
    Guardian file monitoring system.

    PRD: "Real-time filesystem monitoring (unauthorized changes, suspicious binaries)"
    PRD: "Monitors critical system directories (System32, Program Files, etc.)"

    Features:
    - Real-time file system event monitoring
    - Suspicious file detection
    - Automatic quarantine (Guardian/Sentinel levels)
    - Audit logging for all events
    """

    def __init__(self, quarantine_dir: Optional[Path] = None):
        """
        Initialize file monitor.

        Args:
            quarantine_dir: Directory for quarantined files (default: ./quarantine)
        """
        self.quarantine_dir = quarantine_dir or Path("./quarantine")
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.observer = Observer()
        self.event_handler = GuardianFileEventHandler(self)
        self.monitored_paths: Set[str] = set()
        self.is_running = False

    def get_default_monitored_paths(self) -> List[str]:
        """
        Get default critical directories to monitor on Windows.

        PRD: "Monitors critical system directories (System32, Program Files, etc.)"
        """
        system_root = os.getenv("SystemRoot", "C:\\Windows")
        program_files = os.getenv("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.getenv("ProgramFiles(x86)", "C:\\Program Files (x86)")
        appdata = os.getenv("APPDATA", "")
        userprofile = os.getenv("USERPROFILE", "")

        paths = [
            # Critical system directories
            os.path.join(system_root, "System32"),
            os.path.join(system_root, "SysWOW64"),
            program_files,
            program_files_x86,
        ]

        # User-specific directories (if available)
        if appdata:
            paths.extend([
                os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
                # Browser extensions (common attack vector)
                os.path.join(appdata, "..\\Local\\Google\\Chrome\\User Data"),
                os.path.join(appdata, "..\\Roaming\\Mozilla\\Firefox\\Profiles"),
            ])

        # User Downloads (enabled for testing)
        if userprofile:
            downloads = os.path.join(userprofile, "Downloads")
            paths.append(downloads)  # Monitor Downloads for suspicious files

        # Filter to existing paths only
        return [p for p in paths if os.path.exists(p)]

    def add_monitored_path(self, path: str):
        """Add a path to monitor."""
        if os.path.exists(path) and path not in self.monitored_paths:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.monitored_paths.add(path)
            get_audit_logger().log_event(
                event_type=EventType.SYSTEM_START,
                severity=EventSeverity.INFO,
                message=f"Started monitoring: {path}"
            )

    def get_monitored_paths(self) -> List[str]:
        """Get list of currently monitored paths."""
        return list(self.monitored_paths)

    def start(self, paths: Optional[List[str]] = None):
        """
        Start file monitoring.

        Args:
            paths: List of paths to monitor (default: critical system directories)
        """
        if self.is_running:
            return

        # Use provided paths or defaults
        paths_to_monitor = paths or self.get_default_monitored_paths()

        # Add all paths
        for path in paths_to_monitor:
            self.add_monitored_path(path)

        # Start observer
        self.observer.start()
        self.is_running = True

        get_audit_logger().log_event(
            event_type=EventType.SYSTEM_START,
            severity=EventSeverity.INFO,
            message="Guardian file monitoring started",
            details={"monitored_paths": list(self.monitored_paths)}
        )

    def stop(self):
        """Stop file monitoring."""
        if not self.is_running:
            return

        self.observer.stop()
        self.observer.join()
        self.is_running = False

        get_audit_logger().log_event(
            event_type=EventType.SYSTEM_STOP,
            severity=EventSeverity.INFO,
            message="Guardian file monitoring stopped"
        )

    def quarantine_file(self, file_path: str) -> str:
        """
        Move suspicious file to quarantine directory.

        Args:
            file_path: Path to suspicious file

        Returns:
            str: New path in quarantine directory

        PRD: "Can quarantine files (respects security levels)"
        """
        import shutil
        from datetime import datetime

        # Generate quarantine filename with timestamp
        original_name = os.path.basename(file_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_name = f"{timestamp}_{original_name}"
        quarantine_path = self.quarantine_dir / quarantine_name

        # Move file to quarantine
        shutil.move(file_path, quarantine_path)

        return str(quarantine_path)
