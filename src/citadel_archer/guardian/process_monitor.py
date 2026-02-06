# PRD: Guardian Module - Process Monitoring
# Reference: docs/PRD.md v0.2.2, Section: Guardian - Local Machine Protection
#
# Real-time process monitoring (crypto miners, keyloggers, privilege escalation)
# PRD Technical Approach: "Using psutil for process context"
#
# Monitors:
# - Suspicious processes (crypto miners, keyloggers, RATs)
# - Privilege escalation attempts
# - Parent/child process relationships
# - Network connections from processes

import os
import time
import psutil
import threading
from typing import Dict, List, Optional, Set
from datetime import datetime

from ..core import (
    EventType,
    EventSeverity,
    get_audit_logger,
    get_security_manager,
    SecurityLevel,
)


class SuspiciousProcessPatterns:
    """
    Known suspicious process patterns and indicators.

    PRD: "Detects suspicious processes (crypto miners, keyloggers)"
    """

    # Known malicious process names (case-insensitive)
    MALICIOUS_NAMES = [
        "mimikatz", "psexec", "procdump", "pwdump",
        "keylogger", "keylog", "keystroke",
        "cryptominer", "xmrig", "ethminer", "claymore",
        "coinminer", "minergate", "nicehash",
        "backdoor", "netcat", "nc.exe", "ncat",
        "cobaltstr like", "metasploit", "meterpreter",
        "empire", "covenant", "sliver"
    ]

    # Suspicious command-line patterns
    SUSPICIOUS_CMDLINE_PATTERNS = [
        "powershell.exe -enc",  # Encoded PowerShell
        "powershell -w hidden",  # Hidden window
        "cmd.exe /c echo",  # Command injection
        "wscript.exe",  # VBScript execution
        "cscript.exe",  # VBScript execution
        "rundll32.exe javascript:",  # DLL hijacking
        "regsvr32.exe /s /u /i:",  # Squiblydoo technique
        "mshta.exe http",  # MSHTA abuse
        "certutil -decode",  # File download
        "bitsadmin /transfer",  # File download
        "invoke-webrequest",  # PowerShell download
        "downloadstring",  # PowerShell download
        "start-process",  # Process spawning
        "-nop -w hidden -c",  # Obfuscated PowerShell
    ]

    # High CPU usage threshold (potential crypto miner)
    HIGH_CPU_THRESHOLD = 80.0  # 80% CPU usage
    HIGH_CPU_DURATION = 60  # seconds

    @classmethod
    def is_malicious_name(cls, process_name: str) -> bool:
        """Check if process name matches known malware."""
        process_name_lower = process_name.lower()
        return any(malware in process_name_lower for malware in cls.MALICIOUS_NAMES)

    @classmethod
    def has_suspicious_cmdline(cls, cmdline: str) -> bool:
        """Check if command line contains suspicious patterns."""
        if not cmdline:
            return False
        cmdline_lower = cmdline.lower()
        return any(pattern.lower() in cmdline_lower for pattern in cls.SUSPICIOUS_CMDLINE_PATTERNS)

    @classmethod
    def is_suspicious_parent_child(cls, parent_name: str, child_name: str) -> bool:
        """
        Check for suspicious parent-child relationships.

        Examples:
        - Word/Excel spawning PowerShell (macro malware)
        - Browser spawning cmd.exe (exploit)
        """
        parent_lower = parent_name.lower()
        child_lower = child_name.lower()

        suspicious_combos = [
            # Office apps spawning scripts/shells
            (("winword", "excel", "powerpnt"), ("powershell", "cmd", "wscript", "cscript")),
            # Browser spawning shells
            (("chrome", "firefox", "edge", "iexplore"), ("cmd", "powershell")),
            # Explorer spawning unusual processes
            (("explorer",), ("regsvr32", "rundll32", "mshta")),
        ]

        for parents, children in suspicious_combos:
            if any(p in parent_lower for p in parents) and any(c in child_lower for c in children):
                return True

        return False


class ProcessMonitor:
    """
    Guardian process monitoring system.

    PRD: "Real-time process monitoring (crypto miners, keyloggers, privilege escalation)"
    PRD: "Can kill processes (respects security levels)"

    Features:
    - Real-time process scanning
    - Suspicious process detection
    - Automatic process termination (Guardian/Sentinel levels)
    - Parent/child relationship tracking
    - High CPU usage detection (crypto miners)
    - Audit logging for all events
    """

    def __init__(self, scan_interval: int = 5):
        """
        Initialize process monitor.

        Args:
            scan_interval: Seconds between process scans (default: 5)
        """
        self.scan_interval = scan_interval
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.known_processes: Set[int] = set()  # PIDs we've already scanned
        self.high_cpu_processes: Dict[int, float] = {}  # PID -> start time of high CPU
        self.audit_logger = get_audit_logger()
        self.security_manager = get_security_manager()

    def start(self):
        """Start process monitoring in background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()

        self.audit_logger.log_event(
            event_type=EventType.SYSTEM_START,
            severity=EventSeverity.INFO,
            message="Guardian process monitoring started",
            details={"scan_interval": self.scan_interval}
        )

    def stop(self):
        """Stop process monitoring."""
        if not self.is_running:
            return

        self.is_running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)

        self.audit_logger.log_event(
            event_type=EventType.SYSTEM_STOP,
            severity=EventSeverity.INFO,
            message="Guardian process monitoring stopped"
        )

    def _monitor_loop(self):
        """Main monitoring loop (runs in background thread)."""
        while self.is_running:
            try:
                self._scan_processes()
            except Exception as e:
                self.audit_logger.log_event(
                    event_type=EventType.AI_ALERT,
                    severity=EventSeverity.INFO,
                    message=f"Process scan error: {str(e)}"
                )

            time.sleep(self.scan_interval)

    def _scan_processes(self):
        """Scan all running processes for suspicious activity."""
        current_processes = set()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'ppid']):
            try:
                pid = proc.info['pid']
                current_processes.add(pid)

                # Skip processes we've already analyzed
                if pid in self.known_processes:
                    # Check for sustained high CPU (crypto miner indicator)
                    self._check_high_cpu(proc)
                    continue

                # Analyze new process
                self._analyze_process(proc)
                self.known_processes.add(pid)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Process terminated or we don't have access
                continue

        # Clean up terminated processes from tracking
        terminated = self.known_processes - current_processes
        self.known_processes -= terminated
        for pid in terminated:
            self.high_cpu_processes.pop(pid, None)

    def _analyze_process(self, proc: psutil.Process):
        """
        Analyze a process for suspicious characteristics.

        PRD Proactive Protection: "AI acts FIRST (>95% confidence), informs AFTER"
        """
        try:
            info = proc.info
            pid = info['pid']
            name = info['name'] or "Unknown"
            cmdline = ' '.join(info['cmdline']) if info['cmdline'] else ""

            is_suspicious = False
            reasons = []
            confidence = 0.0

            # Check 1: Known malicious process name (very high confidence)
            if SuspiciousProcessPatterns.is_malicious_name(name):
                is_suspicious = True
                reasons.append(f"Known malicious process name: {name}")
                confidence = max(confidence, 0.99)

            # Check 2: Suspicious command line (high confidence)
            if SuspiciousProcessPatterns.has_suspicious_cmdline(cmdline):
                is_suspicious = True
                reasons.append("Suspicious command line detected")
                confidence = max(confidence, 0.95)

            # Check 3: Suspicious parent-child relationship (medium confidence)
            if info['ppid']:
                try:
                    parent = psutil.Process(info['ppid'])
                    parent_name = parent.name()
                    if SuspiciousProcessPatterns.is_suspicious_parent_child(parent_name, name):
                        is_suspicious = True
                        reasons.append(f"Suspicious spawn: {parent_name} → {name}")
                        confidence = max(confidence, 0.85)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            # Log event
            if is_suspicious:
                event_id = self.audit_logger.log_guardian_event(
                    event_type=EventType.PROCESS_SUSPICIOUS,
                    target=f"{name} (PID: {pid})",
                    severity=EventSeverity.ALERT,
                    details={
                        "pid": pid,
                        "name": name,
                        "cmdline": cmdline,
                        "reasons": reasons,
                        "confidence": confidence
                    }
                )

                # Take action if high confidence and security level allows
                if confidence >= 0.95:
                    self._handle_suspicious_process(proc, reasons, confidence, event_id)
            else:
                # Log normal process start (INFO level, for forensics)
                self.audit_logger.log_guardian_event(
                    event_type=EventType.PROCESS_STARTED,
                    target=f"{name} (PID: {pid})",
                    severity=EventSeverity.INFO,
                    details={"pid": pid, "name": name}
                )

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def _handle_suspicious_process(
        self,
        proc: psutil.Process,
        reasons: List[str],
        confidence: float,
        event_id: str
    ):
        """
        Handle suspicious process detection.

        PRD: "Can kill processes (respects security levels)"
        PRD UX: "I blocked it. You're safe." NOT "Should I kill this process?"
        """
        security_level = self.security_manager.current_level
        pid = proc.pid
        name = proc.name()

        # Observer: Alert only, no action
        if security_level == SecurityLevel.OBSERVER:
            self.audit_logger.log_ai_decision(
                action="alert_only",
                confidence=confidence,
                reasoning=f"Suspicious process detected: {', '.join(reasons)}",
                evidence={"process": name, "pid": pid, "event_id": event_id},
                security_level=security_level.value
            )
            return

        # Guardian/Sentinel: Take action (kill process)
        if security_level in (SecurityLevel.GUARDIAN, SecurityLevel.SENTINEL):
            try:
                # Terminate process
                proc.terminate()
                proc.wait(timeout=3)  # Wait for graceful termination

                # Force kill if still running
                if proc.is_running():
                    proc.kill()

                self.audit_logger.log_ai_decision(
                    action="kill_process",
                    confidence=confidence,
                    reasoning=(
                        f"I stopped a suspicious process. {reasons[0]}. "
                        f"The process has been terminated and can't harm your system. You're safe."
                    ),
                    evidence={
                        "process": name,
                        "pid": pid,
                        "reasons": reasons,
                        "event_id": event_id
                    },
                    security_level=security_level.value
                )

                # Log termination
                self.audit_logger.log_guardian_event(
                    event_type=EventType.PROCESS_KILLED,
                    target=f"{name} (PID: {pid})",
                    action="terminated",
                    severity=EventSeverity.ALERT,
                    details={
                        "pid": pid,
                        "reasons": reasons,
                        "confidence": confidence
                    }
                )

            except psutil.NoSuchProcess:
                # Process already terminated
                pass
            except Exception as e:
                # Log failure
                self.audit_logger.log_event(
                    event_type=EventType.AI_DECISION,
                    severity=EventSeverity.CRITICAL,
                    message=f"Failed to terminate suspicious process: {str(e)}",
                    details={
                        "process": name,
                        "pid": pid,
                        "error": str(e)
                    }
                )

    def _check_high_cpu(self, proc: psutil.Process):
        """
        Check for sustained high CPU usage (crypto miner indicator).

        PRD: "Detects crypto miners"
        """
        try:
            pid = proc.pid
            cpu_percent = proc.cpu_percent(interval=1.0)

            # Track high CPU processes
            if cpu_percent >= SuspiciousProcessPatterns.HIGH_CPU_THRESHOLD:
                if pid not in self.high_cpu_processes:
                    self.high_cpu_processes[pid] = time.time()
                else:
                    # Check duration
                    duration = time.time() - self.high_cpu_processes[pid]
                    if duration >= SuspiciousProcessPatterns.HIGH_CPU_DURATION:
                        # Sustained high CPU - potential crypto miner
                        self.audit_logger.log_event(
                            event_type=EventType.PROCESS_SUSPICIOUS,
                            severity=EventSeverity.INVESTIGATE,
                            message=f"Potential crypto miner: {proc.name()} (PID: {pid})",
                            details={
                                "pid": pid,
                                "name": proc.name(),
                                "cpu_percent": cpu_percent,
                                "duration": duration,
                                "reason": "Sustained high CPU usage"
                            }
                        )
                        # Don't track anymore (already alerted)
                        del self.high_cpu_processes[pid]
            else:
                # CPU dropped, stop tracking
                self.high_cpu_processes.pop(pid, None)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            self.high_cpu_processes.pop(proc.pid, None)

    def get_running_processes(self) -> List[Dict]:
        """
        Get list of all running processes (for Dashboard display).

        Returns:
            List of process info dictionaries
        """
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cpu_percent': proc.info['cpu_percent'],
                    'memory_percent': proc.info['memory_percent']
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes

    def kill_process(self, pid: int, reason: str = "User requested") -> bool:
        """
        Manually kill a process (user action).

        Args:
            pid: Process ID to kill
            reason: Reason for termination

        Returns:
            bool: True if successful, False otherwise

        PRD: "User control - users can override AI decisions"
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()

            proc.terminate()
            proc.wait(timeout=3)

            if proc.is_running():
                proc.kill()

            self.audit_logger.log_event(
                event_type=EventType.USER_OVERRIDE,
                severity=EventSeverity.INFO,
                message=f"User killed process: {name} (PID: {pid})",
                details={"pid": pid, "name": name, "reason": reason}
            )

            return True

        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            self.audit_logger.log_event(
                event_type=EventType.AI_ALERT,
                severity=EventSeverity.CRITICAL,
                message=f"Failed to kill process: {str(e)}",
                details={"pid": pid, "error": str(e)}
            )
            return False
