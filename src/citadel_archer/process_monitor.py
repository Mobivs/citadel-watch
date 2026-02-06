"""
T2.2: Process Monitoring Foundation
Real-time process monitoring using psutil.
"""

import psutil
from datetime import datetime
from typing import Callable, List, Dict
import threading
import time


class ProcessMonitor:
    """Monitor running processes for suspicious activity."""

    def __init__(self, on_event: Callable = None, scan_interval: int = 5):
        self.on_event = on_event or self._default_handler
        self.scan_interval = scan_interval
        self.running = False
        self.thread = None
        self.baseline = {}  # Known processes
        self.events = []
        self.event_count = 0

    def _default_handler(self, event: dict):
        """Default event handler - just store events."""
        self.events.append(event)

    def _get_process_info(self, proc):
        """Extract process information."""
        try:
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.exe() else "N/A",
                "cmdline": " ".join(proc.cmdline()) if proc.cmdline() else "N/A",
                "ppid": proc.ppid(),
                "user": proc.username() if hasattr(proc, 'username') else "N/A"
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def _scan_processes(self):
        """Scan current process list and detect changes."""
        current_processes = {}
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                info = self._get_process_info(proc)
                if info:
                    current_processes[info['pid']] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Detect new processes
        for pid, proc_info in current_processes.items():
            if pid not in self.baseline:
                self.event_count += 1
                self.on_event({
                    "type": "process_created",
                    "pid": pid,
                    "name": proc_info["name"],
                    "exe": proc_info["exe"],
                    "ppid": proc_info["ppid"],
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_number": self.event_count
                })

        # Detect terminated processes
        for pid in list(self.baseline.keys()):
            if pid not in current_processes:
                self.event_count += 1
                self.on_event({
                    "type": "process_terminated",
                    "pid": pid,
                    "name": self.baseline[pid]["name"],
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_number": self.event_count
                })

        self.baseline = current_processes

    def _monitor_loop(self):
        """Continuous monitoring loop."""
        print(f"✅ ProcessMonitor started (scan interval: {self.scan_interval}s)")
        
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                print(f"⚠️  ProcessMonitor error: {e}")

    def start(self):
        """Start process monitoring in background thread."""
        if self.running:
            return
        
        self.running = True
        # Initialize baseline
        self._scan_processes()
        
        # Start monitoring thread
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop process monitoring."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        print("✅ ProcessMonitor stopped")

    def get_event_count(self) -> int:
        """Get total events detected."""
        return self.event_count

    def get_recent_events(self, limit: int = 10) -> list:
        """Get recent events."""
        return self.events[-limit:]

    def get_current_process_count(self) -> int:
        """Get current process count."""
        return len(self.baseline)


# Test
def test_process_monitor():
    """Test ProcessMonitor basic functionality."""
    import subprocess
    
    events_captured = []
    
    def capture_event(event):
        events_captured.append(event)
    
    monitor = ProcessMonitor(on_event=capture_event, scan_interval=1)
    monitor.start()
    
    time.sleep(2)  # Let it establish baseline
    
    # Start a test process
    proc = subprocess.Popen(['sleep', '2'])
    time.sleep(1)  # Wait for detection
    
    print(f"✅ ProcessMonitor test: captured {len(events_captured)} events")
    print(f"   Current processes: {monitor.get_current_process_count()}")
    print(f"   Recent events: {monitor.get_recent_events(3)}")
    
    monitor.stop()
    proc.wait()


if __name__ == "__main__":
    test_process_monitor()
