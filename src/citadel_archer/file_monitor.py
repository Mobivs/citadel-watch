"""
T2.1: File Monitoring Foundation
Real-time filesystem monitoring using watchdog.
"""

import os
from pathlib import Path
from typing import List, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent, FileDeletedEvent


class CitadelFileEventHandler(FileSystemEventHandler):
    """Custom event handler for file system events."""

    def __init__(self, on_event: Callable):
        self.on_event = on_event
        self.event_count = 0

    def on_created(self, event):
        if not event.is_directory:
            self.event_count += 1
            self.on_event({
                "type": "created",
                "path": event.src_path,
                "timestamp": datetime.utcnow().isoformat(),
                "event_number": self.event_count
            })

    def on_modified(self, event):
        if not event.is_directory:
            self.event_count += 1
            self.on_event({
                "type": "modified",
                "path": event.src_path,
                "timestamp": datetime.utcnow().isoformat(),
                "event_number": self.event_count
            })

    def on_deleted(self, event):
        if not event.is_directory:
            self.event_count += 1
            self.on_event({
                "type": "deleted",
                "path": event.src_path,
                "timestamp": datetime.utcnow().isoformat(),
                "event_number": self.event_count
            })

    def on_moved(self, event):
        if not event.is_directory:
            self.event_count += 1
            self.on_event({
                "type": "moved",
                "src_path": event.src_path,
                "dest_path": event.dest_path,
                "timestamp": datetime.utcnow().isoformat(),
                "event_number": self.event_count
            })


class FileMonitor:
    """Monitor critical file system paths for changes."""

    def __init__(self, on_event: Callable = None):
        self.observer = None
        self.handlers = {}
        self.events = []
        self.on_event = on_event or self._default_handler
        
        # Critical paths to monitor
        self.critical_paths = [
            "/root/.ssh",
            "/opt",
            "/projects",
            "/var/citadel"
        ]

    def _default_handler(self, event: dict):
        """Default event handler - just store events."""
        self.events.append(event)

    def start(self):
        """Start monitoring critical paths."""
        self.observer = Observer()
        
        for path in self.critical_paths:
            if os.path.exists(path):
                handler = CitadelFileEventHandler(self.on_event)
                self.observer.schedule(handler, path, recursive=True)
                self.handlers[path] = handler
        
        self.observer.start()
        print(f"✅ FileMonitor started, monitoring {len(self.handlers)} paths")

    def stop(self):
        """Stop monitoring."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            print("✅ FileMonitor stopped")

    def get_event_count(self) -> int:
        """Get total events detected."""
        return len(self.events)

    def get_recent_events(self, limit: int = 10) -> list:
        """Get recent events."""
        return self.events[-limit:]


# Test
def test_file_monitor():
    """Test FileMonitor basic functionality."""
    import tempfile
    import time
    from datetime import datetime
    
    events_captured = []
    
    def capture_event(event):
        events_captured.append(event)
    
    # Create temp directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        monitor = FileMonitor(on_event=capture_event)
        monitor.critical_paths = [tmpdir]
        
        monitor.start()
        time.sleep(0.5)  # Let observer start
        
        # Create a test file
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        time.sleep(1)  # Wait for event
        
        # Modify it
        with open(test_file, 'a') as f:
            f.write("\nmore content")
        
        time.sleep(1)  # Wait for event
        
        monitor.stop()
        
        # Verify
        print(f"✅ FileMonitor test: captured {len(events_captured)} events")
        print(f"   Recent events: {monitor.get_recent_events(3)}")


from datetime import datetime

if __name__ == "__main__":
    test_file_monitor()
