"""
T5.1: Central Audit Logger
Centralized append-only logging of all system activity.
"""

import json
import os
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any


class AuditLogger:
    """Append-only audit log for forensic tracking."""

    def __init__(self, log_path: str = "/var/citadel/audit.log"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.retention_days = 90

    def log_event(self, event_type: str, fields: Dict[str, Any]) -> bool:
        """Log an event to the audit trail."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": event_type,
            **fields
        }
        
        with self.lock:
            try:
                with open(self.log_path, 'a') as f:
                    f.write(json.dumps(event) + '\n')
                # Ensure file permissions: owner read/write only
                os.chmod(self.log_path, 0o600)
                return True
            except Exception as e:
                print(f"⚠️  Audit log error: {e}")
                return False

    def log_agent_spawned(self, agent_name: str, task_id: str):
        """Log agent spawn event."""
        return self.log_event("agent_spawned", {
            "agent": agent_name,
            "task": task_id
        })

    def log_agent_ended(self, agent_name: str, exit_code: int):
        """Log agent termination."""
        return self.log_event("agent_ended", {
            "agent": agent_name,
            "exit_code": exit_code
        })

    def log_file_modified(self, file_path: str, change_type: str):
        """Log file system event."""
        return self.log_event("file_modified", {
            "path": file_path,
            "change_type": change_type
        })

    def log_secrets_accessed(self, agent_name: str, secret_name: str, operation: str):
        """Log secrets access (name only, not value)."""
        return self.log_event("secrets_accessed", {
            "agent": agent_name,
            "secret": secret_name,
            "operation": operation
        })

    def log_secrets_rotated(self, secret_name: str):
        """Log secret rotation."""
        return self.log_event("secrets_rotated", {
            "secret": secret_name
        })

    def log_process_created(self, pid: int, name: str, ppid: int):
        """Log process creation."""
        return self.log_event("process_created", {
            "pid": pid,
            "name": name,
            "ppid": ppid
        })

    def log_process_terminated(self, pid: int, name: str):
        """Log process termination."""
        return self.log_event("process_terminated", {
            "pid": pid,
            "name": name
        })

    def log_hardening_run(self, action: str, changes_count: int):
        """Log hardening script execution."""
        return self.log_event("hardening_run", {
            "action": action,
            "changes": changes_count
        })

    def get_all_events(self) -> list:
        """Read all audit log events."""
        events = []
        if self.log_path.exists():
            with open(self.log_path, 'r') as f:
                for line in f:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return events

    def get_events_since(self, hours: int) -> list:
        """Get events from last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        all_events = self.get_all_events()
        
        recent = []
        for event in all_events:
            try:
                event_time = datetime.fromisoformat(event["timestamp"])
                if event_time >= cutoff:
                    recent.append(event)
            except (KeyError, ValueError):
                continue
        
        return recent

    def get_events_by_agent(self, agent_name: str) -> list:
        """Get all events for a specific agent."""
        all_events = self.get_all_events()
        return [e for e in all_events if e.get("agent") == agent_name]

    def cleanup_old_logs(self):
        """Remove log entries older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        events = self.get_all_events()
        
        recent_events = []
        for event in events:
            try:
                event_time = datetime.fromisoformat(event["timestamp"])
                if event_time >= cutoff:
                    recent_events.append(event)
            except (KeyError, ValueError):
                continue
        
        with self.lock:
            with open(self.log_path, 'w') as f:
                for event in recent_events:
                    f.write(json.dumps(event) + '\n')
            os.chmod(self.log_path, 0o600)

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        events = self.get_all_events()
        
        event_types = {}
        agents = set()
        
        for event in events:
            event_type = event.get("event", "unknown")
            event_types[event_type] = event_types.get(event_type, 0) + 1
            
            if "agent" in event:
                agents.add(event["agent"])
        
        return {
            "total_events": len(events),
            "event_types": event_types,
            "agents": list(agents),
            "log_size_mb": self.log_path.stat().st_size / (1024 * 1024) if self.log_path.exists() else 0
        }


# Test
def test_audit_logger():
    """Test AuditLogger functionality."""
    import tempfile
    
    with tempfile.TemporaryDirectory() as tmpdir:
        log_path = os.path.join(tmpdir, "audit.log")
        logger = AuditLogger(log_path)
        
        # Log various events
        logger.log_agent_spawned("dev_agent", "t1_1")
        logger.log_file_modified("/projects/test.py", "created")
        logger.log_secrets_accessed("dev_agent", "github_token", "get")
        logger.log_process_created(1234, "python", 1)
        logger.log_agent_ended("dev_agent", 0)
        
        # Verify
        events = logger.get_all_events()
        print(f"✅ AuditLogger test: logged {len(events)} events")
        
        # Get by agent
        agent_events = logger.get_events_by_agent("dev_agent")
        print(f"   dev_agent events: {len(agent_events)}")
        
        # Get summary
        summary = logger.get_summary()
        print(f"   Summary: {summary}")
        
        # Verify append-only
        with open(log_path, 'r') as f:
            content = f.read()
        print(f"   Log file is JSON Lines: {len(content.split(chr(10)))-1} lines")


if __name__ == "__main__":
    test_audit_logger()
