#!/usr/bin/env python3
"""
Monitor audit log growth and alert if it exceeds thresholds.

This script should be run periodically (e.g., via cron) to check:
1. Daily log size exceeds 500MB
2. Rapid growth patterns indicating log spam
3. Disk space concerns
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
import json
import smtplib
from email.mime.text import MIMEText


class AuditLogMonitor:
    """Monitor audit log growth and alert on anomalies."""
    
    def __init__(self, log_dir: Path = Path("/opt/citadel-archer-prod/audit_logs")):
        self.log_dir = log_dir
        self.state_file = log_dir / ".monitor_state.json"
        self.load_state()
    
    def load_state(self):
        """Load previous monitoring state."""
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                self.state = json.load(f)
        else:
            self.state = {
                "last_check": None,
                "alerts_sent": [],
                "daily_sizes": {}
            }
    
    def save_state(self):
        """Save monitoring state."""
        with open(self.state_file, 'w') as f:
            json.dump(self.state, f, indent=2)
    
    def check_daily_size(self) -> list:
        """Check size of today's audit log."""
        alerts = []
        today = datetime.now().strftime("%Y-%m-%d")
        log_file = self.log_dir / f"audit_{today}.log"
        
        if log_file.exists():
            size_mb = log_file.stat().st_size / (1024 * 1024)
            
            # Record size for historical tracking
            self.state["daily_sizes"][today] = size_mb
            
            # Alert if over 500MB
            if size_mb > 500:
                alerts.append({
                    "type": "daily_size_exceeded",
                    "message": f"Daily audit log exceeds 500MB: {size_mb:.1f}MB",
                    "severity": "warning",
                    "file": str(log_file),
                    "size_mb": size_mb
                })
            
            # Critical alert if over 1GB
            if size_mb > 1000:
                alerts.append({
                    "type": "critical_size",
                    "message": f"CRITICAL: Daily audit log exceeds 1GB: {size_mb:.1f}MB",
                    "severity": "critical",
                    "file": str(log_file),
                    "size_mb": size_mb
                })
        
        return alerts
    
    def check_growth_rate(self) -> list:
        """Check for rapid growth patterns."""
        alerts = []
        
        # Compare last 3 days of growth
        dates = sorted(self.state["daily_sizes"].keys())[-3:]
        if len(dates) >= 2:
            sizes = [self.state["daily_sizes"][d] for d in dates]
            
            # Check for exponential growth
            if len(sizes) >= 3:
                growth_rate_1 = (sizes[1] - sizes[0]) / max(sizes[0], 1)
                growth_rate_2 = (sizes[2] - sizes[1]) / max(sizes[1], 1)
                
                if growth_rate_2 > 2.0 and growth_rate_2 > growth_rate_1 * 1.5:
                    alerts.append({
                        "type": "exponential_growth",
                        "message": f"Exponential log growth detected: {sizes[-1]:.1f}MB today",
                        "severity": "warning",
                        "recent_sizes": dict(zip(dates, sizes))
                    })
        
        return alerts
    
    def check_disk_space(self) -> list:
        """Check available disk space."""
        alerts = []
        
        statvfs = os.statvfs(self.log_dir)
        free_gb = (statvfs.f_frsize * statvfs.f_bavail) / (1024**3)
        total_gb = (statvfs.f_frsize * statvfs.f_blocks) / (1024**3)
        used_percent = ((total_gb - free_gb) / total_gb) * 100
        
        if free_gb < 5:
            alerts.append({
                "type": "low_disk_space",
                "message": f"Low disk space: {free_gb:.1f}GB free ({used_percent:.1f}% used)",
                "severity": "critical" if free_gb < 1 else "warning",
                "free_gb": free_gb,
                "used_percent": used_percent
            })
        
        return alerts
    
    def send_alerts(self, alerts: list):
        """Send alerts (console output for now, email/webhook later)."""
        for alert in alerts:
            # Check if we've already sent this alert recently
            alert_key = f"{alert['type']}_{datetime.now().strftime('%Y-%m-%d')}"
            if alert_key not in self.state["alerts_sent"]:
                print(f"[{alert['severity'].upper()}] {alert['message']}")
                print(f"  Details: {json.dumps(alert, indent=2)}")
                print()
                
                # Mark as sent
                self.state["alerts_sent"].append(alert_key)
                
                # Clean old alerts (keep last 7 days)
                cutoff = datetime.now() - timedelta(days=7)
                self.state["alerts_sent"] = [
                    a for a in self.state["alerts_sent"]
                    if not a.endswith(cutoff.strftime('%Y-%m-%d'))
                ]
    
    def write_status_file(self, alerts: list):
        """Write status file for other systems to check."""
        status = {
            "timestamp": datetime.now().isoformat(),
            "healthy": len(alerts) == 0,
            "alerts": alerts,
            "metrics": {
                "today_size_mb": self.state["daily_sizes"].get(
                    datetime.now().strftime("%Y-%m-%d"), 0
                ),
                "recent_sizes": dict(
                    list(sorted(self.state["daily_sizes"].items())[-7:])
                )
            }
        }
        
        status_file = self.log_dir / "monitor_status.json"
        with open(status_file, 'w') as f:
            json.dump(status, f, indent=2)
    
    def run(self):
        """Run all monitoring checks."""
        print(f"Audit Log Monitor - {datetime.now().isoformat()}")
        print("-" * 50)
        
        alerts = []
        
        # Run all checks
        alerts.extend(self.check_daily_size())
        alerts.extend(self.check_growth_rate())
        alerts.extend(self.check_disk_space())
        
        # Send alerts if any
        if alerts:
            print(f"Found {len(alerts)} alert(s):")
            self.send_alerts(alerts)
        else:
            print("✓ All checks passed - logs are healthy")
        
        # Write status file
        self.write_status_file(alerts)
        
        # Update state
        self.state["last_check"] = datetime.now().isoformat()
        self.save_state()
        
        # Exit with error code if critical alerts
        if any(a["severity"] == "critical" for a in alerts):
            sys.exit(1)


if __name__ == "__main__":
    monitor = AuditLogMonitor()
    monitor.run()