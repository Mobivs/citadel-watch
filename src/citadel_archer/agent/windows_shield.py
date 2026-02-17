#!/usr/bin/env python3
"""
Citadel Shield — Windows Protection Agent

Deployed to family Windows PCs for remote monitoring.
Enrolls via invitation string from the Citadel dashboard.

CONSTRAINTS:
  - Python 3.8+ stdlib ONLY (no pip dependencies)
  - Single file (easy to copy/download)
  - Runs as user-level process (no admin required for basic monitoring)

SENSORS:
  - event_log    : Windows Security Event Log (failed logons, priv escalation)
  - defender     : Windows Defender real-time protection status
  - firewall     : Windows Firewall profile states
  - processes    : detect crypto miners, suspicious executables
  - software     : track newly installed software

CLI:
  windows_shield.py enroll <server_url> <invitation_string>
  windows_shield.py daemon                  Run monitoring loop
  windows_shield.py status                  JSON health status
  windows_shield.py install                 Create scheduled task for auto-start
  windows_shield.py uninstall               Remove scheduled task

Storage: %LOCALAPPDATA%\\CitadelShield\\
"""

import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ───────────────────────────────────────────────────

AGENT_DIR = Path(os.environ.get("LOCALAPPDATA", os.path.expanduser("~"))) / "CitadelShield"
DB_PATH = AGENT_DIR / "events.db"
CONFIG_PATH = AGENT_DIR / "config.json"
PID_FILE = AGENT_DIR / "shield.pid"
VERSION = "0.1.0"

# Sensor intervals (seconds)
EVENT_LOG_INTERVAL = 10
DEFENDER_INTERVAL = 60
FIREWALL_INTERVAL = 120
PROCESS_INTERVAL = 30
SOFTWARE_INTERVAL = 300

# Heartbeat interval
HEARTBEAT_INTERVAL = 60

# Windows Update sensor
WINDOWS_UPDATE_INTERVAL = 3600   # Check every 60 minutes
OVERDUE_DAYS_THRESHOLD = 7       # Report threat if updates pending > 7 days

# Known crypto miner process names
KNOWN_MINERS = {
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
    "ethminer", "claymore", "nbminer", "t-rex", "phoenixminer",
    "nicehash", "kryptex",
}

# Security Event IDs to monitor
EVENT_IDS = {
    4625: "logon_failure",        # Failed logon attempt
    4672: "unauthorized_access",  # Special privileges assigned
    4720: "unauthorized_access",  # Account created
    4726: "unauthorized_access",  # Account deleted
    4732: "unauthorized_access",  # Member added to security group
    1102: "audit_log_cleared",    # Audit log cleared
}

# ── Database ────────────────────────────────────────────────────────

def init_db(db_path=None):
    """Initialize the local events database."""
    path = db_path or DB_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            sensor TEXT NOT NULL DEFAULT 'system',
            threat_type TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            reported INTEGER DEFAULT 0
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_reported ON events(reported)"
    )
    conn.commit()
    return conn


def store_event(conn, severity, sensor, threat_type, detail):
    """Store a security event in the local DB."""
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO events (timestamp, severity, sensor, threat_type, detail) "
        "VALUES (?, ?, ?, ?, ?)",
        (now, severity, sensor, threat_type, detail),
    )
    conn.commit()
    return now


def get_unreported_events(conn, limit=50):
    """Get events not yet reported to the server."""
    cursor = conn.execute(
        "SELECT id, timestamp, severity, sensor, threat_type, detail "
        "FROM events WHERE reported = 0 ORDER BY id LIMIT ?",
        (limit,),
    )
    return cursor.fetchall()


def mark_reported(conn, event_ids):
    """Mark events as reported."""
    if not event_ids:
        return
    placeholders = ",".join("?" for _ in event_ids)
    conn.execute(
        f"UPDATE events SET reported = 1 WHERE id IN ({placeholders})",
        event_ids,
    )
    conn.commit()


# ── Configuration ───────────────────────────────────────────────────

def load_config():
    """Load agent configuration from config.json."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    return {}


def save_config(config):
    """Save agent configuration to config.json."""
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    # Restrict file permissions to current user (best effort; limited on Windows)
    try:
        import stat
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, AttributeError):
        pass


# ── HTTP Client ─────────────────────────────────────────────────────

def http_post(url, data, token=None, timeout=15):
    """POST JSON data to a URL. Returns (status_code, response_dict)."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return e.code, {"detail": body}
    except Exception as e:
        return 0, {"detail": str(e)}


# ── Enrollment ──────────────────────────────────────────────────────

def get_local_ip():
    """Get the local IP address (best effort)."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def get_hostname():
    """Get the local hostname."""
    import socket
    return socket.gethostname()


def enroll(server_url, invitation_string):
    """Enroll this agent with the Citadel server via invitation string."""
    server_url = server_url.rstrip("/")
    url = f"{server_url}/api/agents/enroll"

    hostname = get_hostname()
    ip = get_local_ip()

    status_code, resp = http_post(url, {
        "invitation_string": invitation_string,
        "hostname": hostname,
        "ip": ip,
        "platform": "windows",
    })

    if status_code != 200:
        detail = resp.get("detail", "Unknown error")
        print(f"Enrollment failed (HTTP {status_code}): {detail}", file=sys.stderr)
        return False

    config = {
        "server_url": server_url,
        "agent_id": resp["agent_id"],
        "api_token": resp["api_token"],
        "asset_id": resp.get("asset_id", ""),
        "hostname": hostname,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
    }
    save_config(config)

    print(f"Enrolled successfully!")
    print(f"  Agent ID:  {config['agent_id']}")
    print(f"  Asset ID:  {config['asset_id']}")
    print(f"  Server:    {server_url}")
    print(f"  Config:    {CONFIG_PATH}")
    print(f"\nRun 'python windows_shield.py daemon' to start monitoring.")
    return True


# ── Sensors ─────────────────────────────────────────────────────────

def sensor_event_log(stop_event):
    """Monitor Windows Security Event Log for suspicious events."""
    conn = init_db()
    try:
        while not stop_event.is_set():
            try:
                # Query recent security events (last interval window)
                ms = EVENT_LOG_INTERVAL * 1000
                cmd = [
                    "wevtutil", "qe", "Security",
                    f'/q:*[System[TimeCreated[timediff(@SystemTime) <= {ms}]]]',
                    "/f:text",
                ]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0 and result.stdout.strip():
                    _parse_event_log_output(conn, result.stdout)
            except FileNotFoundError:
                # wevtutil not available — skip sensor
                break
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            stop_event.wait(EVENT_LOG_INTERVAL)
    finally:
        conn.close()


def _parse_event_log_output(conn, output):
    """Parse wevtutil text output and store relevant events."""
    current_event_id = None
    current_lines = []

    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("Event["):
            # Process previous event
            if current_event_id and current_event_id in EVENT_IDS:
                threat_type = EVENT_IDS[current_event_id]
                severity = "critical" if current_event_id == 1102 else "high"
                detail = "\n".join(current_lines[:10])
                store_event(conn, severity, "event_log", threat_type, detail)
            current_event_id = None
            current_lines = []
        elif "Event ID:" in line:
            try:
                current_event_id = int(line.split(":")[-1].strip())
            except (ValueError, IndexError):
                pass
        else:
            current_lines.append(line)

    # Process last event
    if current_event_id and current_event_id in EVENT_IDS:
        threat_type = EVENT_IDS[current_event_id]
        severity = "critical" if current_event_id == 1102 else "high"
        detail = "\n".join(current_lines[:10])
        store_event(conn, severity, "event_log", threat_type, detail)


def sensor_defender(stop_event):
    """Monitor Windows Defender status."""
    conn = init_db()
    try:
        while not stop_event.is_set():
            try:
                result = subprocess.run(
                    [
                        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-Command", "Get-MpComputerStatus | ConvertTo-Json",
                    ],
                    capture_output=True, text=True, timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0 and result.stdout.strip():
                    status = json.loads(result.stdout)
                    rtp = status.get("RealTimeProtectionEnabled", True)
                    if not rtp:
                        store_event(
                            conn, "critical", "defender", "defender_disabled",
                            "Windows Defender real-time protection is DISABLED",
                        )
            except FileNotFoundError:
                break  # PowerShell not available
            except (json.JSONDecodeError, subprocess.TimeoutExpired):
                pass
            except Exception:
                pass
            stop_event.wait(DEFENDER_INTERVAL)
    finally:
        conn.close()


def sensor_firewall(stop_event):
    """Monitor Windows Firewall profile states."""
    conn = init_db()
    try:
        while not stop_event.is_set():
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    _parse_firewall_output(conn, result.stdout)
            except FileNotFoundError:
                break
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            stop_event.wait(FIREWALL_INTERVAL)
    finally:
        conn.close()


def _parse_firewall_output(conn, output):
    """Parse netsh firewall output and detect disabled profiles."""
    current_profile = ""
    for line in output.split("\n"):
        line = line.strip()
        if "Profile Settings" in line:
            current_profile = line.split()[0]
        elif line.startswith("State") and "OFF" in line.upper():
            store_event(
                conn, "high", "firewall", "firewall_disabled",
                f"Windows Firewall {current_profile} profile is OFF",
            )


def sensor_processes(stop_event):
    """Monitor running processes for suspicious executables."""
    conn = init_db()
    try:
        while not stop_event.is_set():
            try:
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    _check_processes(conn, result.stdout)
            except FileNotFoundError:
                break
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            stop_event.wait(PROCESS_INTERVAL)
    finally:
        conn.close()


def _check_processes(conn, output):
    """Check process list for known miners and suspicious executables."""
    for line in output.strip().split("\n"):
        parts = line.strip().strip('"').split('","')
        if not parts:
            continue
        proc_name = parts[0].strip('"').lower()
        base = proc_name.replace(".exe", "")
        if base in KNOWN_MINERS:
            store_event(
                conn, "critical", "processes", "process_anomaly",
                f"Suspected crypto miner detected: {proc_name}",
            )


def sensor_software(stop_event):
    """Track installed software changes."""
    conn = init_db()
    last_software = set()
    first_run = True

    try:
        while not stop_event.is_set():
            try:
                result = subprocess.run(
                    [
                        "reg", "query",
                        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                        "/s", "/v", "DisplayName",
                    ],
                    capture_output=True, text=True, timeout=30,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    current = set()
                    for line in result.stdout.split("\n"):
                        if "DisplayName" in line and "REG_SZ" in line:
                            name = line.split("REG_SZ")[-1].strip()
                            if name:
                                current.add(name)

                    if not first_run and last_software:
                        new_software = current - last_software
                        for sw in new_software:
                            store_event(
                                conn, "medium", "software", "suspicious_software",
                                f"New software installed: {sw}",
                            )
                    last_software = current
                    first_run = False
            except FileNotFoundError:
                break
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            stop_event.wait(SOFTWARE_INTERVAL)
    finally:
        conn.close()


# ── Windows Update Sensor ──────────────────────────────────────────

def sensor_windows_updates(stop_event):
    """Monitor Windows Update status: pending updates, last install, reboot required.

    Reports windows_update_overdue threat when updates are stale.
    Posts patch status to server for dashboard display.
    """
    conn = init_db()
    config = load_config()
    try:
        while not stop_event.is_set():
            try:
                patch_data = _query_windows_updates()
                if patch_data is None:
                    patch_data = {"check_status": "error", "pending_count": 0}

                # Report threat if updates overdue
                if patch_data.get("oldest_pending_days", 0) >= OVERDUE_DAYS_THRESHOLD:
                    pending = patch_data.get("pending_count", 0)
                    days = patch_data.get("oldest_pending_days", 0)
                    store_event(
                        conn, "medium", "windows_updates", "windows_update_overdue",
                        f"{pending} Windows update(s) pending for {days} days",
                    )
                elif patch_data.get("reboot_required", False):
                    store_event(
                        conn, "medium", "windows_updates", "windows_update_overdue",
                        "Computer needs a restart to finish installing updates",
                    )

                # Report patch status to server
                _report_patch_status(config, patch_data)
            except Exception as exc:
                try:
                    print(f"[shield] Windows Update sensor error: {exc}", file=sys.stderr)
                except Exception:
                    pass
            stop_event.wait(WINDOWS_UPDATE_INTERVAL)
    finally:
        conn.close()


def _query_windows_updates():
    """Query Windows Update status via PowerShell COM objects.

    Uses Microsoft.Update.Session (user-level, no admin required) for
    pending updates, Get-HotFix for recent installs, and registry for
    reboot-required flag. Falls back to wmic on failure.

    Returns dict or None on total failure.
    """
    ps_script = r"""
$ErrorActionPreference = 'SilentlyContinue'
$r = @{ check_status='ok'; pending_count=0; installed_count=0;
        reboot_required=$false; oldest_pending_days=0;
        pending_titles=@(); last_check_date=''; last_install_date='' }
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $q = $s.CreateUpdateSearcher()
    $p = $q.Search("IsInstalled=0 and IsHidden=0")
    $r.pending_count = $p.Updates.Count
    $t = @(); $od = 0
    foreach ($u in $p.Updates) {
        if ($t.Count -lt 10) { $t += $u.Title }
        $d = ((Get-Date) - $u.LastDeploymentChangeTime).Days
        if ($d -gt $od) { $od = $d }
    }
    $r.pending_titles = $t; $r.oldest_pending_days = $od
} catch { $r.check_status = 'error' }
try {
    $hf = Get-HotFix | Sort-Object InstalledOn -Descending
    $ago = (Get-Date).AddDays(-30)
    $r.installed_count = @($hf | Where-Object { $_.InstalledOn -ge $ago }).Count
    if ($hf.Count -gt 0 -and $hf[0].InstalledOn) {
        $r.last_install_date = $hf[0].InstalledOn.ToString('o')
    }
} catch {}
$rk = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$r.reboot_required = (Test-Path $rk)
try {
    $au = New-Object -ComObject Microsoft.Update.AutoUpdate
    $r.last_check_date = $au.Results.LastSearchSuccessDate.ToString('o')
} catch {}
$r | ConvertTo-Json -Compress
"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
            capture_output=True, text=True, timeout=90,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0 and result.stdout.strip():
            return json.loads(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    return _query_updates_wmic_fallback()


def _query_updates_wmic_fallback():
    """Fallback: use wmic qfe to get basic hotfix info."""
    try:
        result = subprocess.run(
            ["wmic", "qfe", "list", "brief", "/format:csv"],
            capture_output=True, text=True, timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            lines = [l for l in result.stdout.strip().split("\n")
                     if l.strip() and "Node" not in l and "," in l]
            return {
                "check_status": "ok",
                "installed_count": len(lines),
                "pending_count": 0,
                "reboot_required": False,
                "oldest_pending_days": 0,
                "pending_titles": [],
                "last_check_date": "",
                "last_install_date": "",
            }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _report_patch_status(config, patch_data):
    """POST patch status to the Citadel server."""
    server_url = config.get("server_url", "")
    agent_id = config.get("agent_id", "")
    token = config.get("api_token", "")
    if not server_url or not agent_id:
        return
    url = f"{server_url}/api/agents/{agent_id}/patch-status"
    http_post(url, patch_data, token=token)


# ── Command Execution ──────────────────────────────────────────────

def _execute_command(config, cmd):
    """Execute a command received from the server and acknowledge it."""
    command_id = cmd.get("command_id", "")
    command_type = cmd.get("command_type", "")
    result = "unknown_command"

    if command_type == "check_updates":
        try:
            subprocess.run(
                ["wuauclt", "/detectnow"],
                capture_output=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            result = "triggered_update_check"
        except FileNotFoundError:
            result = "wuauclt_not_found"
        except Exception as e:
            result = f"error: {e}"

    elif command_type == "threat_alert":
        # Cross-system correlation alert from central dashboard
        payload = cmd.get("payload", {})
        severity = payload.get("severity", "unknown")
        desc = payload.get("description", "Cross-system correlation alert")
        indicator = payload.get("indicator", "")
        try:
            print(f"[shield] CROSS-SYSTEM ALERT ({severity}): {desc}", file=sys.stderr)
            if indicator:
                print(f"[shield]   Indicator: {indicator}", file=sys.stderr)
            result = "alert_received"
        except Exception:
            result = "alert_logged"

    elif command_type == "apply_policy":
        # Group policy pushed from central dashboard
        payload = cmd.get("payload", {})
        changed = False
        threshold = payload.get("alert_threshold")
        if threshold is not None:
            config["alert_threshold"] = int(threshold)
            changed = True
        schedule = payload.get("update_schedule")
        if schedule is not None:
            config["update_schedule"] = schedule
            changed = True
        if changed:
            save_config(config)
        fw_count = len(payload.get("firewall_rules", []))
        if fw_count:
            print(f"[shield] Policy received {fw_count} firewall rules (logged)", file=sys.stderr)
        result = f"policy_applied:threshold={threshold},schedule={schedule}"

    elif command_type == "panic_isolate":
        # Emergency network isolation from central dashboard
        payload = cmd.get("payload", {})
        try:
            # Save pre-panic firewall state
            pre_state = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            config["pre_panic_firewall_state"] = pre_state.stdout
            config["panic_active"] = True
            save_config(config)

            # Enable firewall on all profiles
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # Block all traffic
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles",
                 "firewallpolicy", "blockinbound,blockoutbound"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # Whitelist heartbeat endpoint so agent can still report back
            server_url = config.get("server_url", "")
            if server_url:
                import socket as _sock
                from urllib.parse import urlparse
                parsed = urlparse(server_url)
                heartbeat_host = parsed.hostname or ""
                # netsh requires an IP address, not a hostname
                try:
                    heartbeat_ip = _sock.gethostbyname(heartbeat_host)
                except (OSError, _sock.gaierror):
                    heartbeat_ip = heartbeat_host  # best-effort fallback
                heartbeat_port = str(parsed.port or 443)
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=CitadelHeartbeat", "dir=out", "action=allow",
                     "protocol=TCP", f"remoteip={heartbeat_ip}",
                     f"remoteport={heartbeat_port}"],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            print("[shield] PANIC ISOLATE: Network locked down", file=sys.stderr)
            result = "isolated:firewall_locked"
        except Exception as e:
            print(f"[shield] PANIC ISOLATE failed: {e}", file=sys.stderr)
            result = f"isolate_error:{e}"

    elif command_type == "panic_terminate":
        # Emergency process termination from central dashboard
        payload = cmd.get("payload", {})
        killed = 0
        errors = []
        for proc_name in payload.get("process_names", []):
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/IM", proc_name],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if r.returncode == 0:
                    killed += 1
                else:
                    errors.append(f"{proc_name}:exit_{r.returncode}")
            except Exception as e:
                errors.append(f"{proc_name}:{e}")
        for pid in payload.get("pids", []):
            try:
                r = subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if r.returncode == 0:
                    killed += 1
                else:
                    errors.append(f"pid_{pid}:exit_{r.returncode}")
            except Exception as e:
                errors.append(f"pid_{pid}:{e}")
        print(f"[shield] PANIC TERMINATE: killed={killed}", file=sys.stderr)
        result = f"terminated:count={killed}"
        if errors:
            result += f",errors={len(errors)}"

    elif command_type == "panic_rollback":
        # Restore pre-panic network state from central dashboard
        try:
            # Restore saved firewall state
            pre_state = config.get("pre_panic_firewall_state", "")
            # Remove the isolation rule
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 "name=CitadelHeartbeat"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            # Reset firewall to default policy (allow outbound, block inbound)
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles",
                 "firewallpolicy", "blockinbound,allowoutbound"],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            config["panic_active"] = False
            config.pop("pre_panic_firewall_state", None)
            save_config(config)
            print("[shield] PANIC ROLLBACK: Network restored", file=sys.stderr)
            result = "rollback_complete"
        except Exception as e:
            print(f"[shield] PANIC ROLLBACK failed: {e}", file=sys.stderr)
            result = f"rollback_error:{e}"

    # Acknowledge command back to server
    if command_id:
        server_url = config.get("server_url", "")
        agent_id = config.get("agent_id", "")
        token = config.get("api_token", "")
        if server_url and agent_id:
            url = f"{server_url}/api/agents/{agent_id}/commands/ack"
            http_post(url, {"command_id": command_id, "result": result}, token=token)


# ── Reporting ───────────────────────────────────────────────────────

def report_threats(conn, config):
    """Send unreported events to the Citadel server as threats.

    Events below the configured alert_threshold are marked as reported
    locally but NOT sent to the server (prevents event buildup).
    """
    events = get_unreported_events(conn)
    if not events:
        return

    server_url = config["server_url"]
    token = config["api_token"]
    hostname = config.get("hostname", get_hostname())
    threshold = config.get("alert_threshold", 0)
    reported_ids = []
    suppressed_ids = []

    # Severity mapping (local text → numeric 1-10)
    severity_map = {"info": 3, "medium": 5, "high": 7, "critical": 9}

    for event_id, timestamp, severity, sensor, threat_type, detail in events:
        numeric_severity = severity_map.get(severity, 5)

        # Skip events below threshold (mark reported to avoid buildup)
        if threshold > 0 and numeric_severity < threshold:
            suppressed_ids.append(event_id)
            continue

        url = f"{server_url}/api/threats/remote-shield"
        code, resp = http_post(url, {
            "type": threat_type,
            "severity": numeric_severity,
            "title": f"[{sensor}] {detail[:80]}",
            "details": {"raw_detail": detail, "sensor": sensor},
            "hostname": hostname,
            "timestamp": timestamp,
        }, token=token)

        if code == 200 or code == 201:
            reported_ids.append(event_id)
        # On auth failure, don't keep retrying
        elif code == 401:
            break

    mark_reported(conn, reported_ids + suppressed_ids)


def send_heartbeat(config):
    """Send heartbeat to the server. Processes commands and config from response."""
    server_url = config["server_url"]
    agent_id = config["agent_id"]
    token = config["api_token"]
    url = f"{server_url}/api/agents/{agent_id}/heartbeat"
    code, resp = http_post(url, {}, token=token)
    if code == 200 and resp:
        try:
            data = json.loads(resp) if isinstance(resp, str) else resp
            # Update alert_threshold
            new_threshold = data.get("alert_threshold", 0)
            if new_threshold != config.get("alert_threshold", 0):
                config["alert_threshold"] = new_threshold
                save_config(config)
            # Process pending commands from server
            for cmd in data.get("pending_commands", []):
                try:
                    _execute_command(config, cmd)
                except Exception:
                    pass
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass


# ── Daemon ──────────────────────────────────────────────────────────

def daemon(config):
    """Run the monitoring daemon.

    Each sensor thread creates its own SQLite connection to avoid
    cross-thread sharing (SQLite connections are not thread-safe).
    The main loop also uses a dedicated connection for report_threats().
    """
    # Ensure tables exist (connection closed immediately)
    init_db().close()

    stop_event = threading.Event()

    # Handle graceful shutdown
    def handle_signal(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Write PID file
    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"Citadel Shield Windows Agent v{VERSION}")
    print(f"Agent ID: {config['agent_id']}")
    print(f"Server:   {config['server_url']}")
    print(f"Monitoring started. Press Ctrl+C to stop.")

    # Start sensor threads (each creates its own DB connection)
    sensors = [
        ("event_log", sensor_event_log),
        ("defender", sensor_defender),
        ("firewall", sensor_firewall),
        ("processes", sensor_processes),
        ("software", sensor_software),
        ("windows_updates", sensor_windows_updates),
    ]

    threads = []
    for name, func in sensors:
        t = threading.Thread(target=func, args=(stop_event,), daemon=True, name=name)
        t.start()
        threads.append(t)

    # Main loop: heartbeat + report (own connection for thread safety)
    main_conn = init_db()
    last_heartbeat = 0
    last_report = 0

    try:
        while not stop_event.is_set():
            now = time.monotonic()

            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                try:
                    send_heartbeat(config)
                except Exception:
                    pass
                last_heartbeat = now

            if now - last_report >= 30:  # Report every 30s
                try:
                    report_threats(main_conn, config)
                except Exception:
                    pass
                last_report = now

            stop_event.wait(5)
    finally:
        main_conn.close()
        if PID_FILE.exists():
            PID_FILE.unlink()
        print("\nShutdown complete.")


# ── Status ──────────────────────────────────────────────────────────

def get_status():
    """Get agent status as JSON."""
    config = load_config()
    result = {
        "version": VERSION,
        "enrolled": bool(config.get("agent_id")),
        "agent_id": config.get("agent_id", ""),
        "server_url": config.get("server_url", ""),
        "hostname": get_hostname(),
        "config_path": str(CONFIG_PATH),
        "db_path": str(DB_PATH),
        "pid_file": str(PID_FILE),
        "running": PID_FILE.exists(),
    }

    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.execute("SELECT COUNT(*) FROM events")
            result["total_events"] = cursor.fetchone()[0]
            cursor = conn.execute("SELECT COUNT(*) FROM events WHERE reported = 0")
            result["unreported_events"] = cursor.fetchone()[0]
            conn.close()
        except Exception:
            pass

    return result


# ── Task Scheduler ──────────────────────────────────────────────────

def install_task():
    """Create a Windows Task Scheduler task for auto-start at logon."""
    python_path = sys.executable
    script_path = os.path.abspath(__file__)

    cmd = [
        "schtasks", "/Create",
        "/TN", "CitadelShield",
        "/TR", f'"{python_path}" "{script_path}" daemon',
        "/SC", "ONLOGON",
        "/RL", "LIMITED",
        "/F",  # Force overwrite if exists
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            print("Scheduled task 'CitadelShield' created successfully.")
            print("The agent will start automatically at logon.")
        else:
            print(f"Failed to create task: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)


def uninstall_task():
    """Remove the Windows Task Scheduler task."""
    try:
        result = subprocess.run(
            ["schtasks", "/Delete", "/TN", "CitadelShield", "/F"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            print("Scheduled task 'CitadelShield' removed.")
        else:
            print(f"Failed to remove task: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Citadel Shield Windows Agent v{VERSION}")
        print(f"Usage:")
        print(f"  {sys.argv[0]} enroll <server_url> <invitation_string>")
        print(f"  {sys.argv[0]} daemon")
        print(f"  {sys.argv[0]} status")
        print(f"  {sys.argv[0]} install")
        print(f"  {sys.argv[0]} uninstall")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "enroll":
        if len(sys.argv) < 4:
            print("Usage: windows_shield.py enroll <server_url> <invitation_string>",
                  file=sys.stderr)
            sys.exit(1)
        success = enroll(sys.argv[2], sys.argv[3])
        sys.exit(0 if success else 1)

    elif command == "daemon":
        config = load_config()
        if not config.get("agent_id"):
            print("Agent not enrolled. Run 'enroll' first.", file=sys.stderr)
            sys.exit(1)
        daemon(config)

    elif command == "status":
        print(json.dumps(get_status(), indent=2))

    elif command == "install":
        install_task()

    elif command == "uninstall":
        uninstall_task()

    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
