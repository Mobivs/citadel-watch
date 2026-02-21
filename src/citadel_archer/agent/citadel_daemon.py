#!/usr/bin/env python3
"""
Citadel Daemon — Linux VPS Security Agent

Deployed to /opt/citadel-daemon/citadel_daemon.py on remote Linux servers.
Runs as a systemd service (citadel-daemon.service).
Enrolls via invitation string from the Citadel dashboard.
Reports findings back to the coordinator via HTTP.

CONSTRAINTS:
  - Python 3.8+ stdlib ONLY (no pip dependencies)
  - Single file (easy to curl/scp deploy)
  - Must run as root for /var/log/auth.log access and firewall control

SENSORS:
  - auth_log        : tail /var/log/auth.log for failed SSH, sudo abuse
  - processes        : detect crypto miners, reverse shells, suspicious listeners
  - cron             : hash crontabs, detect unauthorized changes
  - file_integrity   : hash critical system files (/etc/passwd, sshd_config, etc.)
  - patch_status     : check apt/dnf for pending security updates
  - resources        : disk, memory, CPU load monitoring

CLI:
  citadel_daemon.py enroll <server_url> <invitation_string>
  citadel_daemon.py daemon                  Run monitoring loop
  citadel_daemon.py status                  JSON health status
  citadel_daemon.py install                 Create systemd service
  citadel_daemon.py uninstall               Remove systemd service

Storage: /opt/citadel-daemon/
"""

import hashlib
import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# -- Configuration -----------------------------------------------------------

AGENT_DIR = Path("/opt/citadel-daemon")
DB_PATH = AGENT_DIR / "events.db"
CONFIG_PATH = AGENT_DIR / "config.json"
PID_FILE = AGENT_DIR / "daemon.pid"
VERSION = "0.1.0"

# Intervals (seconds)
HEARTBEAT_INTERVAL = 300      # 5 min
REPORT_INTERVAL = 30          # Report batches every 30s
AUTH_LOG_INTERVAL = 5
PROCESS_INTERVAL = 30
CRON_INTERVAL = 60
FILE_INTEGRITY_INTERVAL = 120
PATCH_INTERVAL = 3600         # 1 hour
RESOURCE_INTERVAL = 60

# Tripwire thresholds
SSH_FAIL_THRESHOLD = 10
SSH_FAIL_WINDOW = 60  # seconds

# Resource thresholds
DISK_ALERT_PERCENT = 90
LOAD_ALERT_MULTIPLIER = 2.0
MEMORY_ALERT_PERCENT = 95

# Critical files to monitor
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/etc/sudoers",
    "/etc/crontab",
]

# Known crypto miner process names
KNOWN_MINERS = {
    "xmrig", "minerd", "cpuminer", "cgminer", "bfgminer",
    "ethminer", "claymore", "nbminer", "t-rex", "phoenixminer",
    "kswapd0",  # common disguise
}

# Suspicious ports (reverse shells, backdoors)
SUSPICIOUS_PORTS = {4444, 4445, 5555, 6666, 8888, 9999, 1337, 31337}


# -- Database ----------------------------------------------------------------

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
    print(f"[{severity.upper()}] [{sensor}] {detail}", flush=True)
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


# -- Configuration -----------------------------------------------------------

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
    try:
        import stat
        os.chmod(CONFIG_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except (OSError, AttributeError):
        pass


# -- HTTP Client -------------------------------------------------------------

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


# -- Enrollment --------------------------------------------------------------

def get_local_ip():
    """Get the local IP address. Prefers Tailscale IP if available."""
    # Try Tailscale IP first (most useful for our mesh network)
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    # Fallback to default route IP
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
    return socket.gethostname()


def enroll(server_url, invitation_string):
    """Enroll this agent with the Citadel server via invitation string."""
    server_url = server_url.rstrip("/")
    url = f"{server_url}/api/ext-agents/enroll"

    hostname = get_hostname()
    ip = get_local_ip()

    print(f"Enrolling with {server_url}...")
    print(f"  Hostname: {hostname}")
    print(f"  IP:       {ip}")

    status_code, resp = http_post(url, {
        "invitation_string": invitation_string,
        "hostname": hostname,
    })

    if status_code != 200:
        detail = resp.get("detail", "Unknown error") if isinstance(resp, dict) else str(resp)
        print(f"Enrollment failed (HTTP {status_code}): {detail}", file=sys.stderr)
        return False

    config = {
        "server_url": server_url,
        "agent_id": resp["agent_id"],
        "api_token": resp["api_token"],
        "agent_name": resp.get("agent_name", hostname),
        "hostname": hostname,
        "ip_address": ip,
        "enrolled_at": datetime.now(timezone.utc).isoformat(),
    }
    save_config(config)

    print(f"Enrolled successfully!")
    print(f"  Agent ID:  {config['agent_id']}")
    print(f"  Name:      {config['agent_name']}")
    print(f"  Server:    {server_url}")
    print(f"  Config:    {CONFIG_PATH}")
    print(f"\nRun 'python3 {os.path.basename(__file__)} install' to start as a systemd service.")
    return True


# -- Sensors -----------------------------------------------------------------

def sensor_auth_log(stop_event):
    """Watch /var/log/auth.log for failed SSH attempts and sudo abuse."""
    conn = init_db()
    fail_tracker = defaultdict(list)  # ip -> [timestamps]
    blocked_ips = set()

    # Find auth log
    log_path = None
    for path in ["/var/log/auth.log", "/var/log/secure"]:
        if os.path.exists(path):
            log_path = path
            break

    if not log_path:
        print("[auth_log] No auth log found, sensor disabled", flush=True)
        return

    try:
        log_file = open(log_path, "r")
        log_file.seek(0, 2)  # seek to end
    except PermissionError:
        print(f"[auth_log] Permission denied: {log_path}", flush=True)
        return

    try:
        while not stop_event.is_set():
            while True:
                line = log_file.readline()
                if not line:
                    break
                line = line.strip()

                # Failed SSH password/key
                m = re.search(
                    r"Failed (?:password|publickey) for .* from ([\d.]+) port",
                    line,
                )
                if m:
                    ip = m.group(1)
                    fail_tracker[ip].append(time.time())
                    count = len(fail_tracker[ip])
                    if count >= SSH_FAIL_THRESHOLD and ip not in blocked_ips:
                        blocked_ips.add(ip)
                        # Try to block via ufw
                        action = _block_ip(ip)
                        store_event(
                            conn, "high", "auth_log", "brute_force_attempt",
                            f"{count} failed SSH from {ip} in {SSH_FAIL_WINDOW}s. {action}",
                        )
                    continue

                # Invalid user
                m = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
                if m:
                    ip = m.group(2)
                    fail_tracker[ip].append(time.time())
                    continue

                # Sudo abuse
                if "authentication failure" in line and "sudo" in line:
                    store_event(
                        conn, "medium", "auth_log", "unauthorized_access",
                        f"Sudo auth failure: {line[-120:]}",
                    )

            # Expire old entries
            now = time.time()
            for ip in list(fail_tracker.keys()):
                fail_tracker[ip] = [
                    t for t in fail_tracker[ip] if now - t < SSH_FAIL_WINDOW
                ]
                if not fail_tracker[ip]:
                    del fail_tracker[ip]

            stop_event.wait(AUTH_LOG_INTERVAL)
    finally:
        log_file.close()
        conn.close()


def _block_ip(ip):
    """Block an IP via ufw or iptables. Returns description of action."""
    try:
        subprocess.run(
            ["ufw", "deny", "from", ip],
            check=True, capture_output=True, timeout=10,
        )
        return f"ufw deny from {ip}"
    except (FileNotFoundError, subprocess.CalledProcessError):
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            return f"iptables drop {ip}"
        except Exception as exc:
            return f"block failed: {exc}"


def sensor_processes(stop_event):
    """Detect crypto miners, high CPU processes, and suspicious listeners."""
    conn = init_db()
    known_pids = set()

    try:
        while not stop_event.is_set():
            # Check processes
            try:
                result = subprocess.run(
                    ["ps", "aux"], capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n")[1:]:
                        parts = line.split(None, 10)
                        if len(parts) < 11:
                            continue
                        pid_str, cpu_str, cmd = parts[1], parts[2], parts[10]
                        try:
                            pid = int(pid_str)
                            cpu = float(cpu_str)
                        except (ValueError, IndexError):
                            continue

                        proc_name = os.path.basename(cmd.split()[0]) if cmd else ""

                        # Known miners
                        if proc_name.lower() in KNOWN_MINERS:
                            if pid not in known_pids:
                                known_pids.add(pid)
                                try:
                                    os.kill(pid, 9)
                                    action = f"killed pid {pid}"
                                except Exception:
                                    action = f"kill failed for pid {pid}"
                                store_event(
                                    conn, "critical", "processes", "process_anomaly",
                                    f"Crypto miner detected: {proc_name} (pid {pid}, "
                                    f"CPU {cpu}%). {action}",
                                )
                            continue

                        # High CPU
                        if cpu > 80.0 and pid not in known_pids:
                            known_pids.add(pid)
                            store_event(
                                conn, "medium", "processes", "process_anomaly",
                                f"High CPU process: {proc_name} (pid {pid}, CPU {cpu}%)",
                            )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            # Check suspicious listeners
            try:
                result = subprocess.run(
                    ["ss", "-tlnp"], capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n")[1:]:
                        m = re.search(r":(\d+)\s+.*users:\(\(\"([^\"]+)\"", line)
                        if m:
                            port, prog = int(m.group(1)), m.group(2)
                            if port in SUSPICIOUS_PORTS:
                                store_event(
                                    conn, "high", "processes", "port_scan_anomaly",
                                    f"Suspicious listener on port {port}: {prog}",
                                )
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

            stop_event.wait(PROCESS_INTERVAL)
    finally:
        conn.close()


def sensor_cron(stop_event):
    """Detect unauthorized crontab modifications."""
    conn = init_db()
    cron_hashes = {}
    initialized = False

    try:
        while not stop_event.is_set():
            current = _hash_crontabs()

            if not initialized:
                cron_hashes = current
                initialized = True
                stop_event.wait(CRON_INTERVAL)
                continue

            # Detect modifications
            for path, new_hash in current.items():
                old_hash = cron_hashes.get(path)
                if old_hash and old_hash != new_hash:
                    store_event(
                        conn, "critical", "cron", "config_change",
                        f"Crontab modified: {path}",
                    )

            # Detect new crontab files
            for path in current:
                if path not in cron_hashes:
                    store_event(
                        conn, "high", "cron", "config_change",
                        f"New crontab detected: {path}",
                    )

            cron_hashes = current
            stop_event.wait(CRON_INTERVAL)
    finally:
        conn.close()


def _hash_crontabs():
    """Hash all crontab files and return {path: sha256hex}."""
    hashes = {}
    # System crontab
    for path in ["/etc/crontab"]:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    hashes[path] = hashlib.sha256(f.read()).hexdigest()
            except PermissionError:
                pass
    # User crontabs
    for cron_dir in ["/var/spool/cron/crontabs", "/var/spool/cron"]:
        if os.path.isdir(cron_dir):
            try:
                for name in os.listdir(cron_dir):
                    full = os.path.join(cron_dir, name)
                    if os.path.isfile(full):
                        with open(full, "rb") as f:
                            hashes[full] = hashlib.sha256(f.read()).hexdigest()
            except PermissionError:
                pass
    # /etc/cron.d/
    if os.path.isdir("/etc/cron.d"):
        try:
            for name in os.listdir("/etc/cron.d"):
                full = os.path.join("/etc/cron.d", name)
                if os.path.isfile(full):
                    with open(full, "rb") as f:
                        hashes[full] = hashlib.sha256(f.read()).hexdigest()
        except PermissionError:
            pass
    return hashes


def sensor_file_integrity(stop_event):
    """Hash critical system files and alert on changes."""
    conn = init_db()
    file_hashes = {}
    initialized = False

    try:
        while not stop_event.is_set():
            current = {}
            for path in CRITICAL_FILES:
                if os.path.exists(path):
                    try:
                        with open(path, "rb") as f:
                            current[path] = hashlib.sha256(f.read()).hexdigest()
                    except PermissionError:
                        pass

            if not initialized:
                file_hashes = current
                initialized = True
                stop_event.wait(FILE_INTEGRITY_INTERVAL)
                continue

            for path, new_hash in current.items():
                old_hash = file_hashes.get(path)
                if old_hash and old_hash != new_hash:
                    store_event(
                        conn, "critical", "file_integrity", "file_integrity",
                        f"Critical file modified: {path}",
                    )

            file_hashes = current
            stop_event.wait(FILE_INTEGRITY_INTERVAL)
    finally:
        conn.close()


def sensor_patch_status(stop_event):
    """Check for pending OS security updates."""
    conn = init_db()

    try:
        while not stop_event.is_set():
            pending_count = 0
            pending_titles = []
            check_status = "unknown"

            # Try apt (Debian/Ubuntu)
            try:
                result = subprocess.run(
                    ["apt", "list", "--upgradable"],
                    capture_output=True, text=True, timeout=60,
                    env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
                )
                if result.returncode == 0:
                    check_status = "ok"
                    for line in result.stdout.strip().split("\n"):
                        if "/" in line and "upgradable" in line.lower():
                            pkg = line.split("/")[0]
                            pending_titles.append(pkg)
                            pending_count += 1
            except FileNotFoundError:
                # Not Debian-based, try dnf
                try:
                    result = subprocess.run(
                        ["dnf", "check-update", "--quiet"],
                        capture_output=True, text=True, timeout=60,
                    )
                    # dnf returns 100 if updates available, 0 if none
                    if result.returncode in (0, 100):
                        check_status = "ok"
                        for line in result.stdout.strip().split("\n"):
                            parts = line.split()
                            if len(parts) >= 3:
                                pending_titles.append(parts[0])
                                pending_count += 1
                except FileNotFoundError:
                    check_status = "error"
            except subprocess.TimeoutExpired:
                check_status = "error"

            # Report to server if enrolled
            config = load_config()
            if config.get("agent_id") and config.get("api_token"):
                _report_patch_status(config, {
                    "pending_count": pending_count,
                    "installed_count": 0,
                    "reboot_required": os.path.exists("/var/run/reboot-required"),
                    "oldest_pending_days": 0,
                    "check_status": check_status,
                    "pending_titles": pending_titles[:20],
                })

            # Alert if many updates pending
            if pending_count > 10:
                store_event(
                    conn, "medium", "patch_status", "vulnerability",
                    f"{pending_count} pending security updates",
                )

            stop_event.wait(PATCH_INTERVAL)
    finally:
        conn.close()


def _report_patch_status(config, patch_data):
    """POST patch status to coordinator."""
    url = f"{config['server_url']}/api/ext-agents/{config['agent_id']}/patch-status"
    http_post(url, patch_data, token=config["api_token"])


def sensor_resources(stop_event):
    """Monitor disk, memory, and CPU load."""
    conn = init_db()

    try:
        while not stop_event.is_set():
            # CPU count for load average comparison
            try:
                cpu_count = os.cpu_count() or 1
            except Exception:
                cpu_count = 1

            # Load average
            try:
                with open("/proc/loadavg", "r") as f:
                    parts = f.read().split()
                    load_1m = float(parts[0])
                    if load_1m > cpu_count * LOAD_ALERT_MULTIPLIER:
                        store_event(
                            conn, "medium", "resources", "process_anomaly",
                            f"High load average: {load_1m:.1f} "
                            f"({cpu_count} CPUs, threshold {cpu_count * LOAD_ALERT_MULTIPLIER:.0f})",
                        )
            except (FileNotFoundError, ValueError, IndexError):
                pass

            # Memory
            try:
                with open("/proc/meminfo", "r") as f:
                    meminfo = {}
                    for line in f:
                        parts = line.split(":")
                        if len(parts) == 2:
                            key = parts[0].strip()
                            val = parts[1].strip().split()[0]
                            meminfo[key] = int(val)
                    total = meminfo.get("MemTotal", 1)
                    available = meminfo.get("MemAvailable", total)
                    used_pct = ((total - available) / total) * 100
                    if used_pct > MEMORY_ALERT_PERCENT:
                        store_event(
                            conn, "medium", "resources", "process_anomaly",
                            f"High memory usage: {used_pct:.0f}% "
                            f"({available // 1024}MB available of {total // 1024}MB)",
                        )
            except (FileNotFoundError, ValueError, KeyError):
                pass

            # Disk usage
            try:
                result = subprocess.run(
                    ["df", "--output=pcent", "/"],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    lines = result.stdout.strip().split("\n")
                    if len(lines) >= 2:
                        pct = int(lines[1].strip().rstrip("%"))
                        if pct > DISK_ALERT_PERCENT:
                            store_event(
                                conn, "high", "resources", "config_change",
                                f"Disk usage critical: {pct}% on /",
                            )
            except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
                pass

            stop_event.wait(RESOURCE_INTERVAL)
    finally:
        conn.close()


# -- Reporting ---------------------------------------------------------------

def report_threats(conn, config):
    """Send unreported events to the Citadel coordinator as threats.

    Uses POST /api/ext-agents/{agent_id}/threats — dedicated endpoint
    for daemon security findings.
    """
    events = get_unreported_events(conn)
    if not events:
        return

    server_url = config.get("server_url", "")
    agent_id   = config.get("agent_id", "")
    token      = config.get("api_token", "")
    hostname   = config.get("hostname", get_hostname())
    threshold  = config.get("alert_threshold", 0)
    reported_ids = []
    suppressed_ids = []

    if not server_url or not agent_id:
        return

    severity_map = {"info": 3, "medium": 5, "high": 7, "critical": 9}

    for event_id, timestamp, severity, sensor, threat_type, detail in events:
        numeric_severity = severity_map.get(severity, 5)

        # Skip events below threshold (mark reported to avoid buildup)
        if threshold > 0 and numeric_severity < threshold:
            suppressed_ids.append(event_id)
            continue

        url = f"{server_url}/api/ext-agents/{agent_id}/threats"
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
        elif code == 401:
            break

    mark_reported(conn, reported_ids + suppressed_ids)


def send_heartbeat(config):
    """Send heartbeat to the server. Processes commands from response."""
    server_url = config["server_url"]
    agent_id = config["agent_id"]
    token = config["api_token"]
    url = f"{server_url}/api/ext-agents/{agent_id}/heartbeat"
    code, resp = http_post(url, {
        "version": VERSION,
        "status_detail": "daemon_running",
    }, token=token)
    if code == 200 and resp:
        try:
            data = json.loads(resp) if isinstance(resp, str) else resp
            # Update alert_threshold
            new_threshold = data.get("alert_threshold", 0)
            if new_threshold != config.get("alert_threshold", 0):
                config["alert_threshold"] = new_threshold
                save_config(config)
            # Process pending commands
            for cmd in data.get("pending_commands", []):
                try:
                    _execute_command(config, cmd)
                except Exception:
                    pass
        except (json.JSONDecodeError, TypeError, AttributeError):
            pass


# -- Command Execution -------------------------------------------------------

# Hard-coded whitelist — the server cannot instruct the daemon to run anything
# outside this set.  Add new actions here AND in the coordinator's playbook.
ALLOWED_ACTIONS = frozenset({
    # Active defense (new)
    "kill_process",
    "block_ip",
    "disable_cron_job",
    "collect_forensics",
    "rotate_ssh_keys",
    "restart_service",
    "apply_patches",
    # Legacy / policy commands
    "check_updates",
    "threat_alert",
    "apply_policy",
})


def _execute_command(config, cmd):
    """Execute a whitelisted command from the coordinator.

    Schema (new): { action_uuid, action_id, parameters }
    Schema (legacy): { command_id, command_type, payload }

    Unknown or non-whitelisted commands are silently rejected.
    Results are reported back via POST /api/ext-agents/{id}/action-result.
    """
    # Support both new (action_id/action_uuid) and legacy (command_type/command_id) schemas
    action_id = cmd.get("action_id") or cmd.get("command_type", "")
    action_uuid = cmd.get("action_uuid") or cmd.get("command_id", "")
    params = cmd.get("parameters") or cmd.get("payload") or {}

    # Hard whitelist check — reject silently
    if action_id not in ALLOWED_ACTIONS:
        print(f"[!] Rejected unknown command: {action_id}", file=sys.stderr, flush=True)
        return None

    result: dict = {"action_id": action_id, "status": "success"}
    exec_status = "success"

    try:
        if action_id == "kill_process":
            result = _cmd_kill_process(params)

        elif action_id == "block_ip":
            result = _cmd_block_ip(params)

        elif action_id == "disable_cron_job":
            result = _cmd_disable_cron_job(params)

        elif action_id == "collect_forensics":
            result = _cmd_collect_forensics()

        elif action_id == "rotate_ssh_keys":
            result = _cmd_rotate_ssh_keys(params)

        elif action_id == "restart_service":
            svc = params.get("service_name", "")
            if not svc:
                raise ValueError("service_name is required")
            subprocess.run(["systemctl", "restart", svc], check=True, timeout=30)
            result = {"action_id": action_id, "service": svc, "status": "restarted"}

        elif action_id == "apply_patches":
            result = _cmd_apply_patches(params)

        elif action_id == "check_updates":
            result = _cmd_check_updates()

        elif action_id == "threat_alert":
            sev = params.get("severity", "unknown")
            desc = params.get("description", "Cross-system alert")
            print(f"[ALERT] ({sev}): {desc}", file=sys.stderr, flush=True)
            result = {"action_id": action_id, "status": "alert_received"}

        elif action_id == "apply_policy":
            threshold = params.get("alert_threshold")
            if threshold is not None:
                config["alert_threshold"] = int(threshold)
                save_config(config)
            result = {"action_id": action_id, "status": f"policy_applied:threshold={threshold}"}

    except Exception as exc:
        exec_status = "failed"
        result = {"action_id": action_id, "status": "failed", "error": str(exc)}
        print(f"[!] Command {action_id} failed: {exc}", file=sys.stderr, flush=True)

    # Report result back to coordinator via ext-agent API
    if action_uuid:
        url = f"{config['server_url']}/api/ext-agents/{config['agent_id']}/action-result"
        http_post(url, {
            "action_uuid": action_uuid,
            "action_id":   action_id,
            "status":      exec_status,
            "result":      result,
            "forensics":   result.pop("forensics", {}),
            "timestamp":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }, token=config["api_token"])

    return result


# -- Active Defense Helpers --------------------------------------------------

def _cmd_kill_process(params):
    """Kill a process by PID, with optional name safety check."""
    pid = int(params.get("pid", 0))
    if pid <= 0:
        raise ValueError("Invalid PID")
    expected_name = params.get("process_name", "")
    if expected_name:
        try:
            comm_path = f"/proc/{pid}/comm"
            with open(comm_path) as f:
                actual = f.read().strip()
            if actual and expected_name not in actual:
                raise ValueError(
                    f"PID {pid} is '{actual}', not '{expected_name}' — refusing kill"
                )
        except FileNotFoundError:
            raise ValueError(f"PID {pid} does not exist")
    os.kill(pid, signal.SIGTERM)
    time.sleep(3)
    try:
        os.kill(pid, 0)  # check still alive
        os.kill(pid, signal.SIGKILL)
        killed_with = "SIGKILL"
    except ProcessLookupError:
        killed_with = "SIGTERM"
    return {"action_id": "kill_process", "pid": pid, "signal": killed_with, "status": "killed"}


def _cmd_block_ip(params):
    """Block a source IP via iptables with timed expiry via `at`."""
    import re
    ip = params.get("source_ip", "").strip()
    if not ip:
        raise ValueError("source_ip is required")
    # Validate bare IPv4 — reject CIDR, ranges, hostnames
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        raise ValueError(f"Invalid IPv4 address: {ip}")
    parts = ip.split(".")
    if any(int(p) > 255 for p in parts):
        raise ValueError(f"Invalid IPv4 address: {ip}")
    # Refuse to block loopback, unspecified, or broadcast
    if parts[0] == "127" or ip in ("0.0.0.0", "255.255.255.255"):
        raise ValueError(f"Refusing to block reserved address: {ip}")
    hours = min(int(params.get("duration_hours", 24)), 72)
    reason = params.get("reason", "citadel_block")
    comment = f"citadel:{reason[:20]}"
    subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
         "-m", "comment", "--comment", comment],
        check=True, timeout=10,
    )
    # Schedule automatic expiry via `at` (best-effort; persists until reboot if `at` unavailable)
    try:
        remove_cmd = (
            f'iptables -D INPUT -s {ip} -j DROP -m comment --comment "{comment}"'
        )
        subprocess.run(
            ["at", f"now + {hours} hours"],
            input=remove_cmd.encode(),
            capture_output=True, timeout=5,
        )
    except Exception:
        pass  # `at` may not be installed; rule persists until reboot
    return {"action_id": "block_ip", "ip": ip, "duration_hours": hours, "status": "blocked"}


def _cmd_disable_cron_job(params):
    """Comment out matching cron entries in /etc/crontab and /etc/cron.d/*."""
    pattern = params.get("cron_pattern", "").strip()
    if not pattern:
        raise ValueError("cron_pattern is required")
    disabled = []
    cron_files = ["/etc/crontab"] + [
        str(p) for p in __import__("pathlib").Path("/etc/cron.d").glob("*")
        if p.is_file()
    ]
    for cron_file in cron_files:
        try:
            with open(cron_file) as f:
                lines = f.readlines()
            new_lines = []
            changed = False
            for line in lines:
                if pattern in line and not line.strip().startswith("#"):
                    new_lines.append(f"# [citadel-disabled] {line}")
                    disabled.append({"file": cron_file, "entry": line.strip()})
                    changed = True
                else:
                    new_lines.append(line)
            if changed:
                with open(cron_file, "w") as f:
                    f.writelines(new_lines)
        except (OSError, PermissionError):
            continue
    return {"action_id": "disable_cron_job", "pattern": pattern, "disabled": disabled}


def _cmd_rotate_ssh_keys(params):
    """Revoke all existing SSH authorized_keys for a user."""
    username = params.get("username", "root").strip()
    if not username or "/" in username or username.startswith("."):
        raise ValueError(f"Invalid username: {username}")
    # Locate authorized_keys
    if username == "root":
        auth_keys = "/root/.ssh/authorized_keys"
    else:
        auth_keys = f"/home/{username}/.ssh/authorized_keys"
    backed_up = False
    try:
        if os.path.exists(auth_keys):
            backup = auth_keys + ".citadel_backup"
            with open(auth_keys) as f:
                content = f.read()
            with open(backup, "w") as f:
                f.write(content)
            backed_up = True
            # Truncate (revoke all keys)
            with open(auth_keys, "w") as f:
                f.write("# Cleared by Citadel Archer active defense\n")
        return {
            "action_id": "rotate_ssh_keys",
            "username": username,
            "keys_file": auth_keys,
            "backed_up": backed_up,
            "status": "revoked",
        }
    except (OSError, PermissionError) as exc:
        raise ValueError(f"Failed to rotate SSH keys for {username}: {exc}") from exc


def _cmd_collect_forensics():
    """Collect a forensics snapshot of the current system state."""
    data = {}
    cmds = {
        "processes":    ["ps", "aux", "--no-headers"],
        "connections":  ["ss", "-tnup"],
        "logins":       ["last", "-n", "20"],
        "disk":         ["df", "-h"],
        "memory":       ["free", "-m"],
    }
    for key, cmd in cmds.items():
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            data[key] = r.stdout.strip()
        except Exception as exc:
            data[key] = f"error: {exc}"
    return {"action_id": "collect_forensics", "forensics": data, "status": "collected"}


def _cmd_apply_patches(params):
    """Apply OS security patches."""
    security_only = params.get("security_only", True)
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    try:
        if security_only:
            subprocess.run(
                ["apt-get", "upgrade", "-y", "--only-upgrade",
                 "-o", "Dir::Etc::SourceList=/dev/null"],
                check=True, timeout=300, env=env,
            )
        else:
            subprocess.run(
                ["apt-get", "upgrade", "-y"],
                check=True, timeout=300, env=env,
            )
        return {"action_id": "apply_patches", "status": "patches_applied", "manager": "apt"}
    except FileNotFoundError:
        pass
    try:
        args = ["dnf", "update", "-y"]
        if security_only:
            args.append("--security")
        subprocess.run(args, check=True, timeout=300)
        return {"action_id": "apply_patches", "status": "patches_applied", "manager": "dnf"}
    except FileNotFoundError:
        raise ValueError("No supported package manager found (apt/dnf)")


def _cmd_check_updates():
    """Check for available package updates."""
    try:
        subprocess.run(
            ["apt", "update"],
            capture_output=True, timeout=120,
            env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        return {"action_id": "check_updates", "status": "triggered_apt_update"}
    except FileNotFoundError:
        pass
    try:
        subprocess.run(["dnf", "check-update"], capture_output=True, timeout=120)
        return {"action_id": "check_updates", "status": "triggered_dnf_check"}
    except FileNotFoundError:
        return {"action_id": "check_updates", "status": "no_package_manager"}


# -- Daemon ------------------------------------------------------------------

def daemon(config):
    """Run the monitoring daemon.

    Each sensor thread creates its own SQLite connection to avoid
    cross-thread sharing (SQLite connections are not thread-safe).
    The main loop uses a dedicated connection for report_threats().
    """
    init_db().close()

    stop_event = threading.Event()

    def handle_signal(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    AGENT_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    print(f"Citadel Daemon v{VERSION} (Linux)", flush=True)
    print(f"Agent ID: {config['agent_id']}", flush=True)
    print(f"Server:   {config['server_url']}", flush=True)
    print(f"Monitoring started. Ctrl+C to stop.", flush=True)

    sensors = [
        ("auth_log", sensor_auth_log),
        ("processes", sensor_processes),
        ("cron", sensor_cron),
        ("file_integrity", sensor_file_integrity),
        ("patch_status", sensor_patch_status),
        ("resources", sensor_resources),
    ]

    threads = []
    for name, func in sensors:
        t = threading.Thread(target=func, args=(stop_event,), daemon=True, name=name)
        t.start()
        threads.append(t)
        print(f"  [+] Sensor started: {name}", flush=True)

    # Main loop: heartbeat + report
    main_conn = init_db()
    last_heartbeat = 0
    last_report = 0

    # Send initial heartbeat immediately
    try:
        send_heartbeat(config)
        print("  [+] Initial heartbeat sent", flush=True)
    except Exception:
        print("  [!] Initial heartbeat failed (will retry)", flush=True)

    try:
        while not stop_event.is_set():
            now = time.monotonic()

            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                try:
                    send_heartbeat(config)
                except Exception:
                    pass
                last_heartbeat = now

            if now - last_report >= REPORT_INTERVAL:
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
        print("\nShutdown complete.", flush=True)


# -- Status ------------------------------------------------------------------

def get_status():
    """Get agent status as JSON dict."""
    config = load_config()
    result = {
        "version": VERSION,
        "enrolled": bool(config.get("agent_id")),
        "agent_id": config.get("agent_id", ""),
        "server_url": config.get("server_url", ""),
        "hostname": get_hostname(),
        "ip": get_local_ip(),
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


# -- Systemd Service ---------------------------------------------------------

def install_service():
    """Create and enable the systemd service."""
    python_path = subprocess.run(
        ["which", "python3"], capture_output=True, text=True,
    ).stdout.strip() or sys.executable or "python3"
    script_path = os.path.abspath(__file__)

    service_content = f"""[Unit]
Description=Citadel Daemon - VPS Security Agent
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart={python_path} {script_path} daemon
WorkingDirectory={AGENT_DIR}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=citadel-daemon

[Install]
WantedBy=multi-user.target
"""

    service_path = Path("/etc/systemd/system/citadel-daemon.service")
    service_path.write_text(service_content)

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "citadel-daemon"], check=True)

    print(f"Service installed: {service_path}")
    print(f"Start with: systemctl start citadel-daemon")
    print(f"View logs:  journalctl -u citadel-daemon -f")


def uninstall_service():
    """Stop, disable, and remove the systemd service."""
    subprocess.run(["systemctl", "stop", "citadel-daemon"], capture_output=True)
    subprocess.run(["systemctl", "disable", "citadel-daemon"], capture_output=True)
    service_path = Path("/etc/systemd/system/citadel-daemon.service")
    if service_path.exists():
        service_path.unlink()
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    print("Service uninstalled.")


# -- CLI ---------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(f"Citadel Daemon v{VERSION} (Linux VPS Security Agent)")
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
            print(
                f"Usage: {sys.argv[0]} enroll <server_url> <invitation_string>",
                file=sys.stderr,
            )
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
        install_service()

    elif command == "uninstall":
        uninstall_service()

    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
