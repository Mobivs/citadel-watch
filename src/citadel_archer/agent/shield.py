#!/usr/bin/env python3
"""
Citadel Shield — Lightweight VPS Protection Agent

Deployed to /opt/citadel-shield/shield.py on remote VPS servers.
Runs as a systemd service (citadel-shield.service).

CONSTRAINTS:
  - Python 3.8+ stdlib ONLY (no pip dependencies)
  - Single file (easy to SCP deploy)
  - Must run as root for auth.log access and ufw/iptables

SENSORS:
  - auth_log    : tail /var/log/auth.log for failed SSH, sudo abuse
  - processes   : detect crypto miners, reverse shells, suspicious listeners
  - cron        : hash crontabs, detect unauthorized changes
  - file_integrity : hash critical system files

TRIPWIRE RULES (hardcoded, no AI):
  - >10 failed SSH from same IP in 60s → block via ufw
  - Unauthorized cron change → critical alert
  - Unknown process on listening port → alert
  - Critical file modified → critical alert

AUTONOMOUS ACTIONS:
  - block_ip(ip) : ufw deny from <ip>
  - kill_process(pid) : kill -9

CLI (for Citadel desktop to query over SSH):
  shield.py status              → JSON health status
  shield.py events --since <id> → unsynced events as JSON
  shield.py ack --through <id>  → mark events synced

Storage: SQLite at /opt/citadel-shield/events.db
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
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ───────────────────────────────────────────────────

AGENT_DIR = Path("/opt/citadel-shield")
DB_PATH = AGENT_DIR / "events.db"
CONFIG_PATH = AGENT_DIR / "config.json"
PID_FILE = AGENT_DIR / "shield.pid"
VERSION = "0.1.0"

# Sensor intervals (seconds)
AUTH_LOG_INTERVAL = 5
PROCESS_INTERVAL = 30
CRON_INTERVAL = 60
FILE_INTEGRITY_INTERVAL = 120

# Tripwire thresholds (defaults — overridden by config.json)
SSH_FAIL_THRESHOLD = 10
SSH_FAIL_WINDOW = 60  # seconds

# fail2ban++ defaults (overridden by config.json)
DEFAULT_BAN_DURATIONS = [300, 3600, 86400]  # 5min, 1hr, 24hr
DEFAULT_PERMANENT_BAN_AFTER = 5
BAN_CHECK_INTERVAL = 60  # seconds

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

# ── Database ────────────────────────────────────────────────────────

def init_db(db_path=None):
    """Initialize the events database."""
    path = db_path or DB_PATH
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            sensor TEXT NOT NULL DEFAULT 'system',
            detail TEXT NOT NULL DEFAULT '',
            action_taken TEXT DEFAULT '',
            synced INTEGER DEFAULT 0
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_synced ON events(synced)"
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            ban_count INTEGER DEFAULT 1,
            banned_at TEXT NOT NULL,
            expires_at TEXT,
            reason TEXT DEFAULT '',
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bans_ip ON ip_bans(ip)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_bans_active ON ip_bans(is_active)"
    )
    conn.commit()
    return conn


def log_event(conn, severity, sensor, detail, action_taken=""):
    """Write an event to the local event store."""
    ts = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO events (timestamp, severity, sensor, detail, action_taken) "
        "VALUES (?, ?, ?, ?, ?)",
        (ts, severity, sensor, detail, action_taken),
    )
    conn.commit()
    # Also print for systemd journal
    print(f"[{severity.upper()}] [{sensor}] {detail}" +
          (f" → {action_taken}" if action_taken else ""), flush=True)


def get_events_since(conn, since_id=0):
    """Get unsynced events since a given ID."""
    rows = conn.execute(
        "SELECT id, timestamp, severity, sensor, detail, action_taken "
        "FROM events WHERE id > ? AND synced = 0 ORDER BY id ASC",
        (since_id,),
    ).fetchall()
    return [
        {
            "id": r[0], "timestamp": r[1], "severity": r[2],
            "sensor": r[3], "detail": r[4], "action_taken": r[5],
        }
        for r in rows
    ]


def ack_through(conn, through_id):
    """Mark all events up to through_id as synced."""
    conn.execute("UPDATE events SET synced = 1 WHERE id <= ?", (through_id,))
    conn.commit()


# ── Configuration Loading ──────────────────────────────────────────

def _load_config():
    """Load config.json if it exists, return empty dict otherwise."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except (json.JSONDecodeError, PermissionError, OSError):
        pass
    return {}


# ── Autonomous Actions ──────────────────────────────────────────────

def _apply_firewall_block(ip):
    """Low-level firewall block using ufw or iptables fallback."""
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


def unblock_ip(ip):
    """Remove a firewall block for an IP address."""
    try:
        subprocess.run(
            ["ufw", "delete", "deny", "from", ip],
            check=True, capture_output=True, timeout=10,
        )
        return f"ufw unblocked {ip}"
    except (FileNotFoundError, subprocess.CalledProcessError):
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            return f"iptables unblocked {ip}"
        except Exception as exc:
            return f"unblock failed: {exc}"


def block_ip(ip, conn=None, ban_duration=None):
    """Block an IP with progressive banning (fail2ban++).

    First offense: 5 min ban.  Second: 1 hour.  Third: 24 hours.
    After 5 offenses: permanent.  Whitelisted IPs are skipped.

    Args:
        ip: IP address to block.
        conn: SQLite connection for persistent ban tracking (optional).
        ban_duration: Override duration in seconds (None = progressive).

    Returns:
        Description of the action taken.
    """
    config = _load_config()
    whitelist = config.get("ip_whitelist", [])
    if ip in whitelist:
        return f"skipped (whitelisted): {ip}"

    # Determine ban count from history
    ban_count = 0
    if conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM ip_bans WHERE ip = ?", (ip,)
        ).fetchone()
        ban_count = row[0] if row else 0

    # Progressive duration
    durations = config.get("ban_durations", DEFAULT_BAN_DURATIONS)
    permanent_after = config.get("permanent_ban_after", DEFAULT_PERMANENT_BAN_AFTER)

    if ban_duration is None:
        if ban_count >= permanent_after:
            ban_duration = None  # permanent
        elif ban_count < len(durations):
            ban_duration = durations[ban_count]
        else:
            ban_duration = durations[-1]

    # Apply firewall rule
    result = _apply_firewall_block(ip)

    # Record ban in database
    if conn:
        now = datetime.now(timezone.utc).isoformat()
        expires = None
        if ban_duration is not None:
            from datetime import timedelta
            expires = (datetime.now(timezone.utc) + timedelta(seconds=ban_duration)).isoformat()
        conn.execute(
            "INSERT INTO ip_bans (ip, ban_count, banned_at, expires_at, reason, is_active) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            (ip, ban_count + 1, now, expires, f"SSH brute force ({ban_count + 1}x)"),
        )
        conn.commit()

    duration_str = f"{ban_duration}s" if ban_duration else "permanent"
    return f"{result} (duration: {duration_str}, offense #{ban_count + 1})"


def kill_process(pid):
    """Kill a process by PID."""
    try:
        os.kill(pid, signal.SIGKILL)
        return f"killed pid {pid}"
    except (ProcessLookupError, PermissionError) as exc:
        return f"kill failed: {exc}"


# ── Ban Expiry Manager ─────────────────────────────────────────────

class BanExpiryManager:
    """Periodically checks for expired bans and unblocks IPs."""

    def __init__(self, conn):
        self.conn = conn

    def check_expired_bans(self):
        """Unblock IPs whose ban has expired. Returns count of expired bans."""
        now = datetime.now(timezone.utc).isoformat()
        expired = self.conn.execute(
            "SELECT id, ip FROM ip_bans WHERE is_active = 1 "
            "AND expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        ).fetchall()

        for ban_id, ip in expired:
            result = unblock_ip(ip)
            self.conn.execute(
                "UPDATE ip_bans SET is_active = 0 WHERE id = ?", (ban_id,)
            )
            log_event(self.conn, "info", "fail2ban",
                      f"Ban expired for {ip}: {result}")

        if expired:
            self.conn.commit()
        return len(expired)


# ── Port Knock Guard ───────────────────────────────────────────────

class PortKnockGuard:
    """iptables-based port knocking using the kernel's xt_recent module.

    No external daemon needed. Uses iptables chains with the ``recent``
    match to track knock sequences.  The SSH port is blocked by default;
    only after knocking the correct sequence does it open briefly.
    """

    def __init__(self, config=None):
        cfg = config or _load_config()
        self.knock_ports = cfg.get("knock_sequence", [])
        self.ssh_port = cfg.get("ssh_port", 22)
        self.open_time = cfg.get("knock_open_time", 30)
        self._applied = False

    def apply_rules(self):
        """Install iptables port-knocking rules. Idempotent."""
        if not self.knock_ports:
            return False

        # Remove existing rules first
        self._flush_chain("CITADEL-KNOCK")

        # Create the chain
        subprocess.run(["iptables", "-N", "CITADEL-KNOCK"],
                       capture_output=True, timeout=10)

        # Rule 1: If SSH_OPEN is set recently, accept
        subprocess.run([
            "iptables", "-A", "CITADEL-KNOCK", "-m", "recent",
            "--rcheck", "--seconds", str(self.open_time), "--name", "SSH_OPEN",
            "-j", "ACCEPT",
        ], capture_output=True, timeout=10)

        # Stage transitions: knock1 → knock2 → ... → SSH_OPEN
        for i, port in enumerate(self.knock_ports):
            if i == 0:
                # First knock: any SYN to port sets KNOCK1
                subprocess.run([
                    "iptables", "-A", "CITADEL-KNOCK",
                    "-p", "tcp", "--dport", str(port),
                    "-m", "recent", "--set", "--name", "KNOCK1",
                    "-j", "DROP",
                ], capture_output=True, timeout=10)
            else:
                prev_name = f"KNOCK{i}"
                next_name = f"KNOCK{i + 1}" if i < len(self.knock_ports) - 1 else "SSH_OPEN"
                subprocess.run([
                    "iptables", "-A", "CITADEL-KNOCK",
                    "-p", "tcp", "--dport", str(port),
                    "-m", "recent", "--rcheck", "--seconds", "15", "--name", prev_name,
                    "-m", "recent", "--set", "--name", next_name,
                    "-j", "DROP",
                ], capture_output=True, timeout=10)

        # Jump to CITADEL-KNOCK for SSH port traffic
        subprocess.run([
            "iptables", "-I", "INPUT", "-p", "tcp",
            "--dport", str(self.ssh_port), "-j", "CITADEL-KNOCK",
        ], capture_output=True, timeout=10)

        self._applied = True
        return True

    def remove_rules(self):
        """Remove all port-knocking iptables rules."""
        subprocess.run([
            "iptables", "-D", "INPUT", "-p", "tcp",
            "--dport", str(self.ssh_port), "-j", "CITADEL-KNOCK",
        ], capture_output=True, timeout=10)
        self._flush_chain("CITADEL-KNOCK")
        self._applied = False

    def _flush_chain(self, chain):
        subprocess.run(["iptables", "-F", chain],
                       capture_output=True, timeout=10)
        subprocess.run(["iptables", "-X", chain],
                       capture_output=True, timeout=10)

    @property
    def is_active(self):
        return self._applied


# ── Firewall Rule Manager ──────────────────────────────────────────

class FirewallRuleManager:
    """Apply dynamic iptables firewall rules from config.json.

    Manages a dedicated CITADEL-FW iptables chain.  Rules are loaded
    from the ``firewall_rules`` array in config.json and applied in
    priority order (lower number = higher priority).

    Supports:
      - deny / allow / rate_limit actions
      - IP, CIDR, or geo:XX country-code sources
      - TCP/UDP/ICMP/any protocol filters
      - Port and port-range filters
    """

    CHAIN = "CITADEL-FW"
    GEO_CIDRS_PATH = AGENT_DIR / "geo_cidrs.dat"

    def __init__(self, config=None):
        cfg = config or _load_config()
        self._rules = cfg.get("firewall_rules", [])
        self._applied = False

    def apply_rules(self):
        """Install CITADEL-FW chain with all configured rules. Idempotent."""
        if not self._rules:
            return False

        self._flush_chain()

        # Create the chain
        subprocess.run(["iptables", "-N", self.CHAIN],
                       capture_output=True, timeout=10)

        # Sort by priority (ascending = higher priority first)
        sorted_rules = sorted(self._rules, key=lambda r: r.get("priority", 100))

        for rule in sorted_rules:
            if not rule.get("enabled", True):
                continue
            action = rule.get("action", "deny")
            source = rule.get("source", "")

            if source.startswith("geo:"):
                cidrs = self._resolve_geo_cidrs(source[4:])
                for cidr in cidrs:
                    self._apply_single_rule(rule, override_source=cidr)
            elif action == "rate_limit":
                self._apply_rate_limit(rule)
            else:
                self._apply_single_rule(rule)

        # Jump to CITADEL-FW from INPUT for inbound rules
        subprocess.run([
            "iptables", "-I", "INPUT", "-j", self.CHAIN,
        ], capture_output=True, timeout=10)

        self._applied = True
        return True

    def remove_rules(self):
        """Remove the CITADEL-FW chain from iptables."""
        subprocess.run([
            "iptables", "-D", "INPUT", "-j", self.CHAIN,
        ], capture_output=True, timeout=10)
        self._flush_chain()
        self._applied = False

    def reload(self):
        """Reload rules from config.json."""
        cfg = _load_config()
        self._rules = cfg.get("firewall_rules", [])
        if self._applied:
            self.remove_rules()
        if self._rules:
            self.apply_rules()

    def _apply_single_rule(self, rule, override_source=None):
        """Convert a rule dict to a single iptables command."""
        action = rule.get("action", "deny")
        source = override_source or rule.get("source", "any")
        protocol = rule.get("protocol", "any")
        port = rule.get("port", "")

        target = "DROP" if action == "deny" else "ACCEPT"

        cmd = ["iptables", "-A", self.CHAIN]

        if source and source != "any":
            cmd += ["-s", source]

        if protocol and protocol != "any":
            cmd += ["-p", protocol]
            if port:
                cmd += ["--dport", port]

        cmd += ["-j", target]
        subprocess.run(cmd, capture_output=True, timeout=10)

    def _apply_rate_limit(self, rule):
        """Apply a rate-limit rule using iptables hashlimit module."""
        source = rule.get("source", "any")
        protocol = rule.get("protocol", "tcp")
        port = rule.get("port", "")
        rate = rule.get("rate", "100/minute")

        cmd = ["iptables", "-A", self.CHAIN]

        if source and source != "any":
            cmd += ["-s", source]
        if protocol and protocol != "any":
            cmd += ["-p", protocol]
            if port:
                cmd += ["--dport", port]

        cmd += [
            "-m", "hashlimit",
            "--hashlimit-above", rate,
            "--hashlimit-mode", "srcip",
            "--hashlimit-name", "citadel_ratelimit",
            "-j", "DROP",
        ]
        subprocess.run(cmd, capture_output=True, timeout=10)

    def _resolve_geo_cidrs(self, country_code):
        """Read CIDRs for a country code from geo_cidrs.dat.

        File format: one line per entry, ``CC CIDR`` (space-separated).
        Returns list of CIDR strings for the given country code.
        """
        cidrs = []
        cc = country_code.upper()
        try:
            if self.GEO_CIDRS_PATH.exists():
                with open(self.GEO_CIDRS_PATH) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) == 2 and parts[0].upper() == cc:
                            cidrs.append(parts[1])
        except (OSError, PermissionError):
            pass
        return cidrs

    def _flush_chain(self):
        subprocess.run(["iptables", "-F", self.CHAIN],
                       capture_output=True, timeout=10)
        subprocess.run(["iptables", "-X", self.CHAIN],
                       capture_output=True, timeout=10)

    @property
    def is_active(self):
        return self._applied

    def get_status(self):
        """Return JSON-serializable status dict."""
        return {
            "active": self._applied,
            "rule_count": len(self._rules),
            "rules": self._rules,
        }


# ── Sensors ─────────────────────────────────────────────────────────

class AuthLogSensor:
    """Watch /var/log/auth.log for failed SSH attempts and sudo abuse."""

    def __init__(self, conn):
        self.conn = conn
        self._log_path = self._find_auth_log()
        self._file = None
        self._fail_tracker = defaultdict(list)  # ip → [timestamps]
        self._blocked_ips = set()
        # Load configurable thresholds
        config = _load_config()
        self._threshold = config.get("fail_threshold", SSH_FAIL_THRESHOLD)
        self._window = config.get("fail_window", SSH_FAIL_WINDOW)

    @staticmethod
    def _find_auth_log():
        for path in ["/var/log/auth.log", "/var/log/secure"]:
            if os.path.exists(path):
                return path
        return None

    def start(self):
        if not self._log_path:
            print("[auth_log] No auth log found, sensor disabled", flush=True)
            return
        try:
            self._file = open(self._log_path, "r")
            self._file.seek(0, 2)  # seek to end
        except PermissionError:
            print(f"[auth_log] Permission denied: {self._log_path}", flush=True)
            self._file = None

    def poll(self):
        if not self._file:
            return

        while True:
            line = self._file.readline()
            if not line:
                break
            self._process_line(line.strip())

        # Expire old entries from fail tracker
        now = time.time()
        for ip in list(self._fail_tracker.keys()):
            self._fail_tracker[ip] = [
                t for t in self._fail_tracker[ip]
                if now - t < self._window
            ]
            if not self._fail_tracker[ip]:
                del self._fail_tracker[ip]

    def _process_line(self, line):
        # Failed SSH password/key
        m = re.search(
            r"Failed (?:password|publickey) for .* from ([\d.]+) port",
            line,
        )
        if m:
            ip = m.group(1)
            self._fail_tracker[ip].append(time.time())
            count = len(self._fail_tracker[ip])

            if count >= self._threshold and ip not in self._blocked_ips:
                action = block_ip(ip, conn=self.conn)
                self._blocked_ips.add(ip)
                log_event(
                    self.conn, "high", "auth_log",
                    f"{count} failed SSH attempts from {ip} in {self._window}s",
                    action,
                )
            return

        # Invalid user
        m = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
        if m:
            user, ip = m.group(1), m.group(2)
            self._fail_tracker[ip].append(time.time())
            return

        # Sudo abuse
        if "authentication failure" in line and "sudo" in line:
            log_event(
                self.conn, "medium", "auth_log",
                f"Sudo authentication failure: {line[-120:]}",
            )


class ProcessSensor:
    """Detect crypto miners, reverse shells, and suspicious listeners."""

    def __init__(self, conn):
        self.conn = conn
        self._known_pids = set()

    def poll(self):
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=10,
            )
        except Exception:
            return

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

            # Check for known miners
            if proc_name.lower() in KNOWN_MINERS:
                if pid not in self._known_pids:
                    self._known_pids.add(pid)
                    action = kill_process(pid)
                    log_event(
                        self.conn, "critical", "processes",
                        f"Crypto miner detected: {proc_name} (pid {pid}, CPU {cpu}%)",
                        action,
                    )
                continue

            # High CPU unknown process (>80% sustained)
            if cpu > 80.0 and pid not in self._known_pids:
                self._known_pids.add(pid)
                log_event(
                    self.conn, "medium", "processes",
                    f"High CPU process: {proc_name} (pid {pid}, CPU {cpu}%)",
                )

        # Check for suspicious listening ports
        self._check_listeners()

    def _check_listeners(self):
        try:
            result = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=10,
            )
        except Exception:
            return

        for line in result.stdout.strip().split("\n")[1:]:
            # Look for unusual high ports with unknown programs
            m = re.search(r":(\d+)\s+.*users:\(\(\"([^\"]+)\"", line)
            if m:
                port, prog = int(m.group(1)), m.group(2)
                # Flag common reverse shell ports
                if port in (4444, 4445, 5555, 6666, 8888, 9999, 1337, 31337):
                    log_event(
                        self.conn, "high", "processes",
                        f"Suspicious listener on port {port}: {prog}",
                    )


class CronSensor:
    """Detect unauthorized crontab modifications."""

    def __init__(self, conn):
        self.conn = conn
        self._cron_hashes = {}
        self._initialized = False

    def poll(self):
        current_hashes = self._hash_crontabs()

        if not self._initialized:
            self._cron_hashes = current_hashes
            self._initialized = True
            return

        for path, new_hash in current_hashes.items():
            old_hash = self._cron_hashes.get(path)
            if old_hash and old_hash != new_hash:
                log_event(
                    self.conn, "critical", "cron",
                    f"Crontab modified: {path} (was {old_hash[:12]}, now {new_hash[:12]})",
                )

        # Check for new crontab files
        for path in current_hashes:
            if path not in self._cron_hashes:
                log_event(
                    self.conn, "high", "cron",
                    f"New crontab detected: {path}",
                )

        self._cron_hashes = current_hashes

    @staticmethod
    def _hash_crontabs():
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
        cron_dir = "/var/spool/cron/crontabs"
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
        cron_d = "/etc/cron.d"
        if os.path.isdir(cron_d):
            try:
                for name in os.listdir(cron_d):
                    full = os.path.join(cron_d, name)
                    if os.path.isfile(full):
                        with open(full, "rb") as f:
                            hashes[full] = hashlib.sha256(f.read()).hexdigest()
            except PermissionError:
                pass

        return hashes


class FileIntegritySensor:
    """Hash critical system files and alert on changes."""

    def __init__(self, conn):
        self.conn = conn
        self._file_hashes = {}
        self._initialized = False

    def poll(self):
        current_hashes = {}
        for path in CRITICAL_FILES:
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        current_hashes[path] = hashlib.sha256(f.read()).hexdigest()
                except PermissionError:
                    pass

        if not self._initialized:
            self._file_hashes = current_hashes
            self._initialized = True
            return

        for path, new_hash in current_hashes.items():
            old_hash = self._file_hashes.get(path)
            if old_hash and old_hash != new_hash:
                log_event(
                    self.conn, "critical", "file_integrity",
                    f"Critical file modified: {path}",
                )

        self._file_hashes = current_hashes


# ── Daemon ──────────────────────────────────────────────────────────

class ShieldDaemon:
    """Main daemon loop that runs all sensors."""

    def __init__(self, db_path=None):
        self.conn = init_db(db_path)
        self.running = False

        self.auth_sensor = AuthLogSensor(self.conn)
        self.process_sensor = ProcessSensor(self.conn)
        self.cron_sensor = CronSensor(self.conn)
        self.file_sensor = FileIntegritySensor(self.conn)
        self.ban_expiry = BanExpiryManager(self.conn)
        self.port_knock = PortKnockGuard()
        self.firewall_mgr = FirewallRuleManager()

    def start(self):
        """Run the daemon loop."""
        self.running = True
        self.auth_sensor.start()

        # Apply firewall rules if configured
        if self.firewall_mgr._rules:
            if self.firewall_mgr.apply_rules():
                log_event(
                    self.conn, "info", "system",
                    f"Firewall rules applied: {len(self.firewall_mgr._rules)} rules",
                )

        # Apply port knocking rules if configured
        if self.port_knock.knock_ports:
            if self.port_knock.apply_rules():
                log_event(
                    self.conn, "info", "system",
                    f"Port knocking enabled: sequence {self.port_knock.knock_ports}, "
                    f"SSH port {self.port_knock.ssh_port}",
                )

        # Write PID file
        try:
            PID_FILE.parent.mkdir(parents=True, exist_ok=True)
            PID_FILE.write_text(str(os.getpid()))
        except Exception:
            pass

        log_event(
            self.conn, "info", "system",
            f"Citadel Shield v{VERSION} started (pid {os.getpid()})",
        )

        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

        # Sensor timing
        last_auth = 0
        last_proc = 0
        last_cron = 0
        last_file = 0
        last_ban_check = 0
        last_config_check = 0
        config_mtime = self._get_config_mtime()

        while self.running:
            now = time.time()

            if now - last_auth >= AUTH_LOG_INTERVAL:
                self.auth_sensor.poll()
                last_auth = now

            if now - last_proc >= PROCESS_INTERVAL:
                self.process_sensor.poll()
                last_proc = now

            if now - last_cron >= CRON_INTERVAL:
                self.cron_sensor.poll()
                last_cron = now

            if now - last_file >= FILE_INTEGRITY_INTERVAL:
                self.file_sensor.poll()
                last_file = now

            if now - last_ban_check >= BAN_CHECK_INTERVAL:
                self.ban_expiry.check_expired_bans()
                last_ban_check = now

            # Hot-reload config.json on mtime change (every 30s)
            if now - last_config_check >= 30:
                new_mtime = self._get_config_mtime()
                if new_mtime and new_mtime != config_mtime:
                    config_mtime = new_mtime
                    self.firewall_mgr.reload()
                    log_event(self.conn, "info", "system",
                              "config.json changed — firewall rules reloaded")
                last_config_check = now

            time.sleep(1)

        log_event(self.conn, "info", "system", "Citadel Shield stopped")
        try:
            PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass

    @staticmethod
    def _get_config_mtime():
        """Get config.json mtime or None."""
        try:
            return os.path.getmtime(str(CONFIG_PATH))
        except OSError:
            return None

    def _handle_signal(self, signum, frame):
        print(f"[system] Received signal {signum}, shutting down...", flush=True)
        self.running = False


# ── CLI ─────────────────────────────────────────────────────────────

def cli_status(db_path=None):
    """Print agent health status as JSON."""
    conn = init_db(db_path)
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    unsynced = conn.execute(
        "SELECT COUNT(*) FROM events WHERE synced = 0"
    ).fetchone()[0]

    pid = None
    running = False
    try:
        if PID_FILE.exists():
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)  # check if process exists
            running = True
    except (ValueError, ProcessLookupError, PermissionError):
        pass

    status = {
        "version": VERSION,
        "running": running,
        "pid": pid,
        "total_events": total,
        "unsynced_events": unsynced,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
    }
    print(json.dumps(status))


def cli_events(since_id=0, db_path=None):
    """Print unsynced events as JSON."""
    conn = init_db(db_path)
    events = get_events_since(conn, since_id)
    print(json.dumps({"events": events, "count": len(events)}))


def cli_ack(through_id, db_path=None):
    """Mark events as synced through a given ID."""
    conn = init_db(db_path)
    ack_through(conn, through_id)
    print(json.dumps({"acknowledged_through": through_id}))


def cli_hardening_status(db_path=None):
    """Print current SSH hardening status as JSON."""
    conn = init_db(db_path)
    config = _load_config()

    active_bans = conn.execute(
        "SELECT COUNT(*) FROM ip_bans WHERE is_active = 1"
    ).fetchone()[0]
    permanent_bans = conn.execute(
        "SELECT COUNT(*) FROM ip_bans WHERE is_active = 1 AND expires_at IS NULL"
    ).fetchone()[0]
    total_bans = conn.execute(
        "SELECT COUNT(*) FROM ip_bans"
    ).fetchone()[0]

    status = {
        "port_knocking_enabled": bool(config.get("knock_sequence")),
        "knock_sequence": config.get("knock_sequence", []),
        "ssh_port": config.get("ssh_port", 22),
        "fail_threshold": config.get("fail_threshold", SSH_FAIL_THRESHOLD),
        "fail_window": config.get("fail_window", SSH_FAIL_WINDOW),
        "ban_durations": config.get("ban_durations", DEFAULT_BAN_DURATIONS),
        "active_bans": active_bans,
        "permanent_bans": permanent_bans,
        "total_bans_ever": total_bans,
        "ip_whitelist": config.get("ip_whitelist", []),
    }
    print(json.dumps(status))


def cli_firewall_status():
    """Print firewall rule status as JSON."""
    config = _load_config()
    rules = config.get("firewall_rules", [])
    print(json.dumps({
        "rule_count": len(rules),
        "rules": rules,
        "geo_cidrs_exists": Path(AGENT_DIR / "geo_cidrs.dat").exists(),
    }))


def main():
    """Entry point: daemon mode or CLI commands."""
    if len(sys.argv) < 2:
        print(f"Citadel Shield v{VERSION}")
        print("Usage:")
        print("  shield.py daemon                  — Run as daemon")
        print("  shield.py status                  — Agent health (JSON)")
        print("  shield.py hardening-status        — SSH hardening status (JSON)")
        print("  shield.py firewall-status         — Firewall rule status (JSON)")
        print("  shield.py events [--since <id>]   — Unsynced events (JSON)")
        print("  shield.py ack --through <id>      — Mark events synced")
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "daemon":
        daemon = ShieldDaemon()
        daemon.start()

    elif cmd == "status":
        cli_status()

    elif cmd == "hardening-status":
        cli_hardening_status()

    elif cmd == "firewall-status":
        cli_firewall_status()

    elif cmd == "events":
        since_id = 0
        if "--since" in sys.argv:
            idx = sys.argv.index("--since")
            if idx + 1 < len(sys.argv):
                since_id = int(sys.argv[idx + 1])
        cli_events(since_id)

    elif cmd == "ack":
        if "--through" in sys.argv:
            idx = sys.argv.index("--through")
            if idx + 1 < len(sys.argv):
                through_id = int(sys.argv[idx + 1])
                cli_ack(through_id)
            else:
                print("Error: --through requires an ID", file=sys.stderr)
                sys.exit(1)
        else:
            print("Error: ack requires --through <id>", file=sys.stderr)
            sys.exit(1)

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
