#!/usr/bin/env python3
"""Citadel Archer — Agent Keepalive

Minimal standalone script that sends heartbeats to the Citadel coordinator.
No AI inference. No dependencies beyond Python 3.8+ stdlib.

Usage:
  # First-time setup (saves config):
  python3 keepalive.py setup --coordinator http://100.68.75.8:8000 \
                              --agent-id f468e151e1bf4165994b76ea9b84615d \
                              --token YOUR_API_TOKEN

  # Run once (called by cron or systemd timer):
  python3 keepalive.py

  # Run as a daemon (blocking loop):
  python3 keepalive.py --daemon --interval 60

Install as cron (heartbeat every minute):
  (crontab -l 2>/dev/null; echo "* * * * * /usr/bin/python3 /opt/citadel/keepalive.py >> /var/log/citadel-keepalive.log 2>&1") | crontab -

Install as systemd timer (recommended):
  See: python3 keepalive.py install-systemd
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("CITADEL_CONFIG", "/opt/citadel/keepalive.json"))
VERSION = "1.0.0"


# ── Config ──────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        print(f"[ERROR] Config not found: {CONFIG_PATH}", file=sys.stderr)
        print("Run: python3 keepalive.py setup --coordinator URL --agent-id ID --token TOKEN",
              file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(CONFIG_PATH.read_text())
    except Exception as e:
        print(f"[ERROR] Failed to read config: {e}", file=sys.stderr)
        sys.exit(1)


def save_config(coordinator: str, agent_id: str, token: str) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps({
        "coordinator": coordinator.rstrip("/"),
        "agent_id": agent_id,
        "token": token,
        "version": VERSION,
    }, indent=2))
    # Restrict permissions — token is sensitive
    CONFIG_PATH.chmod(0o600)
    print(f"[OK] Config saved to {CONFIG_PATH}")


# ── Heartbeat ────────────────────────────────────────────────────────────────

def send_heartbeat(coordinator: str, agent_id: str, token: str) -> bool:
    """POST /api/ext-agents/{agent_id}/heartbeat. Returns True on success."""
    url = f"{coordinator}/api/ext-agents/{agent_id}/heartbeat"
    payload = json.dumps({"version": VERSION, "status_detail": "keepalive"}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": f"citadel-keepalive/{VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
            ts = body.get("last_seen") or body.get("timestamp", "ok")
            print(f"[HB] Heartbeat sent — {ts}")
            return True
    except urllib.error.HTTPError as e:
        print(f"[ERROR] Heartbeat failed: HTTP {e.code} {e.reason}", file=sys.stderr)
        if e.code == 401:
            print("[ERROR] Invalid token — check config or re-enroll", file=sys.stderr)
        return False
    except urllib.error.URLError as e:
        print(f"[ERROR] Cannot reach coordinator ({url}): {e.reason}", file=sys.stderr)
        print("[ERROR] Check Tailscale is running and coordinator is reachable", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[ERROR] Heartbeat error: {e}", file=sys.stderr)
        return False


# ── Systemd install ──────────────────────────────────────────────────────────

_SYSTEMD_SERVICE = """\
[Unit]
Description=Citadel Archer Agent Keepalive
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
Type=simple
ExecStart={python} {script} --daemon --interval 60
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

_SYSTEMD_TIMER = """\
[Unit]
Description=Citadel Archer Agent Heartbeat (every minute)
After=network-online.target tailscaled.service

[Timer]
OnBootSec=30
OnUnitActiveSec=60
AccuracySec=10

[Install]
WantedBy=timers.target
"""

def install_systemd(script_path: Path) -> None:
    import shutil
    python = shutil.which("python3") or "/usr/bin/python3"

    service_path = Path("/etc/systemd/system/citadel-keepalive.service")
    service_path.write_text(_SYSTEMD_SERVICE.format(python=python, script=script_path))
    service_path.chmod(0o644)

    print(f"[OK] Service installed: {service_path}")
    print("Run:")
    print("  systemctl daemon-reload")
    print("  systemctl enable --now citadel-keepalive.service")
    print("  journalctl -fu citadel-keepalive")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Citadel Archer agent keepalive — sends heartbeats to the coordinator",
    )
    sub = parser.add_subparsers(dest="command")

    # setup
    s = sub.add_parser("setup", help="Save connection config (run once)")
    s.add_argument("--coordinator", required=True, help="Coordinator URL, e.g. http://100.68.75.8:8000")
    s.add_argument("--agent-id", required=True, help="Your agent ID from enrollment")
    s.add_argument("--token", required=True, help="Your API token from enrollment")

    # install-systemd
    sub.add_parser("install-systemd", help="Install as a systemd service")

    # run (default — no subcommand or explicit 'run')
    parser.add_argument("--daemon", action="store_true",
                        help="Run in a loop instead of sending one heartbeat")
    parser.add_argument("--interval", type=int, default=60,
                        help="Heartbeat interval in seconds (daemon mode, default: 60)")

    args = parser.parse_args()

    if args.command == "setup":
        save_config(args.coordinator, args.agent_id, args.token)
        cfg = load_config()
        print("[TEST] Sending test heartbeat...")
        ok = send_heartbeat(cfg["coordinator"], cfg["agent_id"], cfg["token"])
        sys.exit(0 if ok else 1)

    if args.command == "install-systemd":
        install_systemd(Path(__file__).resolve())
        return

    # Default: send one heartbeat (or loop in daemon mode)
    cfg = load_config()
    coordinator = cfg["coordinator"]
    agent_id = cfg["agent_id"]
    token = cfg["token"]

    if args.daemon:
        print(f"[START] Citadel keepalive daemon — heartbeat every {args.interval}s")
        while True:
            send_heartbeat(coordinator, agent_id, token)
            time.sleep(args.interval)
    else:
        ok = send_heartbeat(coordinator, agent_id, token)
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
