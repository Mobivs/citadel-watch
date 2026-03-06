# LAN Sentinel — local network device discovery and alerting.
#
# Periodically sweeps the local subnet for devices via nmap (preferred)
# or Windows-native ARP table (fallback). New/unknown devices trigger a
# Guardian alert and WebSocket broadcast.
#
# Architecture:
#   LanDeviceStore  — SQLite registry at data/lan_devices.db
#   LanScanner      — async background task; runs every LAN_SCAN_INTERVAL seconds

import asyncio
import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional

logger = logging.getLogger(__name__)

_OS = platform.system()
_SCAN_INTERVAL = int(os.environ.get("LAN_SCAN_INTERVAL", "300"))  # 5 minutes

_WIN_FLAGS = (
    subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    if _OS == "Windows"
    else 0
)

_DB_PATH = Path("data/lan_devices.db")

# ── Device Store ───────────────────────────────────────────────────────────────

_store_instance: Optional["LanDeviceStore"] = None
_store_lock = threading.Lock()


class LanDeviceStore:
    """SQLite registry of LAN devices.

    Each row represents a MAC address (primary key). On upsert, ip / hostname /
    manufacturer / last_seen are updated. first_seen and is_known are immutable
    after insertion (is_known only changes via mark_known()).
    """

    def __init__(self, db_path: Path = _DB_PATH):
        self.db_path = db_path
        self._lock = threading.RLock()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        from ..core.db import connect as db_connect
        self._conn = db_connect(str(db_path), check_same_thread=False, row_factory=True)
        self._create_tables()

    def _create_tables(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS lan_devices (
                    mac          TEXT PRIMARY KEY,
                    ip           TEXT,
                    hostname     TEXT,
                    manufacturer TEXT,
                    first_seen   TEXT NOT NULL,
                    last_seen    TEXT NOT NULL,
                    is_known     INTEGER NOT NULL DEFAULT 0,
                    label        TEXT
                );
            """)
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.commit()

    # ── Writes ────────────────────────────────────────────────────────────────

    def upsert(self, device: Dict[str, Any]) -> bool:
        """Insert or update a device record. Returns True if it is a NEW device."""
        mac = (device.get("mac") or "").upper().strip()
        if not mac:
            return False
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._lock:
            existing = self._conn.execute(
                "SELECT mac FROM lan_devices WHERE mac = ?", (mac,)
            ).fetchone()
            is_new = existing is None
            if is_new:
                self._conn.execute(
                    """
                    INSERT INTO lan_devices
                        (mac, ip, hostname, manufacturer, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        mac,
                        device.get("ip", ""),
                        device.get("hostname", ""),
                        device.get("manufacturer", ""),
                        now,
                        now,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    UPDATE lan_devices
                    SET ip=?, hostname=?, manufacturer=?, last_seen=?
                    WHERE mac=?
                    """,
                    (
                        device.get("ip", ""),
                        device.get("hostname", ""),
                        device.get("manufacturer", ""),
                        now,
                        mac,
                    ),
                )
            self._conn.commit()
        return is_new

    def mark_known(self, mac: str, label: Optional[str] = None) -> bool:
        """Mark a device as acknowledged. Returns True if the device existed."""
        mac = mac.upper().strip()
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE lan_devices SET is_known=1, label=? WHERE mac=?",
                (label, mac),
            )
            self._conn.commit()
        return cursor.rowcount > 0

    # ── Reads ─────────────────────────────────────────────────────────────────

    def get_all(self) -> List[Dict]:
        """Return all devices, new/unknown first, then by last_seen descending."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT * FROM lan_devices
                ORDER BY is_known ASC, last_seen DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def get_new(self) -> List[Dict]:
        """Return devices not yet acknowledged by the user (is_known=0)."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM lan_devices WHERE is_known=0"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_by_mac(self, mac: str) -> Optional[Dict]:
        """Fetch a single device by MAC address."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM lan_devices WHERE mac=?", (mac.upper().strip(),)
            ).fetchone()
        return dict(row) if row else None

    def count(self) -> Dict[str, int]:
        """Return {total, new} counts."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM lan_devices").fetchone()[0]
            new = self._conn.execute(
                "SELECT COUNT(*) FROM lan_devices WHERE is_known=0"
            ).fetchone()[0]
        return {"total": total, "new": new}


def get_lan_device_store() -> LanDeviceStore:
    """Return the process-wide LanDeviceStore singleton."""
    global _store_instance
    with _store_lock:
        if _store_instance is None:
            _store_instance = LanDeviceStore()
        return _store_instance


# ── LAN Scanner ────────────────────────────────────────────────────────────────

class LanScanner:
    """Background task that sweeps the local subnet and alerts on new devices.

    New device flow:
        _process_results()
            → aggregator.ingest(event_type='lan.new_device', severity='alert')
            → await broadcast({'type': 'lan_device_discovered', 'device': {...}})

    Constructor args:
        device_store  — LanDeviceStore singleton
        aggregator    — EventAggregator singleton (from app.state)
        broadcast     — manager.broadcast coroutine (from main.py ConnectionManager)
        loop          — asyncio event loop (from startup_event)
    """

    def __init__(
        self,
        device_store: LanDeviceStore,
        aggregator: Any,
        broadcast: Callable[..., Coroutine],
        loop: asyncio.AbstractEventLoop,
    ):
        self._store = device_store
        self._aggregator = aggregator
        self._broadcast = broadcast
        self._loop = loop
        self._running = False
        self._scan_task: Optional[asyncio.Future] = None
        self._last_scan: Optional[str] = None
        self._scan_mode: str = "initializing"  # "nmap" | "native" | "initializing"
        self._subnet: Optional[str] = None
        self._subnet_scan_count: int = 0
        self._SUBNET_REFRESH_EVERY: int = 12  # re-detect every ~1 hour at 5-min intervals

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the background scan loop on the asyncio event loop."""
        if self._running:
            return
        self._running = True
        self._scan_task = asyncio.run_coroutine_threadsafe(
            self._scan_loop(), self._loop
        )
        logger.info("[LAN] Scanner started (interval=%ds)", _SCAN_INTERVAL)

    def stop(self) -> None:
        """Cancel the background scan loop."""
        self._running = False
        if self._scan_task and not self._scan_task.done():
            self._scan_task.cancel()
        logger.info("[LAN] Scanner stopped")

    # ── Public API (called by lan_routes) ─────────────────────────────────────

    async def scan_once(self) -> Dict[str, Any]:
        """Run one scan immediately. Returns status dict."""
        devices = await self._run_scan()
        new_devices = await self._process_results(devices)
        self._last_scan = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        counts = self._store.count()
        return {
            "scanned": len(devices),
            "new": len(new_devices),
            "total": counts["total"],
            "new_total": counts["new"],
            "subnet": self._subnet or "unknown",
            "mode": self._scan_mode,
            "timestamp": self._last_scan,
        }

    def status(self) -> Dict[str, Any]:
        """Return scanner status for the /api/lan/status endpoint."""
        counts = self._store.count()
        return {
            "last_scan": self._last_scan,
            "device_count": counts["total"],
            "new_count": counts["new"],
            "scanner_active": self._running,
            "scan_interval": _SCAN_INTERVAL,
            "subnet": self._subnet or "unknown",
            "mode": self._scan_mode,
        }

    # ── Internal loop ─────────────────────────────────────────────────────────

    async def _scan_loop(self) -> None:
        """Periodic scan loop. Runs immediately, then every _SCAN_INTERVAL seconds."""
        try:
            # First scan runs right away to populate baseline
            await asyncio.sleep(10)  # Give server time to fully start
            while self._running:
                try:
                    await self.scan_once()
                except Exception as exc:
                    logger.warning("[LAN] Scan error: %s", exc)
                await asyncio.sleep(_SCAN_INTERVAL)
        except asyncio.CancelledError:
            pass

    # ── Scanning ──────────────────────────────────────────────────────────────

    async def _run_scan(self) -> List[Dict]:
        """Detect subnet and run the appropriate scanner."""
        loop = asyncio.get_running_loop()
        self._subnet_scan_count += 1
        if self._subnet is None or self._subnet_scan_count >= self._SUBNET_REFRESH_EVERY:
            self._subnet = await loop.run_in_executor(None, self._detect_subnet)
            self._subnet_scan_count = 0

        if shutil.which("nmap"):
            self._scan_mode = "nmap"
            devices = await loop.run_in_executor(None, self._scan_nmap, self._subnet)
        else:
            self._scan_mode = "native"
            devices = await loop.run_in_executor(None, self._scan_native)

        return devices

    def _detect_subnet(self) -> str:
        """Detect the local LAN subnet (e.g. 192.168.1.0/24).

        Strategy: Get the non-loopback IPv4 address and prefix length, then
        compute the network CIDR. Falls back to 192.168.1.0/24 if detection fails.
        """
        try:
            if _OS == "Windows":
                result = subprocess.run(
                    [
                        "powershell",
                        "-NonInteractive",
                        "-NoProfile",
                        "-Command",
                        (
                            "Get-NetIPAddress -AddressFamily IPv4 "
                            "| Where-Object {$_.PrefixLength -lt 32 "
                            "-and $_.IPAddress -notlike '169.*' "
                            "-and $_.IPAddress -ne '127.0.0.1' "
                            "-and $_.InterfaceAlias -notlike '*Loopback*'} "
                            "| Select-Object -First 1 IPAddress,PrefixLength "
                            "| ConvertTo-Json"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=_WIN_FLAGS,
                )
                data = json.loads(result.stdout.strip())
                ip = data.get("IPAddress") or data.get("value", {}).get("IPAddress")
                prefix = data.get("PrefixLength") or data.get("value", {}).get("PrefixLength", 24)
                iface = ipaddress.ip_interface(f"{ip}/{prefix}")
                return str(iface.network)
            else:
                # Linux: use ip route default
                result = subprocess.run(
                    ["ip", "route"],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 1 and "/" in parts[0] and parts[0] != "default":
                        try:
                            ipaddress.ip_network(parts[0], strict=False)
                            return parts[0]
                        except ValueError:
                            continue
                # Fallback: use socket to find local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    s.connect(("8.8.8.8", 80))
                    local_ip = s.getsockname()[0]
                finally:
                    s.close()
                return str(ipaddress.ip_interface(f"{local_ip}/24").network)
        except Exception as exc:
            logger.warning("[LAN] Subnet detection failed (%s), using 192.168.1.0/24", exc)
            return "192.168.1.0/24"

    def _scan_nmap(self, subnet: str) -> List[Dict]:
        """Run nmap ping sweep and parse XML output.

        Returns list of {mac, ip, hostname, manufacturer} dicts.
        """
        try:
            result = subprocess.run(
                [
                    "nmap", "-sn",
                    "--host-timeout", "5s",
                    "-oX", "-",
                    subnet,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                creationflags=_WIN_FLAGS,
            )
            return self._parse_nmap_xml(result.stdout)
        except subprocess.TimeoutExpired:
            logger.warning("[LAN] nmap timed out on %s", subnet)
            return []
        except Exception as exc:
            logger.warning("[LAN] nmap scan failed: %s", exc)
            return []

    def _parse_nmap_xml(self, xml_text: str) -> List[Dict]:
        """Parse nmap XML output into device dicts."""
        devices: List[Dict] = []
        if not xml_text.strip():
            return devices
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("[LAN] nmap XML parse error: %s", exc)
            return devices

        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.get("state") != "up":
                continue
            device: Dict[str, str] = {"mac": "", "ip": "", "hostname": "", "manufacturer": ""}
            for addr in host.findall("address"):
                atype = addr.get("addrtype", "")
                if atype == "ipv4":
                    device["ip"] = addr.get("addr", "")
                elif atype == "mac":
                    device["mac"] = addr.get("addr", "").upper()
                    device["manufacturer"] = addr.get("vendor", "")
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    device["hostname"] = hn.get("name", "")
            # Try ARP table if nmap omitted the MAC (e.g. the scan host itself)
            if device["ip"] and not device["mac"]:
                device["mac"] = self._arp_lookup(device["ip"])
            # Only append devices with both IP and MAC — empty MAC can't be stored
            if device["ip"] and device["mac"]:
                devices.append(device)
        return devices

    def _scan_native(self) -> List[Dict]:
        """Windows-native ARP scan using Get-NetNeighbor + arp -a fallback."""
        devices: List[Dict] = []
        try:
            if _OS == "Windows":
                result = subprocess.run(
                    [
                        "powershell",
                        "-NonInteractive",
                        "-NoProfile",
                        "-Command",
                        (
                            "Get-NetNeighbor -AddressFamily IPv4 -State Reachable "
                            "| Select-Object IPAddress,LinkLayerAddress "
                            "| ConvertTo-Json -Compress"
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    creationflags=_WIN_FLAGS,
                )
                raw = result.stdout.strip()
                if not raw:
                    return devices
                data = json.loads(raw)
                if isinstance(data, dict):
                    data = [data]
                for entry in data:
                    ip = entry.get("IPAddress", "")
                    mac = (entry.get("LinkLayerAddress") or "").replace("-", ":").upper()
                    if ip and mac and not ip.startswith("169."):
                        devices.append({
                            "mac": mac, "ip": ip,
                            "hostname": "", "manufacturer": "",
                        })
            else:
                # Linux: parse arp -n output
                result = subprocess.run(
                    ["arp", "-n"], capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != "<incomplete>":
                        devices.append({
                            "mac": parts[2].upper(), "ip": parts[0],
                            "hostname": "", "manufacturer": "",
                        })
        except Exception as exc:
            logger.warning("[LAN] Native scan failed: %s", exc)
        return devices

    def _arp_lookup(self, ip: str) -> str:
        """Try to find a MAC for a given IP from the system ARP table."""
        try:
            if _OS == "Windows":
                result = subprocess.run(
                    ["arp", "-a", ip],
                    capture_output=True, text=True, timeout=5, creationflags=_WIN_FLAGS
                )
                for line in result.stdout.splitlines():
                    if ip in line:
                        parts = line.split()
                        for p in parts:
                            if "-" in p and len(p) == 17:
                                return p.replace("-", ":").upper()
            else:
                result = subprocess.run(
                    ["arp", "-n", ip], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2].upper()
        except Exception:
            pass
        return ""

    # ── Alert / Persist ───────────────────────────────────────────────────────

    async def _process_results(self, devices: List[Dict]) -> List[Dict]:
        """Upsert each device, collect new ones, fire alerts."""
        new_devices: List[Dict] = []
        for device in devices:
            is_new = self._store.upsert(device)
            if is_new:
                new_devices.append(device)
                await self._alert_new_device(device)

        if devices:
            counts = self._store.count()
            logger.info(
                "[LAN] Scan complete: %d found, %d new, %d total known",
                len(devices), len(new_devices), counts["total"],
            )
        return new_devices

    async def _alert_new_device(self, device: Dict) -> None:
        """Ingest a Guardian alert and broadcast a WebSocket event for a new device."""
        mac = device.get("mac", "unknown")
        ip = device.get("ip", "unknown")
        mfr = device.get("manufacturer", "")
        description = f"New device on LAN: {ip} ({mac})"
        if mfr:
            description += f" — {mfr}"

        # Guardian alert (appears in Timeline)
        try:
            self._aggregator.ingest(
                event_type="lan.new_device",
                severity="alert",
                message=description,
                asset_id="localhost",
                details={"mac": mac, "ip": ip, "manufacturer": mfr},
            )
        except Exception as exc:
            logger.warning("[LAN] Failed to ingest alert: %s", exc)

        # WebSocket broadcast (live toast in LAN Sentinel tab)
        try:
            await self._broadcast({
                "type": "lan_device_discovered",
                "device": device,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
        except Exception as exc:
            logger.warning("[LAN] WebSocket broadcast failed: %s", exc)
