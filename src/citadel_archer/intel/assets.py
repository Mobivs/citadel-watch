# PRD: Intel Module - Asset Inventory
# Reference: PHASE_2_SPEC.md, ASSET_MANAGEMENT_ADDENDUM.md
#
# Defines the Asset model and AssetInventory manager for tracking
# protected endpoints (local machines, VPS instances, etc.).
# Each asset has a platform type, status, and associated metadata.
#
# v0.2.5: SQLite persistence added. The in-memory dict acts as a
# write-through cache — every mutation is persisted immediately.

import json
import logging
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


class AssetPlatform(str, Enum):
    """Platform type for a managed asset."""

    LOCAL = "local"       # Local development machine
    VPS = "vps"           # Virtual Private Server
    WINDOWS = "windows"   # Windows workstation/server
    MAC = "macos"         # macOS workstation
    LINUX = "linux"       # Linux workstation (non-VPS)


class AssetType(str, Enum):
    """Physical/logical type of the asset."""

    VPS = "vps"
    LAN = "lan"
    WORKSTATION = "workstation"
    CLOUD = "cloud"


class AssetStatus(str, Enum):
    """Current protection status of an asset."""

    ONLINE = "online"             # Asset is reachable and reporting
    OFFLINE = "offline"           # Asset not responding
    PROTECTED = "protected"       # Asset online with guardian active
    COMPROMISED = "compromised"   # Asset flagged as compromised
    UNKNOWN = "unknown"           # Newly added, not yet tested

    @property
    def is_healthy(self) -> bool:
        return self in (AssetStatus.ONLINE, AssetStatus.PROTECTED)


@dataclass
class Asset:
    """A managed endpoint in the Citadel security perimeter.

    Represents a machine (local, VPS, workstation) that Citadel
    monitors and protects.
    """

    asset_id: str = field(default_factory=lambda: f"asset_{uuid4().hex[:12]}")
    name: str = ""
    platform: AssetPlatform = AssetPlatform.LOCAL
    asset_type: AssetType = AssetType.VPS
    status: AssetStatus = AssetStatus.UNKNOWN
    hostname: str = ""
    ip_address: str = ""
    os_version: str = ""
    guardian_active: bool = False
    ssh_port: int = 22
    ssh_username: str = "root"
    ssh_credential_id: str = ""
    remote_shield_agent_id: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["platform"] = self.platform.value
        d["asset_type"] = self.asset_type.value
        d["status"] = self.status.value
        return d

    def touch(self) -> None:
        """Update ``last_seen`` to now."""
        self.last_seen = datetime.utcnow().isoformat()


# Default DB path
_DEFAULT_DB_PATH = Path("data/assets.db")


class AssetInventory:
    """Thread-safe registry of managed assets with SQLite persistence.

    The in-memory ``_assets`` dict acts as a write-through cache.
    Every mutation is persisted to SQLite immediately. On init, the
    cache is populated from the database.

    Args:
        db_path: Path to the SQLite database file. Set to ``None``
                 to run in memory-only mode (tests, backwards compat).
    """

    def __init__(self, db_path: Optional[Path] = _DEFAULT_DB_PATH):
        self._lock = threading.RLock()
        self._assets: Dict[str, Asset] = {}
        self._db_path = db_path

        if self._db_path is not None:
            self._db_path = Path(self._db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_database()
            self._load_from_db()

    # ------------------------------------------------------------------
    # Database setup
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        from ..core.db import connect as db_connect

        return db_connect(self._db_path, row_factory=True)

    def _init_database(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS managed_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    hostname TEXT DEFAULT '',
                    ip_address TEXT DEFAULT '',
                    platform TEXT DEFAULT 'local',
                    asset_type TEXT DEFAULT 'vps',
                    status TEXT DEFAULT 'unknown',
                    os_version TEXT DEFAULT '',
                    guardian_active INTEGER DEFAULT 0,
                    ssh_credential_id TEXT DEFAULT '',
                    ssh_port INTEGER DEFAULT 22,
                    ssh_username TEXT DEFAULT 'root',
                    remote_shield_agent_id TEXT DEFAULT '',
                    tags TEXT DEFAULT '[]',
                    notes TEXT DEFAULT '',
                    metadata TEXT DEFAULT '{}',
                    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_assets_status ON managed_assets(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_assets_type ON managed_assets(asset_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_assets_ip ON managed_assets(ip_address)")
            conn.commit()

    def _load_from_db(self):
        """Populate in-memory cache from database."""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM managed_assets").fetchall()
        for row in rows:
            asset = self._row_to_asset(row)
            self._assets[asset.asset_id] = asset
        if rows:
            logger.info(f"Loaded {len(rows)} assets from database")

    @staticmethod
    def _row_to_asset(row: sqlite3.Row) -> "Asset":
        """Convert a database row to an Asset dataclass."""
        tags = []
        try:
            tags = json.loads(row["tags"] or "[]")
        except (json.JSONDecodeError, TypeError):
            pass

        metadata = {}
        try:
            metadata = json.loads(row["metadata"] or "{}")
        except (json.JSONDecodeError, TypeError):
            pass

        # Safe enum parsing with fallbacks
        try:
            platform = AssetPlatform(row["platform"])
        except ValueError:
            platform = AssetPlatform.LOCAL

        try:
            asset_type = AssetType(row["asset_type"])
        except ValueError:
            asset_type = AssetType.VPS

        try:
            status = AssetStatus(row["status"])
        except ValueError:
            status = AssetStatus.UNKNOWN

        return Asset(
            asset_id=row["asset_id"],
            name=row["name"] or "",
            platform=platform,
            asset_type=asset_type,
            status=status,
            hostname=row["hostname"] or "",
            ip_address=row["ip_address"] or "",
            os_version=row["os_version"] or "",
            guardian_active=bool(row["guardian_active"]),
            ssh_port=row["ssh_port"] or 22,
            ssh_username=row["ssh_username"] or "root",
            ssh_credential_id=row["ssh_credential_id"] or "",
            remote_shield_agent_id=row["remote_shield_agent_id"] or "",
            tags=tags,
            notes=row["notes"] or "",
            metadata=metadata,
            registered_at=row["registered_at"] or "",
            last_seen=row["last_seen"] or "",
        )

    def _persist_asset(self, asset: Asset):
        """Insert or replace an asset in the database."""
        if self._db_path is None:
            return
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO managed_assets
                (asset_id, name, hostname, ip_address, platform, asset_type,
                 status, os_version, guardian_active, ssh_credential_id,
                 ssh_port, ssh_username, remote_shield_agent_id,
                 tags, notes, metadata, registered_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                asset.asset_id,
                asset.name,
                asset.hostname,
                asset.ip_address,
                asset.platform.value,
                asset.asset_type.value,
                asset.status.value,
                asset.os_version,
                int(asset.guardian_active),
                asset.ssh_credential_id,
                asset.ssh_port,
                asset.ssh_username,
                asset.remote_shield_agent_id,
                json.dumps(asset.tags),
                asset.notes,
                json.dumps(asset.metadata),
                asset.registered_at,
                asset.last_seen,
            ))
            conn.commit()

    def _delete_from_db(self, asset_id: str):
        """Remove an asset from the database."""
        if self._db_path is None:
            return
        with self._get_conn() as conn:
            conn.execute("DELETE FROM managed_assets WHERE asset_id = ?", (asset_id,))
            conn.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(self, asset: Asset) -> str:
        """Register an asset. Returns its ``asset_id``."""
        with self._lock:
            self._assets[asset.asset_id] = asset
            self._persist_asset(asset)
        return asset.asset_id

    def get(self, asset_id: str) -> Optional[Asset]:
        """Look up an asset by ID."""
        with self._lock:
            return self._assets.get(asset_id)

    def update(self, asset_id: str, **kwargs) -> Optional[Asset]:
        """Update fields on an existing asset. Returns the updated asset or None."""
        with self._lock:
            asset = self._assets.get(asset_id)
            if asset is None:
                return None

            for key, value in kwargs.items():
                if key == "platform" and isinstance(value, str):
                    value = AssetPlatform(value)
                elif key == "asset_type" and isinstance(value, str):
                    value = AssetType(value)
                elif key == "status" and isinstance(value, str):
                    value = AssetStatus(value)

                if hasattr(asset, key):
                    setattr(asset, key, value)

            asset.touch()
            self._persist_asset(asset)
            return asset

    def remove(self, asset_id: str) -> bool:
        """Remove an asset. Returns True if it existed."""
        with self._lock:
            removed = self._assets.pop(asset_id, None) is not None
            if removed:
                self._delete_from_db(asset_id)
            return removed

    def all(self) -> List[Asset]:
        """Return a snapshot list of all assets."""
        with self._lock:
            return list(self._assets.values())

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._assets)

    # ------------------------------------------------------------------
    # Status management
    # ------------------------------------------------------------------

    def set_status(self, asset_id: str, status: AssetStatus) -> bool:
        """Update an asset's status. Returns False if not found."""
        with self._lock:
            asset = self._assets.get(asset_id)
            if asset is None:
                return False
            asset.status = status
            asset.touch()
            self._persist_asset(asset)
            return True

    def mark_online(self, asset_id: str) -> bool:
        return self.set_status(asset_id, AssetStatus.ONLINE)

    def mark_offline(self, asset_id: str) -> bool:
        return self.set_status(asset_id, AssetStatus.OFFLINE)

    def mark_protected(self, asset_id: str) -> bool:
        return self.set_status(asset_id, AssetStatus.PROTECTED)

    def mark_compromised(self, asset_id: str) -> bool:
        return self.set_status(asset_id, AssetStatus.COMPROMISED)

    # ------------------------------------------------------------------
    # Linking helpers
    # ------------------------------------------------------------------

    def link_remote_shield_agent(self, asset_id: str, agent_id: str) -> bool:
        """Link a Remote Shield agent to this asset."""
        return self.update(asset_id, remote_shield_agent_id=agent_id) is not None

    def link_ssh_credential(self, asset_id: str, credential_id: str) -> bool:
        """Link a Vault SSH credential to this asset."""
        return self.update(asset_id, ssh_credential_id=credential_id) is not None

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def by_platform(self, platform: AssetPlatform) -> List[Asset]:
        """Return all assets matching a platform type."""
        with self._lock:
            return [a for a in self._assets.values() if a.platform == platform]

    def by_status(self, status: AssetStatus) -> List[Asset]:
        """Return all assets with a given status."""
        with self._lock:
            return [a for a in self._assets.values() if a.status == status]

    def healthy(self) -> List[Asset]:
        """Return assets with a healthy status (ONLINE or PROTECTED)."""
        with self._lock:
            return [a for a in self._assets.values() if a.status.is_healthy]

    def find_by_hostname(self, hostname: str) -> Optional[Asset]:
        """Look up an asset by hostname (case-insensitive)."""
        hn = hostname.lower()
        with self._lock:
            for a in self._assets.values():
                if a.hostname.lower() == hn:
                    return a
        return None

    def find_by_ip(self, ip_address: str) -> Optional[Asset]:
        """Look up an asset by IP address."""
        with self._lock:
            for a in self._assets.values():
                if a.ip_address == ip_address:
                    return a
        return None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Summary counts by platform and status."""
        with self._lock:
            by_platform: Dict[str, int] = {}
            by_status: Dict[str, int] = {}
            for a in self._assets.values():
                by_platform[a.platform.value] = by_platform.get(a.platform.value, 0) + 1
                by_status[a.status.value] = by_status.get(a.status.value, 0) + 1
            return {
                "total": len(self._assets),
                "by_platform": by_platform,
                "by_status": by_status,
            }
