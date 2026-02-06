# PRD: Intel Module - Asset Inventory
# Reference: PHASE_2_SPEC.md
#
# Defines the Asset model and AssetInventory manager for tracking
# protected endpoints (local machines, VPS instances, etc.).
# Each asset has a platform type, status, and associated metadata.

import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4


class AssetPlatform(str, Enum):
    """Platform type for a managed asset."""

    LOCAL = "local"       # Local development machine
    VPS = "vps"           # Virtual Private Server
    WINDOWS = "windows"   # Windows workstation/server
    MAC = "macos"         # macOS workstation
    LINUX = "linux"       # Linux workstation (non-VPS)


class AssetStatus(str, Enum):
    """Current protection status of an asset."""

    ONLINE = "online"             # Asset is reachable and reporting
    OFFLINE = "offline"           # Asset not responding
    PROTECTED = "protected"       # Asset online with guardian active
    COMPROMISED = "compromised"   # Asset flagged as compromised

    @property
    def is_healthy(self) -> bool:
        return self in (AssetStatus.ONLINE, AssetStatus.PROTECTED)


@dataclass
class Asset:
    """A managed endpoint in the Citadel security perimeter.

    Represents a machine (local, VPS, workstation) that Citadel
    monitors and protects.
    """

    asset_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    platform: AssetPlatform = AssetPlatform.LOCAL
    status: AssetStatus = AssetStatus.ONLINE
    hostname: str = ""
    ip_address: str = ""
    os_version: str = ""
    guardian_active: bool = False
    tags: List[str] = field(default_factory=list)
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
        d["status"] = self.status.value
        return d

    def touch(self) -> None:
        """Update ``last_seen`` to now."""
        self.last_seen = datetime.utcnow().isoformat()


class AssetInventory:
    """Thread-safe registry of managed assets.

    Provides CRUD operations, status transitions, and querying
    by platform or status.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._assets: Dict[str, Asset] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(self, asset: Asset) -> str:
        """Register an asset. Returns its ``asset_id``."""
        with self._lock:
            self._assets[asset.asset_id] = asset
        return asset.asset_id

    def get(self, asset_id: str) -> Optional[Asset]:
        """Look up an asset by ID."""
        with self._lock:
            return self._assets.get(asset_id)

    def remove(self, asset_id: str) -> bool:
        """Remove an asset. Returns True if it existed."""
        with self._lock:
            return self._assets.pop(asset_id, None) is not None

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
