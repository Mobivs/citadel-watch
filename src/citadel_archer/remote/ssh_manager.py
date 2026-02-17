# SSH Connection Manager
# Phase 2.6: Async SSH client for managed assets
# Reference: docs/ASSET_MANAGEMENT_ADDENDUM.md, Section 6
#
# Provides a high-level SSH interface for executing commands on
# managed assets. Credentials are pulled from the Vault; assets
# are looked up from AssetInventory.
#
# Connection lifecycle:
#   1. Look up asset by asset_id → get ssh_credential_id
#   2. Fetch credential from VaultManager.get_ssh_credential()
#   3. Build asyncssh connection (key or password auth)
#   4. Cache connection in _connections dict
#   5. Auto-close idle connections after IDLE_TIMEOUT_SECONDS

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

try:
    import asyncssh
except ImportError:
    asyncssh = None  # type: ignore[assignment]

from ..intel.assets import AssetInventory, AssetStatus
from ..vault import VaultManager

logger = logging.getLogger(__name__)

# How long an idle connection lives before auto-close (seconds)
IDLE_TIMEOUT_SECONDS = 300


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SSHManagerError(Exception):
    """Base exception for SSH Connection Manager."""


class AssetNotFoundError(SSHManagerError):
    """Raised when the requested asset_id does not exist."""


class NoCredentialError(SSHManagerError):
    """Raised when the asset has no linked SSH credential."""


class VaultLockedError(SSHManagerError):
    """Raised when the Vault is locked and credentials cannot be read."""


class ConnectionFailedError(SSHManagerError):
    """Raised when the SSH connection cannot be established."""


class CommandTimeoutError(SSHManagerError):
    """Raised when a remote command exceeds its timeout."""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CommandResult:
    """Result of a remote command execution."""
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    duration_ms: int = 0


@dataclass
class ConnectionTestResult:
    """Result of an SSH connection test."""
    success: bool = False
    asset_id: str = ""
    ssh_fingerprint: str = ""
    remote_os: str = ""
    uptime: str = ""
    hostname: str = ""
    remote_shield_detected: bool = False
    agent_version: str = ""
    error: str = ""
    latency_ms: int = 0


@dataclass
class _CachedConnection:
    """Internal wrapper that tracks idle time for a connection."""
    conn: Any  # asyncssh.SSHClientConnection
    asset_id: str
    last_used: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# SSHConnectionManager
# ---------------------------------------------------------------------------

class SSHConnectionManager:
    """Manage SSH connections to remote assets using Vault credentials.

    Args:
        vault: Unlocked VaultManager instance.
        asset_inventory: AssetInventory with registered assets.
    """

    def __init__(self, vault: VaultManager, asset_inventory: AssetInventory):
        if asyncssh is None:
            raise ImportError(
                "asyncssh is required for SSH Connection Manager. "
                "Install it with: pip install asyncssh"
            )
        self.vault = vault
        self.assets = asset_inventory
        # NOTE: _connections is only accessed from the asyncio event loop
        # (connect/disconnect/reaper are all coroutines). This is safe because
        # asyncio is single-threaded within one event loop. If this class is
        # ever used from multiple threads, add an asyncio.Lock.
        self._connections: Dict[str, _CachedConnection] = {}
        self._idle_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self, asset_id: str) -> "asyncssh.SSHClientConnection":
        """Establish (or reuse) an SSH connection to a managed asset.

        Raises:
            AssetNotFoundError: asset_id not in inventory.
            NoCredentialError: asset has no linked SSH credential.
            VaultLockedError: vault must be unlocked first.
            ConnectionFailedError: SSH handshake/auth failure.
        """
        # Return cached connection if still alive
        cached = self._connections.get(asset_id)
        if cached is not None:
            try:
                # Quick liveness check — asyncssh exposes .is_closed()
                if not cached.conn.is_closed():
                    cached.last_used = time.monotonic()
                    return cached.conn
            except Exception:
                pass
            # Stale — remove and reconnect
            self._connections.pop(asset_id, None)

        # 1. Look up asset
        asset = self.assets.get(asset_id)
        if asset is None:
            raise AssetNotFoundError(f"Asset '{asset_id}' not found in inventory")

        # 2. Check for credential link
        cred_id = asset.ssh_credential_id
        if not cred_id:
            raise NoCredentialError(
                f"Asset '{asset_id}' has no linked SSH credential. "
                "Link one via PUT /api/assets/{id} with ssh_credential_id."
            )

        # 3. Pull credential from Vault
        if not self.vault.is_unlocked:
            raise VaultLockedError("Vault is locked. Unlock the vault before connecting.")

        cred = self.vault.get_ssh_credential(cred_id)
        if cred is None:
            raise NoCredentialError(
                f"SSH credential '{cred_id}' not found in Vault "
                f"(linked from asset '{asset_id}')."
            )

        # 4. Build asyncssh connection kwargs
        host = asset.ip_address or asset.hostname
        port = asset.ssh_port or cred.get("default_port", 22)
        username = asset.ssh_username or cred.get("default_username", "root")

        conn_kwargs: Dict[str, Any] = {
            "host": host,
            "port": port,
            "username": username,
            # SECURITY NOTE: Host key verification is disabled for managed
            # environments where assets are provisioned dynamically and host
            # keys aren't pre-distributed. In production, consider using a
            # known_hosts file populated during asset onboarding.
            "known_hosts": None,
        }

        auth_type = cred.get("auth_type", "password")
        if auth_type == "key":
            private_key_str = cred.get("private_key", "")
            passphrase = cred.get("key_passphrase", "") or None
            try:
                key = asyncssh.import_private_key(private_key_str, passphrase)
                conn_kwargs["client_keys"] = [key]
            except Exception as exc:
                raise ConnectionFailedError(
                    f"Failed to load SSH private key for asset '{asset_id}': {exc}"
                ) from exc
        else:
            conn_kwargs["password"] = cred.get("password", "")

        # 4b. Port knocking (if configured for this asset)
        knock_config = self._get_knock_config(asset_id)
        if knock_config:
            from .knock_client import KnockClient
            client = KnockClient(host, knock_config["sequence"])
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, client.knock)
            await asyncio.sleep(1)  # wait for iptables recent module

        # 5. Connect
        try:
            conn = await asyncssh.connect(**conn_kwargs)
        except asyncssh.DisconnectError as exc:
            raise ConnectionFailedError(
                f"SSH disconnected from {host}:{port}: {exc}"
            ) from exc
        except asyncssh.PermissionDenied as exc:
            raise ConnectionFailedError(
                f"SSH authentication failed for {username}@{host}:{port}: {exc}"
            ) from exc
        except (OSError, asyncssh.Error) as exc:
            raise ConnectionFailedError(
                f"SSH connection to {host}:{port} failed: {exc}"
            ) from exc

        # 6. Cache
        self._connections[asset_id] = _CachedConnection(
            conn=conn, asset_id=asset_id
        )

        # Start idle reaper if not running
        self._ensure_idle_reaper()

        logger.info(f"SSH connected to asset {asset_id} ({username}@{host}:{port})")
        return conn

    async def execute(
        self, asset_id: str, command: str, timeout: int = 30
    ) -> CommandResult:
        """Execute a command on a remote asset.

        Args:
            asset_id: Target asset identifier.
            command: Shell command to run.
            timeout: Max seconds to wait (default 30).

        Raises:
            CommandTimeoutError: if the command exceeds *timeout*.
            (Plus any connect-time exceptions from ``connect()``.)
        """
        conn = await self.connect(asset_id)

        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout,
            )
        except asyncio.TimeoutError as exc:
            raise CommandTimeoutError(
                f"Command timed out after {timeout}s on asset '{asset_id}': {command!r}"
            ) from exc

        elapsed_ms = int((time.monotonic() - start) * 1000)

        return CommandResult(
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            exit_code=result.exit_status if result.exit_status is not None else -1,
            duration_ms=elapsed_ms,
        )

    async def test_connection(self, asset_id: str) -> ConnectionTestResult:
        """Test SSH connectivity and gather basic system info.

        Does not raise — returns a ``ConnectionTestResult`` with
        ``success=False`` and ``error`` set on failure.
        """
        start = time.monotonic()
        try:
            conn = await self.connect(asset_id)
        except SSHManagerError as exc:
            return ConnectionTestResult(
                success=False,
                asset_id=asset_id,
                error=str(exc),
                latency_ms=int((time.monotonic() - start) * 1000),
            )

        latency_ms = int((time.monotonic() - start) * 1000)

        # Gather system info in parallel
        info: Dict[str, str] = {}
        commands = {
            "remote_os": "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"' || uname -s -r",
            "uptime": "uptime -p 2>/dev/null || uptime",
            "hostname": "hostname",
            "agent_check": "systemctl is-active citadel-shield 2>/dev/null || echo inactive",
            "fingerprint": "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null | awk '{print $2}' || echo unknown",
        }

        probes_succeeded = 0
        for key, cmd in commands.items():
            try:
                result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=10)
                info[key] = (result.stdout or "").strip()
                probes_succeeded += 1
            except Exception:
                info[key] = ""

        agent_active = info.get("agent_check", "") == "active"

        # Only mark online if at least one probe command returned data
        if probes_succeeded == 0:
            return ConnectionTestResult(
                success=False,
                asset_id=asset_id,
                error="Connected but all probe commands failed",
                latency_ms=latency_ms,
            )

        # Update asset status based on test result
        self.assets.set_status(asset_id, AssetStatus.ONLINE)

        return ConnectionTestResult(
            success=True,
            asset_id=asset_id,
            ssh_fingerprint=info.get("fingerprint", ""),
            remote_os=info.get("remote_os", ""),
            uptime=info.get("uptime", ""),
            hostname=info.get("hostname", ""),
            remote_shield_detected=agent_active,
            agent_version="1.0.0" if agent_active else "",
            latency_ms=latency_ms,
        )

    async def upload_file(
        self, asset_id: str, local_path: str, remote_path: str
    ) -> None:
        """SCP upload a file to a remote asset.

        Args:
            asset_id: Target asset.
            local_path: Path on local filesystem.
            remote_path: Destination path on the remote host.
        """
        conn = await self.connect(asset_id)
        try:
            await asyncssh.scp(local_path, (conn, remote_path))
        except (asyncssh.Error, OSError) as exc:
            raise ConnectionFailedError(
                f"SCP upload to asset '{asset_id}' failed: {exc}"
            ) from exc

    async def download_file(
        self, asset_id: str, remote_path: str, local_path: str
    ) -> None:
        """SCP download a file from a remote asset.

        Args:
            asset_id: Source asset.
            remote_path: Path on the remote host.
            local_path: Destination path on local filesystem.
        """
        conn = await self.connect(asset_id)
        try:
            await asyncssh.scp((conn, remote_path), local_path)
        except (asyncssh.Error, OSError) as exc:
            raise ConnectionFailedError(
                f"SCP download from asset '{asset_id}' failed: {exc}"
            ) from exc

    async def disconnect(self, asset_id: str) -> None:
        """Close SSH connection to a specific asset."""
        cached = self._connections.pop(asset_id, None)
        if cached is not None:
            try:
                cached.conn.close()
                await cached.conn.wait_closed()
            except Exception:
                pass
            logger.info(f"SSH disconnected from asset {asset_id}")

    async def disconnect_all(self) -> None:
        """Close all active SSH connections and cancel the idle reaper."""
        # Cancel the idle reaper first
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
            try:
                await self._idle_task
            except asyncio.CancelledError:
                pass
            self._idle_task = None

        asset_ids = list(self._connections.keys())
        for aid in asset_ids:
            await self.disconnect(aid)
        logger.info("All SSH connections closed")

    async def invalidate_cache(self, asset_id: str) -> None:
        """Drop cached connection after credential rotation.

        Closes the old connection and removes it from cache so the
        next ``connect()`` call establishes a fresh session with
        the new credentials.
        """
        await self.disconnect(asset_id)
        logger.info(f"SSH cache invalidated for asset {asset_id} (credential rotation)")

    async def invalidate_all_caches(self) -> None:
        """Drop all cached connections (e.g., after bulk credential rotation)."""
        await self.disconnect_all()
        logger.info("All SSH caches invalidated (bulk credential rotation)")

    # ------------------------------------------------------------------
    # Idle connection reaper
    # ------------------------------------------------------------------

    def _ensure_idle_reaper(self) -> None:
        """Start the background reaper task if not already running."""
        if self._idle_task is not None and not self._idle_task.done():
            return
        try:
            loop = asyncio.get_running_loop()
            self._idle_task = loop.create_task(self._reap_idle_connections())
        except RuntimeError:
            pass  # No running event loop — skip reaper

    async def _reap_idle_connections(self) -> None:
        """Periodically close connections idle longer than IDLE_TIMEOUT_SECONDS.

        Restarts automatically after transient errors rather than dying permanently.
        """
        while True:
            try:
                while self._connections:
                    await asyncio.sleep(60)  # Check every minute
                    now = time.monotonic()
                    stale = [
                        aid for aid, cached in self._connections.items()
                        if (now - cached.last_used) > IDLE_TIMEOUT_SECONDS
                    ]
                    for aid in stale:
                        logger.info(f"Reaping idle SSH connection to asset {aid}")
                        await self.disconnect(aid)
                # No connections left — exit (will restart on next connect)
                break
            except asyncio.CancelledError:
                raise  # Let cancellation propagate
            except Exception:
                logger.exception("Idle reaper error — restarting after backoff")
                await asyncio.sleep(5)  # Brief backoff before retry

    # ------------------------------------------------------------------
    # Port knocking config lookup
    # ------------------------------------------------------------------

    def _get_knock_config(self, asset_id: str) -> Optional[dict]:
        """Check if port knocking is configured for this asset."""
        try:
            from ..api.dashboard_ext import services
            db = services.get("shield_db")
            if not db:
                return None
            config = db.get_hardening_config(asset_id)
            if config and config.get("config", {}).get("enable_port_knocking"):
                return {
                    "sequence": config["config"].get(
                        "knock_sequence", [7000, 8000, 9000]
                    ),
                }
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect_all()
