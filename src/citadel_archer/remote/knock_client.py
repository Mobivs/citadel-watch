"""
Port Knock Client — Lightweight TCP knock sender.

Uses stdlib ``socket`` to send TCP SYN packets (connect + immediate close)
to a sequence of ports.  The remote host's iptables ``recent`` module
tracks the knocks and opens the SSH port briefly.

Used by the Citadel desktop to authenticate before SSH when port
knocking is enabled on a managed VPS.
"""

import asyncio
import logging
import socket
import time

logger = logging.getLogger(__name__)


class KnockClient:
    """Send a port-knock sequence to a remote host.

    Each knock is a TCP connect-then-close to the target port.
    The kernel's ``xt_recent`` module records the source IP per port.

    Args:
        host: Target hostname or IP address.
        sequence: Ordered list of ports to knock.
        delay: Seconds to wait between knocks (default 0.5).
    """

    def __init__(self, host: str, sequence: list, delay: float = 0.5):
        self.host = host
        self.sequence = sequence
        self.delay = delay

    def knock(self) -> bool:
        """Send the knock sequence.

        Returns:
            True if all knocks were sent successfully.
        """
        for port in self.sequence:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                # connect_ex returns 0 on success, errno otherwise —
                # we don't care about the result because the port is
                # DROPped by iptables (so we'll always get a timeout
                # or connection refused), but the SYN packet is enough
                # for xt_recent to register the knock.
                sock.connect_ex((self.host, port))
                sock.close()
                logger.debug("Knocked on %s:%d", self.host, port)
            except OSError as exc:
                logger.warning("Knock on %s:%d failed: %s", self.host, port, exc)
                return False
            if port != self.sequence[-1]:
                time.sleep(self.delay)

        logger.info(
            "Knock sequence completed for %s: %s", self.host, self.sequence
        )
        return True


async def knock_and_connect(ssh_manager, asset_id: str,
                            knock_sequence: list, host: str) -> bool:
    """Knock, wait for iptables to register, then verify SSH connection.

    Args:
        ssh_manager: ``SSHConnectionManager`` instance.
        asset_id: Asset identifier for ``ssh_manager.connect()``.
        knock_sequence: Ordered list of ports to knock.
        host: Target hostname or IP address.

    Returns:
        True if SSH connection succeeded after knocking.
    """
    client = KnockClient(host, knock_sequence)
    loop = asyncio.get_event_loop()
    if not await loop.run_in_executor(None, client.knock):
        return False

    # Give iptables recent module a moment to process
    await asyncio.sleep(1)

    try:
        await ssh_manager.connect(asset_id)
        return True
    except Exception as exc:
        logger.warning("SSH connect after knock failed: %s", exc)
        return False
