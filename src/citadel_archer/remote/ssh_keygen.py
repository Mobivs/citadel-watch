# PRD: SSH Key Generation for Quick Add VPS
# Reference: Plan Milestone 2
#
# Generates fresh ed25519 keypairs for VPS onboarding.
# Pattern reused from recovery_key.py:259-301.

import logging
import os
import subprocess
import tempfile
from typing import Tuple

logger = logging.getLogger(__name__)


def generate_ed25519_keypair(comment: str = "citadel-archer") -> Tuple[str, str]:
    """Generate a fresh ed25519 SSH keypair.

    Returns:
        (private_key_pem, public_key_line) — both as strings.
    """
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "citadel_key")
            subprocess.run(
                [
                    "ssh-keygen", "-t", "ed25519",
                    "-f", key_path,
                    "-N", "",  # no passphrase
                    "-C", comment,
                ],
                check=True,
                capture_output=True,
            )
            with open(key_path, "r") as f:
                private_key = f.read()
            with open(key_path + ".pub", "r") as f:
                public_key = f.read().strip()
            return private_key, public_key

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.warning(f"ssh-keygen failed ({e}), using Python cryptography fallback")
        return _generate_keypair_python(comment)


def _generate_keypair_python(comment: str) -> Tuple[str, str]:
    """Fallback: generate keypair using the cryptography library."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    )
    public_key_str = public_bytes.decode() + " " + comment
    return private_bytes.decode(), public_key_str


def build_install_command(public_key: str) -> str:
    """Build a one-liner to add the public key to authorized_keys on a VPS.

    The command:
    1. Creates ~/.ssh if it doesn't exist
    2. Sets correct permissions
    3. Appends the public key to authorized_keys
    """
    # Strip any trailing newlines
    pub = public_key.strip()
    return (
        f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
        f"echo '{pub}' >> ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys"
    )
