"""Backup encryption using AES-256-GCM with PBKDF2 key derivation.

Follows the same cryptographic pattern as vault/encryption.py:
- PBKDF2-SHA256 (600k iterations) for key derivation
- AES-256-GCM for authenticated encryption
- Random 32-byte salt + 12-byte nonce per archive

Archive format: salt(32) + nonce(12) + ciphertext+tag
"""

import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class BackupCrypto:
    """Encrypt/decrypt backup archives with a user-provided passphrase."""

    PBKDF2_ITERATIONS = 600_000  # OWASP 2023: match vault/encryption.py
    KEY_LENGTH = 32              # 256 bits for AES-256
    SALT_LENGTH = 32             # 256-bit salt
    NONCE_LENGTH = 12            # 96-bit nonce for GCM

    # Minimum header size: salt + nonce
    _HEADER_SIZE = SALT_LENGTH + NONCE_LENGTH

    @staticmethod
    def derive_key(passphrase: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from passphrase + salt via PBKDF2-SHA256."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=BackupCrypto.KEY_LENGTH,
            salt=salt,
            iterations=BackupCrypto.PBKDF2_ITERATIONS,
            backend=default_backend(),
        )
        return kdf.derive(passphrase.encode("utf-8"))

    @staticmethod
    def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
        """Encrypt data with AES-256-GCM.

        Returns: salt(32) + nonce(12) + ciphertext_with_tag
        """
        salt = os.urandom(BackupCrypto.SALT_LENGTH)
        key = BackupCrypto.derive_key(passphrase, salt)
        nonce = os.urandom(BackupCrypto.NONCE_LENGTH)
        ciphertext = AESGCM(key).encrypt(nonce, data, None)
        return salt + nonce + ciphertext

    @staticmethod
    def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
        """Decrypt an encrypted archive blob.

        Raises:
            cryptography.exceptions.InvalidTag: Wrong passphrase or corrupt data.
            ValueError: Blob too short to contain header.
        """
        if len(blob) < BackupCrypto._HEADER_SIZE:
            raise ValueError("Encrypted data too short to be a valid backup archive.")
        salt = blob[: BackupCrypto.SALT_LENGTH]
        nonce = blob[BackupCrypto.SALT_LENGTH : BackupCrypto._HEADER_SIZE]
        ciphertext = blob[BackupCrypto._HEADER_SIZE :]
        key = BackupCrypto.derive_key(passphrase, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, None)
