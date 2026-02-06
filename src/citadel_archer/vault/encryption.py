# PRD: Vault - Encryption Service
# Reference: docs/PRD.md v0.2.3, Section: Vault
#
# Master password → Encryption key (PBKDF2)
# Password encryption (AES-256-GCM)
# Secure key derivation with salt

import os
import base64
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class EncryptionService:
    """
    Handles encryption/decryption for Vault passwords.

    PRD: "Master password (PBKDF2 key derivation)" + "AES-256 encryption"

    Flow:
    1. User enters master password
    2. PBKDF2 derives 256-bit key from password + salt
    3. AES-256-GCM encrypts/decrypts password data
    4. Each password has unique nonce for GCM
    """

    # PBKDF2 parameters (OWASP recommendations)
    PBKDF2_ITERATIONS = 600_000  # OWASP 2023: 600k iterations for PBKDF2-SHA256
    KEY_LENGTH = 32  # 256 bits for AES-256
    SALT_LENGTH = 32  # 256-bit salt
    NONCE_LENGTH = 12  # 96-bit nonce for GCM (recommended)

    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from master password using PBKDF2.

        PRD: "Master password (PBKDF2 key derivation)"

        Args:
            master_password: User's master password
            salt: Random salt (stored with vault)

        Returns:
            256-bit encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=EncryptionService.KEY_LENGTH,
            salt=salt,
            iterations=EncryptionService.PBKDF2_ITERATIONS,
            backend=default_backend()
        )

        return kdf.derive(master_password.encode('utf-8'))

    @staticmethod
    def generate_salt() -> bytes:
        """Generate cryptographically random salt."""
        return os.urandom(EncryptionService.SALT_LENGTH)

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.

        PRD: "AES-256 encryption"

        Args:
            plaintext: Password or secret to encrypt
            key: 256-bit encryption key (from derive_key)

        Returns:
            Tuple of (nonce, ciphertext)
            Both needed for decryption
        """
        # Generate random nonce (must be unique per encryption)
        nonce = os.urandom(EncryptionService.NONCE_LENGTH)

        # AES-256-GCM encryption (authenticated encryption)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        return nonce, ciphertext

    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
        """
        Decrypt ciphertext using AES-256-GCM.

        Args:
            nonce: Nonce used during encryption
            ciphertext: Encrypted data
            key: 256-bit encryption key (same as encryption)

        Returns:
            Decrypted plaintext

        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext_bytes.decode('utf-8')

    @staticmethod
    def encode_for_storage(data: bytes) -> str:
        """
        Encode binary data for database storage (base64).

        SQLCipher stores TEXT, so we base64-encode binary data.
        """
        return base64.b64encode(data).decode('utf-8')

    @staticmethod
    def decode_from_storage(data: str) -> bytes:
        """Decode base64-encoded data from database."""
        return base64.b64decode(data.encode('utf-8'))


def verify_master_password(password: str) -> Tuple[bool, str]:
    """
    Verify master password meets security requirements.

    PRD: Security-first mindset - enforce strong passwords

    Requirements:
    - At least 12 characters
    - Mix of uppercase, lowercase, numbers
    - No common weak passwords

    Returns:
        (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Master password must be at least 12 characters long"

    if not any(c.isupper() for c in password):
        return False, "Master password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Master password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Master password must contain at least one number"

    # Common weak passwords (minimal list for MVP)
    weak_passwords = [
        "password123", "Password123", "Admin123456",
        "Welcome12345", "Passw0rd123", "123456789012"
    ]
    if password in weak_passwords:
        return False, "This password is too common. Please choose a stronger password."

    return True, ""
