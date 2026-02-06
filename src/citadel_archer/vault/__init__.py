# PRD: Vault Module - Secure Password Manager
# Reference: docs/PRD.md v0.2.3, Section: Vault
#
# Encrypted password storage using SQLCipher + AES-256
# Master password with PBKDF2 key derivation

from .vault_manager import VaultManager
from .encryption import EncryptionService

__all__ = ["VaultManager", "EncryptionService"]
