"""
T1.2: Secrets Store Foundation
Encrypted storage of credentials with scoped, audited access.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


class SecretsStore:
    """Encrypted vault for storing and rotating secrets."""

    def __init__(self, vault_path: str = "/var/citadel/secrets.vault", master_password: str = ""):
        self.vault_path = Path(vault_path)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.master_password = master_password
        self.cipher = self._derive_cipher(master_password)
        self._load_vault()

    def _derive_cipher(self, password: str) -> Fernet:
        """Derive encryption cipher from master password using PBKDF2."""
        salt = b"citadel_archer_salt_v1"  # Static salt for reproducibility
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def _load_vault(self):
        """Load existing vault or create empty one."""
        if self.vault_path.exists():
            with open(self.vault_path, 'rb') as f:
                encrypted_data = f.read()
            try:
                decrypted = self.cipher.decrypt(encrypted_data).decode()
                self.vault = json.loads(decrypted)
            except Exception as e:
                raise ValueError(f"Failed to decrypt vault: {e}")
        else:
            self.vault = {}

    def _save_vault(self):
        """Encrypt and save vault to disk."""
        vault_json = json.dumps(self.vault, indent=2)
        encrypted = self.cipher.encrypt(vault_json.encode())
        with open(self.vault_path, 'wb') as f:
            f.write(encrypted)
        # Ensure file permissions: owner read/write only
        os.chmod(self.vault_path, 0o600)

    def add_secret(self, name: str, value: str) -> bool:
        """Add a new secret to the vault."""
        self.vault[name] = {
            "value": value,
            "created_at": datetime.utcnow().isoformat(),
            "last_rotated": datetime.utcnow().isoformat(),
            "last_accessed": None
        }
        self._save_vault()
        return True

    def get_secret(self, name: str) -> Optional[str]:
        """Retrieve a secret from the vault."""
        if name not in self.vault:
            return None
        secret = self.vault[name]
        secret["last_accessed"] = datetime.utcnow().isoformat()
        self._save_vault()
        return secret["value"]

    def rotate_secret(self, name: str, new_value: str) -> bool:
        """Rotate a secret with a new value."""
        if name not in self.vault:
            return False
        self.vault[name]["value"] = new_value
        self.vault[name]["last_rotated"] = datetime.utcnow().isoformat()
        self._save_vault()
        return True

    def list_secrets(self) -> list:
        """List all secret names (not values)."""
        return list(self.vault.keys())

    def get_secret_metadata(self, name: str) -> Optional[Dict]:
        """Get metadata for a secret (created, rotated, accessed times)."""
        if name not in self.vault:
            return None
        secret = self.vault[name]
        return {
            "name": name,
            "created_at": secret["created_at"],
            "last_rotated": secret["last_rotated"],
            "last_accessed": secret["last_accessed"]
        }


# Unit Tests
def test_secrets_store():
    """Test SecretsStore implementation."""
    import tempfile
    
    # Test setup
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = os.path.join(tmpdir, "test.vault")
        store = SecretsStore(vault_path, "test_password_123")
        
        # Test add_secret
        assert store.add_secret("github_token", "ghp_abc123xyz")
        
        # Test get_secret
        assert store.get_secret("github_token") == "ghp_abc123xyz"
        
        # Test list_secrets
        assert "github_token" in store.list_secrets()
        
        # Test rotate_secret
        assert store.rotate_secret("github_token", "ghp_new_token")
        assert store.get_secret("github_token") == "ghp_new_token"
        
        # Test encryption roundtrip
        store2 = SecretsStore(vault_path, "test_password_123")
        assert store2.get_secret("github_token") == "ghp_new_token"
        
        # Test metadata
        metadata = store.get_secret_metadata("github_token")
        assert metadata is not None
        assert metadata["name"] == "github_token"
        assert metadata["last_accessed"] is not None
        
        print("✅ All SecretsStore tests passed")


if __name__ == "__main__":
    test_secrets_store()
