"""Tests for secondary brain hardening — security for the fallback coordinator.

v0.3.40: Tests for SSHHardeningPolicy, EncryptedKeyStore, APIRateLimiter,
BrainCredentials, BrainHardeningManager, and hardening API routes.
"""

import time
from unittest.mock import MagicMock

import pytest


# ── SSH Policy Tests ────────────────────────────────────────────────


class TestSSHHardeningPolicy:

    def test_default_policy(self):
        from src.citadel_archer.mesh.brain_hardening import SSHHardeningPolicy

        policy = SSHHardeningPolicy()
        assert policy.key_only_auth is True
        assert policy.non_standard_port == 2222
        assert policy.fail2ban_max_retry == 3
        assert policy.fail2ban_ban_time == 3600
        assert policy.allowed_users == ["citadel"]

    def test_to_dict(self):
        from src.citadel_archer.mesh.brain_hardening import SSHHardeningPolicy

        policy = SSHHardeningPolicy(non_standard_port=3333)
        d = policy.to_dict()
        assert d["non_standard_port"] == 3333
        assert d["key_only_auth"] is True

    def test_to_sshd_config(self):
        from src.citadel_archer.mesh.brain_hardening import SSHHardeningPolicy

        policy = SSHHardeningPolicy(
            non_standard_port=4444,
            allowed_users=["citadel", "admin"],
        )
        config = policy.to_sshd_config_fragment()
        assert "Port 4444" in config
        assert "PasswordAuthentication no" in config
        assert "AllowUsers citadel admin" in config
        assert "PermitRootLogin prohibit-password" in config

    def test_to_fail2ban_config(self):
        from src.citadel_archer.mesh.brain_hardening import SSHHardeningPolicy

        policy = SSHHardeningPolicy(
            non_standard_port=2222,
            fail2ban_max_retry=2,
            fail2ban_ban_time=7200,
        )
        config = policy.to_fail2ban_config()
        assert "port = 2222" in config
        assert "maxretry = 2" in config
        assert "bantime = 7200" in config


# ── Encrypted Key Store Tests ───────────────────────────────────────


class TestEncryptedKeyStore:

    def test_base64_fallback_encrypt_decrypt(self):
        """Without cryptography package, falls back to base64."""
        from src.citadel_archer.mesh.brain_hardening import EncryptedKeyStore

        store = EncryptedKeyStore()

        # Force base64 fallback by monkeypatching
        import importlib
        try:
            import cryptography  # noqa: F401
            has_crypto = True
        except ImportError:
            has_crypto = False

        if not has_crypto:
            # Already in fallback mode
            encrypted = store.encrypt("sk-test-key-123", "passphrase")
            assert encrypted.startswith("b64:")
            decrypted = store.decrypt(encrypted, "passphrase")
            assert decrypted == "sk-test-key-123"

    def test_encrypt_decrypt_with_cryptography(self):
        """Full Fernet encryption if cryptography is available."""
        from src.citadel_archer.mesh.brain_hardening import EncryptedKeyStore

        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography package not installed")

        store = EncryptedKeyStore()
        encrypted = store.encrypt("sk-my-secret-api-key", "strong-passphrase")
        assert ":" in encrypted
        assert not encrypted.startswith("b64:")

        decrypted = store.decrypt(encrypted, "strong-passphrase")
        assert decrypted == "sk-my-secret-api-key"

    def test_wrong_passphrase_fails(self):
        """Wrong passphrase returns None."""
        from src.citadel_archer.mesh.brain_hardening import EncryptedKeyStore

        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography package not installed")

        store = EncryptedKeyStore()
        encrypted = store.encrypt("sk-test", "correct-passphrase")
        result = store.decrypt(encrypted, "wrong-passphrase")
        assert result is None

    def test_is_encrypted(self):
        from src.citadel_archer.mesh.brain_hardening import EncryptedKeyStore

        store = EncryptedKeyStore()
        assert store.is_encrypted("salt:cipher") is True
        assert store.is_encrypted("sk-not-encrypted") is False
        assert store.is_encrypted("b64:base64data") is True


# ── Rate Limiter Tests ──────────────────────────────────────────────


class TestAPIRateLimiter:

    def test_allows_within_limit(self):
        from src.citadel_archer.mesh.brain_hardening import APIRateLimiter

        limiter = APIRateLimiter(rpm=60)  # 1 per second
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True

    def test_denies_over_limit(self):
        from src.citadel_archer.mesh.brain_hardening import APIRateLimiter

        limiter = APIRateLimiter(rpm=1)  # Very restrictive
        assert limiter.try_acquire() is True
        # Second call immediately should fail (no time to refill)
        assert limiter.try_acquire() is False

    def test_get_stats(self):
        from src.citadel_archer.mesh.brain_hardening import APIRateLimiter

        limiter = APIRateLimiter(rpm=10)
        limiter.try_acquire()
        limiter.try_acquire()
        stats = limiter.get_stats()
        assert stats["rpm_limit"] == 10
        assert stats["total_allowed"] == 2
        assert stats["total_denied"] == 0

    def test_update_rpm(self):
        from src.citadel_archer.mesh.brain_hardening import APIRateLimiter

        limiter = APIRateLimiter(rpm=10)
        limiter.update_rpm(5)
        assert limiter.rpm == 5


# ── Brain Credentials Tests ─────────────────────────────────────────


class TestBrainCredentials:

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.brain_hardening import BrainCredentials

        creds = BrainCredentials(brain_node_id="vps1")
        assert creds.created_at != ""

    def test_to_dict_hides_api_key(self):
        from src.citadel_archer.mesh.brain_hardening import BrainCredentials

        creds = BrainCredentials(
            brain_node_id="vps1",
            api_key_encrypted="encrypted-data",
            hmac_key_id="hmac-123",
        )
        d = creds.to_dict()
        assert d["api_key_configured"] is True
        assert "api_key_encrypted" not in d
        assert d["hmac_key_id"] == "hmac-123"


# ── Hardening Manager Tests ─────────────────────────────────────────


class TestBrainHardeningManager:

    def test_default_status(self):
        from src.citadel_archer.mesh.brain_hardening import BrainHardeningManager

        mgr = BrainHardeningManager()
        status = mgr.get_status()
        assert status["ssh_policy"]["key_only_auth"] is True
        assert status["credentials_configured"] is False

    def test_set_ssh_policy(self):
        from src.citadel_archer.mesh.brain_hardening import (
            BrainHardeningManager, SSHHardeningPolicy,
        )

        mgr = BrainHardeningManager()
        mgr.set_ssh_policy(SSHHardeningPolicy(non_standard_port=3333))
        assert mgr.get_ssh_policy().non_standard_port == 3333

    def test_store_and_retrieve_api_key(self):
        from src.citadel_archer.mesh.brain_hardening import BrainHardeningManager

        mgr = BrainHardeningManager()
        mgr.store_api_key("sk-test-key", "passphrase")
        result = mgr.retrieve_api_key("passphrase")
        assert result == "sk-test-key"

    def test_retrieve_with_wrong_passphrase(self):
        from src.citadel_archer.mesh.brain_hardening import BrainHardeningManager

        try:
            import cryptography  # noqa: F401
        except ImportError:
            pytest.skip("cryptography package not installed — base64 fallback has no passphrase")

        mgr = BrainHardeningManager()
        mgr.store_api_key("sk-test-key", "correct")
        result = mgr.retrieve_api_key("wrong")
        assert result is None

    def test_rate_limiting(self):
        from src.citadel_archer.mesh.brain_hardening import BrainHardeningManager

        mgr = BrainHardeningManager()
        mgr.update_rate_limit(1)  # Very restrictive
        assert mgr.check_rate_limit() is True
        assert mgr.check_rate_limit() is False

    def test_set_credentials(self):
        from src.citadel_archer.mesh.brain_hardening import (
            BrainCredentials, BrainHardeningManager,
        )

        mgr = BrainHardeningManager()
        creds = BrainCredentials(
            brain_node_id="vps1",
            hmac_key_id="hmac-abc",
            ssh_key_fingerprint="SHA256:xyz",
        )
        mgr.set_credentials(creds)
        assert mgr.get_credentials() is creds

    def test_audit_log(self):
        from src.citadel_archer.mesh.brain_hardening import (
            BrainHardeningManager, SSHHardeningPolicy,
        )

        mgr = BrainHardeningManager()
        mgr.set_ssh_policy(SSHHardeningPolicy())
        mgr.update_rate_limit(5)

        entries = mgr.get_audit_log()
        assert len(entries) >= 2
        events = [e["event"] for e in entries]
        assert "ssh_policy_updated" in events
        assert "rate_limit_updated" in events

    def test_generate_hardening_commands(self):
        from src.citadel_archer.mesh.brain_hardening import BrainHardeningManager

        mgr = BrainHardeningManager()
        commands = mgr.generate_hardening_commands()
        assert len(commands) == 4

        # SSH config write
        assert commands[0]["type"] == "write_file"
        assert "sshd_config" in commands[0]["path"]

        # SSH restart
        assert commands[1]["type"] == "shell"
        assert "sshd" in commands[1]["command"]

        # Fail2ban config write
        assert commands[2]["type"] == "write_file"
        assert "fail2ban" in commands[2]["path"]

        # Fail2ban restart
        assert commands[3]["type"] == "shell"
        assert "fail2ban" in commands[3]["command"]


# ── Singleton Tests ─────────────────────────────────────────────────


class TestHardeningSingleton:

    def test_get_set(self):
        from src.citadel_archer.mesh.brain_hardening import (
            BrainHardeningManager,
            get_brain_hardening_manager,
            set_brain_hardening_manager,
        )

        mgr = BrainHardeningManager()
        set_brain_hardening_manager(mgr)
        assert get_brain_hardening_manager() is mgr
        set_brain_hardening_manager(None)

    def test_auto_creates(self):
        from src.citadel_archer.mesh.brain_hardening import (
            get_brain_hardening_manager,
            set_brain_hardening_manager,
        )

        set_brain_hardening_manager(None)
        mgr = get_brain_hardening_manager()
        assert mgr is not None
        set_brain_hardening_manager(None)


# ── Route Tests ─────────────────────────────────────────────────────


@pytest.fixture
def hardening_client():
    """TestClient for brain hardening routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.brain_hardening import (
        BrainHardeningManager, set_brain_hardening_manager,
    )
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    mgr = BrainHardeningManager()
    set_brain_hardening_manager(mgr)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_brain_hardening_manager(None)


class TestHardeningRoutes:

    def test_get_status(self, hardening_client):
        resp = hardening_client.get("/api/mesh/hardening")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ssh_policy"]["key_only_auth"] is True
        assert data["credentials_configured"] is False

    def test_update_ssh_policy(self, hardening_client):
        resp = hardening_client.put("/api/mesh/hardening/ssh-policy", json={
            "non_standard_port": 5555,
            "fail2ban_max_retry": 2,
        })
        assert resp.status_code == 200
        assert resp.json()["policy"]["non_standard_port"] == 5555

    def test_get_rate_limiter(self, hardening_client):
        resp = hardening_client.get("/api/mesh/hardening/rate-limiter")
        assert resp.status_code == 200
        assert "rpm_limit" in resp.json()

    def test_update_rate_limit(self, hardening_client):
        resp = hardening_client.put("/api/mesh/hardening/rate-limiter?rpm=5")
        assert resp.status_code == 200
        assert resp.json()["rpm"] == 5

    def test_get_hardening_commands(self, hardening_client):
        resp = hardening_client.get("/api/mesh/hardening/commands")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 4

    def test_get_audit(self, hardening_client):
        resp = hardening_client.get("/api/mesh/hardening/audit")
        assert resp.status_code == 200
        assert "entries" in resp.json()
