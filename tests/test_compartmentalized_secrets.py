"""Tests for compartmentalized secrets — each node only has credentials it needs.

v0.3.41: Tests for SecretCompartmentManager, access policies,
provisioning, compliance checking, and API routes.
"""

from unittest.mock import MagicMock

import pytest


# ── Access Policy Tests ─────────────────────────────────────────────


class TestAccessPolicy:
    """Role-based access control for secret scopes and types."""

    def test_primary_can_access_all_scopes(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretScope, can_access_scope,
        )

        for scope in SecretScope:
            assert can_access_scope("primary", scope.value) is True

    def test_agent_can_only_access_agent_and_mesh(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretScope, can_access_scope,
        )

        assert can_access_scope("agent", SecretScope.AGENT.value) is True
        assert can_access_scope("agent", SecretScope.MESH.value) is True
        assert can_access_scope("agent", SecretScope.GLOBAL.value) is False
        assert can_access_scope("agent", SecretScope.BRAIN.value) is False

    def test_secondary_can_access_brain_and_mesh(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretScope, can_access_scope,
        )

        assert can_access_scope("secondary", SecretScope.BRAIN.value) is True
        assert can_access_scope("secondary", SecretScope.MESH.value) is True
        assert can_access_scope("secondary", SecretScope.GLOBAL.value) is False
        assert can_access_scope("secondary", SecretScope.AGENT.value) is False

    def test_agent_cannot_access_ssh_private_key(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretType, can_access_secret_type,
        )

        assert can_access_secret_type("agent", SecretType.SSH_PRIVATE_KEY.value) is False
        assert can_access_secret_type("agent", SecretType.VAULT_MASTER_KEY.value) is False

    def test_agent_can_access_hmac_and_config(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretType, can_access_secret_type,
        )

        assert can_access_secret_type("agent", SecretType.HMAC_PSK.value) is True
        assert can_access_secret_type("agent", SecretType.AGENT_CONFIG.value) is True
        assert can_access_secret_type("agent", SecretType.ESCALATION_TOKEN.value) is True

    def test_secondary_can_access_api_key(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretType, can_access_secret_type,
        )

        assert can_access_secret_type("secondary", SecretType.API_KEY.value) is True
        assert can_access_secret_type("secondary", SecretType.HMAC_PSK.value) is True
        assert can_access_secret_type("secondary", SecretType.SSH_PRIVATE_KEY.value) is False

    def test_primary_can_access_all_types(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretType, can_access_secret_type,
        )

        for t in SecretType:
            assert can_access_secret_type("primary", t.value) is True


# ── SecretEntry Tests ───────────────────────────────────────────────


class TestSecretEntry:

    def test_auto_timestamp(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import SecretEntry

        entry = SecretEntry(secret_id="s1", secret_type="hmac_psk", scope="mesh")
        assert entry.provisioned_at != ""

    def test_to_dict(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import SecretEntry

        entry = SecretEntry(
            secret_id="s1",
            secret_type="hmac_psk",
            scope="mesh",
            description="Heartbeat PSK",
            fingerprint="abc123",
        )
        d = entry.to_dict()
        assert d["secret_id"] == "s1"
        assert d["scope"] == "mesh"
        assert d["fingerprint"] == "abc123"


# ── Manager Tests ───────────────────────────────────────────────────


class TestSecretCompartmentManager:

    def test_register_node(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager,
        )

        mgr = SecretCompartmentManager()
        manifest = mgr.register_node("vps1", "agent")
        assert manifest.node_id == "vps1"
        assert manifest.role == "agent"
        assert len(manifest.secrets) == 0

    def test_remove_node(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")
        assert mgr.remove_node("vps1") is True
        assert mgr.get_manifest("vps1") is None

    def test_provision_secret_allowed(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")

        entry = SecretEntry(
            secret_id="hmac-1", secret_type="hmac_psk", scope="mesh",
        )
        assert mgr.provision_secret("vps1", entry) is True
        assert len(mgr.get_node_secrets("vps1")) == 1

    def test_provision_secret_denied_scope(self):
        """Agent cannot receive global-scoped secrets."""
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")

        entry = SecretEntry(
            secret_id="vault-master", secret_type="vault_master_key", scope="global",
        )
        assert mgr.provision_secret("vps1", entry) is False
        assert len(mgr.get_node_secrets("vps1")) == 0

    def test_provision_secret_denied_type(self):
        """Agent cannot receive SSH private keys."""
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")

        entry = SecretEntry(
            secret_id="ssh-1", secret_type="ssh_private_key", scope="agent",
        )
        assert mgr.provision_secret("vps1", entry) is False

    def test_primary_gets_everything(self):
        """Desktop (primary) can receive all secret types and scopes."""
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("desktop", "primary")

        entries = [
            SecretEntry(secret_id="v1", secret_type="vault_master_key", scope="global"),
            SecretEntry(secret_id="s1", secret_type="ssh_private_key", scope="global"),
            SecretEntry(secret_id="h1", secret_type="hmac_psk", scope="mesh"),
            SecretEntry(secret_id="a1", secret_type="api_key", scope="brain"),
        ]
        for e in entries:
            assert mgr.provision_secret("desktop", e) is True

        assert len(mgr.get_node_secrets("desktop")) == 4

    def test_revoke_secret(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")
        mgr.provision_secret("vps1", SecretEntry(
            secret_id="h1", secret_type="hmac_psk", scope="mesh",
        ))
        assert mgr.revoke_secret("vps1", "h1") is True
        assert len(mgr.get_node_secrets("vps1")) == 0

    def test_revoke_all_secrets(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")
        for i in range(3):
            mgr.provision_secret("vps1", SecretEntry(
                secret_id=f"h{i}", secret_type="hmac_psk", scope="mesh",
            ))
        count = mgr.revoke_all_secrets("vps1")
        assert count == 3
        assert len(mgr.get_node_secrets("vps1")) == 0

    def test_compliance_check_clean(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")
        mgr.provision_secret("vps1", SecretEntry(
            secret_id="h1", secret_type="hmac_psk", scope="mesh",
        ))
        report = mgr.check_compliance("vps1")
        assert report["compliant"] is True
        assert len(report["violations"]) == 0

    def test_compliance_check_violation(self):
        """Manually injected secret that violates policy is detected."""
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")

        # Manually inject a global secret (bypassing policy check)
        manifest = mgr.get_manifest("vps1")
        manifest.secrets.append(SecretEntry(
            secret_id="vault-master", secret_type="vault_master_key", scope="global",
        ))

        report = mgr.check_compliance("vps1")
        assert report["compliant"] is False
        assert len(report["violations"]) > 0

    def test_secret_distribution(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("desktop", "primary")
        mgr.register_node("vps1", "agent")
        mgr.provision_secret("desktop", SecretEntry(
            secret_id="v1", secret_type="vault_master_key", scope="global",
        ))
        mgr.provision_secret("vps1", SecretEntry(
            secret_id="h1", secret_type="hmac_psk", scope="mesh",
        ))

        dist = mgr.get_secret_distribution()
        assert dist["desktop"]["secret_count"] == 1
        assert dist["vps1"]["secret_count"] == 1

    def test_audit_log(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager, SecretEntry,
        )

        mgr = SecretCompartmentManager()
        mgr.register_node("vps1", "agent")
        mgr.provision_secret("vps1", SecretEntry(
            secret_id="h1", secret_type="hmac_psk", scope="mesh",
        ))

        audit = mgr.get_audit_log()
        events = [e["event"] for e in audit]
        assert "node_registered" in events
        assert "secret_provisioned" in events


# ── Singleton Tests ─────────────────────────────────────────────────


class TestSecretSingleton:

    def test_get_set(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            SecretCompartmentManager,
            get_secret_compartment_manager,
            set_secret_compartment_manager,
        )

        mgr = SecretCompartmentManager()
        set_secret_compartment_manager(mgr)
        assert get_secret_compartment_manager() is mgr
        set_secret_compartment_manager(None)

    def test_auto_creates(self):
        from src.citadel_archer.mesh.compartmentalized_secrets import (
            get_secret_compartment_manager,
            set_secret_compartment_manager,
        )

        set_secret_compartment_manager(None)
        mgr = get_secret_compartment_manager()
        assert mgr is not None
        set_secret_compartment_manager(None)


# ── Route Tests ─────────────────────────────────────────────────────


@pytest.fixture
def secrets_client():
    """TestClient for compartmentalized secrets routes."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from src.citadel_archer.api.mesh_routes import router, set_mesh_coordinator
    from src.citadel_archer.api.security import verify_session_token
    from src.citadel_archer.mesh.compartmentalized_secrets import (
        SecretCompartmentManager, set_secret_compartment_manager,
    )
    from src.citadel_archer.mesh.mesh_state import MeshCoordinator

    coord = MeshCoordinator(node_id="desktop", port=0, interval=30)
    coord.start()
    set_mesh_coordinator(coord)

    mgr = SecretCompartmentManager()
    set_secret_compartment_manager(mgr)

    test_app = FastAPI()
    test_app.include_router(router)
    test_app.dependency_overrides[verify_session_token] = lambda: {"id": "test", "role": "admin"}
    client = TestClient(test_app)
    yield client

    coord.stop()
    set_mesh_coordinator(None)
    set_secret_compartment_manager(None)


class TestSecretsRoutes:

    def test_distribution_empty(self, secrets_client):
        resp = secrets_client.get("/api/mesh/secrets/distribution")
        assert resp.status_code == 200
        assert resp.json() == {}

    def test_register_and_provision(self, secrets_client):
        # Register node
        resp = secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")
        assert resp.status_code == 200
        assert resp.json()["node_id"] == "vps1"

        # Provision allowed secret
        resp = secrets_client.post("/api/mesh/secrets/nodes/vps1/provision", json={
            "secret_id": "h1",
            "secret_type": "hmac_psk",
            "scope": "mesh",
            "description": "Heartbeat PSK",
        })
        assert resp.status_code == 200

        # Get node secrets
        resp = secrets_client.get("/api/mesh/secrets/nodes/vps1")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1

    def test_provision_denied(self, secrets_client):
        secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")

        resp = secrets_client.post("/api/mesh/secrets/nodes/vps1/provision", json={
            "secret_id": "vault1",
            "secret_type": "vault_master_key",
            "scope": "global",
        })
        assert resp.status_code == 403

    def test_revoke_secret(self, secrets_client):
        secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")
        secrets_client.post("/api/mesh/secrets/nodes/vps1/provision", json={
            "secret_id": "h1",
            "secret_type": "hmac_psk",
            "scope": "mesh",
        })

        resp = secrets_client.delete("/api/mesh/secrets/nodes/vps1/h1")
        assert resp.status_code == 200

    def test_compliance_check(self, secrets_client):
        secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")
        resp = secrets_client.get("/api/mesh/secrets/nodes/vps1/compliance")
        assert resp.status_code == 200
        assert resp.json()["compliant"] is True

    def test_audit_log(self, secrets_client):
        secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")
        resp = secrets_client.get("/api/mesh/secrets/audit")
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

    def test_list_manifests(self, secrets_client):
        secrets_client.post("/api/mesh/secrets/nodes/vps1?role=agent")
        secrets_client.post("/api/mesh/secrets/nodes/desktop?role=primary")
        resp = secrets_client.get("/api/mesh/secrets/manifests")
        assert resp.status_code == 200
        assert len(resp.json()["manifests"]) == 2
