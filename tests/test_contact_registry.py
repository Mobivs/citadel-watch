# Tests for Contact Management & Trusted Peer Registry
# v0.3.18 — Contact management and trusted peer registry
#
# Coverage:
#   - ContactRegistry: CRUD operations, trust management, message tracking
#   - TrustLevel: enum values and transitions
#   - Fingerprint: computation, validation
#   - API routes: list, add, get, update, delete, trust, stats, verify
#   - Edge cases: duplicate keys, invalid keys, blocked contacts

import os
import pytest
import secrets
from pathlib import Path
from unittest.mock import patch, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from citadel_archer.chat.contact_registry import (
    Contact,
    ContactRegistry,
    TrustLevel,
    compute_fingerprint,
    get_contact_registry,
    validate_public_key,
)
from citadel_archer.api.contact_routes import router


# ── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def registry(tmp_path):
    """Create a ContactRegistry with a temporary database."""
    db_path = str(tmp_path / "test_contacts.db")
    return ContactRegistry(db_path=db_path)


def _random_key() -> str:
    """Generate a random 32-byte Ed25519-like public key as hex."""
    return secrets.token_hex(32)


# ── Fingerprint Tests ───────────────────────────────────────────────


class TestFingerprint:
    def test_compute_fingerprint(self):
        key = "a" * 64  # 32 bytes of 0xaa
        fp = compute_fingerprint(key)
        assert ":" in fp
        parts = fp.split(":")
        assert len(parts) == 32  # SHA-256 = 32 bytes = 32 hex pairs
        assert all(len(p) == 2 for p in parts)

    def test_fingerprint_deterministic(self):
        key = _random_key()
        assert compute_fingerprint(key) == compute_fingerprint(key)

    def test_different_keys_different_fingerprints(self):
        k1 = _random_key()
        k2 = _random_key()
        assert compute_fingerprint(k1) != compute_fingerprint(k2)

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError, match="Invalid hex"):
            compute_fingerprint("not-hex-at-all!")


class TestValidatePublicKey:
    def test_valid_32_byte_key(self):
        assert validate_public_key("a" * 64) is True

    def test_too_short(self):
        assert validate_public_key("a" * 62) is False

    def test_too_long(self):
        assert validate_public_key("a" * 66) is False

    def test_invalid_hex(self):
        assert validate_public_key("xyz") is False

    def test_empty_string(self):
        assert validate_public_key("") is False


# ── Contact Registry CRUD ───────────────────────────────────────────


class TestContactRegistryAdd:
    def test_add_contact(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        assert contact.display_name == "Alice"
        assert contact.public_key == key
        assert contact.trust_level == TrustLevel.PENDING
        assert contact.fingerprint
        assert contact.contact_id
        assert contact.created_at

    def test_add_with_metadata(self, registry):
        key = _random_key()
        contact = registry.add(
            "Bob", public_key=key,
            alias="bobby", notes="Test peer", tags="friend,dev",
        )
        assert contact.alias == "bobby"
        assert contact.notes == "Test peer"
        assert contact.tags == "friend,dev"

    def test_add_duplicate_key_raises(self, registry):
        key = _random_key()
        registry.add("Alice", public_key=key)
        with pytest.raises(ValueError, match="already registered"):
            registry.add("Bob", public_key=key)

    def test_add_invalid_key_raises(self, registry):
        with pytest.raises(ValueError, match="Invalid public key"):
            registry.add("Alice", public_key="tooshort")

    def test_add_strips_whitespace(self, registry):
        key = _random_key()
        contact = registry.add("  Alice  ", public_key=f"  {key}  ")
        assert contact.display_name == "Alice"
        assert contact.public_key == key

    def test_add_with_initial_trust(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key, trust_level=TrustLevel.TRUSTED)
        assert contact.trust_level == TrustLevel.TRUSTED


class TestContactRegistryGet:
    def test_get_existing(self, registry):
        key = _random_key()
        created = registry.add("Alice", public_key=key)
        retrieved = registry.get(created.contact_id)
        assert retrieved is not None
        assert retrieved.display_name == "Alice"

    def test_get_nonexistent(self, registry):
        assert registry.get("nonexistent-id") is None

    def test_get_by_fingerprint(self, registry):
        key = _random_key()
        created = registry.add("Alice", public_key=key)
        found = registry.get_by_fingerprint(created.fingerprint)
        assert found is not None
        assert found.contact_id == created.contact_id

    def test_get_by_public_key(self, registry):
        key = _random_key()
        created = registry.add("Alice", public_key=key)
        found = registry.get_by_public_key(key)
        assert found is not None
        assert found.contact_id == created.contact_id


class TestContactRegistryList:
    def test_list_empty(self, registry):
        assert registry.list_contacts() == []

    def test_list_all(self, registry):
        for name in ["Alice", "Bob", "Charlie"]:
            registry.add(name, public_key=_random_key())
        contacts = registry.list_contacts()
        assert len(contacts) == 3
        # Should be sorted by display_name
        names = [c.display_name for c in contacts]
        assert names == ["Alice", "Bob", "Charlie"]

    def test_list_filter_by_trust(self, registry):
        k1, k2 = _random_key(), _random_key()
        c1 = registry.add("Alice", public_key=k1)
        c2 = registry.add("Bob", public_key=k2)
        registry.set_trust(c1.contact_id, TrustLevel.TRUSTED)

        trusted = registry.list_contacts(trust_level=TrustLevel.TRUSTED)
        assert len(trusted) == 1
        assert trusted[0].display_name == "Alice"

    def test_list_filter_by_tag(self, registry):
        registry.add("Alice", public_key=_random_key(), tags="friend,dev")
        registry.add("Bob", public_key=_random_key(), tags="work")

        friends = registry.list_contacts(tag="friend")
        assert len(friends) == 1
        assert friends[0].display_name == "Alice"

    def test_list_filter_by_tag_no_false_positives(self, registry):
        """Tag 'dev' should NOT match 'devops' or 'webdev'."""
        registry.add("Alice", public_key=_random_key(), tags="dev")
        registry.add("Bob", public_key=_random_key(), tags="devops")
        registry.add("Charlie", public_key=_random_key(), tags="webdev")
        registry.add("Diana", public_key=_random_key(), tags="work,dev,team")

        results = registry.list_contacts(tag="dev")
        names = [c.display_name for c in results]
        assert "Alice" in names    # exact match (only tag)
        assert "Diana" in names    # exact match (middle of list)
        assert "Bob" not in names  # "devops" is not "dev"
        assert "Charlie" not in names  # "webdev" is not "dev"
        assert len(results) == 2

    def test_list_search(self, registry):
        registry.add("Alice Smith", public_key=_random_key())
        registry.add("Bob Jones", public_key=_random_key(), notes="Alice's friend")

        results = registry.list_contacts(search="Alice")
        assert len(results) == 2  # Found in name and notes


class TestContactRegistryUpdate:
    def test_update_name(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        updated = registry.update(contact.contact_id, display_name="Alice Smith")
        assert updated.display_name == "Alice Smith"

    def test_update_alias(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        updated = registry.update(contact.contact_id, alias="ally")
        assert updated.alias == "ally"

    def test_update_nonexistent(self, registry):
        result = registry.update("nonexistent", display_name="Test")
        assert result is None

    def test_update_sets_updated_at(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        updated = registry.update(contact.contact_id, notes="New notes")
        assert updated.updated_at >= contact.updated_at


class TestContactRegistryDelete:
    def test_delete_existing(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        assert registry.delete(contact.contact_id) is True
        assert registry.get(contact.contact_id) is None

    def test_delete_nonexistent(self, registry):
        assert registry.delete("nonexistent") is False


# ── Trust Management ────────────────────────────────────────────────


class TestTrustManagement:
    def test_set_trust_verified(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        updated = registry.set_trust(contact.contact_id, TrustLevel.VERIFIED)
        assert updated.trust_level == TrustLevel.VERIFIED

    def test_set_trust_trusted(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        registry.set_trust(contact.contact_id, TrustLevel.VERIFIED)
        updated = registry.set_trust(contact.contact_id, TrustLevel.TRUSTED)
        assert updated.trust_level == TrustLevel.TRUSTED

    def test_set_trust_blocked(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        updated = registry.set_trust(contact.contact_id, TrustLevel.BLOCKED)
        assert updated.trust_level == TrustLevel.BLOCKED

    def test_is_trusted_pending(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        assert registry.is_trusted(contact.contact_id) is False

    def test_is_trusted_verified(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        registry.set_trust(contact.contact_id, TrustLevel.VERIFIED)
        assert registry.is_trusted(contact.contact_id) is True

    def test_is_trusted_trusted(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key, trust_level=TrustLevel.TRUSTED)
        assert registry.is_trusted(contact.contact_id) is True

    def test_is_trusted_blocked(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key, trust_level=TrustLevel.TRUSTED)
        registry.set_trust(contact.contact_id, TrustLevel.BLOCKED)
        assert registry.is_trusted(contact.contact_id) is False

    def test_is_blocked(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        assert registry.is_blocked(contact.contact_id) is False
        registry.set_trust(contact.contact_id, TrustLevel.BLOCKED)
        assert registry.is_blocked(contact.contact_id) is True

    def test_is_trusted_nonexistent(self, registry):
        assert registry.is_trusted("nonexistent") is False

    def test_is_blocked_nonexistent(self, registry):
        assert registry.is_blocked("nonexistent") is False

    def test_set_trust_nonexistent(self, registry):
        result = registry.set_trust("nonexistent", TrustLevel.TRUSTED)
        assert result is None


# ── Message Tracking ────────────────────────────────────────────────


class TestMessageTracking:
    def test_record_message(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        assert contact.message_count == 0

        assert registry.record_message(contact.contact_id) is True
        assert registry.record_message(contact.contact_id) is True
        assert registry.record_message(contact.contact_id) is True

        updated = registry.get(contact.contact_id)
        assert updated.message_count == 3
        assert updated.last_message_at != ""

    def test_record_message_nonexistent(self, registry):
        assert registry.record_message("nonexistent-id") is False


# ── Statistics ──────────────────────────────────────────────────────


class TestStats:
    def test_empty_stats(self, registry):
        stats = registry.stats()
        assert stats["total_contacts"] == 0
        assert stats["by_trust_level"] == {}

    def test_stats_with_contacts(self, registry):
        registry.add("Alice", public_key=_random_key())
        c2 = registry.add("Bob", public_key=_random_key())
        registry.set_trust(c2.contact_id, TrustLevel.TRUSTED)

        stats = registry.stats()
        assert stats["total_contacts"] == 2
        assert stats["by_trust_level"]["pending"] == 1
        assert stats["by_trust_level"]["trusted"] == 1


# ── Contact.to_dict() ──────────────────────────────────────────────


class TestContactToDict:
    def test_to_dict(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key, tags="friend,dev")
        d = contact.to_dict()
        assert d["display_name"] == "Alice"
        assert d["trust_level"] == "pending"
        assert d["tags"] == ["friend", "dev"]
        assert "contact_id" in d

    def test_to_dict_empty_tags(self, registry):
        key = _random_key()
        contact = registry.add("Alice", public_key=key)
        d = contact.to_dict()
        assert d["tags"] == []


# ── TrustLevel Enum ─────────────────────────────────────────────────


class TestTrustLevelEnum:
    def test_values(self):
        assert TrustLevel.PENDING.value == "pending"
        assert TrustLevel.VERIFIED.value == "verified"
        assert TrustLevel.TRUSTED.value == "trusted"
        assert TrustLevel.BLOCKED.value == "blocked"

    def test_from_string(self):
        assert TrustLevel("pending") == TrustLevel.PENDING
        assert TrustLevel("blocked") == TrustLevel.BLOCKED


# ── API Route Tests ────────────────────────────────────────────────


@pytest.fixture
def api_registry(tmp_path):
    """ContactRegistry backed by tmp database for API tests."""
    db_path = str(tmp_path / "api_contacts.db")
    return ContactRegistry(db_path=db_path)


@pytest.fixture
def client(api_registry):
    """FastAPI test client with auth bypass and patched registry."""
    from citadel_archer.api.security import verify_session_token

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[verify_session_token] = lambda: "test-token"

    with patch(
        "citadel_archer.api.contact_routes.get_contact_registry",
        return_value=api_registry,
    ):
        yield TestClient(app)

    app.dependency_overrides.clear()


class TestContactRoutesAPI:
    def test_list_empty(self, client):
        resp = client.get("/api/contacts")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["contacts"] == []

    def test_add_and_get(self, client):
        key = _random_key()
        resp = client.post("/api/contacts", json={
            "display_name": "Alice",
            "public_key": key,
        })
        assert resp.status_code == 201
        contact = resp.json()
        assert contact["display_name"] == "Alice"
        assert contact["public_key"] == key
        assert contact["trust_level"] == "pending"

        # GET by ID
        cid = contact["contact_id"]
        resp2 = client.get(f"/api/contacts/{cid}")
        assert resp2.status_code == 200
        assert resp2.json()["display_name"] == "Alice"

    def test_add_invalid_key_400(self, client):
        resp = client.post("/api/contacts", json={
            "display_name": "Bad",
            "public_key": "not-hex",
        })
        assert resp.status_code == 422  # Pydantic validation (hex pattern)

    def test_add_duplicate_key_400(self, client, api_registry):
        key = _random_key()
        api_registry.add("Alice", public_key=key)
        resp = client.post("/api/contacts", json={
            "display_name": "Bob",
            "public_key": key,
        })
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

    def test_update_contact(self, client, api_registry):
        key = _random_key()
        contact = api_registry.add("Alice", public_key=key)
        resp = client.put(f"/api/contacts/{contact.contact_id}", json={
            "display_name": "Alice Smith",
            "alias": "ally",
        })
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "Alice Smith"
        assert resp.json()["alias"] == "ally"

    def test_update_nonexistent_404(self, client):
        resp = client.put("/api/contacts/nonexistent", json={
            "display_name": "Test",
        })
        assert resp.status_code == 404

    def test_delete_contact(self, client, api_registry):
        key = _random_key()
        contact = api_registry.add("Alice", public_key=key)
        resp = client.delete(f"/api/contacts/{contact.contact_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_delete_nonexistent_404(self, client):
        resp = client.delete("/api/contacts/nonexistent")
        assert resp.status_code == 404

    def test_set_trust_level(self, client, api_registry):
        key = _random_key()
        contact = api_registry.add("Alice", public_key=key)
        resp = client.post(f"/api/contacts/{contact.contact_id}/trust", json={
            "trust_level": "verified",
        })
        assert resp.status_code == 200
        assert resp.json()["trust_level"] == "verified"

    def test_set_trust_invalid_level_422(self, client, api_registry):
        key = _random_key()
        contact = api_registry.add("Alice", public_key=key)
        resp = client.post(f"/api/contacts/{contact.contact_id}/trust", json={
            "trust_level": "invalid_level",
        })
        assert resp.status_code == 422  # Pydantic enum validation

    def test_set_trust_nonexistent_404(self, client):
        resp = client.post("/api/contacts/nonexistent/trust", json={
            "trust_level": "trusted",
        })
        assert resp.status_code == 404

    def test_stats_endpoint(self, client, api_registry):
        api_registry.add("Alice", public_key=_random_key())
        resp = client.get("/api/contacts/stats")
        assert resp.status_code == 200
        assert resp.json()["total_contacts"] == 1

    def test_verify_fingerprint(self, client, api_registry):
        key = _random_key()
        contact = api_registry.add("Alice", public_key=key)
        fp = contact.fingerprint
        resp = client.get(f"/api/contacts/verify/{fp}")
        assert resp.status_code == 200
        assert resp.json()["display_name"] == "Alice"

    def test_verify_fingerprint_not_found_404(self, client):
        resp = client.get("/api/contacts/verify/AA:BB:CC:DD")
        assert resp.status_code == 404

    def test_list_with_trust_filter(self, client, api_registry):
        c1 = api_registry.add("Alice", public_key=_random_key())
        api_registry.add("Bob", public_key=_random_key())
        api_registry.set_trust(c1.contact_id, TrustLevel.TRUSTED)

        resp = client.get("/api/contacts?trust=trusted")
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        assert resp.json()["contacts"][0]["display_name"] == "Alice"

    def test_list_with_invalid_trust_400(self, client):
        resp = client.get("/api/contacts?trust=bogus")
        assert resp.status_code == 400
