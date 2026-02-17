"""Tests for Remote Shield SQLite persistence.

Covers:
  - RemoteShieldDatabase: CRUD for agents and threats, token hashing
  - remote_shield_routes: API endpoints use DB instead of in-memory dicts
  - Data survives reinstantiation (persistence proof)
  - Token security: raw tokens are never stored
"""

import hashlib
import json
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from citadel_archer.remote.shield_database import RemoteShieldDatabase, _hash_token


# ── RemoteShieldDatabase unit tests ──────────────────────────────────


class TestRemoteShieldDatabase:
    """Core database operations."""

    @pytest.fixture
    def db(self, tmp_path):
        return RemoteShieldDatabase(db_path=tmp_path / "shield.db")

    def test_creates_db_file(self, tmp_path):
        db = RemoteShieldDatabase(db_path=tmp_path / "shield.db")
        assert (tmp_path / "shield.db").exists()

    def test_creates_parent_dirs(self, tmp_path):
        db = RemoteShieldDatabase(db_path=tmp_path / "sub" / "dir" / "shield.db")
        assert (tmp_path / "sub" / "dir" / "shield.db").exists()


class TestAgentCRUD:
    """Agent create, read, list, update operations."""

    @pytest.fixture
    def db(self, tmp_path):
        return RemoteShieldDatabase(db_path=tmp_path / "shield.db")

    def test_create_and_get_agent(self, db):
        agent = db.create_agent(
            agent_id="agent-1",
            hostname="prod-vps",
            ip_address="10.0.0.1",
            api_token="secret-token-123",
        )
        assert agent["id"] == "agent-1"
        assert agent["hostname"] == "prod-vps"
        assert agent["ip_address"] == "10.0.0.1"
        assert agent["status"] == "active"

        fetched = db.get_agent("agent-1")
        assert fetched is not None
        assert fetched["hostname"] == "prod-vps"

    def test_get_nonexistent_agent_returns_none(self, db):
        assert db.get_agent("no-such-agent") is None

    def test_get_agent_by_hostname(self, db):
        db.create_agent("a1", "myhost", "1.2.3.4", "tok1")
        db.create_agent("a2", "otherhost", "5.6.7.8", "tok2")

        found = db.get_agent_by_hostname("myhost")
        assert found is not None
        assert found["id"] == "a1"

        assert db.get_agent_by_hostname("nope") is None

    def test_list_agents(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")
        db.create_agent("a2", "host2", "2.2.2.2", "t2")
        db.create_agent("a3", "host3", "3.3.3.3", "t3")

        agents = db.list_agents()
        assert len(agents) == 3
        hostnames = {a["hostname"] for a in agents}
        assert hostnames == {"host1", "host2", "host3"}

    def test_update_heartbeat(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")

        result = db.update_agent_heartbeat("a1")
        assert result is True

        agent = db.get_agent("a1")
        assert agent["status"] == "active"
        assert agent["last_heartbeat"] is not None

    def test_update_last_scan(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")

        result = db.update_agent_last_scan("a1")
        assert result is True

        agent = db.get_agent("a1")
        assert agent["last_scan_at"] is not None

    def test_update_asset_id(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")

        db.update_agent_asset_id("a1", "asset_abc123")
        agent = db.get_agent("a1")
        assert agent["asset_id"] == "asset_abc123"

    def test_alert_threshold_default_zero(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")
        assert db.get_agent_alert_threshold("a1") == 0
        agent = db.get_agent("a1")
        assert agent.get("alert_threshold", 0) == 0

    def test_set_and_get_alert_threshold(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "t1")
        result = db.set_agent_alert_threshold("a1", 5)
        assert result is True
        assert db.get_agent_alert_threshold("a1") == 5

    def test_alert_threshold_nonexistent_agent(self, db):
        assert db.get_agent_alert_threshold("no-such") == 0
        assert db.set_agent_alert_threshold("no-such", 3) is False


class TestTokenSecurity:
    """API token hashing and verification."""

    @pytest.fixture
    def db(self, tmp_path):
        return RemoteShieldDatabase(db_path=tmp_path / "shield.db")

    def test_hash_token_is_deterministic(self):
        assert _hash_token("abc") == _hash_token("abc")

    def test_hash_token_is_sha256(self):
        expected = hashlib.sha256(b"test-token").hexdigest()
        assert _hash_token("test-token") == expected

    def test_raw_token_not_stored(self, db, tmp_path):
        """Verify the raw token string does NOT appear in the DB file."""
        token = "super-secret-token-that-should-not-be-stored"
        db.create_agent("a1", "host1", "1.1.1.1", token)

        # Read raw DB bytes (include WAL file if present)
        raw = (tmp_path / "shield.db").read_bytes()
        wal = tmp_path / "shield.db-wal"
        if wal.exists():
            raw += wal.read_bytes()

        assert token.encode() not in raw

    def test_verify_valid_token(self, db):
        token = secrets.token_urlsafe(32)
        db.create_agent("a1", "host1", "1.1.1.1", token)

        agent_id = db.verify_token(token)
        assert agent_id == "a1"

    def test_verify_invalid_token(self, db):
        db.create_agent("a1", "host1", "1.1.1.1", "real-token")
        assert db.verify_token("wrong-token") is None

    def test_token_rotation_invalidates_old(self, db):
        old_token = "old-token"
        new_token = "new-token"
        db.create_agent("a1", "host1", "1.1.1.1", old_token)

        assert db.verify_token(old_token) == "a1"

        db.update_agent_token("a1", new_token)

        assert db.verify_token(old_token) is None
        assert db.verify_token(new_token) == "a1"


class TestThreatCRUD:
    """Threat create, read, list, filter, update operations."""

    @pytest.fixture
    def db(self, tmp_path):
        db = RemoteShieldDatabase(db_path=tmp_path / "shield.db")
        db.create_agent("agent-1", "host1", "1.1.1.1", "tok1")
        return db

    def test_create_and_get_threat(self, db):
        threat_id = db.create_threat({
            "threat_id": "t1",
            "agent_id": "agent-1",
            "type": "port_scan_anomaly",
            "severity": 7,
            "title": "Suspicious port scan",
            "details": {"ports": [22, 80, 443]},
            "hostname": "host1",
            "detected_at": datetime.utcnow(),
        })
        assert threat_id == "t1"

        t = db.get_threat("t1")
        assert t is not None
        assert t["title"] == "Suspicious port scan"
        assert t["severity"] == 7
        assert t["details"] == {"ports": [22, 80, 443]}
        assert t["status"] == "open"

    def test_get_nonexistent_threat(self, db):
        assert db.get_threat("no-such") is None

    def test_list_threats_no_filter(self, db):
        for i in range(5):
            db.create_threat({
                "threat_id": f"t{i}",
                "agent_id": "agent-1",
                "type": "process_anomaly",
                "severity": 3,
                "title": f"Threat {i}",
                "hostname": "host1",
            })

        threats = db.list_threats()
        assert len(threats) == 5

    def test_list_threats_filter_by_agent(self, db):
        db.create_agent("agent-2", "host2", "2.2.2.2", "tok2")
        db.create_threat({"threat_id": "t1", "agent_id": "agent-1", "type": "file_integrity", "severity": 5, "title": "T1", "hostname": "h1"})
        db.create_threat({"threat_id": "t2", "agent_id": "agent-2", "type": "file_integrity", "severity": 5, "title": "T2", "hostname": "h2"})

        threats = db.list_threats(agent_id="agent-1")
        assert len(threats) == 1
        assert threats[0]["id"] == "t1"

    def test_list_threats_filter_by_type(self, db):
        db.create_threat({"threat_id": "t1", "agent_id": "agent-1", "type": "brute_force_attempt", "severity": 8, "title": "BF", "hostname": "h"})
        db.create_threat({"threat_id": "t2", "agent_id": "agent-1", "type": "vulnerability", "severity": 6, "title": "Vuln", "hostname": "h"})

        threats = db.list_threats(threat_type="brute_force_attempt")
        assert len(threats) == 1
        assert threats[0]["type"] == "brute_force_attempt"

    def test_list_threats_filter_by_status(self, db):
        db.create_threat({"threat_id": "t1", "agent_id": "agent-1", "type": "vulnerability", "severity": 5, "title": "A", "hostname": "h"})
        db.create_threat({"threat_id": "t2", "agent_id": "agent-1", "type": "vulnerability", "severity": 5, "title": "B", "hostname": "h"})
        db.update_threat_status("t1", "resolved")

        open_threats = db.list_threats(status="open")
        assert len(open_threats) == 1
        assert open_threats[0]["id"] == "t2"

    def test_list_threats_pagination(self, db):
        for i in range(10):
            db.create_threat({"threat_id": f"t{i}", "agent_id": "agent-1", "type": "process_anomaly", "severity": 3, "title": f"T{i}", "hostname": "h"})

        page1 = db.list_threats(limit=3, offset=0)
        page2 = db.list_threats(limit=3, offset=3)
        assert len(page1) == 3
        assert len(page2) == 3
        assert page1[0]["id"] != page2[0]["id"]

    def test_update_threat_status(self, db):
        db.create_threat({"threat_id": "t1", "agent_id": "agent-1", "type": "file_integrity", "severity": 5, "title": "FI", "hostname": "h"})

        result = db.update_threat_status("t1", "acknowledged")
        assert result is True

        t = db.get_threat("t1")
        assert t["status"] == "acknowledged"

    def test_update_nonexistent_threat(self, db):
        result = db.update_threat_status("nope", "resolved")
        assert result is False


class TestPersistenceAcrossInstances:
    """Data survives database reinstantiation (the whole point)."""

    def test_agent_survives_restart(self, tmp_path):
        db_path = tmp_path / "shield.db"

        # Instance 1: create agent
        db1 = RemoteShieldDatabase(db_path=db_path)
        token = secrets.token_urlsafe(32)
        db1.create_agent("a1", "prod-vps", "10.0.0.1", token)

        # Instance 2: read agent back
        db2 = RemoteShieldDatabase(db_path=db_path)
        agent = db2.get_agent("a1")
        assert agent is not None
        assert agent["hostname"] == "prod-vps"

        # Token still verifies
        assert db2.verify_token(token) == "a1"

    def test_threat_survives_restart(self, tmp_path):
        db_path = tmp_path / "shield.db"

        # Instance 1: create agent + threat
        db1 = RemoteShieldDatabase(db_path=db_path)
        db1.create_agent("a1", "host1", "1.1.1.1", "tok")
        db1.create_threat({
            "threat_id": "t1",
            "agent_id": "a1",
            "type": "brute_force_attempt",
            "severity": 9,
            "title": "SSH brute force",
            "details": {"attempts": 1500},
            "hostname": "host1",
        })

        # Instance 2: read threat back
        db2 = RemoteShieldDatabase(db_path=db_path)
        t = db2.get_threat("t1")
        assert t is not None
        assert t["title"] == "SSH brute force"
        assert t["details"] == {"attempts": 1500}
        assert t["severity"] == 9


# ── Route integration tests ──────────────────────────────────────────

class TestRouteIntegration:
    """Verify route handlers use the database correctly."""

    @pytest.fixture(autouse=True)
    def _setup_db(self, tmp_path):
        """Inject a temp database into the routes module."""
        import citadel_archer.api.remote_shield_routes as rs

        self.db = RemoteShieldDatabase(db_path=tmp_path / "shield.db")
        self._orig_db = rs._shield_db
        self._orig_inv = rs._asset_inventory
        rs.set_shield_db(self.db)

        # Use a temp-dir-backed AssetInventory to avoid polluting production DB
        from citadel_archer.intel.assets import AssetInventory
        inv = AssetInventory(db_path=tmp_path / "assets.db")
        rs.set_asset_inventory(inv)

        yield

        rs._shield_db = self._orig_db
        rs._asset_inventory = self._orig_inv

    @pytest.mark.asyncio
    async def test_register_agent_persists(self):
        from citadel_archer.api.remote_shield_routes import register_agent, AgentRegistration

        reg = AgentRegistration(hostname="test-vps", ip="192.168.1.100")
        resp = await register_agent(reg)

        assert resp.agent_id
        assert resp.api_token
        assert resp.message == "Agent test-vps registered successfully"

        # Verify it's in the DB
        agent = self.db.get_agent(resp.agent_id)
        assert agent is not None
        assert agent["hostname"] == "test-vps"

        # Verify token works
        assert self.db.verify_token(resp.api_token) == resp.agent_id

    @pytest.mark.asyncio
    async def test_re_register_invalidates_old_token(self):
        from citadel_archer.api.remote_shield_routes import register_agent, AgentRegistration

        reg = AgentRegistration(hostname="test-vps", ip="192.168.1.100")
        resp1 = await register_agent(reg)
        old_token = resp1.api_token

        resp2 = await register_agent(reg)
        new_token = resp2.api_token

        assert resp1.agent_id == resp2.agent_id  # same agent
        assert old_token != new_token

        # Old token invalidated
        assert self.db.verify_token(old_token) is None
        assert self.db.verify_token(new_token) == resp1.agent_id

    @pytest.mark.asyncio
    async def test_submit_threat_persists(self):
        from citadel_archer.api.remote_shield_routes import register_agent, submit_threat, AgentRegistration, ThreatReport

        reg = AgentRegistration(hostname="vps1", ip="10.0.0.1")
        resp = await register_agent(reg)

        threat = ThreatReport(
            type="brute_force_attempt",
            severity=8,
            title="SSH brute force detected",
            details={"source_ip": "1.2.3.4", "attempts": 500},
            hostname="vps1",
        )

        # Call submit_threat directly (bypassing auth dep for simplicity)
        result = await submit_threat(threat, agent_id=resp.agent_id)
        assert result.status == "success"

        # Verify threat is persisted
        t = self.db.get_threat(result.id)
        assert t is not None
        assert t["title"] == "SSH brute force detected"
        assert t["severity"] == 8

    @pytest.mark.asyncio
    async def test_list_agents_from_db(self):
        from citadel_archer.api.remote_shield_routes import register_agent, list_agents, AgentRegistration

        await register_agent(AgentRegistration(hostname="vps1", ip="10.0.0.1"))
        await register_agent(AgentRegistration(hostname="vps2", ip="10.0.0.2"))

        agents = await list_agents()
        assert len(agents) == 2

    @pytest.mark.asyncio
    async def test_get_agent_not_found(self):
        from citadel_archer.api.remote_shield_routes import get_agent
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc:
            await get_agent("nonexistent")
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_update_threat_status_persists(self):
        from citadel_archer.api.remote_shield_routes import (
            register_agent, submit_threat, update_threat_status,
            AgentRegistration, ThreatReport,
        )

        reg = AgentRegistration(hostname="vps1", ip="10.0.0.1")
        agent_resp = await register_agent(reg)

        threat = ThreatReport(type="vulnerability", severity=6, title="CVE found", hostname="vps1")
        threat_resp = await submit_threat(threat, agent_id=agent_resp.agent_id)

        await update_threat_status(threat_resp.id, "resolved")

        t = self.db.get_threat(threat_resp.id)
        assert t["status"] == "resolved"

    @pytest.mark.asyncio
    async def test_verify_agent_token_dependency(self):
        from citadel_archer.api.remote_shield_routes import register_agent, verify_agent_token, AgentRegistration
        from fastapi import HTTPException

        reg = AgentRegistration(hostname="vps1", ip="10.0.0.1")
        resp = await register_agent(reg)

        # Valid token
        agent_id = verify_agent_token(f"Bearer {resp.api_token}")
        assert agent_id == resp.agent_id

        # Invalid token
        with pytest.raises(HTTPException) as exc:
            verify_agent_token("Bearer bad-token")
        assert exc.value.status_code == 401

        # Missing header
        with pytest.raises(HTTPException):
            verify_agent_token(None)

        # Bad format
        with pytest.raises(HTTPException):
            verify_agent_token("NotBearer token")

    @pytest.mark.asyncio
    async def test_agent_auto_links_asset(self):
        """Registration should create a managed asset and link it."""
        from citadel_archer.api.remote_shield_routes import register_agent, AgentRegistration, get_asset_inventory

        reg = AgentRegistration(hostname="auto-linked-vps", ip="10.99.0.1")
        resp = await register_agent(reg)

        assert resp.asset_id is not None

        # Asset should exist in inventory
        inv = get_asset_inventory()
        asset = inv.get(resp.asset_id)
        assert asset is not None
        assert asset.hostname == "auto-linked-vps"
        assert asset.remote_shield_agent_id == resp.agent_id
