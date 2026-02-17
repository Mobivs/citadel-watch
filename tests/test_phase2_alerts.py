"""
Phase 2 Alert System Test Suite
Tests all endpoints added for Phase 2 alert functionality.
Uses FastAPI TestClient (no running server required).
"""

import pytest
from datetime import datetime

from fastapi.testclient import TestClient

from citadel_archer.api.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        # Clear any existing alerts at the start
        c.delete("/api/alerts/clear")
        yield c


class TestPhase2Alerts:
    """Test suite for Phase 2 alert endpoints."""

    def test_health_endpoint(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    def test_submit_threat(self, client):
        threat = {
            "threat_type": "port_scan",
            "severity": 7,
            "source": "192.168.1.100",
            "target": "10.0.0.1",
            "description": "Port scan detected from suspicious IP",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        response = client.post("/api/threats/submit", json=threat)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert "alert_id" in data
        assert data["severity_level"] == "high"

    def test_threat_deduplication(self, client):
        threat = {
            "threat_type": "malware",
            "severity": 9,
            "source": "evil.exe",
            "target": "system32",
            "description": "Malware detection"
        }
        r1 = client.post("/api/threats/submit", json=threat)
        assert r1.json()["status"] == "created"
        alert_id1 = r1.json()["alert_id"]

        r2 = client.post("/api/threats/submit", json=threat)
        assert r2.json()["status"] == "deduplicated"
        assert r2.json()["alert_id"] == alert_id1
        assert r2.json()["duplicate_count"] > 0

    def test_get_alerts(self, client):
        threats = [
            {"threat_type": "brute_force", "severity": 5, "source": "attacker1", "description": "Login attempts"},
            {"threat_type": "cve", "severity": 8, "source": "CVE-2024-1234", "description": "Vulnerability"},
            {"threat_type": "port_scan", "severity": 3, "source": "scanner", "description": "Network scan"}
        ]
        for threat in threats:
            client.post("/api/threats/submit", json=threat)

        response = client.get("/api/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert len(data["alerts"]) >= 3

        # Test severity filter
        response = client.get("/api/alerts", params={"severity_min": 7})
        data = response.json()
        for alert in data["alerts"]:
            assert alert["severity"] >= 7

        # Test threat type filter
        response = client.get("/api/alerts", params={"threat_type": "cve"})
        data = response.json()
        for alert in data["alerts"]:
            assert alert["threat_type"] == "cve"

    def test_acknowledge_all_alerts(self, client):
        client.post("/api/threats/submit", json={
            "threat_type": "test_ack",
            "severity": 6,
            "source": "test",
            "description": "Test acknowledgment"
        })

        response = client.post("/api/alerts/acknowledge-all")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "acknowledged_count" in data

        response = client.get("/api/alerts", params={"acknowledged": False})
        data = response.json()
        assert len(data["alerts"]) == 0

    def test_clear_alert_history(self, client):
        for i in range(3):
            client.post("/api/threats/submit", json={
                "threat_type": f"test_clear_{i}",
                "severity": 5,
                "source": "test",
                "description": "Test clear"
            })

        response = client.delete("/api/alerts/clear")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["deleted_count"] >= 3

        response = client.get("/api/alerts")
        data = response.json()
        assert len(data["alerts"]) == 0

    def test_alert_config(self, client):
        response = client.get("/api/alert-config")
        assert response.status_code == 200
        original_config = response.json()
        assert "escalation_enabled" in original_config
        assert "deduplication" in original_config
        assert "stage_intervals" in original_config

        new_config = {
            "escalation_enabled": False,
            "deduplication": True,
            "deduplication_window": 600,
            "stage_intervals": [0, 60, 120]
        }

        response = client.post("/api/alert-config", json=new_config)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["config"]["escalation_enabled"] is False
        assert data["config"]["deduplication_window"] == 600

        # Restore
        client.post("/api/alert-config", json=original_config)

    def test_severity_levels(self, client):
        severity_tests = [
            (2, "info"),
            (4, "low"),
            (6, "medium"),
            (8, "high"),
            (10, "critical")
        ]

        for severity, expected_level in severity_tests:
            response = client.post("/api/threats/submit", json={
                "threat_type": "severity_test",
                "severity": severity,
                "source": "test",
                "description": f"Testing severity {severity}"
            })
            alert_id = response.json()["alert_id"]

            response = client.get("/api/alerts")
            alerts = response.json()["alerts"]
            alert = next((a for a in alerts if a["id"] == alert_id), None)
            assert alert is not None
            assert alert["severity_level"] == expected_level

    def test_escalation_simulation(self, client):
        response = client.post("/api/threats/submit", json={
            "threat_type": "escalation_test",
            "severity": 9,
            "source": "critical_threat",
            "description": "Critical threat requiring escalation"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["escalation_enabled"] is True

    def test_threat_metadata(self, client):
        threat = {
            "threat_type": "advanced_threat",
            "severity": 7,
            "source": "192.168.1.50",
            "target": "web_server",
            "description": "Advanced persistent threat detected",
            "metadata": {
                "attack_vector": "phishing",
                "ioc_count": 5,
                "confidence": 0.85
            }
        }
        response = client.post("/api/threats/submit", json=threat)
        assert response.status_code == 200
