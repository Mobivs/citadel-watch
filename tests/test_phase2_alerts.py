#!/usr/bin/env python3
"""
Phase 2 Alert System Test Suite
Tests all new endpoints added for Phase 2 alert functionality
"""

import pytest
import requests
import json
import time
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:8000"
API_BASE = f"{BASE_URL}/api"

class TestPhase2Alerts:
    """Test suite for Phase 2 alert endpoints"""
    
    @classmethod
    def setup_class(cls):
        """Setup test environment"""
        # Clear any existing alerts
        try:
            requests.delete(f"{API_BASE}/alerts/clear")
        except:
            pass
    
    def test_health_endpoint(self):
        """Test GET /api/health endpoint"""
        response = requests.get(f"{API_BASE}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "timestamp" in data
        print("✓ Health endpoint working")
    
    def test_submit_threat(self):
        """Test POST /api/threats/submit endpoint"""
        threat = {
            "threat_type": "port_scan",
            "severity": 7,
            "source": "192.168.1.100",
            "target": "10.0.0.1",
            "description": "Port scan detected from suspicious IP",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        response = requests.post(f"{API_BASE}/threats/submit", json=threat)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert "alert_id" in data
        assert data["severity_level"] == "high"
        print("✓ Threat submission working")
        return data["alert_id"]
    
    def test_threat_deduplication(self):
        """Test threat deduplication within time window"""
        # Submit same threat multiple times
        threat = {
            "threat_type": "malware",
            "severity": 9,
            "source": "evil.exe",
            "target": "system32",
            "description": "Malware detection"
        }
        
        # First submission should create alert
        response1 = requests.post(f"{API_BASE}/threats/submit", json=threat)
        assert response1.json()["status"] == "created"
        alert_id1 = response1.json()["alert_id"]
        
        # Second submission should be deduplicated
        response2 = requests.post(f"{API_BASE}/threats/submit", json=threat)
        assert response2.json()["status"] == "deduplicated"
        assert response2.json()["alert_id"] == alert_id1
        assert response2.json()["duplicate_count"] > 0
        
        print("✓ Deduplication working")
    
    def test_get_alerts(self):
        """Test GET /api/alerts endpoint with filters"""
        # Submit various threats first
        threats = [
            {"threat_type": "brute_force", "severity": 5, "source": "attacker1", "description": "Login attempts"},
            {"threat_type": "cve", "severity": 8, "source": "CVE-2024-1234", "description": "Vulnerability"},
            {"threat_type": "port_scan", "severity": 3, "source": "scanner", "description": "Network scan"}
        ]
        
        for threat in threats:
            requests.post(f"{API_BASE}/threats/submit", json=threat)
        
        # Test basic listing
        response = requests.get(f"{API_BASE}/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert len(data["alerts"]) >= 3
        
        # Test severity filter
        response = requests.get(f"{API_BASE}/alerts", params={"severity_min": 7})
        data = response.json()
        for alert in data["alerts"]:
            assert alert["severity"] >= 7
        
        # Test threat type filter
        response = requests.get(f"{API_BASE}/alerts", params={"threat_type": "cve"})
        data = response.json()
        for alert in data["alerts"]:
            assert alert["threat_type"] == "cve"
        
        print("✓ Alert listing with filters working")
    
    def test_acknowledge_all_alerts(self):
        """Test POST /api/alerts/acknowledge-all endpoint"""
        # First, ensure we have unacknowledged alerts
        requests.post(f"{API_BASE}/threats/submit", json={
            "threat_type": "test_ack",
            "severity": 6,
            "source": "test",
            "description": "Test acknowledgment"
        })
        
        # Acknowledge all
        response = requests.post(f"{API_BASE}/alerts/acknowledge-all")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "acknowledged_count" in data
        
        # Verify all are acknowledged
        response = requests.get(f"{API_BASE}/alerts", params={"acknowledged": False})
        data = response.json()
        assert len(data["alerts"]) == 0
        
        print("✓ Bulk acknowledgment working")
    
    def test_clear_alert_history(self):
        """Test DELETE /api/alerts/clear endpoint"""
        # Add some alerts
        for i in range(3):
            requests.post(f"{API_BASE}/threats/submit", json={
                "threat_type": f"test_clear_{i}",
                "severity": 5,
                "source": "test",
                "description": "Test clear"
            })
        
        # Clear history
        response = requests.delete(f"{API_BASE}/alerts/clear")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["deleted_count"] >= 3
        
        # Verify alerts are cleared
        response = requests.get(f"{API_BASE}/alerts")
        data = response.json()
        assert len(data["alerts"]) == 0
        
        print("✓ Alert history clearing working")
    
    def test_alert_config(self):
        """Test GET and POST /api/alert-config endpoints"""
        # Get current config
        response = requests.get(f"{API_BASE}/alert-config")
        assert response.status_code == 200
        original_config = response.json()
        assert "escalation_enabled" in original_config
        assert "deduplication" in original_config
        assert "stage_intervals" in original_config
        
        # Update config
        new_config = {
            "escalation_enabled": False,
            "deduplication": True,
            "deduplication_window": 600,
            "stage_intervals": [0, 60, 120]
        }
        
        response = requests.post(f"{API_BASE}/alert-config", json=new_config)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["config"]["escalation_enabled"] == False
        assert data["config"]["deduplication_window"] == 600
        
        # Restore original config
        requests.post(f"{API_BASE}/alert-config", json=original_config)
        
        print("✓ Alert configuration management working")
    
    def test_severity_levels(self):
        """Test severity level categorization"""
        severity_tests = [
            (2, "info"),
            (4, "low"),
            (6, "medium"),
            (8, "high"),
            (10, "critical")
        ]
        
        for severity, expected_level in severity_tests:
            response = requests.post(f"{API_BASE}/threats/submit", json={
                "threat_type": "severity_test",
                "severity": severity,
                "source": "test",
                "description": f"Testing severity {severity}"
            })
            
            alert_id = response.json()["alert_id"]
            
            # Get alert details
            response = requests.get(f"{API_BASE}/alerts")
            alerts = response.json()["alerts"]
            alert = next((a for a in alerts if a["id"] == alert_id), None)
            
            assert alert is not None
            assert alert["severity_level"] == expected_level
        
        print("✓ Severity level categorization working")
    
    def test_escalation_simulation(self):
        """Test alert escalation stages (simplified test)"""
        # Submit high-severity threat that should trigger escalation
        response = requests.post(f"{API_BASE}/threats/submit", json={
            "threat_type": "escalation_test",
            "severity": 9,
            "source": "critical_threat",
            "description": "Critical threat requiring escalation"
        })
        
        assert response.status_code == 200
        data = response.json()
        assert data["escalation_enabled"] == True
        
        # In a real test, we would wait and verify stage progression
        # For now, just verify the escalation was initiated
        print("✓ Escalation initiation working")
    
    def test_threat_metadata(self):
        """Test threat submission with metadata"""
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
        
        response = requests.post(f"{API_BASE}/threats/submit", json=threat)
        assert response.status_code == 200
        print("✓ Threat metadata handling working")

def run_tests():
    """Run all Phase 2 alert tests"""
    print("\n" + "="*60)
    print("PHASE 2 ALERT SYSTEM TEST SUITE")
    print("="*60 + "\n")
    
    test_suite = TestPhase2Alerts()
    test_suite.setup_class()
    
    tests = [
        test_suite.test_health_endpoint,
        test_suite.test_submit_threat,
        test_suite.test_threat_deduplication,
        test_suite.test_get_alerts,
        test_suite.test_acknowledge_all_alerts,
        test_suite.test_clear_alert_history,
        test_suite.test_alert_config,
        test_suite.test_severity_levels,
        test_suite.test_escalation_simulation,
        test_suite.test_threat_metadata
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} failed: {str(e)}")
    
    print("\n" + "="*60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    
    return failed == 0

if __name__ == "__main__":
    # Note: Ensure the API server is running before executing tests
    print("Note: Make sure the API server is running on localhost:8000")
    print("Run with: cd /root/clawd/citadel-watch && python -m src.citadel_archer.api.main")
    print()
    
    success = run_tests()
    exit(0 if success else 1)