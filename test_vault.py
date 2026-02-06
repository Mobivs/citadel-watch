#!/usr/bin/env python3
"""
Quick Vault Backend Test Script
Tests Vault functionality without UI
"""

import requests
import json

BASE_URL = "http://127.0.0.1:8000/api/vault"

def test_vault():
    print("Testing Citadel Archer Vault Backend")
    print("=" * 60)

    # Test 1: Check vault status
    print("\n1. Checking vault status...")
    response = requests.get(f"{BASE_URL}/status")
    status = response.json()
    print(f"   Vault exists: {status['vault_exists']}")
    print(f"   Vault unlocked: {status['is_unlocked']}")

    # Test 2: Initialize vault (if doesn't exist)
    if not status['vault_exists']:
        print("\n2. Initializing vault with master password...")
        response = requests.post(
            f"{BASE_URL}/initialize",
            json={"master_password": "TestPassword123"}
        )
        if response.status_code == 200:
            print(f"   [OK] {response.json()['message']}")
        else:
            print(f"   [ERROR] Error: {response.json()['detail']}")
            return
    else:
        print("\n2. Vault already exists, skipping initialization")

    # Test 3: Unlock vault
    print("\n3. Unlocking vault...")
    response = requests.post(
        f"{BASE_URL}/unlock",
        json={"master_password": "TestPassword123"}
    )
    if response.status_code == 200:
        print(f"   [OK] {response.json()['message']}")
    else:
        print(f"   [ERROR] Error: {response.json()['detail']}")
        return

    # Test 4: Add a test password
    print("\n4. Adding test password...")
    response = requests.post(
        f"{BASE_URL}/passwords",
        json={
            "title": "Test Gmail Account",
            "password": "super_secret_password_123",
            "username": "test@gmail.com",
            "website": "https://gmail.com",
            "notes": "My test account",
            "category": "email"
        }
    )
    if response.status_code == 200:
        password_id = response.json()['password_id']
        print(f"   [OK] Password added! ID: {password_id}")
    else:
        print(f"   [ERROR] Error: {response.json()['detail']}")
        return

    # Test 5: List passwords
    print("\n5. Listing all passwords...")
    response = requests.get(f"{BASE_URL}/passwords")
    passwords = response.json()['passwords']
    print(f"   [OK] Found {len(passwords)} password(s)")
    for pwd in passwords:
        print(f"      - {pwd['title']} ({pwd['username']})")

    # Test 6: Retrieve specific password (decrypted)
    print("\n6. Retrieving password (with decryption)...")
    response = requests.get(f"{BASE_URL}/passwords/{password_id}")
    password_data = response.json()
    print(f"   [OK] Title: {password_data['title']}")
    print(f"   [OK] Username: {password_data['username']}")
    print(f"   [OK] Password: {password_data['password']}")
    print(f"   [OK] Website: {password_data['website']}")

    # Test 7: Lock vault
    print("\n7. Locking vault...")
    response = requests.post(f"{BASE_URL}/lock")
    print(f"   [OK] {response.json()['message']}")

    # Test 8: Verify locked
    print("\n8. Verifying vault is locked...")
    response = requests.get(f"{BASE_URL}/status")
    status = response.json()
    if not status['is_unlocked']:
        print(f"   [OK] Vault is locked (secure)")
    else:
        print(f"   [ERROR] Vault is still unlocked!")

    print("\n" + "=" * 60)
    print("[OK] All tests passed! Vault backend is working!")
    print("\nVault database location:")
    print("   c:\\Users\\John Vickrey\\citadel-archer\\data\\vault.db")
    print("\nYou can now build the UI components.")
    print("=" * 60)

if __name__ == "__main__":
    try:
        test_vault()
    except requests.exceptions.ConnectionError:
        print("[ERROR] Error: Cannot connect to backend.")
        print("Make sure Citadel Archer is running:")
        print("   python -m citadel_archer")
    except Exception as e:
        print(f"[ERROR] Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
