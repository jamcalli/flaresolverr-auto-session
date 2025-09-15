#!/usr/bin/env python3
"""
Test script for automatic session management in FlareSolverr
"""

import requests
import json
import time
import sys

# Configuration
FLARESOLVERR_URL = "http://localhost:8191/v1"
TEST_URL = "https://example.com"  # Change this to a Cloudflare-protected site for real testing

def make_request(url, session_id=None):
    """Make a request through FlareSolverr"""
    payload = {
        "cmd": "request.get",
        "url": url,
        "maxTimeout": 60000
    }

    if session_id:
        payload["session"] = session_id

    response = requests.post(FLARESOLVERR_URL, json=payload)
    return response.json()

def list_sessions():
    """List all active sessions"""
    payload = {"cmd": "sessions.list"}
    response = requests.post(FLARESOLVERR_URL, json=payload)
    return response.json()

def test_auto_sessions():
    """Test automatic session management"""
    print("Testing FlareSolverr Automatic Session Management")
    print("=" * 50)

    # Check if FlareSolverr is running
    try:
        response = requests.get("http://localhost:8191/")
        print(f"✓ FlareSolverr is running: {response.json()['msg']}")
    except Exception as e:
        print(f"✗ FlareSolverr is not running: {e}")
        sys.exit(1)

    print("\n1. Listing initial sessions...")
    sessions_before = list_sessions()
    print(f"   Active sessions: {sessions_before.get('sessions', [])}")
    auto_sessions_before = [s for s in sessions_before.get('sessions', []) if s.startswith('auto_')]
    print(f"   Auto-sessions: {auto_sessions_before}")

    print(f"\n2. Making first request to {TEST_URL} (should create new auto-session)...")
    result1 = make_request(TEST_URL)
    if result1['status'] == 'ok':
        print(f"   ✓ Request successful")
        print(f"   Response URL: {result1['solution']['url']}")
    else:
        print(f"   ✗ Request failed: {result1.get('message', 'Unknown error')}")

    print("\n3. Listing sessions after first request...")
    sessions_after1 = list_sessions()
    print(f"   Active sessions: {sessions_after1.get('sessions', [])}")
    auto_sessions_after1 = [s for s in sessions_after1.get('sessions', []) if s.startswith('auto_')]
    print(f"   Auto-sessions: {auto_sessions_after1}")

    if len(auto_sessions_after1) > len(auto_sessions_before):
        print(f"   ✓ New auto-session created: {set(auto_sessions_after1) - set(auto_sessions_before)}")
    else:
        print(f"   ⚠ No new auto-session created (AUTO_SESSION_MANAGEMENT might be disabled)")

    print(f"\n4. Making second request to {TEST_URL} (should reuse existing session)...")
    time.sleep(2)  # Small delay to make it clear this is a separate request
    result2 = make_request(TEST_URL)
    if result2['status'] == 'ok':
        print(f"   ✓ Request successful")
    else:
        print(f"   ✗ Request failed: {result2.get('message', 'Unknown error')}")

    print("\n5. Listing sessions after second request...")
    sessions_after2 = list_sessions()
    auto_sessions_after2 = [s for s in sessions_after2.get('sessions', []) if s.startswith('auto_')]
    print(f"   Auto-sessions: {auto_sessions_after2}")

    if auto_sessions_after2 == auto_sessions_after1:
        print(f"   ✓ Session reused (no new session created)")
    else:
        print(f"   ⚠ New session created instead of reusing")

    print("\n6. Testing with different domain (should create new session)...")
    different_url = "https://cloudflare.com"
    result3 = make_request(different_url)
    if result3['status'] == 'ok':
        print(f"   ✓ Request to {different_url} successful")

    sessions_after3 = list_sessions()
    auto_sessions_after3 = [s for s in sessions_after3.get('sessions', []) if s.startswith('auto_')]
    print(f"   Auto-sessions: {auto_sessions_after3}")

    if len(auto_sessions_after3) > len(auto_sessions_after2):
        print(f"   ✓ New auto-session created for different domain")

    print("\n" + "=" * 50)
    print("Test Summary:")
    print(f"  - Initial auto-sessions: {len(auto_sessions_before)}")
    print(f"  - Final auto-sessions: {len(auto_sessions_after3)}")
    print(f"  - Sessions created: {len(auto_sessions_after3) - len(auto_sessions_before)}")

    if len(auto_sessions_after3) > len(auto_sessions_before):
        print("\n✓ Automatic session management appears to be working!")
        print("  Sessions are being created and reused as expected.")
    else:
        print("\n⚠ Automatic session management may not be enabled.")
        print("  Set AUTO_SESSION_MANAGEMENT=true environment variable and restart FlareSolverr.")

if __name__ == "__main__":
    test_auto_sessions()