#!/usr/bin/env python3
"""
Flask App Test Script
Simple test to verify the Flask cybersecurity automation system.
"""

import requests
import json
import time
import sys
from datetime import datetime

# Test configuration
BASE_URL = "http://localhost:5000"
TEST_TARGET = "example.com"

def test_flask_app():
    """Run a basic test of the Flask application."""
    print(f"🧪 Testing Flask Cybersecurity Automation System")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Test 1: Dashboard access
    print("1. Testing dashboard access...")
    try:
        response = requests.get(f"{BASE_URL}/", timeout=10)
        if response.status_code == 200:
            print("   ✅ Dashboard accessible")
        else:
            print(f"   ❌ Dashboard error: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Dashboard connection failed: {e}")
        return False
    
    # Test 2: System status API
    print("2. Testing system status API...")
    try:
        response = requests.get(f"{BASE_URL}/api/system/status", timeout=10)
        if response.status_code == 200:
            status = response.json()
            print(f"   ✅ System status: {json.dumps(status, indent=2)}")
        else:
            print(f"   ❌ Status API error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Status API failed: {e}")
    
    # Test 3: New assessment page
    print("3. Testing new assessment page...")
    try:
        response = requests.get(f"{BASE_URL}/new-assessment", timeout=10)
        if response.status_code == 200:
            print("   ✅ New assessment page accessible")
        else:
            print(f"   ❌ New assessment page error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ New assessment page failed: {e}")
    
    # Test 4: Start assessment API
    print("4. Testing start assessment API...")
    try:
        payload = {
            "target": TEST_TARGET,
            "scan_type": "quick",
            "enable_recon": True,
            "enable_predefined_tests": True,
            "enable_ai_tests": False
        }
        
        response = requests.post(
            f"{BASE_URL}/api/assessments",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                assessment_id = result.get('assessment_id')
                print(f"   ✅ Assessment started: {assessment_id}")
                
                # Test 5: Monitor assessment progress
                print("5. Monitoring assessment progress...")
                for i in range(10):  # Check for up to 10 iterations
                    time.sleep(2)
                    status_response = requests.get(
                        f"{BASE_URL}/api/assessment/{assessment_id}/status",
                        timeout=5
                    )
                    
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        current_status = status_data.get('status', 'unknown')
                        progress = status_data.get('progress', 0)
                        phase = status_data.get('current_phase', 'unknown')
                        
                        print(f"   📊 Progress: {progress}% - {current_status} ({phase})")
                        
                        if current_status in ['completed', 'failed']:
                            print(f"   ✅ Assessment {current_status}")
                            break
                    else:
                        print(f"   ⚠️  Status check failed: {status_response.status_code}")
                        break
                
            else:
                print(f"   ❌ Assessment failed to start: {result.get('error', 'Unknown error')}")
        else:
            print(f"   ❌ Assessment API error: {response.status_code}")
            print(f"   Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Assessment API failed: {e}")
    
    # Test 6: Assessments list page
    print("6. Testing assessments list page...")
    try:
        response = requests.get(f"{BASE_URL}/assessments", timeout=10)
        if response.status_code == 200:
            print("   ✅ Assessments list accessible")
        else:
            print(f"   ❌ Assessments list error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Assessments list failed: {e}")
    
    # Test 7: Reports page
    print("7. Testing reports page...")
    try:
        response = requests.get(f"{BASE_URL}/reports", timeout=10)
        if response.status_code == 200:
            print("   ✅ Reports page accessible")
        else:
            print(f"   ❌ Reports page error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Reports page failed: {e}")
    
    # Test 8: Settings page
    print("8. Testing settings page...")
    try:
        response = requests.get(f"{BASE_URL}/settings", timeout=10)
        if response.status_code == 200:
            print("   ✅ Settings page accessible")
        else:
            print(f"   ❌ Settings page error: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Settings page failed: {e}")
    
    print("=" * 60)
    print("🎉 Flask application test completed!")
    print("💡 Next steps:")
    print("   - Visit http://localhost:5000 to use the web interface")
    print("   - Check logs in the logs/ directory")
    print("   - Configure API keys for enhanced functionality")
    print("   - Install security tools (nmap, masscan) for full scanning")
    
    return True

if __name__ == "__main__":
    try:
        test_flask_app()
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        sys.exit(1)
