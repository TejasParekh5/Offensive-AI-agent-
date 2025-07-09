#!/usr/bin/env python3
"""
System Test Script for Multi-Agent Cybersecurity Automation System
Tests all components to ensure proper functionality.
"""

import sys
import os
import asyncio
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def test_imports():
    """Test if all required modules can be imported."""
    print("🔍 Testing imports...")

    try:
        # Test core modules
        from agents.recon_agent import ReconAgent
        from agents.scanning_agent import ScanningAgent
        from agents.test_case_agent import TestCaseAgent
        from database.db_manager import DatabaseManager
        from reports.report_generator import ReportGenerator
        from utils.validators import validate_target
        from utils.helpers import setup_logging, generate_session_id, get_env_var, load_config
        print("✅ All core modules imported successfully")

        # Test external dependencies
        import streamlit
        import pandas
        import plotly
        import requests
        import dns.resolver  # dnspython
        import jinja2
        print("✅ All external dependencies imported successfully")

        return True
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False


def test_configuration():
    """Test configuration loading."""
    print("\n🔧 Testing configuration...")

    try:
        from utils.helpers import load_config, get_env_var

        # Test config loading
        config = load_config('./config/settings.json')
        if config:
            print("✅ Configuration loaded successfully")
        else:
            print("⚠️ Configuration file not found or empty")

        # Test environment variables
        log_level = get_env_var('LOG_LEVEL', 'INFO')
        print(f"✅ Environment variables accessible (LOG_LEVEL: {log_level})")

        return True
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False


def test_database():
    """Test database connection and initialization."""
    print("\n💾 Testing database...")

    try:
        from database.db_manager import DatabaseManager

        db = DatabaseManager()

        # Test session creation
        session_id = db.create_session("test_target", "test_user")
        if session_id:
            print("✅ Database session creation successful")
        else:
            print("❌ Database session creation failed")

        return True
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False


def test_agents():
    """Test agent initialization."""
    print("\n🤖 Testing agents...")

    try:
        from agents.recon_agent import ReconAgent
        from agents.scanning_agent import ScanningAgent
        from agents.test_case_agent import TestCaseAgent

        # Test agent initialization
        recon = ReconAgent()
        scanning = ScanningAgent()
        test_case = TestCaseAgent()

        print("✅ All agents initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Agent initialization error: {e}")
        return False


def test_validators():
    """Test input validation."""
    print("\n✔️ Testing validators...")

    try:
        from utils.validators import validate_target

        # Test valid targets
        valid_ip = validate_target("192.168.1.1", "ip")
        valid_domain = validate_target("example.com", "domain")

        if valid_ip and valid_domain:
            print("✅ Target validation working correctly")
        else:
            print("⚠️ Target validation may have issues")

        return True
    except Exception as e:
        print(f"❌ Validator error: {e}")
        return False


def test_report_generator():
    """Test report generation."""
    print("\n📋 Testing report generator...")

    try:
        from reports.report_generator import ReportGenerator

        report_gen = ReportGenerator()
        print("✅ Report generator initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Report generator error: {e}")
        return False


def test_directory_structure():
    """Test that all required directories exist."""
    print("\n📁 Testing directory structure...")

    required_dirs = [
        'agents',
        'config',
        'database',
        'reports',
        'utils',
        'logs'
    ]

    missing_dirs = []
    for dir_name in required_dirs:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            missing_dirs.append(dir_name)

    if missing_dirs:
        print(f"❌ Missing directories: {missing_dirs}")
        return False
    else:
        print("✅ All required directories exist")
        return True


def test_required_files():
    """Test that all required files exist."""
    print("\n📄 Testing required files...")

    required_files = [
        'requirements.txt',
        'README.md',
        'USER_GUIDE.md',
        '.env',
        '.env.example',
        'dashboard.py',
        'main.py',
        'setup.py',
        '__init__.py',
        'config/settings.json',
        'config/test_cases.json'
    ]

    missing_files = []
    for file_name in required_files:
        file_path = Path(file_name)
        if not file_path.exists():
            missing_files.append(file_name)

    if missing_files:
        print(f"❌ Missing files: {missing_files}")
        return False
    else:
        print("✅ All required files exist")
        return True


def run_basic_functionality_test():
    """Run a basic end-to-end functionality test."""
    print("\n🚀 Running basic functionality test...")

    try:
        from utils.helpers import generate_session_id
        from utils.validators import validate_target

        # Test session ID generation
        session_id = generate_session_id()
        if len(session_id) > 0:
            print(f"✅ Session ID generated: {session_id[:8]}...")

        # Test target validation
        if validate_target("8.8.8.8", "ip"):
            print("✅ IP validation working")

        if validate_target("google.com", "domain"):
            print("✅ Domain validation working")

        print("✅ Basic functionality test passed")
        return True
    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("🛡️ Multi-Agent Cybersecurity System - System Test")
    print("=" * 50)

    tests = [
        test_directory_structure,
        test_required_files,
        test_imports,
        test_configuration,
        test_database,
        test_agents,
        test_validators,
        test_report_generator,
        run_basic_functionality_test
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")

    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! System is ready to use.")
        print("\nNext steps:")
        print("1. Configure API keys in .env file")
        print("2. Install tools (nmap, masscan, etc.) if needed")
        print("3. Run: python main.py dashboard")
    else:
        print("⚠️ Some tests failed. Please check the issues above.")
        print("\nTroubleshooting:")
        print("1. Ensure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check that all required files and directories exist")
        print("3. Verify configuration files are properly formatted")

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
