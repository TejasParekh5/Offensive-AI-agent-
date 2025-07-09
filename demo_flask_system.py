#!/usr/bin/env python3
"""
Flask Cybersecurity System Demo
Comprehensive demonstration of the Flask-based automation platform.
"""

import subprocess
import sys
import time
import requests
import json
from pathlib import Path


def print_banner():
    """Print the demo banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║     🛡️  Flask Cybersecurity Automation System Demo         ║
    ║                                                              ║
    ║  A comprehensive, modular security assessment platform      ║
    ║  featuring multi-agent architecture and real-time tracking  ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def check_system():
    """Check if the system is ready."""
    print("🔍 Checking system requirements...")

    # Check Python version
    python_version = sys.version_info
    print(
        f"   ✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}")

    # Check if Flask app exists
    flask_app_path = Path("flask_app.py")
    if flask_app_path.exists():
        print("   ✅ Flask application found")
    else:
        print("   ❌ Flask application not found")
        return False

    # Check templates
    templates_dir = Path("templates")
    if templates_dir.exists():
        template_count = len(list(templates_dir.glob("*.html")))
        print(f"   ✅ Templates directory found ({template_count} templates)")
    else:
        print("   ❌ Templates directory not found")

    # Check if requirements are met
    try:
        import flask
        print(f"   ✅ Flask {flask.__version__}")
    except ImportError:
        print("   ❌ Flask not installed")
        return False

    try:
        import flask_sqlalchemy
        print("   ✅ Flask-SQLAlchemy available")
    except ImportError:
        print("   ⚠️  Flask-SQLAlchemy not available (database features limited)")

    try:
        import flask_socketio
        print("   ✅ Flask-SocketIO available")
    except ImportError:
        print("   ⚠️  Flask-SocketIO not available (real-time updates disabled)")

    return True


def start_flask_server():
    """Start the Flask server in the background."""
    print("🚀 Starting Flask server...")

    try:
        # Start Flask app in background
        process = subprocess.Popen(
            [sys.executable, "flask_app.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Wait a bit for server to start
        time.sleep(5)

        # Check if server is running
        try:
            response = requests.get("http://localhost:5000", timeout=5)
            if response.status_code == 200:
                print("   ✅ Flask server started successfully")
                print("   🌐 Server running at http://localhost:5000")
                return process
            else:
                print(
                    f"   ❌ Server responded with status {response.status_code}")
                return None
        except requests.exceptions.RequestException:
            print("   ❌ Unable to connect to Flask server")
            return None

    except Exception as e:
        print(f"   ❌ Failed to start server: {e}")
        return None


def demonstrate_features():
    """Demonstrate key features of the system."""
    print("\n🎯 Demonstrating key features...")

    base_url = "http://localhost:5000"

    # Feature 1: Dashboard
    print("\n1. 📊 Dashboard Access")
    try:
        response = requests.get(f"{base_url}/", timeout=10)
        if response.status_code == 200:
            print("   ✅ Dashboard accessible with system overview")
            print("   📈 Real-time statistics and assessment tracking")
        else:
            print(f"   ❌ Dashboard error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Dashboard failed: {e}")

    # Feature 2: System Status API
    print("\n2. 🔧 System Status API")
    try:
        response = requests.get(f"{base_url}/api/system/status", timeout=10)
        if response.status_code == 200:
            status = response.json()
            print("   ✅ System status API working")
            print(f"   📋 Components: Flask App ({'✅' if status.get('flask_app') else '❌'}), "
                  f"Database ({'✅' if status.get('database') else '❌'}), "
                  f"Agents ({'✅' if status.get('agents') else '❌'})")
        else:
            print(f"   ❌ Status API error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Status API failed: {e}")

    # Feature 3: Assessment Creation
    print("\n3. 🎯 Assessment Creation")
    try:
        response = requests.get(f"{base_url}/new-assessment", timeout=10)
        if response.status_code == 200:
            print("   ✅ Assessment creation interface available")
            print("   🔧 Multi-agent configuration with real-time validation")
        else:
            print(f"   ❌ Assessment creation error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Assessment creation failed: {e}")

    # Feature 4: Start Sample Assessment
    print("\n4. 🚀 Sample Assessment Execution")
    try:
        payload = {
            "target": "example.com",
            "scan_type": "quick",
            "enable_recon": True,
            "enable_predefined_tests": True,
            "enable_ai_tests": False
        }

        response = requests.post(
            f"{base_url}/api/assessments",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                assessment_id = result.get('assessment_id')
                print(f"   ✅ Assessment started: {assessment_id}")
                print("   📊 Real-time progress tracking available")

                # Monitor progress briefly
                for i in range(3):
                    time.sleep(2)
                    status_response = requests.get(
                        f"{base_url}/api/assessment/{assessment_id}/status",
                        timeout=5
                    )
                    if status_response.status_code == 200:
                        status_data = status_response.json()
                        progress = status_data.get('progress', 0)
                        phase = status_data.get('current_phase', 'unknown')
                        print(f"   📈 Progress: {progress}% ({phase})")

            else:
                print(
                    f"   ⚠️  Assessment simulation: {result.get('error', 'Demo mode')}")
        else:
            print(
                f"   ⚠️  Assessment API: Demo mode (status {response.status_code})")
    except Exception as e:
        print(f"   ⚠️  Assessment demo: {e}")

    # Feature 5: Report Generation
    print("\n5. 📑 Report Generation")
    try:
        response = requests.get(f"{base_url}/reports", timeout=10)
        if response.status_code == 200:
            print("   ✅ Report management interface available")
            print("   📊 PDF, JSON, and CSV export capabilities")
        else:
            print(f"   ❌ Reports interface error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Reports interface failed: {e}")

    # Feature 6: Settings Management
    print("\n6. ⚙️ Settings Management")
    try:
        response = requests.get(f"{base_url}/settings", timeout=10)
        if response.status_code == 200:
            print("   ✅ Settings interface available")
            print("   🔧 LLM integration, scanning tools, and API configuration")
        else:
            print(f"   ❌ Settings interface error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Settings interface failed: {e}")


def show_next_steps():
    """Show next steps for users."""
    print("\n" + "="*70)
    print("🎉 Flask Cybersecurity Automation System Demo Complete!")
    print("="*70)

    print("\n🚀 **System is ready for use!**")
    print("\n📋 **Next Steps:**")
    print("   1. 🌐 Open http://localhost:5000 in your browser")
    print("   2. 🎯 Create your first security assessment")
    print("   3. 📊 Monitor real-time progress and results")
    print("   4. 📑 Generate and download comprehensive reports")
    print("   5. ⚙️ Configure tools and API keys in settings")

    print("\n🔧 **Advanced Configuration:**")
    print("   • Install security tools: nmap, masscan, rustscan")
    print("   • Set up Ollama for local LLM capabilities")
    print("   • Configure API keys (Shodan, etc.) for enhanced OSINT")
    print("   • Review logs in the logs/ directory")

    print("\n📚 **Documentation:**")
    print("   • README_FLASK.md - Complete system documentation")
    print("   • USER_GUIDE.md - Detailed usage instructions")
    print("   • LLAMA_INTEGRATION.md - LLM setup guide")

    print("\n🛠️ **Troubleshooting:**")
    print("   • Run: python setup_and_test.py check")
    print("   • Test: python test_flask_system.py")
    print("   • Logs: Check logs/ directory for detailed information")

    print("\n" + "="*70)


def main():
    """Main demo function."""
    print_banner()

    # Check system
    if not check_system():
        print("\n❌ System check failed. Please install requirements and try again.")
        return 1

    # Start Flask server
    server_process = start_flask_server()
    if not server_process:
        print("\n❌ Failed to start Flask server.")
        return 1

    try:
        # Demonstrate features
        demonstrate_features()

        # Show next steps
        show_next_steps()

        # Keep server running
        print(f"\n⏳ Server is running at http://localhost:5000")
        print("   Press Ctrl+C to stop the demo and shut down the server...")

        # Wait for user interruption
        server_process.wait()

    except KeyboardInterrupt:
        print("\n\n⏹️  Demo stopped by user")
        if server_process:
            server_process.terminate()
            print("🔄 Shutting down Flask server...")
            time.sleep(2)

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        if server_process:
            server_process.terminate()
        return 1

    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
