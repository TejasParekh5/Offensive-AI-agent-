#!/usr/bin/env python3
"""
Setup script for Multi-Agent Cybersecurity Automation System
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version.split()[0]}")


def install_python_requirements():
    """Install Python dependencies."""
    print("📦 Installing Python requirements...")

    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ])
        print("✅ Python requirements installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install Python requirements: {e}")
        return False

    return True


def check_security_tools():
    """Check availability of security tools."""
    print("🔍 Checking security tools availability...")

    tools = {
        'nmap': 'Network Mapper - Port scanning',
        'masscan': 'Fast port scanner (optional)',
        'rustscan': 'Fast port scanner in Rust (optional)',
        'amass': 'Subdomain enumeration (optional)',
        'theharvester': 'Email harvesting (optional)',
        'whois': 'Domain information lookup',
        'dig': 'DNS lookup utility',
        'ssh': 'SSH client for credential testing',
        'curl': 'HTTP client for web testing'
    }

    available_tools = []
    missing_tools = []

    for tool, description in tools.items():
        if shutil.which(tool):
            print(f"✅ {tool}: Available - {description}")
            available_tools.append(tool)
        else:
            print(f"⚠️  {tool}: Not found - {description}")
            missing_tools.append(tool)

    if missing_tools:
        print(f"\n📝 Missing tools: {', '.join(missing_tools)}")
        print("\nInstallation suggestions:")

        if 'nmap' in missing_tools:
            print("  • nmap: https://nmap.org/download.html")
        if 'masscan' in missing_tools:
            print("  • masscan: https://github.com/robertdavidgraham/masscan")
        if 'rustscan' in missing_tools:
            print("  • rustscan: https://github.com/RustScan/RustScan")
        if 'amass' in missing_tools:
            print("  • amass: https://github.com/OWASP/Amass")
        if 'theharvester' in missing_tools:
            print("  • theHarvester: https://github.com/laramies/theHarvester")

    return available_tools, missing_tools


def create_directories():
    """Create necessary directories."""
    print("📁 Creating directories...")

    directories = [
        'logs',
        'database',
        'reports/output',
        'reports/templates',
        'config',
        'agents',
        'utils'
    ]

    for directory in directories:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        print(f"✅ Created: {directory}")


def setup_environment_file():
    """Setup environment configuration file."""
    print("⚙️  Setting up environment configuration...")

    env_file = Path('.env')
    env_example = Path('.env.example')

    if not env_file.exists():
        if env_example.exists():
            shutil.copy(env_example, env_file)
            print("✅ Created .env file from template")
        else:
            # Create basic .env file
            env_content = """# Multi-Agent Cybersecurity System Configuration

# API Keys (add your actual keys)
SHODAN_API_KEY=your_shodan_api_key_here
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here

# Tool Paths
NMAP_PATH=nmap
MASSCAN_PATH=masscan
RUSTSCAN_PATH=rustscan
THEHARVESTER_PATH=theHarvester
AMASS_PATH=amass

# Database Configuration
DATABASE_PATH=./database/security_assessment.db

# Logging Configuration
LOG_LEVEL=INFO
LOG_FILE=./logs/system.log
"""
            with open(env_file, 'w') as f:
                f.write(env_content)
            print("✅ Created basic .env file")
    else:
        print("✅ .env file already exists")


def initialize_database():
    """Initialize the database."""
    print("🗄️  Initializing database...")

    try:
        # Import and initialize database manager
        sys.path.insert(0, str(Path.cwd()))
        from database.db_manager import DatabaseManager

        db = DatabaseManager()
        print("✅ Database initialized successfully")
        return True

    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False


def run_system_check():
    """Run system compatibility check."""
    print("🔧 Running system check...")

    # Check operating system
    import platform
    os_name = platform.system()
    print(f"✅ Operating System: {os_name}")

    # Check available memory
    try:
        import psutil
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        print(f"✅ Available Memory: {memory_gb:.1f} GB")

        if memory_gb < 2:
            print("⚠️  Warning: Less than 2GB RAM available. Performance may be limited.")
    except ImportError:
        print("ℹ️  psutil not available for memory check")

    # Check disk space
    total, used, free = shutil.disk_usage(".")
    free_gb = free / (1024**3)
    print(f"✅ Free Disk Space: {free_gb:.1f} GB")

    if free_gb < 1:
        print("⚠️  Warning: Less than 1GB free disk space available.")


def display_next_steps():
    """Display next steps for the user."""
    print("\n🎉 Setup completed successfully!")
    print("\n📋 Next Steps:")
    print("1. Configure API keys in the .env file:")
    print("   • Add your Shodan API key for reconnaissance features")
    print("   • Add OpenAI or Anthropic API key for LLM test generation")
    print()
    print("2. Install security tools (if not already available):")
    print("   • nmap (required for port scanning)")
    print("   • masscan, rustscan (optional, for faster scanning)")
    print("   • amass, theHarvester (optional, for enhanced reconnaissance)")
    print()
    print("3. Launch the dashboard:")
    print("   python main.py dashboard")
    print("   OR")
    print("   streamlit run dashboard.py")
    print()
    print("4. Run command-line scans:")
    print("   python main.py scan --target example.com")
    print("   python main.py test --target 192.168.1.1")
    print()
    print("🔒 Security Notice:")
    print("This tool is designed for authorized penetration testing only.")
    print("Ensure you have proper authorization before scanning any targets.")


def main():
    """Main setup function."""
    print("🛡️  Multi-Agent Cybersecurity Automation System Setup")
    print("=" * 60)

    try:
        # Check Python version
        check_python_version()

        # Create directories
        create_directories()

        # Install Python requirements
        if not install_python_requirements():
            print("❌ Setup failed due to dependency installation error")
            sys.exit(1)

        # Setup environment file
        setup_environment_file()

        # Check security tools
        available_tools, missing_tools = check_security_tools()

        # Initialize database
        if not initialize_database():
            print("❌ Setup failed due to database initialization error")
            sys.exit(1)

        # Run system check
        run_system_check()

        # Display next steps
        display_next_steps()

        print("\n✅ Setup completed successfully!")

    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
