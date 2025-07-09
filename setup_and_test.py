#!/usr/bin/env python3
"""
Unified Setup and Test Utility for Multi-Agent Cybersecurity Automation System
Combines setup, testing, and Llama integration into a single comprehensive tool.
"""

import os
import sys
import subprocess
import shutil
import asyncio
import logging
from pathlib import Path
import argparse

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


class Colors:
    """ANSI color codes for better output."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'


def colored_print(text, color=Colors.WHITE):
    """Print colored text."""
    print(f"{color}{text}{Colors.END}")


def check_python_version():
    """Check if Python version is compatible."""
    if sys.version_info < (3, 8):
        colored_print("❌ Python 3.8 or higher is required", Colors.RED)
        colored_print(f"Current version: {sys.version}", Colors.RED)
        return False
    colored_print(f"✅ Python version: {sys.version.split()[0]}", Colors.GREEN)
    return True


def install_dependencies(include_llama=False):
    """Install Python dependencies."""
    colored_print("📦 Installing dependencies...", Colors.BLUE)

    try:
        # Install core requirements
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "--quiet"
        ])
        colored_print("✅ Core dependencies installed", Colors.GREEN)

        # Install Llama dependencies if requested
        if include_llama:
            llama_deps = [
                "torch>=2.0.0",
                "transformers>=4.40.0",
                "accelerate>=0.20.0",
                "bitsandbytes>=0.41.0",
                "sentencepiece>=0.1.99",
                "huggingface-hub>=0.16.0"
            ]

            for dep in llama_deps:
                try:
                    subprocess.check_call([
                        sys.executable, "-m", "pip", "install", dep, "--quiet"
                    ])
                    colored_print(
                        f"✅ {dep.split('>=')[0]} installed", Colors.GREEN)
                except subprocess.CalledProcessError:
                    colored_print(f"⚠️ Failed to install {dep}", Colors.YELLOW)

        return True
    except subprocess.CalledProcessError as e:
        colored_print(f"❌ Failed to install dependencies: {e}", Colors.RED)
        return False


def check_system_requirements():
    """Check system requirements."""
    colored_print("🔍 Checking system requirements...", Colors.BLUE)

    # Check memory
    try:
        import psutil
        memory_gb = psutil.virtual_memory().total / (1024**3)
        if memory_gb >= 16:
            colored_print(
                f"✅ Memory: {memory_gb:.1f}GB (Excellent for Llama)", Colors.GREEN)
        elif memory_gb >= 8:
            colored_print(
                f"✅ Memory: {memory_gb:.1f}GB (Good with quantization)", Colors.YELLOW)
        else:
            colored_print(
                f"⚠️ Memory: {memory_gb:.1f}GB (Limited, may affect performance)", Colors.YELLOW)
    except ImportError:
        colored_print(
            "⚠️ Cannot check memory (psutil not installed)", Colors.YELLOW)

    # Check CUDA
    try:
        import torch
        if torch.cuda.is_available():
            gpu_count = torch.cuda.device_count()
            gpu_memory = torch.cuda.get_device_properties(
                0).total_memory / (1024**3)
            colored_print(
                f"✅ CUDA: {gpu_count} GPU(s), {gpu_memory:.1f}GB VRAM", Colors.GREEN)
        else:
            colored_print(
                "⚠️ CUDA not available - CPU will be used", Colors.YELLOW)
    except ImportError:
        colored_print("ℹ️ PyTorch not installed yet", Colors.CYAN)

    # Check disk space
    total, used, free = shutil.disk_usage(".")
    free_gb = free / (1024**3)
    if free_gb >= 25:
        colored_print(f"✅ Disk space: {free_gb:.1f}GB free", Colors.GREEN)
    else:
        colored_print(
            f"⚠️ Disk space: {free_gb:.1f}GB free (may be insufficient for Llama)", Colors.YELLOW)

    return True


def check_security_tools():
    """Check availability of security tools."""
    colored_print("🔧 Checking security tools...", Colors.BLUE)

    tools = {
        'nmap': 'Network Mapper - Port scanning (Required)',
        'masscan': 'Fast port scanner (Optional)',
        'rustscan': 'Rust port scanner (Optional)',
        'amass': 'Subdomain enumeration (Optional)',
        'theharvester': 'Email harvesting (Optional)',
        'curl': 'HTTP client (Recommended)',
        'whois': 'Domain info (Recommended)'
    }

    available = []
    missing = []

    for tool, description in tools.items():
        if shutil.which(tool):
            colored_print(f"✅ {tool}: Available", Colors.GREEN)
            available.append(tool)
        else:
            color = Colors.RED if 'Required' in description else Colors.YELLOW
            colored_print(f"❌ {tool}: Not found - {description}", color)
            missing.append(tool)

    return available, missing


def create_directories():
    """Create necessary directories."""
    colored_print("📁 Creating directories...", Colors.BLUE)

    directories = [
        'logs', 'database', 'reports/output', 'reports/templates',
        'config', 'agents', 'utils'
    ]

    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

    colored_print("✅ Directories created", Colors.GREEN)


def setup_environment():
    """Setup environment configuration."""
    colored_print("⚙️ Setting up environment...", Colors.BLUE)

    env_file = Path('.env')
    env_example = Path('.env.example')

    if not env_file.exists():
        if env_example.exists():
            shutil.copy(env_example, env_file)
            colored_print("✅ Created .env from template", Colors.GREEN)
        else:
            # Create basic .env
            env_content = """# Multi-Agent Cybersecurity System Configuration
# API Keys
SHODAN_API_KEY=
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# Llama Configuration
LLAMA_MAX_LENGTH=4096
LLAMA_TEMPERATURE=0.7
LLAMA_USE_QUANTIZATION=true

# Tool Paths
NMAP_PATH=nmap
MASSCAN_PATH=masscan
RUSTSCAN_PATH=rustscan

# System Configuration
DATABASE_PATH=./database/security_assessment.db
LOG_LEVEL=INFO
LOG_FILE=./logs/system.log
"""
            env_file.write_text(env_content)
            colored_print("✅ Created basic .env file", Colors.GREEN)
    else:
        colored_print("✅ .env file already exists", Colors.GREEN)


def test_imports():
    """Test core module imports."""
    colored_print("🔍 Testing imports...", Colors.BLUE)

    try:
        # Core modules
        from agents.recon_agent import ReconAgent
        from agents.scanning_agent import ScanningAgent
        from agents.test_case_agent import TestCaseAgent
        from database.db_manager import DatabaseManager
        from reports.report_generator import ReportGenerator
        from utils.validators import validate_target
        from utils.helpers import setup_logging, generate_session_id

        # External dependencies
        import streamlit
        import pandas
        import plotly
        import requests
        import jinja2

        colored_print("✅ All imports successful", Colors.GREEN)
        return True
    except ImportError as e:
        colored_print(f"❌ Import error: {e}", Colors.RED)
        return False


def test_database():
    """Test database initialization."""
    colored_print("💾 Testing database...", Colors.BLUE)

    try:
        from database.db_manager import DatabaseManager
        db = DatabaseManager()

        # Test session creation
        session_created = db.create_session(
            "test_session", "test_target", "domain")
        if session_created:
            colored_print("✅ Database working correctly", Colors.GREEN)
        else:
            colored_print("⚠️ Database session creation failed", Colors.YELLOW)

        return True
    except Exception as e:
        colored_print(f"❌ Database error: {e}", Colors.RED)
        return False


def test_agents():
    """Test agent initialization."""
    colored_print("🤖 Testing agents...", Colors.BLUE)

    try:
        from agents.recon_agent import ReconAgent
        from agents.scanning_agent import ScanningAgent
        from agents.test_case_agent import TestCaseAgent

        ReconAgent()
        ScanningAgent()
        TestCaseAgent()

        colored_print("✅ All agents initialized", Colors.GREEN)
        return True
    except Exception as e:
        colored_print(f"❌ Agent error: {e}", Colors.RED)
        return False


def setup_llama():
    """Setup Llama 3.1 8B model."""
    colored_print("🦙 Setting up Llama 3.1 8B...", Colors.PURPLE)

    try:
        # Check if transformers is available
        import transformers
        from transformers import AutoTokenizer, AutoModelForCausalLM

        model_name = "meta-llama/Meta-Llama-3.1-8B-Instruct"

        colored_print(
            "⬇️ Downloading Llama model (this may take time)...", Colors.CYAN)

        # Download tokenizer
        tokenizer = AutoTokenizer.from_pretrained(
            model_name, trust_remote_code=True)
        colored_print("✅ Tokenizer downloaded", Colors.GREEN)

        # Download model
        model = AutoModelForCausalLM.from_pretrained(
            model_name,
            trust_remote_code=True,
            torch_dtype="auto",
            device_map="auto"
        )
        colored_print("✅ Model downloaded and cached", Colors.GREEN)

        return True

    except Exception as e:
        colored_print(f"❌ Llama setup failed: {e}", Colors.RED)

        if "gated repo" in str(e).lower() or "access" in str(e).lower():
            colored_print("🔐 Model access required:", Colors.YELLOW)
            colored_print(
                "1. Visit: https://huggingface.co/meta-llama/Meta-Llama-3.1-8B-Instruct", Colors.CYAN)
            colored_print(
                "2. Request access and login: huggingface-cli login", Colors.CYAN)

        return False


def test_llama():
    """Test Llama integration."""
    colored_print("🧪 Testing Llama integration...", Colors.PURPLE)

    try:
        from utils.llama_integration import LlamaIntegration

        llama = LlamaIntegration()

        if llama.is_available():
            colored_print("✅ Llama model loaded successfully", Colors.GREEN)

            # Quick test
            test_data = {'target': 'test.com', 'target_type': 'domain'}
            scan_results = [{'port': 80, 'service': 'http', 'state': 'open'}]

            test_cases = llama.generate_test_cases(test_data, scan_results)

            if test_cases:
                colored_print(
                    f"✅ Generated {len(test_cases)} test cases", Colors.GREEN)
            else:
                colored_print("⚠️ No test cases generated", Colors.YELLOW)

            llama.cleanup()
            return True
        else:
            colored_print("❌ Llama model not available", Colors.RED)
            return False

    except Exception as e:
        colored_print(f"❌ Llama test failed: {e}", Colors.RED)
        return False


def run_full_test():
    """Run comprehensive system test."""
    colored_print("🧪 Running comprehensive system test...", Colors.BLUE)

    tests = [
        ("Import Test", test_imports),
        ("Database Test", test_database),
        ("Agents Test", test_agents)
    ]

    passed = 0
    for test_name, test_func in tests:
        if test_func():
            passed += 1

    colored_print(f"📊 Core tests: {passed}/{len(tests)} passed", Colors.CYAN)
    return passed == len(tests)


def display_help():
    """Display usage help."""
    colored_print(
        "🛡️ Multi-Agent Cybersecurity Automation - Setup & Test Utility", Colors.BOLD)
    print("""
Usage: python setup_and_test.py [command] [options]

Commands:
  setup              Complete system setup
  setup-llama        Setup Llama 3.1 8B model only
  test               Run system tests
  test-llama         Test Llama integration only
  install            Install dependencies only
  check              Check system requirements
  tools              Check security tools
  all                Setup everything and test

Options:
  --include-llama    Include Llama dependencies in setup
  --help, -h         Show this help message

Examples:
  python setup_and_test.py setup --include-llama
  python setup_and_test.py test
  python setup_and_test.py setup-llama
  python setup_and_test.py all
    """)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Cybersecurity System Setup & Test")
    parser.add_argument('command', nargs='?', default='help',
                        choices=['setup', 'setup-llama', 'test', 'test-llama',
                                 'install', 'check', 'tools', 'all', 'help'])
    parser.add_argument('--include-llama', action='store_true',
                        help='Include Llama dependencies')

    args = parser.parse_args()

    if args.command == 'help':
        display_help()
        return

    colored_print(
        "🛡️ Multi-Agent Cybersecurity Automation System", Colors.BOLD)
    colored_print("=" * 60, Colors.CYAN)

    if not check_python_version():
        sys.exit(1)

    success = True

    if args.command in ['setup', 'all']:
        colored_print("\n🚀 Running complete setup...", Colors.BLUE)
        create_directories()
        setup_environment()
        success &= install_dependencies(args.include_llama)
        check_system_requirements()
        check_security_tools()
        success &= run_full_test()

        if args.include_llama and success:
            success &= setup_llama()

    elif args.command == 'setup-llama':
        colored_print("\n🦙 Setting up Llama only...", Colors.PURPLE)
        success &= install_dependencies(include_llama=True)
        success &= setup_llama()
        success &= test_llama()

    elif args.command == 'test':
        colored_print("\n🧪 Running system tests...", Colors.BLUE)
        success &= run_full_test()

    elif args.command == 'test-llama':
        colored_print("\n🦙 Testing Llama integration...", Colors.PURPLE)
        success &= test_llama()

    elif args.command == 'install':
        colored_print("\n📦 Installing dependencies...", Colors.BLUE)
        success &= install_dependencies(args.include_llama)

    elif args.command == 'check':
        colored_print("\n🔍 Checking system...", Colors.BLUE)
        check_system_requirements()

    elif args.command == 'tools':
        colored_print("\n🔧 Checking tools...", Colors.BLUE)
        check_security_tools()

    elif args.command == 'all':
        colored_print("\n🚀 Complete setup and test...", Colors.BLUE)
        create_directories()
        setup_environment()
        success &= install_dependencies(include_llama=True)
        check_system_requirements()
        check_security_tools()
        success &= run_full_test()
        success &= setup_llama()
        success &= test_llama()

    # Final status
    colored_print("\n" + "=" * 60, Colors.CYAN)
    if success:
        colored_print("🎉 All operations completed successfully!", Colors.GREEN)
        colored_print("\nNext steps:", Colors.CYAN)
        colored_print("1. Configure API keys in .env file", Colors.WHITE)
        colored_print(
            "2. Launch dashboard: python main.py dashboard", Colors.WHITE)
        colored_print(
            "3. Or run CLI: python main.py scan --target example.com", Colors.WHITE)
    else:
        colored_print(
            "⚠️ Some operations failed. Check the output above.", Colors.YELLOW)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        colored_print("\n\n⏹️ Operation cancelled by user", Colors.YELLOW)
        sys.exit(1)
    except Exception as e:
        colored_print(f"\n❌ Unexpected error: {e}", Colors.RED)
        sys.exit(1)
