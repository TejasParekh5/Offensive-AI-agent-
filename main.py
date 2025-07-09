#!/usr/bin/env python3
"""
Multi-Agent Cybersecurity Automation System
Main entry point for the application.
"""

from database.db_manager import DatabaseManager
from utils.helpers import setup_logging, get_env_var
import sys
import os
import argparse
import asyncio
import logging
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="Multi-Agent Cybersecurity Automation System"
    )

    parser.add_argument(
        'command',
        choices=['dashboard', 'scan', 'test', 'report', 'init'],
        help='Command to execute'
    )

    parser.add_argument(
        '--target',
        help='Target for scanning (domain or IP)'
    )

    parser.add_argument(
        '--config',
        default='./config/settings.json',
        help='Configuration file path'
    )

    parser.add_argument(
        '--output',
        default='./reports/output',
        help='Output directory for reports'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    args = parser.parse_args()

    # Setup logging
    log_level = 'DEBUG' if args.verbose else get_env_var('LOG_LEVEL', 'INFO')
    setup_logging(log_level=log_level)

    # Execute command
    if args.command == 'dashboard':
        run_dashboard()
    elif args.command == 'scan':
        if not args.target:
            print("Error: --target is required for scan command")
            sys.exit(1)
        asyncio.run(run_scan(args.target))
    elif args.command == 'test':
        if not args.target:
            print("Error: --target is required for test command")
            sys.exit(1)
        asyncio.run(run_test(args.target))
    elif args.command == 'report':
        run_report_generation(args.output)
    elif args.command == 'init':
        run_initialization()
    else:
        parser.print_help()


def run_dashboard():
    """Launch the Streamlit dashboard."""
    try:
        import streamlit.web.cli as stcli
        sys.argv = ["streamlit", "run", "dashboard.py"]
        stcli.main()
    except ImportError:
        print("Error: Streamlit not installed. Please install requirements.")
        sys.exit(1)
    except Exception as e:
        print(f"Error launching dashboard: {e}")
        sys.exit(1)


async def run_scan(target: str):
    """Run a standalone scan."""
    from agents.scanning_agent import ScanningAgent
    from utils.validators import validate_target
    from utils.helpers import generate_session_id

    # Validate target
    is_valid, target_type, normalized_target = validate_target(target)
    if not is_valid:
        print(f"Error: Invalid target '{target}'")
        sys.exit(1)

    print(f"Starting scan of {normalized_target} ({target_type})")

    try:
        # Initialize scanning agent
        scanner = ScanningAgent()

        # Generate session ID
        session_id = generate_session_id()

        # Perform scan
        results = await scanner.perform_scan(normalized_target, session_id)

        if results:
            print(f"Scan completed successfully!")
            print(f"Open ports: {len(results.get('open_ports', []))}")
            print(f"Services: {len(results.get('services', []))}")
            print(
                f"Vulnerabilities: {len(results.get('vulnerabilities', []))}")

            # Print open ports
            for port_info in results.get('open_ports', []):
                print(
                    f"  {port_info['port']}/{port_info.get('protocol', 'tcp')} - {port_info.get('service', 'unknown')}")
        else:
            print("Scan failed or returned no results")
            sys.exit(1)

    except Exception as e:
        print(f"Scan error: {e}")
        sys.exit(1)


async def run_test(target: str):
    """Run standalone security tests."""
    from agents.test_case_agent import TestCaseAgent
    from agents.scanning_agent import ScanningAgent
    from utils.validators import validate_target
    from utils.helpers import generate_session_id

    # Validate target
    is_valid, target_type, normalized_target = validate_target(target)
    if not is_valid:
        print(f"Error: Invalid target '{target}'")
        sys.exit(1)

    print(f"Starting security tests for {normalized_target}")

    try:
        # Generate session ID
        session_id = generate_session_id()

        # First, scan the target
        print("Performing initial scan...")
        scanner = ScanningAgent()
        scan_results = await scanner.perform_scan(normalized_target, session_id)

        if not scan_results:
            print("Initial scan failed")
            sys.exit(1)

        # Run security tests
        print("Executing security test cases...")
        test_agent = TestCaseAgent()
        test_results = await test_agent.execute_test_cases(
            normalized_target, session_id,
            scan_data=scan_results
        )

        if test_results:
            summary = test_results.get('summary', {})
            print(f"Tests completed!")
            print(f"Total tests: {summary.get('total_tests', 0)}")
            print(f"Passed (issues found): {summary.get('passed', 0)}")
            print(f"Failed (no issues): {summary.get('failed', 0)}")

            # Show findings
            findings = test_results.get('predefined_results', [])
            for finding in findings:
                if finding.get('status') == 'passed':
                    print(
                        f"  FINDING: {finding.get('test_name')} - {finding.get('severity', 'medium').upper()}")
        else:
            print("Test execution failed")
            sys.exit(1)

    except Exception as e:
        print(f"Test error: {e}")
        sys.exit(1)


def run_report_generation(output_dir: str):
    """Generate reports for recent assessments."""
    try:
        # Initialize database
        db = DatabaseManager()

        # Get recent completed sessions
        sessions = db.get_all_sessions()
        completed_sessions = [
            s for s in sessions if s.get('status') == 'completed']

        if not completed_sessions:
            print("No completed assessments found")
            return

        print(f"Found {len(completed_sessions)} completed assessments")

        # Generate reports for recent sessions
        from reports.report_generator import ReportGenerator
        report_gen = ReportGenerator(output_dir)

        for session in completed_sessions[:5]:  # Last 5 sessions
            session_id = session.get('session_id')
            target = session.get('target')

            print(f"Generating report for {target} ({session_id})")

            session_data = db.get_session_data(session_id)
            if session_data:
                generated_files = report_gen.generate_comprehensive_report(
                    session_data, ['json', 'html']
                )

                for format_name, file_path in generated_files.items():
                    print(f"  Generated {format_name.upper()}: {file_path}")

        print(f"Reports saved to: {output_dir}")

    except Exception as e:
        print(f"Report generation error: {e}")
        sys.exit(1)


def run_initialization():
    """Initialize the system and check configuration."""
    print("Initializing Multi-Agent Cybersecurity System...")

    try:
        # Check Python version
        if sys.version_info < (3, 8):
            print("Error: Python 3.8 or higher is required")
            sys.exit(1)

        print(f"✓ Python version: {sys.version.split()[0]}")

        # Initialize database
        print("Initializing database...")
        db = DatabaseManager()
        print("✓ Database initialized")

        # Check configuration files
        config_files = [
            './config/settings.json',
            './config/test_cases.json'
        ]

        for config_file in config_files:
            if os.path.exists(config_file):
                print(f"✓ Configuration file: {config_file}")
            else:
                print(f"✗ Missing configuration file: {config_file}")

        # Check environment variables
        env_vars = [
            'SHODAN_API_KEY',
            'OPENAI_API_KEY',
            'ANTHROPIC_API_KEY'
        ]

        print("\nEnvironment variables:")
        for var in env_vars:
            value = get_env_var(var)
            if value:
                print(f"✓ {var}: Set")
            else:
                print(f"⚠ {var}: Not set")

        # Create directories
        directories = [
            './logs',
            './reports/output',
            './database'
        ]

        print("\nCreating directories...")
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
            print(f"✓ {directory}")

        # Check tools availability (basic check)
        tools = ['nmap', 'python', 'pip']
        print("\nChecking tools:")

        for tool in tools:
            try:
                import shutil
                if shutil.which(tool):
                    print(f"✓ {tool}: Available")
                else:
                    print(f"⚠ {tool}: Not found in PATH")
            except:
                print(f"? {tool}: Could not check")

        print("\n🎉 System initialization completed!")
        print("\nNext steps:")
        print("1. Configure API keys in .env file")
        print("2. Install security tools (nmap, masscan, etc.)")
        print("3. Run: python main.py dashboard")

    except Exception as e:
        print(f"Initialization error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
