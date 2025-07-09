"""
Multi-Agent Cybersecurity Automation System Package
"""

__version__ = "1.0.0"
__author__ = "Cybersecurity Team"
__description__ = "Automated security assessment system with intelligent agents"

# Import main components for easier access
from agents.recon_agent import ReconAgent
from agents.scanning_agent import ScanningAgent
from agents.test_case_agent import TestCaseAgent
from database.db_manager import DatabaseManager
from reports.report_generator import ReportGenerator

__all__ = [
    'ReconAgent',
    'ScanningAgent',
    'TestCaseAgent',
    'DatabaseManager',
    'ReportGenerator'
]
