import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
import os


class DatabaseManager:
    """Manages SQLite database operations for the cybersecurity assessment system."""

    def __init__(self, db_path: str = "./database/security_assessment.db"):
        self.db_path = db_path
        self.ensure_directory_exists()
        self.init_database()

    def ensure_directory_exists(self):
        """Ensure the database directory exists."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    def init_database(self):
        """Initialize the database with required tables."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Assessment sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assessment_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT DEFAULT 'running',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Recon results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS recon_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    result_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES assessment_sessions(session_id)
                )
            ''')

            # Scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER,
                    service TEXT,
                    version TEXT,
                    state TEXT,
                    banner TEXT,
                    vulnerabilities TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES assessment_sessions(session_id)
                )
            ''')

            # Test case results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_case_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    test_case_id TEXT NOT NULL,
                    test_name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result TEXT,
                    evidence TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES assessment_sessions(session_id)
                )
            ''')

            # LLM generated test cases table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS llm_test_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    test_case_data TEXT NOT NULL,
                    approved BOOLEAN DEFAULT FALSE,
                    executed BOOLEAN DEFAULT FALSE,
                    result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES assessment_sessions(session_id)
                )
            ''')

            conn.commit()
            logging.info("Database initialized successfully")

    def create_session(self, session_id: str, target: str, target_type: str) -> bool:
        """Create a new assessment session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO assessment_sessions (session_id, target, target_type)
                    VALUES (?, ?, ?)
                ''', (session_id, target, target_type))
                conn.commit()
                logging.info(
                    f"Created session {session_id} for target {target}")
                return True
        except Exception as e:
            logging.error(f"Error creating session: {e}")
            return False

    def update_session_status(self, session_id: str, status: str) -> bool:
        """Update session status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE assessment_sessions 
                    SET status = ?, end_time = CURRENT_TIMESTAMP
                    WHERE session_id = ?
                ''', (status, session_id))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error updating session status: {e}")
            return False

    def store_recon_results(self, session_id: str, target: str, result_type: str, data: Dict) -> bool:
        """Store reconnaissance results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO recon_results (session_id, target, result_type, data)
                    VALUES (?, ?, ?, ?)
                ''', (session_id, target, result_type, json.dumps(data)))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing recon results: {e}")
            return False

    def store_scan_results(self, session_id: str, target: str, port: int, service: str,
                           version: str = None, state: str = None, banner: str = None,
                           vulnerabilities: List = None) -> bool:
        """Store scan results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                vuln_data = json.dumps(
                    vulnerabilities) if vulnerabilities else None
                cursor.execute('''
                    INSERT INTO scan_results (session_id, target, port, service, version, state, banner, vulnerabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session_id, target, port, service, version, state, banner, vuln_data))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing scan results: {e}")
            return False

    def store_test_case_result(self, session_id: str, test_case_id: str, test_name: str,
                               category: str, severity: str, status: str, result: str = None,
                               evidence: str = None) -> bool:
        """Store test case results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO test_case_results (session_id, test_case_id, test_name, category, severity, status, result, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session_id, test_case_id, test_name, category, severity, status, result, evidence))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing test case result: {e}")
            return False

    def store_llm_test_case(self, session_id: str, test_case_data: Dict) -> bool:
        """Store LLM generated test case."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO llm_test_cases (session_id, test_case_data)
                    VALUES (?, ?)
                ''', (session_id, json.dumps(test_case_data)))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error storing LLM test case: {e}")
            return False

    def get_session_data(self, session_id: str) -> Dict:
        """Get all data for a session."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                # Get session info
                cursor.execute(
                    'SELECT * FROM assessment_sessions WHERE session_id = ?', (session_id,))
                session = cursor.fetchone()

                if not session:
                    return {}

                # Get recon results
                cursor.execute(
                    'SELECT * FROM recon_results WHERE session_id = ?', (session_id,))
                recon_results = [dict(row) for row in cursor.fetchall()]

                # Get scan results
                cursor.execute(
                    'SELECT * FROM scan_results WHERE session_id = ?', (session_id,))
                scan_results = [dict(row) for row in cursor.fetchall()]

                # Get test case results
                cursor.execute(
                    'SELECT * FROM test_case_results WHERE session_id = ?', (session_id,))
                test_results = [dict(row) for row in cursor.fetchall()]

                # Get LLM test cases
                cursor.execute(
                    'SELECT * FROM llm_test_cases WHERE session_id = ?', (session_id,))
                llm_test_cases = [dict(row) for row in cursor.fetchall()]

                return {
                    'session': dict(session),
                    'recon_results': recon_results,
                    'scan_results': scan_results,
                    'test_results': test_results,
                    'llm_test_cases': llm_test_cases
                }
        except Exception as e:
            logging.error(f"Error getting session data: {e}")
            return {}

    def get_all_sessions(self) -> List[Dict]:
        """Get all assessment sessions."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT * FROM assessment_sessions ORDER BY created_at DESC')
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logging.error(f"Error getting sessions: {e}")
            return []

    def approve_llm_test_case(self, test_case_id: int) -> bool:
        """Approve an LLM generated test case."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE llm_test_cases SET approved = TRUE WHERE id = ?
                ''', (test_case_id,))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error approving test case: {e}")
            return False

    def update_llm_test_case_result(self, test_case_id: int, result: str) -> bool:
        """Update LLM test case execution result."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE llm_test_cases SET executed = TRUE, result = ? WHERE id = ?
                ''', (result, test_case_id))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Error updating test case result: {e}")
            return False

    def cleanup_old_sessions(self, days: int = 30) -> bool:
        """Clean up sessions older than specified days."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM assessment_sessions 
                    WHERE created_at < datetime('now', '-{} days')
                '''.format(days))
                conn.commit()
                logging.info(f"Cleaned up sessions older than {days} days")
                return True
        except Exception as e:
            logging.error(f"Error cleaning up sessions: {e}")
            return False
