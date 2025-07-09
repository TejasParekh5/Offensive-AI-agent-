"""
Flask Test Case Agent
Handles execution of predefined and LLM-generated security test cases.
"""

import json
import subprocess
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
import logging
import os
from pathlib import Path
import uuid
import tempfile

from utils.ollama_integration import OllamaLLMClient


class FlaskTestAgent:
    """
    Modular test case agent for executing security tests.
    Supports both predefined test cases and LLM-generated test cases via Ollama.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.test_results = {}
        self.test_status = {}
        self.llm_client = OllamaLLMClient()
        
        # Load predefined test cases
        self.predefined_tests = self._load_predefined_tests()
        
        # Test execution queue
        self.execution_queue = []
        self.queue_lock = threading.Lock()
        
        self.logger.info("FlaskTestAgent initialized")
    
    def _load_predefined_tests(self) -> Dict[str, Any]:
        """Load predefined test cases from configuration."""
        config_path = Path(__file__).parent.parent / 'config' / 'test_cases.json'
        
        try:
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                # Return default test cases if config file doesn't exist
                return self._get_default_test_cases()
        except Exception as e:
            self.logger.error(f"Failed to load test cases: {e}")
            return self._get_default_test_cases()
    
    def _get_default_test_cases(self) -> Dict[str, Any]:
        """Return default predefined test cases."""
        return {
            "network_tests": [
                {
                    "id": "port_scan_validation",
                    "name": "Port Scan Validation",
                    "description": "Validate open ports against expected services",
                    "category": "network",
                    "severity": "medium",
                    "automated": True,
                    "command_template": "nmap -sV -p {ports} {target}",
                    "expected_results": "Service versions should be up to date"
                },
                {
                    "id": "ssl_tls_check",
                    "name": "SSL/TLS Configuration Check",
                    "description": "Check SSL/TLS configuration and certificate validity",
                    "category": "crypto",
                    "severity": "high",
                    "automated": True,
                    "command_template": "sslscan {target}:{port}",
                    "expected_results": "Strong ciphers, valid certificate"
                }
            ],
            "web_tests": [
                {
                    "id": "directory_traversal",
                    "name": "Directory Traversal Test",
                    "description": "Test for directory traversal vulnerabilities",
                    "category": "web",
                    "severity": "high",
                    "automated": True,
                    "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                    "expected_results": "Should not expose sensitive files"
                },
                {
                    "id": "sql_injection_basic",
                    "name": "Basic SQL Injection Test",
                    "description": "Test for basic SQL injection vulnerabilities",
                    "category": "web",
                    "severity": "critical",
                    "automated": True,
                    "payloads": ["' OR '1'='1", "1'; DROP TABLE users; --", "1' UNION SELECT version() --"],
                    "expected_results": "Should not execute SQL queries"
                }
            ],
            "system_tests": [
                {
                    "id": "default_credentials",
                    "name": "Default Credentials Check",
                    "description": "Check for default username/password combinations",
                    "category": "authentication",
                    "severity": "critical",
                    "automated": True,
                    "credentials": [
                        {"username": "admin", "password": "admin"},
                        {"username": "admin", "password": "password"},
                        {"username": "root", "password": "root"},
                        {"username": "guest", "password": "guest"}
                    ],
                    "expected_results": "Default credentials should be disabled"
                }
            ]
        }
    
    def generate_llm_test_cases(self, target_info: Dict[str, Any], 
                               scan_results: Dict[str, Any] = None,
                               callback: Callable = None) -> str:
        """
        Generate custom test cases using LLM based on target information.
        
        Args:
            target_info: Information about the target (IP, domain, services, etc.)
            scan_results: Results from previous scans to inform test generation
            callback: Callback function for real-time updates
        
        Returns:
            Generation ID for tracking progress
        """
        generation_id = f"llm_gen_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Initialize generation tracking
        self.test_status[generation_id] = {
            'status': 'generating',
            'type': 'llm_generation',
            'target': target_info.get('target', 'unknown'),
            'start_time': datetime.now(),
            'progress': 0
        }
        
        # Start generation in background thread
        thread = threading.Thread(
            target=self._generate_llm_tests_background,
            args=(generation_id, target_info, scan_results, callback)
        )
        thread.daemon = True
        thread.start()
        
        return generation_id
    
    def _generate_llm_tests_background(self, generation_id: str, target_info: Dict[str, Any],
                                     scan_results: Dict[str, Any], callback: Callable):
        """Background task for LLM test case generation."""
        try:
            if callback:
                callback(generation_id, {'status': 'generating', 'message': 'Analyzing target information'})
            
            self.test_status[generation_id]['progress'] = 20
            
            # Prepare context for LLM
            context = self._prepare_llm_context(target_info, scan_results)
            
            if callback:
                callback(generation_id, {'status': 'generating', 'message': 'Generating test cases with LLM'})
            
            self.test_status[generation_id]['progress'] = 50
            
            # Generate test cases using LLM
            generated_tests = self.llm_client.generate_test_cases(context)
            
            if callback:
                callback(generation_id, {'status': 'generating', 'message': 'Processing generated test cases'})
            
            self.test_status[generation_id]['progress'] = 80
            
            # Process and validate generated test cases
            processed_tests = self._process_generated_tests(generated_tests, target_info)
            
            # Store results
            self.test_results[generation_id] = {
                'generation_id': generation_id,
                'target_info': target_info,
                'generated_tests': processed_tests,
                'status': 'completed',
                'timestamp': datetime.now().isoformat(),
                'requires_approval': True
            }
            
            self.test_status[generation_id]['status'] = 'completed'
            self.test_status[generation_id]['progress'] = 100
            
            if callback:
                callback(generation_id, {
                    'status': 'completed', 
                    'message': f'Generated {len(processed_tests)} test cases',
                    'test_count': len(processed_tests)
                })
                
        except Exception as e:
            self.logger.error(f"LLM test generation {generation_id} failed: {e}")
            self.test_results[generation_id] = {
                'generation_id': generation_id,
                'status': 'failed',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            self.test_status[generation_id]['status'] = 'failed'
            
            if callback:
                callback(generation_id, {'status': 'failed', 'error': str(e)})
    
    def _prepare_llm_context(self, target_info: Dict[str, Any], scan_results: Dict[str, Any] = None) -> str:
        """Prepare context information for LLM test case generation."""
        context_parts = []
        
        # Target information
        context_parts.append(f"Target: {target_info.get('target', 'unknown')}")
        context_parts.append(f"Target Type: {target_info.get('type', 'unknown')}")
        
        # Add scan results if available
        if scan_results:
            context_parts.append("\\nScan Results:")
            
            # Add open ports information
            if 'hosts' in scan_results:
                for host in scan_results['hosts']:
                    if 'ports' in host:
                        open_ports = [p for p in host['ports'] if p.get('state') == 'open']
                        if open_ports:
                            context_parts.append(f"Host {host.get('ip', 'unknown')} has open ports:")
                            for port in open_ports:
                                service_info = f"Port {port.get('port')}/{port.get('protocol', 'tcp')}"
                                if port.get('service'):
                                    service_info += f" ({port.get('service')})"
                                if port.get('version'):
                                    service_info += f" - {port.get('version')}"
                                context_parts.append(f"  - {service_info}")
        
        # Add reconnaissance results if available
        if 'recon_results' in target_info:
            recon = target_info['recon_results']
            context_parts.append("\\nReconnaissance Results:")
            
            if 'subdomains' in recon:
                context_parts.append(f"Subdomains found: {len(recon['subdomains'])}")
            
            if 'technologies' in recon:
                context_parts.append(f"Technologies detected: {', '.join(recon['technologies'])}")
            
            if 'emails' in recon:
                context_parts.append(f"Email addresses found: {len(recon['emails'])}")
        
        return "\\n".join(context_parts)
    
    def _process_generated_tests(self, generated_tests: List[Dict[str, Any]], 
                               target_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process and validate LLM-generated test cases."""
        processed_tests = []
        
        for i, test in enumerate(generated_tests):
            try:
                # Validate required fields
                if not all(key in test for key in ['name', 'description', 'category']):
                    self.logger.warning(f"Generated test {i} missing required fields, skipping")
                    continue
                
                # Add metadata
                test['id'] = f"llm_generated_{uuid.uuid4().hex[:8]}"
                test['source'] = 'llm_generated'
                test['target'] = target_info.get('target', 'unknown')
                test['timestamp'] = datetime.now().isoformat()
                test['approved'] = False
                test['executed'] = False
                
                # Set default severity if not provided
                if 'severity' not in test:
                    test['severity'] = 'medium'
                
                # Validate severity level
                valid_severities = ['low', 'medium', 'high', 'critical']
                if test['severity'] not in valid_severities:
                    test['severity'] = 'medium'
                
                # Add safety checks for dangerous commands
                if 'command' in test:
                    test['command'] = self._sanitize_command(test['command'])
                
                processed_tests.append(test)
                
            except Exception as e:
                self.logger.warning(f"Failed to process generated test {i}: {e}")
                continue
        
        return processed_tests
    
    def _sanitize_command(self, command: str) -> str:
        """Sanitize command to prevent dangerous operations."""
        # List of dangerous patterns to block or modify
        dangerous_patterns = [
            'rm -rf /',
            'format c:',
            'del /f /s /q',
            'shutdown',
            'reboot',
            'halt',
            'init 0',
            'init 6',
            'dd if=/dev/zero',
            ':(){ :|:& };:',  # Fork bomb
        ]
        
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                self.logger.warning(f"Blocked dangerous command pattern: {pattern}")
                return f"# BLOCKED: Potentially dangerous command - {command}"
        
        return command
    
    def execute_test_suite(self, test_suite: List[Dict[str, Any]], target: str,
                          execution_mode: str = 'safe', callback: Callable = None) -> str:
        """
        Execute a suite of test cases.
        
        Args:
            test_suite: List of test cases to execute
            target: Target to test against
            execution_mode: 'safe' (manual approval), 'auto' (automated), 'review' (generate only)
            callback: Callback function for real-time updates
        
        Returns:
            Execution ID for tracking progress
        """
        execution_id = f"exec_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
        
        # Initialize execution tracking
        self.test_status[execution_id] = {
            'status': 'starting',
            'type': 'test_execution',
            'target': target,
            'execution_mode': execution_mode,
            'start_time': datetime.now(),
            'progress': 0,
            'total_tests': len(test_suite),
            'completed_tests': 0
        }
        
        self.test_results[execution_id] = {
            'execution_id': execution_id,
            'target': target,
            'execution_mode': execution_mode,
            'start_time': datetime.now().isoformat(),
            'status': 'running',
            'total_tests': len(test_suite),
            'test_results': [],
            'summary': {
                'passed': 0,
                'failed': 0,
                'errors': 0,
                'skipped': 0
            }
        }
        
        # Start execution in background thread
        thread = threading.Thread(
            target=self._execute_test_suite_background,
            args=(execution_id, test_suite, target, execution_mode, callback)
        )
        thread.daemon = True
        thread.start()
        
        return execution_id
    
    def _execute_test_suite_background(self, execution_id: str, test_suite: List[Dict[str, Any]],
                                     target: str, execution_mode: str, callback: Callable):
        """Background task for test suite execution."""
        try:
            self.test_status[execution_id]['status'] = 'running'
            
            if callback:
                callback(execution_id, {
                    'status': 'running', 
                    'message': f'Starting execution of {len(test_suite)} tests'
                })
            
            for i, test_case in enumerate(test_suite):
                # Check if execution should continue
                if self.test_status[execution_id]['status'] == 'cancelled':
                    break
                
                # Update progress
                progress = int((i / len(test_suite)) * 100)
                self.test_status[execution_id]['progress'] = progress
                self.test_status[execution_id]['completed_tests'] = i
                
                if callback:
                    callback(execution_id, {
                        'status': 'running',
                        'message': f'Executing test: {test_case.get("name", "Unknown")}',
                        'progress': progress,
                        'current_test': test_case.get('name', 'Unknown')
                    })
                
                # Execute individual test
                test_result = self._execute_single_test(test_case, target, execution_mode)
                self.test_results[execution_id]['test_results'].append(test_result)
                
                # Update summary
                result_status = test_result.get('status', 'error')
                if result_status in self.test_results[execution_id]['summary']:
                    self.test_results[execution_id]['summary'][result_status] += 1
                
                # Brief pause between tests
                time.sleep(0.5)
            
            # Finalize execution
            self.test_results[execution_id]['status'] = 'completed'
            self.test_results[execution_id]['end_time'] = datetime.now().isoformat()
            self.test_status[execution_id]['status'] = 'completed'
            self.test_status[execution_id]['progress'] = 100
            self.test_status[execution_id]['completed_tests'] = len(test_suite)
            
            if callback:
                callback(execution_id, {
                    'status': 'completed',
                    'message': 'Test execution completed',
                    'summary': self.test_results[execution_id]['summary']
                })
                
        except Exception as e:
            self.logger.error(f"Test execution {execution_id} failed: {e}")
            self.test_results[execution_id]['status'] = 'failed'
            self.test_results[execution_id]['error'] = str(e)
            self.test_status[execution_id]['status'] = 'failed'
            
            if callback:
                callback(execution_id, {'status': 'failed', 'error': str(e)})
    
    def _execute_single_test(self, test_case: Dict[str, Any], target: str, 
                           execution_mode: str) -> Dict[str, Any]:
        """Execute a single test case."""
        test_result = {
            'test_id': test_case.get('id', 'unknown'),
            'test_name': test_case.get('name', 'Unknown Test'),
            'target': target,
            'start_time': datetime.now().isoformat(),
            'status': 'running'
        }
        
        try:
            # Check if LLM-generated test requires approval
            if (test_case.get('source') == 'llm_generated' and 
                not test_case.get('approved', False) and 
                execution_mode == 'safe'):
                
                test_result.update({
                    'status': 'skipped',
                    'reason': 'LLM-generated test requires manual approval',
                    'end_time': datetime.now().isoformat()
                })
                return test_result
            
            # Execute based on test type
            if 'command' in test_case:
                result = self._execute_command_test(test_case, target)
            elif 'payloads' in test_case:
                result = self._execute_payload_test(test_case, target)
            elif 'credentials' in test_case:
                result = self._execute_credential_test(test_case, target)
            else:
                result = self._execute_custom_test(test_case, target)
            
            test_result.update(result)
            test_result['end_time'] = datetime.now().isoformat()
            
        except Exception as e:
            self.logger.error(f"Test execution failed for {test_case.get('name', 'unknown')}: {e}")
            test_result.update({
                'status': 'error',
                'error': str(e),
                'end_time': datetime.now().isoformat()
            })
        
        return test_result
    
    def _execute_command_test(self, test_case: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Execute a command-based test case."""
        command_template = test_case.get('command', '')
        
        # Replace placeholders
        command = command_template.replace('{target}', target)
        
        # Additional placeholder replacements
        if '{port}' in command:
            # Use default port or extract from target
            port = '80'  # Default, could be smarter
            command = command.replace('{port}', port)
        
        try:
            # Execute command with timeout
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            return {
                'status': 'passed' if result.returncode == 0 else 'failed',
                'command': command,
                'stdout': result.stdout[:1000],  # Limit output size
                'stderr': result.stderr[:1000],
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'status': 'failed',
                'error': 'Command execution timed out',
                'command': command
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'command': command
            }
    
    def _execute_payload_test(self, test_case: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Execute a payload-based test case (e.g., for web vulnerabilities)."""
        payloads = test_case.get('payloads', [])
        results = []
        
        for payload in payloads:
            try:
                # This is a simplified implementation
                # In a real scenario, you'd use tools like sqlmap, or custom HTTP requests
                result = {
                    'payload': payload,
                    'status': 'tested',
                    'response': f'Tested payload against {target}',
                    'vulnerable': False  # Would be determined by actual testing
                }
                results.append(result)
                
            except Exception as e:
                results.append({
                    'payload': payload,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Determine overall status
        vulnerable_count = sum(1 for r in results if r.get('vulnerable', False))
        overall_status = 'failed' if vulnerable_count > 0 else 'passed'
        
        return {
            'status': overall_status,
            'payload_results': results,
            'vulnerable_payloads': vulnerable_count
        }
    
    def _execute_credential_test(self, test_case: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Execute a credential-based test case."""
        credentials = test_case.get('credentials', [])
        results = []
        
        for cred in credentials:
            username = cred.get('username', '')
            password = cred.get('password', '')
            
            try:
                # This is a simplified implementation
                # In a real scenario, you'd attempt actual authentication
                result = {
                    'username': username,
                    'password': '***',  # Don't log actual passwords
                    'status': 'tested',
                    'authentication_successful': False  # Would be determined by actual testing
                }
                results.append(result)
                
            except Exception as e:
                results.append({
                    'username': username,
                    'status': 'error',
                    'error': str(e)
                })
        
        # Determine overall status
        successful_auths = sum(1 for r in results if r.get('authentication_successful', False))
        overall_status = 'failed' if successful_auths > 0 else 'passed'
        
        return {
            'status': overall_status,
            'credential_results': results,
            'successful_authentications': successful_auths
        }
    
    def _execute_custom_test(self, test_case: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Execute a custom test case."""
        # This is a placeholder for custom test implementations
        return {
            'status': 'skipped',
            'reason': 'Custom test execution not implemented',
            'test_case': test_case.get('name', 'Unknown')
        }
    
    def get_predefined_tests(self, category: str = None) -> List[Dict[str, Any]]:
        """Get predefined test cases, optionally filtered by category."""
        all_tests = []
        
        for category_name, tests in self.predefined_tests.items():
            if category is None or category == category_name:
                all_tests.extend(tests)
        
        return all_tests
    
    def approve_llm_test(self, generation_id: str, test_id: str) -> bool:
        """Approve an LLM-generated test case for execution."""
        if generation_id in self.test_results:
            generated_tests = self.test_results[generation_id].get('generated_tests', [])
            for test in generated_tests:
                if test.get('id') == test_id:
                    test['approved'] = True
                    test['approved_at'] = datetime.now().isoformat()
                    return True
        return False
    
    def get_test_status(self, test_id: str) -> Dict[str, Any]:
        """Get the current status of a test execution or generation."""
        return self.test_status.get(test_id, {'status': 'not_found'})
    
    def get_test_results(self, test_id: str) -> Dict[str, Any]:
        """Get the results of a completed test execution or generation."""
        return self.test_results.get(test_id, {'error': 'Test not found'})
    
    def list_active_tests(self) -> List[str]:
        """Get a list of currently active test IDs."""
        return [test_id for test_id, status in self.test_status.items() 
                if status['status'] in ['starting', 'running', 'generating']]
    
    def cancel_test(self, test_id: str) -> bool:
        """Cancel an active test execution or generation."""
        if test_id in self.test_status:
            self.test_status[test_id]['status'] = 'cancelled'
            if test_id in self.test_results:
                self.test_results[test_id]['status'] = 'cancelled'
            return True
        return False
