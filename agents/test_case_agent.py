import asyncio
import json
import logging
import subprocess
import requests
import base64
import socket
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor
import re
import os
from datetime import datetime

from utils.helpers import get_env_var, safe_json_dumps, load_config
from utils.validators import is_valid_ip
from utils.llama_integration import get_llama_instance


class TestCaseAgent:
    """Test Case Agent for executing predefined and LLM-generated security test cases."""

    def __init__(self):
        self.test_cases_config = load_config('./config/test_cases.json')
        self.test_cases = self.test_cases_config.get('test_cases', [])
        self.llm_prompts = self.test_cases_config.get('llm_prompts', {})

        # LLM API configuration
        self.openai_api_key = get_env_var('OPENAI_API_KEY')
        self.anthropic_api_key = get_env_var('ANTHROPIC_API_KEY')

        self.results = {}
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def execute_test_cases(self, target: str, session_id: str,
                                 recon_data: Dict = None,
                                 scan_data: Dict = None,
                                 approved_llm_cases: List[Dict] = None) -> Dict[str, Any]:
        """
        Execute predefined test cases and approved LLM-generated test cases.

        Args:
            target: Target IP or domain
            session_id: Session identifier
            recon_data: Results from reconnaissance phase
            scan_data: Results from scanning phase
            approved_llm_cases: List of approved LLM-generated test cases

        Returns:
            Dictionary containing all test results
        """
        logging.info(f"Starting test case execution for target: {target}")

        self.results = {
            'target': target,
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'predefined_results': [],
            'llm_results': [],
            'summary': {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0
            }
        }

        # Execute predefined test cases
        if scan_data and scan_data.get('open_ports'):
            await self._execute_predefined_tests(target, scan_data)

        # Execute approved LLM test cases
        if approved_llm_cases:
            await self._execute_llm_tests(target, approved_llm_cases)

        # Generate summary
        self._generate_summary()

        logging.info(f"Test case execution completed for {target}")
        return self.results

    async def generate_llm_test_cases(self, recon_data: Dict, scan_data: Dict) -> List[Dict]:
        """
        Generate test cases using LLM based on recon and scan results.

        Args:
            recon_data: Reconnaissance results
            scan_data: Scan results

        Returns:
            List of LLM-generated test case dictionaries
        """
        logging.info("Generating LLM test cases")

        try:
            # Prepare context for LLM
            context = self._prepare_llm_context(recon_data, scan_data)

            # Try Llama first (local model), then fall back to API-based models
            try:
                llama = get_llama_instance()
                if llama.is_available():
                    logging.info("Using Llama 3.1 8B for test case generation")
                    target_info = {
                        'target': scan_data.get('target', ''),
                        'target_type': 'domain' if not is_valid_ip(scan_data.get('target', '')) else 'ip'
                    }
                    test_cases = llama.generate_test_cases(
                        target_info, scan_data.get('open_ports', []))
                else:
                    raise Exception("Llama model not available")
            except Exception as llama_error:
                logging.warning(
                    f"Llama generation failed: {llama_error}, falling back to API models")

                # Generate test cases using available LLM API
                if self.openai_api_key:
                    test_cases = await self._generate_with_openai(context)
                elif self.anthropic_api_key:
                    test_cases = await self._generate_with_anthropic(context)
                else:
                    logging.warning(
                        "No LLM API key available for test case generation")
                    return []

            # Validate and format test cases
            validated_cases = self._validate_llm_test_cases(test_cases)

            logging.info(f"Generated {len(validated_cases)} LLM test cases")
            return validated_cases

        except Exception as e:
            logging.error(f"Error generating LLM test cases: {e}")
            return []

    def _prepare_llm_context(self, recon_data: Dict, scan_data: Dict) -> str:
        """Prepare context string for LLM prompt."""
        context_parts = []

        # Add recon information
        if recon_data:
            context_parts.append("RECONNAISSANCE DATA:")
            if recon_data.get('subdomains'):
                context_parts.append(
                    f"- Subdomains found: {len(recon_data['subdomains'])}")
            if recon_data.get('dns_records'):
                context_parts.append(
                    f"- DNS records: {list(recon_data['dns_records'].keys())}")
            if recon_data.get('technologies'):
                tech_list = [tech.get('name', '')
                             for tech in recon_data['technologies']]
                context_parts.append(f"- Technologies: {', '.join(tech_list)}")
            if recon_data.get('emails'):
                context_parts.append(
                    f"- Email addresses found: {len(recon_data['emails'])}")

        # Add scan information
        if scan_data:
            context_parts.append("\nSCAN DATA:")
            if scan_data.get('open_ports'):
                ports = [str(port['port']) for port in scan_data['open_ports']]
                context_parts.append(f"- Open ports: {', '.join(ports)}")

            if scan_data.get('services'):
                services = {}
                for service in scan_data['services']:
                    port = service['port']
                    svc_name = service['service']
                    services[port] = svc_name

                context_parts.append("- Services detected:")
                for port, service in services.items():
                    context_parts.append(f"  * Port {port}: {service}")

            if scan_data.get('vulnerabilities'):
                context_parts.append(
                    f"- Vulnerabilities found: {len(scan_data['vulnerabilities'])}")
                for vuln in scan_data['vulnerabilities'][:5]:  # Limit to first 5
                    context_parts.append(
                        f"  * {vuln.get('description', '')[:100]}")

        return '\n'.join(context_parts)

    async def _generate_with_openai(self, context: str) -> List[Dict]:
        """Generate test cases using OpenAI API."""
        try:
            import openai

            client = openai.OpenAI(api_key=self.openai_api_key)

            prompt = self.llm_prompts.get('generate_test_cases', '').format(
                recon_data=context.split('SCAN DATA:')[
                    0] if 'SCAN DATA:' in context else context,
                scan_data=context.split('SCAN DATA:')[
                    1] if 'SCAN DATA:' in context else ''
            )

            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Generate specific, actionable penetration test cases in JSON format."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2000,
                temperature=0.7
            )

            content = response.choices[0].message.content

            # Extract JSON from response
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                test_cases_json = json_match.group(0)
                return json.loads(test_cases_json)
            else:
                logging.warning("Could not extract JSON from OpenAI response")
                return []

        except Exception as e:
            logging.error(f"Error with OpenAI API: {e}")
            return []

    async def _generate_with_anthropic(self, context: str) -> List[Dict]:
        """Generate test cases using Anthropic API."""
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.anthropic_api_key)

            prompt = self.llm_prompts.get('generate_test_cases', '').format(
                recon_data=context.split('SCAN DATA:')[
                    0] if 'SCAN DATA:' in context else context,
                scan_data=context.split('SCAN DATA:')[
                    1] if 'SCAN DATA:' in context else ''
            )

            response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            content = response.content[0].text

            # Extract JSON from response
            json_match = re.search(r'\[.*\]', content, re.DOTALL)
            if json_match:
                test_cases_json = json_match.group(0)
                return json.loads(test_cases_json)
            else:
                logging.warning(
                    "Could not extract JSON from Anthropic response")
                return []

        except Exception as e:
            logging.error(f"Error with Anthropic API: {e}")
            return []

    def _validate_llm_test_cases(self, test_cases: List[Dict]) -> List[Dict]:
        """Validate and format LLM-generated test cases."""
        validated_cases = []

        for case in test_cases:
            if isinstance(case, dict):
                # Ensure required fields
                validated_case = {
                    'id': case.get('id', f"LLM_{len(validated_cases) + 1}"),
                    'name': case.get('name', case.get('Test Case Name', 'Unknown')),
                    'category': case.get('category', case.get('Category', 'Custom')),
                    'severity': case.get('severity', case.get('Severity', 'Medium')).lower(),
                    'description': case.get('description', case.get('Description', '')),
                    'methodology': case.get('methodology', case.get('Specific commands or methodology', '')),
                    'expected_outcomes': case.get('expected_outcomes', case.get('Expected outcomes', '')),
                    'type': 'llm_generated',
                    'approved': False,
                    'executed': False
                }

                validated_cases.append(validated_case)

        return validated_cases

    async def _execute_predefined_tests(self, target: str, scan_data: Dict):
        """Execute predefined test cases based on scan results."""
        logging.info("Executing predefined test cases")

        open_ports = {port['port']                      : port for port in scan_data.get('open_ports', [])}
        services = {svc['port']: svc['service']
                    for svc in scan_data.get('services', [])}

        applicable_tests = []

        # Filter test cases based on scan results
        for test_case in self.test_cases:
            if self._is_test_applicable(test_case, open_ports, services):
                applicable_tests.append(test_case)

        logging.info(
            f"Found {len(applicable_tests)} applicable predefined test cases")

        # Execute tests concurrently
        tasks = []
        for test_case in applicable_tests:
            tasks.append(self._execute_single_test(
                target, test_case, open_ports, services))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                self.results['predefined_results'].append(result)

    def _is_test_applicable(self, test_case: Dict, open_ports: Dict, services: Dict) -> bool:
        """Check if a test case is applicable based on scan results."""
        conditions = test_case.get('conditions', {})

        # Check port conditions
        required_ports = conditions.get('ports', [])
        if required_ports:
            if not any(port in open_ports for port in required_ports):
                return False

        # Check service conditions
        required_services = conditions.get('services', [])
        if required_services:
            detected_services = list(services.values())
            if not any(svc in detected_services for svc in required_services):
                return False

        return True

    async def _execute_single_test(self, target: str, test_case: Dict,
                                   open_ports: Dict, services: Dict) -> Dict:
        """Execute a single test case."""
        test_id = test_case.get('id', 'unknown')
        test_name = test_case.get('name', 'Unknown Test')
        category = test_case.get('category', 'Unknown')
        severity = test_case.get('severity', 'Medium')

        logging.info(f"Executing test case: {test_name} ({test_id})")

        result = {
            'test_id': test_id,
            'test_name': test_name,
            'category': category,
            'severity': severity,
            'status': 'failed',
            'details': '',
            'evidence': [],
            'timestamp': datetime.now().isoformat()
        }

        try:
            # Execute test based on category
            if category.lower() == 'authentication':
                await self._test_authentication(target, test_case, result, open_ports, services)
            elif category.lower() == 'web security':
                await self._test_web_security(target, test_case, result, open_ports, services)
            elif category.lower() == 'information disclosure':
                await self._test_information_disclosure(target, test_case, result, open_ports, services)
            elif category.lower() == 'injection':
                await self._test_injection(target, test_case, result, open_ports, services)
            elif category.lower() == 'cryptography':
                await self._test_cryptography(target, test_case, result, open_ports, services)
            else:
                await self._test_generic(target, test_case, result, open_ports, services)

        except Exception as e:
            result['status'] = 'error'
            result['details'] = f"Test execution error: {str(e)}"
            logging.error(f"Error executing test {test_id}: {e}")

        return result

    async def _test_authentication(self, target: str, test_case: Dict, result: Dict,
                                   open_ports: Dict, services: Dict):
        """Execute authentication-related tests."""
        test_name = test_case.get('name', '')

        if 'ssh' in test_name.lower():
            await self._test_ssh_credentials(target, test_case, result, open_ports)
        elif 'ftp' in test_name.lower():
            await self._test_ftp_credentials(target, test_case, result, open_ports)
        elif 'web' in test_name.lower():
            await self._test_web_credentials(target, test_case, result, open_ports)
        elif 'snmp' in test_name.lower():
            await self._test_snmp_community(target, test_case, result, open_ports)
        elif 'smb' in test_name.lower():
            await self._test_smb_null_session(target, test_case, result, open_ports)
        else:
            result['status'] = 'skipped'
            result['details'] = 'Authentication test type not implemented'

    async def _test_ssh_credentials(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test SSH default credentials."""
        if 22 not in open_ports:
            result['status'] = 'skipped'
            result['details'] = 'SSH port not open'
            return

        credentials = test_case.get('credentials', [])
        successful_logins = []

        for username, password in credentials:
            try:
                # Use SSH client to test credentials
                cmd = [
                    'ssh', '-o', 'ConnectTimeout=5',
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'PasswordAuthentication=yes',
                    f'{username}@{target}', 'exit'
                ]

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    stdin=asyncio.subprocess.PIPE
                )

                # Send password
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(input=f'{password}\n'.encode()),
                    timeout=10
                )

                if process.returncode == 0:
                    successful_logins.append((username, password))
                    result['evidence'].append(
                        f"Successful SSH login: {username}:{password}")

            except Exception as e:
                logging.debug(
                    f"SSH test failed for {username}:{password} - {e}")

        if successful_logins:
            result['status'] = 'passed'
            result['details'] = f"Found {len(successful_logins)} working SSH credential(s)"
        else:
            result['status'] = 'failed'
            result['details'] = 'No default SSH credentials found'

    async def _test_ftp_credentials(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test FTP anonymous/default access."""
        if 21 not in open_ports:
            result['status'] = 'skipped'
            result['details'] = 'FTP port not open'
            return

        credentials = test_case.get('credentials', [])
        successful_logins = []

        for username, password in credentials:
            try:
                import ftplib

                ftp = ftplib.FTP()
                ftp.connect(target, 21, timeout=10)
                ftp.login(username, password)

                # Test if we can list directory
                files = ftp.nlst()
                successful_logins.append((username, password))
                result['evidence'].append(
                    f"Successful FTP login: {username}:{password}")
                result['evidence'].append(
                    f"Directory listing: {files[:10]}")  # First 10 files

                ftp.quit()

            except Exception as e:
                logging.debug(
                    f"FTP test failed for {username}:{password} - {e}")

        if successful_logins:
            result['status'] = 'passed'
            result['details'] = f"Found {len(successful_logins)} working FTP credential(s)"
        else:
            result['status'] = 'failed'
            result['details'] = 'No FTP anonymous/default access found'

    async def _test_web_credentials(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test web application default credentials."""
        web_ports = [port for port in [
            80, 443, 8080, 8443] if port in open_ports]

        if not web_ports:
            result['status'] = 'skipped'
            result['details'] = 'No web ports open'
            return

        paths = test_case.get('paths', ['/admin', '/login'])
        credentials = test_case.get('credentials', [])
        successful_logins = []

        for port in web_ports:
            protocol = 'https' if port in [443, 8443] else 'http'

            for path in paths:
                for username, password in credentials:
                    try:
                        url = f"{protocol}://{target}:{port}{path}"

                        # Try basic authentication
                        response = requests.get(url, auth=(
                            username, password), timeout=10, verify=False)

                        if response.status_code == 200 and 'login' not in response.text.lower():
                            successful_logins.append((url, username, password))
                            result['evidence'].append(
                                f"Successful web login: {url} - {username}:{password}")

                        # Try form-based authentication
                        if 'form' in response.text.lower():
                            login_data = {'username': username,
                                          'password': password}
                            post_response = requests.post(
                                url, data=login_data, timeout=10, verify=False)

                            if post_response.status_code == 200 and 'dashboard' in post_response.text.lower():
                                successful_logins.append(
                                    (url, username, password))
                                result['evidence'].append(
                                    f"Successful form login: {url} - {username}:{password}")

                    except Exception as e:
                        logging.debug(
                            f"Web auth test failed for {url} {username}:{password} - {e}")

        if successful_logins:
            result['status'] = 'passed'
            result['details'] = f"Found {len(successful_logins)} working web credential(s)"
        else:
            result['status'] = 'failed'
            result['details'] = 'No default web credentials found'

    async def _test_snmp_community(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test SNMP community strings."""
        if 161 not in open_ports:
            result['status'] = 'skipped'
            result['details'] = 'SNMP port not open'
            return

        community_strings = test_case.get(
            'community_strings', ['public', 'private'])
        successful_communities = []

        for community in community_strings:
            try:
                cmd = ['snmpwalk', '-v2c', '-c',
                       community, target, '1.3.6.1.2.1.1.1.0']

                result_proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(result_proc.communicate(), timeout=10)

                if result_proc.returncode == 0 and stdout:
                    successful_communities.append(community)
                    result['evidence'].append(
                        f"Valid SNMP community: {community}")
                    result['evidence'].append(
                        f"System info: {stdout.decode()[:200]}")

            except Exception as e:
                logging.debug(
                    f"SNMP test failed for community {community} - {e}")

        if successful_communities:
            result['status'] = 'passed'
            result['details'] = f"Found {len(successful_communities)} valid SNMP community string(s)"
        else:
            result['status'] = 'failed'
            result['details'] = 'No valid SNMP community strings found'

    async def _test_smb_null_session(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test SMB null session access."""
        smb_ports = [port for port in [139, 445] if port in open_ports]

        if not smb_ports:
            result['status'] = 'skipped'
            result['details'] = 'SMB ports not open'
            return

        try:
            # Use smbclient to test null session
            cmd = ['smbclient', '-L', target, '-N']

            result_proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result_proc.communicate(), timeout=15)

            if result_proc.returncode == 0 and 'Sharename' in stdout.decode():
                result['status'] = 'passed'
                result['details'] = 'SMB null session allowed'
                result['evidence'].append(f"SMB shares: {stdout.decode()}")
            else:
                result['status'] = 'failed'
                result['details'] = 'SMB null session not allowed'

        except Exception as e:
            result['status'] = 'error'
            result['details'] = f"SMB test error: {str(e)}"

    async def _test_web_security(self, target: str, test_case: Dict, result: Dict,
                                 open_ports: Dict, services: Dict):
        """Execute web security tests."""
        web_ports = [port for port in [
            80, 443, 8080, 8443] if port in open_ports]

        if not web_ports:
            result['status'] = 'skipped'
            result['details'] = 'No web ports open'
            return

        test_name = test_case.get('name', '')

        if 'header' in test_name.lower():
            await self._test_security_headers(target, test_case, result, web_ports)
        elif 'directory' in test_name.lower():
            await self._test_directory_listing(target, test_case, result, web_ports)
        else:
            result['status'] = 'skipped'
            result['details'] = 'Web security test type not implemented'

    async def _test_security_headers(self, target: str, test_case: Dict, result: Dict, web_ports: List[int]):
        """Test for missing security headers."""
        headers_to_check = test_case.get('headers_to_check', [])
        missing_headers = []

        for port in web_ports:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{target}:{port}/"

            try:
                response = requests.get(url, timeout=10, verify=False)

                for header in headers_to_check:
                    if header not in response.headers:
                        missing_headers.append((url, header))

            except Exception as e:
                logging.debug(f"Security header test failed for {url} - {e}")

        if missing_headers:
            result['status'] = 'passed'
            result['details'] = f"Found {len(missing_headers)} missing security header(s)"
            for url, header in missing_headers:
                result['evidence'].append(
                    f"Missing header '{header}' on {url}")
        else:
            result['status'] = 'failed'
            result['details'] = 'All security headers present'

    async def _test_directory_listing(self, target: str, test_case: Dict, result: Dict, web_ports: List[int]):
        """Test for directory listing vulnerabilities."""
        directories = test_case.get('directories', [])
        vulnerable_dirs = []

        for port in web_ports:
            protocol = 'https' if port in [443, 8443] else 'http'

            for directory in directories:
                url = f"{protocol}://{target}:{port}{directory}"

                try:
                    response = requests.get(url, timeout=10, verify=False)

                    if (response.status_code == 200 and
                        ('index of' in response.text.lower() or
                         'directory listing' in response.text.lower() or
                         '<pre>' in response.text.lower())):
                        vulnerable_dirs.append(url)

                except Exception as e:
                    logging.debug(
                        f"Directory listing test failed for {url} - {e}")

        if vulnerable_dirs:
            result['status'] = 'passed'
            result['details'] = f"Found {len(vulnerable_dirs)} directory listing(s)"
            for url in vulnerable_dirs:
                result['evidence'].append(f"Directory listing enabled: {url}")
        else:
            result['status'] = 'failed'
            result['details'] = 'No directory listings found'

    async def _test_information_disclosure(self, target: str, test_case: Dict, result: Dict,
                                           open_ports: Dict, services: Dict):
        """Execute information disclosure tests."""
        test_name = test_case.get('name', '')

        if 'database' in test_name.lower():
            await self._test_exposed_databases(target, test_case, result, open_ports)
        else:
            result['status'] = 'skipped'
            result['details'] = 'Information disclosure test type not implemented'

    async def _test_exposed_databases(self, target: str, test_case: Dict, result: Dict, open_ports: Dict):
        """Test for exposed database services."""
        db_ports = {
            3306: 'MySQL',
            5432: 'PostgreSQL',
            1433: 'MSSQL',
            27017: 'MongoDB',
            6379: 'Redis'
        }

        exposed_dbs = []

        for port, db_type in db_ports.items():
            if port in open_ports:
                try:
                    # Test if port is accessible
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    result_conn = sock.connect_ex((target, port))
                    sock.close()

                    if result_conn == 0:
                        exposed_dbs.append((port, db_type))

                except Exception as e:
                    logging.debug(
                        f"Database connectivity test failed for {port} - {e}")

        if exposed_dbs:
            result['status'] = 'passed'
            result['details'] = f"Found {len(exposed_dbs)} exposed database(s)"
            for port, db_type in exposed_dbs:
                result['evidence'].append(f"Exposed {db_type} on port {port}")
        else:
            result['status'] = 'failed'
            result['details'] = 'No exposed databases found'

    async def _test_injection(self, target: str, test_case: Dict, result: Dict,
                              open_ports: Dict, services: Dict):
        """Execute injection tests."""
        # Basic SQL injection test implementation
        result['status'] = 'skipped'
        result['details'] = 'Injection tests require manual implementation'

    async def _test_cryptography(self, target: str, test_case: Dict, result: Dict,
                                 open_ports: Dict, services: Dict):
        """Execute cryptography-related tests."""
        # SSL/TLS configuration test implementation
        result['status'] = 'skipped'
        result['details'] = 'Cryptography tests require specialized tools'

    async def _test_generic(self, target: str, test_case: Dict, result: Dict,
                            open_ports: Dict, services: Dict):
        """Execute generic test cases."""
        result['status'] = 'skipped'
        result['details'] = 'Generic test execution not implemented'

    async def _execute_llm_tests(self, target: str, approved_llm_cases: List[Dict]):
        """Execute approved LLM-generated test cases."""
        logging.info(
            f"Executing {len(approved_llm_cases)} approved LLM test cases")

        for test_case in approved_llm_cases:
            result = {
                'test_id': test_case.get('id', 'unknown'),
                'test_name': test_case.get('name', 'Unknown LLM Test'),
                'category': test_case.get('category', 'Custom'),
                'severity': test_case.get('severity', 'medium'),
                'status': 'manual_required',
                'details': test_case.get('methodology', ''),
                'evidence': [],
                'timestamp': datetime.now().isoformat(),
                'type': 'llm_generated'
            }

            # LLM test cases typically require manual execution
            # Store the methodology for manual review
            result['methodology'] = test_case.get('methodology', '')
            result['expected_outcomes'] = test_case.get(
                'expected_outcomes', '')

            self.results['llm_results'].append(result)

    def _generate_summary(self):
        """Generate test execution summary."""
        all_results = self.results['predefined_results'] + \
            self.results['llm_results']

        self.results['summary']['total_tests'] = len(all_results)

        for result in all_results:
            status = result.get('status', 'unknown')
            severity = result.get('severity', 'medium').lower()

            if status == 'passed':
                self.results['summary']['passed'] += 1

                # Count by severity
                if severity == 'critical':
                    self.results['summary']['critical_findings'] += 1
                elif severity == 'high':
                    self.results['summary']['high_findings'] += 1
                elif severity == 'medium':
                    self.results['summary']['medium_findings'] += 1
                elif severity == 'low':
                    self.results['summary']['low_findings'] += 1
            else:
                self.results['summary']['failed'] += 1

    def generate_report(self) -> str:
        """Generate a comprehensive test case execution report."""
        return safe_json_dumps(self.results, indent=2)
