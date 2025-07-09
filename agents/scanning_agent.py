import subprocess
import asyncio
import json
import logging
import ipaddress
import socket
from typing import Dict, List, Optional, Any, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import xml.etree.ElementTree as ET
import re
import os
from utils.helpers import get_env_var, safe_json_dumps, ProgressTracker
from utils.validators import is_valid_ip, validate_port_range, parse_nmap_output, parse_masscan_output


class ScanningAgent:
    """Scanning Agent for port scanning, service discovery, and vulnerability detection."""

    def __init__(self):
        self.nmap_path = get_env_var('NMAP_PATH', 'nmap')
        self.masscan_path = get_env_var('MASSCAN_PATH', 'masscan')
        self.rustscan_path = get_env_var('RUSTSCAN_PATH', 'rustscan')

        self.results = {}
        self.executor = ThreadPoolExecutor(max_workers=3)

    async def perform_scan(self, target: str, session_id: str,
                           port_range: str = "1-65535",
                           scan_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Perform comprehensive port scanning and service discovery.

        Args:
            target: IP address or hostname to scan
            session_id: Session identifier for tracking
            port_range: Port range to scan (default: 1-65535)
            scan_type: Type of scan (quick, standard, comprehensive)

        Returns:
            Dictionary containing all scan results
        """
        logging.info(f"Starting scan for target: {target}")

        self.results = {
            'target': target,
            'session_id': session_id,
            'timestamp': None,
            'scan_type': scan_type,
            'port_range': port_range,
            'open_ports': [],
            'services': [],
            'os_detection': {},
            'vulnerabilities': [],
            'banners': {},
            'ssl_info': {},
            'metadata': {}
        }

        # Resolve hostname to IP if needed
        target_ip = self._resolve_target(target)
        if not target_ip:
            logging.error(f"Could not resolve target: {target}")
            return self.results

        self.results['resolved_ip'] = target_ip

        # Select scanning strategy based on scan type
        if scan_type == "quick":
            await self._quick_scan(target_ip, "22,80,443,3389,21,25,53,110,135,139,445")
        elif scan_type == "standard":
            await self._standard_scan(target_ip, "1-1000")
        else:  # comprehensive
            await self._comprehensive_scan(target_ip, port_range)

        # Perform service detection on open ports
        if self.results['open_ports']:
            await self._service_detection(target_ip)
            await self._vulnerability_scan(target_ip)
            await self._banner_grabbing(target_ip)
            await self._ssl_analysis(target_ip)

        # Add metadata
        self.results['metadata'] = {
            'total_ports_scanned': self._count_ports_in_range(port_range),
            'open_ports_count': len(self.results['open_ports']),
            'services_detected': len(self.results['services']),
            'vulnerabilities_found': len(self.results['vulnerabilities']),
            'scan_duration': None  # Will be calculated by caller
        }

        logging.info(f"Scan completed for {target}")
        return self.results

    def _resolve_target(self, target: str) -> Optional[str]:
        """Resolve target to IP address."""
        if is_valid_ip(target):
            return target

        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            logging.error(f"Could not resolve hostname: {target}")
            return None

    def _count_ports_in_range(self, port_range: str) -> int:
        """Count total ports in the given range."""
        try:
            if port_range == "1-65535":
                return 65535
            elif '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return end - start + 1
            elif ',' in port_range:
                return len(port_range.split(','))
            else:
                return 1
        except:
            return 0

    async def _quick_scan(self, target: str, ports: str):
        """Perform quick scan on common ports."""
        logging.info(f"Performing quick scan on {target}")

        # Use Rustscan for speed if available
        if await self._is_tool_available(self.rustscan_path):
            await self._rustscan(target, ports)
        else:
            await self._nmap_scan(target, ports, ["-T4", "-F"])

    async def _standard_scan(self, target: str, ports: str):
        """Perform standard scan."""
        logging.info(f"Performing standard scan on {target}")

        # Use Masscan for initial discovery, then Nmap for service detection
        if await self._is_tool_available(self.masscan_path):
            open_ports = await self._masscan(target, ports)
            if open_ports:
                port_list = ",".join(map(str, open_ports))
                await self._nmap_scan(target, port_list, ["-sV", "-T4"])
        else:
            await self._nmap_scan(target, ports, ["-sV", "-T4"])

    async def _comprehensive_scan(self, target: str, ports: str):
        """Perform comprehensive scan with all features."""
        logging.info(f"Performing comprehensive scan on {target}")

        # Multi-stage scanning approach
        # Stage 1: Fast port discovery
        if await self._is_tool_available(self.masscan_path):
            open_ports = await self._masscan(target, ports)
            if open_ports:
                port_list = ",".join(map(str, open_ports))
                # Stage 2: Detailed scanning of open ports
                await self._nmap_scan(target, port_list, ["-sV", "-sC", "-O", "-A", "--script=vuln"])
            else:
                await self._nmap_scan(target, ports, ["-sV", "-sC", "-O", "-A"])
        else:
            await self._nmap_scan(target, ports, ["-sV", "-sC", "-O", "-A"])

    async def _rustscan(self, target: str, ports: str) -> List[int]:
        """Use Rustscan for fast port discovery."""
        try:
            cmd = [self.rustscan_path, "-a", target, "--accessible"]
            if ports and ports != "1-65535":
                cmd.extend(["-p", ports])

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)

            if result.returncode == 0:
                open_ports = self._parse_rustscan_output(stdout.decode())
                self.results['open_ports'].extend(open_ports)
                return [port['port'] for port in open_ports]
            else:
                logging.warning(f"Rustscan failed: {stderr.decode()}")
                return []

        except Exception as e:
            logging.error(f"Error running Rustscan: {e}")
            return []

    async def _masscan(self, target: str, ports: str) -> List[int]:
        """Use Masscan for fast port scanning."""
        try:
            cmd = [self.masscan_path, target, "-p",
                   ports, "--rate=1000", "--wait=0"]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=600)

            if result.returncode == 0:
                open_ports_data = parse_masscan_output(stdout.decode())
                self.results['open_ports'].extend(open_ports_data)
                return [port['port'] for port in open_ports_data]
            else:
                logging.warning(f"Masscan failed: {stderr.decode()}")
                return []

        except Exception as e:
            logging.error(f"Error running Masscan: {e}")
            return []

    async def _nmap_scan(self, target: str, ports: str, additional_args: List[str] = None):
        """Use Nmap for detailed port scanning and service detection."""
        try:
            cmd = [self.nmap_path, "-Pn"]

            if additional_args:
                cmd.extend(additional_args)

            if ports:
                cmd.extend(["-p", ports])

            cmd.extend(["-oX", "-", target])  # XML output to stdout

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=900)

            if result.returncode == 0:
                self._parse_nmap_xml_output(stdout.decode())
            else:
                logging.warning(f"Nmap failed: {stderr.decode()}")

        except Exception as e:
            logging.error(f"Error running Nmap: {e}")

    def _parse_rustscan_output(self, output: str) -> List[Dict]:
        """Parse Rustscan output."""
        ports = []
        lines = output.split('\n')

        for line in lines:
            # Rustscan output format: "Open 192.168.1.1:80"
            match = re.search(r'Open\s+[\d\.]+:(\d+)', line)
            if match:
                port_info = {
                    'port': int(match.group(1)),
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': 'unknown'
                }
                ports.append(port_info)

        return ports

    def _parse_nmap_xml_output(self, xml_output: str):
        """Parse Nmap XML output and extract detailed information."""
        try:
            root = ET.fromstring(xml_output)

            for host in root.findall('host'):
                # Extract host information
                address = host.find('address').get('addr')

                # Extract port information
                ports_elem = host.find('ports')
                if ports_elem is not None:
                    for port in ports_elem.findall('port'):
                        port_id = int(port.get('portid'))
                        protocol = port.get('protocol')

                        state_elem = port.find('state')
                        state = state_elem.get(
                            'state') if state_elem is not None else 'unknown'

                        service_elem = port.find('service')
                        service_name = 'unknown'
                        service_version = ''
                        service_product = ''

                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            service_version = service_elem.get('version', '')
                            service_product = service_elem.get('product', '')

                        port_info = {
                            'port': port_id,
                            'protocol': protocol,
                            'state': state,
                            'service': service_name,
                            'version': service_version,
                            'product': service_product
                        }

                        if state == 'open':
                            self.results['open_ports'].append(port_info)

                            # Extract service details
                            service_info = {
                                'port': port_id,
                                'service': service_name,
                                'version': f"{service_product} {service_version}".strip(),
                                'protocol': protocol
                            }
                            self.results['services'].append(service_info)

                        # Extract script results (vulnerabilities)
                        for script in port.findall('script'):
                            script_id = script.get('id')
                            script_output = script.get('output', '')

                            if 'vuln' in script_id or 'CVE' in script_output:
                                vuln_info = {
                                    'port': port_id,
                                    'script': script_id,
                                    # Truncate long outputs
                                    'description': script_output[:500],
                                    'severity': self._extract_severity_from_script(script_output)
                                }
                                self.results['vulnerabilities'].append(
                                    vuln_info)

                # Extract OS information
                os_elem = host.find('os')
                if os_elem is not None:
                    os_matches = []
                    for osmatch in os_elem.findall('osmatch'):
                        os_matches.append({
                            'name': osmatch.get('name'),
                            'accuracy': int(osmatch.get('accuracy', 0))
                        })

                    if os_matches:
                        self.results['os_detection'] = {
                            'matches': os_matches,
                            'best_match': max(os_matches, key=lambda x: x['accuracy'])
                        }

        except ET.ParseError as e:
            logging.error(f"Error parsing Nmap XML output: {e}")
        except Exception as e:
            logging.error(f"Error processing Nmap results: {e}")

    def _extract_severity_from_script(self, script_output: str) -> str:
        """Extract vulnerability severity from script output."""
        severity_keywords = {
            'critical': ['critical', 'exploit'],
            'high': ['high', 'dangerous', 'severe'],
            'medium': ['medium', 'moderate'],
            'low': ['low', 'minor'],
            'info': ['info', 'information']
        }

        script_lower = script_output.lower()

        for severity, keywords in severity_keywords.items():
            for keyword in keywords:
                if keyword in script_lower:
                    return severity

        return 'unknown'

    async def _service_detection(self, target: str):
        """Perform detailed service detection on open ports."""
        logging.info(f"Performing service detection on {target}")

        open_ports = [str(port['port']) for port in self.results['open_ports']]
        if not open_ports:
            return

        port_list = ",".join(open_ports)

        try:
            cmd = [self.nmap_path, "-Pn", "-sV",
                   "--version-all", "-p", port_list, target]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=300)

            if result.returncode == 0:
                # Parse service information from output
                self._parse_service_output(stdout.decode())

        except Exception as e:
            logging.error(f"Error in service detection: {e}")

    def _parse_service_output(self, output: str):
        """Parse service detection output."""
        lines = output.split('\n')

        for line in lines:
            if re.match(r'\d+/\w+', line):
                parts = line.split()
                if len(parts) >= 3:
                    port_protocol = parts[0]
                    port = int(port_protocol.split('/')[0])
                    state = parts[1]
                    service_info = ' '.join(parts[2:])

                    # Update existing port information
                    for port_data in self.results['open_ports']:
                        if port_data['port'] == port:
                            port_data['service_details'] = service_info
                            break

    async def _vulnerability_scan(self, target: str):
        """Scan for known vulnerabilities."""
        logging.info(f"Scanning for vulnerabilities on {target}")

        open_ports = [str(port['port']) for port in self.results['open_ports']]
        if not open_ports:
            return

        port_list = ",".join(open_ports)

        try:
            cmd = [self.nmap_path, "-Pn",
                   "--script=vuln", "-p", port_list, target]

            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=600)

            if result.returncode == 0:
                self._parse_vulnerability_output(stdout.decode())

        except Exception as e:
            logging.error(f"Error in vulnerability scan: {e}")

    def _parse_vulnerability_output(self, output: str):
        """Parse vulnerability scan output."""
        lines = output.split('\n')
        current_port = None

        for line in lines:
            line = line.strip()

            # Detect port line
            port_match = re.match(r'(\d+)/\w+', line)
            if port_match:
                current_port = int(port_match.group(1))
                continue

            # Detect vulnerability information
            if current_port and ('CVE-' in line or 'VULNERABLE' in line):
                vuln_info = {
                    'port': current_port,
                    'description': line,
                    'cves': re.findall(r'CVE-\d{4}-\d{4,}', line),
                    'severity': 'medium'  # Default severity
                }

                # Determine severity from keywords
                if any(keyword in line.lower() for keyword in ['critical', 'exploit', 'rce']):
                    vuln_info['severity'] = 'critical'
                elif any(keyword in line.lower() for keyword in ['high', 'dangerous']):
                    vuln_info['severity'] = 'high'
                elif any(keyword in line.lower() for keyword in ['low', 'minor']):
                    vuln_info['severity'] = 'low'

                self.results['vulnerabilities'].append(vuln_info)

    async def _banner_grabbing(self, target: str):
        """Grab service banners from open ports."""
        logging.info(f"Grabbing banners from {target}")

        tasks = []
        for port_info in self.results['open_ports']:
            port = port_info['port']
            tasks.append(self._grab_banner(target, port))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _grab_banner(self, target: str, port: int):
        """Grab banner from a specific port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=10
            )

            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                writer.write(b'GET / HTTP/1.1\r\nHost: ' +
                             target.encode() + b'\r\n\r\n')
            elif port == 21:  # FTP
                writer.write(b'USER anonymous\r\n')
            elif port == 25:  # SMTP
                writer.write(b'EHLO test\r\n')
            else:
                writer.write(b'\r\n')

            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            banner = data.decode('utf-8', errors='ignore').strip()

            if banner:
                self.results['banners'][port] = banner

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            logging.debug(f"Could not grab banner from port {port}: {e}")

    async def _ssl_analysis(self, target: str):
        """Analyze SSL/TLS configuration for HTTPS ports."""
        https_ports = [port['port'] for port in self.results['open_ports']
                       if port['port'] in [443, 8443] or 'https' in port.get('service', '').lower()]

        if not https_ports:
            return

        logging.info(f"Analyzing SSL/TLS configuration on {target}")

        for port in https_ports:
            try:
                cmd = [self.nmap_path, "-Pn", "--script=ssl-enum-ciphers,ssl-cert",
                       "-p", str(port), target]

                result = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=120)

                if result.returncode == 0:
                    ssl_info = self._parse_ssl_output(stdout.decode())
                    if ssl_info:
                        self.results['ssl_info'][port] = ssl_info

            except Exception as e:
                logging.error(f"Error in SSL analysis for port {port}: {e}")

    def _parse_ssl_output(self, output: str) -> Dict:
        """Parse SSL/TLS analysis output."""
        ssl_info = {
            'certificate': {},
            'ciphers': [],
            'vulnerabilities': []
        }

        lines = output.split('\n')

        for line in lines:
            line = line.strip()

            # Extract certificate information
            if 'Subject:' in line:
                ssl_info['certificate']['subject'] = line.split('Subject:', 1)[
                    1].strip()
            elif 'Issuer:' in line:
                ssl_info['certificate']['issuer'] = line.split('Issuer:', 1)[
                    1].strip()
            elif 'Not valid before:' in line:
                ssl_info['certificate']['not_before'] = line.split(
                    'Not valid before:', 1)[1].strip()
            elif 'Not valid after:' in line:
                ssl_info['certificate']['not_after'] = line.split(
                    'Not valid after:', 1)[1].strip()

            # Extract cipher information
            elif 'TLS_' in line or 'cipher:' in line.lower():
                ssl_info['ciphers'].append(line)

            # Detect SSL vulnerabilities
            elif any(vuln in line.lower() for vuln in ['heartbleed', 'poodle', 'beast', 'crime']):
                ssl_info['vulnerabilities'].append(line)

        return ssl_info

    async def _is_tool_available(self, tool_path: str) -> bool:
        """Check if a tool is available on the system."""
        try:
            result = await asyncio.create_subprocess_exec(
                tool_path, '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await asyncio.wait_for(result.communicate(), timeout=5)
            return result.returncode == 0

        except Exception:
            return False

    def generate_report(self) -> str:
        """Generate a comprehensive scanning report."""
        return safe_json_dumps(self.results, indent=2)
