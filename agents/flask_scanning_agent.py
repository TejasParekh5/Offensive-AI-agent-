"""
Flask Scanning Agent
Handles port scanning, service detection, and vulnerability scanning using Nmap, Masscan, and Rustscan.
"""

import subprocess
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import ipaddress
import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import threading
import time


class FlaskScanningAgent:
    """
    Modular scanning agent for port scanning and service detection.
    Supports Nmap, Masscan, and Rustscan with configurable scan types.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scan_results = {}
        self.scan_status = {}
        
        # Scanning tool configurations
        self.scan_tools = {
            'nmap': {
                'available': self._check_tool_availability('nmap'),
                'command': 'nmap'
            },
            'masscan': {
                'available': self._check_tool_availability('masscan'),
                'command': 'masscan'
            },
            'rustscan': {
                'available': self._check_tool_availability('rustscan'),
                'command': 'rustscan'
            }
        }
        
        # Common port lists
        self.port_lists = {
            'top_100': '7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157',
            'common_web': '80,443,8000,8080,8443,9000,9080,9443',
            'common_db': '1433,1521,3306,5432,27017,6379',
            'all': '1-65535'
        }
        # Get top 1000 ports from nmap if available, otherwise use top 100
        self.port_lists['top_1000'] = self._get_nmap_top_ports(1000)
        
        self.logger.info(f"FlaskScanningAgent initialized. Available tools: {[tool for tool, config in self.scan_tools.items() if config['available']]}")
    
    def _check_tool_availability(self, tool_name: str) -> bool:
        """Check if a scanning tool is available in the system PATH."""
        try:
            subprocess.run([tool_name, '--help'], capture_output=True, timeout=5)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def _get_nmap_top_ports(self, count: int) -> str:
        """Get Nmap's top N ports list."""
        try:
            result = subprocess.run(['nmap', '--top-ports', str(count), '--list-ports'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse the output to extract port numbers
                ports = []
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        port = line.split('/')[0].strip()
                        if port.isdigit():
                            ports.append(port)
                return ','.join(ports)
        except Exception as e:
            self.logger.warning(f"Could not get Nmap top ports: {e}")
        return self.port_lists['top_100']
    
    def start_scan(self, target: str, scan_type: str = 'comprehensive', ports: str = 'top_1000', 
                   tool_preference: str = 'nmap', callback=None) -> str:
        """
        Start a port scanning operation.
        
        Args:
            target: IP address or CIDR range to scan
            scan_type: Type of scan (quick, comprehensive, stealth, aggressive)
            ports: Port specification (top_100, top_1000, common_web, etc.)
            tool_preference: Preferred scanning tool (nmap, masscan, rustscan)
            callback: Callback function for real-time updates
        
        Returns:
            Scan ID for tracking progress
        """
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(target) % 10000}"
        
        # Validate target
        if not self._validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        # Get port specification
        port_spec = self.port_lists.get(ports, ports)
        
        # Choose scanning tool
        tool = self._select_scanning_tool(tool_preference)
        if not tool:
            raise RuntimeError("No scanning tools available")
        
        # Initialize scan tracking
        self.scan_status[scan_id] = {
            'status': 'starting',
            'target': target,
            'scan_type': scan_type,
            'tool': tool,
            'start_time': datetime.now(),
            'progress': 0
        }
        
        self.scan_results[scan_id] = {
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'tool': tool,
            'start_time': datetime.now().isoformat(),
            'status': 'running',
            'ports': port_spec,
            'results': {}
        }
        
        # Start scanning in background thread
        thread = threading.Thread(
            target=self._run_scan,
            args=(scan_id, target, scan_type, port_spec, tool, callback)
        )
        thread.daemon = True
        thread.start()
        
        return scan_id
    
    def _validate_target(self, target: str) -> bool:
        """Validate that the target is a valid IP address or CIDR range."""
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                return False
    
    def _select_scanning_tool(self, preference: str) -> Optional[str]:
        """Select an available scanning tool based on preference."""
        # Try preferred tool first
        if preference in self.scan_tools and self.scan_tools[preference]['available']:
            return preference
        
        # Fallback to any available tool
        for tool, config in self.scan_tools.items():
            if config['available']:
                return tool
        
        return None
    
    def _run_scan(self, scan_id: str, target: str, scan_type: str, ports: str, tool: str, callback=None):
        """Execute the actual scanning operation."""
        try:
            self.scan_status[scan_id]['status'] = 'scanning'
            
            if callback:
                callback(scan_id, {'status': 'scanning', 'message': f'Starting {tool} scan of {target}'})
            
            # Execute scan based on tool
            if tool == 'nmap':
                results = self._run_nmap_scan(scan_id, target, scan_type, ports, callback)
            elif tool == 'masscan':
                results = self._run_masscan_scan(scan_id, target, scan_type, ports, callback)
            elif tool == 'rustscan':
                results = self._run_rustscan_scan(scan_id, target, scan_type, ports, callback)
            else:
                raise ValueError(f"Unsupported scanning tool: {tool}")
            
            # Update results
            self.scan_results[scan_id].update(results)
            self.scan_results[scan_id]['status'] = 'completed'
            self.scan_results[scan_id]['end_time'] = datetime.now().isoformat()
            self.scan_status[scan_id]['status'] = 'completed'
            self.scan_status[scan_id]['progress'] = 100
            
            if callback:
                callback(scan_id, {'status': 'completed', 'results': results})
                
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {e}")
            self.scan_results[scan_id]['status'] = 'failed'
            self.scan_results[scan_id]['error'] = str(e)
            self.scan_status[scan_id]['status'] = 'failed'
            
            if callback:
                callback(scan_id, {'status': 'failed', 'error': str(e)})
    
    def _run_nmap_scan(self, scan_id: str, target: str, scan_type: str, ports: str, callback=None) -> Dict[str, Any]:
        """Execute Nmap scan with specified parameters."""
        # Build Nmap command based on scan type
        cmd = ['nmap']
        
        if scan_type == 'quick':
            cmd.extend(['-T4', '-F'])  # Fast scan, top 100 ports
        elif scan_type == 'comprehensive':
            cmd.extend(['-sS', '-sV', '-O', '-A', '--script=default'])  # Comprehensive scan
        elif scan_type == 'stealth':
            cmd.extend(['-sS', '-T2', '-f'])  # Stealth scan
        elif scan_type == 'aggressive':
            cmd.extend(['-T4', '-A', '--script=vuln'])  # Aggressive scan with vuln scripts
        
        # Add port specification
        if ports and ports != 'all':
            cmd.extend(['-p', ports])
        
        # Output options
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as temp_file:
            xml_output = temp_file.name
        
        cmd.extend(['-oX', xml_output, target])
        
        # Execute scan
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Monitor progress (simplified)
        while process.poll() is None:
            if callback:
                # Update progress (this is a simplified progress indicator)
                current_progress = min(self.scan_status[scan_id]['progress'] + 10, 90)
                self.scan_status[scan_id]['progress'] = current_progress
                callback(scan_id, {'status': 'scanning', 'progress': current_progress})
            time.sleep(2)
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            raise RuntimeError(f"Nmap scan failed: {stderr}")
        
        # Parse XML output
        return self._parse_nmap_xml(xml_output)
    
    def _run_masscan_scan(self, scan_id: str, target: str, scan_type: str, ports: str, callback=None) -> Dict[str, Any]:
        """Execute Masscan scan with specified parameters."""
        # Build Masscan command
        cmd = ['masscan']
        
        # Rate limiting based on scan type
        if scan_type == 'quick':
            cmd.extend(['--rate', '1000'])
        elif scan_type == 'comprehensive':
            cmd.extend(['--rate', '10000'])
        elif scan_type == 'stealth':
            cmd.extend(['--rate', '100'])
        elif scan_type == 'aggressive':
            cmd.extend(['--rate', '100000'])
        
        # Add port specification
        if ports and ports != 'all':
            cmd.extend(['-p', ports])
        else:
            cmd.extend(['-p', '1-65535'])
        
        # Output format
        cmd.extend(['--output-format', 'json', target])
        
        # Execute scan
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise RuntimeError(f"Masscan failed: {result.stderr}")
        
        # Parse JSON output
        return self._parse_masscan_output(result.stdout)
    
    def _run_rustscan_scan(self, scan_id: str, target: str, scan_type: str, ports: str, callback=None) -> Dict[str, Any]:
        """Execute Rustscan scan with specified parameters."""
        # Build Rustscan command
        cmd = ['rustscan', '-a', target]
        
        # Add port specification
        if ports and ports != 'all':
            cmd.extend(['-p', ports])
        
        # Batch size based on scan type
        if scan_type == 'quick':
            cmd.extend(['-b', '500'])
        elif scan_type == 'comprehensive':
            cmd.extend(['-b', '2000'])
        elif scan_type == 'stealth':
            cmd.extend(['-b', '100'])
        elif scan_type == 'aggressive':
            cmd.extend(['-b', '5000'])
        
        # JSON output
        cmd.extend(['--format', 'json'])
        
        # Execute scan
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            raise RuntimeError(f"Rustscan failed: {result.stderr}")
        
        # Parse JSON output
        return self._parse_rustscan_output(result.stdout)
    
    def _parse_nmap_xml(self, xml_file: str) -> Dict[str, Any]:
        """Parse Nmap XML output to extract scan results."""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            results = {
                'hosts': [],
                'summary': {
                    'total_hosts': 0,
                    'hosts_up': 0,
                    'total_ports': 0,
                    'open_ports': 0
                }
            }
            
            for host in root.findall('host'):
                host_data = {
                    'ip': '',
                    'hostname': '',
                    'status': '',
                    'os': '',
                    'ports': []
                }
                
                # Get IP address
                address = host.find('address')
                if address is not None:
                    host_data['ip'] = address.get('addr', '')
                
                # Get hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_data['hostname'] = hostname.get('name', '')
                
                # Get host status
                status = host.find('status')
                if status is not None:
                    host_data['status'] = status.get('state', '')
                
                # Get OS detection
                os_elem = host.find('os')
                if os_elem is not None:
                    osmatch = os_elem.find('osmatch')
                    if osmatch is not None:
                        host_data['os'] = osmatch.get('name', '')
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_data = {
                            'port': port.get('portid', ''),
                            'protocol': port.get('protocol', ''),
                            'state': '',
                            'service': '',
                            'version': ''
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_data['state'] = state.get('state', '')
                        
                        service = port.find('service')
                        if service is not None:
                            port_data['service'] = service.get('name', '')
                            port_data['version'] = service.get('version', '')
                        
                        host_data['ports'].append(port_data)
                        results['summary']['total_ports'] += 1
                        if port_data['state'] == 'open':
                            results['summary']['open_ports'] += 1
                
                results['hosts'].append(host_data)
                results['summary']['total_hosts'] += 1
                if host_data['status'] == 'up':
                    results['summary']['hosts_up'] += 1
            
            # Clean up temp file
            os.unlink(xml_file)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to parse Nmap XML: {e}")
            return {'error': f"Failed to parse scan results: {e}"}
    
    def _parse_masscan_output(self, output: str) -> Dict[str, Any]:
        """Parse Masscan JSON output."""
        try:
            lines = output.strip().split('\n')
            results = {
                'hosts': {},
                'summary': {
                    'total_hosts': 0,
                    'total_ports': 0,
                    'open_ports': 0
                }
            }
            
            for line in lines:
                if line.strip() and line.startswith('{'):
                    data = json.loads(line)
                    ip = data.get('ip', '')
                    port = data.get('port', '')
                    
                    if ip not in results['hosts']:
                        results['hosts'][ip] = {
                            'ip': ip,
                            'ports': []
                        }
                        results['summary']['total_hosts'] += 1
                    
                    results['hosts'][ip]['ports'].append({
                        'port': str(port),
                        'state': 'open',
                        'protocol': 'tcp'
                    })
                    results['summary']['open_ports'] += 1
            
            # Convert hosts dict to list
            results['hosts'] = list(results['hosts'].values())
            results['summary']['total_ports'] = results['summary']['open_ports']
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to parse Masscan output: {e}")
            return {'error': f"Failed to parse scan results: {e}"}
    
    def _parse_rustscan_output(self, output: str) -> Dict[str, Any]:
        """Parse Rustscan JSON output."""
        try:
            data = json.loads(output)
            results = {
                'hosts': [],
                'summary': {
                    'total_hosts': 0,
                    'total_ports': 0,
                    'open_ports': 0
                }
            }
            
            for host_ip, ports in data.items():
                host_data = {
                    'ip': host_ip,
                    'ports': []
                }
                
                for port in ports:
                    host_data['ports'].append({
                        'port': str(port),
                        'state': 'open',
                        'protocol': 'tcp'
                    })
                    results['summary']['open_ports'] += 1
                
                results['hosts'].append(host_data)
                results['summary']['total_hosts'] += 1
            
            results['summary']['total_ports'] = results['summary']['open_ports']
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to parse Rustscan output: {e}")
            return {'error': f"Failed to parse scan results: {e}"}
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the current status of a scan."""
        return self.scan_status.get(scan_id, {'status': 'not_found'})
    
    def get_scan_results(self, scan_id: str) -> Dict[str, Any]:
        """Get the results of a completed scan."""
        return self.scan_results.get(scan_id, {'error': 'Scan not found'})
    
    def list_active_scans(self) -> List[str]:
        """Get a list of currently active scan IDs."""
        return [scan_id for scan_id, status in self.scan_status.items() 
                if status['status'] in ['starting', 'scanning']]
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an active scan (implementation depends on process management)."""
        if scan_id in self.scan_status:
            self.scan_status[scan_id]['status'] = 'cancelled'
            self.scan_results[scan_id]['status'] = 'cancelled'
            return True
        return False
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get the availability status of all scanning tools."""
        return {tool: config['available'] for tool, config in self.scan_tools.items()}
