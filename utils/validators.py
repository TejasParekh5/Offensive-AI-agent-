import re
import ipaddress
import socket
import logging
from urllib.parse import urlparse
from typing import Optional, Tuple


def is_valid_ip(ip: str) -> bool:
    """Check if the given string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if the given string is a valid domain name."""
    # Basic domain regex pattern
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )

    if not domain_pattern.match(domain):
        return False

    # Additional checks
    if len(domain) > 253:
        return False

    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            return False

    return True


def is_valid_url(url: str) -> bool:
    """Check if the given string is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def validate_target(target: str) -> Tuple[bool, str, str]:
    """
    Validate target input and determine its type.

    Returns:
        Tuple of (is_valid, target_type, normalized_target)
    """
    target = target.strip()

    if not target:
        return False, "empty", ""

    # Check if it's an IP address
    if is_valid_ip(target):
        return True, "ip", target

    # Check if it's a URL
    if is_valid_url(target):
        parsed = urlparse(target)
        domain = parsed.netloc
        if is_valid_ip(domain):
            return True, "ip", domain
        elif is_valid_domain(domain):
            return True, "domain", domain
        else:
            return False, "invalid", target

    # Check if it's a domain
    if is_valid_domain(target):
        return True, "domain", target

    return False, "invalid", target


def validate_port_range(port_range: str) -> bool:
    """Validate port range format."""
    if not port_range:
        return False

    # Single port
    if port_range.isdigit():
        port = int(port_range)
        return 1 <= port <= 65535

    # Port range
    if '-' in port_range:
        try:
            start, end = port_range.split('-', 1)
            start_port = int(start)
            end_port = int(end)
            return (1 <= start_port <= 65535 and
                    1 <= end_port <= 65535 and
                    start_port <= end_port)
        except ValueError:
            return False

    # Comma-separated ports
    if ',' in port_range:
        try:
            ports = port_range.split(',')
            for port in ports:
                port = port.strip()
                if port.isdigit():
                    if not (1 <= int(port) <= 65535):
                        return False
                elif '-' in port:
                    if not validate_port_range(port):
                        return False
                else:
                    return False
            return True
        except ValueError:
            return False

    return False


def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """Resolve domain name to IP address."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        logging.warning(f"Could not resolve domain {domain}: {e}")
        return None


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = filename.strip('.')

    # Limit length
    if len(filename) > 100:
        filename = filename[:100]

    return filename


def format_bytes(bytes_val: int) -> str:
    """Format bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} PB"


def parse_nmap_output(output: str) -> dict:
    """Parse Nmap output and extract structured data."""
    results = {
        'host': None,
        'ports': [],
        'os': None,
        'services': []
    }

    lines = output.split('\n')
    current_host = None

    for line in lines:
        line = line.strip()

        # Extract host information
        if 'Nmap scan report for' in line:
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                current_host = host_match.group(1)
                results['host'] = current_host

        # Extract port information
        elif re.match(r'\d+/\w+', line):
            port_match = re.match(r'(\d+)/(\w+)\s+(\w+)\s+(.+)', line)
            if port_match:
                port_info = {
                    'port': int(port_match.group(1)),
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4)
                }
                results['ports'].append(port_info)

        # Extract OS information
        elif 'OS details:' in line:
            os_match = re.search(r'OS details: (.+)', line)
            if os_match:
                results['os'] = os_match.group(1)

    return results


def parse_masscan_output(output: str) -> list:
    """Parse Masscan output and extract open ports."""
    ports = []
    lines = output.split('\n')

    for line in lines:
        # Masscan output format: "Discovered open port 80/tcp on 192.168.1.1"
        match = re.search(r'Discovered open port (\d+)/(\w+) on (.+)', line)
        if match:
            port_info = {
                'port': int(match.group(1)),
                'protocol': match.group(2),
                'host': match.group(3),
                'state': 'open'
            }
            ports.append(port_info)

    return ports


def extract_cves_from_text(text: str) -> list:
    """Extract CVE identifiers from text."""
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    return list(set(cve_pattern.findall(text)))


def calculate_risk_score(severity: str, confidence: str = "medium") -> int:
    """Calculate numerical risk score based on severity and confidence."""
    severity_scores = {
        'critical': 9,
        'high': 7,
        'medium': 5,
        'low': 3,
        'info': 1
    }

    confidence_multipliers = {
        'high': 1.0,
        'medium': 0.8,
        'low': 0.6
    }

    base_score = severity_scores.get(severity.lower(), 1)
    multiplier = confidence_multipliers.get(confidence.lower(), 0.8)

    return int(base_score * multiplier)


def format_duration(seconds: int) -> str:
    """Format duration in seconds to human readable format."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        remaining_seconds = seconds % 60
        return f"{minutes}m {remaining_seconds}s"
    else:
        hours = seconds // 3600
        remaining_minutes = (seconds % 3600) // 60
        return f"{hours}h {remaining_minutes}m"


def clean_ansi_codes(text: str) -> str:
    """Remove ANSI color codes from text."""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)
