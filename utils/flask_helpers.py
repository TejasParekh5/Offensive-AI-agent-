"""
Flask Utilities and Helper Functions
Common utilities for the Flask cybersecurity automation system.
"""

import os
import re
import logging
import ipaddress
import socket
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from pathlib import Path
import json
import hashlib


def setup_logging(log_level: str = 'INFO', log_file: Optional[str] = None) -> None:
    """
    Setup logging configuration for the Flask application.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
    """
    # Create logs directory if it doesn't exist
    logs_dir = Path(__file__).parent.parent / 'logs'
    logs_dir.mkdir(exist_ok=True)

    # Set default log file if not provided
    if not log_file:
        log_file = logs_dir / \
            f"flask_app_{datetime.now().strftime('%Y%m%d')}.log"

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger(__name__)
    logger.info(f"Logging configured: level={log_level}, file={log_file}")


def is_valid_ip(ip_address: str) -> bool:
    """
    Validate if a string is a valid IP address.

    Args:
        ip_address: String to validate

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.

    Args:
        domain: String to validate

    Returns:
        True if valid domain, False otherwise
    """
    # Basic domain regex pattern
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )

    if not domain_pattern.match(domain):
        return False

    # Additional checks
    if len(domain) > 253:
        return False

    # Check each label
    labels = domain.split('.')
    for label in labels:
        if len(label) > 63:
            return False

    return True


def is_valid_cidr(cidr: str) -> bool:
    """
    Validate if a string is a valid CIDR notation.

    Args:
        cidr: String to validate

    Returns:
        True if valid CIDR, False otherwise
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def resolve_domain_to_ip(domain: str) -> Optional[str]:
    """
    Resolve domain name to IP address.

    Args:
        domain: Domain name to resolve

    Returns:
        IP address string or None if resolution fails
    """
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None


def get_target_type(target: str) -> str:
    """
    Determine the type of target (IP, domain, or CIDR).

    Args:
        target: Target string to analyze

    Returns:
        Target type: 'ip', 'domain', 'cidr', or 'unknown'
    """
    if is_valid_ip(target):
        return 'ip'
    elif is_valid_cidr(target):
        return 'cidr'
    elif is_valid_domain(target):
        return 'domain'
    else:
        return 'unknown'


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe filesystem operations.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove or replace invalid characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)

    # Remove multiple consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)

    # Limit length
    if len(sanitized) > 255:
        name, ext = os.path.splitext(sanitized)
        sanitized = name[:255-len(ext)] + ext

    return sanitized


def generate_assessment_id() -> str:
    """
    Generate a unique assessment ID.

    Returns:
        Unique assessment ID string
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    random_hash = hashlib.md5(
        str(datetime.now().timestamp()).encode()).hexdigest()[:8]
    return f"assess_{timestamp}_{random_hash}"


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024.0 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1

    return f"{size_bytes:.1f} {size_names[i]}"


def format_duration(start_time: datetime, end_time: Optional[datetime] = None) -> str:
    """
    Format duration between two datetime objects.

    Args:
        start_time: Start datetime
        end_time: End datetime (defaults to now)

    Returns:
        Formatted duration string
    """
    if end_time is None:
        end_time = datetime.now()

    duration = end_time - start_time
    total_seconds = int(duration.total_seconds())

    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def load_json_config(config_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load JSON configuration file.

    Args:
        config_path: Path to JSON config file

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logging.getLogger(__name__).error(
            f"Failed to load config {config_path}: {e}")
        return {}


def save_json_config(config_data: Dict[str, Any], config_path: Union[str, Path]) -> bool:
    """
    Save configuration to JSON file.

    Args:
        config_data: Configuration dictionary
        config_path: Path to save JSON config

    Returns:
        True if successful, False otherwise
    """
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logging.getLogger(__name__).error(
            f"Failed to save config {config_path}: {e}")
        return False


def get_system_info() -> Dict[str, Any]:
    """
    Get system information for debugging and logging.

    Returns:
        System information dictionary
    """
    import platform
    import psutil

    try:
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'disk_usage': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
        }
    except ImportError:
        # Fallback if psutil is not available
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version()
        }


def validate_port_list(port_list: str) -> bool:
    """
    Validate port list format.

    Args:
        port_list: Port list string (e.g., "80,443,8080-8090")

    Returns:
        True if valid, False otherwise
    """
    if not port_list:
        return False

    # Split by commas
    parts = port_list.split(',')

    for part in parts:
        part = part.strip()

        # Check for range (e.g., "8080-8090")
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())

                if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
                    return False
                if start_port > end_port:
                    return False
            except ValueError:
                return False
        else:
            # Single port
            try:
                port = int(part)
                if not (1 <= port <= 65535):
                    return False
            except ValueError:
                return False

    return True


def expand_port_list(port_list: str) -> List[int]:
    """
    Expand port list string to list of individual port numbers.

    Args:
        port_list: Port list string (e.g., "80,443,8080-8090")

    Returns:
        List of port numbers
    """
    ports = []

    if not port_list:
        return ports

    parts = port_list.split(',')

    for part in parts:
        part = part.strip()

        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                ports.extend(range(start_port, end_port + 1))
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                ports.append(port)
            except ValueError:
                continue

    return sorted(list(set(ports)))  # Remove duplicates and sort


def create_progress_tracker():
    """
    Create a simple progress tracking utility.

    Returns:
        Progress tracker object
    """
    class ProgressTracker:
        def __init__(self):
            self.total = 0
            self.current = 0
            self.start_time = datetime.now()

        def set_total(self, total: int):
            self.total = total

        def update(self, current: int):
            self.current = current

        def increment(self):
            self.current += 1

        def get_percentage(self) -> float:
            if self.total == 0:
                return 0.0
            return (self.current / self.total) * 100

        def get_eta(self) -> Optional[datetime]:
            if self.current == 0:
                return None

            elapsed = datetime.now() - self.start_time
            rate = self.current / elapsed.total_seconds()
            remaining = self.total - self.current

            if rate > 0:
                eta_seconds = remaining / rate
                return datetime.now() + timedelta(seconds=eta_seconds)

            return None

    return ProgressTracker()


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """
    Hash a string using specified algorithm.

    Args:
        text: Text to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hexadecimal hash string
    """
    try:
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(text.encode('utf-8'))
        return hash_obj.hexdigest()
    except ValueError:
        # Fallback to SHA256 if algorithm is not supported
        return hashlib.sha256(text.encode('utf-8')).hexdigest()


def mask_sensitive_data(data: str, mask_char: str = '*', visible_chars: int = 4) -> str:
    """
    Mask sensitive data (e.g., API keys, passwords).

    Args:
        data: Sensitive data to mask
        mask_char: Character to use for masking
        visible_chars: Number of characters to keep visible at the end

    Returns:
        Masked string
    """
    if len(data) <= visible_chars:
        return mask_char * len(data)

    visible_part = data[-visible_chars:]
    masked_part = mask_char * (len(data) - visible_chars)

    return masked_part + visible_part


def get_file_hash(file_path: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
    """
    Calculate hash of a file.

    Args:
        file_path: Path to file
        algorithm: Hash algorithm

    Returns:
        File hash or None if error
    """
    try:
        hash_obj = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()
    except Exception:
        return None


def ensure_directory_exists(directory_path: Union[str, Path]) -> bool:
    """
    Ensure directory exists, create if it doesn't.

    Args:
        directory_path: Path to directory

    Returns:
        True if directory exists or was created, False on error
    """
    try:
        Path(directory_path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception:
        return False


# Error handling utilities
class FlaskAppError(Exception):
    """Base exception for Flask application errors."""
    pass


class ValidationError(FlaskAppError):
    """Raised when input validation fails."""
    pass


class ConfigurationError(FlaskAppError):
    """Raised when configuration is invalid."""
    pass


class ToolNotFoundError(FlaskAppError):
    """Raised when required external tool is not found."""
    pass


class AssessmentError(FlaskAppError):
    """Raised when assessment operations fail."""
    pass
