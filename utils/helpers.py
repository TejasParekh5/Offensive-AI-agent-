import os
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def setup_logging(log_level: str = "INFO", log_file: str = None):
    """Setup logging configuration."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    handlers = [logging.StreamHandler()]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )


def load_config(config_path: str) -> Dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading config from {config_path}: {e}")
        return {}


def save_config(config: Dict, config_path: str) -> bool:
    """Save configuration to JSON file."""
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"Error saving config to {config_path}: {e}")
        return False


def generate_session_id() -> str:
    """Generate a unique session ID."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    return f"{timestamp}_{unique_id}"


def get_env_var(key: str, default: Any = None) -> Any:
    """Get environment variable with optional default."""
    return os.getenv(key, default)


def ensure_directory(path: str):
    """Ensure directory exists, create if it doesn't."""
    os.makedirs(path, exist_ok=True)


def read_file_safe(file_path: str) -> str:
    """Safely read file content."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return ""


def write_file_safe(file_path: str, content: str) -> bool:
    """Safely write content to file."""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception as e:
        logging.error(f"Error writing file {file_path}: {e}")
        return False


def merge_dicts(dict1: Dict, dict2: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = dict1.copy()

    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value

    return result


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """Flatten nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def chunk_list(lst: List, chunk_size: int) -> List[List]:
    """Split list into chunks of specified size."""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def filter_dict_by_keys(d: Dict, keys: List[str]) -> Dict:
    """Filter dictionary to only include specified keys."""
    return {k: v for k, v in d.items() if k in keys}


def normalize_port_list(ports: str) -> List[int]:
    """Normalize port specification to list of integers."""
    port_list = []

    for part in ports.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            port_list.extend(range(start, end + 1))
        else:
            port_list.append(int(part))

    return sorted(list(set(port_list)))


def format_timestamp(timestamp: datetime = None) -> str:
    """Format timestamp for display."""
    if timestamp is None:
        timestamp = datetime.now()
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def convert_to_serializable(obj: Any) -> Any:
    """Convert object to JSON serializable format."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    elif hasattr(obj, '__dict__'):
        return obj.__dict__
    elif isinstance(obj, (set, tuple)):
        return list(obj)
    else:
        return str(obj)


def safe_json_dumps(obj: Any, indent: int = 2) -> str:
    """Safely convert object to JSON string."""
    try:
        return json.dumps(obj, indent=indent, default=convert_to_serializable)
    except Exception as e:
        logging.error(f"Error converting to JSON: {e}")
        return "{}"


def parse_json_safe(json_str: str) -> Dict:
    """Safely parse JSON string."""
    try:
        return json.loads(json_str)
    except Exception as e:
        logging.error(f"Error parsing JSON: {e}")
        return {}


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except Exception:
        return 0


def is_tool_available(tool_name: str) -> bool:
    """Check if a command-line tool is available."""
    from shutil import which
    return which(tool_name) is not None


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string to maximum length."""
    if len(s) <= max_length:
        return s
    return s[:max_length-3] + "..."


def extract_domain_from_url(url: str) -> str:
    """Extract domain from URL."""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url


def deduplicate_list(lst: List) -> List:
    """Remove duplicates from list while preserving order."""
    seen = set()
    result = []
    for item in lst:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def timeout_handler(signum, frame):
    """Signal handler for timeouts."""
    raise TimeoutError("Operation timed out")


class ProgressTracker:
    """Simple progress tracking utility."""

    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = datetime.now()

    def update(self, increment: int = 1):
        """Update progress."""
        self.current += increment
        if self.current > self.total:
            self.current = self.total

    def get_percentage(self) -> float:
        """Get completion percentage."""
        if self.total == 0:
            return 0.0
        return (self.current / self.total) * 100

    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        return (datetime.now() - self.start_time).total_seconds()

    def get_eta(self) -> Optional[float]:
        """Get estimated time to completion."""
        if self.current == 0:
            return None
        elapsed = self.get_elapsed_time()
        rate = self.current / elapsed
        remaining = self.total - self.current
        return remaining / rate if rate > 0 else None

    def __str__(self) -> str:
        """String representation of progress."""
        percentage = self.get_percentage()
        return f"{self.description}: {self.current}/{self.total} ({percentage:.1f}%)"
