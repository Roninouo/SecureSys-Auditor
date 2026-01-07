"""
Configuration Management for SecureSys Agent

Handles configuration loading, saving, and validation for the agent.
Supports minimal telemetry mode to filter sensitive data from scans.
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

# Fields that are filtered out when minimal_telemetry is enabled
SENSITIVE_FIELDS = [
    "ip_address",
    "mac_address",
    "user_home_paths",
    "environment_variables",
    "command_history",
    "ssh_keys",
    "private_keys",
    "passwords",
    "tokens",
    "credentials",
]


@dataclass
class Config:
    """
    Agent configuration.

    Attributes:
        api_url: URL of the SecureSys API
        api_key: API key for authentication and payload signing
        system_id: Cached system ID after registration
        minimal_telemetry: When True, filters sensitive data from scan payloads
        allow_insecure_localhost: Allow HTTP for localhost (dev only)
    """

    api_url: Optional[str] = None
    api_key: Optional[str] = None
    system_id: Optional[str] = None
    minimal_telemetry: bool = True  # Default to privacy-preserving mode
    allow_insecure_localhost: bool = False
    sensitive_fields: List[str] = field(default_factory=lambda: SENSITIVE_FIELDS.copy())

    def to_dict(self):
        """Convert config to dictionary."""
        return asdict(self)


def get_config_path() -> Path:
    """Get the configuration file path."""
    if os.name == "nt":  # Windows
        config_dir = Path(os.environ.get("APPDATA", "~")) / "SecureSys"
    else:  # Linux/macOS
        config_dir = Path.home() / ".config" / "securesys"

    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "agent.json"


def load_config() -> Config:
    """Load configuration from file."""
    config_path = get_config_path()

    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return Config(**data)
        except Exception as e:
            logger.error(f"Failed to load config from {config_path}: {e}", exc_info=True)
            # Proceeding with defaults, but error is visible now

    return Config()


def save_config(config: Config) -> None:
    """Save configuration to file."""
    config_path = get_config_path()

    with open(config_path, "w") as f:
        json.dump(config.to_dict(), f, indent=2)

    # Secure the file permissions (Unix only)
    if os.name != "nt":
        os.chmod(config_path, 0o600)
