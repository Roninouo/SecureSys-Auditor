"""
Configuration Management for SecureSys Agent
"""

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional


@dataclass
class Config:
    """Agent configuration."""
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    system_id: Optional[str] = None
    
    def to_dict(self):
        return asdict(self)


def get_config_path() -> Path:
    """Get the configuration file path."""
    if os.name == 'nt':  # Windows
        config_dir = Path(os.environ.get('APPDATA', '~')) / 'SecureSys'
    else:  # Linux/macOS
        config_dir = Path.home() / '.config' / 'securesys'
    
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / 'agent.json'


def load_config() -> Config:
    """Load configuration from file."""
    config_path = get_config_path()
    
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                return Config(**data)
        except Exception:
            pass
    
    return Config()


def save_config(config: Config) -> None:
    """Save configuration to file."""
    config_path = get_config_path()
    
    with open(config_path, 'w') as f:
        json.dump(config.to_dict(), f, indent=2)
    
    # Secure the file permissions (Unix only)
    if os.name != 'nt':
        os.chmod(config_path, 0o600)
