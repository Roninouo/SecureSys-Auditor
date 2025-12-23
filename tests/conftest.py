"""
Test configuration and fixtures for SecureSys Auditor tests.
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add source directories to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / 'src' / 'backend'))
sys.path.insert(0, str(BASE_DIR / 'src' / 'agent'))

# Set Django settings before importing Django modules
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
os.environ.setdefault('TESTING', 'True')

# Setup Django
import django
django.setup()


@pytest.fixture(scope='session')
def django_db_setup():
    """Setup database for session."""
    pass


@pytest.fixture
def sample_scan_payload():
    """Sample scan payload for testing analysis."""
    return {
        'hostname': 'test-server-01',
        'os': {
            'name': 'Linux',
            'version': '5.4.0',
            'release': 'Ubuntu 20.04',
            'architecture': 'x86_64',
        },
        'scan_time': '2024-01-15T10:30:00Z',
        'ssh_config': {
            'permit_root_login': True,  # Security issue
            'password_auth': True,
            'port': 22,
        },
        'firewall': {
            'enabled': False,  # Security issue
        },
        'packages': {
            'outdated': [
                {'name': 'openssl', 'current': '1.1.1', 'latest': '1.1.1k'},
                {'name': 'curl', 'current': '7.68.0', 'latest': '7.81.0'},
            ],
        },
        'password_policy': {
            'min_length': 8,  # Too short - security issue
            'require_special': False,  # Missing - security issue
            'require_numbers': True,
        },
        'users': {
            'local_users': ['root', 'admin', 'user1', 'user2'],
            'admin_users': ['root', 'admin', 'dev1', 'dev2', 'backup'],  # Too many - security issue
            'logged_in_users': [{'name': 'admin', 'terminal': 'pts/0', 'host': '10.0.0.1'}],
        },
        'network': {
            'open_ports': [
                {'port': 22, 'service': 'ssh'},
                {'port': 23, 'service': 'telnet'},  # Security issue - risky port
                {'port': 80, 'service': 'http'},
                {'port': 443, 'service': 'https'},
            ],
        },
    }


@pytest.fixture
def secure_scan_payload():
    """Scan payload with no security issues."""
    return {
        'hostname': 'secure-server-01',
        'os': {
            'name': 'Linux',
            'version': '5.4.0',
            'release': 'Ubuntu 20.04',
            'architecture': 'x86_64',
        },
        'scan_time': '2024-01-15T10:30:00Z',
        'ssh_config': {
            'permit_root_login': False,
            'password_auth': False,
            'port': 22,
        },
        'firewall': {
            'enabled': True,
        },
        'packages': {
            'outdated': [],
        },
        'password_policy': {
            'min_length': 14,
            'require_special': True,
            'require_numbers': True,
        },
        'users': {
            'local_users': ['admin', 'user1'],
            'admin_users': ['admin'],
            'logged_in_users': [],
        },
        'network': {
            'open_ports': [
                {'port': 22, 'service': 'ssh'},
                {'port': 443, 'service': 'https'},
            ],
        },
    }


@pytest.fixture
def mock_api_client():
    """Mock API client for agent tests."""
    client = MagicMock()
    client.api_url = 'https://api.securesys.example.com'
    client.api_key = 'test-api-key-12345'
    return client
