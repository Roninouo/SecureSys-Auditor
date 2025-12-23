"""
Base Client Module for SecureSys Agent.

Provides extensible base classes for API clients using:
- Template Method pattern for scan types
- Strategy pattern for authentication
- Proper async context management
"""
from .base import BaseAsyncClient, ScanType
from .async_client import AsyncSecureSysClient

__all__ = [
    'BaseAsyncClient',
    'ScanType',
    'AsyncSecureSysClient',
]
