"""
Base Async Client for SecureSys Agent.

Provides extensible base class for API clients with:
- Template Method pattern for different scan types
- Proper resource management
- Configurable authentication

Adding New Scan Types:
1. Subclass ScanType
2. Implement get_scan_data() method
3. Register in ScanTypeRegistry
"""
import abc
import asyncio
import hashlib
import hmac
import json
import logging
import ssl
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol
from urllib.parse import urlparse

import aiohttp
from aiohttp import TCPConnector, ClientTimeout

logger = logging.getLogger(__name__)


class ScanType(str, Enum):
    """Supported scan types."""
    FULL = 'full'
    QUICK = 'quick'
    COMPLIANCE = 'compliance'
    VULNERABILITY = 'vulnerability'


class AuthStrategy(Protocol):
    """Protocol for authentication strategies."""
    
    def get_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        ...
    
    def sign_payload(self, payload: Dict, timestamp: int) -> str:
        """Sign a payload for verification."""
        ...


class BearerTokenAuth:
    """Bearer token authentication with HMAC signing."""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def get_headers(self) -> Dict[str, str]:
        return {
            'Authorization': f'Bearer {self.api_key}',
        }
    
    def sign_payload(self, payload: Dict, timestamp: int) -> str:
        """Generate HMAC-SHA256 signature."""
        canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        message = f"{timestamp}.{canonical}"
        
        return hmac.new(
            key=self.api_key.encode('utf-8'),
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()


class BaseAsyncClient(abc.ABC):
    """
    Base async client for SecureSys API.
    
    Provides common functionality:
    - Connection pooling
    - TLS configuration
    - Retry logic
    - Authentication
    
    Subclasses implement specific API operations.
    """
    
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_CONNECTIONS = 10
    DEFAULT_RETRY_ATTEMPTS = 3
    DEFAULT_RETRY_BACKOFF = 1.0
    
    def __init__(
        self,
        api_url: str,
        auth: AuthStrategy,
        *,
        allow_insecure_localhost: bool = False,
        max_connections: int = DEFAULT_MAX_CONNECTIONS,
        timeout: int = DEFAULT_TIMEOUT,
        retry_attempts: int = DEFAULT_RETRY_ATTEMPTS,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
    ):
        """
        Initialize the async client.
        
        Args:
            api_url: Base URL of the API
            auth: Authentication strategy
            allow_insecure_localhost: Allow HTTP for localhost (dev only)
            max_connections: Maximum concurrent connections
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts
            ca_cert_path: Path to CA certificate
            client_cert_path: Path to client certificate (for mTLS)
            client_key_path: Path to client key (for mTLS)
        """
        self.api_url = api_url.rstrip('/')
        self.auth = auth
        self.allow_insecure_localhost = allow_insecure_localhost
        self.max_connections = max_connections
        self.timeout = ClientTimeout(total=timeout)
        self.retry_attempts = retry_attempts
        
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._validate_tls()
    
    def _validate_tls(self) -> None:
        """Validate TLS requirement."""
        parsed = urlparse(self.api_url)
        
        if parsed.scheme == 'https':
            return
        
        is_localhost = parsed.hostname in ('localhost', '127.0.0.1', '::1')
        
        if parsed.scheme == 'http' and is_localhost and self.allow_insecure_localhost:
            logger.warning("Using insecure HTTP for localhost - development only!")
            return
        
        raise ValueError(f"API URL must use HTTPS. Got: {self.api_url}")
    
    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for secure connections."""
        parsed = urlparse(self.api_url)
        
        if parsed.scheme != 'https':
            return None
        
        ssl_context = ssl.create_default_context()
        
        if self.ca_cert_path and Path(self.ca_cert_path).exists():
            ssl_context.load_verify_locations(self.ca_cert_path)
        
        if self.client_cert_path and self.client_key_path:
            if Path(self.client_cert_path).exists() and Path(self.client_key_path).exists():
                ssl_context.load_cert_chain(
                    self.client_cert_path,
                    self.client_key_path
                )
        
        return ssl_context
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None or self._session.closed:
            ssl_context = self._create_ssl_context()
            
            connector = TCPConnector(
                limit=self.max_connections,
                ssl=ssl_context,
                enable_cleanup_closed=True,
            )
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'SecureSys-Agent/2.0',
                **self.auth.get_headers(),
            }
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers=headers,
            )
        
        return self._session
    
    async def _request_with_retry(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """Make HTTP request with retry."""
        session = await self._get_session()
        last_exception = None
        
        for attempt in range(self.retry_attempts):
            try:
                async with session.request(method, url, **kwargs) as response:
                    body = await response.read()
                    response._body = body
                    return response
                    
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                wait_time = self.DEFAULT_RETRY_BACKOFF * (2 ** attempt)
                
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}. "
                    f"Retrying in {wait_time}s"
                )
                
                await asyncio.sleep(wait_time)
        
        raise last_exception or Exception("Request failed after retries")
    
    async def close(self):
        """Close the client session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    @abc.abstractmethod
    async def health_check(self) -> bool:
        """Check if API is accessible."""
        raise NotImplementedError


class ScanTypeRegistry:
    """
    Registry for scan type handlers.
    
    Allows adding new scan types without modifying client code.
    """
    
    _handlers: Dict[ScanType, type] = {}
    
    @classmethod
    def register(cls, scan_type: ScanType):
        """Decorator to register a scan handler."""
        def decorator(handler_class):
            cls._handlers[scan_type] = handler_class
            return handler_class
        return decorator
    
    @classmethod
    def get_handler(cls, scan_type: ScanType):
        """Get handler for scan type."""
        return cls._handlers.get(scan_type)
    
    @classmethod
    def list_types(cls) -> List[ScanType]:
        """List registered scan types."""
        return list(cls._handlers.keys())
