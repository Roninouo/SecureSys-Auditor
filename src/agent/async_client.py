"""
Enhanced Async API Client for SecureSys Agent

High-performance async HTTP client using aiohttp for:
- Concurrent scan submissions
- Non-blocking I/O operations
- Connection pooling
- Automatic retries with exponential backoff

Security features:
- TLS certificate verification
- HMAC-SHA256 payload signing
- Mutual TLS support (optional)
"""

import asyncio
import hashlib
import hmac
import json
import logging
import ssl
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

logger = logging.getLogger(__name__)


class AsyncSecureSysClient:
    """
    High-performance async client for SecureSys API.

    Features:
    - Connection pooling with configurable limits
    - Automatic retries with exponential backoff
    - TLS enforcement with certificate verification
    - HMAC-SHA256 request signing
    - Concurrent operations support
    """

    # Default configuration
    DEFAULT_TIMEOUT = 30
    DEFAULT_MAX_CONNECTIONS = 10
    DEFAULT_RETRY_ATTEMPTS = 3
    DEFAULT_RETRY_BACKOFF = 1.0

    def __init__(
        self,
        api_url: str,
        api_key: str,
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
        Initialize the async API client.

        Args:
            api_url: Base URL of the SecureSys API
            api_key: API key for authentication and signing
            allow_insecure_localhost: Allow HTTP for localhost (dev only)
            max_connections: Maximum concurrent connections
            timeout: Request timeout in seconds
            retry_attempts: Number of retry attempts on failure
            ca_cert_path: Path to CA certificate for verification
            client_cert_path: Path to client certificate (for mTLS)
            client_key_path: Path to client key (for mTLS)
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.allow_insecure_localhost = allow_insecure_localhost
        self.max_connections = max_connections
        self.timeout = ClientTimeout(total=timeout)
        self.retry_attempts = retry_attempts

        # TLS configuration
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path

        # Session will be created on first use
        self._session: Optional[aiohttp.ClientSession] = None
        self._validate_tls()

    def _validate_tls(self) -> None:
        """Validate TLS requirement for the API URL."""
        parsed = urlparse(self.api_url)

        if parsed.scheme == "https":
            return

        is_localhost = parsed.hostname in ("localhost", "127.0.0.1", "::1")

        if parsed.scheme == "http" and is_localhost and self.allow_insecure_localhost:
            logger.warning("Using insecure HTTP for localhost - for development only!")
            return

        raise ValueError(f"API URL must use HTTPS for secure communication. Got: {self.api_url}")

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for secure connections."""
        parsed = urlparse(self.api_url)

        if parsed.scheme != "https":
            return None

        ssl_context = ssl.create_default_context()

        # Load CA certificate if provided
        if self.ca_cert_path and Path(self.ca_cert_path).exists():
            ssl_context.load_verify_locations(self.ca_cert_path)
            logger.info(f"Loaded CA certificate from {self.ca_cert_path}")

        # Load client certificate for mTLS if provided
        if self.client_cert_path and self.client_key_path:
            if Path(self.client_cert_path).exists() and Path(self.client_key_path).exists():
                ssl_context.load_cert_chain(self.client_cert_path, self.client_key_path)
                logger.info("Loaded client certificate for mTLS")

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

            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "SecureSys-Agent/2.0",
                },
            )

        return self._session

    def _generate_signature(self, payload: Dict[str, Any], timestamp: int) -> str:
        """Generate HMAC-SHA256 signature for payload."""
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        message = f"{timestamp}.{canonical_payload}"

        signature = hmac.new(
            key=self.api_key.encode("utf-8"), msg=message.encode("utf-8"), digestmod=hashlib.sha256
        ).hexdigest()

        return signature

    async def _request_with_retry(self, method: str, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Make HTTP request with automatic retry on failure."""
        session = await self._get_session()
        last_exception = None

        for attempt in range(self.retry_attempts):
            try:
                async with session.request(method, url, **kwargs) as response:
                    # Read response body before returning
                    body = await response.read()
                    response._body = body
                    return response

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                wait_time = self.DEFAULT_RETRY_BACKOFF * (2**attempt)

                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{self.retry_attempts}): {e}. Retrying in {wait_time}s"
                )

                await asyncio.sleep(wait_time)

        raise last_exception or Exception("Request failed after retries")

    async def health_check(self) -> bool:
        """Check if API is accessible."""
        try:
            response = await self._request_with_retry("GET", f"{self.api_url}/api/v1/health/")
            return response.status == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False

    async def register_or_get_system(self, hostname: str, os: str, environment: str = "production") -> Dict[str, Any]:
        """Register a new system or get existing one."""
        # Try to find existing system
        try:
            response = await self._request_with_retry(
                "GET", f"{self.api_url}/api/v1/systems/", params={"hostname": hostname}
            )

            if response.status == 200:
                data = json.loads(response._body)
                if isinstance(data, list) and data:
                    return data[0]
                elif isinstance(data, dict) and data.get("results"):
                    return data["results"][0]
        except Exception:
            pass

        # Register new system
        response = await self._request_with_retry(
            "POST",
            f"{self.api_url}/api/v1/systems/",
            json={
                "hostname": hostname,
                "os": os,
                "environment": environment,
            },
        )

        if response.status in [200, 201]:
            return json.loads(response._body)
        else:
            raise Exception(f"Failed to register system: {response._body.decode()}")

    async def submit_scan(self, system_id: str, scan_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a scan with HMAC signature."""
        timestamp = int(time.time())

        payload = {
            "system_id": system_id,
            "scan_payload": scan_payload,
        }

        signature = self._generate_signature(payload, timestamp)

        response = await self._request_with_retry(
            "POST",
            f"{self.api_url}/api/v1/scans/submit/",
            json=payload,
            headers={
                "X-Signature": signature,
                "X-Timestamp": str(timestamp),
            },
        )

        if response.status in [200, 201]:
            return json.loads(response._body)
        else:
            raise Exception(f"Failed to submit scan: {response._body.decode()}")

    async def submit_scans_batch(self, scans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Submit multiple scans concurrently.

        Args:
            scans: List of dicts with 'system_id' and 'scan_payload'

        Returns:
            List of API responses
        """
        tasks = [self.submit_scan(scan["system_id"], scan["scan_payload"]) for scan in scans]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        return [result if not isinstance(result, Exception) else {"error": str(result)} for result in results]

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status of a scan."""
        response = await self._request_with_retry("GET", f"{self.api_url}/api/v1/scans/{scan_id}/")

        if response.status == 200:
            return json.loads(response._body)
        else:
            raise Exception(f"Failed to get scan status: {response._body.decode()}")

    async def wait_for_scan_completion(
        self, scan_id: str, poll_interval: float = 2.0, timeout: float = 300.0
    ) -> Dict[str, Any]:
        """
        Wait for a scan to complete with polling.

        Args:
            scan_id: ID of the scan to wait for
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait

        Returns:
            Final scan status

        Raises:
            TimeoutError: If scan doesn't complete within timeout
        """
        start_time = time.time()

        while (time.time() - start_time) < timeout:
            status = await self.get_scan_status(scan_id)

            if status.get("status") in ["completed", "failed"]:
                return status

            await asyncio.sleep(poll_interval)

        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout}s")

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


async def run_scan_async(api_url: str, api_key: str, minimal_telemetry: bool = True, **client_kwargs) -> Dict[str, Any]:
    """
    Run a complete scan workflow asynchronously.

    This function:
    1. Collects system data
    2. Registers/gets system
    3. Submits scan
    4. Waits for completion

    Args:
        api_url: SecureSys API URL
        api_key: API key
        minimal_telemetry: Filter sensitive data
        **client_kwargs: Additional client configuration

    Returns:
        Completed scan results
    """
    from scanner import SystemScanner

    async with AsyncSecureSysClient(api_url, api_key, **client_kwargs) as client:
        # Check API health
        if not await client.health_check():
            raise Exception("API is not accessible")

        # Collect system data
        scanner = SystemScanner(minimal_telemetry=minimal_telemetry)
        scan_data = scanner.collect_all()

        # Register system
        system = await client.register_or_get_system(
            hostname=scan_data["hostname"], os=scan_data["os"]["name"], environment="production"
        )

        # Submit scan
        scan_result = await client.submit_scan(system_id=system["id"], scan_payload=scan_data)

        # Wait for completion
        final_result = await client.wait_for_scan_completion(scan_id=scan_result["id"], timeout=120.0)

        return final_result
