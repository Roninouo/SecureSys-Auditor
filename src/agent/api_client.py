"""
API Client for SecureSys Agent

Handles communication with the SecureSys Auditor backend API.
Implements TLS enforcement and HMAC-SHA256 payload signing for security.
"""

import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests


class SecureSysAPIClient:
    """
    Client for communicating with SecureSys Auditor API.

    Security features:
    - TLS enforcement: Only HTTPS endpoints are allowed (except localhost for dev)
    - HMAC-SHA256 signing: All scan submissions include signature for integrity
    - Timestamp headers: Prevents replay attacks
    """

    # Maximum age of request timestamp (5 minutes) to prevent replay attacks
    MAX_TIMESTAMP_AGE_SECONDS = 300

    def __init__(
        self,
        api_url: str,
        api_key: str,
        allow_insecure_localhost: bool = False
    ):
        """
        Initialize the API client.

        Args:
            api_url: The base URL of the SecureSys API
            api_key: API key for authentication (also used for HMAC signing)
            allow_insecure_localhost: Allow HTTP for localhost (dev only)

        Raises:
            ValueError: If api_url is not HTTPS (unless localhost with flag)
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self._allow_insecure_localhost = allow_insecure_localhost

        # Validate TLS requirement
        self._validate_tls()

        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        })

    def _validate_tls(self) -> None:
        """
        Validate that the API URL uses TLS (HTTPS).

        Raises:
            ValueError: If URL doesn't use HTTPS and isn't localhost
        """
        parsed = urlparse(self.api_url)

        if parsed.scheme == 'https':
            return

        # Allow localhost/127.0.0.1 for development if explicitly enabled
        is_localhost = parsed.hostname in ('localhost', '127.0.0.1', '::1')

        if parsed.scheme == 'http' and is_localhost and self._allow_insecure_localhost:
            return

        raise ValueError(
            f"API URL must use https:// for secure communication. "
            f"Got: {self.api_url}. "
            f"For local development, use allow_insecure_localhost=True."
        )

    def _generate_signature(
        self,
        payload: Dict[str, Any],
        timestamp: int
    ) -> str:
        """
        Generate HMAC-SHA256 signature for payload.

        The signature covers the JSON-serialized payload and timestamp
        to prevent tampering and replay attacks.

        Args:
            payload: The request payload to sign
            timestamp: Unix timestamp of the request

        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        # Create canonical string: timestamp + sorted JSON payload
        canonical_payload = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        message = f"{timestamp}.{canonical_payload}"

        signature = hmac.new(
            key=self.api_key.encode('utf-8'),
            msg=message.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest()

        return signature

    def health_check(self) -> bool:
        """Check if API is accessible."""
        try:
            response = self.session.get(
                f'{self.api_url}/api/v1/health/',
                timeout=10
            )
            return response.status_code == 200
        except Exception:
            return False

    def register_or_get_system(
        self,
        hostname: str,
        os: str,
        environment: str = 'production'
    ) -> Dict[str, Any]:
        """
        Register a new system or get existing one.
        """
        # First, try to find existing system
        try:
            response = self.session.get(
                f'{self.api_url}/api/v1/systems/',
                params={'hostname': hostname},
                timeout=10
            )

            if response.status_code == 200:
                systems = response.json()
                if isinstance(systems, list) and systems:
                    return systems[0]
                elif isinstance(systems, dict) and systems.get('results'):
                    return systems['results'][0]
        except Exception:
            pass

        # Register new system
        response = self.session.post(
            f'{self.api_url}/api/v1/systems/',
            json={
                'hostname': hostname,
                'os': os,
                'environment': environment,
            },
            timeout=10
        )

        if response.status_code in [200, 201]:
            return response.json()
        else:
            raise Exception(f'Failed to register system: {response.text}')

    def submit_scan(
        self,
        system_id: str,
        scan_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Submit a scan to the API for processing.

        The request is signed with HMAC-SHA256 using the API key.
        Headers included:
        - X-Signature: HMAC-SHA256 signature of timestamp.payload
        - X-Timestamp: Unix timestamp of request

        Args:
            system_id: ID of the system being scanned
            scan_payload: Scan data from the scanner

        Returns:
            API response containing scan ID and status

        Raises:
            Exception: If submission fails
        """
        timestamp = int(time.time())

        payload = {
            'system_id': system_id,
            'scan_payload': scan_payload,
        }

        signature = self._generate_signature(payload, timestamp)

        headers = {
            'X-Signature': signature,
            'X-Timestamp': str(timestamp),
        }

        response = self.session.post(
            f'{self.api_url}/api/v1/scans/submit/',
            json=payload,
            headers=headers,
            timeout=30
        )

        if response.status_code in [200, 201]:
            return response.json()
        else:
            raise Exception(f'Failed to submit scan: {response.text}')

    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status of a scan."""
        response = self.session.get(
            f'{self.api_url}/api/v1/scans/{scan_id}/',
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f'Failed to get scan status: {response.text}')
