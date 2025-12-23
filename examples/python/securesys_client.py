"""
SecureSys Auditor Python Client

A simple, easy-to-use Python client for the SecureSys Auditor API.

Usage:
    from securesys_client import SecureSysClient
    
    client = SecureSysClient(api_url="https://api.securesys.io", api_key="your-key")
    
    # Submit a scan
    scan = client.submit_scan(
        hostname="webserver-01.example.com",
        scan_type="vulnerability",
        findings=[
            {"title": "CVE-2023-1234", "severity": "high", "description": "..."}
        ]
    )
    
    # Get scan status
    status = client.get_scan(scan["id"])
    
    # List all scans
    scans = client.list_scans(page=1, page_size=20)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Represents a security finding."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    recommendation: str = ""
    affected_component: str = ""
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "recommendation": self.recommendation,
            "affected_component": self.affected_component,
            "cve_id": self.cve_id,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ScanResult:
    """Represents a scan result."""
    id: str
    hostname: str
    scan_type: str
    status: str
    created_at: str
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        return cls(
            id=data["id"],
            hostname=data["hostname"],
            scan_type=data["scan_type"],
            status=data["status"],
            created_at=data["created_at"],
            findings_count=data.get("findings_count", 0),
            critical_count=data.get("critical_count", 0),
            high_count=data.get("high_count", 0),
            medium_count=data.get("medium_count", 0),
            low_count=data.get("low_count", 0),
        )


class SecureSysError(Exception):
    """Base exception for SecureSys client errors."""
    def __init__(self, message: str, status_code: Optional[int] = None, response: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class AuthenticationError(SecureSysError):
    """Raised when authentication fails."""
    pass


class RateLimitError(SecureSysError):
    """Raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: Optional[int] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ValidationError(SecureSysError):
    """Raised when request validation fails."""
    pass


class SecureSysClient:
    """
    SecureSys Auditor API Client.
    
    Example:
        client = SecureSysClient(
            api_url="https://api.securesys.io",
            api_key="your-api-key"
        )
        
        # Submit a scan
        scan = client.submit_scan(
            hostname="server.example.com",
            scan_type="vulnerability",
            findings=[Finding(title="CVE-2023-1234", severity="high", description="...")]
        )
    """
    
    DEFAULT_TIMEOUT = 30
    DEFAULT_RETRIES = 3
    
    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: int = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        verify_ssl: bool = True,
    ):
        """
        Initialize the SecureSys client.
        
        Args:
            api_url: Base URL of the SecureSys API
            api_key: API key for authentication
            timeout: Request timeout in seconds
            retries: Number of retries for failed requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Configure session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "SecureSys-Python-Client/1.0",
        })
    
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make an API request."""
        url = urljoin(self.api_url + "/", endpoint.lstrip("/"))
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            # Handle errors
            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication failed. Check your API key.",
                    status_code=401
                )
            elif response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                raise RateLimitError(
                    "Rate limit exceeded.",
                    status_code=429,
                    retry_after=int(retry_after) if retry_after else None
                )
            elif response.status_code == 400:
                raise ValidationError(
                    f"Validation error: {response.text}",
                    status_code=400,
                    response=response.json() if response.text else None
                )
            elif response.status_code >= 400:
                raise SecureSysError(
                    f"API error: {response.text}",
                    status_code=response.status_code
                )
            
            if response.text:
                return response.json()
            return {}
            
        except requests.exceptions.Timeout:
            raise SecureSysError("Request timed out")
        except requests.exceptions.ConnectionError:
            raise SecureSysError("Connection failed")
    
    # =========================================================================
    # Health & Status
    # =========================================================================
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        return self._request("GET", "/api/v1/health/")
    
    # =========================================================================
    # Scans
    # =========================================================================
    
    def submit_scan(
        self,
        hostname: str,
        scan_type: str = "vulnerability",
        findings: Optional[List[Union[Finding, Dict]]] = None,
        agent_version: str = "python-client-1.0",
        metadata: Optional[Dict] = None,
    ) -> ScanResult:
        """
        Submit a new security scan.
        
        Args:
            hostname: Target hostname
            scan_type: Type of scan (vulnerability, compliance, configuration)
            findings: List of findings (Finding objects or dicts)
            agent_version: Version of the scanning agent
            metadata: Additional metadata
        
        Returns:
            ScanResult object with scan details
        """
        # Convert Finding objects to dicts
        findings_data = []
        if findings:
            for f in findings:
                if isinstance(f, Finding):
                    findings_data.append(f.to_dict())
                else:
                    findings_data.append(f)
        
        data = {
            "hostname": hostname,
            "scan_type": scan_type,
            "agent_version": agent_version,
            "started_at": datetime.utcnow().isoformat() + "Z",
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "findings": findings_data,
            "metadata": metadata or {},
        }
        
        result = self._request("POST", "/api/v1/scans/", data=data)
        return ScanResult.from_dict(result)
    
    def get_scan(self, scan_id: str) -> ScanResult:
        """Get details of a specific scan."""
        result = self._request("GET", f"/api/v1/scans/{scan_id}/")
        return ScanResult.from_dict(result)
    
    def list_scans(
        self,
        page: int = 1,
        page_size: int = 20,
        hostname: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List scans with pagination and filtering.
        
        Args:
            page: Page number
            page_size: Number of results per page
            hostname: Filter by hostname
            status: Filter by status
        
        Returns:
            Dict with 'results' list and pagination info
        """
        params = {"page": page, "page_size": page_size}
        if hostname:
            params["hostname"] = hostname
        if status:
            params["status"] = status
        
        return self._request("GET", "/api/v1/scans/", params=params)
    
    def get_scan_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get findings for a specific scan."""
        result = self._request("GET", f"/api/v1/scans/{scan_id}/findings/")
        return result.get("results", [])
    
    # =========================================================================
    # Systems
    # =========================================================================
    
    def list_systems(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """List all systems."""
        return self._request("GET", "/api/v1/systems/", params={"page": page, "page_size": page_size})
    
    def get_system(self, system_id: str) -> Dict[str, Any]:
        """Get details of a specific system."""
        return self._request("GET", f"/api/v1/systems/{system_id}/")
    
    # =========================================================================
    # Dashboard
    # =========================================================================
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get dashboard statistics."""
        return self._request("GET", "/api/v1/dashboard/stats/")
    
    def get_severity_breakdown(self) -> Dict[str, Any]:
        """Get severity breakdown for findings."""
        return self._request("GET", "/api/v1/dashboard/severity-breakdown/")
    
    # =========================================================================
    # Webhooks
    # =========================================================================
    
    def list_webhooks(self) -> List[Dict[str, Any]]:
        """List configured webhooks."""
        result = self._request("GET", "/api/v1/webhooks/")
        return result.get("results", [])
    
    def create_webhook(
        self,
        name: str,
        url: str,
        event_types: List[str],
        secret: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new webhook endpoint.
        
        Args:
            name: Webhook name
            url: Webhook URL
            event_types: List of events to subscribe to
            secret: HMAC secret for signing payloads
        """
        data = {
            "name": name,
            "url": url,
            "event_types": event_types,
        }
        if secret:
            data["secret"] = secret
        
        return self._request("POST", "/api/v1/webhooks/", data=data)


# Convenience function for quick usage
def create_client(api_url: str, api_key: str, **kwargs) -> SecureSysClient:
    """Create a SecureSys client with default settings."""
    return SecureSysClient(api_url=api_url, api_key=api_key, **kwargs)


if __name__ == "__main__":
    # Example usage
    import os
    
    client = SecureSysClient(
        api_url=os.environ.get("SECURESYS_API_URL", "http://localhost:8000"),
        api_key=os.environ.get("SECURESYS_API_KEY", "test-key"),
    )
    
    # Check health
    print("Health:", client.health_check())
    
    # Submit a scan
    scan = client.submit_scan(
        hostname="example-server.local",
        scan_type="vulnerability",
        findings=[
            Finding(
                title="CVE-2023-1234",
                severity="high",
                description="Example vulnerability",
                recommendation="Update to latest version",
            )
        ],
    )
    print(f"Submitted scan: {scan.id}")
