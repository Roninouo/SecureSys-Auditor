"""
Async API Client Implementation.

Extends base client with SecureSys-specific operations.
"""
import json
import logging
import time
from typing import Any, Dict, List, Optional

from .base import BaseAsyncClient, BearerTokenAuth, ScanType

logger = logging.getLogger(__name__)


class AsyncSecureSysClient(BaseAsyncClient):
    """
    High-performance async client for SecureSys API.
    
    Features:
    - Connection pooling with configurable limits
    - Automatic retries with exponential backoff
    - TLS enforcement with certificate verification
    - HMAC-SHA256 request signing
    - Concurrent operations support
    - Extensible scan type support
    """
    
    def __init__(
        self,
        api_url: str,
        api_key: str,
        **kwargs
    ):
        """
        Initialize the SecureSys client.
        
        Args:
            api_url: Base URL of the SecureSys API
            api_key: API key for authentication
            **kwargs: Additional configuration (see BaseAsyncClient)
        """
        auth = BearerTokenAuth(api_key)
        super().__init__(api_url, auth, **kwargs)
        self.api_key = api_key
    
    async def health_check(self) -> bool:
        """Check if API is accessible."""
        try:
            response = await self._request_with_retry(
                'GET',
                f'{self.api_url}/api/v1/health/'
            )
            return response.status == 200
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return False
    
    async def register_or_get_system(
        self,
        hostname: str,
        os: str,
        environment: str = 'production'
    ) -> Dict[str, Any]:
        """Register a new system or get existing one."""
        # Try to find existing
        try:
            response = await self._request_with_retry(
                'GET',
                f'{self.api_url}/api/v1/scanning/systems/by_hostname/',
                params={'hostname': hostname}
            )
            
            if response.status == 200:
                data = json.loads(response._body)
                return data
        except Exception:
            pass
        
        # Register new
        response = await self._request_with_retry(
            'POST',
            f'{self.api_url}/api/v1/scanning/systems/',
            json={
                'hostname': hostname,
                'os': os,
                'environment': environment,
            }
        )
        
        if response.status in [200, 201]:
            return json.loads(response._body)
        else:
            raise Exception(f'Failed to register system: {response._body.decode()}')
    
    async def submit_scan(
        self,
        system_id: str,
        scan_payload: Dict[str, Any],
        scan_type: ScanType = ScanType.FULL
    ) -> Dict[str, Any]:
        """
        Submit a scan with HMAC signature.
        
        Args:
            system_id: ID of the system being scanned
            scan_payload: Scan data from scanner
            scan_type: Type of scan being submitted
            
        Returns:
            API response with scan ID and status
        """
        timestamp = int(time.time())
        
        payload = {
            'system_id': system_id,
            'scan_payload': scan_payload,
            'scan_type': scan_type.value,
        }
        
        signature = self.auth.sign_payload(payload, timestamp)
        
        response = await self._request_with_retry(
            'POST',
            f'{self.api_url}/api/v1/scanning/scans/submit/',
            json=payload,
            headers={
                'X-Signature': signature,
                'X-Timestamp': str(timestamp),
            }
        )
        
        if response.status in [200, 201]:
            return json.loads(response._body)
        else:
            raise Exception(f'Failed to submit scan: {response._body.decode()}')
    
    async def submit_scans_batch(
        self,
        scans: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Submit multiple scans concurrently.
        
        Args:
            scans: List of dicts with 'system_id' and 'scan_payload'
            
        Returns:
            List of API responses
        """
        import asyncio
        
        tasks = [
            self.submit_scan(
                scan['system_id'],
                scan['scan_payload'],
                scan.get('scan_type', ScanType.FULL)
            )
            for scan in scans
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [
            result if not isinstance(result, Exception) else {'error': str(result)}
            for result in results
        ]
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get the status of a scan."""
        response = await self._request_with_retry(
            'GET',
            f'{self.api_url}/api/v1/scanning/scans/{scan_id}/'
        )
        
        if response.status == 200:
            return json.loads(response._body)
        else:
            raise Exception(f'Failed to get scan status: {response._body.decode()}')
    
    async def wait_for_scan_completion(
        self,
        scan_id: str,
        poll_interval: float = 2.0,
        timeout: float = 300.0
    ) -> Dict[str, Any]:
        """
        Wait for a scan to complete with polling.
        
        Args:
            scan_id: ID of the scan
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait
            
        Returns:
            Final scan status
            
        Raises:
            TimeoutError: If scan doesn't complete within timeout
        """
        import asyncio
        
        start_time = time.time()
        
        while (time.time() - start_time) < timeout:
            status = await self.get_scan_status(scan_id)
            
            if status.get('status') in ['completed', 'failed']:
                return status
            
            await asyncio.sleep(poll_interval)
        
        raise TimeoutError(f"Scan {scan_id} did not complete within {timeout}s")
    
    async def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get findings with optional filters.
        
        Args:
            scan_id: Filter by scan ID
            severity: Filter by severity
            limit: Maximum number of findings
            
        Returns:
            List of findings
        """
        params = {'limit': limit}
        
        if scan_id:
            params['scan'] = scan_id
        if severity:
            params['severity'] = severity
        
        response = await self._request_with_retry(
            'GET',
            f'{self.api_url}/api/v1/scanning/findings/',
            params=params
        )
        
        if response.status == 200:
            data = json.loads(response._body)
            return data.get('results', data) if isinstance(data, dict) else data
        else:
            raise Exception(f'Failed to get findings: {response._body.decode()}')


async def run_scan_async(
    api_url: str,
    api_key: str,
    scan_type: ScanType = ScanType.FULL,
    minimal_telemetry: bool = True,
    **client_kwargs
) -> Dict[str, Any]:
    """
    Run a complete scan workflow asynchronously.
    
    Steps:
    1. Collect system data
    2. Register/get system
    3. Submit scan
    4. Wait for completion
    
    Args:
        api_url: SecureSys API URL
        api_key: API key
        scan_type: Type of scan to run
        minimal_telemetry: Filter sensitive data
        **client_kwargs: Additional client configuration
        
    Returns:
        Completed scan results
    """
    from scanner import SystemScanner
    
    async with AsyncSecureSysClient(api_url, api_key, **client_kwargs) as client:
        # Check health
        if not await client.health_check():
            raise Exception("API is not accessible")
        
        # Collect data
        scanner = SystemScanner(minimal_telemetry=minimal_telemetry)
        scan_data = scanner.collect_all()
        
        # Register system
        system = await client.register_or_get_system(
            hostname=scan_data['hostname'],
            os=scan_data['os']['name'],
            environment='production'
        )
        
        # Submit scan
        scan_result = await client.submit_scan(
            system_id=system['id'],
            scan_payload=scan_data,
            scan_type=scan_type
        )
        
        # Wait for completion
        final_result = await client.wait_for_scan_completion(
            scan_id=scan_result['scan_id'],
            timeout=120.0
        )
        
        return final_result
