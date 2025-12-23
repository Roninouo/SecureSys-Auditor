"""
API Client for SecureSys Agent

Handles communication with the SecureSys Auditor backend API.
"""

import requests
from typing import Dict, Any, Optional


class SecureSysAPIClient:
    """
    Client for communicating with SecureSys Auditor API.
    """
    
    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        })
    
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
        """
        response = self.session.post(
            f'{self.api_url}/api/v1/scans/submit/',
            json={
                'system_id': system_id,
                'scan_payload': scan_payload,
            },
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
