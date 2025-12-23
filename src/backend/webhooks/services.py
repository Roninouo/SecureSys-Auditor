"""
Webhook Service Layer.

Handles webhook delivery with:
- HMAC signing
- Retry logic
- Circuit breaker pattern
- Connection pooling
"""
import hashlib
import hmac
import json
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from django.conf import settings
from django.utils import timezone

from .models import WebhookEndpoint, WebhookDelivery

logger = logging.getLogger(__name__)


@dataclass
class DeliveryResult:
    """Result of a webhook delivery attempt."""
    endpoint_id: str
    endpoint_url: str
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


class WebhookService:
    """
    Webhook delivery service with connection pooling.
    
    Uses a shared session with retry configuration
    for better performance at scale.
    """
    
    def __init__(self):
        """Initialize with connection pool."""
        self._session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """
        Create HTTP session with connection pooling and retry.
        
        Uses a shared pool to avoid connection exhaustion at scale.
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=0,  # We handle retries in Celery
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )
        
        # Mount adapter with connection pool
        adapter = HTTPAdapter(
            pool_connections=10,
            pool_maxsize=100,
            max_retries=retry_strategy,
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        return session
    
    def deliver(
        self,
        endpoint: WebhookEndpoint,
        event_type: str,
        payload: Dict[str, Any]
    ) -> DeliveryResult:
        """
        Deliver webhook to an endpoint.
        
        Args:
            endpoint: WebhookEndpoint to deliver to
            event_type: Type of event
            payload: Event payload data
            
        Returns:
            DeliveryResult with status
        """
        # Check circuit breaker
        if endpoint.is_circuit_open():
            logger.info(f"Circuit open for {endpoint.name}, skipping delivery")
            return DeliveryResult(
                endpoint_id=str(endpoint.id),
                endpoint_url=endpoint.url,
                success=False,
                error="Circuit breaker open"
            )
        
        # Build webhook payload
        webhook_payload = {
            'event_type': event_type,
            'timestamp': timezone.now().isoformat(),
            'data': payload,
        }
        
        # Sign payload
        signature = self._sign_payload(webhook_payload, endpoint.secret)
        
        # Build headers
        headers = {
            'Content-Type': 'application/json',
            'X-SecureSys-Event': event_type,
            'X-SecureSys-Signature': f'sha256={signature}',
            'X-SecureSys-Timestamp': str(int(timezone.now().timestamp())),
            'User-Agent': 'SecureSys-Webhook/2.0',
        }
        
        # Add custom headers
        if endpoint.headers:
            headers.update(endpoint.headers)
        
        try:
            response = self._session.post(
                endpoint.url,
                json=webhook_payload,
                headers=headers,
                timeout=30
            )
            
            success = response.status_code < 400
            
            if success:
                endpoint.record_success(response.status_code)
            else:
                endpoint.record_failure(response.status_code)
            
            logger.info(f"Webhook delivered to {endpoint.url}", extra={
                'event_type': event_type,
                'status_code': response.status_code,
                'success': success,
            })
            
            return DeliveryResult(
                endpoint_id=str(endpoint.id),
                endpoint_url=endpoint.url,
                success=success,
                status_code=response.status_code,
            )
            
        except requests.RequestException as e:
            endpoint.record_failure()
            
            logger.error(f"Webhook delivery failed: {endpoint.url}", extra={
                'error': str(e),
                'event_type': event_type,
            })
            
            return DeliveryResult(
                endpoint_id=str(endpoint.id),
                endpoint_url=endpoint.url,
                success=False,
                error=str(e),
            )
    
    def deliver_to_all(
        self,
        event_type: str,
        payload: Dict[str, Any]
    ) -> List[DeliveryResult]:
        """
        Deliver webhook to all active endpoints subscribed to event type.
        
        Args:
            event_type: Type of event
            payload: Event payload data
            
        Returns:
            List of DeliveryResult for each endpoint
        """
        endpoints = WebhookEndpoint.objects.filter(
            is_active=True,
            event_types__contains=[event_type]
        )
        
        results = []
        for endpoint in endpoints:
            result = self.deliver(endpoint, event_type, payload)
            results.append(result)
            
            # Track delivery
            WebhookDelivery.objects.create(
                endpoint=endpoint,
                event_type=event_type,
                payload=payload,
                status=(
                    WebhookDelivery.Status.SUCCESS if result.success
                    else WebhookDelivery.Status.FAILED
                ),
                status_code=result.status_code,
                error_message=result.error or '',
                attempt_count=1,
                delivered_at=timezone.now() if result.success else None,
            )
        
        return results
    
    def _sign_payload(
        self,
        payload: Dict[str, Any],
        secret: Optional[str]
    ) -> str:
        """
        Sign payload with HMAC-SHA256.
        
        Uses endpoint secret or global WEBHOOK_SECRET.
        """
        secret_key = secret or getattr(settings, 'WEBHOOK_SECRET', 'default-secret')
        payload_json = json.dumps(payload, sort_keys=True)
        
        return hmac.new(
            secret_key.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()


# Singleton instance
_webhook_service: Optional[WebhookService] = None


def get_webhook_service() -> WebhookService:
    """Get the webhook service singleton."""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    return _webhook_service
