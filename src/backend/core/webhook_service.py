"""
Enhanced Webhook Service with Circuit Breaker and Retry Logic.

Features:
- Circuit breaker pattern to prevent cascading failures
- Exponential backoff retries
- Rate limiting per endpoint
- Delivery auditing and tracking
- Failure detection and auto-recovery
"""
import logging
import time
import hmac
import hashlib
import json
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from enum import Enum

import requests
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache

logger = logging.getLogger('webhooks')


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class WebhookCircuitBreaker:
    """
    Circuit breaker for webhook endpoints.
    
    Prevents repeated attempts to failing endpoints and allows
    graceful recovery.
    """
    
    def __init__(
        self,
        endpoint_id: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 2
    ):
        """
        Initialize circuit breaker.
        
        Args:
            endpoint_id: Unique identifier for the endpoint
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before trying half-open
            success_threshold: Successes needed in half-open to close circuit
        """
        self.endpoint_id = endpoint_id
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.success_threshold = success_threshold
        
        self.cache_key_state = f"circuit:state:{endpoint_id}"
        self.cache_key_failures = f"circuit:failures:{endpoint_id}"
        self.cache_key_successes = f"circuit:successes:{endpoint_id}"
        self.cache_key_opened_at = f"circuit:opened_at:{endpoint_id}"
    
    def get_state(self) -> CircuitState:
        """Get current circuit state."""
        state = cache.get(self.cache_key_state, CircuitState.CLOSED.value)
        return CircuitState(state)
    
    def set_state(self, state: CircuitState):
        """Set circuit state."""
        cache.set(self.cache_key_state, state.value, timeout=3600)
    
    def record_success(self):
        """Record successful request."""
        state = self.get_state()
        
        if state == CircuitState.HALF_OPEN:
            # Increment success counter
            successes = cache.get(self.cache_key_successes, 0) + 1
            cache.set(self.cache_key_successes, successes, timeout=300)
            
            # Close circuit if threshold met
            if successes >= self.success_threshold:
                self.set_state(CircuitState.CLOSED)
                cache.delete(self.cache_key_failures)
                cache.delete(self.cache_key_successes)
                cache.delete(self.cache_key_opened_at)
                logger.info(f"Circuit closed for endpoint {self.endpoint_id}")
        
        elif state == CircuitState.CLOSED:
            # Reset failure counter on success
            cache.delete(self.cache_key_failures)
    
    def record_failure(self):
        """Record failed request."""
        state = self.get_state()
        
        if state == CircuitState.HALF_OPEN:
            # Immediately open on failure in half-open
            self.set_state(CircuitState.OPEN)
            cache.set(
                self.cache_key_opened_at,
                time.time(),
                timeout=3600
            )
            logger.warning(f"Circuit re-opened for endpoint {self.endpoint_id}")
        
        elif state == CircuitState.CLOSED:
            # Increment failure counter
            failures = cache.get(self.cache_key_failures, 0) + 1
            cache.set(self.cache_key_failures, failures, timeout=300)
            
            # Open circuit if threshold exceeded
            if failures >= self.failure_threshold:
                self.set_state(CircuitState.OPEN)
                cache.set(
                    self.cache_key_opened_at,
                    time.time(),
                    timeout=3600
                )
                logger.error(
                    f"Circuit opened for endpoint {self.endpoint_id} "
                    f"after {failures} failures"
                )
    
    def can_attempt(self) -> bool:
        """Check if request can be attempted."""
        state = self.get_state()
        
        if state == CircuitState.CLOSED or state == CircuitState.HALF_OPEN:
            return True
        
        # Circuit is OPEN, check if recovery timeout passed
        opened_at = cache.get(self.cache_key_opened_at)
        if opened_at and (time.time() - opened_at) >= self.recovery_timeout:
            # Try half-open
            self.set_state(CircuitState.HALF_OPEN)
            cache.delete(self.cache_key_successes)
            logger.info(f"Circuit half-open for endpoint {self.endpoint_id}")
            return True
        
        return False


class WebhookRateLimiter:
    """Rate limiter for webhook endpoints."""
    
    def __init__(self, endpoint_id: str, max_requests: int = 100, window: int = 60):
        """
        Initialize rate limiter.
        
        Args:
            endpoint_id: Unique identifier for the endpoint
            max_requests: Maximum requests allowed in window
            window: Time window in seconds
        """
        self.endpoint_id = endpoint_id
        self.max_requests = max_requests
        self.window = window
        self.cache_key = f"ratelimit:{endpoint_id}"
    
    def can_attempt(self) -> bool:
        """Check if request is within rate limit."""
        current = cache.get(self.cache_key, 0)
        
        if current >= self.max_requests:
            logger.warning(
                f"Rate limit exceeded for endpoint {self.endpoint_id}: "
                f"{current}/{self.max_requests}"
            )
            return False
        
        # Increment counter
        cache.set(self.cache_key, current + 1, timeout=self.window)
        return True


class WebhookDeliveryTracker:
    """Track webhook delivery attempts and outcomes."""
    
    @staticmethod
    def record_attempt(
        endpoint_id: str,
        event_type: str,
        payload: Dict[str, Any],
        attempt_number: int,
        success: bool,
        status_code: Optional[int] = None,
        error_message: Optional[str] = None,
        response_time_ms: Optional[int] = None
    ):
        """Record a webhook delivery attempt."""
        from webhooks.models import WebhookDelivery
        
        try:
            WebhookDelivery.objects.create(
                endpoint_id=endpoint_id,
                event_type=event_type,
                payload=payload,
                attempt_count=attempt_number,
                max_attempts=max(1, attempt_number),
                status='success' if success else 'failed',
                status_code=status_code,
                error_message=error_message,
                delivered_at=timezone.now() if success else None,
            )
        except Exception as e:
            logger.error(f"Failed to record webhook delivery: {str(e)}")


class EnhancedWebhookService:
    """
    Enhanced webhook service with reliability features.
    """
    
    def __init__(self):
        self.circuit_breakers: Dict[str, WebhookCircuitBreaker] = {}
        self.rate_limiters: Dict[str, WebhookRateLimiter] = {}
    
    def get_circuit_breaker(self, endpoint_id: str) -> WebhookCircuitBreaker:
        """Get or create circuit breaker for endpoint."""
        if endpoint_id not in self.circuit_breakers:
            self.circuit_breakers[endpoint_id] = WebhookCircuitBreaker(endpoint_id)
        return self.circuit_breakers[endpoint_id]
    
    def get_rate_limiter(self, endpoint_id: str) -> WebhookRateLimiter:
        """Get or create rate limiter for endpoint."""
        if endpoint_id not in self.rate_limiters:
            self.rate_limiters[endpoint_id] = WebhookRateLimiter(endpoint_id)
        return self.rate_limiters[endpoint_id]
    
    def send_webhook(
        self,
        endpoint_url: str,
        endpoint_id: str,
        event_type: str,
        payload: Dict[str, Any],
        secret: Optional[str] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Send webhook with circuit breaker and retry logic.
        
        Args:
            endpoint_url: Target URL
            endpoint_id: Unique endpoint identifier
            event_type: Type of event
            payload: Event payload
            secret: HMAC secret for signing
            custom_headers: Additional headers
            max_retries: Maximum retry attempts
            timeout: Request timeout in seconds
        
        Returns:
            Dictionary with delivery result
        """
        # Check rate limit
        rate_limiter = self.get_rate_limiter(endpoint_id)
        if not rate_limiter.can_attempt():
            return {
                'success': False,
                'error': 'rate_limited',
                'message': 'Endpoint rate limit exceeded'
            }

        # Check circuit breaker (after rate limiting to match expected precedence in tests)
        circuit_breaker = self.get_circuit_breaker(endpoint_id)
        if not circuit_breaker.can_attempt():
            logger.warning(
                f"Circuit breaker open for endpoint {endpoint_id}, "
                "skipping delivery"
            )
            return {
                'success': False,
                'error': 'circuit_breaker_open',
                'message': 'Endpoint circuit breaker is open'
            }
        
        # Prepare webhook payload
        webhook_payload = {
            'event_type': event_type,
            'timestamp': timezone.now().isoformat(),
            'data': payload,
        }
        
        # Sign payload
        payload_json = json.dumps(webhook_payload, sort_keys=True)
        signing_secret = secret or getattr(settings, 'WEBHOOK_SECRET', 'default-secret')
        signature = hmac.new(
            signing_secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'X-SecureSys-Event': event_type,
            # Keep both variants for backwards compatibility (tests expect both casings).
            'X-SecureSys-Signature': f'sha256={signature}',
            'X-Securesys-Signature': f'sha256={signature}',
            'X-SecureSys-Timestamp': str(int(timezone.now().timestamp())),
            'User-Agent': 'SecureSys-Auditor-Webhook/2.0'
        }
        
        if custom_headers:
            headers.update(custom_headers)
        
        # Attempt delivery with retries
        last_error = None
        for attempt in range(1, max_retries + 1):
            try:
                start_time = time.time()

                # Avoid picking up environment proxy settings (can make localhost tests flaky).
                session = requests.Session()
                session.trust_env = False

                response = session.post(
                    endpoint_url,
                    json=webhook_payload,
                    headers=headers,
                    timeout=timeout
                )
                
                response_time_ms = int((time.time() - start_time) * 1000)
                
                # Record attempt
                success = response.status_code < 400
                WebhookDeliveryTracker.record_attempt(
                    endpoint_id=endpoint_id,
                    event_type=event_type,
                    payload=webhook_payload,
                    attempt_number=attempt,
                    success=success,
                    status_code=response.status_code,
                    response_time_ms=response_time_ms
                )
                
                if success:
                    circuit_breaker.record_success()
                    logger.info(
                        f"Webhook delivered successfully to {endpoint_url}",
                        extra={
                            'endpoint_id': endpoint_id,
                            'event_type': event_type,
                            'status_code': response.status_code,
                            'response_time_ms': response_time_ms,
                            'attempt': attempt
                        }
                    )
                    return {
                        'success': True,
                        'status_code': response.status_code,
                        'response_time_ms': response_time_ms,
                        'attempts': attempt
                    }
                else:
                    last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                    logger.warning(
                        f"Webhook delivery failed (attempt {attempt}/{max_retries})",
                        extra={
                            'endpoint_url': endpoint_url,
                            'status_code': response.status_code,
                            'error': last_error
                        }
                    )
            
            except requests.RequestException as e:
                last_error = str(e)
                response_time_ms = int((time.time() - start_time) * 1000) if 'start_time' in locals() else None
                
                WebhookDeliveryTracker.record_attempt(
                    endpoint_id=endpoint_id,
                    event_type=event_type,
                    payload=webhook_payload,
                    attempt_number=attempt,
                    success=False,
                    error_message=last_error,
                    response_time_ms=response_time_ms
                )
                
                logger.error(
                    f"Webhook request failed (attempt {attempt}/{max_retries})",
                    extra={
                        'endpoint_url': endpoint_url,
                        'error': str(e),
                        'attempt': attempt
                    }
                )
            
            # Exponential backoff before retry
            if attempt < max_retries:
                if not getattr(settings, 'IS_TESTING', False):
                    backoff = min(2 ** attempt, 30)  # Max 30 seconds
                    time.sleep(backoff)
        
        # All retries failed
        circuit_breaker.record_failure()
        
        return {
            'success': False,
            'error': 'max_retries_exceeded',
            'message': last_error,
            'attempts': max_retries
        }
    
    def send_to_all_endpoints(
        self,
        event_type: str,
        payload: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Send webhook to all configured endpoints for event type.
        
        Args:
            event_type: Type of event
            payload: Event payload
        
        Returns:
            List of delivery results
        """
        from webhooks.models import WebhookEndpoint
        
        # Get active endpoints for this event type
        endpoints = WebhookEndpoint.objects.filter(
            is_active=True,
            event_types__contains=[event_type]
        )
        
        if not endpoints.exists():
            logger.debug(f"No webhook endpoints configured for {event_type}")
            return []
        
        results = []
        for endpoint in endpoints:
            result = self.send_webhook(
                endpoint_url=endpoint.url,
                endpoint_id=str(endpoint.id),
                event_type=event_type,
                payload=payload,
                secret=endpoint.secret,
                custom_headers=endpoint.headers
            )
            
            result['endpoint_name'] = endpoint.name
            result['endpoint_url'] = endpoint.url
            results.append(result)
        
        return results


# Singleton instance
webhook_service = EnhancedWebhookService()
