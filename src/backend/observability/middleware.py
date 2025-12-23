"""
Django Middleware for Observability.

Adds request context to traces without duplicating auto-instrumentation.
"""
import logging
from typing import Callable

from django.http import HttpRequest, HttpResponse

logger = logging.getLogger(__name__)


class RequestContextMiddleware:
    """
    Middleware to add security context to traces.
    
    Adds:
    - User ID and role (if authenticated)
    - Auth method (OIDC vs JWT)
    - Request metadata
    
    NOTE: Does NOT create new spans - relies on Django auto-instrumentation.
    Only adds attributes to existing span.
    """
    
    def __init__(self, get_response: Callable):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Add context to current span (created by auto-instrumentation)
        self._add_span_context(request)
        
        response = self.get_response(request)
        
        return response
    
    def _add_span_context(self, request: HttpRequest):
        """Add security context to current span."""
        from .telemetry import OTEL_AVAILABLE
        
        if not OTEL_AVAILABLE:
            return
        
        try:
            from opentelemetry import trace
            
            span = trace.get_current_span()
            if not span or not span.is_recording():
                return
            
            # Add user context if authenticated
            if hasattr(request, 'user') and request.user.is_authenticated:
                span.set_attribute('user.id', str(request.user.id))
                span.set_attribute('user.email', request.user.email)
                span.set_attribute('user.role', getattr(request.user, 'role', 'unknown'))
            
            # Add auth method if available
            if hasattr(request, 'auth') and request.auth:
                if isinstance(request.auth, dict):
                    auth_method = 'oidc' if 'realm_access' in request.auth else 'jwt'
                else:
                    auth_method = 'jwt'
                span.set_attribute('auth.method', auth_method)
            
            # Add client IP
            span.set_attribute('http.client_ip', self._get_client_ip(request))
            
        except Exception as e:
            logger.debug(f"Failed to add span context: {e}")
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class HealthCheckBypassMiddleware:
    """
    Middleware to exclude health checks from tracing.
    
    Prevents health check endpoints from flooding traces.
    """
    
    HEALTH_PATHS = ['/api/v1/health/', '/health/', '/healthz/', '/ready/']
    
    def __init__(self, get_response: Callable):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Check if this is a health endpoint
        if request.path in self.HEALTH_PATHS:
            # Suppress tracing for health checks
            from .telemetry import OTEL_AVAILABLE
            if OTEL_AVAILABLE:
                try:
                    from opentelemetry import trace
                    span = trace.get_current_span()
                    if span and span.is_recording():
                        span.set_attribute('http.health_check', True)
                except Exception:
                    pass
        
        return self.get_response(request)
