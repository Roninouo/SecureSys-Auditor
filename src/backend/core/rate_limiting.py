"""
Rate Limiting Middleware for SecureSys Auditor.

Implements per-user and per-IP rate limiting using Django cache.
"""
import logging
import time
from typing import Optional
from django.core.cache import cache
from django.http import JsonResponse
from django.conf import settings

logger = logging.getLogger('security')


class RateLimitMiddleware:
    """
    Rate limiting middleware using token bucket algorithm.
    
    Limits requests per user (authenticated) or IP (anonymous).
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Rate limit configuration (requests per minute)
        self.limits = getattr(settings, 'RATE_LIMITS', {
            'authenticated': 100,  # 100 req/min for authenticated users
            'anonymous': 20,       # 20 req/min for anonymous users
            'admin': 200,          # 200 req/min for admin users
        })
        
        # Burst allowance (can burst up to this many requests)
        self.burst = getattr(settings, 'RATE_LIMIT_BURST', {
            'authenticated': 20,
            'anonymous': 5,
            'admin': 50,
        })
    
    def __call__(self, request):
        # Skip rate limiting for certain paths
        if self.should_skip(request):
            return self.get_response(request)
        
        # Get rate limit key
        limit_key = self.get_limit_key(request)
        user_type = self.get_user_type(request)
        
        # Check rate limit
        allowed, retry_after = self.check_rate_limit(
            limit_key,
            self.limits.get(user_type, 20),
            self.burst.get(user_type, 5)
        )
        
        if not allowed:
            logger.warning(
                f"Rate limit exceeded for {limit_key}",
                extra={
                    'user_type': user_type,
                    'path': request.path,
                    'method': request.method
                }
            )
            
            return JsonResponse({
                'error': 'rate_limit_exceeded',
                'message': 'Too many requests. Please try again later.',
                'retry_after': retry_after
            }, status=429)
        
        response = self.get_response(request)
        
        # Add rate limit headers
        response['X-RateLimit-Limit'] = self.limits.get(user_type, 20)
        response['X-RateLimit-Remaining'] = self.get_remaining(limit_key)
        
        return response
    
    def should_skip(self, request) -> bool:
        """Check if rate limiting should be skipped for this request."""
        # Skip for health checks
        if request.path in ['/health/', '/api/health/']:
            return True
        
        # Skip for static files
        if request.path.startswith('/static/') or request.path.startswith('/media/'):
            return True
        
        # Skip for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return True
        
        return False
    
    def get_limit_key(self, request) -> str:
        """Get unique key for rate limiting."""
        if request.user.is_authenticated:
            return f"ratelimit:user:{request.user.id}"
        else:
            # Use IP address for anonymous users
            ip = self.get_client_ip(request)
            return f"ratelimit:ip:{ip}"
    
    def get_user_type(self, request) -> str:
        """Determine user type for rate limit selection."""
        if not request.user.is_authenticated:
            return 'anonymous'
        
        if hasattr(request.user, 'role') and request.user.role == 'admin':
            return 'admin'
        
        return 'authenticated'
    
    def get_client_ip(self, request) -> str:
        """Extract client IP address from request."""
        # Check for proxy headers
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or 'unknown'
    
    def check_rate_limit(
        self,
        key: str,
        rate: int,
        burst: int
    ) -> tuple[bool, Optional[int]]:
        """
        Check rate limit using token bucket algorithm.
        
        Args:
            key: Cache key for this client
            rate: Requests per minute allowed
            burst: Maximum burst size
        
        Returns:
            (allowed, retry_after): Whether request is allowed and retry time
        """
        now = time.time()
        
        # Get current token bucket state
        bucket_data = cache.get(key)
        
        if bucket_data is None:
            # Initialize new bucket
            tokens = burst
            last_update = now
        else:
            tokens, last_update = bucket_data
        
        # Calculate tokens to add based on time passed
        time_passed = now - last_update
        tokens_to_add = time_passed * (rate / 60.0)  # Convert rate/minute to rate/second
        tokens = min(burst, tokens + tokens_to_add)
        
        # Check if request can proceed
        if tokens >= 1.0:
            # Consume one token
            tokens -= 1.0
            cache.set(key, (tokens, now), timeout=120)  # 2 minute expiry
            return True, None
        else:
            # Calculate retry after time
            tokens_needed = 1.0 - tokens
            retry_after = int((tokens_needed / (rate / 60.0)) + 1)
            return False, retry_after
    
    def get_remaining(self, key: str) -> int:
        """Get remaining requests for this key."""
        bucket_data = cache.get(key)
        if bucket_data is None:
            return self.burst.get('authenticated', 20)
        
        tokens, _ = bucket_data
        return int(tokens)


class EndpointRateLimiter:
    """
    Decorator for endpoint-specific rate limiting.
    
    Usage:
        @EndpointRateLimiter(rate=10, period=60)
        def my_view(request):
            ...
    """
    
    def __init__(self, rate: int = 10, period: int = 60):
        """
        Initialize endpoint rate limiter.
        
        Args:
            rate: Number of requests allowed
            period: Time period in seconds
        """
        self.rate = rate
        self.period = period
    
    def __call__(self, func):
        """Decorator implementation."""
        def wrapper(request, *args, **kwargs):
            # Get rate limit key for this endpoint
            if request.user.is_authenticated:
                key = f"endpoint_limit:{func.__name__}:user:{request.user.id}"
            else:
                ip = self.get_client_ip(request)
                key = f"endpoint_limit:{func.__name__}:ip:{ip}"
            
            # Check rate limit
            count = cache.get(key, 0)
            
            if count >= self.rate:
                logger.warning(
                    f"Endpoint rate limit exceeded: {func.__name__}",
                    extra={
                        'endpoint': func.__name__,
                        'user': request.user.id if request.user.is_authenticated else 'anonymous'
                    }
                )
                
                return JsonResponse({
                    'error': 'rate_limit_exceeded',
                    'message': f'Rate limit exceeded for this endpoint. Limit: {self.rate} requests per {self.period} seconds.'
                }, status=429)
            
            # Increment counter
            cache.set(key, count + 1, timeout=self.period)
            
            # Call the actual view
            return func(request, *args, **kwargs)
        
        return wrapper
    
    @staticmethod
    def get_client_ip(request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip or 'unknown'
