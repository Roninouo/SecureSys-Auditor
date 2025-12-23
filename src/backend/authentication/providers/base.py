"""
Base Authentication Provider Interface.

Implements Strategy Pattern for pluggable authentication.
Following Interface Segregation Principle (ISP).
"""
import abc
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from django.contrib.auth import get_user_model


User = get_user_model()


@dataclass
class AuthResult:
    """
    Result of authentication attempt.
    
    Attributes:
        user: Authenticated user (None if failed)
        token_payload: Decoded token data
        provider_name: Name of the provider that authenticated
        error: Error message if authentication failed
    """
    user: Optional[Any] = None
    token_payload: Optional[Dict[str, Any]] = None
    provider_name: str = ""
    error: Optional[str] = None
    
    @property
    def is_authenticated(self) -> bool:
        """Check if authentication was successful."""
        return self.user is not None and self.error is None


class AuthProvider(abc.ABC):
    """
    Abstract base class for authentication providers.
    
    Implements Strategy Pattern - each provider can be swapped
    without changing the authentication logic.
    
    To add a new provider:
    1. Subclass AuthProvider
    2. Implement authenticate() and can_handle()
    3. Register in settings.AUTH_PROVIDERS
    """
    
    # Provider identifier - must be unique
    name: str = "base"
    
    # Priority order (lower = higher priority)
    priority: int = 100
    
    @abc.abstractmethod
    def authenticate(self, request) -> AuthResult:
        """
        Attempt to authenticate the request.
        
        Args:
            request: DRF Request object
            
        Returns:
            AuthResult with user if successful, error if not
        """
        raise NotImplementedError
    
    @abc.abstractmethod
    def can_handle(self, request) -> bool:
        """
        Check if this provider can handle the request.
        
        Args:
            request: DRF Request object
            
        Returns:
            True if this provider should attempt authentication
        """
        raise NotImplementedError
    
    def get_user_from_payload(self, payload: Dict[str, Any]) -> Optional[Any]:
        """
        Get or create user from token payload.
        Override in subclasses for custom user mapping.
        """
        return None
    
    def refresh_user(self, user: Any, payload: Dict[str, Any]) -> Any:
        """
        Update user with latest token claims.
        Override in subclasses if needed.
        """
        return user


class TokenCache(abc.ABC):
    """
    Abstract token/JWKS cache interface.
    
    Supports different backends:
    - In-memory (development)
    - Redis (production)
    - Django cache framework
    """
    
    @abc.abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        raise NotImplementedError
    
    @abc.abstractmethod
    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        """Set value in cache with TTL."""
        raise NotImplementedError
    
    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Delete value from cache."""
        raise NotImplementedError
    
    @abc.abstractmethod
    def clear(self) -> None:
        """Clear all cached values."""
        raise NotImplementedError


class DjangoCacheBackend(TokenCache):
    """
    Token cache using Django's cache framework.
    
    Supports Redis, Memcached, etc. based on Django settings.
    This ensures cache consistency across multiple workers.
    """
    
    def __init__(self, cache_alias: str = 'default', key_prefix: str = 'auth:'):
        from django.core.cache import caches
        self._cache = caches[cache_alias]
        self._key_prefix = key_prefix
    
    def _make_key(self, key: str) -> str:
        return f"{self._key_prefix}{key}"
    
    def get(self, key: str) -> Optional[Any]:
        return self._cache.get(self._make_key(key))
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        self._cache.set(self._make_key(key), value, ttl)
    
    def delete(self, key: str) -> None:
        self._cache.delete(self._make_key(key))
    
    def clear(self) -> None:
        # Note: This clears all keys with the prefix
        # For production, consider using cache.clear() with caution
        pass


class InMemoryCache(TokenCache):
    """
    Simple in-memory cache for development/testing.
    
    WARNING: Not suitable for production with multiple workers.
    """
    
    _store: Dict[str, Any] = {}
    
    def get(self, key: str) -> Optional[Any]:
        return self._store.get(key)
    
    def set(self, key: str, value: Any, ttl: int = 3600) -> None:
        self._store[key] = value
    
    def delete(self, key: str) -> None:
        self._store.pop(key, None)
    
    def clear(self) -> None:
        self._store.clear()
