"""
DRF Authentication Backend.

Implements a unified authentication backend that delegates
to registered providers using the Chain of Responsibility pattern.
"""
import logging
from typing import Any, List, Optional, Tuple

from rest_framework import authentication, exceptions
from rest_framework.request import Request

from django.conf import settings
from django.utils.module_loading import import_string

from .providers import AuthProvider, KeycloakOIDCProvider, SimpleJWTProvider

logger = logging.getLogger(__name__)


class ProviderChainAuthentication(authentication.BaseAuthentication):
    """
    Unified authentication backend using Chain of Responsibility.

    Iterates through registered providers in priority order.
    First provider to successfully authenticate wins.

    Benefits:
    - Easy to add new providers
    - Providers are loosely coupled
    - Supports fallback chains

    Configuration:
        REST_FRAMEWORK = {
            'DEFAULT_AUTHENTICATION_CLASSES': [
                'authentication.backends.ProviderChainAuthentication',
            ]
        }
    """

    def __init__(self):
        """Initialize with default providers."""
        self._providers: List[AuthProvider] = []
        self._init_providers()

    def _init_providers(self):
        """
        Initialize authentication providers.

        Providers are sorted by priority (lower number = higher priority).
        """
        # Get provider classes from settings or use defaults
        provider_classes = getattr(settings, "AUTH_PROVIDERS", [KeycloakOIDCProvider, SimpleJWTProvider])

        # Instantiate providers
        for provider_class in provider_classes:
            if isinstance(provider_class, str):
                provider_class = import_string(provider_class)

            if isinstance(provider_class, type):
                provider = provider_class()
            else:
                provider = provider_class

            self._providers.append(provider)

        # Sort by priority
        self._providers.sort(key=lambda p: p.priority)

        logger.debug(f"Initialized auth providers: {[p.name for p in self._providers]}")

    def authenticate(self, request: Request) -> Optional[Tuple[Any, Any]]:
        """
        Authenticate the request using registered providers.

        Returns:
            Tuple of (user, auth_info) if authenticated, None otherwise.

        Raises:
            AuthenticationFailed: If authentication attempted but failed.
        """
        last_error = None

        for provider in self._providers:
            if not provider.can_handle(request):
                continue

            logger.debug(f"Trying provider: {provider.name}")
            result = provider.authenticate(request)

            if result.is_authenticated:
                logger.debug(f"Authenticated via {provider.name}")
                return (result.user, result.token_payload)

            if result.error:
                last_error = result.error

        # If we tried to authenticate but all providers failed
        if last_error:
            raise exceptions.AuthenticationFailed(last_error)

        # No provider could handle the request
        return None

    def authenticate_header(self, request: Request) -> str:
        """Return WWW-Authenticate header value."""
        return 'Bearer realm="SecureSys"'


# Backwards compatibility alias
HybridAuthentication = ProviderChainAuthentication
