"""
Simple JWT Authentication Provider.

Provides backwards compatibility with existing JWT tokens.
Can be used as fallback when OIDC is unavailable.
"""
import logging

from django.conf import settings

from .base import AuthProvider, AuthResult

logger = logging.getLogger(__name__)


class SimpleJWTProvider(AuthProvider):
    """
    Simple JWT Authentication Provider.

    Uses django-rest-framework-simplejwt for token validation.
    Serves as a fallback when OIDC is unavailable or for
    service-to-service authentication.

    Configuration:
        SIMPLE_JWT = {
            'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
            'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
            'ALGORITHM': 'HS256',
            ...
        }
    """

    name = "simple_jwt"
    priority = 50  # Lower priority than OIDC

    def __init__(self):
        """Initialize the JWT provider."""
        # Lazy import to avoid circular dependencies
        self._jwt_auth = None

    def _get_jwt_auth(self):
        """Get JWT authentication class (lazy loaded)."""
        if self._jwt_auth is None:
            from rest_framework_simplejwt.authentication import JWTAuthentication

            self._jwt_auth = JWTAuthentication()
        return self._jwt_auth

    def can_handle(self, request) -> bool:
        """
        Check if this provider can handle the request.

        Handles Bearer tokens when OIDC fallback is allowed.
        """
        oidc_settings = getattr(settings, "OIDC_AUTH", {})

        # If OIDC is disabled or fallback is allowed
        if not oidc_settings.get("ENABLED", False):
            # OIDC disabled - JWT is primary
            return self._has_bearer_token(request)

        if oidc_settings.get("ALLOW_JWT_FALLBACK", True):
            # OIDC enabled but fallback allowed
            return self._has_bearer_token(request)

        return False

    def _has_bearer_token(self, request) -> bool:
        """Check if request has Bearer token."""
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        return auth_header.startswith("Bearer ")

    def authenticate(self, request) -> AuthResult:
        """
        Authenticate using Simple JWT.

        Delegates to djangorestframework-simplejwt.
        """
        if not self.can_handle(request):
            return AuthResult(error="JWT authentication not available")

        try:
            jwt_auth = self._get_jwt_auth()
            result = jwt_auth.authenticate(request)

            if result is None:
                return AuthResult(error="Invalid or missing token")

            user, validated_token = result

            # Extract payload for consistency with OIDC
            payload = {
                "user_id": str(validated_token.get("user_id", "")),
                "email": getattr(user, "email", ""),
                "role": getattr(user, "role", "viewer"),
            }

            return AuthResult(user=user, token_payload=payload, provider_name=self.name)

        except Exception as e:
            logger.warning(f"JWT authentication failed: {e}")
            return AuthResult(error=str(e))
