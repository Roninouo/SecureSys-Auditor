"""
Keycloak OIDC Authentication Provider.

Implements the AuthProvider interface for Keycloak/OIDC authentication.
Designed to be loosely coupled - switching identity providers requires
only configuration changes, not code changes.
"""
import logging
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import jwt
import requests

from django.conf import settings
from django.contrib.auth import get_user_model

from .base import AuthProvider, AuthResult, DjangoCacheBackend, TokenCache

logger = logging.getLogger(__name__)
User = get_user_model()


class KeycloakOIDCProvider(AuthProvider):
    """
    Keycloak/OIDC Authentication Provider.

    Features:
    - OIDC Discovery (well-known configuration)
    - JWKS key rotation support
    - Automatic user provisioning from claims
    - Role mapping from realm roles

    Configuration (in settings.py):
        OIDC_AUTH = {
            'ENABLED': True,
            'ISSUER': 'https://keycloak.example.com/realms/securesys',
            'AUDIENCE': 'securesys-api',
            'AUTO_CREATE_USER': True,
            'ROLE_MAPPINGS': {
                'admin': 'admin',
                'auditor': 'auditor',
                'viewer': 'viewer',
            }
        }
    """

    name = "keycloak_oidc"
    priority = 10  # High priority - try OIDC first

    # Cache TTL values
    OIDC_CONFIG_TTL = 3600  # 1 hour
    JWKS_TTL = 3600  # 1 hour

    def __init__(self, cache: Optional[TokenCache] = None):
        """
        Initialize the provider with optional cache backend.

        Args:
            cache: TokenCache implementation (defaults to Django cache)
        """
        self._cache = cache or DjangoCacheBackend(key_prefix="oidc:")
        self._settings = getattr(settings, "OIDC_AUTH", {})

    @property
    def is_enabled(self) -> bool:
        """Check if OIDC is enabled."""
        return self._settings.get("ENABLED", False)

    @property
    def issuer(self) -> Optional[str]:
        """Get OIDC issuer URL."""
        return self._settings.get("ISSUER")

    @property
    def audience(self) -> Optional[str]:
        """Get expected token audience."""
        return self._settings.get("AUDIENCE")

    def can_handle(self, request) -> bool:
        """
        Check if this provider can handle the request.

        Handles requests with Bearer tokens when OIDC is enabled.
        """
        if not self.is_enabled:
            return False

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        return auth_header.startswith("Bearer ")

    def authenticate(self, request) -> AuthResult:
        """
        Authenticate using OIDC token.

        Steps:
        1. Extract Bearer token
        2. Fetch OIDC configuration (cached)
        3. Validate token signature with JWKS
        4. Validate token claims
        5. Get or create user
        """
        if not self.can_handle(request):
            return AuthResult(error="OIDC not configured or invalid token format")

        # Extract token
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        token = auth_header[7:]  # Remove 'Bearer '

        if not token:
            return AuthResult(error="Empty token")

        try:
            # Validate token and get payload
            payload = self._validate_token(token)

            # Get or create user
            user = self._get_or_create_user(payload)

            return AuthResult(user=user, token_payload=payload, provider_name=self.name)

        except jwt.ExpiredSignatureError:
            return AuthResult(error="Token has expired")
        except jwt.InvalidAudienceError:
            return AuthResult(error="Invalid token audience")
        except jwt.InvalidIssuerError:
            return AuthResult(error="Invalid token issuer")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {e}")
            return AuthResult(error="Invalid token")
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return AuthResult(error="Authentication failed")

    def _get_oidc_config(self) -> Dict[str, Any]:
        """
        Fetch OIDC configuration from well-known endpoint.
        Results are cached for performance.
        """
        cache_key = f"config:{self.issuer}"
        cached = self._cache.get(cache_key)

        if cached:
            return cached

        well_known_url = urljoin(self.issuer.rstrip("/") + "/", ".well-known/openid-configuration")

        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        config = response.json()

        self._cache.set(cache_key, config, self.OIDC_CONFIG_TTL)
        return config

    def _get_jwks(self, jwks_uri: str) -> Dict[str, Any]:
        """
        Fetch JWKS from issuer.
        Results are cached for performance.
        """
        cache_key = f"jwks:{jwks_uri}"
        cached = self._cache.get(cache_key)

        if cached:
            return cached

        response = requests.get(jwks_uri, timeout=10)
        response.raise_for_status()
        jwks = response.json()

        self._cache.set(cache_key, jwks, self.JWKS_TTL)
        return jwks

    def _validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate token signature and claims.

        Supports automatic key rotation by clearing cache on unknown kid.
        """
        # Get OIDC configuration
        oidc_config = self._get_oidc_config()
        jwks_uri = oidc_config.get("jwks_uri")

        if not jwks_uri:
            raise jwt.InvalidTokenError("JWKS URI not found in OIDC config")

        # Get unverified header for key ID
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError:
            raise jwt.InvalidTokenError("Invalid token format")

        kid = unverified_header.get("kid")
        if not kid:
            raise jwt.InvalidTokenError("Token missing key ID")

        # Get signing key from JWKS
        key = self._find_signing_key(jwks_uri, kid)

        if key is None:
            # Key not found - maybe keys rotated, clear cache and retry
            self._cache.delete(f"jwks:{jwks_uri}")
            key = self._find_signing_key(jwks_uri, kid)

        if key is None:
            raise jwt.InvalidTokenError("Unable to find signing key")

        # Validate token
        payload = jwt.decode(
            token,
            key=key,
            algorithms=["RS256"],
            audience=self.audience,
            issuer=self.issuer,
            options={
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": bool(self.audience),
                "verify_iss": True,
            },
        )

        return payload

    def _find_signing_key(self, jwks_uri: str, kid: str):
        """Find the signing key with matching kid in JWKS."""
        jwks = self._get_jwks(jwks_uri)

        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

        return None

    def _get_or_create_user(self, payload: Dict[str, Any]) -> User:
        """
        Get or create Django user from OIDC claims.

        Maps Keycloak realm roles to Django user roles.
        """
        # Extract email (primary identifier)
        email = payload.get("email") or payload.get("preferred_username")

        if not email:
            raise ValueError("Token missing user identifier")

        # Map roles
        realm_access = payload.get("realm_access", {})
        roles = realm_access.get("roles", [])
        django_role = self._map_roles(roles)

        # Get or create user
        try:
            user = User.objects.get(email=email)

            # Update role if changed in Keycloak
            if user.role != django_role:
                user.role = django_role
                user.save(update_fields=["role", "updated_at"])

        except User.DoesNotExist:
            # Auto-provision user if enabled
            if not self._settings.get("AUTO_CREATE_USER", True):
                raise ValueError("User not found and auto-creation disabled")

            user = User.objects.create(
                email=email,
                first_name=payload.get("given_name", ""),
                last_name=payload.get("family_name", ""),
                role=django_role,
                is_active=True,
            )
            logger.info(f"Auto-provisioned user from OIDC: {email}")

        if not user.is_active:
            raise ValueError("User account is disabled")

        return user

    def _map_roles(self, keycloak_roles: list) -> str:
        """
        Map Keycloak realm roles to Django user roles.

        Uses configurable mapping from settings.
        """
        role_mappings = self._settings.get(
            "ROLE_MAPPINGS",
            {
                "admin": "admin",
                "auditor": "auditor",
            },
        )

        # Priority order
        for kc_role, django_role in role_mappings.items():
            if kc_role in keycloak_roles:
                return django_role

        return "viewer"  # Default role
