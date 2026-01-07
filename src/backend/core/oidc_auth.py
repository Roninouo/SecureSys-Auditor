"""
OIDC Authentication Backend for Keycloak Integration.

This module provides authentication classes for validating OIDC tokens
from Keycloak and mapping them to Django users.
"""
import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin

import jwt
import requests
from rest_framework import authentication, exceptions
from rest_framework.request import Request

from django.conf import settings
from django.contrib.auth import get_user_model

logger = logging.getLogger("core")
User = get_user_model()


class OIDCTokenCache:
    """Simple in-memory cache for OIDC configuration and JWKS."""

    _jwks_cache: Optional[Dict] = None
    _oidc_config: Optional[Dict] = None

    @classmethod
    def clear(cls):
        """Clear the cache."""
        cls._jwks_cache = None
        cls._oidc_config = None

    @classmethod
    def get_oidc_config(cls, issuer_url: str) -> Dict:
        """Fetch and cache OIDC configuration from issuer."""
        if cls._oidc_config is None:
            well_known_url = urljoin(issuer_url.rstrip("/") + "/", ".well-known/openid-configuration")
            try:
                response = requests.get(well_known_url, timeout=10)
                response.raise_for_status()
                cls._oidc_config = response.json()
            except requests.RequestException as e:
                logger.error(f"Failed to fetch OIDC config: {e}")
                raise exceptions.AuthenticationFailed("Unable to verify token: OIDC config unavailable")
        return cls._oidc_config

    @classmethod
    def get_jwks(cls, jwks_uri: str) -> Dict:
        """Fetch and cache JWKS from issuer."""
        if cls._jwks_cache is None:
            try:
                response = requests.get(jwks_uri, timeout=10)
                response.raise_for_status()
                cls._jwks_cache = response.json()
            except requests.RequestException as e:
                logger.error(f"Failed to fetch JWKS: {e}")
                raise exceptions.AuthenticationFailed("Unable to verify token: JWKS unavailable")
        return cls._jwks_cache


class KeycloakOIDCAuthentication(authentication.BaseAuthentication):
    """
    OIDC Token Authentication for Keycloak.

    Validates access tokens issued by Keycloak and maps them to Django users.
    Supports automatic user provisioning from OIDC claims.
    """

    def authenticate(self, request: Request) -> Optional[Tuple[User, Dict]]:
        """
        Authenticate the request using the OIDC token.

        Returns:
            Tuple of (user, token_payload) if authenticated, None otherwise.
        """
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if not auth_header.startswith("Bearer "):
            return None

        token = auth_header[7:]  # Remove 'Bearer ' prefix

        if not token:
            return None

        try:
            payload = self._validate_token(token)
            user = self._get_or_create_user(payload)
            return (user, payload)
        except exceptions.AuthenticationFailed:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise exceptions.AuthenticationFailed("Invalid token")

    def authenticate_header(self, request: Request) -> str:
        """Return the WWW-Authenticate header value."""
        return 'Bearer realm="SecureSys"'

    def _validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate the OIDC token and return the payload.

        Validates:
        - Token signature using Keycloak's public key
        - Token expiration
        - Token audience
        - Token issuer
        """
        oidc_settings = getattr(settings, "OIDC_AUTH", {})
        issuer = oidc_settings.get("ISSUER")
        audience = oidc_settings.get("AUDIENCE")

        if not issuer:
            raise exceptions.AuthenticationFailed("OIDC not configured")

        # Get OIDC configuration
        oidc_config = OIDCTokenCache.get_oidc_config(issuer)
        jwks_uri = oidc_config.get("jwks_uri")

        if not jwks_uri:
            raise exceptions.AuthenticationFailed("JWKS URI not found in OIDC config")

        # Get JWKS
        jwks = OIDCTokenCache.get_jwks(jwks_uri)

        # Get the signing key
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.exceptions.DecodeError:
            raise exceptions.AuthenticationFailed("Invalid token format")

        kid = unverified_header.get("kid")
        if not kid:
            raise exceptions.AuthenticationFailed("Token missing key ID")

        # Find the key
        key = None
        for jwk in jwks.get("keys", []):
            if jwk.get("kid") == kid:
                key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
                break

        if key is None:
            # Clear cache and retry once in case keys rotated
            OIDCTokenCache.clear()
            jwks = OIDCTokenCache.get_jwks(jwks_uri)
            for jwk in jwks.get("keys", []):
                if jwk.get("kid") == kid:
                    key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
                    break

        if key is None:
            raise exceptions.AuthenticationFailed("Unable to find signing key")

        # Validate token
        try:
            payload = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=audience,
                issuer=issuer,
                options={
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": bool(audience),
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed("Token has expired")
        except jwt.InvalidAudienceError:
            raise exceptions.AuthenticationFailed("Invalid token audience")
        except jwt.InvalidIssuerError:
            raise exceptions.AuthenticationFailed("Invalid token issuer")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {e}")
            raise exceptions.AuthenticationFailed("Invalid token")

        return payload

    def _get_or_create_user(self, payload: Dict[str, Any]) -> User:
        """
        Get or create a Django user from the OIDC token payload.

        Maps Keycloak roles to Django user roles.
        """
        email = payload.get("email")
        if not email:
            # Fallback to preferred_username if email not available
            email = payload.get("preferred_username")

        if not email:
            raise exceptions.AuthenticationFailed("Token missing user identifier")

        # Extract realm roles from token
        realm_access = payload.get("realm_access", {})
        roles = realm_access.get("roles", [])

        # Map Keycloak roles to Django roles
        django_role = self._map_role(roles)

        # Get or create user
        try:
            user = User.objects.get(email=email)
            # Update role if changed in Keycloak
            if user.role != django_role:
                user.role = django_role
                user.save(update_fields=["role", "updated_at"])
        except User.DoesNotExist:
            # Auto-provision user from OIDC claims
            oidc_settings = getattr(settings, "OIDC_AUTH", {})
            if not oidc_settings.get("AUTO_CREATE_USER", True):
                raise exceptions.AuthenticationFailed("User not found")

            user = User.objects.create(
                email=email,
                first_name=payload.get("given_name", ""),
                last_name=payload.get("family_name", ""),
                role=django_role,
                is_active=True,
            )
            logger.info(f"Auto-provisioned user from OIDC: {email}")

        if not user.is_active:
            raise exceptions.AuthenticationFailed("User account is disabled")

        return user

    def _map_role(self, keycloak_roles: list) -> str:
        """Map Keycloak realm roles to Django user roles."""
        # Priority order: admin > auditor > viewer
        if "admin" in keycloak_roles:
            return "admin"
        elif "auditor" in keycloak_roles:
            return "auditor"
        else:
            return "viewer"


class HybridAuthentication(authentication.BaseAuthentication):
    """
    Hybrid authentication that supports both OIDC and legacy JWT.

    Tries OIDC first, falls back to simple JWT for backwards compatibility.
    """

    def __init__(self):
        self.oidc_auth = KeycloakOIDCAuthentication()
        # Import here to avoid circular imports
        from rest_framework_simplejwt.authentication import JWTAuthentication

        self.jwt_auth = JWTAuthentication()

    def authenticate(self, request: Request) -> Optional[Tuple[User, Any]]:
        """Try OIDC first, then fall back to simple JWT."""
        oidc_settings = getattr(settings, "OIDC_AUTH", {})

        # If OIDC is configured and enabled, try it first
        if oidc_settings.get("ENABLED", False):
            try:
                result = self.oidc_auth.authenticate(request)
                if result is not None:
                    return result
            except exceptions.AuthenticationFailed:
                # If OIDC fails, try JWT as fallback if allowed
                if not oidc_settings.get("ALLOW_JWT_FALLBACK", True):
                    raise

        # Fall back to simple JWT
        return self.jwt_auth.authenticate(request)

    def authenticate_header(self, request: Request) -> str:
        """Return the WWW-Authenticate header value."""
        return 'Bearer realm="SecureSys"'
