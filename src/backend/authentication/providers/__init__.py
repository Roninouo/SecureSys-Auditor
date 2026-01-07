"""
Authentication Providers Package.

Implements Strategy Pattern for pluggable authentication backends.
"""
from .base import AuthProvider, AuthResult
from .jwt_provider import SimpleJWTProvider
from .keycloak import KeycloakOIDCProvider

__all__ = [
    "AuthProvider",
    "AuthResult",
    "KeycloakOIDCProvider",
    "SimpleJWTProvider",
]
