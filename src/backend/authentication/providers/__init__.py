"""
Authentication Providers Package.

Implements Strategy Pattern for pluggable authentication backends.
"""
from .base import AuthProvider, AuthResult
from .keycloak import KeycloakOIDCProvider
from .jwt_provider import SimpleJWTProvider

__all__ = [
    'AuthProvider',
    'AuthResult',
    'KeycloakOIDCProvider',
    'SimpleJWTProvider',
]
