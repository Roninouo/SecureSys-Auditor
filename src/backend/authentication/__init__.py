"""
Authentication App for SecureSys Auditor.

This app provides a loosely-coupled authentication layer that supports:
- Keycloak OIDC
- Simple JWT (legacy/fallback)
- Pluggable identity providers

Design Principles:
- Strategy Pattern for auth providers
- Dependency Injection for testability
- Cache abstraction for scalability
"""
default_app_config = 'authentication.apps.AuthenticationConfig'
