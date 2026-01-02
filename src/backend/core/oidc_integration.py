"""
Keycloak/OIDC SSO Integration for SecureSys Auditor.

Provides enterprise authentication via OpenID Connect.
"""
import logging
from typing import Any, Dict

from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from django.conf import settings
from django.contrib.auth import get_user_model

User = get_user_model()
logger = logging.getLogger("authentication")


class KeycloakOIDCBackend(OIDCAuthenticationBackend):
    """
    Custom OIDC backend for Keycloak integration.

    Handles user creation, role mapping, and profile syncing.
    """

    def create_user(self, claims: Dict[str, Any]) -> User:
        """
        Create user from OIDC claims.

        Args:
            claims: OIDC user claims from Keycloak

        Returns:
            Created User instance
        """
        email = claims.get("email")

        if not email:
            logger.error("No email in OIDC claims", extra={"claims": claims})
            raise ValueError("Email is required for user creation")

        user = User.objects.create_user(
            email=email,
            first_name=claims.get("given_name", ""),
            last_name=claims.get("family_name", ""),
        )

        # Map Keycloak roles to application roles
        self.update_user_roles(user, claims)

        logger.info(f"Created user from OIDC: {email}")

        return user

    def update_user(self, user: User, claims: Dict[str, Any]) -> User:
        """
        Update existing user from OIDC claims.

        Args:
            user: Existing User instance
            claims: OIDC user claims from Keycloak

        Returns:
            Updated User instance
        """
        # Update profile information
        user.first_name = claims.get("given_name", user.first_name)
        user.last_name = claims.get("family_name", user.last_name)
        user.email = claims.get("email", user.email)

        # Update roles
        self.update_user_roles(user, claims)

        user.save()

        logger.info(f"Updated user from OIDC: {user.email}")

        return user

    def update_user_roles(self, user: User, claims: Dict[str, Any]):
        """
        Map Keycloak roles to application roles.

        Keycloak role mapping:
        - securesys-admin → admin
        - securesys-auditor → auditor
        - securesys-viewer → viewer
        """
        # Get realm roles
        realm_roles = claims.get("realm_access", {}).get("roles", [])

        # Get client roles (if using client-specific roles)
        client_roles = claims.get("resource_access", {}).get(settings.OIDC_RP_CLIENT_ID, {}).get("roles", [])

        all_roles = set(realm_roles + client_roles)

        # Map to application roles
        if "securesys-admin" in all_roles:
            user.role = User.Role.ADMIN
            user.is_staff = True
        elif "securesys-auditor" in all_roles:
            user.role = User.Role.AUDITOR
            user.is_staff = False
        elif "securesys-viewer" in all_roles:
            user.role = User.Role.VIEWER
            user.is_staff = False
        else:
            # Default to viewer for authenticated users
            user.role = User.Role.VIEWER
            user.is_staff = False

        logger.debug(f"Mapped roles for {user.email}", extra={"keycloak_roles": list(all_roles), "app_role": user.role})

    def filter_users_by_claims(self, claims: Dict[str, Any]):
        """
        Filter users to find existing user by email.

        Args:
            claims: OIDC user claims

        Returns:
            QuerySet of matching users
        """
        email = claims.get("email")
        if not email:
            return User.objects.none()

        return User.objects.filter(email__iexact=email)

    def verify_claims(self, claims: Dict[str, Any]) -> bool:
        """
        Verify that claims are valid and user should be authenticated.

        Args:
            claims: OIDC user claims

        Returns:
            True if claims are valid
        """
        # Verify email exists
        if not claims.get("email"):
            logger.warning("OIDC claims missing email")
            return False

        # Verify email is verified (if Keycloak is configured to require this)
        email_verified = claims.get("email_verified", True)
        if not email_verified:
            logger.warning(f"OIDC user email not verified: {claims.get('email')}")
            return False

        # Optional: Verify user belongs to allowed groups
        allowed_groups = getattr(settings, "OIDC_ALLOWED_GROUPS", None)
        if allowed_groups:
            user_groups = claims.get("groups", [])
            if not any(group in allowed_groups for group in user_groups):
                logger.warning(f"User not in allowed groups: {claims.get('email')}", extra={"user_groups": user_groups})
                return False

        return True
