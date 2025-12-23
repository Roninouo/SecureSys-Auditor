"""
Keycloak/OIDC SSO Integration for SecureSys Auditor.

Provides enterprise authentication via OpenID Connect.
"""
import logging
from typing import Optional, Dict, Any
import requests
from django.conf import settings
from django.contrib.auth import get_user_model
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

User = get_user_model()
logger = logging.getLogger('authentication')


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
        email = claims.get('email')
        
        if not email:
            logger.error("No email in OIDC claims", extra={'claims': claims})
            raise ValueError("Email is required for user creation")
        
        user = User.objects.create_user(
            email=email,
            first_name=claims.get('given_name', ''),
            last_name=claims.get('family_name', ''),
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
        user.first_name = claims.get('given_name', user.first_name)
        user.last_name = claims.get('family_name', user.last_name)
        user.email = claims.get('email', user.email)
        
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
        realm_roles = claims.get('realm_access', {}).get('roles', [])
        
        # Get client roles (if using client-specific roles)
        client_roles = claims.get('resource_access', {}).get(
            settings.OIDC_RP_CLIENT_ID,
            {}
        ).get('roles', [])
        
        all_roles = set(realm_roles + client_roles)
        
        # Map to application roles
        if 'securesys-admin' in all_roles:
            user.role = User.Role.ADMIN
            user.is_staff = True
        elif 'securesys-auditor' in all_roles:
            user.role = User.Role.AUDITOR
            user.is_staff = False
        elif 'securesys-viewer' in all_roles:
            user.role = User.Role.VIEWER
            user.is_staff = False
        else:
            # Default to viewer for authenticated users
            user.role = User.Role.VIEWER
            user.is_staff = False
        
        logger.debug(
            f"Mapped roles for {user.email}",
            extra={
                'keycloak_roles': list(all_roles),
                'app_role': user.role
            }
        )
    
    def filter_users_by_claims(self, claims: Dict[str, Any]):
        """
        Filter users to find existing user by email.
        
        Args:
            claims: OIDC user claims
        
        Returns:
            QuerySet of matching users
        """
        email = claims.get('email')
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
        if not claims.get('email'):
            logger.warning("OIDC claims missing email")
            return False
        
        # Verify email is verified (if Keycloak is configured to require this)
        email_verified = claims.get('email_verified', True)
        if not email_verified:
            logger.warning(
                f"OIDC user email not verified: {claims.get('email')}"
            )
            return False
        
        # Optional: Verify user belongs to allowed groups
        allowed_groups = getattr(settings, 'OIDC_ALLOWED_GROUPS', None)
        if allowed_groups:
            user_groups = claims.get('groups', [])
            if not any(group in allowed_groups for group in user_groups):
                logger.warning(
                    f"User not in allowed groups: {claims.get('email')}",
                    extra={'user_groups': user_groups}
                )
                return False
        
        return True


class KeycloakAdminClient:
    """
    Client for Keycloak Admin API.
    
    Provides methods for user management, role assignment, etc.
    """
    
    def __init__(self):
        self.server_url = getattr(settings, 'KEYCLOAK_SERVER_URL', '')
        self.realm = getattr(settings, 'KEYCLOAK_REALM', 'master')
        self.client_id = getattr(settings, 'KEYCLOAK_ADMIN_CLIENT_ID', '')
        self.client_secret = getattr(settings, 'KEYCLOAK_ADMIN_CLIENT_SECRET', '')
        self._access_token: Optional[str] = None
    
    def get_access_token(self) -> str:
        """
        Get admin access token from Keycloak.
        
        Returns:
            Access token string
        """
        if self._access_token:
            # TODO: Check token expiry and refresh if needed
            return self._access_token
        
        token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        response = requests.post(
            token_url,
            data={
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
            },
            timeout=10
        )
        
        response.raise_for_status()
        self._access_token = response.json()['access_token']
        
        return self._access_token
    
    def create_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        enabled: bool = True
    ) -> Dict[str, Any]:
        """
        Create user in Keycloak.
        
        Args:
            email: User email
            first_name: First name
            last_name: Last name
            enabled: Whether user is enabled
        
        Returns:
            Created user data
        """
        token = self.get_access_token()
        url = f"{self.server_url}/admin/realms/{self.realm}/users"
        
        response = requests.post(
            url,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json={
                'email': email,
                'emailVerified': True,
                'firstName': first_name,
                'lastName': last_name,
                'enabled': enabled,
                'username': email,
            },
            timeout=10
        )
        
        response.raise_for_status()
        
        logger.info(f"Created Keycloak user: {email}")
        
        return response.json()
    
    def assign_role(self, user_id: str, role_name: str):
        """
        Assign role to user in Keycloak.
        
        Args:
            user_id: Keycloak user ID
            role_name: Role name to assign
        """
        token = self.get_access_token()
        
        # First, get the role ID
        roles_url = f"{self.server_url}/admin/realms/{self.realm}/roles/{role_name}"
        response = requests.get(
            roles_url,
            headers={'Authorization': f'Bearer {token}'},
            timeout=10
        )
        response.raise_for_status()
        role_data = response.json()
        
        # Assign role to user
        assign_url = f"{self.server_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
        response = requests.post(
            assign_url,
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            },
            json=[role_data],
            timeout=10
        )
        response.raise_for_status()
        
        logger.info(f"Assigned role {role_name} to user {user_id}")
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get user from Keycloak by email.
        
        Args:
            email: User email
        
        Returns:
            User data or None if not found
        """
        token = self.get_access_token()
        url = f"{self.server_url}/admin/realms/{self.realm}/users"
        
        response = requests.get(
            url,
            headers={'Authorization': f'Bearer {token}'},
            params={'email': email, 'exact': 'true'},
            timeout=10
        )
        response.raise_for_status()
        
        users = response.json()
        return users[0] if users else None
