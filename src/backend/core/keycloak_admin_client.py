"""Keycloak Admin API client.

Kept separate from OIDC backend plumbing so it can be imported and tested
without requiring optional OIDC dependencies.
"""

import logging
import time
from typing import Any, Dict, Optional

import requests

from django.conf import settings

logger = logging.getLogger("authentication")


class KeycloakAdminClient:
    """Client for Keycloak Admin API (client_credentials)."""

    def __init__(self):
        self.server_url = getattr(settings, "KEYCLOAK_SERVER_URL", "")
        self.realm = getattr(settings, "KEYCLOAK_REALM", "master")
        self.client_id = getattr(settings, "KEYCLOAK_ADMIN_CLIENT_ID", "")
        self.client_secret = getattr(settings, "KEYCLOAK_ADMIN_CLIENT_SECRET", "")
        self._access_token: Optional[str] = None
        self._access_token_expires_at: Optional[float] = None

    def _validate_config(self) -> None:
        if not self.server_url:
            raise ValueError("KEYCLOAK_SERVER_URL must be configured")
        if not self.realm:
            raise ValueError("KEYCLOAK_REALM must be configured")
        if not self.client_id:
            raise ValueError("KEYCLOAK_ADMIN_CLIENT_ID must be configured")
        if not self.client_secret:
            raise ValueError("KEYCLOAK_ADMIN_CLIENT_SECRET must be configured")

    def _fetch_access_token(self) -> str:
        """Fetch a fresh admin access token from Keycloak."""
        self._validate_config()

        token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"

        response = requests.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=10,
        )
        response.raise_for_status()

        token_data = response.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Keycloak token response missing access_token")

        # Track expiry with a small safety window to avoid edge-of-expiry 401s.
        now = time.time()
        expires_in = int(token_data.get("expires_in", 0) or 0)
        refresh_skew_seconds = 30
        effective_ttl = max(0, expires_in - refresh_skew_seconds)

        self._access_token = access_token
        self._access_token_expires_at = now + effective_ttl

        return access_token

    def _is_token_valid(self) -> bool:
        if not self._access_token or not self._access_token_expires_at:
            return False
        return time.time() < self._access_token_expires_at

    def get_access_token(self) -> str:
        """Return a cached token if still valid, otherwise fetch a new one."""
        if self._is_token_valid():
            return self._access_token  # type: ignore[return-value]

        return self._fetch_access_token()

    def _request(self, method: str, url: str, *, retry_on_401: bool = True, **kwargs):
        """Authenticated request with one refresh retry on 401."""
        token = self.get_access_token()

        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("Authorization", f"Bearer {token}")
        kwargs["headers"] = headers

        response = requests.request(method, url, **kwargs)

        if response.status_code == 401 and retry_on_401:
            # Token might have expired or been revoked; refresh once and retry.
            self._access_token = None
            self._access_token_expires_at = None

            token = self.get_access_token()
            headers = dict(headers)
            headers["Authorization"] = f"Bearer {token}"
            kwargs["headers"] = headers
            response = requests.request(method, url, **kwargs)

        return response

    def create_user(
        self,
        email: str,
        first_name: str,
        last_name: str,
        enabled: bool = True,
    ) -> Dict[str, Any]:
        url = f"{self.server_url}/admin/realms/{self.realm}/users"

        response = self._request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            json={
                "email": email,
                "emailVerified": True,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": enabled,
                "username": email,
            },
            timeout=10,
        )

        response.raise_for_status()
        logger.info(f"Created Keycloak user: {email}")
        return response.json()

    def assign_role(self, user_id: str, role_name: str) -> None:
        roles_url = f"{self.server_url}/admin/realms/{self.realm}/roles/{role_name}"
        response = self._request("GET", roles_url, timeout=10)
        response.raise_for_status()
        role_data = response.json()

        assign_url = f"{self.server_url}/admin/realms/{self.realm}/users/{user_id}" "/role-mappings/realm"
        response = self._request(
            "POST",
            assign_url,
            headers={"Content-Type": "application/json"},
            json=[role_data],
            timeout=10,
        )
        response.raise_for_status()

        logger.info(f"Assigned role {role_name} to user {user_id}")

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        url = f"{self.server_url}/admin/realms/{self.realm}/users"

        response = self._request(
            "GET",
            url,
            params={"email": email, "exact": "true"},
            timeout=10,
        )
        response.raise_for_status()

        users = response.json()
        return users[0] if users else None
