import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def keycloak_settings(monkeypatch):
    # Patch settings before importing/instantiating the client.
    from django.conf import settings

    settings.KEYCLOAK_SERVER_URL = "http://keycloak:8080"
    settings.KEYCLOAK_REALM = "securesys"
    settings.KEYCLOAK_ADMIN_CLIENT_ID = "admin-client"
    settings.KEYCLOAK_ADMIN_CLIENT_SECRET = "admin-secret"

    return settings


def _token_response(token: str, expires_in: int = 3600):
    resp = Mock()
    resp.status_code = 200
    resp.json.return_value = {"access_token": token, "expires_in": expires_in}
    resp.raise_for_status = Mock()
    return resp


def test_keycloak_admin_token_cached_until_expiry(keycloak_settings):
    from core.keycloak_admin_client import KeycloakAdminClient

    with patch("core.keycloak_admin_client.requests.post") as post:
        post.return_value = _token_response("token-1", expires_in=3600)

        client = KeycloakAdminClient()
        t1 = client.get_access_token()
        t2 = client.get_access_token()

        assert t1 == "token-1"
        assert t2 == "token-1"
        assert post.call_count == 1


def test_keycloak_admin_retries_on_401_with_refresh(keycloak_settings):
    from core.keycloak_admin_client import KeycloakAdminClient

    # Token fetch returns token-1, then token-2 on refresh
    with patch("core.keycloak_admin_client.requests.post") as post, patch(
        "core.keycloak_admin_client.requests.request"
    ) as req:
        post.side_effect = [
            _token_response("token-1", expires_in=3600),
            _token_response("token-2", expires_in=3600),
        ]

        first = Mock()
        first.status_code = 401
        second = Mock()
        second.status_code = 200
        second.json.return_value = [{"id": "u1", "email": "a@b.com"}]
        second.raise_for_status = Mock()

        req.side_effect = [first, second]

        client = KeycloakAdminClient()
        user = client.get_user_by_email("a@b.com")

        assert user and user["id"] == "u1"
        assert post.call_count == 2
        assert req.call_count == 2

        # Ensure the retry used the refreshed token
        first_auth = req.call_args_list[0].kwargs["headers"]["Authorization"]
        second_auth = req.call_args_list[1].kwargs["headers"]["Authorization"]
        assert first_auth == "Bearer token-1"
        assert second_auth == "Bearer token-2"
