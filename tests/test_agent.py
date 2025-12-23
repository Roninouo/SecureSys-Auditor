"""
Unit tests for agent API client.

Tests coverage for:
- TLS enforcement
- HMAC signature generation and verification
- register_or_get_system flow
- submit_scan with signature
- Error handling
"""
import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch

import pytest


class TestTLSEnforcement:
    """Test TLS enforcement in API client."""

    def test_api_client_rejects_http_url(self):
        """Test API client rejects non-HTTPS URLs."""
        from agent.api_client import SecureSysAPIClient

        with pytest.raises(ValueError, match='https://'):
            SecureSysAPIClient(
                api_url='http://insecure.example.com',
                api_key='test-key'
            )

    def test_api_client_accepts_https_url(self):
        """Test API client accepts HTTPS URLs."""
        from agent.api_client import SecureSysAPIClient

        client = SecureSysAPIClient(
            api_url='https://secure.example.com',
            api_key='test-key'
        )

        assert client.api_url == 'https://secure.example.com'

    def test_api_client_accepts_localhost_http_for_dev(self):
        """Test API client allows localhost HTTP for development."""
        from agent.api_client import SecureSysAPIClient

        # localhost should be allowed for development
        client = SecureSysAPIClient(
            api_url='http://localhost:8000',
            api_key='test-key',
            allow_insecure_localhost=True
        )

        assert 'localhost' in client.api_url


class TestHMACSignature:
    """Test HMAC signature generation."""

    def test_generate_signature(self):
        """Test signature generation."""
        from agent.api_client import SecureSysAPIClient

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='secret-key-12345'
        )

        payload = {'system_id': 'abc123', 'data': 'test'}
        timestamp = int(time.time())

        signature = client._generate_signature(payload, timestamp)

        # Verify signature format
        assert signature is not None
        assert len(signature) == 64  # SHA256 hex digest length

    def test_signature_is_deterministic(self):
        """Test same payload + timestamp produces same signature."""
        from agent.api_client import SecureSysAPIClient

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='secret-key-12345'
        )

        payload = {'system_id': 'abc123', 'data': 'test'}
        timestamp = 1700000000

        sig1 = client._generate_signature(payload, timestamp)
        sig2 = client._generate_signature(payload, timestamp)

        assert sig1 == sig2

    def test_different_timestamps_different_signatures(self):
        """Test different timestamps produce different signatures."""
        from agent.api_client import SecureSysAPIClient

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='secret-key-12345'
        )

        payload = {'system_id': 'abc123', 'data': 'test'}

        sig1 = client._generate_signature(payload, 1700000000)
        sig2 = client._generate_signature(payload, 1700000001)

        assert sig1 != sig2

    def test_different_keys_different_signatures(self):
        """Test different API keys produce different signatures."""
        from agent.api_client import SecureSysAPIClient

        client1 = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='key-1'
        )
        client2 = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='key-2'
        )

        payload = {'test': 'data'}
        timestamp = 1700000000

        sig1 = client1._generate_signature(payload, timestamp)
        sig2 = client2._generate_signature(payload, timestamp)

        assert sig1 != sig2


class TestSubmitScanWithSignature:
    """Test submit_scan with HMAC signature."""

    @patch('agent.api_client.requests.Session')
    def test_submit_scan_includes_signature_header(self, mock_session_class):
        """Test submit_scan includes X-Signature header."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'id': 'scan-123', 'status': 'pending'}
        mock_session.post.return_value = mock_response

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        result = client.submit_scan(
            system_id='system-123',
            scan_payload={'hostname': 'test', 'data': 'test'}
        )

        # Verify post was called
        mock_session.post.assert_called_once()

        # Check headers include signature
        call_kwargs = mock_session.post.call_args
        headers = call_kwargs.kwargs.get('headers', {})

        assert 'X-Signature' in headers
        assert 'X-Timestamp' in headers

    @patch('agent.api_client.requests.Session')
    def test_submit_scan_timestamp_is_recent(self, mock_session_class):
        """Test submit_scan includes recent timestamp."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'id': 'scan-123'}
        mock_session.post.return_value = mock_response

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        before = int(time.time())
        client.submit_scan(system_id='sys-1', scan_payload={})
        after = int(time.time())

        call_kwargs = mock_session.post.call_args
        headers = call_kwargs.kwargs.get('headers', {})
        timestamp = int(headers['X-Timestamp'])

        assert before <= timestamp <= after


class TestRegisterOrGetSystem:
    """Test register_or_get_system flow."""

    @patch('agent.api_client.requests.Session')
    def test_returns_existing_system(self, mock_session_class):
        """Test returns existing system when found."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        existing_system = {
            'id': 'existing-123',
            'hostname': 'test-host',
            'os': 'Linux'
        }

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'results': [existing_system]}
        mock_session.get.return_value = mock_response

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        result = client.register_or_get_system(
            hostname='test-host',
            os='Linux'
        )

        assert result['id'] == 'existing-123'

    @patch('agent.api_client.requests.Session')
    def test_creates_new_system_when_not_found(self, mock_session_class):
        """Test creates new system when not found."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # GET returns empty
        mock_get_response = MagicMock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {'results': []}
        mock_session.get.return_value = mock_get_response

        # POST creates new
        new_system = {
            'id': 'new-456',
            'hostname': 'new-host',
            'os': 'Linux'
        }
        mock_post_response = MagicMock()
        mock_post_response.status_code = 201
        mock_post_response.json.return_value = new_system
        mock_session.post.return_value = mock_post_response

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        result = client.register_or_get_system(
            hostname='new-host',
            os='Linux'
        )

        assert result['id'] == 'new-456'
        mock_session.post.assert_called_once()


class TestErrorHandling:
    """Test error handling in API client."""

    @patch('agent.api_client.requests.Session')
    def test_submit_scan_raises_on_error(self, mock_session_class):
        """Test submit_scan raises exception on API error."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_session.post.return_value = mock_response

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        with pytest.raises(Exception, match='Failed to submit scan'):
            client.submit_scan(
                system_id='system-123',
                scan_payload={}
            )

    @patch('agent.api_client.requests.Session')
    def test_health_check_returns_false_on_error(self, mock_session_class):
        """Test health_check returns False on connection error."""
        from agent.api_client import SecureSysAPIClient

        mock_session = MagicMock()
        mock_session_class.return_value = mock_session
        mock_session.get.side_effect = Exception('Connection failed')

        client = SecureSysAPIClient(
            api_url='https://api.example.com',
            api_key='test-key'
        )

        assert client.health_check() is False
