"""
Webhook integration tests with mock HTTP server.
"""
import pytest
import json
import hmac
import hashlib
from unittest.mock import Mock, patch
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time

from core.webhook_service import (
    webhook_service,
    WebhookCircuitBreaker,
    WebhookRateLimiter,
    CircuitState
)


class MockWebhookHandler(BaseHTTPRequestHandler):
    """Mock HTTP handler for webhook testing."""
    
    # Class variables to track requests
    requests_received = []
    response_status = 200
    response_delay = 0
    
    def do_POST(self):
        """Handle POST requests."""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Store request for verification
        self.requests_received.append({
            'path': self.path,
            'headers': dict(self.headers),
            'body': json.loads(body) if body else None
        })
        
        # Simulate delay if configured
        if self.response_delay > 0:
            time.sleep(self.response_delay)
        
        # Send response
        self.send_response(self.response_status)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status': 'ok'}).encode())
    
    def log_message(self, format, *args):
        """Suppress log messages."""
        pass


@pytest.fixture
def mock_webhook_server():
    """Start a mock webhook server for testing."""
    server = HTTPServer(('localhost', 8888), MockWebhookHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    
    yield server
    
    server.shutdown()
    MockWebhookHandler.requests_received = []


class TestWebhookCircuitBreaker:
    """Test circuit breaker functionality."""
    
    def test_circuit_starts_closed(self):
        """Test circuit breaker starts in closed state."""
        cb = WebhookCircuitBreaker("test-endpoint")
        assert cb.get_state() == CircuitState.CLOSED
        assert cb.can_attempt() is True
    
    def test_circuit_opens_after_failures(self):
        """Test circuit opens after threshold failures."""
        cb = WebhookCircuitBreaker("test-endpoint-2", failure_threshold=3)
        
        # Record failures
        for _ in range(3):
            cb.record_failure()
        
        # Circuit should be open
        assert cb.get_state() == CircuitState.OPEN
        assert cb.can_attempt() is False
    
    def test_circuit_half_open_after_timeout(self):
        """Test circuit goes to half-open after recovery timeout."""
        cb = WebhookCircuitBreaker(
            "test-endpoint-3",
            failure_threshold=2,
            recovery_timeout=1  # 1 second
        )
        
        # Open circuit
        cb.record_failure()
        cb.record_failure()
        assert cb.get_state() == CircuitState.OPEN
        
        # Wait for recovery timeout
        time.sleep(1.5)
        
        # Should allow attempt (half-open)
        assert cb.can_attempt() is True
        assert cb.get_state() == CircuitState.HALF_OPEN
    
    def test_circuit_closes_after_successes(self):
        """Test circuit closes after successful requests in half-open."""
        cb = WebhookCircuitBreaker(
            "test-endpoint-4",
            failure_threshold=2,
            recovery_timeout=1,
            success_threshold=2
        )
        
        # Open circuit
        cb.record_failure()
        cb.record_failure()
        
        # Wait and move to half-open
        time.sleep(1.5)
        cb.can_attempt()  # Triggers half-open
        
        # Record successes
        cb.record_success()
        assert cb.get_state() == CircuitState.HALF_OPEN
        
        cb.record_success()
        # Should now be closed
        assert cb.get_state() == CircuitState.CLOSED


class TestWebhookRateLimiter:
    """Test rate limiting functionality."""
    
    def test_rate_limiter_allows_within_limit(self):
        """Test rate limiter allows requests within limit."""
        limiter = WebhookRateLimiter(
            "test-endpoint-5",
            max_requests=5,
            window=10
        )
        
        # Should allow up to 5 requests
        for _ in range(5):
            assert limiter.can_attempt() is True
    
    def test_rate_limiter_blocks_over_limit(self):
        """Test rate limiter blocks requests over limit."""
        limiter = WebhookRateLimiter(
            "test-endpoint-6",
            max_requests=3,
            window=10
        )
        
        # Allow first 3
        for _ in range(3):
            assert limiter.can_attempt() is True
        
        # Block 4th
        assert limiter.can_attempt() is False


class TestWebhookService:
    """Test webhook service functionality."""
    
    def test_send_webhook_success(self, mock_webhook_server):
        """Test successful webhook delivery."""
        MockWebhookHandler.response_status = 200
        
        result = webhook_service.send_webhook(
            endpoint_url="http://localhost:8888/webhook",
            endpoint_id="test-endpoint-7",
            event_type="test.event",
            payload={"message": "test"},
            secret="test-secret"
        )
        
        assert result['success'] is True
        assert result['status_code'] == 200
        assert result['attempts'] == 1
        
        # Verify request was received
        assert len(MockWebhookHandler.requests_received) > 0
        request = MockWebhookHandler.requests_received[-1]
        assert request['body']['event_type'] == "test.event"
        header_keys = {k.lower() for k in request['headers'].keys()}
        assert 'x-securesys-signature' in header_keys
    
    def test_send_webhook_with_signature(self, mock_webhook_server):
        """Test webhook payload is correctly signed."""
        MockWebhookHandler.response_status = 200
        secret = "test-secret-123"
        payload = {"test": "data"}
        
        result = webhook_service.send_webhook(
            endpoint_url="http://localhost:8888/webhook",
            endpoint_id="test-endpoint-8",
            event_type="test.event",
            payload=payload,
            secret=secret
        )
        
        # Get the request
        request = MockWebhookHandler.requests_received[-1]
        headers_lower = {k.lower(): v for k, v in request['headers'].items()}
        signature = headers_lower['x-securesys-signature']
        
        # Verify signature
        payload_json = json.dumps(request['body'], sort_keys=True)
        expected_sig = hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        assert signature == f"sha256={expected_sig}"
    
    def test_send_webhook_retry_on_failure(self, mock_webhook_server):
        """Test webhook retries on failure."""
        MockWebhookHandler.response_status = 500
        
        result = webhook_service.send_webhook(
            endpoint_url="http://localhost:8888/webhook",
            endpoint_id="test-endpoint-9",
            event_type="test.event",
            payload={"message": "test"},
            max_retries=3
        )
        
        assert result['success'] is False
        assert result['attempts'] == 3
        
        # Should have received 3 requests
        test_requests = [
            r for r in MockWebhookHandler.requests_received
            if r['body'] and r['body'].get('event_type') == 'test.event'
        ]
        assert len(test_requests) >= 3
    
    def test_send_webhook_respects_circuit_breaker(self):
        """Test webhook service respects circuit breaker."""
        # Open circuit breaker
        cb = webhook_service.get_circuit_breaker("test-endpoint-10")
        for _ in range(5):
            cb.record_failure()
        
        # Attempt to send webhook
        result = webhook_service.send_webhook(
            endpoint_url="http://localhost:8888/webhook",
            endpoint_id="test-endpoint-10",
            event_type="test.event",
            payload={"message": "test"}
        )
        
        assert result['success'] is False
        assert result['error'] == 'circuit_breaker_open'
    
    def test_send_webhook_respects_rate_limit(self):
        """Test webhook service respects rate limiting."""
        endpoint_id = "test-endpoint-11"
        
        # Send requests up to limit
        for _ in range(100):
            result = webhook_service.send_webhook(
                endpoint_url="http://localhost:8888/webhook",
                endpoint_id=endpoint_id,
                event_type="test.event",
                payload={"message": "test"},
                max_retries=1
            )
        
        # Next request should be rate limited
        result = webhook_service.send_webhook(
            endpoint_url="http://localhost:8888/webhook",
            endpoint_id=endpoint_id,
            event_type="test.event",
            payload={"message": "test"}
        )
        
        assert result['success'] is False
        assert result['error'] == 'rate_limited'
    
    @patch('webhooks.models.WebhookEndpoint.objects.filter')
    def test_send_to_all_endpoints(self, mock_filter, mock_webhook_server):
        """Test sending to all configured endpoints."""
        # Mock endpoint queryset
        mock_endpoint = Mock()
        mock_endpoint.id = "endpoint-1"
        mock_endpoint.name = "Test Endpoint"
        mock_endpoint.url = "http://localhost:8888/webhook"
        mock_endpoint.secret = "secret"
        mock_endpoint.headers = {}
        
        mock_filter.return_value.exists.return_value = True
        mock_filter.return_value.__iter__.return_value = [mock_endpoint]
        
        MockWebhookHandler.response_status = 200
        
        results = webhook_service.send_to_all_endpoints(
            event_type="test.event",
            payload={"message": "test"}
        )
        
        assert len(results) == 1
        assert results[0]['success'] is True
        assert results[0]['endpoint_name'] == "Test Endpoint"


class TestWebhookDeliveryTracking:
    """Test webhook delivery tracking."""
    
    @patch('webhooks.models.WebhookDelivery.objects.create')
    def test_record_delivery_attempt(self, mock_create):
        """Test recording webhook delivery attempts."""
        from core.webhook_service import WebhookDeliveryTracker
        
        WebhookDeliveryTracker.record_attempt(
            endpoint_id="test-endpoint",
            event_type="test.event",
            payload={"test": "data"},
            attempt_number=1,
            success=True,
            status_code=200,
            response_time_ms=150
        )
        
        mock_create.assert_called_once()
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs['endpoint_id'] == "test-endpoint"
        assert call_kwargs['status'] == 'success'
        assert call_kwargs['status_code'] == 200
