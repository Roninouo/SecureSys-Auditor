import pytest
from django.utils import timezone
from webhooks.models import WebhookEndpoint, WebhookDelivery, DeadLetterQueue
from unittest.mock import patch, MagicMock

@pytest.mark.django_db
class TestWebhookIdempotency:
    def test_idempotency_key_uniqueness(self):
        """Test that idempotency key prevents duplicate deliveries."""
        endpoint = WebhookEndpoint.objects.create(
            name="Test Endpoint",
            url="http://example.com/webhook"
        )
        
        key = "unique-key-123"
        
        # First delivery
        WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type="scan.completed",
            payload={"scan_id": 1},
            idempotency_key=key
        )
        
        # Second delivery with same key should fail
        with pytest.raises(Exception):  # IntegrityError
            WebhookDelivery.objects.create(
                endpoint=endpoint,
                event_type="scan.completed",
                payload={"scan_id": 1},
                idempotency_key=key
            )

@pytest.mark.django_db
class TestDeadLetterQueue:
    def test_move_to_dlq(self):
        """Test moving failed delivery to DLQ."""
        endpoint = WebhookEndpoint.objects.create(
            name="Test Endpoint",
            url="http://example.com/webhook"
        )
        
        delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type="scan.failed",
            status=WebhookDelivery.Status.FAILED,
            attempt_count=5
        )
        
        delivery.move_to_dlq()
        
        assert delivery.status == WebhookDelivery.Status.DLQ
        assert delivery.moved_to_dlq_at is not None
        
    @patch('webhooks.services.WebhookService.deliver')
    def test_dlq_reprocessing(self, mock_deliver):
        """Test reprocessing from DLQ."""
        # Setup mock
        mock_result = MagicMock()
        mock_result.success = True
        mock_deliver.return_value = mock_result
        
        endpoint = WebhookEndpoint.objects.create(
            name="Test Endpoint",
            url="http://example.com/webhook"
        )
        
        delivery = WebhookDelivery.objects.create(
            endpoint=endpoint,
            event_type="scan.failed",
            status=WebhookDelivery.Status.DLQ
        )
        
        dlq_entry = DeadLetterQueue.objects.create(
            original_delivery=delivery,
            reason=DeadLetterQueue.Reason.MAX_RETRIES
        )
        
        # Reprocess
        with patch('webhooks.models.get_webhook_service') as mock_get_service:
            mock_service_instance = MagicMock()
            mock_service_instance.deliver.return_value = mock_result
            mock_get_service.return_value = mock_service_instance
            
            dlq_entry.reprocess()
            
            dlq_entry.refresh_from_db()
            assert dlq_entry.reprocessed is True
            assert dlq_entry.reprocessed_at is not None
            assert dlq_entry.reprocess_result == 'success'
