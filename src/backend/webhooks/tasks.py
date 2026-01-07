"""
Celery Tasks for Webhook Delivery.

Uses dedicated queue with rate limiting to prevent
overwhelming external systems.
"""
import logging

from celery import shared_task

from django.conf import settings

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    max_retries=3,
    queue="webhooks",  # Dedicated queue
    rate_limit="100/m",  # Rate limit per worker
)
def send_webhook_notification_task(self, event_type: str, payload: dict):
    """
    Send webhook notification to all subscribed endpoints.

    Args:
        event_type: Type of event (e.g., 'scan.completed')
        payload: Event payload data (must be JSON-serializable)

    Returns:
        Dictionary with delivery results
    """
    if not getattr(settings, "WEBHOOK_ENABLED", True):
        logger.debug("Webhooks disabled, skipping notification")
        return {"status": "skipped", "reason": "webhooks_disabled"}

    from .models import WebhookEndpoint
    from .services import get_webhook_service

    try:
        # Check for active endpoints
        endpoints = WebhookEndpoint.objects.filter(is_active=True, event_types__contains=[event_type])

        if not endpoints.exists():
            logger.debug(f"No webhook endpoints for event: {event_type}")
            return {"status": "skipped", "reason": "no_endpoints"}

        # Deliver to all endpoints
        service = get_webhook_service()
        results = service.deliver_to_all(event_type, payload)

        # Summary
        success_count = sum(1 for r in results if r.success)
        failure_count = len(results) - success_count

        logger.info(
            "Webhook delivery complete",
            extra={
                "event_type": event_type,
                "total": len(results),
                "success": success_count,
                "failed": failure_count,
            },
        )

        return {
            "status": "completed",
            "event_type": event_type,
            "total": len(results),
            "success": success_count,
            "failed": failure_count,
        }

    except Exception as e:
        logger.error(f"Webhook delivery error: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task(
    bind=True,
    max_retries=5,
    queue="webhooks",
)
def send_webhook_to_endpoint_task(self, endpoint_id: str, event_type: str, payload: dict):
    """
    Send webhook to a specific endpoint with retry.

    Used for retrying failed deliveries.
    """
    from .models import WebhookEndpoint
    from .services import get_webhook_service

    try:
        endpoint = WebhookEndpoint.objects.get(id=endpoint_id)
    except WebhookEndpoint.DoesNotExist:
        logger.error(f"Webhook endpoint not found: {endpoint_id}")
        return {"status": "failed", "reason": "endpoint_not_found"}

    if not endpoint.is_active:
        return {"status": "skipped", "reason": "endpoint_inactive"}

    service = get_webhook_service()
    result = service.deliver(endpoint, event_type, payload)

    if not result.success:
        # Calculate backoff
        countdown = endpoint.retry_delay_seconds * (2**self.request.retries)
        raise self.retry(countdown=countdown)

    return {
        "status": "success",
        "endpoint": endpoint.name,
        "status_code": result.status_code,
    }


@shared_task(queue="webhooks")
def cleanup_old_deliveries_task(days: int = 7):
    """
    Cleanup old webhook delivery records.

    Keeps recent deliveries for debugging.
    """
    from datetime import timedelta

    from django.utils import timezone

    from .models import WebhookDelivery

    cutoff = timezone.now() - timedelta(days=days)
    deleted, _ = WebhookDelivery.objects.filter(created_at__lt=cutoff).delete()

    logger.info(f"Cleaned up {deleted} old webhook deliveries")

    return {"deleted": deleted}
