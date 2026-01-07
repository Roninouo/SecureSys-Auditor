"""
Webhook Management Views.
"""
import logging

from authentication.permissions import IsAdminRole
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import WebhookDelivery, WebhookEndpoint
from .serializers import WebhookDeliverySerializer, WebhookEndpointSerializer
from .tasks import send_webhook_notification_task

logger = logging.getLogger(__name__)


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing webhook endpoints.

    Only administrators can manage webhook configurations.
    """

    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminRole]

    def get_queryset(self):
        """Return all webhook endpoints."""
        return WebhookEndpoint.objects.all().order_by("name")

    @action(detail=True, methods=["post"])
    def test(self, request, pk=None):
        """
        Send a test webhook to verify endpoint configuration.
        """
        endpoint = self.get_object()

        # Queue test notification
        send_webhook_notification_task.delay(
            event_type="webhook.test",
            payload={
                "message": "This is a test webhook from SecureSys Auditor",
                "endpoint_name": endpoint.name,
            },
        )

        logger.info(f"Test webhook queued for endpoint: {endpoint.name}")

        return Response({"status": "queued", "message": f"Test webhook queued for {endpoint.name}"})

    @action(detail=True, methods=["post"])
    def toggle(self, request, pk=None):
        """Toggle webhook endpoint active status."""
        endpoint = self.get_object()
        endpoint.is_active = not endpoint.is_active
        endpoint.save(update_fields=["is_active", "updated_at"])

        status_text = "activated" if endpoint.is_active else "deactivated"
        logger.info(f"Webhook endpoint {status_text}: {endpoint.name}")

        return Response({"status": "success", "is_active": endpoint.is_active, "message": f"Endpoint {status_text}"})

    @action(detail=True, methods=["post"])
    def reset_circuit(self, request, pk=None):
        """Reset circuit breaker for an endpoint."""
        endpoint = self.get_object()
        endpoint.failure_count = 0
        endpoint.circuit_open_until = None
        endpoint.save(update_fields=["failure_count", "circuit_open_until", "updated_at"])

        return Response({"status": "success", "message": "Circuit breaker reset"})

    @action(detail=True, methods=["get"])
    def deliveries(self, request, pk=None):
        """Get recent deliveries for this endpoint."""
        endpoint = self.get_object()
        deliveries = WebhookDelivery.objects.filter(endpoint=endpoint).order_by("-created_at")[:50]

        serializer = WebhookDeliverySerializer(deliveries, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def event_types(self, request):
        """
        Return list of available webhook event types.
        """
        event_types = [
            {"type": "scan.submitted", "description": "Triggered when a new scan is submitted"},
            {"type": "scan.completed", "description": "Triggered when scan analysis is complete"},
            {"type": "scan.failed", "description": "Triggered when scan processing fails"},
            {"type": "finding.critical", "description": "Triggered when a critical finding is detected"},
            {"type": "finding.high", "description": "Triggered when a high-severity finding is detected"},
            {"type": "report.generated", "description": "Triggered when a PDF report is generated"},
            {"type": "system.registered", "description": "Triggered when a new system is registered"},
            {"type": "user.created", "description": "Triggered when a new user is created"},
            {"type": "webhook.test", "description": "Test event for verifying webhook configuration"},
        ]

        return Response(event_types)
