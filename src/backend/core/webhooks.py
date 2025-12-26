"""
Webhook Management Views for SecureSys Auditor.

Provides API endpoints for managing webhook endpoints
and viewing delivery history.
"""
import logging
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response

from webhooks.models import WebhookEndpoint
from .serializers import WebhookEndpointSerializer
from .tasks import send_webhook_notification

logger = logging.getLogger('core')


class IsAdminUser(permissions.BasePermission):
    """Allow access only to admin users."""
    
    def has_permission(self, request, view):
        return (
            request.user.is_authenticated and 
            request.user.role == 'admin'
        )


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing webhook endpoints.
    
    Only administrators can manage webhook configurations.
    """
    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminUser]
    
    def get_queryset(self):
        """Return all webhook endpoints."""
        return WebhookEndpoint.objects.all().order_by('name')
    
    @action(detail=True, methods=['post'])
    def test(self, request, pk=None):
        """
        Send a test webhook to verify endpoint configuration.
        """
        endpoint = self.get_object()
        
        # Queue test notification
        send_webhook_notification.delay(
            event_type='webhook.test',
            payload={
                'message': 'This is a test webhook from SecureSys Auditor',
                'endpoint_name': endpoint.name,
                'timestamp': str(endpoint.updated_at),
            }
        )
        
        logger.info(f"Test webhook queued for endpoint: {endpoint.name}")
        
        return Response({
            'status': 'queued',
            'message': f'Test webhook queued for {endpoint.name}'
        })
    
    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        """Toggle webhook endpoint active status."""
        endpoint = self.get_object()
        endpoint.is_active = not endpoint.is_active
        endpoint.save(update_fields=['is_active', 'updated_at'])
        
        status_text = 'activated' if endpoint.is_active else 'deactivated'
        logger.info(f"Webhook endpoint {status_text}: {endpoint.name}")
        
        return Response({
            'status': 'success',
            'is_active': endpoint.is_active,
            'message': f'Endpoint {status_text}'
        })
    
    @action(detail=False, methods=['get'])
    def event_types(self, request):
        """
        Return list of available webhook event types.
        """
        event_types = [
            {
                'type': 'scan.submitted',
                'description': 'Triggered when a new scan is submitted'
            },
            {
                'type': 'scan.completed',
                'description': 'Triggered when scan analysis is complete'
            },
            {
                'type': 'scan.failed',
                'description': 'Triggered when scan processing fails'
            },
            {
                'type': 'finding.critical',
                'description': 'Triggered when a critical finding is detected'
            },
            {
                'type': 'finding.high',
                'description': 'Triggered when a high-severity finding is detected'
            },
            {
                'type': 'report.generated',
                'description': 'Triggered when a PDF report is generated'
            },
            {
                'type': 'system.registered',
                'description': 'Triggered when a new system is registered'
            },
            {
                'type': 'user.created',
                'description': 'Triggered when a new user is created'
            },
            {
                'type': 'webhook.test',
                'description': 'Test event for verifying webhook configuration'
            },
        ]
        
        return Response(event_types)
