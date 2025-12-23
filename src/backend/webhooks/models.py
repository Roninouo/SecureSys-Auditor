"""
Webhook Models.

Moved from core.models for better separation of concerns.
"""
import uuid
from django.db import models
from django.utils import timezone


class WebhookEndpoint(models.Model):
    """
    Webhook endpoint configuration for external integrations.
    Supports SIEM, alerting systems, and custom integrations.
    """
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text='Descriptive name for this endpoint')
    url = models.URLField(help_text='Webhook URL to receive events')
    secret = models.CharField(
        max_length=255,
        blank=True,
        help_text='HMAC secret for signing payloads'
    )
    
    # Event type filtering
    event_types = models.JSONField(
        default=list,
        help_text='List of event types to send'
    )
    
    # Custom headers
    headers = models.JSONField(
        default=dict,
        blank=True,
        help_text='Additional headers to include'
    )
    
    # Status
    is_active = models.BooleanField(default=True)
    
    # Retry configuration
    max_retries = models.IntegerField(default=3)
    retry_delay_seconds = models.IntegerField(default=60)
    
    # Tracking
    last_triggered = models.DateTimeField(null=True, blank=True)
    last_status_code = models.IntegerField(null=True, blank=True)
    failure_count = models.IntegerField(default=0)
    
    # Circuit breaker
    circuit_open_until = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'webhook_endpoints'
        verbose_name = 'webhook endpoint'
        verbose_name_plural = 'webhook endpoints'
        ordering = ['name']
    
    def __str__(self):
        status = "active" if self.is_active else "inactive"
        return f"{self.name} ({status})"
    
    def is_circuit_open(self) -> bool:
        """Check if circuit breaker is open."""
        if self.circuit_open_until is None:
            return False
        return timezone.now() < self.circuit_open_until
    
    def record_success(self, status_code: int):
        """Record successful delivery."""
        self.last_triggered = timezone.now()
        self.last_status_code = status_code
        self.failure_count = 0
        self.circuit_open_until = None
        self.save(update_fields=[
            'last_triggered', 'last_status_code',
            'failure_count', 'circuit_open_until', 'updated_at'
        ])
    
    def record_failure(self, status_code: int = None):
        """
        Record failed delivery.
        Opens circuit breaker after 5 consecutive failures.
        """
        self.last_triggered = timezone.now()
        self.last_status_code = status_code
        self.failure_count += 1
        
        # Open circuit breaker after 5 failures
        if self.failure_count >= 5:
            from datetime import timedelta
            self.circuit_open_until = timezone.now() + timedelta(minutes=15)
        
        self.save(update_fields=[
            'last_triggered', 'last_status_code',
            'failure_count', 'circuit_open_until', 'updated_at'
        ])


class WebhookDelivery(models.Model):
    """
    Tracks individual webhook delivery attempts.
    Useful for debugging and audit.
    """
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        SUCCESS = 'success', 'Success'
        FAILED = 'failed', 'Failed'
        SKIPPED = 'skipped', 'Skipped'
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    endpoint = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    event_type = models.CharField(max_length=100, db_index=True)
    payload = models.JSONField(default=dict)
    
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    status_code = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    attempt_count = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'webhook_deliveries'
        verbose_name = 'webhook delivery'
        verbose_name_plural = 'webhook deliveries'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['event_type']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.event_type} -> {self.endpoint.name} ({self.status})"
