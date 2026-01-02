"""
Webhook Serializers.
"""
from rest_framework import serializers

from .models import WebhookDelivery, WebhookEndpoint


class WebhookEndpointSerializer(serializers.ModelSerializer):
    """Serializer for WebhookEndpoint model."""

    is_circuit_open = serializers.SerializerMethodField()

    class Meta:
        model = WebhookEndpoint
        fields = [
            "id",
            "name",
            "url",
            "secret",
            "event_types",
            "headers",
            "is_active",
            "max_retries",
            "retry_delay_seconds",
            "last_triggered",
            "last_status_code",
            "failure_count",
            "is_circuit_open",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "last_triggered", "last_status_code", "failure_count", "created_at", "updated_at"]
        extra_kwargs = {"secret": {"write_only": True}}

    def get_is_circuit_open(self, obj) -> bool:
        return obj.is_circuit_open()


class WebhookDeliverySerializer(serializers.ModelSerializer):
    """Serializer for WebhookDelivery model."""

    endpoint_name = serializers.CharField(source="endpoint.name", read_only=True)

    class Meta:
        model = WebhookDelivery
        fields = [
            "id",
            "endpoint",
            "endpoint_name",
            "event_type",
            "status",
            "status_code",
            "error_message",
            "attempt_count",
            "created_at",
            "delivered_at",
        ]
        read_only_fields = ["id", "created_at"]
