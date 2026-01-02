"""
Observability app configuration.
"""
from django.apps import AppConfig


class ObservabilityConfig(AppConfig):
    """Configuration for the observability app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "observability"
    verbose_name = "Observability & Telemetry"

    def ready(self):
        """Initialize telemetry on app ready."""
        from .telemetry import initialize_telemetry

        initialize_telemetry()
