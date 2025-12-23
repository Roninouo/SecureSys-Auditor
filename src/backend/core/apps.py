"""
Core app configuration.
"""
from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    verbose_name = 'SecureSys Core'

    def ready(self):
        """Initialize app components when Django is ready."""
        # Import signals
        import core.signals  # noqa: F401
        
        # Initialize OpenTelemetry instrumentation
        from core.telemetry import initialize_telemetry
        initialize_telemetry()

