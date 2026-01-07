"""
Authentication app configuration.
"""
from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    """Configuration for the authentication app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "authentication"
    verbose_name = "Authentication & Authorization"

    def ready(self):
        """Initialize authentication on app ready."""
        # Import signals if needed
        pass
