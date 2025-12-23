"""
Scanning app configuration.
"""
from django.apps import AppConfig


class ScanningConfig(AppConfig):
    """Configuration for the scanning app."""
    
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanning'
    verbose_name = 'Security Scanning'
