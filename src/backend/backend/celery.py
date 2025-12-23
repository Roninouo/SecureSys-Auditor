"""
Celery configuration for SecureSys Auditor.
"""
import os

from celery import Celery

# Set the default Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')

app = Celery('securesys')

# Load configuration from Django settings
app.config_from_object('django.conf:settings', namespace='CELERY')

# Autodiscover tasks in all registered Django apps
app.autodiscover_tasks()


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    """Debug task for testing Celery configuration."""
    print(f'Request: {self.request!r}')
