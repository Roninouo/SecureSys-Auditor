"""
Webhooks App for SecureSys Auditor.

Handles webhook configuration and delivery with:
- Rate limiting
- Retry with exponential backoff
- Circuit breaker pattern
- Dedicated Celery queue
"""
default_app_config = "webhooks.apps.WebhooksConfig"
