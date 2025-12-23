"""
Scanning App for SecureSys Auditor.

Handles scan processing with:
- Service layer for business logic
- Proper Celery task design (IDs, not ORM objects)
- Dedicated queue for scan processing
"""
default_app_config = 'scanning.apps.ScanningConfig'
