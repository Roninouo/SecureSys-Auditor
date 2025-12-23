"""
Scanning App for SecureSys Auditor.

Handles scan processing with:
- Data models for System, Scan, Finding, Recommendation
- Service layer for business logic
- REST API endpoints for frontend/agent integration
- Proper Celery task design (IDs, not ORM objects)
- Dedicated queue for scan processing
"""
default_app_config = 'scanning.apps.ScanningConfig'
