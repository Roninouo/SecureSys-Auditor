"""
Reports App for SecureSys Auditor.

Handles asynchronous PDF report generation with:
- Service layer abstraction
- Dedicated Celery queue for reports
- Template-based report generation
"""
default_app_config = 'reports.apps.ReportsConfig'
