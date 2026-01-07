"""
Celery Tasks for Report Generation.

Uses a dedicated queue for report tasks to prevent
blocking scan processing.
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    max_retries=2,
    queue="reports",  # Dedicated queue for reports
    rate_limit="10/m",  # Rate limit to prevent resource exhaustion
)
def generate_pdf_report_task(
    self,
    scan_id: str,
    report_type: str = "executive",
    company_name: str = "Organization",
    notify_webhook: bool = False,
    requested_by_id: str = None,
):
    """
    Generate a PDF report asynchronously.

    This task uses a dedicated queue ('reports') to prevent
    blocking scan processing tasks.

    Args:
        scan_id: UUID of the scan (passed as string, not ORM object!)
        report_type: Type of report (executive, technical, compliance)
        company_name: Organization name for report header
        notify_webhook: Whether to send webhook notification
        requested_by_id: ID of user who requested the report

    Returns:
        Dictionary with report file path and metadata
    """
    from .services import get_report_service

    try:
        logger.info(f"Starting {report_type} report generation for scan {scan_id}")

        service = get_report_service()
        result = service.generate_report(scan_id=scan_id, report_type=report_type, company_name=company_name)

        # Create audit log
        _create_audit_log(scan_id, result, requested_by_id)

        # Send webhook notification if enabled
        if notify_webhook:
            _send_webhook_notification(result)

        logger.info(f"Report generated successfully: {result.filename}")

        return result.to_dict()

    except ValueError as e:
        # Don't retry for validation errors
        logger.error(f"Report generation validation error: {e}")
        raise

    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise self.retry(exc=e, countdown=30)


@shared_task(queue="reports")
def cleanup_old_reports_task(days: int = 30):
    """
    Cleanup old report files.

    Should be scheduled as a periodic task.
    """
    from .services import get_report_service

    service = get_report_service()
    removed = service.cleanup_old_reports(days=days)

    return {"removed_count": removed}


def _create_audit_log(scan_id: str, result, requested_by_id: str = None):
    """Create audit log entry for report generation."""
    try:
        from core.models import AuditLog, Scan

        scan = Scan.objects.get(id=scan_id)

        AuditLog.objects.create(
            user_id=requested_by_id,
            action=AuditLog.Action.GENERATE_REPORT,
            resource_type="scan",
            resource_id=scan.id,
            metadata={
                "report_type": result.report_type,
                "filename": result.filename,
                "file_size": result.file_size,
            },
        )
    except Exception as e:
        logger.warning(f"Failed to create audit log: {e}")


def _send_webhook_notification(result):
    """Send webhook notification for report generation."""
    try:
        from webhooks.tasks import send_webhook_notification_task

        send_webhook_notification_task.delay(event_type="report.generated", payload=result.to_dict())
    except Exception as e:
        logger.warning(f"Failed to queue webhook notification: {e}")
