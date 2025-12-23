"""
Celery Tasks for Scan Processing.

IMPORTANT: Tasks receive IDs (strings), not ORM objects!
This follows Celery best practices for:
- Serialization safety
- Retry reliability
- Memory efficiency
"""
import logging
from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    max_retries=3,
    queue='scans',  # Dedicated queue for scan processing
    rate_limit='50/m',  # Rate limit to prevent overload
    acks_late=True,  # Acknowledge after processing (safer retries)
)
def process_scan_task(self, scan_id: str):
    """
    Process a submitted scan.
    
    IMPORTANT: Only pass scan_id, NOT the ORM object!
    
    Args:
        scan_id: UUID of the scan (string)
        
    Returns:
        Dictionary with processing results
    """
    from .services import get_scan_service
    
    try:
        logger.info(f"Starting scan processing: {scan_id}")
        
        service = get_scan_service()
        result = service.process_scan(scan_id)
        
        return result.to_dict()
        
    except ValueError as e:
        # Don't retry for validation errors
        logger.error(f"Scan validation error: {e}")
        raise
        
    except Exception as e:
        logger.error(f"Scan processing failed: {e}")
        
        # Mark scan as failed before retry
        _mark_scan_failed_safe(scan_id, str(e))
        
        # Exponential backoff retry
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(queue='scans')
def cleanup_old_scans_task(days: int = 90):
    """
    Cleanup old scan data.
    
    Removes raw payload from completed scans older than threshold.
    Keeps summary data for historical reporting.
    """
    from core.models import Scan
    
    cutoff_date = timezone.now() - timezone.timedelta(days=days)
    old_scans = Scan.objects.filter(
        scan_date__lt=cutoff_date,
        status=Scan.Status.COMPLETED
    )
    
    count = old_scans.count()
    
    # Clear payload but keep summary
    old_scans.update(scan_payload={})
    
    logger.info(f"Cleaned up {count} old scans", extra={
        'scans_cleaned': count,
        'cutoff_date': str(cutoff_date)
    })
    
    return {'cleaned': count}


@shared_task(queue='scans')
def generate_daily_report_task():
    """
    Generate daily summary of security status.
    
    Can be scheduled as a periodic task.
    """
    from core.models import System, Scan, Finding
    
    today = timezone.now().date()
    
    report = {
        'date': str(today),
        'new_scans': Scan.objects.filter(scan_date__date=today).count(),
        'new_findings': Finding.objects.filter(created_at__date=today).count(),
        'critical_unresolved': Finding.objects.filter(
            severity='critical', is_resolved=False
        ).count(),
        'high_unresolved': Finding.objects.filter(
            severity='high', is_resolved=False
        ).count(),
    }
    
    logger.info("Daily report generated", extra=report)
    
    return report


def _mark_scan_failed_safe(scan_id: str, error_message: str):
    """
    Safely mark a scan as failed.
    
    Used during error handling to ensure scan state is updated
    even if retry fails.
    """
    try:
        from core.models import Scan
        scan = Scan.objects.get(id=scan_id)
        scan.mark_failed(error_message)
    except Exception:
        pass  # Best effort - don't fail retry because of this
