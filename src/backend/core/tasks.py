"""
Celery tasks for background processing.
"""
import logging
from celery import shared_task
from django.utils import timezone

# Import at module scope so tests can patch `core.tasks.SecurityAnalyzer`.
from .analysis import SecurityAnalyzer

logger = logging.getLogger('core')


@shared_task(bind=True, max_retries=3)
def process_scan(self, scan_id: str):
    """
    Process a submitted scan and calculate risk score.
    
    This task:
    1. Retrieves the scan data
    2. Analyzes the payload using security rules
    3. Generates findings
    4. Calculates overall risk score
    5. Determines maturity level
    6. Creates recommendations
    """
    from .models import Scan, Finding, Recommendation
    
    try:
        scan = Scan.objects.get(id=scan_id)
        scan.mark_processing()
        
        logger.info(f"Processing scan {scan_id}", extra={
            'scan_id': scan_id,
            'system_id': str(scan.system.id)
        })
        
        # Initialize analyzer and process
        analyzer = SecurityAnalyzer(scan.scan_payload)
        analysis_result = analyzer.analyze()
        
        # Create findings from analysis
        findings_created = []
        for finding_data in analysis_result['findings']:
            finding = Finding.objects.create(
                scan=scan,
                category=finding_data['category'],
                severity=finding_data['severity'],
                title=finding_data['title'],
                description=finding_data['description'],
                evidence=finding_data.get('evidence', {})
            )
            findings_created.append(finding)
            
            # Create recommendations for each finding
            for rec_data in finding_data.get('recommendations', []):
                Recommendation.objects.create(
                    finding=finding,
                    priority=rec_data.get('priority', 'medium'),
                    effort=rec_data.get('effort', 'medium'),
                    title=rec_data['title'],
                    description=rec_data['description'],
                    steps=rec_data.get('steps', [])
                )
        
        # Mark scan as completed
        scan.mark_completed(
            risk_score=analysis_result['risk_score'],
            maturity_level=analysis_result['maturity_level'],
            score_breakdown=analysis_result['score_breakdown']
        )
        
        logger.info(f"Scan {scan_id} completed", extra={
            'scan_id': scan_id,
            'risk_score': analysis_result['risk_score'],
            'findings_count': len(findings_created)
        })
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'risk_score': analysis_result['risk_score'],
            'findings_count': len(findings_created)
        }
        
    except Scan.DoesNotExist:
        logger.error(f"Scan not found: {scan_id}")
        raise
        
    except Exception as e:
        logger.error(f"Error processing scan {scan_id}: {str(e)}")
        
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.mark_failed(str(e))
        except Scan.DoesNotExist:
            pass
        
        # Retry the task
        raise self.retry(exc=e, countdown=60)


@shared_task
def cleanup_old_scans(days: int = 90):
    """
    Cleanup old scan data older than specified days.
    Keeps summary data but removes raw payloads.
    """
    from .models import Scan
    
    cutoff_date = timezone.now() - timezone.timedelta(days=days)
    old_scans = Scan.objects.filter(
        scan_date__lt=cutoff_date,
        status=Scan.Status.COMPLETED
    )
    
    count = old_scans.count()
    
    # Clear payload data but keep summary
    old_scans.update(scan_payload={})
    
    logger.info(f"Cleaned up {count} old scans", extra={
        'scans_cleaned': count,
        'cutoff_date': str(cutoff_date)
    })
    
    return {'cleaned': count}


@shared_task
def generate_daily_report():
    """
    Generate daily summary report of security status.
    """
    from .models import System, Scan, Finding
    
    today = timezone.now().date()
    
    # Get today's stats
    new_scans = Scan.objects.filter(scan_date__date=today).count()
    new_findings = Finding.objects.filter(created_at__date=today).count()
    
    critical_unresolved = Finding.objects.filter(
        severity='critical',
        is_resolved=False
    ).count()
    
    high_unresolved = Finding.objects.filter(
        severity='high',
        is_resolved=False
    ).count()
    
    report = {
        'date': str(today),
        'new_scans': new_scans,
        'new_findings': new_findings,
        'critical_unresolved': critical_unresolved,
        'high_unresolved': high_unresolved
    }
    
    logger.info("Daily report generated", extra=report)
    
    return report


@shared_task(bind=True, max_retries=2)
def generate_pdf_report(
    self,
    scan_id: str,
    report_type: str = 'executive',
    company_name: str = 'Organization',
    notify_webhook: bool = False
):
    """
    Generate a PDF report asynchronously.
    
    This task:
    1. Fetches scan data from database
    2. Generates PDF using WeasyPrint
    3. Stores the PDF in media storage
    4. Optionally notifies via webhook
    
    Args:
        scan_id: UUID of the scan to report on
        report_type: Type of report (executive, technical, compliance)
        company_name: Organization name for report header
        notify_webhook: Whether to send webhook notification when complete
    
    Returns:
        Dictionary with report file path and metadata
    """
    import os
    from django.conf import settings
    from .reports import generate_scan_report, ReportType, WEASYPRINT_AVAILABLE
    from .models import Scan, AuditLog
    
    if not WEASYPRINT_AVAILABLE:
        logger.error("PDF generation failed: WeasyPrint not installed")
        raise RuntimeError("WeasyPrint is not available")
    
    try:
        scan = Scan.objects.get(id=scan_id)
        
        logger.info(f"Generating {report_type} PDF report for scan {scan_id}")
        
        # Generate PDF
        pdf_bytes = generate_scan_report(
            scan_id=scan_id,
            report_type=report_type,
            company_name=company_name
        )
        
        # Create reports directory if needed
        reports_dir = settings.MEDIA_ROOT / 'reports'
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate filename with timestamp
        timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
        filename = f"scan_{scan_id}_{report_type}_{timestamp}.pdf"
        filepath = reports_dir / filename
        
        # Write PDF to file
        with open(filepath, 'wb') as f:
            f.write(pdf_bytes)
        
        # Log audit entry
        AuditLog.objects.create(
            action=AuditLog.Action.GENERATE_REPORT,
            resource_type='scan',
            resource_id=scan.id,
            metadata={
                'report_type': report_type,
                'filename': filename,
                'file_size': len(pdf_bytes),
            }
        )
        
        result = {
            'scan_id': scan_id,
            'report_type': report_type,
            'filename': filename,
            'file_path': str(filepath),
            'file_size': len(pdf_bytes),
            'generated_at': timezone.now().isoformat(),
        }
        
        logger.info(f"PDF report generated successfully", extra=result)
        
        # Send webhook notification if enabled
        if notify_webhook:
            send_webhook_notification.delay(
                event_type='report.generated',
                payload=result
            )
        
        return result
        
    except Scan.DoesNotExist:
        logger.error(f"Scan not found for report generation: {scan_id}")
        raise
        
    except Exception as e:
        logger.error(f"Error generating PDF report: {str(e)}")
        raise self.retry(exc=e, countdown=30)


@shared_task(bind=True, max_retries=3)
def send_webhook_notification(self, event_type: str, payload: dict):
    """
    Send webhook notification to configured endpoints.
    
    Supports SIEM integration and external alerting systems.
    
    Args:
        event_type: Type of event (e.g., 'scan.completed', 'finding.critical')
        payload: Event payload data
    """
    import hmac
    import hashlib
    import json
    import requests
    from django.conf import settings
    
    if not settings.WEBHOOK_ENABLED:
        logger.debug("Webhooks disabled, skipping notification")
        return {'status': 'skipped', 'reason': 'webhooks_disabled'}
    
    from webhooks.models import WebhookEndpoint
    
    try:
        # Get active webhook endpoints for this event type
        endpoints = WebhookEndpoint.objects.filter(
            is_active=True,
            event_types__contains=[event_type]
        )
        
        if not endpoints.exists():
            logger.debug(f"No webhook endpoints configured for event: {event_type}")
            return {'status': 'skipped', 'reason': 'no_endpoints'}
        
        results = []
        
        for endpoint in endpoints:
            try:
                # Prepare payload
                webhook_payload = {
                    'event_type': event_type,
                    'timestamp': timezone.now().isoformat(),
                    'data': payload,
                }
                
                # Sign payload with HMAC
                payload_json = json.dumps(webhook_payload, sort_keys=True)
                signature = hmac.new(
                    endpoint.secret.encode() if endpoint.secret else settings.WEBHOOK_SECRET.encode(),
                    payload_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                headers = {
                    'Content-Type': 'application/json',
                    'X-SecureSys-Event': event_type,
                    'X-SecureSys-Signature': f'sha256={signature}',
                    'X-SecureSys-Timestamp': str(int(timezone.now().timestamp())),
                }
                
                # Add custom headers
                if endpoint.headers:
                    headers.update(endpoint.headers)
                
                # Send webhook
                response = requests.post(
                    endpoint.url,
                    json=webhook_payload,
                    headers=headers,
                    timeout=30
                )
                
                results.append({
                    'endpoint': endpoint.url,
                    'status_code': response.status_code,
                    'success': response.status_code < 400,
                })
                
                logger.info(f"Webhook sent to {endpoint.url}", extra={
                    'event_type': event_type,
                    'status_code': response.status_code
                })
                
            except requests.RequestException as e:
                logger.error(f"Webhook delivery failed: {endpoint.url}", extra={
                    'error': str(e),
                    'event_type': event_type
                })
                results.append({
                    'endpoint': endpoint.url,
                    'success': False,
                    'error': str(e),
                })
        
        return {'status': 'completed', 'results': results}
        
    except Exception as e:
        logger.error(f"Error sending webhook: {str(e)}")
        raise self.retry(exc=e, countdown=60)

