"""
Celery tasks for background processing.
"""
import logging
from celery import shared_task
from django.utils import timezone

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
    from .analysis import SecurityAnalyzer
    
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
