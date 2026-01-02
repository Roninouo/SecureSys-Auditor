"""
Scan Processing Service.

Implements Service Layer pattern for scan processing.
Separated from Celery tasks for testability.
"""
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of scan processing."""

    scan_id: str
    status: str
    risk_score: int
    maturity_level: str
    findings_count: int
    duration: float

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "risk_score": self.risk_score,
            "maturity_level": self.maturity_level,
            "findings_count": self.findings_count,
            "duration": self.duration,
        }


class ScanProcessingService:
    """
    Service for processing security scans.

    Encapsulates all scan processing logic:
    - Analysis execution
    - Finding creation
    - Recommendation generation
    - Score calculation

    Benefits:
    - Testable without Celery
    - Clear transaction boundaries
    - Reusable from different entry points
    """

    def __init__(self):
        """Initialize the service."""
        pass

    def process_scan(self, scan_id: str) -> ScanResult:
        """
        Process a scan and calculate results.

        Args:
            scan_id: UUID of the scan (string, not ORM object!)

        Returns:
            ScanResult with processing outcome

        Raises:
            ValueError: If scan not found or invalid state
        """
        from core.analysis import SecurityAnalyzer

        from .models import Scan

        start_time = time.time()

        # Get scan by ID
        try:
            scan = Scan.objects.select_related("system").get(id=scan_id)
        except Scan.DoesNotExist:
            raise ValueError(f"Scan not found: {scan_id}")

        # Mark as processing
        scan.mark_processing()

        logger.info(
            f"Processing scan {scan_id}",
            extra={
                "scan_id": scan_id,
                "system_id": str(scan.system.id),
                "hostname": scan.system.hostname,
            },
        )

        try:
            # Analyze payload
            analyzer = SecurityAnalyzer(scan.scan_payload)
            analysis_result = analyzer.analyze()

            # Create findings
            findings_created = self._create_findings(scan=scan, findings_data=analysis_result["findings"])

            # Mark completed
            scan.mark_completed(
                risk_score=analysis_result["risk_score"],
                maturity_level=analysis_result["maturity_level"],
                score_breakdown=analysis_result["score_breakdown"],
            )

            duration = time.time() - start_time

            logger.info(
                f"Scan {scan_id} completed",
                extra={
                    "scan_id": scan_id,
                    "risk_score": analysis_result["risk_score"],
                    "findings_count": len(findings_created),
                    "duration": duration,
                },
            )

            # Record metrics
            self._record_metrics(scan=scan, duration=duration, findings=findings_created)

            # Send webhook notification
            self._notify_scan_completed(scan, analysis_result, findings_created)

            return ScanResult(
                scan_id=scan_id,
                status="completed",
                risk_score=analysis_result["risk_score"],
                maturity_level=analysis_result["maturity_level"],
                findings_count=len(findings_created),
                duration=duration,
            )

        except Exception as e:
            scan.mark_failed(str(e))
            logger.error(f"Scan {scan_id} failed: {e}")
            raise

    def _create_findings(self, scan, findings_data: List[Dict[str, Any]]) -> List:
        """
        Create Finding and Recommendation records.

        Args:
            scan: Scan model instance
            findings_data: List of finding dictionaries from analysis

        Returns:
            List of created Finding objects
        """
        from .models import Finding, Recommendation

        findings = []

        for finding_data in findings_data:
            finding = Finding.objects.create(
                scan=scan,
                category=finding_data["category"],
                severity=finding_data["severity"],
                title=finding_data["title"],
                description=finding_data["description"],
                evidence=finding_data.get("evidence", {}),
            )
            findings.append(finding)

            # Create recommendations
            for rec_data in finding_data.get("recommendations", []):
                Recommendation.objects.create(
                    finding=finding,
                    priority=rec_data.get("priority", "medium"),
                    effort=rec_data.get("effort", "medium"),
                    title=rec_data["title"],
                    description=rec_data["description"],
                    steps=rec_data.get("steps", []),
                )

        return findings

    def _record_metrics(self, scan, duration: float, findings: List):
        """Record scan processing metrics."""
        try:
            from observability.metrics import security_metrics

            security_metrics.record_scan(
                status="completed", duration=duration, risk_score=scan.risk_score, environment=scan.system.environment
            )

            for finding in findings:
                security_metrics.record_finding(severity=finding.severity, category=finding.category)
        except Exception as e:
            logger.debug(f"Failed to record metrics: {e}")

    def _notify_scan_completed(self, scan, analysis_result: dict, findings: List):
        """Send webhook notifications for completed scan."""
        try:
            from webhooks.tasks import send_webhook_notification_task

            # Notify scan completed
            send_webhook_notification_task.delay(
                event_type="scan.completed",
                payload={
                    "scan_id": str(scan.id),
                    "system_id": str(scan.system.id),
                    "hostname": scan.system.hostname,
                    "risk_score": analysis_result["risk_score"],
                    "maturity_level": analysis_result["maturity_level"],
                    "findings_count": len(findings),
                },
            )

            # Notify critical/high findings
            critical_findings = [f for f in findings if f.severity == "critical"]
            high_findings = [f for f in findings if f.severity == "high"]

            if critical_findings:
                send_webhook_notification_task.delay(
                    event_type="finding.critical",
                    payload={
                        "scan_id": str(scan.id),
                        "system_id": str(scan.system.id),
                        "hostname": scan.system.hostname,
                        "count": len(critical_findings),
                        "titles": [f.title for f in critical_findings],
                    },
                )

            if high_findings:
                send_webhook_notification_task.delay(
                    event_type="finding.high",
                    payload={
                        "scan_id": str(scan.id),
                        "system_id": str(scan.system.id),
                        "hostname": scan.system.hostname,
                        "count": len(high_findings),
                    },
                )

        except Exception as e:
            logger.warning(f"Failed to send webhook notification: {e}")


# Singleton instance
_scan_service: Optional[ScanProcessingService] = None


def get_scan_service() -> ScanProcessingService:
    """Get the scan processing service singleton."""
    global _scan_service
    if _scan_service is None:
        _scan_service = ScanProcessingService()
    return _scan_service
