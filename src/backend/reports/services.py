"""
Report Generation Service Layer.

Implements the Service Layer pattern to separate business logic
from views and Celery tasks.

Benefits:
- Testable without HTTP/Celery overhead
- Reusable across different entry points
- Clear transaction boundaries
"""
import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)


class ReportType(str, Enum):
    """Report type enumeration."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"


@dataclass
class ReportResult:
    """Result of report generation."""

    scan_id: str
    report_type: str
    filename: str
    file_path: str
    file_size: int
    generated_at: datetime

    def to_dict(self):
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "report_type": self.report_type,
            "filename": self.filename,
            "file_path": self.file_path,
            "file_size": self.file_size,
            "generated_at": self.generated_at.isoformat(),
        }


class ReportService:
    """
    Report generation service.

    Encapsulates all report generation logic, making it:
    - Testable in isolation
    - Reusable from views and tasks
    - Clear about dependencies
    """

    def __init__(self, reports_dir: Optional[Path] = None):
        """
        Initialize the report service.

        Args:
            reports_dir: Directory for storing reports (defaults to MEDIA_ROOT/reports)
        """
        self.reports_dir = reports_dir or (Path(settings.MEDIA_ROOT) / "reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self, scan_id: str, report_type: str = "executive", company_name: str = "Organization"
    ) -> ReportResult:
        """
        Generate a PDF report for a scan.

        Args:
            scan_id: UUID of the scan
            report_type: Type of report (executive, technical, compliance)
            company_name: Company name for report header

        Returns:
            ReportResult with file information

        Raises:
            ValueError: If scan not found or not completed
            RuntimeError: If WeasyPrint not available
        """
        from .generator import PDF_GENERATION_AVAILABLE, PDFReportGenerator

        if not PDF_GENERATION_AVAILABLE:
            raise RuntimeError("No PDF generation engine available")

        # Import here to avoid circular dependency
        from scanning.models import Scan

        # Get scan
        try:
            scan = Scan.objects.select_related("system").prefetch_related("findings__recommendations").get(id=scan_id)
        except Scan.DoesNotExist:
            raise ValueError(f"Scan not found: {scan_id}")

        if scan.status != Scan.Status.COMPLETED:
            raise ValueError(f"Cannot generate report for scan with status: {scan.status}")

        # Generate PDF
        generator = PDFReportGenerator()
        pdf_bytes = generator.generate(scan=scan, report_type=report_type, company_name=company_name)

        # Generate filename
        timestamp = timezone.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{scan_id}_{report_type}_{timestamp}.pdf"
        filepath = self.reports_dir / filename

        # Write to file
        with open(filepath, "wb") as f:
            f.write(pdf_bytes)

        logger.info(
            f"Report generated: {filename}",
            extra={
                "scan_id": scan_id,
                "report_type": report_type,
                "file_size": len(pdf_bytes),
            },
        )

        return ReportResult(
            scan_id=scan_id,
            report_type=report_type,
            filename=filename,
            file_path=str(filepath),
            file_size=len(pdf_bytes),
            generated_at=timezone.now(),
        )

    def get_report_path(self, filename: str) -> Optional[Path]:
        """
        Get the full path for a report file.

        Args:
            filename: Report filename

        Returns:
            Path to report file if exists, None otherwise
        """
        filepath = self.reports_dir / filename
        return filepath if filepath.exists() else None

    def cleanup_old_reports(self, days: int = 30) -> int:
        """
        Remove reports older than specified days.

        Args:
            days: Age threshold in days

        Returns:
            Number of reports removed
        """
        from datetime import timedelta

        cutoff = timezone.now() - timedelta(days=days)
        removed = 0

        for filepath in self.reports_dir.glob("*.pdf"):
            mtime = datetime.fromtimestamp(filepath.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                filepath.unlink()
                removed += 1

        logger.info(f"Cleaned up {removed} old reports")
        return removed


# Singleton instance for convenience
_report_service: Optional[ReportService] = None


def get_report_service() -> ReportService:
    """Get the report service singleton."""
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service
