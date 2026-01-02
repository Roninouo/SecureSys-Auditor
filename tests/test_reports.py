"""
Tests for PDF Report Generation (Milestone 3).

Exit criteria:
- Report endpoint returns/stores a PDF for an existing scan
"""
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Check WeasyPrint availability once
try:
    from reports.generator import WEASYPRINT_AVAILABLE
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

weasyprint_skip = pytest.mark.skipif(
    not WEASYPRINT_AVAILABLE, reason="WeasyPrint not available (requires GTK libraries)"
)


@pytest.fixture
def processed_scan(db):
    """Create a completed scan with findings for report generation."""
    from scanning.models import Finding, Recommendation, Scan, System
    from scanning.services import ScanProcessingService

    # Create system
    system = System.objects.create(
        hostname="report-test-server", os="Linux", os_version="Ubuntu 22.04", environment=System.Environment.PRODUCTION
    )

    # Create scan with issues
    scan_payload = {
        "hostname": "report-test-server",
        "os": {"name": "Linux", "version": "5.15.0"},
        "ssh_config": {"permit_root_login": True},
        "firewall": {"enabled": False},
        "packages": {"outdated": [{"name": "openssl", "current": "1.0", "latest": "3.0"}]},
        "password_policy": {"min_length": 6, "require_special": False},
        "users": {"admin_users": ["root", "admin", "backup", "devops"]},
        "network": {"open_ports": [{"port": 23, "service": "telnet"}]},
    }

    scan = Scan.objects.create(
        system=system, scan_type=Scan.ScanType.FULL, scan_payload=scan_payload, status=Scan.Status.PENDING
    )

    # Process to create findings
    service = ScanProcessingService()
    service.process_scan(str(scan.id))

    scan.refresh_from_db()
    return scan


@pytest.mark.django_db
class TestReportGenerator:
    """Test PDF report generation."""

    @weasyprint_skip
    def test_pdf_generator_produces_bytes(self, processed_scan):
        """Test PDFReportGenerator produces valid PDF bytes."""
        from reports.generator import PDFReportGenerator

        generator = PDFReportGenerator()
        pdf_bytes = generator.generate(scan=processed_scan, report_type="executive", company_name="Test Organization")

        # PDF files start with %PDF
        assert pdf_bytes[:4] == b"%PDF"
        assert len(pdf_bytes) > 1000  # A real PDF should be > 1KB

    @weasyprint_skip
    def test_generator_handles_all_report_types(self, processed_scan):
        """Test generator handles all report types."""
        from reports.generator import PDFReportGenerator

        generator = PDFReportGenerator()

        for report_type in ["executive", "technical", "compliance"]:
            pdf_bytes = generator.generate(scan=processed_scan, report_type=report_type, company_name="Test Org")
            assert pdf_bytes[:4] == b"%PDF"

    def test_generator_context_includes_findings(self, processed_scan):
        """Test report context includes all findings data."""
        from reports.generator import PDFReportGenerator

        generator = PDFReportGenerator()
        context = generator._build_context(processed_scan, "executive", "Test Org")

        assert "scan" in context
        assert "system" in context
        assert "findings" in context
        assert "severity_groups" in context
        assert context["total_findings"] >= 0
        assert "critical" in context["severity_groups"]


@pytest.mark.django_db
class TestReportService:
    """Test report service layer."""

    @weasyprint_skip
    def test_service_generates_and_saves_report(self, processed_scan):
        """Test service generates report and saves to disk."""
        from reports.services import ReportService

        # Use temp directory
        with tempfile.TemporaryDirectory() as tmpdir:
            service = ReportService(reports_dir=Path(tmpdir))
            result = service.generate_report(
                scan_id=str(processed_scan.id), report_type="executive", company_name="Test Inc."
            )

            assert result.scan_id == str(processed_scan.id)
            assert result.report_type == "executive"
            assert result.filename.endswith(".pdf")
            assert result.file_size > 0

            # File should exist
            filepath = Path(result.file_path)
            assert filepath.exists()

            # Content should be valid PDF
            with open(filepath, "rb") as f:
                content = f.read()
            assert content[:4] == b"%PDF"

    @weasyprint_skip
    def test_service_rejects_pending_scan(self, db):
        """Test service rejects report for non-completed scans."""
        from reports.services import ReportService
        from scanning.models import Scan, System

        system = System.objects.create(hostname="test", os="Linux")
        scan = Scan.objects.create(system=system, scan_payload={}, status=Scan.Status.PENDING)  # Not completed

        with tempfile.TemporaryDirectory() as tmpdir:
            service = ReportService(reports_dir=Path(tmpdir))

            with pytest.raises(ValueError, match="status"):
                service.generate_report(str(scan.id), "executive")

    @weasyprint_skip
    def test_service_rejects_nonexistent_scan(self, db):
        """Test service rejects non-existent scan ID."""
        import uuid

        from reports.services import ReportService

        with tempfile.TemporaryDirectory() as tmpdir:
            service = ReportService(reports_dir=Path(tmpdir))

            with pytest.raises(ValueError, match="not found"):
                service.generate_report(str(uuid.uuid4()), "executive")

    @weasyprint_skip
    def test_service_get_report_path(self, processed_scan):
        """Test service can retrieve saved report path."""
        from reports.services import ReportService

        with tempfile.TemporaryDirectory() as tmpdir:
            service = ReportService(reports_dir=Path(tmpdir))
            result = service.generate_report(scan_id=str(processed_scan.id), report_type="technical")

            # Should find existing report
            path = service.get_report_path(result.filename)
            assert path is not None
            assert path.exists()

            # Should return None for non-existent
            path = service.get_report_path("nonexistent.pdf")
            assert path is None


@pytest.mark.django_db
class TestReportEndpoint:
    """Test report API endpoint."""

    def test_report_type_validation(self, db):
        """Test endpoint validates report type."""
        from reports.services import ReportType

        # All valid types
        valid_types = [t.value for t in ReportType]
        assert "executive" in valid_types
        assert "technical" in valid_types
        assert "compliance" in valid_types

    @weasyprint_skip
    def test_synchronous_report_generation(self, processed_scan, rf):
        """Test synchronous report generation via API view."""
        from reports.views import ReportGenerationView

        from core.models import User

        # Create admin user
        user = User.objects.create_user(email="admin@test.com", password="testpass", role=User.Role.ADMIN)

        # Create request
        request = rf.post(
            "/reports/generate/",
            {
                "scan_id": str(processed_scan.id),
                "report_type": "executive",
                "async": False,
                "company_name": "Test Corp",
            },
            content_type="application/json",
        )
        request.user = user

        view = ReportGenerationView.as_view()
        response = view(request)

        # Should return PDF file
        assert response.status_code == 200
        assert "application/pdf" in response.get("Content-Type", "")
