"""
Unit tests for Celery tasks.

Tests coverage for:
- process_scan task (main analysis pipeline)
- cleanup_old_scans task
- generate_daily_report task
- Error handling and retry logic
"""
import uuid
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from django.utils import timezone


@pytest.mark.django_db
class TestProcessScanTask:
    """Test process_scan Celery task."""

    @pytest.fixture
    def system(self):
        """Create a test system."""
        from core.models import System

        return System.objects.create(hostname="celery-test-system", os="Linux", os_version="Ubuntu 20.04")

    @pytest.fixture
    def scan_with_payload(self, system, sample_scan_payload):
        """Create a scan with test payload."""
        from core.models import Scan

        return Scan.objects.create(system=system, scan_payload=sample_scan_payload)

    @pytest.fixture
    def secure_scan(self, system, secure_scan_payload):
        """Create a scan with secure payload."""
        from core.models import Scan

        return Scan.objects.create(system=system, scan_payload=secure_scan_payload)

    def test_process_scan_creates_findings(self, scan_with_payload):
        """Test process_scan creates findings from analysis."""
        from core.models import Finding
        from core.tasks import process_scan

        # Run task synchronously
        result = process_scan(str(scan_with_payload.id))

        assert result["status"] == "completed"
        assert result["findings_count"] > 0

        # Verify findings were created
        findings = Finding.objects.filter(scan=scan_with_payload)
        assert findings.count() > 0

    def test_process_scan_updates_scan_status(self, scan_with_payload):
        """Test process_scan updates scan status correctly."""
        from core.models import Scan
        from core.tasks import process_scan

        result = process_scan(str(scan_with_payload.id))

        scan_with_payload.refresh_from_db()
        assert scan_with_payload.status == Scan.Status.COMPLETED
        assert scan_with_payload.risk_score is not None
        assert scan_with_payload.maturity_level != ""
        assert scan_with_payload.completed_at is not None

    def test_process_scan_calculates_risk_score(self, scan_with_payload):
        """Test process_scan calculates risk score."""
        from core.tasks import process_scan

        result = process_scan(str(scan_with_payload.id))

        assert "risk_score" in result
        assert result["risk_score"] > 0  # Insecure payload should have risk

    def test_process_scan_secure_system_low_risk(self, secure_scan):
        """Test process_scan gives low risk to secure system."""
        from core.tasks import process_scan

        result = process_scan(str(secure_scan.id))

        assert result["risk_score"] == 0
        assert result["findings_count"] == 0

    def test_process_scan_updates_system_last_seen(self, scan_with_payload, system):
        """Test process_scan updates system's latest data."""
        from core.tasks import process_scan

        process_scan(str(scan_with_payload.id))

        system.refresh_from_db()
        assert system.latest_risk_score is not None
        assert system.latest_maturity_level != ""
        assert system.last_seen is not None

    def test_process_scan_creates_recommendations(self, scan_with_payload):
        """Test process_scan creates recommendations for findings."""
        from core.models import Finding, Recommendation
        from core.tasks import process_scan

        process_scan(str(scan_with_payload.id))

        findings = Finding.objects.filter(scan=scan_with_payload)
        for finding in findings:
            recommendations = Recommendation.objects.filter(finding=finding)
            assert recommendations.count() > 0

    def test_process_scan_nonexistent_raises(self):
        """Test process_scan raises for non-existent scan."""
        from core.models import Scan
        from core.tasks import process_scan

        fake_id = str(uuid.uuid4())

        with pytest.raises(Scan.DoesNotExist):
            process_scan(fake_id)

    @patch("core.tasks.SecurityAnalyzer")
    def test_process_scan_marks_failed_on_error(self, mock_analyzer, scan_with_payload):
        """Test process_scan marks scan as failed on analysis error."""
        from core.models import Scan
        from core.tasks import process_scan

        # Make analyzer raise exception
        mock_analyzer.side_effect = Exception("Analysis failed")

        with pytest.raises(Exception):
            process_scan(str(scan_with_payload.id))

        scan_with_payload.refresh_from_db()
        assert scan_with_payload.status == Scan.Status.FAILED
        assert "Analysis failed" in scan_with_payload.error_message


@pytest.mark.django_db
class TestCleanupOldScansTask:
    """Test cleanup_old_scans task."""

    @pytest.fixture
    def old_scans(self):
        """Create old completed scans."""
        from core.models import Scan, System

        system = System.objects.create(hostname="cleanup-test", os="Linux")

        scans = []
        for i in range(3):
            scan = Scan.objects.create(system=system, scan_payload={"data": f"test-{i}"}, status=Scan.Status.COMPLETED)
            # Manually set old date
            Scan.objects.filter(id=scan.id).update(scan_date=timezone.now() - timedelta(days=100))
            scans.append(scan)

        return scans

    def test_cleanup_removes_old_payloads(self, old_scans):
        """Test cleanup removes payload data from old scans."""
        from core.models import Scan
        from core.tasks import cleanup_old_scans

        result = cleanup_old_scans(days=90)

        assert result["cleaned"] == 3

        # Verify payloads were cleared
        for scan in old_scans:
            scan.refresh_from_db()
            assert scan.scan_payload == {}

    def test_cleanup_keeps_recent_scans(self):
        """Test cleanup keeps recent scans intact."""
        from core.models import Scan, System
        from core.tasks import cleanup_old_scans

        system = System.objects.create(hostname="recent-test", os="Linux")
        scan = Scan.objects.create(system=system, scan_payload={"important": "data"}, status=Scan.Status.COMPLETED)

        cleanup_old_scans(days=90)

        scan.refresh_from_db()
        assert scan.scan_payload == {"important": "data"}


@pytest.mark.django_db
class TestGenerateDailyReportTask:
    """Test generate_daily_report task."""

    def test_generate_daily_report_returns_stats(self):
        """Test daily report returns expected statistics."""
        from core.tasks import generate_daily_report

        report = generate_daily_report()

        assert "date" in report
        assert "new_scans" in report
        assert "new_findings" in report
        assert "critical_unresolved" in report
        assert "high_unresolved" in report

    def test_generate_daily_report_counts_todays_scans(self):
        """Test daily report counts today's scans."""
        from core.models import Scan, System
        from core.tasks import generate_daily_report

        system = System.objects.create(hostname="report-test", os="Linux")

        # Create scans for today
        for i in range(3):
            Scan.objects.create(system=system)

        report = generate_daily_report()

        assert report["new_scans"] >= 3
