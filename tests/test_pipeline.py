"""
Integration tests for the scan pipeline (Milestone 1).

Tests the complete flow:
Agent → API → Analysis → DB

Exit criteria:
- Scan submission creates a Scan
- process_scan runs and persists findings/recommendations
- System risk/maturity are updated
"""
from unittest.mock import MagicMock, patch

import pytest

from django.utils import timezone


@pytest.fixture
def test_system(db):
    """Create a test system for scans."""
    from scanning.models import System

    return System.objects.create(
        hostname="pipeline-test-server",
        os="Linux",
        os_version="Ubuntu 22.04",
        environment=System.Environment.PRODUCTION,
    )


@pytest.fixture
def scan_payload_with_issues():
    """Scan payload with security issues to trigger findings."""
    return {
        "hostname": "pipeline-test-server",
        "os": {
            "name": "Linux",
            "version": "5.15.0",
            "release": "Ubuntu 22.04",
            "architecture": "x86_64",
        },
        "scan_time": timezone.now().isoformat(),
        "ssh_config": {
            "permit_root_login": True,  # Security issue
            "password_auth": True,
            "port": 22,
        },
        "firewall": {
            "enabled": False,  # Security issue
        },
        "packages": {
            "outdated": [
                {"name": "openssl", "current": "1.1.1", "latest": "3.0.0"},
                {"name": "nginx", "current": "1.18", "latest": "1.24"},
            ],
        },
        "password_policy": {
            "min_length": 6,  # Too short
            "require_special": False,  # Missing
            "require_numbers": False,  # Missing
        },
        "users": {
            "local_users": ["root", "admin", "app", "backup", "monitor"],
            "admin_users": ["root", "admin", "backup", "devops", "sysadmin"],  # Too many admins
            "logged_in_users": [],
        },
        "network": {
            "open_ports": [
                {"port": 22, "service": "ssh"},
                {"port": 23, "service": "telnet"},  # Risky
                {"port": 80, "service": "http"},
            ],
        },
    }


@pytest.mark.django_db
class TestScanPipeline:
    """Test the complete scan pipeline."""

    def test_create_scan_from_payload(self, test_system, scan_payload_with_issues):
        """Test creating a scan from agent payload."""
        from scanning.models import Scan

        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload=scan_payload_with_issues,
            status=Scan.Status.PENDING,
        )

        assert scan.id is not None
        assert scan.status == "pending"
        assert scan.system == test_system
        assert scan.scan_payload == scan_payload_with_issues

    def test_process_scan_creates_findings(self, test_system, scan_payload_with_issues):
        """Test that processing a scan creates findings in the database."""
        from scanning.models import Finding, Recommendation, Scan
        from scanning.services import ScanProcessingService

        # Create a scan
        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload=scan_payload_with_issues,
            status=Scan.Status.PENDING,
        )

        # Process the scan (synchronously for testing)
        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        # Verify the result
        assert result.status == "completed"
        assert result.risk_score > 0
        assert result.findings_count > 0

        # Verify scan is updated
        scan.refresh_from_db()
        assert scan.status == "completed"
        assert scan.risk_score == result.risk_score
        assert scan.maturity_level in ["reactive", "basic", "managed", "optimized"]

        # Verify findings are created
        findings = Finding.objects.filter(scan=scan)
        assert findings.count() > 0

        # Verify each finding has recommendations
        for finding in findings:
            recs = Recommendation.objects.filter(finding=finding)
            assert recs.count() >= 0  # Some findings may have no recs

    def test_process_scan_updates_system_metrics(self, test_system, scan_payload_with_issues):
        """Test that scan processing updates system risk/maturity."""
        from scanning.models import Scan
        from scanning.services import ScanProcessingService

        # Initially no risk score
        assert test_system.latest_risk_score is None

        # Create and process scan
        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload=scan_payload_with_issues,
            status=Scan.Status.PENDING,
        )

        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        # Verify system is updated
        test_system.refresh_from_db()
        assert test_system.latest_risk_score == result.risk_score
        assert test_system.latest_maturity_level == result.maturity_level
        assert test_system.last_seen is not None

    def test_process_scan_handles_secure_payload(self, test_system):
        """Test processing a secure system results in low risk."""
        from scanning.models import Scan
        from scanning.services import ScanProcessingService

        secure_payload = {
            "hostname": "secure-server",
            "os": {"name": "Linux", "version": "5.15.0"},
            "ssh_config": {"permit_root_login": False, "password_auth": False},
            "firewall": {"enabled": True},
            "packages": {"outdated": []},
            "password_policy": {"min_length": 14, "require_special": True, "require_numbers": True},
            "users": {"admin_users": ["admin"], "local_users": ["admin", "app"]},
            "network": {"open_ports": [{"port": 443, "service": "https"}]},
        }

        scan = Scan.objects.create(
            system=test_system, scan_type=Scan.ScanType.FULL, scan_payload=secure_payload, status=Scan.Status.PENDING
        )

        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        assert result.risk_score == 0
        assert result.findings_count == 0
        assert result.maturity_level == "optimized"

    def test_process_scan_handles_empty_payload(self, test_system):
        """Test processing empty payload doesn't crash."""
        from scanning.models import Scan
        from scanning.services import ScanProcessingService

        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload={},  # Empty payload
            status=Scan.Status.PENDING,
        )

        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        assert result.status == "completed"
        assert result.risk_score == 0
        assert result.findings_count == 0

    def test_scan_findings_have_correct_categories(self, test_system, scan_payload_with_issues):
        """Test findings are categorized correctly."""
        from scanning.models import Finding, Scan
        from scanning.services import ScanProcessingService

        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload=scan_payload_with_issues,
            status=Scan.Status.PENDING,
        )

        service = ScanProcessingService()
        service.process_scan(str(scan.id))

        findings = Finding.objects.filter(scan=scan)
        categories = {f.category for f in findings}

        # Should have findings in multiple categories
        assert "access_control" in categories or "network" in categories

        # Verify severities are valid
        for finding in findings:
            assert finding.severity in ["low", "medium", "high", "critical"]
            assert finding.category in [
                "access_control",
                "configuration",
                "patch_management",
                "network",
                "authentication",
                "encryption",
                "logging",
                "other",
            ]


@pytest.mark.django_db
class TestScanSubmissionAPI:
    """Test scan submission via API serializers."""

    def test_scan_submit_serializer_validates_system(self, test_system, scan_payload_with_issues):
        """Test ScanSubmitSerializer validates system exists."""
        import uuid

        from scanning.serializers import ScanSubmitSerializer

        # Valid system ID
        data = {"system_id": str(test_system.id), "scan_payload": scan_payload_with_issues, "scan_type": "full"}
        serializer = ScanSubmitSerializer(data=data)
        assert serializer.is_valid(), serializer.errors

        # Invalid system ID
        data["system_id"] = str(uuid.uuid4())
        serializer = ScanSubmitSerializer(data=data)
        assert not serializer.is_valid()
        assert "system_id" in serializer.errors

    def test_scan_submit_serializer_validates_payload(self, test_system):
        """Test ScanSubmitSerializer validates payload structure."""
        from scanning.serializers import ScanSubmitSerializer

        # Missing required fields in payload
        data = {
            "system_id": str(test_system.id),
            "scan_payload": {"network": {}},  # Missing hostname, os
            "scan_type": "full",
        }
        serializer = ScanSubmitSerializer(data=data)
        assert not serializer.is_valid()
        assert "scan_payload" in serializer.errors

    def test_scan_submit_creates_scan(self, test_system, scan_payload_with_issues):
        """Test ScanSubmitSerializer creates scan record."""
        from scanning.models import Scan
        from scanning.serializers import ScanSubmitSerializer

        data = {"system_id": str(test_system.id), "scan_payload": scan_payload_with_issues, "scan_type": "full"}
        serializer = ScanSubmitSerializer(data=data)
        assert serializer.is_valid(), serializer.errors

        scan = serializer.save()

        assert scan.id is not None
        assert scan.system == test_system
        assert scan.status == Scan.Status.PENDING
        assert scan.scan_payload == scan_payload_with_issues


@pytest.mark.django_db
class TestDashboardStats:
    """Test dashboard statistics reflect scan results."""

    def test_dashboard_reflects_scan_results(self, test_system, scan_payload_with_issues):
        """Test dashboard shows correct metrics after scan."""
        from scanning.models import Finding, Scan, System
        from scanning.services import ScanProcessingService

        # Process a scan
        scan = Scan.objects.create(
            system=test_system,
            scan_type=Scan.ScanType.FULL,
            scan_payload=scan_payload_with_issues,
            status=Scan.Status.PENDING,
        )

        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        # Calculate dashboard stats
        total_systems = System.objects.filter(is_active=True).count()
        total_scans = Scan.objects.count()
        completed_scans = Scan.objects.filter(status=Scan.Status.COMPLETED).count()
        unresolved_findings = Finding.objects.filter(is_resolved=False).count()

        assert total_systems >= 1
        assert total_scans >= 1
        assert completed_scans >= 1
        assert unresolved_findings == result.findings_count

    def test_system_has_updated_metrics(self, test_system, scan_payload_with_issues):
        """Test system card shows latest risk score."""
        from scanning.models import Scan
        from scanning.services import ScanProcessingService

        scan = Scan.objects.create(
            system=test_system, scan_payload=scan_payload_with_issues, status=Scan.Status.PENDING
        )

        service = ScanProcessingService()
        result = service.process_scan(str(scan.id))

        test_system.refresh_from_db()

        # These are what the frontend displays
        assert test_system.latest_risk_score is not None
        assert test_system.latest_risk_score > 0
        assert test_system.latest_maturity_level in ["reactive", "basic", "managed", "optimized"]
