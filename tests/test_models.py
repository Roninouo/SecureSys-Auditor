"""
Unit tests for Django models.

Tests coverage for:
- User model (creation, roles, managers)
- System model (lifecycle, updates)
- Scan model (status transitions, completion)
- Finding model (resolution)
- Recommendation model
- AuditLog model (immutability)
"""
import uuid
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.utils import timezone


@pytest.mark.django_db
class TestUserModel:
    """Test User model functionality."""

    def test_create_user_with_email(self):
        """Test creating a user with email."""
        from core.models import User

        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

        assert user.email == 'test@example.com'
        assert user.check_password('testpass123')
        assert user.is_active
        assert not user.is_staff
        assert user.role == User.Role.VIEWER

    def test_create_user_without_email_raises(self):
        """Test creating user without email raises ValueError."""
        from core.models import User

        with pytest.raises(ValueError, match='email'):
            User.objects.create_user(email='', password='testpass123')

    def test_create_superuser(self):
        """Test creating a superuser."""
        from core.models import User

        admin = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )

        assert admin.is_staff
        assert admin.is_superuser
        assert admin.role == User.Role.ADMIN

    def test_user_roles(self):
        """Test user role choices."""
        from core.models import User

        user = User.objects.create_user(
            email='auditor@example.com',
            password='testpass',
            role=User.Role.AUDITOR
        )

        assert user.role == 'auditor'
        assert User.Role.VIEWER in User.Role.values
        assert User.Role.AUDITOR in User.Role.values
        assert User.Role.ADMIN in User.Role.values

    def test_user_get_full_name(self):
        """Test get_full_name method."""
        from core.models import User

        user = User.objects.create_user(
            email='john@example.com',
            password='testpass',
            first_name='John',
            last_name='Doe'
        )

        assert user.get_full_name() == 'John Doe'

    def test_user_get_short_name(self):
        """Test get_short_name method."""
        from core.models import User

        user = User.objects.create_user(
            email='john@example.com',
            password='testpass',
            first_name='John'
        )

        assert user.get_short_name() == 'John'


@pytest.mark.django_db
class TestSystemModel:
    """Test System model functionality."""

    def test_create_system(self):
        """Test creating a system."""
        from core.models import System

        system = System.objects.create(
            hostname='server-01',
            os='Linux',
            os_version='Ubuntu 20.04',
            environment=System.Environment.PRODUCTION
        )

        assert system.hostname == 'server-01'
        assert system.os == 'Linux'
        assert system.environment == 'production'
        assert system.is_active
        assert system.id is not None

    def test_system_environments(self):
        """Test system environment choices."""
        from core.models import System

        assert 'development' in System.Environment.values
        assert 'staging' in System.Environment.values
        assert 'production' in System.Environment.values
        assert 'testing' in System.Environment.values

    def test_system_update_last_seen(self):
        """Test update_last_seen method."""
        from core.models import System

        system = System.objects.create(
            hostname='server-02',
            os='Linux'
        )

        old_last_seen = system.last_seen
        system.update_last_seen()
        system.refresh_from_db()

        assert system.last_seen is not None
        assert system.last_seen != old_last_seen

    def test_system_str_representation(self):
        """Test system string representation."""
        from core.models import System

        system = System.objects.create(
            hostname='web-server',
            os='Linux'
        )

        assert 'web-server' in str(system)
        assert 'Linux' in str(system)


@pytest.mark.django_db
class TestScanModel:
    """Test Scan model functionality."""

    @pytest.fixture
    def system(self):
        """Create a test system."""
        from core.models import System
        return System.objects.create(
            hostname='test-system',
            os='Linux'
        )

    def test_create_scan(self, system):
        """Test creating a scan."""
        from core.models import Scan

        scan = Scan.objects.create(
            system=system,
            scan_payload={'test': 'data'}
        )

        assert scan.system == system
        assert scan.status == Scan.Status.PENDING
        assert scan.scan_payload == {'test': 'data'}

    def test_scan_mark_processing(self, system):
        """Test mark_processing method."""
        from core.models import Scan

        scan = Scan.objects.create(system=system)
        scan.mark_processing()
        scan.refresh_from_db()

        assert scan.status == Scan.Status.PROCESSING
        assert scan.started_at is not None

    def test_scan_mark_completed(self, system):
        """Test mark_completed method."""
        from core.models import Scan

        scan = Scan.objects.create(system=system)
        scan.mark_processing()
        scan.mark_completed(
            risk_score=45,
            maturity_level='managed',
            score_breakdown={'high': 2, 'medium': 3}
        )
        scan.refresh_from_db()

        assert scan.status == Scan.Status.COMPLETED
        assert scan.risk_score == 45
        assert scan.maturity_level == 'managed'
        assert scan.completed_at is not None

        # Check system was updated
        system.refresh_from_db()
        assert system.latest_risk_score == 45
        assert system.latest_maturity_level == 'managed'

    def test_scan_mark_failed(self, system):
        """Test mark_failed method."""
        from core.models import Scan

        scan = Scan.objects.create(system=system)
        scan.mark_processing()
        scan.mark_failed('Test error message')
        scan.refresh_from_db()

        assert scan.status == Scan.Status.FAILED
        assert scan.error_message == 'Test error message'
        assert scan.completed_at is not None

    def test_scan_status_choices(self):
        """Test scan status choices."""
        from core.models import Scan

        assert 'pending' in Scan.Status.values
        assert 'processing' in Scan.Status.values
        assert 'completed' in Scan.Status.values
        assert 'failed' in Scan.Status.values

    def test_scan_maturity_levels(self):
        """Test scan maturity level choices."""
        from core.models import Scan

        assert 'reactive' in Scan.MaturityLevel.values
        assert 'basic' in Scan.MaturityLevel.values
        assert 'managed' in Scan.MaturityLevel.values
        assert 'optimized' in Scan.MaturityLevel.values


@pytest.mark.django_db
class TestFindingModel:
    """Test Finding model functionality."""

    @pytest.fixture
    def scan(self):
        """Create a test scan."""
        from core.models import System, Scan
        system = System.objects.create(hostname='finding-test', os='Linux')
        return Scan.objects.create(system=system)

    def test_create_finding(self, scan):
        """Test creating a finding."""
        from core.models import Finding

        finding = Finding.objects.create(
            scan=scan,
            category=Finding.Category.ACCESS_CONTROL,
            severity=Finding.Severity.HIGH,
            title='Test Finding',
            description='Test description'
        )

        assert finding.scan == scan
        assert finding.category == 'access_control'
        assert finding.severity == 'high'
        assert not finding.is_resolved

    def test_finding_mark_resolved(self, scan):
        """Test mark_resolved method."""
        from core.models import Finding

        finding = Finding.objects.create(
            scan=scan,
            category=Finding.Category.NETWORK,
            severity=Finding.Severity.MEDIUM,
            title='Resolve Test',
            description='Test'
        )

        finding.mark_resolved()
        finding.refresh_from_db()

        assert finding.is_resolved
        assert finding.resolved_at is not None

    def test_finding_severity_choices(self):
        """Test finding severity choices."""
        from core.models import Finding

        assert 'low' in Finding.Severity.values
        assert 'medium' in Finding.Severity.values
        assert 'high' in Finding.Severity.values
        assert 'critical' in Finding.Severity.values

    def test_finding_category_choices(self):
        """Test finding category choices."""
        from core.models import Finding

        assert 'access_control' in Finding.Category.values
        assert 'network' in Finding.Category.values
        assert 'authentication' in Finding.Category.values


@pytest.mark.django_db
class TestRecommendationModel:
    """Test Recommendation model functionality."""

    @pytest.fixture
    def finding(self):
        """Create a test finding."""
        from core.models import System, Scan, Finding
        system = System.objects.create(hostname='rec-test', os='Linux')
        scan = Scan.objects.create(system=system)
        return Finding.objects.create(
            scan=scan,
            category='access_control',
            severity='high',
            title='Test',
            description='Test'
        )

    def test_create_recommendation(self, finding):
        """Test creating a recommendation."""
        from core.models import Recommendation

        rec = Recommendation.objects.create(
            finding=finding,
            priority=Recommendation.Priority.HIGH,
            effort=Recommendation.Effort.LOW,
            title='Fix Issue',
            description='Steps to fix',
            steps=['Step 1', 'Step 2']
        )

        assert rec.finding == finding
        assert rec.priority == 'high'
        assert rec.effort == 'low'
        assert len(rec.steps) == 2
