"""
Core models for SecureSys Auditor.

This module defines the data models for:
- User: Custom user model with role-based access control
- System: Monitored systems/machines
- Scan: Security assessment executions
- Finding: Detected security issues
- Recommendation: Remediation guidance
- AuditLog: Action tracking for compliance
"""
import uuid
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom manager for User model."""

    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user."""
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', User.Role.ADMIN)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model for SecureSys Auditor.
    Uses email as the primary identifier with role-based access control.
    """
    
    class Role(models.TextChoices):
        VIEWER = 'viewer', 'Viewer'
        AUDITOR = 'auditor', 'Auditor'
        ADMIN = 'admin', 'Admin'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.VIEWER
    )
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    class Meta:
        db_table = 'users'
        verbose_name = 'user'
        verbose_name_plural = 'users'
        ordering = ['-created_at']

    def __str__(self):
        return self.email

    def get_full_name(self):
        """Return the full name of the user."""
        return f"{self.first_name} {self.last_name}".strip() or self.email

    def get_short_name(self):
        """Return the short name of the user."""
        return self.first_name or self.email.split('@')[0]


class System(models.Model):
    """
    Represents a monitored machine/system.
    """
    
    class Environment(models.TextChoices):
        DEVELOPMENT = 'development', 'Development'
        STAGING = 'staging', 'Staging'
        PRODUCTION = 'production', 'Production'
        TESTING = 'testing', 'Testing'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    hostname = models.CharField(max_length=255, db_index=True)
    os = models.CharField(max_length=255, verbose_name='Operating System')
    os_version = models.CharField(max_length=100, blank=True)
    environment = models.CharField(
        max_length=20,
        choices=Environment.choices,
        default=Environment.DEVELOPMENT
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    
    # Cached latest scan data for quick access
    latest_risk_score = models.IntegerField(null=True, blank=True)
    latest_maturity_level = models.CharField(max_length=20, blank=True)

    class Meta:
        db_table = 'systems'
        verbose_name = 'system'
        verbose_name_plural = 'systems'
        ordering = ['-last_seen', 'hostname']
        indexes = [
            models.Index(fields=['hostname']),
            models.Index(fields=['environment']),
            models.Index(fields=['last_seen']),
        ]

    def __str__(self):
        return f"{self.hostname} ({self.os})"

    def update_last_seen(self):
        """Update the last_seen timestamp."""
        self.last_seen = timezone.now()
        self.save(update_fields=['last_seen', 'updated_at'])


class Scan(models.Model):
    """
    Represents a single security assessment execution.
    """
    
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        PROCESSING = 'processing', 'Processing'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    class MaturityLevel(models.TextChoices):
        REACTIVE = 'reactive', 'Reactive'
        BASIC = 'basic', 'Basic'
        MANAGED = 'managed', 'Managed'
        OPTIMIZED = 'optimized', 'Optimized'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    system = models.ForeignKey(
        System,
        on_delete=models.CASCADE,
        related_name='scans'
    )
    scan_date = models.DateTimeField(auto_now_add=True, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING
    )
    risk_score = models.IntegerField(
        null=True,
        blank=True,
        help_text='Risk score from 0-100'
    )
    maturity_level = models.CharField(
        max_length=20,
        choices=MaturityLevel.choices,
        blank=True
    )
    
    # Raw scan payload from agent
    scan_payload = models.JSONField(default=dict)
    
    # Analysis results breakdown
    score_breakdown = models.JSONField(default=dict)
    
    # Error information if scan failed
    error_message = models.TextField(blank=True)
    
    # Timestamps
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scans'
        verbose_name = 'scan'
        verbose_name_plural = 'scans'
        ordering = ['-scan_date']
        indexes = [
            models.Index(fields=['scan_date']),
            models.Index(fields=['status']),
            models.Index(fields=['system', 'scan_date']),
        ]

    def __str__(self):
        return f"Scan {self.id} - {self.system.hostname} ({self.status})"

    def mark_processing(self):
        """Mark scan as processing."""
        self.status = self.Status.PROCESSING
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at', 'updated_at'])

    def mark_completed(self, risk_score, maturity_level, score_breakdown=None):
        """Mark scan as completed with results."""
        self.status = self.Status.COMPLETED
        self.risk_score = risk_score
        self.maturity_level = maturity_level
        self.score_breakdown = score_breakdown or {}
        self.completed_at = timezone.now()
        self.save(update_fields=[
            'status', 'risk_score', 'maturity_level',
            'score_breakdown', 'completed_at', 'updated_at'
        ])
        
        # Update system with latest scan data
        self.system.latest_risk_score = risk_score
        self.system.latest_maturity_level = maturity_level
        self.system.last_seen = timezone.now()
        self.system.save(update_fields=[
            'latest_risk_score', 'latest_maturity_level',
            'last_seen', 'updated_at'
        ])

    def mark_failed(self, error_message):
        """Mark scan as failed with error message."""
        self.status = self.Status.FAILED
        self.error_message = error_message
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'error_message', 'completed_at', 'updated_at'])


class Finding(models.Model):
    """
    Represents a detected security issue.
    """
    
    class Severity(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'

    class Category(models.TextChoices):
        ACCESS_CONTROL = 'access_control', 'Access Control'
        CONFIGURATION = 'configuration', 'Configuration'
        PATCH_MANAGEMENT = 'patch_management', 'Patch Management'
        NETWORK = 'network', 'Network'
        AUTHENTICATION = 'authentication', 'Authentication'
        ENCRYPTION = 'encryption', 'Encryption'
        LOGGING = 'logging', 'Logging'
        OTHER = 'other', 'Other'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='findings'
    )
    category = models.CharField(
        max_length=30,
        choices=Category.choices,
        db_index=True
    )
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices,
        db_index=True
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    
    # Evidence data (file paths, configurations, etc.)
    evidence = models.JSONField(default=dict)
    
    # Additional metadata
    cwe_id = models.CharField(max_length=20, blank=True, help_text='CWE ID if applicable')
    cvss_score = models.FloatField(null=True, blank=True)
    
    # Tracking
    is_resolved = models.BooleanField(default=False)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'findings'
        verbose_name = 'finding'
        verbose_name_plural = 'findings'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['severity']),
            models.Index(fields=['category']),
            models.Index(fields=['scan', 'severity']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    def mark_resolved(self):
        """Mark finding as resolved."""
        self.is_resolved = True
        self.resolved_at = timezone.now()
        self.save(update_fields=['is_resolved', 'resolved_at', 'updated_at'])


class Recommendation(models.Model):
    """
    Represents remediation guidance for a finding.
    """
    
    class Priority(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'

    class Effort(models.TextChoices):
        LOW = 'low', 'Low (< 1 hour)'
        MEDIUM = 'medium', 'Medium (1-4 hours)'
        HIGH = 'high', 'High (4+ hours)'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name='recommendations'
    )
    priority = models.CharField(
        max_length=10,
        choices=Priority.choices,
        default=Priority.MEDIUM
    )
    effort = models.CharField(
        max_length=10,
        choices=Effort.choices,
        default=Effort.MEDIUM
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    
    # Step-by-step remediation steps (stored as JSON array)
    steps = models.JSONField(default=list)
    
    # Optional automation scripts
    script_bash = models.TextField(blank=True)
    script_powershell = models.TextField(blank=True)
    script_ansible = models.TextField(blank=True)
    
    # Reference links
    references = models.JSONField(default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'recommendations'
        verbose_name = 'recommendation'
        verbose_name_plural = 'recommendations'
        ordering = ['-priority', 'effort']

    def __str__(self):
        return f"[{self.priority.upper()}] {self.title}"


class AuditLog(models.Model):
    """
    Tracks sensitive actions for compliance and security.
    Audit logs are append-only (immutable).
    """
    
    class Action(models.TextChoices):
        LOGIN = 'LOGIN', 'User Login'
        LOGOUT = 'LOGOUT', 'User Logout'
        CREATE_SYSTEM = 'CREATE_SYSTEM', 'System Created'
        UPDATE_SYSTEM = 'UPDATE_SYSTEM', 'System Updated'
        DELETE_SYSTEM = 'DELETE_SYSTEM', 'System Deleted'
        SUBMIT_SCAN = 'SUBMIT_SCAN', 'Scan Submitted'
        VIEW_SCAN = 'VIEW_SCAN', 'Scan Viewed'
        GENERATE_REPORT = 'GENERATE_REPORT', 'Report Generated'
        UPDATE_FINDING = 'UPDATE_FINDING', 'Finding Updated'
        USER_CREATED = 'USER_CREATED', 'User Created'
        USER_UPDATED = 'USER_UPDATED', 'User Updated'
        ROLE_CHANGED = 'ROLE_CHANGED', 'User Role Changed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=30, choices=Action.choices, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    
    # Request metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    # Action context
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.UUIDField(null=True, blank=True)
    
    # Additional metadata (flexible JSON field)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'audit_logs'
        verbose_name = 'audit log'
        verbose_name_plural = 'audit logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['action']),
            models.Index(fields=['user', 'timestamp']),
        ]
        # Prevent modifications to audit logs
        managed = True

    def __str__(self):
        return f"[{self.timestamp}] {self.user} - {self.action}"

    def save(self, *args, **kwargs):
        """Override save to make audit logs append-only."""
        if self.pk and AuditLog.objects.filter(pk=self.pk).exists():
            raise ValueError("Audit logs cannot be modified after creation.")
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        """Override delete to prevent deletion of audit logs."""
        raise ValueError("Audit logs cannot be deleted.")
