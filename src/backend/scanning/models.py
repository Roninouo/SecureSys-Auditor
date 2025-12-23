"""
Scanning Models for SecureSys Auditor.

This module defines the data models for security scanning:
- System: Monitored systems/machines
- Scan: Security assessment executions
- Finding: Detected security issues
- Recommendation: Remediation guidance

These models were migrated from core.models as part of Phase 3
architectural decoupling to establish proper domain separation.
"""
import uuid
from django.db import models
from django.utils import timezone


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
        db_table = 'scanning_systems'
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

    class ScanType(models.TextChoices):
        FULL = 'full', 'Full Scan'
        QUICK = 'quick', 'Quick Scan'
        COMPLIANCE = 'compliance', 'Compliance Scan'
        VULNERABILITY = 'vulnerability', 'Vulnerability Scan'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    system = models.ForeignKey(
        System,
        on_delete=models.CASCADE,
        related_name='scans'
    )
    scan_type = models.CharField(
        max_length=20,
        choices=ScanType.choices,
        default=ScanType.FULL
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
        db_table = 'scanning_scans'
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
        db_table = 'scanning_findings'
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
        db_table = 'scanning_recommendations'
        verbose_name = 'recommendation'
        verbose_name_plural = 'recommendations'
        ordering = ['-priority', 'effort']

    def __str__(self):
        return f"[{self.priority.upper()}] {self.title}"
