"""
Signals for the core app.
"""
from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import AuditLog, Scan, System, User


@receiver(post_save, sender=User)
def log_user_creation(sender, instance, created, **kwargs):
    """Log when a new user is created."""
    if created:
        AuditLog.objects.create(
            user=instance,
            action=AuditLog.Action.USER_CREATED,
            resource_type="User",
            resource_id=instance.id,
            metadata={"email": instance.email, "role": instance.role},
        )


@receiver(post_save, sender=System)
def log_system_creation(sender, instance, created, **kwargs):
    """Log when a new system is registered."""
    if created:
        AuditLog.objects.create(
            action=AuditLog.Action.CREATE_SYSTEM,
            resource_type="System",
            resource_id=instance.id,
            metadata={"hostname": instance.hostname, "os": instance.os, "environment": instance.environment},
        )


@receiver(post_save, sender=Scan)
def log_scan_submission(sender, instance, created, **kwargs):
    """Log when a new scan is submitted."""
    if created:
        AuditLog.objects.create(
            action=AuditLog.Action.SUBMIT_SCAN,
            resource_type="Scan",
            resource_id=instance.id,
            metadata={"system_id": str(instance.system.id), "hostname": instance.system.hostname},
        )
