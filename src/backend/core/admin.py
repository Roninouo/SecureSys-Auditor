"""
Admin configuration for the core app.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, System, Scan, Finding, Recommendation, AuditLog


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model."""
    list_display = ['email', 'first_name', 'last_name', 'role', 'is_active', 'created_at']
    list_filter = ['role', 'is_active', 'is_staff']
    search_fields = ['email', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    readonly_fields = ['created_at', 'updated_at', 'last_login']
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role'),
        }),
    )


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    """Admin configuration for System model."""
    list_display = ['hostname', 'os', 'environment', 'is_active', 'last_seen', 'latest_risk_score']
    list_filter = ['environment', 'is_active', 'os']
    search_fields = ['hostname', 'os', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at', 'last_seen', 'latest_risk_score', 'latest_maturity_level']


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    """Admin configuration for Scan model."""
    list_display = ['id', 'system', 'status', 'risk_score', 'maturity_level', 'scan_date']
    list_filter = ['status', 'maturity_level']
    search_fields = ['system__hostname']
    readonly_fields = ['id', 'scan_date', 'created_at', 'updated_at', 'started_at', 'completed_at']


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    """Admin configuration for Finding model."""
    list_display = ['title', 'severity', 'category', 'scan', 'is_resolved', 'created_at']
    list_filter = ['severity', 'category', 'is_resolved']
    search_fields = ['title', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at', 'resolved_at']


@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    """Admin configuration for Recommendation model."""
    list_display = ['title', 'priority', 'effort', 'finding', 'created_at']
    list_filter = ['priority', 'effort']
    search_fields = ['title', 'description']
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin configuration for AuditLog model."""
    list_display = ['action', 'user', 'resource_type', 'timestamp', 'ip_address']
    list_filter = ['action', 'resource_type']
    search_fields = ['user__email', 'action']
    readonly_fields = ['id', 'user', 'action', 'timestamp', 'ip_address', 'user_agent', 'resource_type', 'resource_id', 'metadata']
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
