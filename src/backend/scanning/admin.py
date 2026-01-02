"""
Django Admin configuration for the Scanning app.
"""
from django.contrib import admin
from django.utils.html import format_html

from .models import Finding, Recommendation, Scan, System


@admin.register(System)
class SystemAdmin(admin.ModelAdmin):
    """Admin for System model."""

    list_display = [
        "hostname",
        "os",
        "environment",
        "is_active",
        "latest_risk_score",
        "latest_maturity_level",
        "last_seen",
    ]
    list_filter = ["environment", "is_active", "os"]
    search_fields = ["hostname", "os", "description"]
    readonly_fields = ["id", "created_at", "updated_at", "last_seen", "latest_risk_score", "latest_maturity_level"]
    ordering = ["-last_seen", "hostname"]

    fieldsets = (
        (None, {"fields": ("hostname", "os", "os_version", "environment")}),
        ("Network", {"fields": ("ip_address", "description")}),
        ("Status", {"fields": ("is_active", "latest_risk_score", "latest_maturity_level")}),
        ("Timestamps", {"fields": ("last_seen", "created_at", "updated_at"), "classes": ("collapse",)}),
    )


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    """Admin for Scan model."""

    list_display = [
        "id_short",
        "system_hostname",
        "scan_type",
        "status",
        "risk_score_display",
        "maturity_level",
        "scan_date",
    ]
    list_filter = ["status", "maturity_level", "scan_type"]
    search_fields = ["id", "system__hostname"]
    readonly_fields = ["id", "created_at", "updated_at", "scan_date", "started_at", "completed_at"]
    raw_id_fields = ["system"]
    ordering = ["-scan_date"]

    def id_short(self, obj):
        return str(obj.id)[:8] + "..."

    id_short.short_description = "Scan ID"

    def system_hostname(self, obj):
        return obj.system.hostname

    system_hostname.short_description = "System"

    def risk_score_display(self, obj):
        if obj.risk_score is None:
            return "-"

        if obj.risk_score < 40:
            color = "green"
        elif obj.risk_score < 60:
            color = "orange"
        elif obj.risk_score < 80:
            color = "red"
        else:
            color = "darkred"

        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.risk_score)

    risk_score_display.short_description = "Risk Score"

    fieldsets = (
        (None, {"fields": ("system", "scan_type", "status")}),
        ("Results", {"fields": ("risk_score", "maturity_level", "score_breakdown")}),
        ("Data", {"fields": ("scan_payload", "error_message"), "classes": ("collapse",)}),
        (
            "Timestamps",
            {
                "fields": ("scan_date", "started_at", "completed_at", "created_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    """Admin for Finding model."""

    list_display = ["title", "category", "severity_display", "scan_hostname", "is_resolved", "created_at"]
    list_filter = ["severity", "category", "is_resolved"]
    search_fields = ["title", "description", "scan__system__hostname"]
    readonly_fields = ["id", "created_at", "updated_at", "resolved_at"]
    raw_id_fields = ["scan"]
    ordering = ["-severity", "-created_at"]

    def scan_hostname(self, obj):
        return obj.scan.system.hostname

    scan_hostname.short_description = "System"

    def severity_display(self, obj):
        colors = {
            "critical": "darkred",
            "high": "red",
            "medium": "orange",
            "low": "green",
        }
        return format_html(
            '<span style="color: {}; font-weight: bold; text-transform: uppercase;">{}</span>',
            colors.get(obj.severity, "gray"),
            obj.severity,
        )

    severity_display.short_description = "Severity"

    actions = ["mark_resolved", "mark_unresolved"]

    def mark_resolved(self, request, queryset):
        queryset.update(is_resolved=True)
        self.message_user(request, f"{queryset.count()} findings marked as resolved.")

    mark_resolved.short_description = "Mark selected findings as resolved"

    def mark_unresolved(self, request, queryset):
        queryset.update(is_resolved=False, resolved_at=None)
        self.message_user(request, f"{queryset.count()} findings marked as unresolved.")

    mark_unresolved.short_description = "Mark selected findings as unresolved"


@admin.register(Recommendation)
class RecommendationAdmin(admin.ModelAdmin):
    """Admin for Recommendation model."""

    list_display = ["title", "finding_title", "priority", "effort", "created_at"]
    list_filter = ["priority", "effort"]
    search_fields = ["title", "description", "finding__title"]
    readonly_fields = ["id", "created_at", "updated_at"]
    raw_id_fields = ["finding"]
    ordering = ["-priority", "effort"]

    def finding_title(self, obj):
        return obj.finding.title

    finding_title.short_description = "Finding"
