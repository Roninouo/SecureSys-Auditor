"""
Serializers for the Scanning API.

Provides serialization for System, Scan, Finding, and Recommendation models
with both full and lightweight list variants for efficient API responses.
"""
from rest_framework import serializers

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator

from .models import Finding, Recommendation, Scan, System

# ============================================================================
# System Serializers
# ============================================================================


class SystemSerializer(serializers.ModelSerializer):
    """Full serializer for System model."""

    scans_count = serializers.SerializerMethodField()

    class Meta:
        model = System
        fields = [
            "id",
            "system_type",
            "hostname",
            "url",
            "os",
            "os_version",
            "environment",
            "ip_address",
            "description",
            "is_active",
            "created_at",
            "updated_at",
            "last_seen",
            "latest_risk_score",
            "latest_maturity_level",
            "scans_count",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "last_seen", "latest_risk_score", "latest_maturity_level"]

    def get_scans_count(self, obj):
        return obj.scans.count()


class SystemListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for system lists."""

    class Meta:
        model = System
        fields = [
            "id",
            "system_type",
            "hostname",
            "url",
            "os",
            "environment",
            "last_seen",
            "latest_risk_score",
            "latest_maturity_level",
        ]


class SystemCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/registering systems."""

    class Meta:
        model = System
        fields = ["system_type", "hostname", "url", "os", "os_version", "environment", "ip_address", "description"]

    def validate(self, data):
        """Validate that websites have URLs and servers have OS."""
        system_type = data.get("system_type", System.SystemType.SERVER)

        if system_type == System.SystemType.WEBSITE:
            if not data.get("url"):
                raise serializers.ValidationError({"url": "URL is required for website targets."})
            # Set default OS for websites
            if not data.get("os"):
                data["os"] = "Web"
        else:
            if not data.get("os"):
                raise serializers.ValidationError({"os": "Operating system is required for server targets."})

        return data

    def create(self, validated_data):
        # Check if system with same hostname exists
        hostname = validated_data.get("hostname")
        existing = System.objects.filter(hostname=hostname, is_active=True).first()
        if existing:
            # Update existing system
            for key, value in validated_data.items():
                setattr(existing, key, value)
            existing.save()
            return existing
        return super().create(validated_data)


class WebsiteCreateSerializer(serializers.Serializer):
    """Serializer for creating website targets."""

    url = serializers.URLField(max_length=500)
    hostname = serializers.CharField(max_length=255, required=False)
    environment = serializers.ChoiceField(choices=System.Environment.choices, default=System.Environment.DEVELOPMENT)
    description = serializers.CharField(required=False, allow_blank=True)

    def validate_url(self, value):
        """Validate and normalize URL."""
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"

        # Validate URL format
        validator = URLValidator()
        try:
            validator(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Invalid URL format.")

        return value

    def create(self, validated_data):
        """Create or update a website system."""
        url = validated_data["url"]

        # Extract hostname from URL if not provided
        from urllib.parse import urlparse

        parsed = urlparse(url)
        hostname = validated_data.get("hostname") or parsed.netloc

        # Check if system with same URL exists
        existing = System.objects.filter(url=url, is_active=True).first()
        if existing:
            existing.environment = validated_data.get("environment", existing.environment)
            existing.description = validated_data.get("description", existing.description)
            existing.save()
            return existing

        return System.objects.create(
            system_type=System.SystemType.WEBSITE,
            hostname=hostname,
            url=url,
            os="Web",
            environment=validated_data.get("environment", System.Environment.DEVELOPMENT),
            description=validated_data.get("description", ""),
        )


# ============================================================================
# Recommendation Serializers
# ============================================================================


class RecommendationSerializer(serializers.ModelSerializer):
    """Full serializer for Recommendation model."""

    class Meta:
        model = Recommendation
        fields = [
            "id",
            "finding",
            "priority",
            "effort",
            "title",
            "description",
            "steps",
            "script_bash",
            "script_powershell",
            "script_ansible",
            "references",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "finding", "created_at", "updated_at"]


class RecommendationListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for recommendation lists."""

    class Meta:
        model = Recommendation
        fields = ["id", "priority", "effort", "title"]


# ============================================================================
# Finding Serializers
# ============================================================================


class FindingSerializer(serializers.ModelSerializer):
    """Full serializer for Finding model."""

    recommendations = RecommendationListSerializer(many=True, read_only=True)

    class Meta:
        model = Finding
        fields = [
            "id",
            "scan",
            "category",
            "severity",
            "title",
            "description",
            "evidence",
            "cwe_id",
            "cvss_score",
            "is_resolved",
            "resolved_at",
            "created_at",
            "updated_at",
            "recommendations",
        ]
        read_only_fields = ["id", "scan", "created_at", "updated_at"]


class FindingListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for finding lists."""

    class Meta:
        model = Finding
        fields = ["id", "category", "severity", "title", "is_resolved", "created_at"]


class FindingDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for finding detail view with recommendations."""

    recommendations = RecommendationSerializer(many=True, read_only=True)
    scan_info = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = [
            "id",
            "scan",
            "scan_info",
            "category",
            "severity",
            "title",
            "description",
            "evidence",
            "cwe_id",
            "cvss_score",
            "is_resolved",
            "resolved_at",
            "created_at",
            "updated_at",
            "recommendations",
        ]

    def get_scan_info(self, obj):
        return {
            "id": str(obj.scan.id),
            "system_hostname": obj.scan.system.hostname,
            "scan_date": obj.scan.scan_date,
        }


# ============================================================================
# Scan Serializers
# ============================================================================


class ScanSerializer(serializers.ModelSerializer):
    """Full serializer for Scan model."""

    findings_count = serializers.SerializerMethodField()
    findings = FindingListSerializer(many=True, read_only=True)
    system_info = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "system",
            "system_info",
            "scan_type",
            "scan_date",
            "status",
            "risk_score",
            "maturity_level",
            "score_breakdown",
            "error_message",
            "started_at",
            "completed_at",
            "created_at",
            "updated_at",
            "findings_count",
            "findings",
        ]
        read_only_fields = [
            "id",
            "scan_date",
            "status",
            "risk_score",
            "maturity_level",
            "score_breakdown",
            "error_message",
            "started_at",
            "completed_at",
            "created_at",
            "updated_at",
        ]

    def get_findings_count(self, obj):
        return obj.findings.count()

    def get_system_info(self, obj):
        return {
            "id": str(obj.system.id),
            "hostname": obj.system.hostname,
            "os": obj.system.os,
            "environment": obj.system.environment,
        }


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan lists."""

    system_hostname = serializers.CharField(source="system.hostname", read_only=True)
    findings_count = serializers.SerializerMethodField()

    class Meta:
        model = Scan
        fields = [
            "id",
            "system",
            "system_hostname",
            "scan_type",
            "scan_date",
            "status",
            "risk_score",
            "maturity_level",
            "findings_count",
        ]

    def get_findings_count(self, obj):
        return obj.findings.count()


class ScanSubmitSerializer(serializers.Serializer):
    """Serializer for submitting scan data from agent."""

    system_id = serializers.UUIDField()
    scan_payload = serializers.JSONField()
    scan_type = serializers.ChoiceField(choices=Scan.ScanType.choices, default=Scan.ScanType.FULL)

    def validate_system_id(self, value):
        """Validate that the system exists."""
        if not System.objects.filter(id=value).exists():
            raise serializers.ValidationError("System not found.")
        return value

    def validate_scan_payload(self, value):
        """Validate scan payload structure."""
        required_keys = ["hostname", "os"]
        for key in required_keys:
            if key not in value:
                raise serializers.ValidationError(f"Missing required field: {key}")
        return value

    def create(self, validated_data):
        """Create a new scan from the submitted data."""
        system = System.objects.get(id=validated_data["system_id"])
        scan = Scan.objects.create(
            system=system,
            scan_type=validated_data.get("scan_type", Scan.ScanType.FULL),
            scan_payload=validated_data["scan_payload"],
            status=Scan.Status.PENDING,
        )
        return scan


# ============================================================================
# Dashboard & Stats Serializers
# ============================================================================


class DashboardStatsSerializer(serializers.Serializer):
    """Serializer for dashboard statistics."""

    total_systems = serializers.IntegerField()
    total_scans = serializers.IntegerField()
    completed_scans = serializers.IntegerField()
    average_risk_score = serializers.FloatField()
    total_unresolved_findings = serializers.IntegerField()
    severity_counts = serializers.DictField(child=serializers.IntegerField())
    recent_scans = ScanListSerializer(many=True, read_only=True)
    systems_by_environment = serializers.DictField(child=serializers.IntegerField())


# ============================================================================
# URL Scan Serializers
# ============================================================================


class URLScanSubmitSerializer(serializers.Serializer):
    """Serializer for submitting a URL scan."""

    url = serializers.URLField(max_length=500)
    environment = serializers.ChoiceField(choices=System.Environment.choices, default=System.Environment.DEVELOPMENT)
    description = serializers.CharField(required=False, allow_blank=True, default="")

    def validate_url(self, value):
        """Validate and normalize URL."""
        if not value.startswith(("http://", "https://")):
            value = f"https://{value}"

        # Validate URL format
        validator = URLValidator()
        try:
            validator(value)
        except DjangoValidationError:
            raise serializers.ValidationError("Invalid URL format.")

        return value


class URLScanResultSerializer(serializers.Serializer):
    """Serializer for URL scan results."""

    scan_id = serializers.UUIDField()
    system_id = serializers.UUIDField()
    url = serializers.URLField()
    status = serializers.CharField()
    risk_score = serializers.IntegerField(allow_null=True)
    maturity_level = serializers.CharField(allow_null=True)
    findings_count = serializers.IntegerField()
    scan_details = serializers.DictField(allow_null=True)
