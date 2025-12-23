"""
Serializers for the core API.
"""
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model
from .models import System, Scan, Finding, Recommendation, AuditLog

User = get_user_model()


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT token serializer that includes user role."""
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        # Add custom claims
        token['email'] = user.email
        token['role'] = user.role
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        # Add extra responses
        data['role'] = self.user.role
        data['email'] = self.user.email
        data['user_id'] = str(self.user.id)
        return data


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name',
            'role', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new users."""
    
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'email', 'password', 'password_confirm',
            'first_name', 'last_name', 'role'
        ]

    def validate(self, attrs):
        if attrs['password'] != attrs.pop('password_confirm'):
            raise serializers.ValidationError({
                'password_confirm': 'Passwords do not match.'
            })
        return attrs

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class SystemSerializer(serializers.ModelSerializer):
    """Serializer for System model."""
    
    class Meta:
        model = System
        fields = [
            'id', 'hostname', 'os', 'os_version', 'environment',
            'ip_address', 'description', 'is_active',
            'created_at', 'updated_at', 'last_seen',
            'latest_risk_score', 'latest_maturity_level'
        ]
        read_only_fields = [
            'id', 'created_at', 'updated_at', 'last_seen',
            'latest_risk_score', 'latest_maturity_level'
        ]


class SystemListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for system lists."""
    
    class Meta:
        model = System
        fields = [
            'id', 'hostname', 'os', 'environment',
            'last_seen', 'latest_risk_score', 'latest_maturity_level'
        ]


class FindingSerializer(serializers.ModelSerializer):
    """Serializer for Finding model."""
    
    class Meta:
        model = Finding
        fields = [
            'id', 'scan', 'category', 'severity', 'title',
            'description', 'evidence', 'cwe_id', 'cvss_score',
            'is_resolved', 'resolved_at', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'scan', 'created_at', 'updated_at']


class FindingListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for finding lists."""
    
    class Meta:
        model = Finding
        fields = [
            'id', 'category', 'severity', 'title',
            'is_resolved', 'created_at'
        ]


class RecommendationSerializer(serializers.ModelSerializer):
    """Serializer for Recommendation model."""
    
    class Meta:
        model = Recommendation
        fields = [
            'id', 'finding', 'priority', 'effort', 'title',
            'description', 'steps', 'script_bash', 'script_powershell',
            'script_ansible', 'references', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'finding', 'created_at', 'updated_at']


class ScanSerializer(serializers.ModelSerializer):
    """Serializer for Scan model."""
    
    findings_count = serializers.SerializerMethodField()
    findings = FindingListSerializer(many=True, read_only=True)
    
    class Meta:
        model = Scan
        fields = [
            'id', 'system', 'scan_date', 'status',
            'risk_score', 'maturity_level', 'score_breakdown',
            'error_message', 'started_at', 'completed_at',
            'created_at', 'updated_at', 'findings_count', 'findings'
        ]
        read_only_fields = [
            'id', 'scan_date', 'status', 'risk_score',
            'maturity_level', 'score_breakdown', 'error_message',
            'started_at', 'completed_at', 'created_at', 'updated_at'
        ]

    def get_findings_count(self, obj):
        return obj.findings.count()


class ScanListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan lists."""
    
    system_hostname = serializers.CharField(source='system.hostname', read_only=True)
    findings_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Scan
        fields = [
            'id', 'system', 'system_hostname', 'scan_date',
            'status', 'risk_score', 'maturity_level', 'findings_count'
        ]

    def get_findings_count(self, obj):
        return obj.findings.count()


class ScanSubmitSerializer(serializers.Serializer):
    """Serializer for submitting scan data from agent."""
    
    system_id = serializers.UUIDField()
    scan_payload = serializers.JSONField()

    def validate_system_id(self, value):
        """Validate that the system exists."""
        if not System.objects.filter(id=value).exists():
            raise serializers.ValidationError('System not found.')
        return value

    def validate_scan_payload(self, value):
        """Validate scan payload structure."""
        required_keys = ['hostname', 'os']
        for key in required_keys:
            if key not in value:
                raise serializers.ValidationError(
                    f"Missing required field: {key}"
                )
        return value

    def create(self, validated_data):
        """Create a new scan from the submitted data."""
        system = System.objects.get(id=validated_data['system_id'])
        scan = Scan.objects.create(
            system=system,
            scan_payload=validated_data['scan_payload'],
            status=Scan.Status.PENDING
        )
        return scan


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model."""
    
    user_email = serializers.CharField(source='user.email', read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'user', 'user_email', 'action', 'timestamp',
            'ip_address', 'resource_type', 'resource_id', 'metadata'
        ]
        read_only_fields = '__all__'


class FindingDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for findings with recommendations."""
    
    recommendations = RecommendationSerializer(many=True, read_only=True)
    
    class Meta:
        model = Finding
        fields = [
            'id', 'scan', 'category', 'severity', 'title',
            'description', 'evidence', 'cwe_id', 'cvss_score',
            'is_resolved', 'resolved_at', 'created_at', 'updated_at',
            'recommendations'
        ]
