"""
API Views for the core app.
"""
import io
import logging

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from django.http import FileResponse
from django.shortcuts import get_object_or_404

from .models import AuditLog, Finding, Recommendation, Scan, System, User
from .serializers import (
    AuditLogSerializer,
    CustomTokenObtainPairSerializer,
    FindingDetailSerializer,
    FindingListSerializer,
    FindingSerializer,
    RecommendationSerializer,
    ReportGenerationSerializer,
    ScanListSerializer,
    ScanSerializer,
    ScanSubmitSerializer,
    SystemListSerializer,
    SystemSerializer,
    UserCreateSerializer,
    UserSerializer,
)
from .tasks import generate_pdf_report, process_scan

logger = logging.getLogger("core")


class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom JWT token view that returns additional user info."""

    serializer_class = CustomTokenObtainPairSerializer


class IsAdminOrReadOnly(permissions.BasePermission):
    """Allow read access to all, write access only to admins."""

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_authenticated and request.user.role == "admin"


class IsAuditorOrAdmin(permissions.BasePermission):
    """Allow access only to auditors and admins."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return request.user.role in ["auditor", "admin"]


class HealthCheckView(APIView):
    """Health check endpoint for monitoring."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({"status": "healthy", "service": "SecureSys Auditor API", "version": "1.0.0"})


class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for User management."""

    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]

    def get_serializer_class(self):
        if self.action == "create":
            return UserCreateSerializer
        return UserSerializer

    @action(detail=False, methods=["get"])
    def me(self, request):
        """Get current user profile."""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)


class SystemViewSet(viewsets.ModelViewSet):
    """ViewSet for System management."""

    queryset = System.objects.filter(is_active=True)
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["environment", "os"]
    search_fields = ["hostname", "os", "description"]
    ordering_fields = ["hostname", "created_at", "last_seen", "latest_risk_score"]

    def get_serializer_class(self):
        if self.action == "list":
            return SystemListSerializer
        return SystemSerializer

    def perform_create(self, serializer):
        system = serializer.save()
        logger.info(
            f"System registered: {system.hostname}", extra={"system_id": str(system.id), "hostname": system.hostname}
        )

    @action(detail=True, methods=["get"])
    def scans(self, request, pk=None):
        """Get all scans for a specific system."""
        system = self.get_object()
        scans = Scan.objects.filter(system=system).order_by("-scan_date")
        serializer = ScanListSerializer(scans, many=True)
        return Response(serializer.data)


class ScanViewSet(viewsets.ModelViewSet):
    """ViewSet for Scan management."""

    queryset = Scan.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["status", "system", "maturity_level"]
    ordering_fields = ["scan_date", "risk_score"]

    def get_serializer_class(self):
        if self.action == "list":
            return ScanListSerializer
        if self.action == "submit":
            return ScanSubmitSerializer
        return ScanSerializer

    @action(detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated])
    def submit(self, request):
        """Submit a new scan from the agent."""
        serializer = ScanSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan = serializer.save()

        # Queue background processing task
        process_scan.delay(str(scan.id))

        logger.info(f"Scan submitted: {scan.id}", extra={"scan_id": str(scan.id), "system_id": str(scan.system.id)})

        return Response({"scan_id": str(scan.id), "status": scan.status}, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        """Get all findings for a specific scan."""
        scan = self.get_object()
        findings = Finding.objects.filter(scan=scan)
        serializer = FindingListSerializer(findings, many=True)
        return Response(serializer.data)


class FindingViewSet(viewsets.ModelViewSet):
    """ViewSet for Finding management."""

    queryset = Finding.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["severity", "category", "is_resolved", "scan"]
    ordering_fields = ["severity", "created_at"]

    def get_serializer_class(self):
        if self.action == "list":
            return FindingListSerializer
        if self.action == "retrieve":
            return FindingDetailSerializer
        return FindingSerializer

    @action(detail=True, methods=["post"])
    def resolve(self, request, pk=None):
        """Mark a finding as resolved."""
        finding = self.get_object()
        finding.mark_resolved()

        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action=AuditLog.Action.UPDATE_FINDING,
            resource_type="Finding",
            resource_id=finding.id,
            metadata={"action": "resolved"},
            ip_address=self._get_client_ip(request),
        )

        return Response({"status": "resolved"})

    @action(detail=True, methods=["get"])
    def recommendations(self, request, pk=None):
        """Get recommendations for a specific finding."""
        finding = self.get_object()
        recommendations = Recommendation.objects.filter(finding=finding)
        serializer = RecommendationSerializer(recommendations, many=True)
        return Response(serializer.data)

    def _get_client_ip(self, request):
        """Extract client IP from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0]
        return request.META.get("REMOTE_ADDR")


class RecommendationViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for Recommendation (read-only)."""

    queryset = Recommendation.objects.all()
    serializer_class = RecommendationSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["priority", "effort", "finding"]


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for AuditLog (read-only, admin only)."""

    queryset = AuditLog.objects.all()
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, IsAdminOrReadOnly]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["action", "user", "resource_type"]
    ordering_fields = ["timestamp"]


class DashboardStatsView(APIView):
    """Dashboard statistics endpoint."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        """Get dashboard statistics."""
        total_systems = System.objects.filter(is_active=True).count()
        total_scans = Scan.objects.count()
        completed_scans = Scan.objects.filter(status=Scan.Status.COMPLETED).count()

        # Get severity counts
        severity_counts = {
            "critical": Finding.objects.filter(severity="critical", is_resolved=False).count(),
            "high": Finding.objects.filter(severity="high", is_resolved=False).count(),
            "medium": Finding.objects.filter(severity="medium", is_resolved=False).count(),
            "low": Finding.objects.filter(severity="low", is_resolved=False).count(),
        }

        # Calculate average risk score
        avg_risk_score = Scan.objects.filter(status=Scan.Status.COMPLETED, risk_score__isnull=False).values_list(
            "risk_score", flat=True
        )

        avg_score = sum(avg_risk_score) / len(avg_risk_score) if avg_risk_score else 0

        return Response(
            {
                "total_systems": total_systems,
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "severity_counts": severity_counts,
                "average_risk_score": round(avg_score, 1),
                "total_unresolved_findings": sum(severity_counts.values()),
            }
        )


class ReportGenerationView(APIView):
    """
    API endpoint for generating PDF security reports.

    Supports three report types:
    - executive: High-level summary for leadership
    - technical: Detailed findings for security teams
    - compliance: NIST/ISO 27001 compliance mapping
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Generate a PDF report for a completed scan.

        Request body:
        {
            "scan_id": <int>,
            "report_type": "executive" | "technical" | "compliance",
            "async": true | false (optional, default: true)
        }
        """
        serializer = ReportGenerationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.validated_data["scan_id"]
        report_type = serializer.validated_data["report_type"]
        async_generation = serializer.validated_data.get("async", True)

        # Verify scan exists and is completed
        scan = get_object_or_404(Scan, id=scan_id)

        if scan.status != Scan.Status.COMPLETED:
            return Response(
                {"error": "Report can only be generated for completed scans"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Check user has access to this scan's system
        if not request.user.is_staff:
            if not scan.system.owners.filter(id=request.user.id).exists():
                return Response(
                    {"error": "You do not have permission to generate reports for this scan"},
                    status=status.HTTP_403_FORBIDDEN,
                )

        if async_generation:
            # Queue async report generation
            task = generate_pdf_report.delay(scan_id=scan_id, report_type=report_type, requested_by=request.user.id)

            logger.info(
                f"Report generation queued: scan={scan_id}, type={report_type}, "
                f"task={task.id}, user={request.user.email}"
            )

            return Response(
                {
                    "message": "Report generation started",
                    "task_id": task.id,
                    "scan_id": scan_id,
                    "report_type": report_type,
                    "status": "processing",
                },
                status=status.HTTP_202_ACCEPTED,
            )
        else:
            # Synchronous generation (for smaller reports or testing)
            try:
                from .reports import generate_scan_report

                pdf_content = generate_scan_report(str(scan.id), report_type)

                # Create file response
                response = FileResponse(
                    io.BytesIO(pdf_content),
                    content_type="application/pdf",
                    as_attachment=True,
                    filename=f"{scan.system.hostname}_{report_type}_report_{scan.id}.pdf",
                )

                logger.info(
                    f"Report generated synchronously: scan={scan_id}, type={report_type}, " f"user={request.user.email}"
                )

                return response

            except Exception as e:
                logger.error(f"Report generation failed: {e}", exc_info=True)
                return Response(
                    {"error": "Report generation failed", "detail": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

    def get(self, request):
        """
        Get report generation status or download completed report.

        Query parameters:
        - task_id: Celery task ID to check status
        """
        task_id = request.query_params.get("task_id")

        if not task_id:
            return Response({"error": "task_id query parameter required"}, status=status.HTTP_400_BAD_REQUEST)

        from celery.result import AsyncResult

        result = AsyncResult(task_id)

        if result.state == "PENDING":
            return Response({"task_id": task_id, "status": "pending", "message": "Report generation is queued"})
        elif result.state == "STARTED":
            return Response({"task_id": task_id, "status": "processing", "message": "Report is being generated"})
        elif result.state == "SUCCESS":
            report_info = result.result
            return Response(
                {
                    "task_id": task_id,
                    "status": "completed",
                    "report_path": report_info.get("report_path"),
                    "report_type": report_info.get("report_type"),
                    "scan_id": report_info.get("scan_id"),
                    "download_url": f"/api/reports/download/{task_id}/",
                }
            )
        elif result.state == "FAILURE":
            return Response(
                {"task_id": task_id, "status": "failed", "error": str(result.result)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            return Response({"task_id": task_id, "status": result.state.lower()})
