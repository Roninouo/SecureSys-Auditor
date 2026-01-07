"""
API Views for the Scanning app.

Provides REST API endpoints for:
- System management (CRUD + registration)
- Scan management (submit, list, detail, findings)
- Finding management (list, detail, resolve)
- Recommendation management
- Dashboard statistics
- URL/Website security scanning
"""
import logging

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from django.db.models import Avg, Count, Q
from django.utils import timezone

from .models import Finding, Recommendation, Scan, System
from .serializers import (
    FindingDetailSerializer,
    FindingListSerializer,
    FindingSerializer,
    RecommendationListSerializer,
    RecommendationSerializer,
    ScanListSerializer,
    ScanSerializer,
    ScanSubmitSerializer,
    SystemCreateSerializer,
    SystemListSerializer,
    SystemSerializer,
    URLScanSubmitSerializer,
)
from .tasks import process_scan_task

logger = logging.getLogger(__name__)


def _is_truthy(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _synthetic_system_q(prefix: str = "") -> Q:
    field = f"{prefix}description" if prefix else "description"
    return (
        Q(**{f"{field}__icontains": "auto-generated"})
        | Q(**{f"{field}__icontains": "synthetic"})
        | Q(**{f"{field}__icontains": "for testing"})
    )


def _exclude_synthetic_systems(qs, request, *, prefix: str = ""):
    include_synthetic = _is_truthy(request.query_params.get("include_synthetic"))
    if include_synthetic:
        return qs
    return qs.exclude(_synthetic_system_q(prefix=prefix))


# ============================================================================
# Permission Classes
# ============================================================================


class IsAdminOrReadOnly(permissions.BasePermission):
    """Allow read access to all authenticated, write access only to admins."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.method in permissions.SAFE_METHODS:
            return True
        return hasattr(request.user, "role") and request.user.role == "admin"


class IsAuditorOrAdmin(permissions.BasePermission):
    """Allow access only to auditors and admins."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        return hasattr(request.user, "role") and request.user.role in ["auditor", "admin"]


class AllowAgentOrAuthenticated(permissions.BasePermission):
    """Allow agents (with API key) or authenticated users."""

    def has_permission(self, request, view):
        # Check for API key in header (agent authentication)
        api_key = request.headers.get("X-API-Key")
        if api_key:
            # In production, validate API key against database
            return True
        return request.user and request.user.is_authenticated


# ============================================================================
# System ViewSet
# ============================================================================


class SystemViewSet(viewsets.ModelViewSet):
    """
    ViewSet for System management.

    Endpoints:
    - GET /systems/ - List all active systems
    - POST /systems/ - Create/register a new system
    - GET /systems/{id}/ - Get system details
    - PUT /systems/{id}/ - Update system
    - DELETE /systems/{id}/ - Soft delete (deactivate) system
    - GET /systems/{id}/scans/ - Get all scans for a system
    """

    queryset = System.objects.filter(is_active=True)
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["environment", "os"]
    search_fields = ["hostname", "os", "description"]
    ordering_fields = ["hostname", "created_at", "last_seen", "latest_risk_score"]

    def get_queryset(self):
        qs = super().get_queryset()
        return _exclude_synthetic_systems(qs, self.request)

    def get_serializer_class(self):
        if self.action == "list":
            return SystemListSerializer
        if self.action == "create":
            return SystemCreateSerializer
        return SystemSerializer

    def perform_create(self, serializer):
        system = serializer.save()
        logger.info(
            f"System registered: {system.hostname}", extra={"system_id": str(system.id), "hostname": system.hostname}
        )

    def perform_destroy(self, instance):
        """Soft delete - mark as inactive."""
        instance.is_active = False
        instance.save(update_fields=["is_active", "updated_at"])
        logger.info(f"System deactivated: {instance.hostname}", extra={"system_id": str(instance.id)})

    @action(detail=True, methods=["get"])
    def scans(self, request, pk=None):
        """Get all scans for a specific system."""
        system = self.get_object()
        scans = Scan.objects.filter(system=system).order_by("-scan_date")

        # Optional status filtering
        scan_status = request.query_params.get("status")
        if scan_status:
            scans = scans.filter(status=scan_status)

        serializer = ScanListSerializer(scans, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=["get"])
    def by_hostname(self, request):
        """Get system by hostname (for agent registration)."""
        hostname = request.query_params.get("hostname")
        if not hostname:
            return Response({"error": "hostname parameter required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            system = System.objects.get(hostname=hostname, is_active=True)
            serializer = SystemSerializer(system)
            return Response(serializer.data)
        except System.DoesNotExist:
            return Response({"error": "System not found"}, status=status.HTTP_404_NOT_FOUND)


# ============================================================================
# Scan ViewSet
# ============================================================================


class ScanViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Scan management.

    Endpoints:
    - GET /scans/ - List all scans
    - POST /scans/submit/ - Submit a new scan from agent
    - GET /scans/{id}/ - Get scan details
    - GET /scans/{id}/findings/ - Get findings for a scan
    """

    queryset = Scan.objects.select_related("system").all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["status", "system", "maturity_level", "scan_type"]
    ordering_fields = ["scan_date", "risk_score"]

    def get_queryset(self):
        qs = super().get_queryset()
        # Synthetic is derived from the related System.description
        return _exclude_synthetic_systems(qs, self.request, prefix="system__")

    def get_serializer_class(self):
        if self.action == "list":
            return ScanListSerializer
        if self.action == "submit":
            return ScanSubmitSerializer
        return ScanSerializer

    @action(detail=False, methods=["post"], permission_classes=[AllowAgentOrAuthenticated])
    def submit(self, request):
        """
        Submit a new scan from the agent.

        Accepts scan payload, creates scan record, and queues processing task.
        """
        serializer = ScanSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan = serializer.save()

        # Queue background processing task
        process_scan_task.delay(str(scan.id))

        logger.info(
            f"Scan submitted: {scan.id}",
            extra={
                "scan_id": str(scan.id),
                "system_id": str(scan.system.id),
                "hostname": scan.system.hostname,
            },
        )

        return Response(
            {"scan_id": str(scan.id), "status": scan.status, "message": "Scan queued for processing"},
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        """Get all findings for a specific scan."""
        scan = self.get_object()
        findings = Finding.objects.filter(scan=scan)

        # Optional severity filtering
        severity = request.query_params.get("severity")
        if severity:
            findings = findings.filter(severity=severity)

        # Optional category filtering
        category = request.query_params.get("category")
        if category:
            findings = findings.filter(category=category)

        serializer = FindingListSerializer(findings, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def summary(self, request, pk=None):
        """Get summary statistics for a scan."""
        scan = self.get_object()

        findings_by_severity = scan.findings.values("severity").annotate(count=Count("id"))

        findings_by_category = scan.findings.values("category").annotate(count=Count("id"))

        return Response(
            {
                "scan_id": str(scan.id),
                "status": scan.status,
                "risk_score": scan.risk_score,
                "maturity_level": scan.maturity_level,
                "total_findings": scan.findings.count(),
                "unresolved_findings": scan.findings.filter(is_resolved=False).count(),
                "findings_by_severity": {item["severity"]: item["count"] for item in findings_by_severity},
                "findings_by_category": {item["category"]: item["count"] for item in findings_by_category},
                "duration": (
                    (scan.completed_at - scan.started_at).total_seconds()
                    if scan.completed_at and scan.started_at
                    else None
                ),
            }
        )


# ============================================================================
# Finding ViewSet
# ============================================================================


class FindingViewSet(viewsets.ModelViewSet):
    """
    ViewSet for Finding management.

    Endpoints:
    - GET /findings/ - List all findings
    - GET /findings/{id}/ - Get finding details
    - POST /findings/{id}/resolve/ - Mark finding as resolved
    - GET /findings/{id}/recommendations/ - Get recommendations for finding
    """

    queryset = Finding.objects.select_related("scan", "scan__system").all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["severity", "category", "is_resolved", "scan"]
    ordering_fields = ["severity", "created_at"]

    def get_queryset(self):
        qs = super().get_queryset()
        return _exclude_synthetic_systems(qs, self.request, prefix="scan__system__")

    def get_serializer_class(self):
        if self.action == "list":
            return FindingListSerializer
        if self.action == "retrieve":
            return FindingDetailSerializer
        return FindingSerializer

    @action(detail=True, methods=["post"], permission_classes=[IsAuditorOrAdmin])
    def resolve(self, request, pk=None):
        """Mark a finding as resolved."""
        finding = self.get_object()

        if finding.is_resolved:
            return Response({"error": "Finding is already resolved"}, status=status.HTTP_400_BAD_REQUEST)

        finding.mark_resolved()

        logger.info(
            f"Finding resolved: {finding.id}",
            extra={
                "finding_id": str(finding.id),
                "user": str(request.user.id) if request.user.is_authenticated else "anonymous",
            },
        )

        return Response({"status": "resolved", "resolved_at": finding.resolved_at})

    @action(detail=True, methods=["post"], permission_classes=[IsAuditorOrAdmin])
    def unresolve(self, request, pk=None):
        """Mark a resolved finding as unresolved."""
        finding = self.get_object()

        if not finding.is_resolved:
            return Response({"error": "Finding is not resolved"}, status=status.HTTP_400_BAD_REQUEST)

        finding.is_resolved = False
        finding.resolved_at = None
        finding.save(update_fields=["is_resolved", "resolved_at", "updated_at"])

        return Response({"status": "unresolved"})

    @action(detail=True, methods=["get"])
    def recommendations(self, request, pk=None):
        """Get recommendations for a specific finding."""
        finding = self.get_object()
        recommendations = Recommendation.objects.filter(finding=finding)
        serializer = RecommendationSerializer(recommendations, many=True)
        return Response(serializer.data)


# ============================================================================
# Recommendation ViewSet
# ============================================================================


class RecommendationViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for Recommendation management (read-only).

    Recommendations are auto-generated during scan processing.
    """

    queryset = Recommendation.objects.select_related("finding", "finding__scan").all()
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["priority", "effort", "finding"]

    def get_serializer_class(self):
        if self.action == "list":
            return RecommendationListSerializer
        return RecommendationSerializer


# ============================================================================
# Dashboard Stats View
# ============================================================================


class DashboardStatsView(APIView):
    """
    Dashboard statistics endpoint.

    Returns aggregated statistics about systems, scans, and findings.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        include_synthetic = _is_truthy(request.query_params.get("include_synthetic"))

        systems_qs = System.objects.filter(is_active=True)
        scans_qs = Scan.objects.all()
        findings_qs = Finding.objects.all()

        if not include_synthetic:
            systems_qs = systems_qs.exclude(_synthetic_system_q())
            scans_qs = scans_qs.exclude(_synthetic_system_q(prefix="system__"))
            findings_qs = findings_qs.exclude(_synthetic_system_q(prefix="scan__system__"))

        # System counts
        total_systems = systems_qs.count()
        systems_by_env = dict(
            systems_qs.values("environment").annotate(count=Count("id")).values_list("environment", "count")
        )

        # Scan counts
        total_scans = scans_qs.count()
        completed_scans = scans_qs.filter(status=Scan.Status.COMPLETED).count()

        # Risk score average (only completed scans)
        avg_risk = (
            scans_qs.filter(status=Scan.Status.COMPLETED, risk_score__isnull=False).aggregate(avg=Avg("risk_score"))[
                "avg"
            ]
            or 0
        )

        # Unresolved findings count
        total_unresolved = findings_qs.filter(is_resolved=False).count()

        # Severity counts for unresolved findings
        severity_counts = dict(
            findings_qs.filter(is_resolved=False)
            .values("severity")
            .annotate(count=Count("id"))
            .values_list("severity", "count")
        )

        # Ensure all severity levels are present
        for severity in ["critical", "high", "medium", "low"]:
            if severity not in severity_counts:
                severity_counts[severity] = 0

        # Recent scans (last 10)
        recent_scans = scans_qs.select_related("system").order_by("-scan_date")[:10]
        recent_scans_data = ScanListSerializer(recent_scans, many=True).data

        return Response(
            {
                "total_systems": total_systems,
                "total_scans": total_scans,
                "completed_scans": completed_scans,
                "average_risk_score": round(avg_risk, 1),
                "total_unresolved_findings": total_unresolved,
                "severity_counts": severity_counts,
                "recent_scans": recent_scans_data,
                "systems_by_environment": systems_by_env,
            }
        )


# ============================================================================
# URL Scan View
# ============================================================================


class URLScanView(APIView):
    """
    URL/Website security scanning endpoint.

    POST /api/scans/url/
    Submits a URL for security scanning and returns results.

    The scan checks:
    - HTTP security headers (HSTS, CSP, X-Frame-Options, etc.)
    - SSL/TLS certificate validity and configuration
    - Cookie security settings
    - Server information disclosure
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        """
        Submit a URL for security scanning.

        Request body:
        {
            "url": "https://example.com",
            "environment": "production",  // optional
            "description": "Main website"  // optional
        }

        Returns scan results with findings and recommendations.
        """
        serializer = URLScanSubmitSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        url = serializer.validated_data["url"]
        environment = serializer.validated_data.get("environment", System.Environment.DEVELOPMENT)
        description = serializer.validated_data.get("description", "")
        # New option for deep content analysis
        deep_analysis = serializer.validated_data.get("deep_analysis", True)

        logger.info(f"URL scan requested for: {url} (deep_analysis={deep_analysis})")

        try:
            # Import scanner and analyzer
            from urllib.parse import urlparse

            from .scanners.content_rules import ContentSecurityAnalyzer
            from .scanners.content_scanner import ContentScanner
            from .scanners.url_scanner import URLScanner
            from .url_rules import URLSecurityAnalyzer

            # Extract hostname from URL
            parsed = urlparse(url)
            hostname = parsed.netloc

            # Get or create system for this URL
            system, created = System.objects.get_or_create(
                url=url,
                is_active=True,
                defaults={
                    "system_type": System.SystemType.WEBSITE,
                    "hostname": hostname,
                    "os": "Web",
                    "environment": environment,
                    "description": description,
                },
            )

            if not created:
                # Update environment/description if provided
                if environment:
                    system.environment = environment
                if description:
                    system.description = description
                system.save()

            # Create scan record
            scan = Scan.objects.create(
                system=system,
                scan_type=Scan.ScanType.URL_SCAN,
                status=Scan.Status.PROCESSING,
                started_at=timezone.now(),
            )

            # Perform the URL scan (headers, SSL, etc.)
            scanner = URLScanner(timeout=30, verify_ssl=True)
            scan_result = scanner.scan(url)

            # Analyze URL scan results
            url_analyzer = URLSecurityAnalyzer()
            url_analysis = url_analyzer.analyze(scan_result.to_dict())

            # Initialize combined results
            all_findings = url_analysis["findings"].copy()
            combined_score_breakdown = url_analysis["score_breakdown"].copy()
            content_analysis_data = None

            # Perform deep content analysis if enabled
            if deep_analysis:
                try:
                    content_scanner = ContentScanner(timeout=30)
                    content_result = content_scanner.scan(url)
                    content_analysis_data = content_result.to_dict()

                    # Analyze content for security issues
                    content_analyzer = ContentSecurityAnalyzer()
                    content_analysis = content_analyzer.analyze(content_analysis_data)

                    # Merge findings
                    all_findings.extend(content_analysis["findings"])

                    # Merge score breakdowns
                    for severity, count in content_analysis["score_breakdown"].items():
                        combined_score_breakdown[severity] = combined_score_breakdown.get(severity, 0) + count

                    logger.info(
                        f"Content analysis completed for {url}: "
                        f"content_findings={len(content_analysis['findings'])}"
                    )
                except Exception:
                    logger.warning(
                        "Content analysis failed; continuing with URL-only analysis",
                        extra={"url": url},
                        exc_info=True,
                    )

                    # Best-effort internal error metric
                    try:
                        from observability.metrics import security_metrics

                        security_metrics.record_internal_error(component="scanning", operation="content_analysis")
                    except Exception:
                        logger.debug("Failed to record content analysis metric", exc_info=True)
                    # Continue with URL-only analysis

            # Calculate combined risk score
            severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
            combined_risk_score = min(
                100, sum(count * severity_weights.get(sev, 0) for sev, count in combined_score_breakdown.items())
            )

            # Determine maturity level
            maturity_thresholds = {"optimized": 20, "managed": 40, "basic": 60, "reactive": 100}
            combined_maturity = "reactive"
            for level, threshold in maturity_thresholds.items():
                if combined_risk_score <= threshold:
                    combined_maturity = level
                    break

            # Build comprehensive scan payload
            scan_payload = scan_result.to_dict()
            if content_analysis_data:
                scan_payload["content_analysis"] = content_analysis_data

            # Store scan payload
            scan.scan_payload = scan_payload

            # Create findings and recommendations
            findings_created = self._create_findings(scan, all_findings)

            # Update scan with results
            scan.risk_score = combined_risk_score
            scan.maturity_level = combined_maturity
            scan.score_breakdown = combined_score_breakdown
            scan.status = Scan.Status.COMPLETED
            scan.completed_at = timezone.now()
            scan.save()

            # Update system with latest scan data
            system.latest_risk_score = combined_risk_score
            system.latest_maturity_level = combined_maturity
            system.last_seen = timezone.now()
            system.save()

            logger.info(
                "URL scan completed for %s: risk_score=%s, findings=%s (url=%s, content=%s)",
                url,
                combined_risk_score,
                len(findings_created),
                len(url_analysis["findings"]),
                len(all_findings) - len(url_analysis["findings"]),
            )

            # Build response with comprehensive details
            response_data = {
                "scan_id": str(scan.id),
                "system_id": str(system.id),
                "url": url,
                "status": "completed",
                "risk_score": combined_risk_score,
                "maturity_level": combined_maturity,
                "findings_count": len(findings_created),
                "score_breakdown": combined_score_breakdown,
                "scan_details": {
                    "final_url": scan_result.final_url,
                    "status_code": scan_result.status_code,
                    "response_time_ms": scan_result.response_time_ms,
                    "ssl_valid": scan_result.ssl_info.is_valid if scan_result.ssl_info else None,
                    "ssl_days_until_expiry": scan_result.ssl_info.days_until_expiry if scan_result.ssl_info else None,
                    "missing_headers": scan_result.security_headers.missing_headers
                    if scan_result.security_headers
                    else [],
                    "redirects": scan_result.redirects,
                    "errors": scan_result.errors,
                },
            }

            # Add content analysis summary if performed
            if content_analysis_data:
                response_data["content_analysis"] = {
                    "performed": True,
                    "page_title": content_analysis_data.get("page_title"),
                    "content_length": content_analysis_data.get("content_length"),
                    "scripts_count": len(content_analysis_data.get("scripts", [])),
                    "forms_count": len(content_analysis_data.get("forms", [])),
                    "third_party_resources": len(content_analysis_data.get("third_party_resources", [])),
                    "detected_technologies": content_analysis_data.get("detected_technologies", []),
                    "has_mixed_content": content_analysis_data.get("has_mixed_content", False),
                    "has_inline_event_handlers": content_analysis_data.get("has_inline_event_handlers", 0),
                    "sensitive_data_exposure": {
                        "emails_found": content_analysis_data.get("sensitive_data", {}).get("emails_count", 0),
                        "api_keys_found": len(content_analysis_data.get("sensitive_data", {}).get("api_keys", [])),
                        "private_keys_found": content_analysis_data.get("sensitive_data", {}).get(
                            "private_keys_found", False
                        ),
                    }
                    if content_analysis_data.get("sensitive_data")
                    else None,
                }
            else:
                response_data["content_analysis"] = {"performed": False}

            return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(
                "URL scan failed",
                extra={"url": url},
                exc_info=True,
            )

            try:
                from observability.metrics import security_metrics

                security_metrics.record_internal_error(component="scanning", operation="url_scan")
            except Exception:
                logger.debug("Failed to record url_scan metric", exc_info=True)

            # If scan was created, mark it as failed
            if "scan" in locals():
                scan.status = Scan.Status.FAILED
                scan.error_message = str(e)
                scan.completed_at = timezone.now()
                scan.save()

            return Response(
                {
                    "error": "URL scan failed",
                    "detail": str(e),
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def _create_findings(self, scan, findings_data):
        """Create Finding and Recommendation records from analysis results."""
        findings = []

        for finding_data in findings_data:
            finding = Finding.objects.create(
                scan=scan,
                category=finding_data["category"],
                severity=finding_data["severity"],
                title=finding_data["title"],
                description=finding_data["description"],
                evidence=finding_data.get("evidence", {}),
            )
            findings.append(finding)

            # Create recommendations
            for rec_data in finding_data.get("recommendations", []):
                Recommendation.objects.create(
                    finding=finding,
                    priority=rec_data.get("priority", "medium"),
                    effort=rec_data.get("effort", "medium"),
                    title=rec_data["title"],
                    description=rec_data["description"],
                    steps=rec_data.get("steps", []),
                )

        return findings


# ============================================================================
# Health Check View
# ============================================================================


class ScanningHealthCheckView(APIView):
    """Health check endpoint for the scanning service."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response(
            {
                "status": "healthy",
                "service": "SecureSys Scanning API",
                "version": "1.0.0",
                "timestamp": timezone.now().isoformat(),
            }
        )
