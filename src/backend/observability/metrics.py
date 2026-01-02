"""
Custom Metrics for SecureSys.

Provides business-specific metrics for monitoring and alerting.
Uses OpenTelemetry metrics API.

Guidelines:
- Only create metrics that provide actionable insights
- Avoid high-cardinality labels
- Use appropriate metric types (counter, histogram, gauge)
"""
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class SecurityMetrics:
    """
    Security-specific metrics for SLI/SLO monitoring.

    Metrics:
    - Scan processing counts and duration
    - Finding detection by severity
    - Report generation
    - Authentication events
    """

    _instance: Optional["SecurityMetrics"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        from .telemetry import OTEL_AVAILABLE, get_meter

        if not OTEL_AVAILABLE:
            self._initialized = True
            self._enabled = False
            return

        meter = get_meter()
        if not meter:
            self._initialized = True
            self._enabled = False
            return

        self._enabled = True

        # Scan metrics
        self.scans_total = meter.create_counter(
            name="securesys_scans_total",
            description="Total number of scans processed",
            unit="1",
        )

        self.scan_duration = meter.create_histogram(
            name="securesys_scan_duration_seconds",
            description="Scan processing duration",
            unit="s",
        )

        # Finding metrics
        self.findings_total = meter.create_counter(
            name="securesys_findings_total",
            description="Total findings detected",
            unit="1",
        )

        # Report metrics
        self.reports_total = meter.create_counter(
            name="securesys_reports_total",
            description="Total reports generated",
            unit="1",
        )

        # Auth metrics
        self.auth_attempts_total = meter.create_counter(
            name="securesys_auth_attempts_total",
            description="Authentication attempts",
            unit="1",
        )

        # Risk score distribution
        self.risk_score = meter.create_histogram(
            name="securesys_risk_score",
            description="Distribution of risk scores",
            unit="1",
        )

        self._initialized = True

    def record_scan(self, status: str, duration: float, risk_score: Optional[int] = None, environment: str = "unknown"):
        """
        Record scan completion metrics.

        Args:
            status: 'completed' or 'failed'
            duration: Processing time in seconds
            risk_score: Final risk score (0-100)
            environment: System environment
        """
        if not self._enabled:
            return

        labels = {
            "status": status,
            "environment": environment,
        }

        self.scans_total.add(1, labels)
        self.scan_duration.record(duration, labels)

        if risk_score is not None:
            self.risk_score.record(risk_score, {"environment": environment})

    def record_finding(self, severity: str, category: str):
        """
        Record finding detection.

        Args:
            severity: Finding severity (low, medium, high, critical)
            category: Finding category
        """
        if not self._enabled:
            return

        self.findings_total.add(
            1,
            {
                "severity": severity,
                "category": category,
            },
        )

    def record_report(self, report_type: str, duration: float):
        """
        Record report generation.

        Args:
            report_type: Type of report generated
            duration: Generation time in seconds
        """
        if not self._enabled:
            return

        self.reports_total.add(1, {"report_type": report_type})

    def record_auth(self, success: bool, provider: str):
        """
        Record authentication attempt.

        Args:
            success: Whether authentication succeeded
            provider: Auth provider name
        """
        if not self._enabled:
            return

        self.auth_attempts_total.add(
            1,
            {
                "success": str(success).lower(),
                "provider": provider,
            },
        )


# Global instance
security_metrics = SecurityMetrics()
