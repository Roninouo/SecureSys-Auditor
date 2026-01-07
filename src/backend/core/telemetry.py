"""
OpenTelemetry Instrumentation for SecureSys Auditor.

Provides distributed tracing, metrics, and logging integration
for observability across the backend services.

Features:
- Automatic Django instrumentation
- Celery task tracing
- Database query tracing
- Custom span attributes for security context
- Metrics collection for SLI/SLO monitoring
"""
import logging
from functools import wraps
from typing import Callable, Optional

from django.conf import settings

logger = logging.getLogger("core")

# Track initialization state
_instrumentation_initialized = False

# Try to import OpenTelemetry, gracefully handle if not available
try:
    from opentelemetry import metrics, trace
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.celery import CeleryInstrumentor
    from opentelemetry.instrumentation.django import DjangoInstrumentor
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
    from opentelemetry.instrumentation.redis import RedisInstrumentor
    from opentelemetry.instrumentation.requests import RequestsInstrumentor
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import SERVICE_NAME, SERVICE_VERSION, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.trace import Status, StatusCode

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    logger.info("OpenTelemetry not installed. Observability features disabled.")


def initialize_telemetry():
    """
    Initialize OpenTelemetry instrumentation.

    Should be called during Django startup (e.g., in AppConfig.ready()).
    """
    global _instrumentation_initialized

    if _instrumentation_initialized:
        return

    if not OTEL_AVAILABLE:
        logger.warning("OpenTelemetry not available, skipping initialization")
        return

    if not getattr(settings, "OTEL_ENABLED", False):
        logger.info("OpenTelemetry disabled by configuration")
        return

    try:
        # Create resource with service info
        resource = Resource.create(
            {
                SERVICE_NAME: getattr(settings, "OTEL_SERVICE_NAME", "securesys-backend"),
                SERVICE_VERSION: "2.0.0",
                "deployment.environment": getattr(settings, "ENVIRONMENT", "development"),
            }
        )

        # Configure trace provider
        endpoint = getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        trace_provider = TracerProvider(resource=resource)
        trace_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        trace_provider.add_span_processor(BatchSpanProcessor(trace_exporter))
        trace.set_tracer_provider(trace_provider)

        # Configure metrics provider
        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=endpoint, insecure=True),
            export_interval_millis=60000,  # Export every 60 seconds
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)

        # Instrument Django
        DjangoInstrumentor().instrument()

        # Instrument Celery
        CeleryInstrumentor().instrument()

        # Instrument database
        Psycopg2Instrumentor().instrument()

        # Instrument Redis
        RedisInstrumentor().instrument()

        # Instrument outgoing HTTP requests
        RequestsInstrumentor().instrument()

        _instrumentation_initialized = True
        logger.info(
            "OpenTelemetry instrumentation initialized",
            extra={
                "endpoint": endpoint,
                "service_name": getattr(settings, "OTEL_SERVICE_NAME", "securesys-backend"),
            },
        )

    except Exception as e:
        logger.error(f"Failed to initialize OpenTelemetry: {e}")


def get_tracer(name: str = "securesys.core"):
    """Get a tracer instance."""
    if not OTEL_AVAILABLE or not _instrumentation_initialized:
        return None
    return trace.get_tracer(name)


def get_meter(name: str = "securesys.core"):
    """Get a meter instance for metrics."""
    if not OTEL_AVAILABLE or not _instrumentation_initialized:
        return None
    return metrics.get_meter(name)


class TracingMiddleware:
    """
    Django middleware to add custom attributes to traces.

    Adds security-relevant context like user ID, role, and request metadata.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not OTEL_AVAILABLE or not _instrumentation_initialized:
            return self.get_response(request)

        # Get current span
        span = trace.get_current_span()

        if span and span.is_recording():
            # Add user context if authenticated
            if hasattr(request, "user") and request.user.is_authenticated:
                span.set_attribute("user.id", str(request.user.id))
                span.set_attribute("user.email", request.user.email)
                span.set_attribute("user.role", getattr(request.user, "role", "unknown"))

            # Add request metadata
            span.set_attribute("http.client_ip", self._get_client_ip(request))

            # Add custom attributes
            if hasattr(request, "auth") and request.auth:
                span.set_attribute("auth.method", "oidc" if "realm_access" in request.auth else "jwt")

        response = self.get_response(request)

        return response

    def _get_client_ip(self, request) -> str:
        """Extract client IP from request."""
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")


def traced(name: Optional[str] = None, attributes: Optional[dict] = None) -> Callable:
    """
    Decorator to add tracing to a function.

    Args:
        name: Custom span name (defaults to function name)
        attributes: Additional span attributes

    Example:
        @traced(name='process_scan', attributes={'scan.type': 'full'})
        def process_scan(scan_id):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not OTEL_AVAILABLE or not _instrumentation_initialized:
                return func(*args, **kwargs)

            tracer = get_tracer()
            if not tracer:
                return func(*args, **kwargs)

            span_name = name or func.__name__

            with tracer.start_as_current_span(span_name) as span:
                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)

                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise

        return wrapper

    return decorator


class SecurityMetrics:
    """
    Security-specific metrics for monitoring and alerting.

    Provides counters and histograms for:
    - Scan processing
    - Finding detection
    - Authentication events
    - Report generation
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        if not OTEL_AVAILABLE:
            self._initialized = True
            return

        meter = get_meter()
        if not meter:
            self._initialized = True
            return

        # Scan metrics
        self.scans_processed = meter.create_counter(
            name="securesys.scans.processed",
            description="Number of scans processed",
            unit="1",
        )

        self.scan_duration = meter.create_histogram(
            name="securesys.scans.duration",
            description="Scan processing duration",
            unit="s",
        )

        # Finding metrics
        self.findings_detected = meter.create_counter(
            name="securesys.findings.detected",
            description="Number of findings detected",
            unit="1",
        )

        # Authentication metrics
        self.auth_attempts = meter.create_counter(
            name="securesys.auth.attempts",
            description="Number of authentication attempts",
            unit="1",
        )

        # Report metrics
        self.reports_generated = meter.create_counter(
            name="securesys.reports.generated",
            description="Number of reports generated",
            unit="1",
        )

        self.report_generation_duration = meter.create_histogram(
            name="securesys.reports.duration",
            description="Report generation duration",
            unit="s",
        )

        # Risk score distribution
        self.risk_score_histogram = meter.create_histogram(
            name="securesys.risk_score",
            description="Distribution of risk scores",
            unit="1",
        )

        self._initialized = True

    def record_scan_processed(self, system_id: str, risk_score: int, duration: float):
        """Record scan processing metrics."""
        if not OTEL_AVAILABLE or not _instrumentation_initialized:
            return

        self.scans_processed.add(1, {"system_id": system_id})
        self.scan_duration.record(duration, {"system_id": system_id})
        self.risk_score_histogram.record(risk_score, {"system_id": system_id})

    def record_finding(self, severity: str, category: str):
        """Record finding detection."""
        if not OTEL_AVAILABLE or not _instrumentation_initialized:
            return

        self.findings_detected.add(
            1,
            {
                "severity": severity,
                "category": category,
            },
        )

    def record_auth_attempt(self, success: bool, method: str):
        """Record authentication attempt."""
        if not OTEL_AVAILABLE or not _instrumentation_initialized:
            return

        self.auth_attempts.add(
            1,
            {
                "success": str(success),
                "method": method,
            },
        )

    def record_report_generated(self, report_type: str, duration: float):
        """Record report generation."""
        if not OTEL_AVAILABLE or not _instrumentation_initialized:
            return

        self.reports_generated.add(1, {"report_type": report_type})
        self.report_generation_duration.record(duration, {"report_type": report_type})


# Global metrics instance
security_metrics = SecurityMetrics()
