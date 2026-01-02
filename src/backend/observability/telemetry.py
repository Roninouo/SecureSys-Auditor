"""
OpenTelemetry Instrumentation.

Key improvements over previous implementation:
1. Relies primarily on auto-instrumentation
2. Minimal manual instrumentation only where needed
3. Proper context propagation
4. Singleton pattern for initialization
"""
import logging
from functools import wraps
from typing import Callable, Optional

from django.conf import settings

logger = logging.getLogger(__name__)

# Track initialization state
_instrumentation_initialized = False
_tracer = None
_meter = None

# Try to import OpenTelemetry
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

    Called during Django startup via AppConfig.ready().
    Only initializes once per process.
    """
    global _instrumentation_initialized, _tracer, _meter

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
        service_name = getattr(settings, "OTEL_SERVICE_NAME", "securesys-backend")
        environment = getattr(settings, "ENVIRONMENT", "development")

        resource = Resource.create(
            {
                SERVICE_NAME: service_name,
                SERVICE_VERSION: "2.0.0",
                "deployment.environment": environment,
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
            export_interval_millis=60000,
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)

        # Auto-instrument Django (handles most HTTP tracing)
        DjangoInstrumentor().instrument()

        # Auto-instrument Celery
        CeleryInstrumentor().instrument()

        # Auto-instrument database
        try:
            Psycopg2Instrumentor().instrument()
        except Exception:
            logger.debug("psycopg2 instrumentation skipped")

        # Auto-instrument Redis
        try:
            RedisInstrumentor().instrument()
        except Exception:
            logger.debug("Redis instrumentation skipped")

        # Auto-instrument outgoing HTTP
        RequestsInstrumentor().instrument()

        # Store tracer and meter for use
        _tracer = trace.get_tracer("securesys.core")
        _meter = metrics.get_meter("securesys.core")

        _instrumentation_initialized = True
        logger.info(
            "OpenTelemetry instrumentation initialized",
            extra={
                "endpoint": endpoint,
                "service_name": service_name,
            },
        )

    except Exception as e:
        logger.error(f"Failed to initialize OpenTelemetry: {e}")


def get_tracer():
    """Get the OpenTelemetry tracer."""
    global _tracer
    return _tracer


def get_meter():
    """Get the OpenTelemetry meter."""
    global _meter
    return _meter


def traced(name: Optional[str] = None, attributes: Optional[dict] = None) -> Callable:
    """
    Decorator to add tracing to a function.

    Use sparingly - auto-instrumentation covers most cases.
    Only use for:
    - Business-critical operations
    - Long-running background tasks
    - Complex multi-step operations

    Example:
        @traced(name='process_critical_finding')
        def process_finding(finding_id):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            if not tracer:
                return func(*args, **kwargs)

            span_name = name or func.__name__

            with tracer.start_as_current_span(span_name) as span:
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
