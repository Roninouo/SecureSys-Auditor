"""
Health Check Views.

Provides Kubernetes-compatible health endpoints.
"""
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import connection


def _prometheus_metrics_response():
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    except Exception:
        return Response(
            {'detail': 'Prometheus client not installed'},
            status=status.HTTP_404_NOT_FOUND,
        )

    payload = generate_latest()
    # DRF Response tries to serialize bytes -> use raw HttpResponse.
    from django.http import HttpResponse

    return HttpResponse(payload, content_type=CONTENT_TYPE_LATEST)


class HealthCheckView(APIView):
    """
    Basic health check endpoint.
    
    Returns 200 if the service is running.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        return Response({
            'status': 'healthy',
            'service': 'SecureSys Auditor API',
            'version': '2.0.0'
        })


class ReadinessCheckView(APIView):
    """
    Kubernetes readiness probe.
    
    Checks that all dependencies are accessible:
    - Database connection
    - Redis connection (if configured)
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        checks = {}
        all_healthy = True
        
        # Check database
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1')
            checks['database'] = 'healthy'
        except Exception as e:
            checks['database'] = f'unhealthy: {str(e)}'
            all_healthy = False
        
        # Check Redis (if configured)
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 10)
            if cache.get('health_check') == 'ok':
                checks['cache'] = 'healthy'
            else:
                checks['cache'] = 'unhealthy: cache not working'
                all_healthy = False
        except Exception as e:
            checks['cache'] = f'unhealthy: {str(e)}'
            all_healthy = False
        
        # Check Celery (optional)
        try:
            from django.conf import settings
            if getattr(settings, 'CELERY_BROKER_URL', None):
                from celery import current_app
                inspect = current_app.control.inspect()
                if inspect.ping():
                    checks['celery'] = 'healthy'
                else:
                    checks['celery'] = 'unhealthy: no workers'
                    # Don't fail readiness for missing workers
        except Exception as e:
            checks['celery'] = f'unknown: {str(e)}'
        
        http_status = status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return Response({
            'status': 'ready' if all_healthy else 'not_ready',
            'checks': checks
        }, status=http_status)


class LivenessCheckView(APIView):
    """
    Kubernetes liveness probe.
    
    Simple check that the process is alive.
    Does NOT check dependencies (that's readiness).
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        return Response({'status': 'alive'})


class MetricsView(APIView):
    """Prometheus scrape endpoint."""

    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return _prometheus_metrics_response()
