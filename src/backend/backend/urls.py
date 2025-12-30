"""
URL configuration for SecureSys Auditor backend.

URL Structure:
- /admin/                   Django admin
- /api/v1/                  Core API (legacy routes, being refactored)
- /api/v1/auth/             Authentication endpoints
- /api/v1/scanning/         Scanning endpoints (new modular app)
- /api/v1/scans/.../report/ Report generation (new modular reports app)
- /api/v1/webhooks/         Webhook management (new modular webhooks app)
- /api/docs/                OpenAPI documentation (Swagger UI)
- /api/redoc/               OpenAPI documentation (ReDoc)
- /api/schema/              OpenAPI schema (JSON/YAML)
- /health/                  Health check endpoints (K8s compatible)
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from observability.views import MetricsView

urlpatterns = [
    # Admin
    path('admin/', admin.site.urls),
    
    # Health checks (outside /api/v1/ for load balancer compatibility)
    path('health/', include('observability.urls')),

    # Prometheus metrics (backwards-compatible alias)
    path('api/v1/metrics/prometheus', MetricsView.as_view(), name='metrics-prometheus'),
    path('api/v1/metrics/prometheus/', MetricsView.as_view(), name='metrics-prometheus-slash'),
    
    # API Documentation - always available
    path('api/', include('backend.api_docs')),
    
    # API v1 - Core routes (legacy, being refactored)
    path('api/v1/', include('core.urls')),
    
    # API v1 - Scanning app (new decoupled architecture)
    path('api/v1/scanning/', include('scanning.urls')),
    
    # API v1 - Modular apps
    path('api/v1/reports/', include('reports.urls')),
    path('api/v1/webhooks/', include('webhooks.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
