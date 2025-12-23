"""
URL configuration for the core API.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    CustomTokenObtainPairView,
    HealthCheckView,
    UserViewSet,
    SystemViewSet,
    ScanViewSet,
    FindingViewSet,
    RecommendationViewSet,
    AuditLogViewSet,
    DashboardStatsView,
    ReportGenerationView,
)
from .webhooks import WebhookEndpointViewSet

# Create router and register viewsets
router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'systems', SystemViewSet, basename='system')
router.register(r'scans', ScanViewSet, basename='scan')
router.register(r'findings', FindingViewSet, basename='finding')
router.register(r'recommendations', RecommendationViewSet, basename='recommendation')
router.register(r'audit-logs', AuditLogViewSet, basename='audit-log')
router.register(r'webhooks', WebhookEndpointViewSet, basename='webhook')

urlpatterns = [
    # Health check
    path('health/', HealthCheckView.as_view(), name='health-check'),
    
    # Authentication endpoints
    path('auth/login/', CustomTokenObtainPairView.as_view(), name='token-obtain'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # Dashboard
    path('dashboard/stats/', DashboardStatsView.as_view(), name='dashboard-stats'),
    
    # Reports
    path('reports/generate/', ReportGenerationView.as_view(), name='generate-report'),
    
    # Router URLs
    path('', include(router.urls)),
]
