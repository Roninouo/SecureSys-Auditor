"""
URL configuration for the Scanning API.

Routes:
- /api/v1/scanning/systems/      System management
- /api/v1/scanning/scans/        Scan management
- /api/v1/scanning/scans/url/    URL/Website security scanning
- /api/v1/scanning/findings/     Finding management
- /api/v1/scanning/recommendations/ Recommendation access
- /api/v1/scanning/dashboard/    Dashboard stats
- /api/v1/scanning/health/       Health check
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import (
    SystemViewSet,
    ScanViewSet,
    FindingViewSet,
    RecommendationViewSet,
    DashboardStatsView,
    ScanningHealthCheckView,
    URLScanView,
)

# Create router and register viewsets
router = DefaultRouter()
router.register(r'systems', SystemViewSet, basename='scanning-system')
router.register(r'scans', ScanViewSet, basename='scanning-scan')
router.register(r'findings', FindingViewSet, basename='scanning-finding')
router.register(r'recommendations', RecommendationViewSet, basename='scanning-recommendation')

urlpatterns = [
    # Health check
    path('health/', ScanningHealthCheckView.as_view(), name='scanning-health'),
    
    # Dashboard stats
    path('dashboard/stats/', DashboardStatsView.as_view(), name='scanning-dashboard-stats'),
    
    # URL/Website scanning
    path('scans/url/', URLScanView.as_view(), name='scanning-url-scan'),
    
    # Router URLs
    path('', include(router.urls)),
]
