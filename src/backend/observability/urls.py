"""URL configuration for observability app."""

from django.urls import path

from .views import HealthCheckView, ReadinessCheckView, LivenessCheckView, MetricsView

urlpatterns = [
    path('health/', HealthCheckView.as_view(), name='health-check'),
    path('ready/', ReadinessCheckView.as_view(), name='readiness-check'),
    path('live/', LivenessCheckView.as_view(), name='liveness-check'),
    path('metrics/', MetricsView.as_view(), name='metrics'),
]
