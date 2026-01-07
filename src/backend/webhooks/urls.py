"""
URL configuration for webhooks app.
"""
from rest_framework.routers import DefaultRouter

from django.urls import include, path

from .views import WebhookEndpointViewSet

router = DefaultRouter()
router.register(r"", WebhookEndpointViewSet, basename="webhook")

urlpatterns = [
    path("", include(router.urls)),
]
