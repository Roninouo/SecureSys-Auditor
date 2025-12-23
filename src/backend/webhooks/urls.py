"""
URL configuration for webhooks app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import WebhookEndpointViewSet

router = DefaultRouter()
router.register(r'', WebhookEndpointViewSet, basename='webhook')

urlpatterns = [
    path('', include(router.urls)),
]
