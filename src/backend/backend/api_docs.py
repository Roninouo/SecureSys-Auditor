"""
OpenAPI/Swagger Configuration for SecureSys Auditor API.

Provides interactive API documentation using drf-spectacular.
"""
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView
)
from django.urls import path
from django.conf import settings
from rest_framework.permissions import IsAdminUser, AllowAny

# In production, restrict documentation to admin users
# In development, allow access to everyone
if getattr(settings, 'IS_PRODUCTION', False):
    permission_classes = [IsAdminUser]
else:
    permission_classes = [AllowAny]

urlpatterns = [
    # OpenAPI schema endpoint
    path('schema/', SpectacularAPIView.as_view(permission_classes=permission_classes), name='schema'),
    
    # Swagger UI
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema', permission_classes=permission_classes), name='swagger-ui'),
    
    # ReDoc UI (alternative documentation)
    path('redoc/', SpectacularRedocView.as_view(url_name='schema', permission_classes=permission_classes), name='redoc'),
]
