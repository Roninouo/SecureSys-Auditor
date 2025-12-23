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

urlpatterns = [
    # OpenAPI schema endpoint
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    
    # Swagger UI
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    
    # ReDoc UI (alternative documentation)
    path('redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
