"""
URL configuration for reports app.
"""
from django.urls import path
from .views import ReportGenerationView, ReportDownloadView

urlpatterns = [
    path('generate/', ReportGenerationView.as_view(), name='generate-report'),
    path('download/<str:filename>/', ReportDownloadView.as_view(), name='download-report'),
]
