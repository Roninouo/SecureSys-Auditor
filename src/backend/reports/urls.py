"""
URL configuration for reports app.
"""
from django.urls import path
from .views import ReportGenerationView

urlpatterns = [
    path('generate/', ReportGenerationView.as_view(), name='generate-report'),
]
