"""
URL configuration for core app.
"""

from django.urls import path
from . import views
from .api import api

app_name = 'core'

urlpatterns = [
    # Health check endpoint
    path('health/', views.health_check, name='health_check'),
    
    # API endpoints
    path('api/', api.urls),
] 