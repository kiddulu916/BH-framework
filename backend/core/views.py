"""
Core views for the Bug Hunting Framework.
"""

from django.http import JsonResponse
from django.db import connection
from django.db.utils import OperationalError


def health_check(request):
    """
    Health check endpoint for the backend service.
    
    Returns:
        JsonResponse: Health status with database connectivity check
    """
    try:
        # Check database connectivity
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            db_status = "healthy"
    except OperationalError:
        db_status = "unhealthy"
    
    # Determine overall health
    overall_status = "healthy" if db_status == "healthy" else "unhealthy"
    status_code = 200 if overall_status == "healthy" else 503
    
    return JsonResponse({
        "status": overall_status,
        "service": "bug-hunting-backend",
        "database": db_status,
        "timestamp": "2025-06-07T00:00:00Z"  # TODO: Use actual timestamp
    }, status=status_code) 