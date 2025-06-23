"""
API module for the Bug Hunting Framework.

This package contains all Django Ninja API endpoints for the Bug Hunting Framework,
including target management, stage result submission, workflow execution, and reporting.
"""

from ninja import NinjaAPI
from django.conf import settings

from core.schemas.base import APIResponse

# Create the main API instance
api = NinjaAPI(
    title="Bug Hunting Framework API",
    version="1.0.0",
    description="API for automated bug hunting and security testing",
    docs_url="/docs",
    openapi_url="/openapi.json",
    csrf=False,  # Disable CSRF for API endpoints
)

# Import and register all API routers
from .targets import router as targets_router
from .results import router as results_router
from .workflow_api import router as workflow_api_router
from .report_api import router as report_api_router
from .execution import router as execution_router

# Register API routers
api.add_router("/targets/", targets_router, tags=["Targets"])
api.add_router("/results/", results_router, tags=["Results"])
api.add_router("/workflows/", workflow_api_router, tags=["Workflows"])
api.add_router("/reports/", report_api_router, tags=["Reports"])
api.add_router("/execution/", execution_router, tags=["Execution"])

# Global exception handlers
@api.exception_handler(Exception)
def global_exception_handler(request, exc):
    """Global exception handler for unhandled exceptions."""
    return APIResponse(
        success=False,
        message="Internal server error",
        errors=[str(exc)],
        data=None
    )

@api.exception_handler(ValueError)
def validation_exception_handler(request, exc):
    """Handler for validation errors."""
    return APIResponse(
        success=False,
        message="Validation error",
        errors=[str(exc)],
        data=None
    )

@api.exception_handler(KeyError)
def key_error_handler(request, exc):
    """Handler for key errors."""
    return APIResponse(
        success=False,
        message="Missing required field",
        errors=[f"Missing field: {exc}"],
        data=None
    )

# Health check endpoint
@api.get("/health", response=APIResponse, tags=["Health"])
def health_check(request):
    """Health check endpoint for the API."""
    return APIResponse(
        success=True,
        message="API is healthy",
        data={
            "service": "bug-hunting-api",
            "version": "1.0.0",
            "status": "healthy"
        },
        errors=None
    )

# API info endpoint
@api.get("/info", response=APIResponse, tags=["Info"])
def api_info(request):
    """Get API information and available endpoints."""
    return APIResponse(
        success=True,
        message="API information retrieved successfully",
        data={
            "title": "Bug Hunting Framework API",
            "version": "1.0.0",
            "description": "API for automated bug hunting and security testing",
            "endpoints": {
                "targets": "/api/targets/",
                "results": "/api/results/",
                "workflows": "/api/workflows/",
                "reports": "/api/reports/",
                "execution": "/api/execution/",
                "health": "/api/health",
                "docs": "/api/docs"
            }
        },
        errors=None
    ) 