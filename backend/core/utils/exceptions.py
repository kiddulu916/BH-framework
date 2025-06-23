"""
Custom exceptions for the Bug Hunting Framework.

This module contains custom exception classes used throughout the application
for consistent error handling and meaningful error messages.
"""

from typing import Optional, List, Dict, Any


class BugHuntingError(Exception):
    """Base exception class for all bug hunting framework errors."""
    
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.details = details or {}
        super().__init__(self.message)


class ValidationError(BugHuntingError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, value: Optional[Any] = None):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = value
        
        super().__init__(message, details)


class NotFoundError(BugHuntingError):
    """Raised when a requested resource is not found."""
    
    def __init__(self, message: str, resource_type: Optional[str] = None, resource_id: Optional[str] = None):
        details = {}
        if resource_type:
            details["resource_type"] = resource_type
        if resource_id:
            details["resource_id"] = resource_id
        
        super().__init__(message, details)


class AuthenticationError(BugHuntingError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str, auth_type: Optional[str] = None):
        details = {"auth_type": auth_type} if auth_type else {}
        super().__init__(message, details)


class AuthorizationError(BugHuntingError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str, required_permission: Optional[str] = None, user_permissions: Optional[List[str]] = None):
        details = {}
        if required_permission:
            details["required_permission"] = required_permission
        if user_permissions:
            details["user_permissions"] = user_permissions
        
        super().__init__(message, details)


class DatabaseError(BugHuntingError):
    """Raised when database operations fail."""
    
    def __init__(self, message: str, operation: Optional[str] = None, table: Optional[str] = None):
        details = {}
        if operation:
            details["operation"] = operation
        if table:
            details["table"] = table
        
        super().__init__(message, details)


class ServiceError(BugHuntingError):
    """Raised when external service operations fail."""
    
    def __init__(self, message: str, service_name: Optional[str] = None, status_code: Optional[int] = None):
        details = {}
        if service_name:
            details["service_name"] = service_name
        if status_code:
            details["status_code"] = status_code
        
        super().__init__(message, details)


class WorkflowError(BugHuntingError):
    """Raised when workflow operations fail."""
    
    def __init__(self, message: str, workflow_id: Optional[str] = None, stage: Optional[str] = None):
        details = {}
        if workflow_id:
            details["workflow_id"] = workflow_id
        if stage:
            details["stage"] = stage
        
        super().__init__(message, details)


class StageExecutionError(BugHuntingError):
    """Raised when stage execution fails."""
    
    def __init__(self, message: str, stage_name: Optional[str] = None, target_id: Optional[str] = None, tool_output: Optional[str] = None):
        details = {}
        if stage_name:
            details["stage_name"] = stage_name
        if target_id:
            details["target_id"] = target_id
        if tool_output:
            details["tool_output"] = tool_output
        
        super().__init__(message, details)


class ExecutionError(BugHuntingError):
    """Raised when execution operations fail."""
    
    def __init__(self, message: str, execution_id: Optional[str] = None, container_name: Optional[str] = None):
        details = {}
        if execution_id:
            details["execution_id"] = execution_id
        if container_name:
            details["container_name"] = container_name
        
        super().__init__(message, details)


class ContainerError(BugHuntingError):
    """Raised when container operations fail."""
    
    def __init__(self, message: str, container_name: Optional[str] = None, container_id: Optional[str] = None):
        details = {}
        if container_name:
            details["container_name"] = container_name
        if container_id:
            details["container_id"] = container_id
        
        super().__init__(message, details)


class ConfigurationError(BugHuntingError):
    """Raised when configuration is invalid or missing."""
    
    def __init__(self, message: str, config_key: Optional[str] = None, config_value: Optional[Any] = None):
        details = {}
        if config_key:
            details["config_key"] = config_key
        if config_value is not None:
            details["config_value"] = config_value
        
        super().__init__(message, details)


class ReportGenerationError(BugHuntingError):
    """Raised when report generation fails."""
    
    def __init__(self, message: str, report_id: Optional[str] = None, format: Optional[str] = None):
        details = {}
        if report_id:
            details["report_id"] = report_id
        if format:
            details["format"] = format
        
        super().__init__(message, details)


class ExportError(BugHuntingError):
    """Raised when export operations fail."""
    
    def __init__(self, message: str, export_format: Optional[str] = None, report_id: Optional[str] = None):
        details = {}
        if export_format:
            details["export_format"] = export_format
        if report_id:
            details["report_id"] = report_id
        
        super().__init__(message, details)


class TargetValidationError(BugHuntingError):
    """Raised when target validation fails."""
    
    def __init__(self, message: str, target_id: Optional[str] = None, validation_checks: Optional[Dict[str, bool]] = None):
        details = {}
        if target_id:
            details["target_id"] = target_id
        if validation_checks:
            details["validation_checks"] = validation_checks
        
        super().__init__(message, details)


class RateLimitError(BugHuntingError):
    """Raised when rate limits are exceeded."""
    
    def __init__(self, message: str, limit: Optional[int] = None, window: Optional[int] = None):
        details = {}
        if limit:
            details["limit"] = limit
        if window:
            details["window"] = window
        
        super().__init__(message, details)


class DependencyError(BugHuntingError):
    """Raised when required dependencies are missing or unavailable."""
    
    def __init__(self, message: str, dependency: Optional[str] = None, required_version: Optional[str] = None):
        details = {}
        if dependency:
            details["dependency"] = dependency
        if required_version:
            details["required_version"] = required_version
        
        super().__init__(message, details)


# Exception mapping for HTTP status codes
EXCEPTION_STATUS_MAP = {
    ValidationError: 400,
    NotFoundError: 404,
    AuthenticationError: 401,
    AuthorizationError: 403,
    DatabaseError: 500,
    ServiceError: 502,
    WorkflowError: 500,
    StageExecutionError: 500,
    ExecutionError: 500,
    ContainerError: 500,
    ConfigurationError: 500,
    ReportGenerationError: 500,
    ExportError: 500,
    TargetValidationError: 400,
    RateLimitError: 429,
    DependencyError: 503,
}


def get_status_code_for_exception(exception: Exception) -> int:
    """
    Get the appropriate HTTP status code for an exception.
    
    Args:
        exception: The exception instance
        
    Returns:
        HTTP status code
    """
    exception_type = type(exception)
    return EXCEPTION_STATUS_MAP.get(exception_type, 500) 