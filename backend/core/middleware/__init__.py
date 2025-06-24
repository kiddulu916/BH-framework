"""
Middleware for handling API responses and other custom functionality.
"""

from django.http import JsonResponse
from core.schemas.base import APIResponse


class APIResponseMiddleware:
    """
    Middleware to handle APIResponse objects from Django Ninja.
    Converts APIResponse objects to proper Django JsonResponse objects.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        response = self.get_response(request)
        
        # If the response is an APIResponse object, convert it to JsonResponse
        if isinstance(response, APIResponse):
            return JsonResponse(
                response.model_dump(),
                status=200,
                content_type='application/json'
            )
        
        return response 