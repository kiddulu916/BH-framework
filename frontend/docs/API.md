# API Documentation

## Overview

The Bug Hunting Framework Frontend integrates with the backend API to provide target management functionality. This document describes all API endpoints, request/response formats, error handling, and usage examples.

## Base Configuration

### API Base URL
```
Development: http://localhost:8000
Production: https://api.bughuntingframework.com
```

### Authentication
The API uses JWT (JSON Web Tokens) for authentication. Include the token in the Authorization header:

```typescript
Authorization: Bearer <your-jwt-token>
```

### Content Type
All requests should use:
```
Content-Type: application/json
```

## Response Format

All API responses follow a standardized format:

```typescript
interface APIResponse<T> {
  success: boolean;
  message: string;
  data?: T;
  errors?: string[];
}
```

### Success Response Example
```json
{
  "success": true,
  "message": "Target created successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Example Target",
    "domain": "example.com",
    "platform": "hackerone",
    "created_at": "2025-01-27T10:00:00.000Z"
  }
}
```

### Error Response Example
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    "Domain is required",
    "Platform must be one of: hackerone, bugcrowd, intigriti"
  ]
}
```

## Target Management API

### Create Target

Creates a new bug hunting target.

**Endpoint:** `POST /api/v1/targets/`

**Request Body:**
```typescript
interface CreateTargetRequest {
  name: string;
  domain: string;
  platform: BugBountyPlatform;
  scope?: TargetScope;
  additional_rules?: string;
  rate_limits?: RateLimitConfig[];
  custom_headers?: CustomHeader[];
}
```

**Request Example:**
```json
{
  "name": "Example Target",
  "domain": "example.com",
  "platform": "hackerone",
  "scope": {
    "in_scope": ["*.example.com", "api.example.com"],
    "out_scope": ["admin.example.com"]
  },
  "additional_rules": "No automated scanning without permission",
  "rate_limits": [
    {
      "endpoint": "/api/*",
      "requests_per_minute": 60
    }
  ],
  "custom_headers": [
    {
      "name": "X-API-Key",
      "value": "your-api-key"
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Target created successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Example Target",
    "domain": "example.com",
    "platform": "hackerone",
    "scope": {
      "in_scope": ["*.example.com", "api.example.com"],
      "out_scope": ["admin.example.com"]
    },
    "additional_rules": "No automated scanning without permission",
    "rate_limits": [
      {
        "endpoint": "/api/*",
        "requests_per_minute": 60
      }
    ],
    "custom_headers": [
      {
        "name": "X-API-Key",
        "value": "your-api-key"
      }
    ],
    "created_at": "2025-01-27T10:00:00.000Z",
    "updated_at": "2025-01-27T10:00:00.000Z"
  }
}
```

### Get Target

Retrieves a specific target by ID.

**Endpoint:** `GET /api/v1/targets/{target_id}`

**Path Parameters:**
- `target_id` (UUID): The unique identifier of the target

**Response:**
```json
{
  "success": true,
  "message": "Target retrieved successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Example Target",
    "domain": "example.com",
    "platform": "hackerone",
    "scope": {
      "in_scope": ["*.example.com"],
      "out_scope": ["admin.example.com"]
    },
    "created_at": "2025-01-27T10:00:00.000Z",
    "updated_at": "2025-01-27T10:00:00.000Z"
  }
}
```

### List Targets

Retrieves a list of all targets with optional pagination.

**Endpoint:** `GET /api/v1/targets/`

**Query Parameters:**
- `page` (number, optional): Page number (default: 1)
- `limit` (number, optional): Number of items per page (default: 10, max: 100)
- `platform` (string, optional): Filter by platform
- `domain` (string, optional): Filter by domain

**Response:**
```json
{
  "success": true,
  "message": "Targets retrieved successfully",
  "data": {
    "targets": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Example Target",
        "domain": "example.com",
        "platform": "hackerone",
        "created_at": "2025-01-27T10:00:00.000Z"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 10,
      "total": 1,
      "pages": 1
    }
  }
}
```

### Update Target

Updates an existing target.

**Endpoint:** `PUT /api/v1/targets/{target_id}`

**Path Parameters:**
- `target_id` (UUID): The unique identifier of the target

**Request Body:** Same as Create Target (all fields optional)

**Response:**
```json
{
  "success": true,
  "message": "Target updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Updated Target",
    "domain": "example.com",
    "platform": "bugcrowd",
    "updated_at": "2025-01-27T11:00:00.000Z"
  }
}
```

### Delete Target

Deletes a target.

**Endpoint:** `DELETE /api/v1/targets/{target_id}`

**Path Parameters:**
- `target_id` (UUID): The unique identifier of the target

**Response:**
```json
{
  "success": true,
  "message": "Target deleted successfully"
}
```

## Data Types

### BugBountyPlatform
```typescript
enum BugBountyPlatform {
  HACKERONE = "hackerone",
  BUGCROWD = "bugcrowd",
  INTIGRITI = "intigriti",
  YESWEHACK = "yeswehack",
  SYNACK = "synack",
  CROWDSTRIKE = "crowdstrike",
  FEDERACY = "federacy",
  OPENBUGBOUNTY = "openbugbounty",
  HACKENPROOF = "hackenproof",
  ANONYMOUS = "anonymous"
}
```

### TargetScope
```typescript
interface TargetScope {
  in_scope: string[];
  out_scope: string[];
}
```

### RateLimitConfig
```typescript
interface RateLimitConfig {
  endpoint: string;
  requests_per_minute: number;
}
```

### CustomHeader
```typescript
interface CustomHeader {
  name: string;
  value: string;
}
```

## Error Handling

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation errors
- `500 Internal Server Error`: Server error

### Common Error Responses

#### Validation Error (422)
```json
{
  "success": false,
  "message": "Validation failed",
  "errors": [
    "Domain is required",
    "Platform must be one of: hackerone, bugcrowd, intigriti",
    "Name must be between 1 and 100 characters"
  ]
}
```

#### Not Found Error (404)
```json
{
  "success": false,
  "message": "Target not found",
  "errors": ["Target with ID 550e8400-e29b-41d4-a716-446655440000 not found"]
}
```

#### Authentication Error (401)
```json
{
  "success": false,
  "message": "Authentication required",
  "errors": ["Valid JWT token required"]
}
```

## Frontend Integration

### API Client Usage

The frontend uses an Axios-based API client with automatic error handling:

```typescript
import { targetsApi } from '@/lib/api/targets';

// Create a target
const createTarget = async (targetData: CreateTargetRequest) => {
  try {
    const response = await targetsApi.createTarget(targetData);
    return response.data;
  } catch (error) {
    // Error handling is automatic
    throw error;
  }
};

// Get a target
const getTarget = async (targetId: string) => {
  try {
    const response = await targetsApi.getTarget(targetId);
    return response.data;
  } catch (error) {
    throw error;
  }
};
```

### Error Handling in Components

```typescript
import { useMutation, useQuery } from '@tanstack/react-query';
import { targetsApi } from '@/lib/api/targets';

const TargetForm = () => {
  const createTargetMutation = useMutation({
    mutationFn: targetsApi.createTarget,
    onSuccess: (data) => {
      // Handle success
      console.log('Target created:', data);
    },
    onError: (error) => {
      // Handle error
      console.error('Failed to create target:', error);
    },
  });

  const handleSubmit = (formData: CreateTargetRequest) => {
    createTargetMutation.mutate(formData);
  };

  return (
    <form onSubmit={handleSubmit}>
      {/* Form fields */}
      <button 
        type="submit" 
        disabled={createTargetMutation.isPending}
      >
        {createTargetMutation.isPending ? 'Creating...' : 'Create Target'}
      </button>
    </form>
  );
};
```

### Caching Strategy

The frontend uses React Query for intelligent caching:

```typescript
// Query with caching
const useTargets = () => {
  return useQuery({
    queryKey: ['targets'],
    queryFn: targetsApi.getTargets,
    staleTime: 5 * 60 * 1000, // 5 minutes
    gcTime: 10 * 60 * 1000,   // 10 minutes
  });
};

// Mutation with cache invalidation
const useCreateTarget = () => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: targetsApi.createTarget,
    onSuccess: () => {
      // Invalidate and refetch targets
      queryClient.invalidateQueries({ queryKey: ['targets'] });
    },
  });
};
```

## Testing

### API Testing Examples

```typescript
import { render, screen, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { targetsApi } from '@/lib/api/targets';

// Mock API client
jest.mock('@/lib/api/targets');

const mockTargetsApi = targetsApi as jest.Mocked<typeof targetsApi>;

describe('Target API Integration', () => {
  it('should create a target successfully', async () => {
    const mockTarget = {
      id: '550e8400-e29b-41d4-a716-446655440000',
      name: 'Test Target',
      domain: 'test.com',
      platform: 'hackerone' as const,
    };

    mockTargetsApi.createTarget.mockResolvedValue({
      success: true,
      message: 'Target created successfully',
      data: mockTarget,
    });

    // Test implementation
  });

  it('should handle API errors gracefully', async () => {
    mockTargetsApi.createTarget.mockRejectedValue({
      response: {
        data: {
          success: false,
          message: 'Validation failed',
          errors: ['Domain is required'],
        },
        status: 422,
      },
    });

    // Test error handling
  });
});
```

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default**: 100 requests per minute per IP
- **Authenticated**: 1000 requests per minute per user
- **Headers**: Rate limit information is included in response headers

### Rate Limit Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1643289600
```

## Security

### Input Validation
- All inputs are validated using Pydantic schemas
- SQL injection protection through parameterized queries
- XSS protection through input sanitization
- CSRF protection for state-changing operations

### Authentication
- JWT tokens with configurable expiration
- Token refresh mechanism
- Secure token storage in HTTP-only cookies
- Automatic token rotation

### Authorization
- Role-based access control (RBAC)
- Resource-level permissions
- Audit logging for all operations

## Monitoring

### Health Check Endpoint
```
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-27T10:00:00.000Z",
  "version": "1.0.0",
  "uptime": 3600,
  "database": "connected",
  "cache": "connected"
}
```

### Metrics Endpoint
```
GET /metrics
```

Returns Prometheus-compatible metrics for monitoring.

## Versioning

API versioning is handled through URL paths:
- Current version: `/api/v1/`
- Future versions: `/api/v2/`, `/api/v3/`, etc.

Breaking changes will be introduced in new versions with deprecation notices for old versions.

## Support

For API support:
- **Documentation**: This document and inline code comments
- **Issues**: Create an issue on GitHub with detailed information
- **Discussions**: Use GitHub Discussions for questions and ideas

When reporting API issues, please include:
- HTTP method and endpoint
- Request headers and body
- Response status code and body
- Expected vs actual behavior
- Steps to reproduce 