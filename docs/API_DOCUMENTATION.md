# Bug Hunting Framework - API Documentation

## Table of Contents
1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Base URL and Endpoints](#base-url-and-endpoints)
4. [Request/Response Format](#requestresponse-format)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Targets API](#targets-api)
8. [Workflows API](#workflows-api)
9. [Results API](#results-api)
10. [Reports API](#reports-api)
11. [User Management API](#user-management-api)
12. [System API](#system-api)
13. [SDK Examples](#sdk-examples)
14. [Integration Guides](#integration-guides)
15. [Best Practices](#best-practices)

## Overview

The Bug Hunting Framework provides a comprehensive REST API for programmatic access to all framework functionality. The API is designed to be RESTful, secure, and easy to integrate with existing systems.

### API Versioning

- **Current Version**: v1
- **Base URL**: `https://your-domain.com/api/v1/`
- **Content Type**: `application/json`
- **Character Encoding**: UTF-8

### API Features

- **RESTful Design**: Follows REST principles
- **JWT Authentication**: Secure token-based authentication
- **Rate Limiting**: Built-in rate limiting for API protection
- **Comprehensive Error Handling**: Detailed error messages and codes
- **OpenAPI/Swagger**: Interactive API documentation
- **Webhook Support**: Real-time notifications for workflow events

## Authentication

### JWT Token Authentication

The API uses JWT (JSON Web Tokens) for authentication. All API requests must include a valid JWT token in the Authorization header.

#### Targets

```http
POST /api/targets/
Authorization: Bearer <JWT_token>
Content-Type: application/json

{
  "id": "targets_uuid",
},

```

**Response:**
```json
{
  "success": true,
  "target": {
    "id": "targets_uuid",
    "target": "example llc",
    "domain": "example.com",
    ......more target data
  }
}

```

#### Using Access Token

```http
GET /api/targets/
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

#### Token Refresh

```http
POST /api/v1/auth/refresh
Authorization: Bearer <refresh_token>
Content-Type: application/json
```

### API Key Authentication (Alternative)

For service-to-service integration, API keys are also supported:

```http
GET /api/targets/
X-API-Key: your_api_key_here
Content-Type: application/json
```

## Base URL and Endpoints

### Base URL

```
Production: https://backend:8000/api
Development: http://localhost:8000/api
```

### Endpoint Structure

```
/api
├── auth/           # Authentication endpoints
├── targets/        # Target management
├── workflows/      # Workflow execution
├── results/        # Results retrieval
├── reports/        # Report generation
└── system/         # System information
```

## Request/Response Format

### Standard Request Format

All requests should include:
- `Content-Type: application/json`
- `Authorization: Bearer <JWT_token>`

### Standard Response Format

All API responses follow a consistent format:

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    // Response data here
  },
  "errors": null,
  "meta": {
    "timestamp": "2024-01-27T10:00:00Z",
    "request_id": "uuid",
    "version": "v1"
  }
}
```

### Pagination

For endpoints that return lists, pagination is supported:

```json
{
  "success": true,
  "data": {
    "items": [...],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 100,
      "pages": 5,
      "has_next": true,
      "has_prev": false
    }
  }
}
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `per_page`: Items per page (default: 20, max: 100)
- `sort`: Sort field (default: created_at)
- `order`: Sort order (asc/desc, default: desc)

## Error Handling

### Error Response Format

```json
{
  "success": false,
  "message": "Validation error",
  "data": null,
  "errors": [
    "Target domain is required",
    "Invalid domain format"
  ],
  "meta": {
    "timestamp": "2024-01-27T10:00:00Z",
    "request_id": "uuid",
    "error_code": "VALIDATION_ERROR"
  }
}
```

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation error
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Common Error Codes

```json
{
  "error_codes": {
    "AUTHENTICATION_FAILED": "Invalid credentials",
    "TOKEN_EXPIRED": "Access token has expired",
    "INSUFFICIENT_PERMISSIONS": "User lacks required permissions",
    "RESOURCE_NOT_FOUND": "Requested resource does not exist",
    "VALIDATION_ERROR": "Request data validation failed",
    "RATE_LIMIT_EXCEEDED": "API rate limit exceeded",
    "WORKFLOW_IN_PROGRESS": "Workflow is currently running",
    "TARGET_ALREADY_EXISTS": "Target with this domain already exists"
  }
}
```

## Rate Limiting

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1643270400
Retry-After: 60
```

### Rate Limit Rules

- **Authenticated Users**: 1000 requests per hour
- **API Key Users**: 5000 requests per hour
- **Anonymous Users**: 100 requests per hour

### Rate Limit Response

```json
{
  "success": false,
  "message": "Rate limit exceeded",
  "errors": ["Too many requests. Please try again later."],
  "meta": {
    "retry_after": 60,
    "rate_limit_reset": 1643270400
  }
}
```

## Targets API

### List Targets

```http
GET /api/v1/targets/
Authorization: Bearer <token>
```

**Query Parameters:**
- `status`: Filter by status (active, paused, completed, archived)
- `platform`: Filter by platform (bugbounty, internal, external)
- `search`: Search in target domain and description

**Response:**
```json
{
  "success": true,
  "data": {
    "items": [
      {
        "id": "uuid",
        "target": "example.com",
        "platform": "BUGBOUNTY",
        "status": "ACTIVE",
        "description": "Web application security testing",
        "created_at": "2024-01-27T10:00:00Z",
        "updated_at": "2024-01-27T10:00:00Z"
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 1,
      "pages": 1
    }
  }
}
```

### Create Target

```http
POST /api/v1/targets/
Authorization: Bearer <token>
Content-Type: application/json

{
  "target": "example.com",
  "platform": "BUGBOUNTY",
  "description": "Web application security testing",
  "scope": {
    "domains": ["*.example.com", "api.example.com"],
    "exclusions": ["admin.example.com"]
  },
  "scan_config": {
    "depth": "DEEP",
    "rate_limit": 100,
    "timeout": 3600
  }
}
```

### Get Target Details

```http
GET /api/v1/targets/{target_id}/
Authorization: Bearer <token>
```

### Update Target

```http
PUT /api/v1/targets/{target_id}/
Authorization: Bearer <token>
Content-Type: application/json

{
  "description": "Updated description",
  "status": "PAUSED"
}
```

### Delete Target

```http
DELETE /api/v1/targets/{target_id}/
Authorization: Bearer <token>
```

### Target Operations

```http
# Pause target
POST /api/v1/targets/{target_id}/pause/
Authorization: Bearer <token>

# Resume target
POST /api/v1/targets/{target_id}/resume/
Authorization: Bearer <token>

# Archive target
POST /api/v1/targets/{target_id}/archive/
Authorization: Bearer <token>
```

## Workflows API

### List Workflows

```http
GET /api/v1/workflows/
Authorization: Bearer <token>
```

**Query Parameters:**
- `target_id`: Filter by target ID
- `status`: Filter by status (queued, running, completed, failed, cancelled)
- `stage`: Filter by stage name

### Create Workflow

```http
POST /api/v1/workflows/
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_id": "target_uuid",
  "name": "Security Assessment",
  "description": "Comprehensive security testing",
  "stages": {
    "passive_recon": {
      "enabled": true,
      "tools": ["amass", "subfinder"],
      "timeout": 1800
    },
    "active_recon": {
      "enabled": true,
      "tools": ["nmap", "httpx"],
      "timeout": 3600
    },
    "vuln_scan": {
      "enabled": true,
      "tools": ["nuclei", "nikto"],
      "timeout": 7200
    },
    "vuln_test": {
      "enabled": true,
      "ai_analysis": true,
      "timeout": 5400
    },
    "kill_chain": {
      "enabled": true,
      "analysis_depth": "DEEP",
      "timeout": 1800
    },
    "reporting": {
      "enabled": true,
      "formats": ["PDF", "HTML", "JSON"],
      "timeout": 900
    }
  },
  "config": {
    "concurrency": 3,
    "rate_limit": 50,
    "resource_limits": {
      "memory_per_tool": "512MB",
      "cpu_per_tool": "0.5"
    }
  }
}
```

### Get Workflow Status

```http
GET /api/v1/workflows/{workflow_id}/
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "target_id": "target_uuid",
    "name": "Security Assessment",
    "status": "RUNNING",
    "current_stage": "vuln_scan",
    "progress": {
      "overall": 45,
      "stages": {
        "passive_recon": "COMPLETED",
        "active_recon": "COMPLETED",
        "vuln_scan": "RUNNING",
        "vuln_test": "PENDING",
        "kill_chain": "PENDING",
        "reporting": "PENDING"
      }
    },
    "started_at": "2024-01-27T10:00:00Z",
    "estimated_completion": "2024-01-27T14:00:00Z"
  }
}
```

### Workflow Operations

```http
# Cancel workflow
POST /api/v1/workflows/{workflow_id}/cancel/
Authorization: Bearer <token>

# Pause workflow
POST /api/v1/workflows/{workflow_id}/pause/
Authorization: Bearer <token>

# Resume workflow
POST /api/v1/workflows/{workflow_id}/resume/
Authorization: Bearer <token>
```

### Get Workflow Logs

```http
GET /api/v1/workflows/{workflow_id}/logs/
Authorization: Bearer <token>
```

**Query Parameters:**
- `stage`: Filter by stage name
- `level`: Filter by log level (DEBUG, INFO, WARNING, ERROR)
- `limit`: Number of log entries (default: 100, max: 1000)

## Results API

### Get Workflow Results

```http
GET /api/v1/workflows/{workflow_id}/results/
Authorization: Bearer <token>
```

**Response:**
```json
{
  "success": true,
  "data": {
    "workflow_id": "uuid",
    "target": "example.com",
    "summary": {
      "total_vulnerabilities": 5,
      "critical": 1,
      "high": 2,
      "medium": 1,
      "low": 1,
      "total_assets": 45,
      "total_subdomains": 15
    },
    "stages": {
      "passive_recon": {
        "status": "COMPLETED",
        "results": {
          "subdomains": [...],
          "assets": [...]
        }
      },
      "vuln_scan": {
        "status": "COMPLETED",
        "results": {
          "vulnerabilities": [...]
        }
      }
    }
  }
}
```

### Get Stage Results

```http
GET /api/v1/workflows/{workflow_id}/stages/{stage_name}/results/
Authorization: Bearer <token>
```

### Export Results

```http
GET /api/v1/workflows/{workflow_id}/export/
Authorization: Bearer <token>
```

**Query Parameters:**
- `format`: Export format (json, csv, xml)
- `include_raw`: Include raw tool output (true/false)
- `include_evidence`: Include vulnerability evidence (true/false)

## Reports API

### Generate Report

```http
POST /api/v1/reports/
Authorization: Bearer <token>
Content-Type: application/json

{
  "workflow_id": "workflow_uuid",
  "report_type": "COMPREHENSIVE",
  "formats": ["PDF", "HTML"],
  "template": "CUSTOM",
  "customization": {
    "company_logo": "base64_encoded_logo",
    "company_name": "Your Company",
    "contact_info": "security@company.com",
    "sections": [
      "executive_summary",
      "methodology",
      "findings",
      "remediation",
      "appendix"
    ]
  }
}
```

### Get Report Status

```http
GET /api/v1/reports/{report_id}/
Authorization: Bearer <token>
```

### Download Report

```http
GET /api/v1/reports/{report_id}/download/
Authorization: Bearer <token>
```

**Query Parameters:**
- `format`: Report format (pdf, html, json)

### List Reports

```http
GET /api/v1/reports/
Authorization: Bearer <token>
```

**Query Parameters:**
- `workflow_id`: Filter by workflow ID
- `report_type`: Filter by report type
- `status`: Filter by status (generating, completed, failed)

## User Management API

### List Users

```http
GET /api/v1/users/
Authorization: Bearer <token>
```

### Create User

```http
POST /api/v1/users/
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "secure_password",
  "role": "ANALYST",
  "permissions": ["read_targets", "create_workflows", "view_results"]
}
```

### Update User

```http
PUT /api/v1/users/{user_id}/
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "updated@example.com",
  "role": "MANAGER",
  "is_active": true
}
```

### User Operations

```http
# Reset password
POST /api/v1/users/{user_id}/reset-password/
Authorization: Bearer <token>

# Disable user
POST /api/v1/users/{user_id}/disable/
Authorization: Bearer <token>

# Enable user
POST /api/v1/users/{user_id}/enable/
Authorization: Bearer <token>
```

## System API

### Health Check

```http
GET /api/v1/system/health/
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-27T10:00:00Z",
    "version": "1.3.0",
    "services": {
      "database": "healthy",
      "backend": "healthy",
      "frontend": "healthy",
      "monitoring": "healthy"
    }
  }
}
```

### System Information

```http
GET /api/v1/system/info/
Authorization: Bearer <token>
```

### API Statistics

```http
GET /api/v1/system/stats/
Authorization: Bearer <token>
```

## SDK Examples

### Python SDK

```python
from bug_hunting_framework import BugHuntingFramework

# Initialize client
client = BugHuntingFramework(
    base_url="https://your-domain.com/api/v1/",
    api_key="your_api_key"
)

# Create target
target = client.targets.create(
    target="example.com",
    platform="BUGBOUNTY",
    description="Security testing target"
)

# Start workflow
workflow = client.workflows.create(
    target_id=target.id,
    stages=["passive_recon", "active_recon", "vuln_scan"]
)

# Monitor progress
while workflow.status == "RUNNING":
    workflow = client.workflows.get(workflow.id)
    print(f"Progress: {workflow.progress.overall}%")
    time.sleep(30)

# Get results
results = client.workflows.get_results(workflow.id)
print(f"Found {results.summary.total_vulnerabilities} vulnerabilities")

# Generate report
report = client.reports.generate(
    workflow_id=workflow.id,
    report_type="COMPREHENSIVE"
)
```

### JavaScript SDK

```javascript
import { BugHuntingFramework } from '@bug-hunting-framework/sdk';

// Initialize client
const client = new BugHuntingFramework({
  baseUrl: 'https://your-domain.com/api/v1/',
  apiKey: 'your_api_key'
});

// Create target
const target = await client.targets.create({
  target: 'example.com',
  platform: 'BUGBOUNTY',
  description: 'Security testing target'
});

// Start workflow
const workflow = await client.workflows.create({
  targetId: target.id,
  stages: ['passive_recon', 'active_recon', 'vuln_scan']
});

// Monitor progress
const monitorProgress = async () => {
  const status = await client.workflows.get(workflow.id);
  console.log(`Progress: ${status.progress.overall}%`);
  
  if (status.status === 'RUNNING') {
    setTimeout(monitorProgress, 30000);
  }
};

monitorProgress();

// Get results
const results = await client.workflows.getResults(workflow.id);
console.log(`Found ${results.summary.total_vulnerabilities} vulnerabilities`);
```

### cURL Examples

```bash
# Login and get token
TOKEN=$(curl -s -X POST https://your-domain.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"your_username","password":"your_password"}' \
  | jq -r '.data.access_token')

# Create target
curl -X POST https://your-domain.com/api/v1/targets/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "example.com",
    "platform": "BUGBOUNTY",
    "description": "Security testing target"
  }'

# Start workflow
curl -X POST https://your-domain.com/api/v1/workflows/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_id": "target_uuid",
    "stages": ["passive_recon", "active_recon"]
  }'
```

## Integration Guides

### Webhook Integration

Configure webhooks to receive real-time notifications:

```http
POST /api/v1/webhooks/
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://your-server.com/webhook",
  "events": ["workflow.started", "workflow.completed", "vulnerability.found"],
  "secret": "webhook_secret"
}
```

**Webhook Payload:**
```json
{
  "event": "workflow.completed",
  "timestamp": "2024-01-27T10:00:00Z",
  "data": {
    "workflow_id": "uuid",
    "target": "example.com",
    "status": "COMPLETED",
    "summary": {
      "total_vulnerabilities": 5
    }
  }
}
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Security Testing
on:
  push:
    branches: [main]

jobs:
  security-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Security Tests
        run: |
          # Create target
          TARGET_ID=$(curl -s -X POST ${{ secrets.API_URL }}/targets/ \
            -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d "{\"target\":\"${{ secrets.TARGET_DOMAIN }}\"}" \
            | jq -r '.data.id')
          
          # Start workflow
          WORKFLOW_ID=$(curl -s -X POST ${{ secrets.API_URL }}/workflows/ \
            -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d "{\"target_id\":\"$TARGET_ID\",\"stages\":[\"vuln_scan\"]}" \
            | jq -r '.data.id')
          
          # Wait for completion
          while true; do
            STATUS=$(curl -s ${{ secrets.API_URL }}/workflows/$WORKFLOW_ID/ \
              -H "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
              | jq -r '.data.status')
            
            if [ "$STATUS" = "COMPLETED" ]; then
              break
            elif [ "$STATUS" = "FAILED" ]; then
              exit 1
            fi
            
            sleep 30
          done
```

### Slack Integration

```python
import requests
from bug_hunting_framework import BugHuntingFramework

def send_slack_notification(message, webhook_url):
    requests.post(webhook_url, json={"text": message})

# Monitor workflows and send notifications
client = BugHuntingFramework(api_key="your_api_key")

workflows = client.workflows.list(status="running")
for workflow in workflows:
    if workflow.status == "COMPLETED":
        results = client.workflows.get_results(workflow.id)
        message = f"Workflow completed for {workflow.target}: {results.summary.total_vulnerabilities} vulnerabilities found"
        send_slack_notification(message, "your_slack_webhook_url")
```

## Best Practices

### Authentication

```python
# Store tokens securely
import os
from bug_hunting_framework import BugHuntingFramework

client = BugHuntingFramework(
    api_key=os.environ.get('BUG_HUNTING_API_KEY')
)

# Refresh tokens automatically
client.auth.refresh_token()
```

### Error Handling

```python
from bug_hunting_framework import BugHuntingFramework, APIError

try:
    workflow = client.workflows.create(target_id="uuid", stages=["vuln_scan"])
except APIError as e:
    if e.status_code == 401:
        # Handle authentication error
        client.auth.refresh_token()
        workflow = client.workflows.create(target_id="uuid", stages=["vuln_scan"])
    elif e.status_code == 429:
        # Handle rate limiting
        time.sleep(e.retry_after)
        workflow = client.workflows.create(target_id="uuid", stages=["vuln_scan"])
    else:
        raise
```

### Rate Limiting

```python
import time
from bug_hunting_framework import BugHuntingFramework

client = BugHuntingFramework(api_key="your_api_key")

# Implement exponential backoff
def api_call_with_retry(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except APIError as e:
            if e.status_code == 429:
                wait_time = 2 ** attempt
                time.sleep(wait_time)
                continue
            raise
    raise Exception("Max retries exceeded")

# Use with retry logic
workflow = api_call_with_retry(
    lambda: client.workflows.create(target_id="uuid", stages=["vuln_scan"])
)
```

### Data Validation

```python
from pydantic import BaseModel, validator

class WorkflowConfig(BaseModel):
    target_id: str
    stages: list[str]
    
    @validator('stages')
    def validate_stages(cls, v):
        valid_stages = ['passive_recon', 'active_recon', 'vuln_scan', 'vuln_test', 'kill_chain', 'reporting']
        for stage in v:
            if stage not in valid_stages:
                raise ValueError(f'Invalid stage: {stage}')
        return v

# Validate before API call
config = WorkflowConfig(target_id="uuid", stages=["vuln_scan"])
workflow = client.workflows.create(**config.dict())
```

### Logging

```python
import logging
from bug_hunting_framework import BugHuntingFramework

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

client = BugHuntingFramework(api_key="your_api_key")

# Log API calls
logger.info("Starting security workflow")
workflow = client.workflows.create(target_id="uuid", stages=["vuln_scan"])
logger.info(f"Workflow created: {workflow.id}")

# Monitor progress
while workflow.status == "RUNNING":
    workflow = client.workflows.get(workflow.id)
    logger.info(f"Progress: {workflow.progress.overall}%")
    time.sleep(30)

logger.info(f"Workflow completed: {workflow.status}")
```

---

## Appendix

### A. SDK Installation

```bash
# Python SDK
pip install bug-hunting-framework

# JavaScript SDK
npm install @bug-hunting-framework/sdk

# Go SDK
go get github.com/bug-hunting-framework/sdk-go
```

### B. OpenAPI Specification

The complete OpenAPI specification is available at:
```
https://your-domain.com/api/v1/docs/
```

### C. SDK Documentation

- **Python SDK**: https://bug-hunting-framework.readthedocs.io/
- **JavaScript SDK**: https://bug-hunting-framework.github.io/sdk-js/
- **Go SDK**: https://pkg.go.dev/github.com/bug-hunting-framework/sdk-go

### D. Support

For API support and questions:
- **Email**: dat1kidd916@gmail.com
- **Documentation**: `/docs` directory
- **Community**: GitHub Discussions 