# Bug Hunting Framework - User Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Framework Overview](#framework-overview)
3. [Target Management](#target-management)
4. [Workflow Execution](#workflow-execution)
5. [Results and Reporting](#results-and-reporting)
6. [User Interface Guide](#user-interface-guide)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)
9. [API Reference](#api-reference)
10. [Security Guidelines](#security-guidelines)

## Getting Started

### Prerequisites

Before using the Bug Hunting Framework, ensure you have:

- **Web Browser**: Modern browser (Chrome, Firefox, Safari, Edge)
- **Internet Connection**: Stable connection for tool updates and external API access
- **Target Authorization**: Proper authorization to test the target systems
- **Docker Compose**: Docker Compose installed and running
- **System Requirements**: Meet system requirements for the framework
- **.env Configuration**: Configure the .env file with the correct values
- **OS Requirement**: Ubuntu 22.04 LTS (Not tested on other OS)

### First-Time Setup

1. **Access the Framework**
   - Navigate to your framework URL: `https://localhost:3000`
   - You will be asked to create initial target profile(scope)

2. **Target Profile Creation**
   - Create a target profile with the following information:
     - Target Company Name: `Example LLC.`
     - Target Domain: `example.com`
     - Primary Target: `True/False`
     - Bounty Platform: `BugCrowd, HackerOne, etc.`
     - Bounty Platform Login Email: `example@example.com`
     - Bounty Platform Researcher Email: `example@ninja-bugcrowd.com`
     - In-Scope Domains: `*.example.com`
     - Out-of-Scope Domains: `*.dev.example.com`
     - Rate Limiting Requests: `5`
     - Rate Limiting Per Seconds: `1`
     - Custom Headers: `X-Custom-Header: Custom-Value`
     - Additional Info:  `Additional information about the target`
     - Notes: `Notes about the target`

3. **Dashboard Overview**
   - After Target creation, you'll see the main dashboard
   - Familiarize yourself with the navigation menu and key metrics

### Quick Start Tutorial

#### Step 1: Create Your First Target

**If you are new to the framework, you will be directed to create a target profile automatically.**
**To create an additional target profile, follow the steps below:**

1. Click **NavMenu** in the top left of the dashboard
2. Click **"Targets"**, then click **"New Target"**
3. You will be redirected to the target creation workflow
4. Click **"Save Target"**

#### Step 2: Run Your First Workflow

1. Select the target you want to run the workflow on from the dashboard nav menu **"Targets"**
2. Choose the stages you want to run:
   - **Passive Reconnaissance**: Subdomain enumeration, asset discovery
   - **Active Reconnaissance**: Port scanning, service discovery
   - **Vulnerability Scanning**: Automated vulnerability detection
   - **Vulnerability Testing**: AI-powered analysis and testing
   - **Kill Chain Analysis**: Attack path analysis
   - **Comprehensive Reporting**: Detailed reports and recommendations
3. Click **"Start"** if the target info is displayed on the dashboard
4. Just wait for the workflow to finish, you can monitor the progress in real-time
5. Once the workflow is finished, you can view the results in the **"Results"** tab
6. You can also download the reports in the **"Reports"** tab

#### Step 3: Review Results

1. Monitor the workflow progress in real-time
2. View results as they become available
3. Download comprehensive reports
4. Review the generated reports and adjust as needed.
5. Send report to bounty program, PROFIT!!!

## Framework Overview

### Architecture

The Bug Hunting Framework is a comprehensive security testing platform that automates the entire bug hunting process:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Interface│    │   Workflow      │    │   Security      │
│   (Frontend)    │    │   Orchestration │    │   Tools         │
│                 │    │   (Backend)     │    │   (Stages)      │
│ - Dashboard     │    │ - API           │    │ - Reconnaissance│
│ - Target Mgmt   │    │ - Validation    │    │ - Scanning      │
│ - Results View  │    │ - Database      │    │ - Testing       │
│ - Reporting     │    │ - Monitoring    │    │ - Analysis      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Key Components

#### 1. Frontend Interface
- **Dashboard**: Overview of targets, workflows, and results
- **Target Management**: Create and manage testing targets
- **Workflow Execution**: Configure and run security testing workflows
- **Results Visualization**: View and analyze findings
- **Reporting**: Generate comprehensive security reports

#### 2. Backend Services
- **API Layer**: RESTful API for all operations
- **Authentication**: JWT-based secure authentication
- **Database**: PostgreSQL for data storage
- **Monitoring**: Real-time system monitoring and alerting

#### 3. Security Testing Stages
- **Passive Reconnaissance**: Subdomain enumeration, asset discovery
- **Active Reconnaissance**: Port scanning, service fingerprinting
- **Vulnerability Scanning**: Automated vulnerability detection
- **Vulnerability Testing**: AI-powered analysis and exploitation testing
- **Kill Chain Analysis**: Attack path analysis/Post Exploitation and risk assessment
- **Comprehensive Reporting**: Detailed reports and remediation guidance

### Target Status and Management

#### Target States

- **ACTIVE**: Target is available for testing
- **PAUSED**: Target testing is temporarily suspended
- **COMPLETED**: All workflows for this target are finished
- **ARCHIVED**: Target is archived and no longer active

#### Target Operations

```bash
# View target details
GET /api/targets/{target_id}

# Update target configuration
PUT /api/targets/{target_id}

# Pause target
POST /api/targets/{target_id}/pause

# Resume target
POST /api/targets/{target_id}/resume

# Archive target
POST /api/targets/{target_id}/archive
```

## Workflow Execution

### Workflow Types

#### 1. Quick Assessment
- **Duration**: 30-60 minutes
- **Stages**: Passive Recon + Basic Scanning
- **Use Case**: Initial target assessment

#### 2. Standard Assessment
- **Duration**: 2-4 hours
- **Stages**: All stages with standard depth
- **Use Case**: Comprehensive security testing

#### 3. Deep Assessment
- **Duration**: 6-12 hours
- **Stages**: All stages with maximum depth
- **Use Case**: Thorough security audit

### Workflow Configuration

#### Stage Selection

```json
{
  "workflow_config": {
    "stages": {
      "passive_recon": {
        "enabled": true,
        "tools": ["amass", "subfinder", "assetfinder", "trufflehog"],
        "timeout": 1800
      },
      "active_recon": {
        "enabled": true,
        "tools": ["nmap", "katana", "nabuu"],
        "timeout": 3600
      },
      "vuln_scan": {
        "enabled": true,
        "tools": ["nuclei", "nikto", "zap"],
        "timeout": 7200
      },
      "vuln_test": {
        "enabled": true,
        "ai_analysis": true,
        "ai_agent": true,
        "timeout": 5400
      },
      "kill_chain": {
        "enabled": true,
        "ai_analysis": true,
        "ai_agent": true,
        "analysis_depth": "DEEP",
        "timeout": 1800
      },
      "reporting": {
        "enabled": true,
        "formats": ["PDF", "HTML", "JSON", "XML"],
        "timeout": 900
      }
    }
  }
}
```

#### Execution Parameters

- **Rate Limiting**: Requests per second limits
- **Scope**: In-Scope and Out-of-Scope domains
- **Custom Headers**: Custom headers to be added to the requests when testing the target

### Workflow Monitoring

#### Real-Time Progress

```bash
# Check workflow status
GET /api/workflows/{workflow_id}/status

# View stage progress
GET /api/workflows/{workflow_id}/stages/{stage_name}/progress

# Get execution logs
GET /api/workflows/{workflow_id}/logs
```

#### Progress Indicators

- **Queued**: Workflow is waiting to start
- **Running**: Workflow is currently executing
- **Completed**: Workflow has finished successfully
- **Failed**: Workflow encountered an error
- **Cancelled**: Workflow was manually cancelled

## Results and Reporting

### Results Structure

#### Stage Results

Each stage produces structured results:

```json
{
  "stage": "passive_recon",
  "target": "example.com",
  "target_id": "uuid",
  "execution_id": "execution_uuid",
  "start_time": "2024-01-27T10:00:00Z",
  "end_time": "2024-01-27T10:30:00Z",
  "status": "COMPLETED",
  "results": {
    "infrastructure": {
        "subdomains": [
      {
        "domain": "api.example.com",
        "ip": "192.168.1.100",
        "server_os": "Linux",
        "tool": "amass",
        "confidence": 0.95
      }
      {
        .......more subdomains
      }
    ],
    "nameservers": [
      {
        "url": "https://ns1.example.com",
        "status_code": 200,
        "ip": "192.168.1.100",
        "dns_records": [
            "A": "192.168.1.100",
            "NS": "ns1.example.com",
            "MX": "mx.example.com",
            "SOA": "ns1.example.com",
            "TXT": "txt.example.com",
            "CNAME": "cname.example.com",
            .......more dns records
        ],
        "tool": "amass",
        "confidence": 0.95
      },
      {
        .......more nameservers
      }
    ],
    "ASNs": [
        {
            "asn": "AS123456",
            "asn_name": "Example ASN",
            "asn_url": "https://example.com/asn/123456",
            "asn_cidr": "192.168.1.0/24",
            "associated_asns": [
                {
                    "asn": "AS123456",
                    "asn_name": "Example ASN",
                    "asn_url": "https://example.com/asn/123456",
                    "asn_cidr": "192.168.1.0/24",
                },
                {
                    .......more associated asns
                }
            ],
            "tool": "amass",
            "confidence": 0.95
        },
        {
            .......more asns
        }
    ],
    "ip_addresses": [
        {
            "ip": "192.168.1.100",
            "reverse_whois": "example.com",
        },
        {
            .......more ip addresses
        }
    ],
    "cloud_environment": [
        {
        "cloud_provider": "AWS",
        "cloud_region": "us-east-1",
        "cloud_service": "EC2",
        "cloud_url": "https://console.aws.amazon.com/ec2/v2/home?region=us-east-1#Instances:sort=instanceId",
        "cloud_instance_id": "i-01234567890abcdef0"
        },
        {
            .......more cloud instances found
        }
    ]
  },
  "summary": {
    "total_subdomains": 15,
    "total_nameservers": 3,
    "total_asns": 3,
    "total_ip_addresses": 15,
    "total_cloud_instances": 2,
    "unique_ips": 8
  }
}
```

#### Vulnerability Results

```json
{
  "vulnerability": {
    "id": "CVE-2024-1234",
    "title": "SQL Injection in User API",
    "severity": "HIGH",
    "cvss_score": 8.5,
    "description": "SQL injection vulnerability in /api/users endpoint",
    "evidence": {
      "url": "https://sql.example.com/api/users?id=1",
      "payload": "' OR 1=1--",
      "request": "request_body",  **request body or header used to exploit the vulnerability**
      "response": "Error: syntax error at or near \"1\"",
      "screenshot": "base64_encoded_image"
    },
    "exploitation": {
        "successful": true, **true if the exploit was successful, false if it was not**
        "exploit_url": "https://example.com/exploit", **url used to exploit the vulnerability**
        "exploit_payload": "payload", **payload used to exploit the vulnerability**
        "exploit_request": "request_body", **request body or header used to exploit the vulnerability**
        "exploit_response": "response", **response from the exploit with redacted sensitive data**
        "exploit_screenshot": "base64_encoded_image", **screenshot of the exploit**
        "exploit_tool": "sqlmap", **tool used to exploit the vulnerability**
        "post_exploitation": {
            "success": "true", **true if post exploitation was successful, false if it was not**
            "vuln_type": "RCE", **type of vulnerability that maybe exploited**
            "tactic": "Reverse Shell", **tactic needed to achieve possible vuln type**
            "technique": "SQL Injection w/ malicious payload", **technique needed to achieve possible vuln type**
            "screenshots": [
                "base64_encoded_image", **screenshot of the post exploitation**
                "base64_encoded_image", **screenshot of the post exploitation**
                ],
            "impact": [
                "Remote Code Execution", **impact of the vulnerability**
                "Data Exfiltration", **impact of the vulnerability**
                "Access to Internal Servers", **impact of the vulnerability**
                ],
            "tools": [
                "metasploit", **tool used to post exploit**
                "netcat", **tool used to post exploit**
                "curl", **tool used to post exploit**
            ],
            "risk_assessment": {
                "risk_level": "HIGH", **risk level of the vulnerability**
                "risk_description": "High risk of data exfiltration and remote code execution", **description of the risk**
                "risk_impact": "High", **impact of the risk**
                "risk_likelihood": "High", **likelihood of the risk**
                "risk_mitigation": "Use parameterized queries", **mitigation of the risk**
            },
            "references": "https://owasp.org/www-community/attacks/SQL_Injection", **references to the vulnerability**
            "date_discovered": "2024-01-01", **date the vulnerability was discovered**
            "time_discovered": "10:00:00" **time the vulnerability was discovered**
        },       
        "exploit_confidence": 0.95
    }
  }
}
```

### Report Generation

#### Report Types

1. **Executive Summary**
   - High-level findings overview
   - Risk assessment
   - Business impact analysis

2. **Technical Report**
   - Detailed vulnerability descriptions
   - Proof of concept
   - Remediation steps

3. **Compliance Report**
   - Regulatory compliance mapping
   - Industry standard alignment
   - Audit trail

#### Report Formats

- **PDF**: Professional formatted reports
- **HTML**: Interactive web-based reports
- **JSON**: Machine-readable data
- **CSV**: Spreadsheet-compatible data

### Report Customization

#### Custom Templates

```json
{
  "template_config": {
    "company_logo": "base64_encoded_logo",
    "company_name": "Your Company",
    "contact_info": "security@company.com",
    "custom_sections": [
      "executive_summary",
      "methodology",
      "findings",
      "remediation",
      "appendix"
    ]
  }
}
```

## User Interface Guide

### Dashboard Overview

#### Key Metrics

- **Active Target**: Active target currently being tested
- **Completed Workflows**: Total workflows finished
- **Vulnerabilities Found**: Number of security issues discovered
- **System Health**: Current system status and performance

#### Quick Actions

- **New Target**: Create a new testing target
- **Start Workflow**: Begin a new security testing workflow
- **View Reports**: Access generated reports
- **System Status**: Check framework health

### Navigation

#### Main Menu

- **Dashboard**: Overview and metrics
- **Targets**: Target management
- **Stages**: [
   -"passive_recon",
   -"active_recon",
   -"vuln_scan",
   -"vuln_test",
   -"kill_chain",
   -"reporting"
    ]
- **Results**: View and analyze findings
- **Reports**: Generate and download reports
- **Settings**: User preferences and configuration

#### Secondary Navigation

- **Help**: Documentation and support
- **Profile**: User account management
- **Logout**: Secure session termination

### Data Visualization

#### Charts and Graphs

- **Vulnerability Distribution**: Pie chart of vulnerability types
- **Timeline**: Workflow execution timeline
- **Geographic Distribution**: Map of discovered assets
- **Trend Analysis**: Security findings over time

#### Interactive Elements

- **Drill-down**: Click to explore detailed information
- **Filtering**: Filter results by various criteria
- **Sorting**: Sort data by different columns
- **Export**: Download data in various formats

## Best Practices

### Target Scope Definition

#### Clear Scope Definition

```json
{
  "scope": {
    "included": [
      "*.example.com",
      "api.example.com",
      "admin.example.com"
    ],
    "excluded": [
      "*.dev.example.com",
      "staging.example.com",
      "*.test.example.com"
    ],
    "rate_limits": {
      "requests_per_second": 10,
      "concurrent_connections": 5
    }
  }
}
```

#### Legal and Ethical Considerations

- **Authorization**: Ensure proper authorization before testing
- **Rate Limiting**: Respect target system rate limits
- **Data Handling**: Follow data protection regulations
- **Reporting**: Report findings responsibly

### Workflow Optimization

#### Performance Tuning

```json
{
  "optimization": {
    "concurrency": {
      "passive_recon": 5,
      "active_recon": 3,
      "vuln_scan": 2,
      "vuln_test": 1
    },
    "timeouts": {
      "tool_timeout": 300,
      "stage_timeout": 3600,
      "workflow_timeout": 14400
    },
    "resource_limits": {
      "memory_per_tool": "512MB",
      "cpu_per_tool": "0.5"
    }
  }
}
```

#### Tool Selection

- **Passive Recon**: Use multiple tools for comprehensive coverage
- **Active Recon**: Balance speed with thoroughness
- **Vulnerability Scanning**: Focus on high-impact vulnerabilities
- **Testing**: Use AI-powered analysis for efficiency

### Result Analysis

#### Prioritization Framework

```json
{
  "prioritization": {
    "critical": {
      "criteria": ["remote_code_execution", "data_breach", "authentication_bypass"],
      "response_time": "immediate"
    },
    "high": {
      "criteria": ["sql_injection", "xss", "privilege_escalation"],
      "response_time": "24_hours"
    },
    "medium": {
      "criteria": ["information_disclosure", "weak_crypto"],
      "response_time": "7_days"
    },
    "low": {
      "criteria": ["missing_headers", "version_disclosure"],
      "response_time": "30_days"
    }
  }
}
```

#### False Positive Reduction

- **Manual Verification**: Verify automated findings
- **Context Analysis**: Consider business context
- **Exploitation Testing**: Test actual exploitability
- **Documentation**: Document verification process

## Troubleshooting

### Common Issues

#### Workflow Failures

**Issue**: Workflow fails to start
```bash
# Check system resources
docker stats

# Check service status
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs backend
```

**Solution**: Ensure sufficient system resources and all services are running

#### Tool Execution Errors

**Issue**: Individual tools fail during execution
```bash
# Check tool configuration
GET /api/workflows/{workflow_id}/stages/{stage_name}/tools/{tool_name}/config

# Check tool logs
GET /api/workflows/{workflow_id}/stages/{stage_name}/tools/{tool_name}/logs
```

**Solution**: Verify tool configuration and network connectivity

#### Performance Issues

**Issue**: Slow workflow execution
```bash
# Check resource usage
docker stats --no-stream

# Check database performance
docker-compose -f docker-compose.prod.yml exec db psql -U $DB_USER -d $DB_NAME -c "
SELECT * FROM pg_stat_activity WHERE state = 'active';
"
```

**Solution**: Optimize resource allocation and database queries

### Error Messages

#### Common Error Codes

- **400 Bad Request**: Invalid input parameters
- **401 Unauthorized**: Authentication required
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server-side error

#### Error Resolution

```json
{
  "error_handling": {
    "400": "Check input parameters and format",
    "401": "Verify authentication credentials",
    "403": "Contact administrator for permissions",
    "404": "Verify resource exists and is accessible",
    "500": "Check server logs and contact support"
  }
}
```

### Support Resources

#### Documentation

- **User Guide**: This comprehensive guide
- **API Documentation**: Technical API reference
- **Video Tutorials**: Step-by-step video guides
- **FAQ**: Frequently asked questions

#### Support Channels

- **Email Support**: dat1kidd916@gmail.com
- **Documentation**: `/docs` directory
- **Community**: User forums and discussions
- **Training**: Scheduled training sessions

## API Reference

### Authentication

#### JWT Token Authentication

```bash
# Login to get access token
POST /api/auth/login
{
  "username": "your_username",
  "password": "your_password"
}

# Use token in requests
Authorization: Bearer <your_jwt_token>
```

#### Token Management

```bash
# Refresh token
POST /api/auth/refresh
Authorization: Bearer <refresh_token>

# Logout
POST /api/auth/logout
Authorization: Bearer <access_token>
```

### Core Endpoints

#### Targets

```bash
# List targets
GET /api/targets/

# Create target
POST /api/targets/
{
  "target": "example.com",
  "platform": "BUGBOUNTY",
  "description": "Security testing target"
}

# Get target details
GET /api/targets/{target_id}

# Update target
PUT /api/targets/{target_id}

# Delete target
DELETE /api/targets/{target_id}
```

#### Workflows

```bash
# List workflows
GET /api/workflows/

# Create workflow
POST /api/workflows/
{
  "target_id": "target_uuid",
  "stages": ["passive_recon", "active_recon"],
  "config": {...}
}

# Get workflow status
GET /api/workflows/{workflow_id}

# Cancel workflow
POST /api/workflows/{workflow_id}/cancel
```

#### Results

```bash
# Get workflow results
GET /api/workflows/{workflow_id}/results

# Get stage results
GET /api/workflows/{workflow_id}/stages/{stage_name}/results

# Export results
GET /api/workflows/{workflow_id}/export?format=json
```

### Response Format

#### Standard Response

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "data": {
    "id": "uuid",
    "created_at": "2024-01-27T10:00:00Z",
    "updated_at": "2024-01-27T10:00:00Z"
  },
  "errors": null
}
```

#### Error Response

```json
{
  "success": false,
  "message": "Validation error",
  "data": null,
  "errors": [
    "Target domain is required",
    "Invalid domain format"
  ]
}
```

### Rate Limiting

```bash
# Rate limit headers
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1643270400
```

## Security Guidelines

### Access Control

#### User Permissions

- **Admin**: Full system access
- **Manager**: Target and workflow management
- **Analyst**: Results viewing and reporting
- **Viewer**: Read-only access

#### Session Management

```json
{
  "session_config": {
    "access_token_lifetime": 1800,
    "refresh_token_lifetime": 604800,
    "max_concurrent_sessions": 3,
    "inactivity_timeout": 3600
  }
}
```

### Data Protection

#### Data Classification

- **Public**: General information
- **Internal**: Company-specific data
- **Confidential**: Sensitive information
- **Restricted**: Highly sensitive data

#### Data Handling

```json
{
  "data_protection": {
    "encryption": {
      "at_rest": "AES-256",
      "in_transit": "TLS 1.3"
    },
    "retention": {
      "raw_data": "30_days",
      "processed_data": "1_year",
      "reports": "7_years"
    },
    "access_logging": true,
    "audit_trail": true
  }
}
```

### Compliance

#### Regulatory Compliance

- **GDPR**: Data protection and privacy
- **SOC 2**: Security controls and procedures
- **ISO 27001**: Information security management
- **PCI DSS**: Payment card industry standards

#### Audit Requirements

```json
{
  "audit_config": {
    "access_logs": true,
    "data_access_logs": true,
    "configuration_changes": true,
    "security_events": true,
    "retention_period": "7_years"
  }
}
```

### Incident Response

#### Security Incident Procedures

1. **Detection**: Automated monitoring and alerting
2. **Assessment**: Evaluate incident severity
3. **Containment**: Isolate affected systems
4. **Eradication**: Remove threat and vulnerabilities
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Document and improve procedures

#### Contact Information

- **Security Team**: dat1kidd916@gmail.com
- **Emergency Contact**: dat1kidd916@gmail.com
- **Incident Response**: Follow operational runbooks

---

## Appendix

### A. Glossary

- **Target**: System or application being tested
- **Workflow**: Automated security testing process
- **Stage**: Individual phase of security testing
- **Tool**: Security testing utility or script
- **Vulnerability**: Security weakness or flaw
- **Exploit**: Method to take advantage of vulnerability
- **Payload**: Data used to test for vulnerabilities
- **Report**: Documented findings and recommendations

### B. Acronyms

- **API**: Application Programming Interface
- **CVE**: Common Vulnerabilities and Exposures
- **CVSS**: Common Vulnerability Scoring System
- **GDPR**: General Data Protection Regulation
- **JWT**: JSON Web Token
- **OWASP**: Open Web Application Security Project
- **SQL**: Structured Query Language
- **XSS**: Cross-Site Scripting

### C. References

- **OWASP Top 10**: https://owasp.org/www-project-top-ten/
- **CVE Database**: https://cve.mitre.org/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **ISO 27001**: https://www.iso.org/isoiec-27001-information-security.html

### D. Version History

- **v1.0.0**: Initial release with basic functionality
- **v1.1.0**: Added AI-powered vulnerability testing
- **v1.2.0**: Enhanced reporting and compliance features
- **v1.3.0**: Improved performance and monitoring 