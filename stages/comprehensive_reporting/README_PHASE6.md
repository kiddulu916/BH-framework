# Phase 6 - Stakeholder Communication Runner

## Overview

Phase 6 is the final phase of the comprehensive reporting stage, focusing on stakeholder communication, handoff documentation, and final deliverable packaging. This phase creates the final deliverables that will be presented to stakeholders and used for project handoff.

## Features

### Step 6.1: Stakeholder Communication Materials
- **Executive Briefing**: High-level summary for C-level executives
- **Technical Briefing**: Detailed technical findings for IT teams
- **Board Presentation**: Strategic overview for board members
- **Stakeholder Summary**: Customized summaries for different stakeholders
- **Communication Plan**: Structured communication strategy

### Step 6.2: Handoff Documentation
- **Technical Handoff**: Technical details for development teams
- **Management Handoff**: Management overview and next steps
- **Compliance Handoff**: Compliance and regulatory information
- **Operational Handoff**: Operational procedures and recommendations
- **Handoff Summary**: Comprehensive handoff overview

### Step 6.3: Final Deliverables
- **Executive Package**: Complete executive-level deliverables
- **Technical Package**: Complete technical documentation
- **Compliance Package**: Complete compliance documentation
- **Complete Package**: All deliverables in one comprehensive package

## Usage

### Running Phase 6 Independently

```bash
# Run Phase 6 only
python run_phase6_stakeholder_communication.py --target example.com

# Run with custom stage name
python run_phase6_stakeholder_communication.py --target example.com --stage custom_stage

# Run with phase-only flag
python run_phase6_stakeholder_communication.py --target example.com --phase-only
```

### Running via Docker Compose

```bash
# Start the comprehensive reporting service
docker-compose up comprehensive_reporting

# Run with specific target
TARGET=example.com docker-compose up comprehensive_reporting
```

### Running the Full Comprehensive Reporting

```bash
# Run all phases including Phase 6
python run_comprehensive_reporting.py --target example.com
```

## Output Structure

```
outputs/comprehensive_reporting/{target}/
├── phase_6/
│   ├── communication_materials/
│   │   ├── executive_briefing.pdf
│   │   ├── technical_briefing.pdf
│   │   ├── board_presentation.pptx
│   │   ├── stakeholder_summary.pdf
│   │   └── communication_plan.md
│   ├── handoff_documentation/
│   │   ├── technical_handoff.md
│   │   ├── management_handoff.md
│   │   ├── compliance_handoff.md
│   │   ├── operational_handoff.md
│   │   └── handoff_summary.md
│   ├── final_deliverables/
│   │   ├── executive_package.zip
│   │   ├── technical_package.zip
│   │   ├── compliance_package.zip
│   │   └── complete_package.zip
│   ├── logs/
│   │   └── phase6_stakeholder_communication.log
│   └── phase_6_results.json
```

## Configuration

### Environment Variables

Copy `.env.template` to `.env` and configure:

```bash
# Backend API Configuration
BACKEND_API_URL=http://backend:8000/api/results/comprehensive-reporting
BACKEND_JWT_TOKEN=your_jwt_token_here

# JWT Configuration
JWT_SECRET=your_jwt_secret_here
JWT_ALGORITHM=HS256

# Stage Configuration
STAGE_NAME=comprehensive_reporting
TARGET=example.com
STAGE_TIMEOUT_SECONDS=3600

# Reporting Configuration
REPORT_FORMATS=pdf,html,markdown,docx,pptx
STAKEHOLDER_COMMUNICATION_ENABLED=true
```

### JWT Token Generation

Generate JWT tokens using the universal script:

```bash
# Generate JWT for comprehensive_reporting stage
python stages/utils/generate_jwt.py --sub comprehensive_reporting_stage --env-path stages/comprehensive_reporting/.env
```

## Dependencies

### System Dependencies
- Python 3.11+
- Minimal font packages (Liberation, DejaVu)
- Pandoc for document conversion
- wkhtmltopdf for PDF generation

### Python Dependencies
- Core: python-dotenv, pydantic, asyncio
- Data processing: pandas, numpy, openpyxl
- Report generation: jinja2, markdown, weasyprint, reportlab
- Visualization: matplotlib, seaborn, plotly
- Presentation: python-pptx, dash
- Web: requests, aiohttp, fastapi

## Docker Configuration

### Dockerfile Features
- **Base Image**: python:3.11-slim
- **Minimal Fonts**: Only essential fonts for smaller image size
- **Security**: Non-root user execution
- **Health Checks**: Built-in health monitoring
- **Resource Limits**: Configurable memory and CPU limits

### Docker Compose Service
```yaml
comprehensive_reporting:
  build:
    context: ./stages/comprehensive_reporting
    dockerfile: Dockerfile
  container_name: bug-hunting-comprehensive-reporting
  ports:
    - "8007:8007"
  environment:
    - BACKEND_API_URL=${BACKEND_API_URL}
    - BACKEND_JWT_TOKEN=${BACKEND_JWT_TOKEN}
    - TARGET=${TARGET:-example.com}
  volumes:
    - ./stages/comprehensive_reporting:/app
    - ./outputs:/app/outputs
```

## Monitoring and Logging

### Health Checks
- **Endpoint**: HTTP health check on port 8000
- **Interval**: 30 seconds
- **Timeout**: 10 seconds
- **Retries**: 3 attempts

### Logging
- **Level**: INFO (configurable)
- **Format**: Structured logging with timestamps
- **Output**: File and console logging
- **Location**: `phase6_stakeholder_communication.log`

## Performance Optimization

### Font Optimization
- **Minimal Fonts**: Only Liberation and DejaVu fonts
- **Reduced Size**: Smaller Docker image size
- **Faster Build**: Reduced installation time

### Resource Management
- **Memory Limit**: 4GB default (configurable)
- **CPU Limit**: 1.0 cores default (configurable)
- **Timeout**: 3600 seconds for long-running operations

## Integration

### Backend API Integration
- **Endpoint**: `/api/results/comprehensive-reporting`
- **Authentication**: JWT Bearer token
- **Data Format**: JSON with standardized APIResponse model
- **Error Handling**: Comprehensive error handling and retry logic

### Stage Dependencies
- **Depends on**: All previous stages (passive_recon, active_recon, vuln_scan, vuln_test, kill_chain)
- **Data Source**: Consolidated results from all previous stages
- **Output**: Final deliverables for stakeholder handoff

## Troubleshooting

### Common Issues

1. **JWT Token Issues**
   ```bash
   # Regenerate JWT token
   python stages/utils/generate_jwt.py --sub comprehensive_reporting_stage --env-path stages/comprehensive_reporting/.env
   ```

2. **Font Issues**
   ```bash
   # Check font installation
   docker exec bug-hunting-comprehensive-reporting fc-list
   ```

3. **Memory Issues**
   ```bash
   # Increase memory limit in docker-compose.yml
   memory: 8192M
   ```

4. **Timeout Issues**
   ```bash
   # Increase timeout in .env
   STAGE_TIMEOUT_SECONDS=7200
   ```

### Debug Mode

Enable debug logging:

```bash
# Set log level to DEBUG
LOG_LEVEL=DEBUG
```

## Security Considerations

- **Non-root User**: Container runs as non-root user
- **JWT Authentication**: Secure API communication
- **Input Validation**: All inputs validated with Pydantic
- **Output Sanitization**: All outputs sanitized before delivery
- **Secret Management**: Secrets stored in environment variables

## Best Practices

1. **Environment Configuration**: Always use `.env` files for configuration
2. **JWT Rotation**: Regularly rotate JWT secrets and tokens
3. **Resource Monitoring**: Monitor memory and CPU usage
4. **Log Review**: Regularly review logs for issues
5. **Backup**: Backup important deliverables and configurations
6. **Testing**: Test with sample data before production use
7. **Documentation**: Keep documentation updated with changes

## Support

For issues and questions:
1. Check the logs in `outputs/comprehensive_reporting/{target}/phase_6/logs/`
2. Review the troubleshooting section above
3. Check the main project documentation
4. Review the comprehensive reporting stage documentation 