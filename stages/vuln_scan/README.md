# Vulnerability Scanning Stage

## Overview

The Vulnerability Scanning Stage implements comprehensive black-box vulnerability scanning following a 7-step methodology. This stage assumes no internal access (no source code or credentials) and simulates a real attacker by probing from the outside using automation-first tooling.

## 7-Step Methodology

### Step 1: Define Scope and Gather Targets
- Collect all target endpoints (web apps, APIs, cloud services) from previous recon stages
- Categorize targets into web applications, APIs, and cloud services
- Validate and deduplicate target lists
- Generate comprehensive target inventory

### Step 2: Prepare Vulnerability Scanning Tools
- Set up automated tools: Burp Suite (Pro), OWASP ZAP (Automation Framework/API), Nuclei (template-based, CLI)
- Additional tools: Nikto, Wapiti, Arachni, Skipfish, OpenVAS, API fuzzers
- Emphasize CLI/scriptable interfaces and tool configuration
- Configure rate limiting based on target profiles

### Step 3: Leverage Nuclei (Including Extended Fuzzing Templates)
- Use latest community templates and `fuzzing-templates` for deeper parameter testing
- Run Nuclei on all targets with severity filtering
- Implement multiple scan types: basic, fuzzing, technology detection, custom templates
- Parse and categorize results by severity and type

### Step 4: Automated Scanning of Web Applications (Black-Box Testing)
- Perform generalized dynamic scans using tools like Burp Scanner or OWASP ZAP
- Include spidering/crawling and active scanning
- Cover all tech stacks and automate via CLI/Docker
- Implement comprehensive web vulnerability detection

### Step 5: Scan APIs and Cloud Components
- Treat APIs as first-class targets with OpenAPI/Swagger analysis
- Check for common API issues: authentication bypass, injection, IDOR
- Scan publicly accessible cloud resources (storage buckets, public services)
- Test cloud metadata services for SSRF potential

### Step 6: Collect, Consolidate, and Interpret Scan Results
- Combine results from all scanning tools
- Categorize and prioritize findings by severity
- Verify and eliminate false positives
- Document key details and decide next actions (exploitation, chaining, deeper validation)

### Step 7: Continuous Improvement and Re-Scanning
- Update tool signatures and templates
- Implement re-scanning capabilities for new endpoints
- Set up scheduled scanning and monitoring
- Generate improvement recommendations and trend analysis

## Tools and Technologies

### Primary Scanners
- **Nuclei**: Template-based vulnerability scanner with community and extended fuzzing templates
- **OWASP ZAP**: Open-source DAST scanner with Automation Framework and CLI
- **Burp Suite**: Professional web application security testing platform

### Additional Scanners
- **Nikto**: Web server scanner for comprehensive server vulnerability testing
- **Wapiti**: Web application vulnerability scanner with SQL injection, XSS, and file inclusion detection
- **Arachni**: High-performance web application security scanner with modular framework
- **Skipfish**: Web application security reconnaissance tool with interactive sitemap generation
- **OpenVAS**: Open source vulnerability assessment system with thousands of vulnerability tests

### API Scanners
- **Custom API Scanner**: OpenAPI/Swagger analysis, GraphQL testing, REST API fuzzing
- **Authentication bypass testing**
- **Security header analysis**

### Cloud Scanners
- **Custom Cloud Scanner**: AWS S3, Azure Blob Storage, Google Cloud Storage
- **Cloud metadata service testing**
- **Public cloud resource discovery**

### Analysis Tools
- **Result Analyzer**: Consolidation, categorization, false positive detection
- **Continuous Improvement**: Template updates, trend analysis, recommendations

## Architecture

### Directory Structure
```
stages/vuln_scan/
├── run_vuln_scan.py          # Main orchestrator script
├── requirements.txt          # Python dependencies
├── Dockerfile               # Container configuration
├── README.md               # This file
├── runners/                # Tool-specific runners
│   ├── target_gatherer.py   # Step 1: Target collection
│   ├── tool_preparer.py     # Step 2: Tool preparation
│   ├── nuclei_runner.py     # Step 3: Nuclei scanning
│   ├── zap_runner.py        # Step 4: ZAP scanning
│   ├── nikto_runner.py      # Step 4b: Nikto scanning
│   ├── wapiti_runner.py     # Step 4c: Wapiti scanning
│   ├── arachni_runner.py    # Step 4d: Arachni scanning
│   ├── skipfish_runner.py   # Step 4e: Skipfish scanning
│   ├── openvas_runner.py    # Step 4f: OpenVAS scanning
│   ├── api_scanner.py       # Step 5: API scanning
│   ├── cloud_scanner.py     # Step 5: Cloud scanning
│   ├── result_analyzer.py   # Step 6: Result analysis
│   └── continuous_improvement.py # Step 7: Continuous improvement
└── tools/                   # Additional tools and scripts
```

### Output Structure
```
/outputs/vuln_scan/{target}/
├── targets/                 # Target lists and categorization
├── nuclei/                  # Nuclei scan results
├── zap/                     # ZAP scan results
├── nikto/                   # Nikto scan results
├── wapiti/                  # Wapiti scan results
├── arachni/                 # Arachni scan results
├── skipfish/                # Skipfish scan results
├── openvas/                 # OpenVAS scan results
├── api_scan/                # API scanning results
├── cloud_scan/              # Cloud scanning results
├── consolidated/            # Consolidated analysis results
└── reports/                 # Final reports and recommendations
```

## Usage

### Command Line Usage
```bash
# Basic usage
python run_vuln_scan.py --target example.com

# With specific options
python run_vuln_scan.py \
    --target example.com \
    --enable-nuclei \
    --enable-zap \
    --enable-nikto \
    --enable-wapiti \
    --enable-arachni \
    --enable-skipfish \
    --enable-openvas \
    --enable-api-scanning \
    --enable-cloud-scanning \
    --rate-limit 10 \
    --max-concurrent 5 \
    --severity critical high medium \
    --api-url http://backend:8000/api/results/vuln_scan \
    --jwt-token your-jwt-token
```

### Docker Usage
```bash
# Build the container
docker build -t vuln-scan .

# Run the container
docker run -v $(pwd)/outputs:/outputs \
    -e BACKEND_API_URL=http://backend:8000/api/results/vuln_scan \
    -e BACKEND_JWT_TOKEN=your-jwt-token \
    vuln-scan python run_vuln_scan.py --target example.com
```

### Docker Compose Integration
```yaml
vuln_scan:
  build:
    context: ./stages/vuln_scan
    dockerfile: Dockerfile
  container_name: bug-hunting-vuln-scan
  restart: unless-stopped
  depends_on:
    backend:
      condition: service_healthy
  environment:
    - BACKEND_API_URL=http://backend:8000/api/results/vuln_scan
    - BACKEND_JWT_TOKEN=${JWT_SECRET_KEY}
    - TARGET=${TARGET}
  volumes:
    - ./outputs:/outputs
    - ./stages/vuln_scan/.env:/app/.env
  networks:
    - bug-hunting-network
```

## Configuration

### Environment Variables
- `BACKEND_API_URL`: Backend API URL for result submission
- `BACKEND_JWT_TOKEN`: JWT token for API authentication
- `TARGET`: Target domain or IP for scanning
- `RATE_LIMIT`: Rate limiting configuration (requests per second)
- `MAX_CONCURRENT_SCANS`: Maximum concurrent scans
- `SEVERITY_FILTER`: Severity levels to scan (critical, high, medium, low)

### Rate Limiting
The stage implements rate limiting based on target profiles to ensure responsible scanning:
- Default rate limit: 10 requests per second
- Configurable per target type
- Respects target-specific limitations
- Implements backoff strategies for failures

## API Integration

### Result Submission
The stage automatically submits results to the backend API using JWT authentication:
- Raw scan outputs
- Parsed and categorized findings
- Consolidated analysis results
- Improvement recommendations

### Status Tracking
Real-time status updates are provided through the API:
- Scan progress and completion status
- Tool-specific results and summaries
- Error reporting and recovery

## Security Considerations

### Ethical Scanning
- All scanning is non-intrusive and follows responsible disclosure
- Rate limiting prevents overwhelming target systems
- No exploitation or actual attack capabilities
- Respects robots.txt and security headers

### Data Protection
- Sensitive data is properly handled and encrypted
- Results are stored securely with access controls
- JWT tokens are rotated regularly
- No sensitive information is logged or exposed

## Monitoring and Alerting

### Metrics Collection
- Scan duration and performance metrics
- Vulnerability discovery rates
- False positive analysis
- Coverage and effectiveness metrics

### Alerting
- Critical vulnerability notifications
- Scan failure alerts
- Coverage drop warnings
- Performance degradation alerts

## Continuous Improvement

### Template Updates
- Automatic Nuclei template updates
- ZAP add-on and rule updates
- Signature database updates
- Custom template development

### Trend Analysis
- Vulnerability trend analysis
- Tool effectiveness comparison
- Performance optimization
- Coverage improvement recommendations

### Re-scanning
- Incremental scanning for new endpoints
- Scheduled scanning and monitoring
- Change detection and differential scanning
- Priority-based scanning queues

## Troubleshooting

### Common Issues
1. **Tool Installation**: Ensure all required tools are installed and in PATH
2. **Rate Limiting**: Adjust rate limits if targets are blocking requests
3. **API Connectivity**: Verify backend API URL and JWT token configuration
4. **Output Permissions**: Ensure output directories have proper write permissions

### Debug Mode
Enable debug logging for detailed troubleshooting:
```bash
export LOG_LEVEL=DEBUG
python run_vuln_scan.py --target example.com
```

### Performance Optimization
- Adjust concurrent scan limits based on system resources
- Use appropriate rate limiting for target systems
- Monitor memory and CPU usage during scanning
- Implement proper cleanup and resource management

## Contributing

### Adding New Tools
1. Create a new runner in the `runners/` directory
2. Implement the standard interface with `run_scan()` method
3. Add proper error handling and logging
4. Update the main orchestrator to include the new tool
5. Add tests and documentation

### Custom Templates
1. Create custom Nuclei templates for specific vulnerabilities
2. Add technology-specific scanning rules
3. Implement custom API testing scenarios
4. Develop cloud-specific security checks

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Check the troubleshooting section
- Review the API documentation
- Contact the development team
- Submit issues through the project repository 