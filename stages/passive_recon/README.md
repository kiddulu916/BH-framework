# Enhanced Passive Reconnaissance Stage

A comprehensive passive reconnaissance stage for bug hunting that implements all major OSINT techniques from the article, providing stealthy attack surface mapping without direct target interaction.

## Overview

This enhanced passive reconnaissance stage implements 10 major technique categories:

1. **Domain & WHOIS Profiling** - Domain registration information and relationships
2. **Enhanced Subdomain Enumeration** - Certificate transparency and passive DNS
3. **Public Repository Mining** - GitHub, GitLab, and secret detection
4. **Search Engine Dorking** - Advanced Google/Bing search operators
5. **Data Breach & Leak Checking** - HaveIBeenPwned, DeHashed, IntelX integration
6. **Infrastructure Exposure Analysis** - Shodan, Censys, BinaryEdge, ZoomEye
7. **Archive & Historical Data Mining** - Wayback Machine and historical URLs
8. **Social Media & Public Information** - Employee and tech stack discovery
9. **Cloud Asset Enumeration** - AWS S3, GCP, Azure bucket discovery
10. **Continuous Monitoring** - Automated discovery tracking and alerting

## Features

### 🚀 Enhanced Capabilities
- **22+ Tool Runners**: Comprehensive OSINT tool coverage
- **Parallel Execution**: Multi-threaded tool execution for performance
- **Rate Limiting**: Intelligent API rate limiting to prevent service blocking
- **Error Handling**: Robust error handling with retry logic
- **Data Correlation**: Cross-tool data correlation and deduplication
- **Progress Tracking**: Real-time progress monitoring and reporting

### 📊 Data Management
- **Comprehensive Data Models**: 9 new OSINT data models for complete coverage
- **Target Integration**: All data properly linked to target_id for framework integration
- **API Integration**: Seamless backend API integration with JWT authentication
- **Data Validation**: Pydantic schema validation for all data types
- **Export Capabilities**: Multiple output formats for next-phase testing

### 🔄 Automation & Monitoring
- **Continuous Monitoring**: Scheduled reconnaissance execution
- **Discovery Alerts**: Email alerts for new discoveries
- **Performance Tracking**: Comprehensive performance metrics
- **Historical Comparison**: Track changes over time
- **Configurable Scheduling**: Flexible monitoring intervals

## Architecture

### Tool Runner Structure
```
stages/passive_recon/
├── run_passive_recon.py          # Main orchestration script
├── monitor_passive_recon.py      # Continuous monitoring
├── monitor_config.json          # Monitoring configuration
├── requirements.txt             # Python dependencies
├── .env                        # Environment variables
├── runners/                    # Individual tool runners
│   ├── run_whois.py           # WHOIS and DNS profiling
│   ├── run_certificate_transparency.py  # CT logs and passive DNS
│   ├── run_repository_mining.py         # Public repository scanning
│   ├── run_search_dorking.py           # Search engine dorking
│   ├── run_breach_checking.py          # Data breach checking
│   ├── run_infrastructure_exposure.py  # Infrastructure scanning
│   ├── run_archive_mining.py           # Archive and historical data
│   ├── run_social_intelligence.py      # Social media intelligence
│   └── utils.py                        # Shared utilities
└── outputs/                    # Output directory structure
    └── <target>/
        ├── raw/               # Raw tool outputs
        └── parsed/            # Parsed and structured data
```

### Data Flow
1. **Target Creation**: Automatic target creation in backend
2. **Tool Execution**: Parallel execution of all OSINT tools
3. **Data Collection**: Raw and parsed data collection
4. **API Submission**: Data submission to backend with target_id
5. **Correlation**: Cross-tool data correlation and analysis
6. **Monitoring**: Continuous monitoring for new discoveries

## Installation

### Prerequisites
- Python 3.11+
- Docker and Docker Compose
- API keys for external services (see Configuration section)

### Setup
1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd bug-hunting-framework
   ```

2. **Install dependencies**:
   ```bash
   cd stages/passive_recon
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

4. **Start the framework**:
   ```bash
   docker-compose up -d
   ```

## Configuration

### Environment Variables (.env)
```bash
# Backend API Configuration
BACKEND_API_URL=http://backend:8000/api/results/passive-recon
BACKEND_JWT_TOKEN=your-jwt-token
JWT_SECRET=your-jwt-secret
JWT_ALGORITHM=HS256

# Tool Paths
AMASS_PATH=/usr/local/bin/amass
SUBFINDER_PATH=/usr/local/bin/subfinder
ASSETFINDER_PATH=/usr/local/bin/assetfinder
GAU_PATH=/usr/local/bin/gau
WAYBACKURLS_PATH=/usr/local/bin/waybackurls
TRUFFLEHOG_PATH=/usr/local/bin/trufflehog

# API Keys (Required for enhanced features)
CENSYS_API_ID=your-censys-api-id
CENSYS_API_SECRET=your-censys-api-secret
SECURITYTRAILS_API_KEY=your-securitytrails-key
VIRUSTOTAL_API_KEY=your-virustotal-key
GITHUB_TOKEN=your-github-token
GITLAB_TOKEN=your-gitlab-token
GOOGLE_CUSTOM_SEARCH_API_KEY=your-google-search-key
GOOGLE_CUSTOM_SEARCH_ENGINE_ID=your-search-engine-id
BING_SEARCH_API_KEY=your-bing-search-key
HIBP_API_KEY=your-haveibeenpwned-key
DEHASHED_API_KEY=your-dehashed-key
INTELX_API_KEY=your-intelx-key
SHODAN_API_KEY=your-shodan-key
BINARYEDGE_API_KEY=your-binaryedge-key
ZOOMEYE_API_KEY=your-zoomeye-key
```

### Monitoring Configuration (monitor_config.json)
```json
{
  "targets": ["example.com", "test.example.com"],
  "schedule_interval": 24,
  "alert_threshold": 5,
  "email": {
    "enabled": false,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "your-email@gmail.com",
    "to_email": "alerts@yourdomain.com"
  }
}
```

## Usage

### Basic Usage
```bash
# Run passive recon for a single target
python run_passive_recon.py --target example.com

# Run with custom parallel execution and rate limiting
python run_passive_recon.py --target example.com --parallel 5 --rate-limit 2.0
```

### Continuous Monitoring
```bash
# Start continuous monitoring
python monitor_passive_recon.py --targets example.com test.example.com --interval 12

# Run once for testing
python monitor_passive_recon.py --targets example.com --run-once

# Use configuration file
python monitor_passive_recon.py --config monitor_config.json
```

### Docker Usage
```bash
# Run in Docker container
docker run --rm -v $(pwd)/outputs:/outputs \
  -e BACKEND_API_URL=http://backend:8000/api/results/passive-recon \
  -e BACKEND_JWT_TOKEN=your-token \
  passive-recon:latest --target example.com
```

## Tool Runners

### 1. WHOIS & DNS Profiling (run_whois.py)
- **WHOIS Lookup**: Domain registration information
- **Reverse WHOIS**: Find domains by registrant
- **DNS Records**: Comprehensive DNS record enumeration
- **Domain Relationships**: Discover related domains

### 2. Certificate Transparency (run_certificate_transparency.py)
- **CT Logs**: Certificate transparency log monitoring
- **Passive DNS**: DNS database queries
- **Subdomain Discovery**: Certificate-based subdomain enumeration
- **SSL Analysis**: SSL certificate analysis

### 3. Repository Mining (run_repository_mining.py)
- **GitHub Scanning**: Public repository analysis
- **GitLab Scanning**: GitLab repository scanning
- **Secret Detection**: TruffleHog integration
- **Code Analysis**: Internal reference discovery

### 4. Search Engine Dorking (run_search_dorking.py)
- **Google Dorks**: Advanced Google search operators
- **Bing Dorks**: Bing search engine dorking
- **File Discovery**: File type and extension discovery
- **Error Messages**: Debug information discovery

### 5. Breach Checking (run_breach_checking.py)
- **HaveIBeenPwned**: Data breach checking
- **DeHashed**: Credential leak database
- **IntelX**: Intelligence platform integration
- **Credential Analysis**: Password pattern analysis

### 6. Infrastructure Exposure (run_infrastructure_exposure.py)
- **Shodan**: Internet-wide scanner integration
- **Censys**: Certificate and port scanning
- **BinaryEdge**: Network intelligence platform
- **ZoomEye**: Cyberspace search engine

### 7. Archive Mining (run_archive_mining.py)
- **Wayback Machine**: Historical URL discovery
- **Google Cache**: Cached content analysis
- **JavaScript Analysis**: Secret extraction from JS files
- **Parameter Discovery**: URL parameter enumeration

### 8. Social Intelligence (run_social_intelligence.py)
- **Employee Discovery**: Employee information gathering
- **Tech Stack Analysis**: Technology stack identification
- **Cloud Assets**: Cloud service enumeration
- **Community Monitoring**: Forum and community analysis

## Output Structure

### Raw Outputs
```
/outputs/<target>/raw/
├── whois_<target>.json
├── certificate_transparency_<target>.json
├── repository_mining_<target>.json
├── search_dorking_<target>.json
├── breach_checking_<target>.json
├── infrastructure_exposure_<target>.json
├── archive_mining_<target>.json
└── social_intelligence_<target>.json
```

### Parsed Outputs
```
/outputs/<target>/parsed/
├── whois_<target>.txt
├── certificate_transparency_<target>.txt
├── repository_mining_<target>.txt
├── search_dorking_<target>.txt
├── breach_checking_<target>.txt
├── infrastructure_exposure_<target>.txt
├── archive_mining_<target>.txt
├── social_intelligence_<target>.txt
├── correlation_analysis.json
└── comprehensive_summary.json
```

## Data Models

### Enhanced OSINT Models
- **WHOISRecord**: Domain registration information
- **CertificateLog**: Certificate transparency logs
- **RepositoryFinding**: Public repository findings
- **SearchDorkResult**: Search engine dorking results
- **BreachRecord**: Data breach records
- **InfrastructureExposure**: Infrastructure exposure data
- **ArchiveFinding**: Archive and historical data
- **SocialMediaIntel**: Social media intelligence
- **CloudAsset**: Cloud asset discovery

### Framework Integration
All data models include `target_id` foreign keys for seamless integration with subsequent stages:
- **Active Reconnaissance**: Use discovered subdomains and endpoints
- **Vulnerability Scanning**: Target discovered services and technologies
- **Kill Chain Analysis**: Correlate with breach data and infrastructure
- **Reporting**: Comprehensive OSINT data for reports

## Monitoring & Alerting

### Continuous Monitoring
- **Scheduled Execution**: Configurable monitoring intervals
- **Discovery Tracking**: Track new discoveries over time
- **Performance Metrics**: Monitor execution performance
- **Historical Comparison**: Compare results across time periods

### Alert System
- **Email Alerts**: Configurable email notifications
- **Threshold Alerts**: Alert on discovery thresholds
- **Performance Alerts**: Alert on execution failures
- **Custom Alerts**: Extensible alert system

### Performance Tracking
- **Execution Metrics**: Success/failure rates, execution times
- **Discovery Metrics**: Total and new discoveries
- **Resource Usage**: CPU, memory, and network usage
- **API Usage**: Rate limiting and quota tracking

## Security Considerations

### Stealth Operations
- **No Direct Interaction**: All techniques are passive
- **Rate Limiting**: Respect API rate limits
- **User-Agent Rotation**: Rotate user agents for requests
- **Proxy Support**: Optional proxy configuration

### Legal Compliance
- **Scope Validation**: Ensure targets are in scope
- **Terms of Service**: Respect API terms of service
- **Data Privacy**: Handle sensitive data appropriately
- **Audit Logging**: Comprehensive audit trails

### API Key Management
- **Secure Storage**: Environment variable storage
- **Key Rotation**: Regular API key rotation
- **Access Control**: Minimal required permissions
- **Monitoring**: API key usage monitoring

## Troubleshooting

### Common Issues
1. **API Key Errors**: Verify API keys in .env file
2. **Rate Limiting**: Adjust rate limits in configuration
3. **Network Issues**: Check internet connectivity
4. **Permission Errors**: Verify file permissions

### Debug Mode
```bash
# Enable debug logging
export DEBUG=1
python run_passive_recon.py --target example.com
```

### Performance Optimization
- **Parallel Execution**: Adjust --parallel parameter
- **Rate Limiting**: Optimize --rate-limit for your APIs
- **Resource Limits**: Monitor system resources
- **Caching**: Enable result caching for repeated runs

## Contributing

### Adding New Tools
1. Create new runner in `runners/` directory
2. Follow established patterns and error handling
3. Add to `tools_to_run` list in main script
4. Update data models if needed
5. Add tests and documentation

### Testing
```bash
# Run unit tests
pytest tests/

# Run integration tests
pytest tests/integration/

# Run with coverage
pytest --cov=runners tests/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the configuration examples
- Consult the API documentation 