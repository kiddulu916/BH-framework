# Integration Tests for Bug Hunting Framework

This directory contains comprehensive integration tests for the Bug Hunting Framework, validating complete workflow execution, API integration, and system reliability.

## Overview

The integration tests validate that all components of the framework work together seamlessly, from individual stage execution to complete end-to-end workflows.

## Test Categories

### 1. Complete Workflow Integration Tests
- **File**: `test_complete_workflow_integration.py`
- **Purpose**: Test complete workflows from target creation to final report delivery
- **Coverage**: All 6 stages (passive_recon → active_recon → vuln_scan → vuln_test → kill_chain → comprehensive_reporting)

### 2. Docker Compose Integration Tests
- **File**: `test_docker_compose_integration.py`
- **Purpose**: Validate containerized environment and service orchestration
- **Coverage**: Service startup, health checks, networking, data persistence

## Test Scenarios

### Complete Workflow Tests

#### `test_complete_workflow_lifecycle`
- Creates target and workflow
- Executes all 6 stages sequentially
- Validates data flow between stages
- Verifies final report generation

#### `test_data_flow_between_stages`
- Validates data consistency across stages
- Tests data transformation and enrichment
- Ensures proper data handoff between stages

#### `test_error_handling_and_recovery`
- Tests invalid input handling
- Validates error recovery mechanisms
- Ensures graceful failure handling

#### `test_concurrent_workflow_execution`
- Tests multiple workflows running simultaneously
- Validates resource management
- Ensures no conflicts between workflows

### API Integration Tests

#### `test_api_endpoint_integration`
- Tests all API endpoints work together
- Validates CRUD operations
- Ensures proper error responses

#### `test_authentication_and_authorization`
- Tests JWT token management
- Validates access controls
- Ensures security compliance

### Performance Tests

#### `test_system_performance`
- Tests API response times
- Validates resource usage
- Ensures performance requirements

#### `test_concurrent_api_requests`
- Tests system under load
- Validates scalability
- Ensures stability under stress

### Docker Compose Tests

#### `test_service_startup_and_health_checks`
- Validates service startup order
- Tests health check mechanisms
- Ensures service dependencies

#### `test_network_connectivity`
- Tests inter-service communication
- Validates port mappings
- Ensures network isolation

#### `test_volume_mounting_and_data_persistence`
- Tests data persistence across restarts
- Validates volume configurations
- Ensures data integrity

## Prerequisites

### System Requirements
- Python 3.11+
- Docker and Docker Compose
- PostgreSQL (for local testing)
- 8GB+ RAM (for concurrent testing)

### Dependencies
Install the required dependencies:

```bash
cd tests/integration
pip install -r requirements.txt
```

### Environment Setup
1. **Start Docker services**:
   ```bash
   cd /path/to/bug-hunting-framework
   docker-compose up -d
   ```

2. **Set environment variables**:
   ```bash
   export TESTING=true
   export DEBUG=true
   export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/bug_hunting_framework_test
   export SECRET_KEY=test-secret-key-for-integration-tests
   export JWT_SECRET=test-jwt-secret-for-integration-tests
   ```

## Running Tests

### Quick Validation
Run a quick validation of core components:

```bash
python run_integration_tests.py --quick
```

### Complete Integration Tests
Run all integration tests:

```bash
python run_integration_tests.py
```

### Specific Test Categories
Run tests for specific categories:

```bash
# Complete workflow tests only
python run_integration_tests.py --category complete_workflow

# API integration tests only
python run_integration_tests.py --category api_integration

# Performance tests only
python run_integration_tests.py --category performance
```

### Using Pytest Directly
Run specific test files or functions:

```bash
# Run all integration tests
pytest

# Run specific test file
pytest test_complete_workflow_integration.py

# Run specific test function
pytest test_complete_workflow_integration.py::TestCompleteWorkflowIntegration::test_complete_workflow_lifecycle

# Run with verbose output
pytest -v

# Run with coverage
pytest --cov=backend --cov=stages --cov-report=html
```

### Docker Compose Tests
Run Docker Compose integration tests:

```bash
# Ensure Docker services are running
docker-compose up -d

# Run Docker Compose tests
pytest test_docker_compose_integration.py -v
```

## Test Configuration

### Pytest Configuration
The `pytest.ini` file contains comprehensive configuration for:
- Test discovery and execution
- Coverage reporting
- Logging configuration
- Timeout settings
- Environment variables

### Environment Variables
Key environment variables for testing:

```bash
TESTING=true                    # Enable test mode
DEBUG=true                      # Enable debug mode
DATABASE_URL=...               # Test database URL
SECRET_KEY=...                 # Test secret key
JWT_SECRET=...                 # Test JWT secret
```

## Test Data

### Test Targets
Integration tests use predefined test targets:
- `test-integration.com` - Complete workflow testing
- `dataflow-test.com` - Data flow validation
- `error-test.com` - Error handling testing
- `concurrent-test-*.com` - Concurrent execution testing

### Test Workflows
Test workflows are configured with:
- Minimal tool sets for faster execution
- Reduced timeouts for quicker feedback
- Test mode enabled for safety

## Expected Results

### Success Criteria
- All tests pass with 80%+ coverage
- Complete workflows execute successfully
- API endpoints respond correctly
- Docker services start and communicate properly
- Data flows correctly between stages

### Performance Benchmarks
- API response time < 1 second
- Workflow execution time < 10 minutes
- Memory usage < 80% of limits
- CPU usage < 80% of limits

## Troubleshooting

### Common Issues

#### Docker Services Not Starting
```bash
# Check Docker status
docker-compose ps

# View service logs
docker-compose logs

# Restart services
docker-compose down && docker-compose up -d
```

#### Database Connection Issues
```bash
# Check database status
docker-compose exec db pg_isready -U postgres

# Reset database
docker-compose down -v && docker-compose up -d
```

#### Test Timeouts
```bash
# Increase timeout for slow tests
pytest --timeout=600

# Run tests individually
pytest test_complete_workflow_integration.py::TestCompleteWorkflowIntegration::test_complete_workflow_lifecycle
```

#### Memory Issues
```bash
# Check available memory
free -h

# Reduce concurrent tests
pytest -n 1

# Increase Docker memory limits
docker-compose down
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_BUILDKIT=1
docker-compose up -d
```

### Debug Mode
Enable debug mode for detailed logging:

```bash
python run_integration_tests.py --verbose
```

## Test Reports

### Generated Reports
After running tests, the following reports are generated:

1. **HTML Coverage Report**: `htmlcov/index.html`
2. **XML Coverage Report**: `coverage.xml`
3. **HTML Test Report**: `integration_test_report.html`
4. **JSON Test Results**: `integration_test_results.json`
5. **Test Logs**: `integration_tests.log`

### Report Analysis
- **Coverage Report**: Shows code coverage by module and function
- **Test Report**: Shows test results with pass/fail status
- **Performance Report**: Shows execution times and resource usage
- **Error Report**: Shows detailed error information for failed tests

## Continuous Integration

### CI/CD Integration
These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Integration Tests
  run: |
    cd tests/integration
    pip install -r requirements.txt
    python run_integration_tests.py
```

### Automated Testing
For automated testing, use:

```bash
# Non-interactive mode
python run_integration_tests.py --no-color

# Exit on first failure
pytest --maxfail=1

# Generate reports for CI
pytest --junitxml=test-results.xml --cov-report=xml
```

## Contributing

### Adding New Tests
When adding new integration tests:

1. **Follow naming conventions**: `test_*.py` for test files
2. **Use appropriate markers**: `@pytest.mark.integration`
3. **Add to test categories**: Update `run_integration_tests.py`
4. **Update documentation**: Add test description to this README

### Test Guidelines
- Keep tests independent and isolated
- Use realistic test data
- Clean up after tests
- Handle errors gracefully
- Provide clear error messages

## Support

For issues with integration tests:

1. Check the troubleshooting section
2. Review test logs in `integration_tests.log`
3. Verify environment setup
4. Check Docker service status
5. Review test configuration

## License

These integration tests are part of the Bug Hunting Framework and follow the same license terms. 