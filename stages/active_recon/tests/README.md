# Active Recon Test Suite

This directory contains comprehensive tests for the Active Reconnaissance stage of the Bug Hunting Framework.

## Test Structure

```
tests/
├── __init__.py                    # Test package initialization
├── conftest.py                    # Pytest configuration and shared fixtures
├── test_nmap_runner.py            # Unit tests for Nmap runner
├── test_naabu_runner.py           # Unit tests for Naabu runner
├── test_katana_runner.py          # Unit tests for Katana runner
├── test_feroxbuster_runner.py     # Unit tests for Feroxbuster runner
├── test_getjs_runner.py           # Unit tests for GetJS runner
├── test_linkfinder_runner.py      # Unit tests for LinkFinder runner
├── test_arjun_runner.py           # Unit tests for Arjun runner
├── test_webanalyze_runner.py      # Unit tests for WebAnalyze runner
├── test_eyewitness_runner.py      # Unit tests for EyeWitness runner
├── test_eyeballer_runner.py       # Unit tests for EyeBaller runner
├── test_active_recon_workflow.py  # Workflow tests for complete pipeline
├── test_integration.py            # Integration tests between components
├── test_runner_utils.py           # Tests for utility functions
├── run_tests.py                   # Test runner script
└── README.md                      # This documentation
```

## Test Categories

### 1. Unit Tests
- **Purpose**: Test individual components in isolation
- **Files**: `test_nmap_runner.py`, `test_naabu_runner.py`, `test_katana_runner.py`, `test_feroxbuster_runner.py`, `test_getjs_runner.py`, `test_linkfinder_runner.py`, `test_arjun_runner.py`, `test_webanalyze_runner.py`, `test_eyewitness_runner.py`, `test_eyeballer_runner.py`, `test_runner_utils.py`
- **Scope**: Individual runner functions, utility functions, data processing
- **Mocking**: Heavy use of mocks for external dependencies

### 2. Integration Tests
- **Purpose**: Test interaction between different components
- **Files**: `test_integration.py`
- **Scope**: Data flow between tools, API integration, file system operations
- **Mocking**: Moderate mocking, focus on component interaction

### 3. Workflow Tests
- **Purpose**: Test complete end-to-end workflows
- **Files**: `test_active_recon_workflow.py`
- **Scope**: Complete pipeline execution, error handling, data persistence
- **Mocking**: Light mocking, focus on real workflow scenarios

## Running Tests

### Prerequisites
```bash
# Install test dependencies
pip install pytest pytest-cov pytest-mock

# Ensure you're in the active_recon directory
cd stages/active_recon
```

### Running All Tests
```bash
# Using the test runner script
python tests/run_tests.py

# Using pytest directly
pytest tests/ -v

# With coverage
pytest tests/ --cov=runners --cov=utils --cov-report=html
```

### Running Specific Test Categories
```bash
# Run only unit tests
python tests/run_tests.py category unit

# Run only integration tests
python tests/run_tests.py category integration

# Run only workflow tests
python tests/run_tests.py category workflow

# Using pytest markers
pytest tests/ -m unit
pytest tests/ -m integration
pytest tests/ -m workflow
```

### Running Specific Test Modules
```bash
# Run specific module
python tests/run_tests.py module test_eyewitness_runner

# Using pytest
pytest tests/test_eyewitness_runner.py -v
```

### Running Individual Tests
```bash
# Run specific test class
pytest tests/test_eyewitness_runner.py::TestEyeWitnessRunner -v

# Run specific test method
pytest tests/test_eyewitness_runner.py::TestEyeWitnessRunner::test_run_eyewitness_success -v
```

## Test Coverage

### Nmap Runner Tests
- ✅ Successful port scanning
- ✅ Failed port scanning
- ✅ Timeout handling
- ✅ Port categorization
- ✅ Service detection
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### Naabu Runner Tests
- ✅ Successful port scanning
- ✅ Failed port scanning
- ✅ Timeout handling
- ✅ Port categorization
- ✅ Service detection
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### Katana Runner Tests
- ✅ Successful URL discovery
- ✅ Failed URL discovery
- ✅ Timeout handling
- ✅ URL categorization
- ✅ Parameter extraction
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### Feroxbuster Runner Tests
- ✅ Successful directory enumeration
- ✅ Failed directory enumeration
- ✅ Timeout handling
- ✅ URL categorization
- ✅ Status code analysis
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### GetJS Runner Tests
- ✅ Successful JavaScript file discovery
- ✅ Failed JavaScript file discovery
- ✅ Timeout handling
- ✅ File categorization
- ✅ URL extraction
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### LinkFinder Runner Tests
- ✅ Successful endpoint discovery
- ✅ Failed endpoint discovery
- ✅ Timeout handling
- ✅ Endpoint categorization
- ✅ Parameter extraction
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### Arjun Runner Tests
- ✅ Successful parameter discovery
- ✅ Failed parameter discovery
- ✅ Timeout handling
- ✅ Parameter categorization
- ✅ HTTP method analysis
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### WebAnalyze Runner Tests
- ✅ Successful technology detection
- ✅ Failed technology detection
- ✅ Timeout handling
- ✅ Technology categorization
- ✅ Version detection
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### EyeWitness Runner Tests
- ✅ Successful screenshot capture
- ✅ Failed screenshot capture
- ✅ Timeout handling
- ✅ Screenshot categorization
- ✅ Report generation
- ✅ Error handling for file operations
- ✅ Command construction validation
- ✅ Large target list handling
- ✅ Mixed protocol targets

### EyeBaller Runner Tests
- ✅ Successful screenshot analysis
- ✅ Failed analysis handling
- ✅ Timeout scenarios
- ✅ Findings categorization
- ✅ Analysis report generation
- ✅ Confidence threshold filtering
- ✅ Large screenshot set handling
- ✅ Mixed confidence findings

### Integration Tests
- ✅ Port scanning integration (nmap + naabu)
- ✅ Technology detection integration
- ✅ Directory enumeration integration
- ✅ JavaScript analysis integration
- ✅ Parameter discovery integration
- ✅ Screenshot workflow integration
- ✅ Data flow validation
- ✅ Error propagation testing

### Workflow Tests
- ✅ Complete workflow success scenario
- ✅ Workflow with tool failures
- ✅ Missing environment variables
- ✅ Network failure handling
- ✅ File system error handling
- ✅ Missing dependencies handling
- ✅ Live server extraction
- ✅ Endpoint collection and deduplication

### Utility Tests
- ✅ Raw data submission to database
- ✅ Parsed data submission to database
- ✅ API call success/failure scenarios
- ✅ Network error handling
- ✅ File system error handling
- ✅ Large file handling
- ✅ Complex data structure handling
- ✅ Unicode character handling
- ✅ Special character filename handling
- ✅ Concurrent API calls

## Test Data and Fixtures

### Sample Data Fixtures
The test suite includes comprehensive sample data for all components:

- **Targets and Subdomains**: Sample domain lists for testing
- **Port Scanning Results**: Mock nmap and naabu outputs
- **Technology Detection**: Sample webanalyze results
- **Directory Enumeration**: Mock katana and feroxbuster outputs
- **JavaScript Analysis**: Sample getJS and LinkFinder results
- **Parameter Discovery**: Mock Arjun results
- **Screenshot Data**: Sample EyeWitness and EyeBaller outputs

### Mock Responses
- **API Responses**: Mock backend API responses
- **Subprocess Results**: Mock tool execution results
- **File System**: Mock directory structures and files

## Test Configuration

### Pytest Configuration (`conftest.py`)
- **Fixtures**: Shared test fixtures for all test modules
- **Markers**: Custom pytest markers for test categorization
- **Test Classes**: Base classes for different test types
- **Sample Data**: Comprehensive sample data for testing

### Test Runner (`run_tests.py`)
- **Test Discovery**: Automatic discovery of test modules
- **Category Filtering**: Run tests by category (unit, integration, workflow)
- **Module Filtering**: Run specific test modules
- **Result Reporting**: Detailed test execution reports
- **JSON Output**: Save test results to JSON file

## Test Best Practices

### 1. Test Organization
- Each runner has its own test file
- Tests are organized by functionality
- Clear test method names describing the scenario
- Comprehensive docstrings for all test methods

### 2. Mocking Strategy
- **Unit Tests**: Heavy mocking of external dependencies
- **Integration Tests**: Moderate mocking, focus on component interaction
- **Workflow Tests**: Light mocking, focus on real scenarios

### 3. Error Testing
- Test both success and failure scenarios
- Test timeout conditions
- Test network failures
- Test file system errors
- Test invalid input data

### 4. Edge Cases
- Empty data structures
- Very large data sets
- Unicode characters
- Special characters in filenames
- Concurrent operations

### 5. Data Validation
- Verify data structure integrity
- Check data flow between components
- Validate API request/response formats
- Test data transformation accuracy

## Continuous Integration

### GitHub Actions Integration
The test suite is designed to integrate with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Active Recon Tests
  run: |
    cd stages/active_recon
    python tests/run_tests.py
    pytest tests/ --cov=runners --cov-report=xml
```

### Test Reporting
- **Console Output**: Detailed test execution information
- **JSON Reports**: Machine-readable test results
- **Coverage Reports**: Code coverage analysis
- **Failure Details**: Comprehensive error information

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure you're in the correct directory
   cd stages/active_recon
   
   # Add runners to Python path
   export PYTHONPATH="${PYTHONPATH}:$(pwd)/runners"
   ```

2. **Mock Import Issues**
   ```bash
   # Install required mocking libraries
   pip install pytest-mock unittest-mock
   ```

3. **File Permission Issues**
   ```bash
   # Ensure test files are executable
   chmod +x tests/*.py
   ```

### Debug Mode
```bash
# Run tests with debug output
pytest tests/ -v -s --tb=long

# Run specific test with debug
pytest tests/test_eyewitness_runner.py::TestEyeWitnessRunner::test_run_eyewitness_success -v -s
```

## Contributing

### Adding New Tests
1. Follow the existing test structure
2. Use appropriate test categories (unit, integration, workflow)
3. Add comprehensive docstrings
4. Include both success and failure scenarios
5. Test edge cases and error conditions

### Test Naming Conventions
- Test classes: `Test[ComponentName][TestType]`
- Test methods: `test_[scenario_description]`
- Use descriptive names that explain the test purpose

### Test Data
- Use fixtures for shared test data
- Create realistic sample data
- Include edge cases in sample data
- Document data structure and purpose

## Performance Considerations

### Test Execution Time
- Unit tests: < 1 second each
- Integration tests: < 5 seconds each
- Workflow tests: < 30 seconds each
- Total test suite: < 5 minutes

### Resource Usage
- Minimal disk I/O (use temporary directories)
- Efficient mocking (avoid heavy operations)
- Clean up resources after tests
- Use appropriate test scopes (function, class, session)

## Future Enhancements

### Planned Improvements
1. **Performance Tests**: Add performance benchmarking
2. **Load Tests**: Test with large datasets
3. **Security Tests**: Add security-focused test cases
4. **API Contract Tests**: Validate API contracts
5. **Visual Regression Tests**: For screenshot analysis

### Test Automation
1. **Auto-discovery**: Automatic test discovery for new runners
2. **Test Generation**: Generate tests from API specifications
3. **Coverage Tracking**: Track test coverage trends
4. **Performance Monitoring**: Monitor test execution performance

---

For questions or issues with the test suite, please refer to the main project documentation or create an issue in the project repository. 