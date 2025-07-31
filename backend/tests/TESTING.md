# Testing Documentation

## Overview

This document provides comprehensive guidance for testing the Bug Hunting Framework, including the testing infrastructure, test patterns, and best practices.

## Testing Infrastructure

### Test Configuration

The project uses a dedicated test configuration to ensure proper test isolation and consistent behavior:

- **Test Settings**: `api/test_settings.py` - Dedicated Django settings for testing
- **Pytest Configuration**: `pytest.ini` - Pytest configuration with proper test discovery
- **Test Fixtures**: `tests/conftest.py` - Shared test fixtures and utilities

### Key Testing Features

1. **In-Memory Database**: Uses SQLite in-memory database for fast, isolated tests
2. **ALLOWED_HOSTS Configuration**: Properly configured for HTTPX testing with 'testserver'
3. **JWT Authentication**: Test-specific JWT configuration for API testing
4. **Mock Infrastructure**: Comprehensive mocking for external dependencies
5. **Async Support**: Full async/await support for all tests

## Test Organization

### Test Structure

```
tests/
├── conftest.py              # Shared fixtures and configuration
├── api/                     # API endpoint tests
│   ├── test_execution_api.py
│   ├── test_targets_api.py
│   ├── test_workflow_api.py
│   └── ...
├── models/                  # Model tests
│   ├── test_target_model.py
│   ├── test_workflow_model.py
│   └── ...
├── integration/             # Integration tests
│   ├── test_workflow_integration.py
│   └── test_frontend_submission.py
└── ...
```

### Test Categories

1. **Unit Tests**: Test individual components in isolation
2. **Integration Tests**: Test component interactions
3. **API Tests**: Test HTTP endpoints and responses
4. **Model Tests**: Test data models and validation
5. **Service Tests**: Test business logic services

## Running Tests

### Basic Test Commands

```bash
# Run all tests
python -m pytest

# Run tests with coverage
python -m pytest --cov=core --cov-report=html

# Run specific test file
python -m pytest tests/api/test_targets_api.py

# Run specific test
python -m pytest tests/api/test_targets_api.py::TestTargetsAPI::test_create_target_success

# Run tests with verbose output
python -m pytest -v

# Run tests and stop after first failure
python -m pytest --maxfail=1
```

### Test Markers

The project uses pytest markers for test categorization:

- `@pytest.mark.asyncio`: Marks async tests
- `@pytest.mark.django_db`: Marks tests requiring database access
- `@pytest.mark.integration`: Marks integration tests
- `@pytest.mark.unit`: Marks unit tests

## Test Patterns

### API Testing Pattern

```python
@pytest.mark.asyncio
@pytest.mark.django_db
async def test_api_endpoint_success(self, api_client: AsyncClient, sample_data):
    """Test successful API endpoint."""
    # Arrange
    payload = {"key": "value"}
    
    # Act
    response = await api_client.post("/api/endpoint/", json=payload)
    
    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "data" in data
```

### Model Testing Pattern

```python
@pytest.mark.asyncio
async def test_model_creation(self, db_session):
    """Test model creation and validation."""
    # Arrange
    model_data = {"field": "value"}
    
    # Act
    model = Model(**model_data)
    db_session.add(model)
    await db_session.commit()
    await db_session.refresh(model)
    
    # Assert
    assert model.id is not None
    assert model.field == "value"
```

### Mock Testing Pattern

```python
@pytest.fixture(autouse=True)
def mock_external_service():
    with patch("module.external_service") as mock:
        mock.return_value = "mocked_response"
        yield mock

@pytest.mark.asyncio
async def test_with_mock(self, mock_external_service):
    """Test with mocked external service."""
    # Test implementation
    result = await service.call_external()
    assert result == "mocked_response"
    mock_external_service.assert_called_once()
```

## Test Fixtures

### Core Fixtures

- `api_client`: Async HTTP client for API testing
- `db_session`: Database session for model testing
- `sample_target`: Sample target data for testing
- `sample_workflow`: Sample workflow data for testing
- `mock_repositories`: Mocked repository layer for service testing

### Custom Fixtures

```python
@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "name": "Test User",
        "email": "test@example.com",
        "platform": "hackerone"
    }

@pytest.fixture
async def sample_user(db_session, sample_user_data):
    """Create a sample user in the database."""
    user = User(**sample_user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user
```

## Testing Best Practices

### 1. Test Isolation

- Each test should be independent and not rely on other tests
- Use database transactions that rollback after each test
- Mock external dependencies to avoid side effects

### 2. Test Naming

- Use descriptive test names that explain what is being tested
- Follow the pattern: `test_[method]_[scenario]_[expected_result]`
- Include the expected behavior in the test name

### 3. Test Structure

- Follow the Arrange-Act-Assert pattern
- Keep tests focused on a single behavior
- Use clear variable names and comments

### 4. Error Testing

- Test both success and failure scenarios
- Test edge cases and boundary conditions
- Verify error messages and status codes

### 5. Performance

- Use in-memory databases for fast test execution
- Mock expensive operations
- Avoid unnecessary database queries

## Common Issues and Solutions

### ALLOWED_HOSTS Issues

**Problem**: Django rejecting 'testserver' host header
**Solution**: Use `api/test_settings.py` with proper ALLOWED_HOSTS configuration

### Enum Serialization Issues

**Problem**: Case sensitivity mismatch between tests and implementation
**Solution**: Ensure consistent enum value handling in model serialization methods

### Database Connection Issues

**Problem**: Tests failing due to database configuration
**Solution**: Use in-memory SQLite database in test settings

### Async Test Issues

**Problem**: Async tests not running properly
**Solution**: Use `@pytest.mark.asyncio` decorator and proper async fixtures

## Test Coverage

### Coverage Goals

- **Unit Tests**: >90% coverage for core business logic
- **Integration Tests**: >80% coverage for component interactions
- **API Tests**: >95% coverage for all endpoints
- **Model Tests**: >95% coverage for all models

### Coverage Reporting

```bash
# Generate coverage report
python -m pytest --cov=core --cov-report=html

# View coverage report
open htmlcov/index.html
```

## Continuous Integration

### CI/CD Pipeline

The testing infrastructure is designed to work with CI/CD pipelines:

1. **Test Execution**: Automated test suite execution
2. **Coverage Reporting**: Automated coverage analysis
3. **Quality Gates**: Minimum coverage thresholds
4. **Test Results**: Detailed test result reporting

### Pre-commit Hooks

Consider implementing pre-commit hooks for:

- Running tests before commits
- Checking code coverage
- Running linting and formatting
- Validating test documentation

## Troubleshooting

### Common Test Failures

1. **ALLOWED_HOSTS Errors**: Check test settings configuration
2. **Database Errors**: Verify database configuration in test settings
3. **Import Errors**: Check test discovery configuration
4. **Async Errors**: Verify async test decorators and fixtures

### Debugging Tests

```bash
# Run tests with debug output
python -m pytest -v -s

# Run specific test with debug
python -m pytest tests/path/to/test.py::test_name -v -s

# Run tests with maximum verbosity
python -m pytest -vvv
```

## Future Improvements

### Planned Enhancements

1. **Performance Testing**: Add load testing and performance benchmarks
2. **Security Testing**: Add security-focused test cases
3. **End-to-End Testing**: Add comprehensive E2E test suite
4. **Visual Testing**: Add screenshot testing for UI components
5. **Contract Testing**: Add API contract testing

### Testing Tools

Consider adding these testing tools:

- **Locust**: Load testing framework
- **Playwright**: End-to-end testing
- **Pytest-benchmark**: Performance benchmarking
- **Pytest-mock**: Enhanced mocking capabilities
- **Pytest-cov**: Coverage reporting

## Conclusion

This testing infrastructure provides a solid foundation for ensuring code quality and reliability. The combination of unit tests, integration tests, and API tests ensures comprehensive coverage of the Bug Hunting Framework functionality.

For questions or issues with testing, refer to the troubleshooting section or consult the project documentation. 