#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for Active Recon tests
"""

import pytest
import tempfile
import os
import shutil
import json
from unittest.mock import MagicMock, patch
from datetime import datetime


@pytest.fixture(scope="session")
def test_output_dir():
    """Create a temporary output directory for all tests"""
    temp_dir = tempfile.mkdtemp(prefix="active_recon_tests_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(scope="function")
def temp_dir():
    """Create a temporary directory for individual tests"""
    temp_dir = tempfile.mkdtemp(prefix="test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def sample_targets():
    """Sample target domains for testing"""
    return ["example.com", "test.example.com", "admin.example.com"]


@pytest.fixture
def sample_subdomains():
    """Sample subdomains for testing"""
    return [
        "www.example.com",
        "api.example.com", 
        "admin.example.com",
        "dev.example.com",
        "staging.example.com"
    ]


@pytest.fixture
def sample_nmap_results():
    """Sample nmap scan results"""
    return {
        "success": True,
        "hosts": [
            {
                "hostname": "example.com",
                "ip": "93.184.216.34",
                "ports": [
                    {"port": 80, "service": "http", "state": "open"},
                    {"port": 443, "service": "https", "state": "open"},
                    {"port": 22, "service": "ssh", "state": "open"}
                ],
                "os_info": {"os": "Linux", "version": "4.19.0"}
            },
            {
                "hostname": "www.example.com",
                "ip": "93.184.216.34",
                "ports": [
                    {"port": 80, "service": "http", "state": "open"},
                    {"port": 443, "service": "https", "state": "open"}
                ],
                "os_info": {"os": "Linux", "version": "4.19.0"}
            }
        ],
        "summary": {
            "total_hosts": 2,
            "total_ports": 5,
            "open_ports": [22, 80, 443],
            "web_ports": [80, 443]
        }
    }


@pytest.fixture
def sample_naabu_results():
    """Sample naabu scan results"""
    return {
        "success": True,
        "hosts": [
            {
                "hostname": "example.com",
                "ip": "93.184.216.34",
                "ports": [
                    {"port": 80, "service": "http"},
                    {"port": 443, "service": "https"},
                    {"port": 8080, "service": "http-proxy"}
                ]
            },
            {
                "hostname": "api.example.com",
                "ip": "93.184.216.35",
                "ports": [
                    {"port": 80, "service": "http"},
                    {"port": 443, "service": "https"}
                ]
            }
        ],
        "summary": {
            "total_hosts": 2,
            "total_ports": 5,
            "web_ports": [80, 443, 8080]
        }
    }


@pytest.fixture
def sample_webanalyze_results():
    """Sample webanalyze results"""
    return {
        "success": True,
        "technologies": [
            {
                "name": "Apache",
                "version": "2.4.41",
                "hostname": "example.com",
                "port": 80,
                "confidence": 100
            },
            {
                "name": "PHP",
                "version": "7.4.3",
                "hostname": "example.com",
                "port": 80,
                "confidence": 100
            },
            {
                "name": "jQuery",
                "version": "3.5.1",
                "hostname": "example.com",
                "port": 80,
                "confidence": 100
            },
            {
                "name": "Bootstrap",
                "version": "4.5.0",
                "hostname": "example.com",
                "port": 443,
                "confidence": 100
            }
        ],
        "technology_mapping": {
            "example.com": {
                "80": ["Apache", "PHP", "jQuery"],
                "443": ["Apache", "Bootstrap"]
            }
        },
        "summary": {
            "total_technologies": 4,
            "unique_technologies": ["Apache", "PHP", "jQuery", "Bootstrap"]
        }
    }


@pytest.fixture
def sample_directory_enumeration_results():
    """Sample directory enumeration results"""
    return {
        "success": True,
        "urls_found": [
            {
                "url": "http://example.com/",
                "status_code": 200,
                "method": "GET",
                "content_length": 1234
            },
            {
                "url": "http://example.com/admin",
                "status_code": 403,
                "method": "GET",
                "content_length": 567
            },
            {
                "url": "http://example.com/login",
                "status_code": 200,
                "method": "GET",
                "content_length": 890
            },
            {
                "url": "http://example.com/robots.txt",
                "status_code": 200,
                "method": "GET",
                "content_length": 123
            },
            {
                "url": "http://example.com/sitemap.xml",
                "status_code": 200,
                "method": "GET",
                "content_length": 456
            }
        ],
        "summary": {
            "total_urls": 5,
            "status_codes": {"200": 4, "403": 1},
            "interesting_urls": ["/admin", "/login"]
        }
    }


@pytest.fixture
def sample_javascript_results():
    """Sample JavaScript analysis results"""
    return {
        "success": True,
        "js_files_found": [
            {
                "file_path": "http://example.com/app.js",
                "endpoints": ["/api/users", "/api/admin", "/api/config"],
                "file_size": 1024,
                "content_type": "application/javascript"
            },
            {
                "file_path": "http://example.com/admin.js",
                "endpoints": ["/admin/dashboard", "/admin/users", "/admin/settings"],
                "file_size": 2048,
                "content_type": "application/javascript"
            }
        ],
        "all_endpoints": [
            {"endpoint": "/api/users", "confidence": 0.8, "source": "app.js"},
            {"endpoint": "/api/admin", "confidence": 0.9, "source": "app.js"},
            {"endpoint": "/api/config", "confidence": 0.7, "source": "app.js"},
            {"endpoint": "/admin/dashboard", "confidence": 0.85, "source": "admin.js"},
            {"endpoint": "/admin/users", "confidence": 0.9, "source": "admin.js"},
            {"endpoint": "/admin/settings", "confidence": 0.75, "source": "admin.js"}
        ],
        "summary": {
            "total_js_files": 2,
            "total_endpoints": 6,
            "unique_endpoints": 6
        }
    }


@pytest.fixture
def sample_parameter_results():
    """Sample parameter discovery results"""
    return {
        "success": True,
        "endpoints_found": [
            {
                "url": "http://example.com/api/users",
                "method": "GET",
                "parameters": ["id", "name", "email", "page", "limit"],
                "parameter_count": 5
            },
            {
                "url": "http://example.com/api/admin",
                "method": "GET",
                "parameters": ["user", "action", "token", "admin_id"],
                "parameter_count": 4
            },
            {
                "url": "http://example.com/search",
                "method": "GET",
                "parameters": ["q", "category", "sort", "filter"],
                "parameter_count": 4
            }
        ],
        "unique_parameters": [
            "id", "name", "email", "page", "limit", "user", "action", "token", 
            "admin_id", "q", "category", "sort", "filter"
        ],
        "summary": {
            "total_endpoints": 3,
            "total_parameters": 13,
            "unique_parameters": 13,
            "parameter_categories": {
                "authentication": ["token", "user"],
                "pagination": ["page", "limit"],
                "search": ["q", "category", "sort", "filter"],
                "identification": ["id", "name", "email", "admin_id"],
                "actions": ["action"]
            }
        }
    }


@pytest.fixture
def sample_screenshot_results():
    """Sample screenshot capture results"""
    return {
        "success": True,
        "screenshots": [
            "/path/to/example_com.png",
            "/path/to/www_example_com.png",
            "/path/to/api_example_com.png"
        ],
        "screenshot_details": [
            {
                "filename": "example_com.png",
                "hostname": "example.com",
                "file_path": "/path/to/example_com.png",
                "file_size": 102400,
                "capture_time": "2024-01-01T12:00:00Z"
            },
            {
                "filename": "www_example_com.png",
                "hostname": "www.example.com",
                "file_path": "/path/to/www_example_com.png",
                "file_size": 153600,
                "capture_time": "2024-01-01T12:01:00Z"
            },
            {
                "filename": "api_example_com.png",
                "hostname": "api.example.com",
                "file_path": "/path/to/api_example_com.png",
                "file_size": 128000,
                "capture_time": "2024-01-01T12:02:00Z"
            }
        ],
        "summary": {
            "total_targets": 3,
            "successful_screenshots": 3,
            "failed_screenshots": 0,
            "total_file_size": 384000
        }
    }


@pytest.fixture
def sample_eyeballer_results():
    """Sample EyeBaller analysis results"""
    return {
        "success": True,
        "predictions": [
            {
                "filename": "example_com.png",
                "category": "login",
                "confidence": 0.85,
                "file_path": "/path/to/example_com.png",
                "interesting": True
            },
            {
                "filename": "www_example_com.png",
                "category": "dashboard",
                "confidence": 0.92,
                "file_path": "/path/to/www_example_com.png",
                "interesting": True
            },
            {
                "filename": "api_example_com.png",
                "category": "error",
                "confidence": 0.78,
                "file_path": "/path/to/api_example_com.png",
                "interesting": False
            }
        ],
        "interesting_findings": [
            {
                "filename": "example_com.png",
                "category": "login",
                "confidence": 0.85,
                "interesting": True,
                "description": "Login page detected"
            },
            {
                "filename": "www_example_com.png",
                "category": "dashboard",
                "confidence": 0.92,
                "interesting": True,
                "description": "Admin dashboard detected"
            }
        ],
        "summary": {
            "analyzed_screenshots": 3,
            "interesting_findings": 2,
            "categories_found": ["login", "dashboard", "error"],
            "high_confidence_findings": 2
        }
    }


@pytest.fixture
def mock_api_responses():
    """Mock API responses for testing"""
    return {
        "target_lookup": {
            "status_code": 200,
            "json": {
                "success": True,
                "data": {
                    "targets": [{"id": "test-target-id", "value": "example.com"}]
                }
            }
        },
        "result_submission": {
            "status_code": 200,
            "json": {"success": True, "message": "Results saved successfully"}
        },
        "passive_recon_results": {
            "status_code": 200,
            "json": {
                "success": True,
                "data": {
                    "results": [
                        {
                            "tool_name": "sublist3r",
                            "data": {"subdomains": ["www.example.com", "api.example.com"]}
                        },
                        {
                            "tool_name": "amass",
                            "data": {"subdomains": ["admin.example.com", "dev.example.com"]}
                        }
                    ]
                }
            }
        }
    }


@pytest.fixture
def mock_subprocess_results():
    """Mock subprocess results for testing"""
    return {
        "success": MagicMock(returncode=0, stdout="Success output", stderr=""),
        "failure": MagicMock(returncode=1, stdout="", stderr="Error output"),
        "timeout": MagicMock(side_effect=Exception("Timeout")),
        "file_not_found": MagicMock(side_effect=FileNotFoundError("Command not found"))
    }


@pytest.fixture
def sample_workflow_data():
    """Sample complete workflow data for integration testing"""
    return {
        "target": "example.com",
        "stage": "active_recon",
        "passive_recon_subdomains": [
            "www.example.com",
            "api.example.com",
            "admin.example.com",
            "dev.example.com"
        ],
        "port_scanning": {
            "live_servers": ["www.example.com", "api.example.com", "admin.example.com"],
            "dead_servers": ["dev.example.com"]
        },
        "technology_detection": {
            "technologies": ["Apache", "PHP", "jQuery", "Bootstrap"],
            "technology_mapping": {
                "www.example.com": ["Apache", "PHP", "jQuery"],
                "api.example.com": ["Apache", "PHP"],
                "admin.example.com": ["Apache", "Bootstrap"]
            }
        },
        "directory_enumeration": {
            "urls_found": [
                "http://www.example.com/",
                "http://www.example.com/admin",
                "http://api.example.com/users",
                "http://admin.example.com/login"
            ]
        },
        "javascript_analysis": {
            "js_files": [
                "http://www.example.com/app.js",
                "http://api.example.com/api.js"
            ],
            "endpoints": [
                "/api/users",
                "/api/admin",
                "/api/config"
            ]
        },
        "parameter_discovery": {
            "endpoints_with_params": [
                {
                    "url": "http://api.example.com/users",
                    "parameters": ["id", "name", "email"]
                },
                {
                    "url": "http://api.example.com/admin",
                    "parameters": ["user", "action", "token"]
                }
            ]
        },
        "screenshot_capture": {
            "screenshots": [
                "/path/to/www_example_com.png",
                "/path/to/api_example_com.png",
                "/path/to/admin_example_com.png"
            ]
        },
        "screenshot_analysis": {
            "interesting_findings": [
                {
                    "filename": "www_example_com.png",
                    "category": "login",
                    "confidence": 0.85,
                    "interesting": True
                },
                {
                    "filename": "admin_example_com.png",
                    "category": "admin",
                    "confidence": 0.92,
                    "interesting": True
                }
            ]
        }
    }


@pytest.fixture
def mock_file_system(temp_dir):
    """Mock file system structure for testing"""
    # Create directory structure
    os.makedirs(os.path.join(temp_dir, "enumeration"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "enumeration", "eyewitness"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "enumeration", "eyeballer"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "port_scanning"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "technology_detection"), exist_ok=True)
    os.makedirs(os.path.join(temp_dir, "reports"), exist_ok=True)
    
    # Create sample files
    with open(os.path.join(temp_dir, "enumeration", "eyewitness", "example_com.png"), "w") as f:
        f.write("mock screenshot content")
    
    with open(os.path.join(temp_dir, "enumeration", "eyewitness", "www_example_com.png"), "w") as f:
        f.write("mock screenshot content")
    
    with open(os.path.join(temp_dir, "reports", "active_recon_summary.json"), "w") as f:
        json.dump({"test": "data"}, f)
    
    return temp_dir


# Pytest configuration
def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "workflow: mark test as a workflow test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Mark tests based on their names
        if "test_eyewitness" in item.name or "test_eyeballer" in item.name or "test_runner_utils" in item.name:
            item.add_marker(pytest.mark.unit)
        elif "test_integration" in item.name:
            item.add_marker(pytest.mark.integration)
        elif "test_workflow" in item.name:
            item.add_marker(pytest.mark.workflow)
        
        # Mark slow tests
        if "large" in item.name or "concurrent" in item.name:
            item.add_marker(pytest.mark.slow)


# Custom test classes for different test types
class UnitTestBase:
    """Base class for unit tests"""
    pass


class IntegrationTestBase:
    """Base class for integration tests"""
    pass


class WorkflowTestBase:
    """Base class for workflow tests"""
    pass 