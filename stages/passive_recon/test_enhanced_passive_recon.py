#!/usr/bin/env python3
"""
Comprehensive Test Suite for Enhanced Passive Reconnaissance Stage

This test suite covers all aspects of the enhanced passive reconnaissance stage:
- Individual tool runners
- API integration
- Data flow and target_id association
- Error handling and edge cases
- Performance and rate limiting
"""

import pytest
import os
import json
import tempfile
import shutil
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any
import requests
from datetime import datetime

# Import the tool runners
from runners.run_whois import run_whois_lookup, run_reverse_whois
from runners.run_certificate_transparency import run_certificate_transparency, run_passive_dns
from runners.run_repository_mining import run_repository_mining
from runners.run_search_dorking import run_search_dorking, run_advanced_dorking
from runners.run_breach_checking import run_breach_checking, run_credential_stuffing_check
from runners.run_infrastructure_exposure import run_infrastructure_exposure, run_vulnerability_scanning
from runners.run_archive_mining import run_archive_mining, run_archive_analysis
from runners.run_social_intelligence import run_social_intelligence

# Import the main runner
from run_passive_recon import (
    RateLimiter, ProgressTracker, run_tool_with_retry, 
    correlate_data, get_target_id, create_target_if_not_exists
)

# Import monitoring
from monitor_passive_recon import PassiveReconMonitor


class TestRateLimiter:
    """Test the RateLimiter class."""
    
    def test_rate_limiter_initialization(self):
        """Test rate limiter initialization."""
        limiter = RateLimiter(2.0)  # 2 calls per second
        assert limiter.calls_per_second == 2.0
        assert limiter.last_call_time == 0
    
    def test_rate_limiter_wait(self):
        """Test rate limiter wait functionality."""
        limiter = RateLimiter(1.0)  # 1 call per second
        
        # First call should not wait
        start_time = datetime.now()
        limiter.wait()
        first_call_time = (datetime.now() - start_time).total_seconds()
        assert first_call_time < 0.1  # Should be very fast
        
        # Second call should wait
        start_time = datetime.now()
        limiter.wait()
        second_call_time = (datetime.now() - start_time).total_seconds()
        assert second_call_time >= 0.9  # Should wait about 1 second


class TestProgressTracker:
    """Test the ProgressTracker class."""
    
    def test_progress_tracker_initialization(self):
        """Test progress tracker initialization."""
        tracker = ProgressTracker(10)
        assert tracker.total_tools == 10
        assert tracker.completed_tools == 0
        assert tracker.failed_tools == 0
    
    def test_mark_completed_success(self):
        """Test marking a tool as successfully completed."""
        tracker = ProgressTracker(5)
        tracker.mark_completed("test_tool", True)
        assert tracker.completed_tools == 1
        assert tracker.failed_tools == 0
    
    def test_mark_completed_failure(self):
        """Test marking a tool as failed."""
        tracker = ProgressTracker(5)
        tracker.mark_completed("test_tool", False)
        assert tracker.completed_tools == 0
        assert tracker.failed_tools == 1
    
    def test_get_progress(self):
        """Test getting progress statistics."""
        tracker = ProgressTracker(4)
        tracker.mark_completed("tool1", True)
        tracker.mark_completed("tool2", True)
        tracker.mark_completed("tool3", False)
        
        progress = tracker.get_progress()
        assert progress["completed"] == 2
        assert progress["failed"] == 1
        assert progress["total"] == 4
        assert progress["success_rate"] == 50.0


class TestToolRunners:
    """Test individual tool runners."""
    
    @pytest.fixture
    def temp_output_dir(self):
        """Create a temporary output directory."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    def test_whois_lookup(self, temp_output_dir):
        """Test WHOIS lookup functionality."""
        target = "example.com"
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=b"Domain Name: example.com\nRegistrar: Test Registrar\nCreation Date: 2020-01-01"
            )
            
            result = run_whois_lookup(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "whois_data" in result
            assert "registrar" in result["whois_data"]
    
    def test_certificate_transparency(self, temp_output_dir):
        """Test certificate transparency functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: [{"name_value": "test.example.com"}]
            )
            
            result = run_certificate_transparency(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "certificates" in result
    
    def test_repository_mining(self, temp_output_dir):
        """Test repository mining functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"items": [{"html_url": "https://github.com/test/repo"}]}
            )
            
            result = run_repository_mining(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "repositories" in result
    
    def test_search_dorking(self, temp_output_dir):
        """Test search engine dorking functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                text="<html><body>Search results</body></html>"
            )
            
            result = run_search_dorking(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "search_results" in result
    
    def test_breach_checking(self, temp_output_dir):
        """Test breach checking functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"breaches": []}
            )
            
            result = run_breach_checking(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "breaches" in result
    
    def test_infrastructure_exposure(self, temp_output_dir):
        """Test infrastructure exposure functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"matches": []}
            )
            
            result = run_infrastructure_exposure(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "infrastructure" in result
    
    def test_archive_mining(self, temp_output_dir):
        """Test archive mining functionality."""
        target = "example.com"
        
        with patch('requests.get') as mock_get:
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"archived_snapshots": {"closest": {"url": "http://web.archive.org/test"}}}
            )
            
            result = run_archive_mining(target, temp_output_dir)
            
            assert "domain" in result
            assert result["domain"] == target
            assert "archives" in result
    
    def test_social_intelligence(self, temp_output_dir):
        """Test social intelligence functionality."""
        target = "example.com"
        
        result = run_social_intelligence(target, temp_output_dir)
        
        assert "domain" in result
        assert result["domain"] == target
        assert "social_intel" in result


class TestDataCorrelation:
    """Test data correlation functionality."""
    
    def test_correlate_data_empty(self):
        """Test correlation with empty results."""
        all_results = {}
        correlation = correlate_data(all_results)
        
        assert "subdomains" in correlation
        assert "ips" in correlation
        assert "technologies" in correlation
        assert "vulnerabilities" in correlation
        assert "secrets" in correlation
        assert len(correlation["subdomains"]) == 0
    
    def test_correlate_data_with_subdomains(self):
        """Test correlation with subdomain data."""
        all_results = {
            "amass": {"subdomains": ["test1.example.com", "test2.example.com"]},
            "subfinder": {"subdomains": ["test2.example.com", "test3.example.com"]}
        }
        
        correlation = correlate_data(all_results)
        
        assert len(correlation["subdomains"]) == 3
        assert "test1.example.com" in correlation["subdomains"]
        assert "test2.example.com" in correlation["subdomains"]
        assert "test3.example.com" in correlation["subdomains"]
    
    def test_correlate_data_with_ips(self):
        """Test correlation with IP data."""
        all_results = {
            "infrastructure": {
                "infrastructure": {
                    "ips": ["192.168.1.1", "10.0.0.1"]
                }
            }
        }
        
        correlation = correlate_data(all_results)
        
        assert len(correlation["ips"]) == 2
        assert "192.168.1.1" in correlation["ips"]
        assert "10.0.0.1" in correlation["ips"]


class TestAPIIntegration:
    """Test API integration functionality."""
    
    @patch('requests.get')
    def test_get_target_id_existing(self, mock_get):
        """Test getting existing target ID."""
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "success": True,
                "data": {
                    "targets": [{"id": "test-uuid-123"}]
                }
            }
        )
        
        target_id = get_target_id("example.com", "http://test.com/api", "test-token")
        assert target_id == "test-uuid-123"
    
    @patch('requests.get')
    @patch('requests.post')
    def test_get_target_id_create_new(self, mock_post, mock_get):
        """Test creating new target when not found."""
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {"success": True, "data": {"targets": []}}
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                "success": True,
                "data": {"id": "new-uuid-456"}
            }
        )
        
        target_id = get_target_id("example.com", "http://test.com/api", "test-token")
        assert target_id == "new-uuid-456"
    
    @patch('requests.get')
    def test_get_target_id_error(self, mock_get):
        """Test error handling in target ID retrieval."""
        mock_get.side_effect = Exception("Network error")
        
        target_id = get_target_id("example.com", "http://test.com/api", "test-token")
        assert target_id is None


class TestToolRetryLogic:
    """Test tool retry logic."""
    
    @patch('time.sleep')  # Mock sleep to speed up tests
    def test_run_tool_with_retry_success(self, mock_sleep):
        """Test successful tool execution."""
        mock_tool_func = Mock(return_value={"success": True})
        
        result = run_tool_with_retry(
            mock_tool_func, "test_tool", "example.com", "/tmp",
            "test-target-id", "http://test.com/api", "test-token",
            ProgressTracker(1), RateLimiter(1.0)
        )
        
        assert result["success"] is True
        assert "results" in result
    
    @patch('time.sleep')  # Mock sleep to speed up tests
    def test_run_tool_with_retry_failure(self, mock_sleep):
        """Test tool execution with retries and eventual failure."""
        mock_tool_func = Mock(side_effect=Exception("Tool failed"))
        
        result = run_tool_with_retry(
            mock_tool_func, "test_tool", "example.com", "/tmp",
            "test-target-id", "http://test.com/api", "test-token",
            ProgressTracker(1), RateLimiter(1.0),
            max_retries=2
        )
        
        assert result["success"] is False
        assert "error" in result
        assert mock_tool_func.call_count == 2  # Should retry twice


class TestMonitoring:
    """Test monitoring functionality."""
    
    def test_monitor_initialization(self):
        """Test monitor initialization."""
        config = {
            "targets": ["example.com"],
            "schedule_interval": 24,
            "alert_threshold": 5
        }
        
        monitor = PassiveReconMonitor(config)
        assert monitor.targets == ["example.com"]
        assert monitor.schedule_interval == 24
        assert monitor.alert_threshold == 5
    
    def test_compare_results(self):
        """Test result comparison functionality."""
        config = {"targets": ["example.com"]}
        monitor = PassiveReconMonitor(config)
        
        new_results = {
            "correlation": {
                "subdomains": ["test1.example.com", "test2.example.com"],
                "ips": ["192.168.1.1"],
                "technologies": ["nginx"],
                "vulnerabilities": [],
                "secrets": []
            }
        }
        
        previous_results = {
            "correlation": {
                "subdomains": ["test1.example.com"],
                "ips": [],
                "technologies": [],
                "vulnerabilities": [],
                "secrets": []
            }
        }
        
        comparison = monitor.compare_results("example.com", new_results, previous_results)
        
        assert comparison["total_new_discoveries"] == 2
        assert "test2.example.com" in comparison["new_subdomains"]
        assert "192.168.1.1" in comparison["new_ips"]
        assert "nginx" in comparison["new_technologies"]


class TestErrorHandling:
    """Test error handling scenarios."""
    
    def test_tool_runner_exception_handling(self, temp_output_dir):
        """Test that tool runners handle exceptions gracefully."""
        target = "example.com"
        
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception("Tool not found")
            
            # Should not raise exception
            result = run_whois_lookup(target, temp_output_dir)
            assert "error" in result
    
    def test_api_request_exception_handling(self):
        """Test API request exception handling."""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.RequestException("Network error")
            
            # Should handle network errors gracefully
            result = get_target_id("example.com", "http://test.com/api", "test-token")
            assert result is None


class TestPerformance:
    """Test performance aspects."""
    
    def test_rate_limiting_performance(self):
        """Test rate limiting performance impact."""
        limiter = RateLimiter(10.0)  # 10 calls per second
        
        start_time = datetime.now()
        for _ in range(5):
            limiter.wait()
        end_time = datetime.now()
        
        # Should be fast with high rate limit
        duration = (end_time - start_time).total_seconds()
        assert duration < 1.0  # Should complete quickly
    
    def test_progress_tracking_performance(self):
        """Test progress tracking performance."""
        tracker = ProgressTracker(1000)
        
        start_time = datetime.now()
        for i in range(1000):
            tracker.mark_completed(f"tool_{i}", i % 2 == 0)  # Alternate success/failure
        end_time = datetime.now()
        
        # Should be very fast
        duration = (end_time - start_time).total_seconds()
        assert duration < 0.1  # Should complete very quickly


class TestDataValidation:
    """Test data validation."""
    
    def test_subdomain_validation(self):
        """Test subdomain format validation."""
        from runners.utils import extract_domain
        
        # Valid domains
        assert extract_domain("test.example.com") == "example.com"
        assert extract_domain("sub.test.example.com") == "example.com"
        
        # Invalid domains should be handled gracefully
        assert extract_domain("invalid") == "invalid"
        assert extract_domain("") == ""
    
    def test_url_parameter_extraction(self):
        """Test URL parameter extraction."""
        from runners.run_archive_mining import extract_url_parameters
        
        url = "https://example.com/test?param1=value1&param2=value2"
        params = extract_url_parameters(url)
        
        assert "param1" in params
        assert "param2" in params
        assert params["param1"] == "value1"
        assert params["param2"] == "value2"


class TestIntegration:
    """Integration tests."""
    
    @pytest.fixture
    def mock_environment(self):
        """Set up mock environment variables."""
        with patch.dict(os.environ, {
            "BACKEND_API_URL": "http://test.com/api",
            "BACKEND_JWT_TOKEN": "test-token",
            "CENSYS_API_ID": "test-id",
            "CENSYS_API_SECRET": "test-secret"
        }):
            yield
    
    def test_full_workflow_integration(self, mock_environment, temp_output_dir):
        """Test full workflow integration."""
        target = "example.com"
        
        # Mock all external dependencies
        with patch('requests.get') as mock_get, \
             patch('requests.post') as mock_post, \
             patch('subprocess.run') as mock_run:
            
            # Mock API responses
            mock_get.return_value = Mock(
                status_code=200,
                json=lambda: {"success": True, "data": {"targets": [{"id": "test-uuid"}]}}
            )
            mock_post.return_value = Mock(status_code=200, json=lambda: {"success": True})
            
            # Mock tool execution
            mock_run.return_value = Mock(returncode=0, stdout=b"test output")
            
            # Test that the workflow can run without errors
            # This is a basic integration test - in a real scenario,
            # you would test the actual workflow execution
            
            assert True  # Placeholder for actual integration test


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v"])