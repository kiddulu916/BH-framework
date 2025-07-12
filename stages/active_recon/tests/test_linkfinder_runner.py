#!/usr/bin/env python3
"""
Unit tests for LinkFinder runner
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import subprocess
from datetime import datetime

# Add parent directory to path to import the runner
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'runners'))

from run_linkfinder import run_linkfinder, parse_linkfinder_output


class TestLinkFinderRunner(unittest.TestCase):
    """Test cases for LinkFinder runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.linkfinder_dir = os.path.join(self.test_output_dir, "javascript_analysis")
        os.makedirs(self.linkfinder_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_linkfinder_success(self, mock_run):
        """Test successful LinkFinder execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
[+] Found: /api/v1/users
[+] Found: /admin/login
[+] Found: /api/v2/data
[+] Found: /dashboard
[+] Found: /config.js
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('endpoints', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['endpoints']), 5)
        self.assertEqual(result['summary']['total_endpoints'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_linkfinder_failure(self, mock_run):
        """Test LinkFinder execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_endpoints'], 0)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_linkfinder_timeout(self, mock_run):
        """Test LinkFinder execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="linkfinder", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_linkfinder_output_success(self):
        """Test successful LinkFinder output parsing"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /admin/login
[+] Found: /api/v2/data
[+] Found: /dashboard
[+] Found: /config.js
[+] Found: /api/v3/endpoint
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify parsing
        self.assertEqual(len(endpoints), 6)
        
        # Check specific endpoints
        expected_endpoints = [
            "/api/v1/users",
            "/admin/login",
            "/api/v2/data",
            "/dashboard",
            "/config.js",
            "/api/v3/endpoint"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_parse_linkfinder_output_empty(self):
        """Test LinkFinder output parsing with empty output"""
        linkfinder_output = ""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify no endpoints found
        self.assertEqual(len(endpoints), 0)

    def test_parse_linkfinder_output_invalid_format(self):
        """Test LinkFinder output parsing with invalid format"""
        invalid_output = "This is not valid linkfinder output"

        endpoints = parse_linkfinder_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(endpoints), 0)

    def test_parse_linkfinder_output_mixed_formats(self):
        """Test LinkFinder output parsing with mixed valid and invalid lines"""
        mixed_output = """
[+] Found: /api/v1/users
invalid line
[+] Found: /admin/login
another invalid line
[+] Found: /dashboard
"""

        endpoints = parse_linkfinder_output(mixed_output)

        # Should only parse valid endpoints
        self.assertEqual(len(endpoints), 3)
        
        # Check that valid endpoints are parsed
        expected_endpoints = [
            "/api/v1/users",
            "/admin/login",
            "/dashboard"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_command_construction(self):
        """Test that LinkFinder command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[+] Found: /api/v1/users"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('linkfinder', command)
        self.assertIn('-i', command)  # Input parameter
        self.assertIn('-o', command)  # Output parameter

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_linkfinder(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_linkfinder(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[+] Found: /api/v1/users"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_linkfinder(large_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 50)

    def test_mixed_http_https_targets(self):
        """Test handling of mixed HTTP and HTTPS targets"""
        mixed_targets = [
            "http://example.com",
            "https://test.example.com",
            "http://admin.example.com",
            "https://api.example.com"
        ]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[+] Found: /api/v1/users"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_linkfinder(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_endpoint_deduplication(self):
        """Test endpoint deduplication functionality"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /api/v1/users
[+] Found: /admin/login
[+] Found: /admin/login
[+] Found: /dashboard
[+] Found: /dashboard
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify duplicates are removed
        self.assertEqual(len(endpoints), 3)  # Should be unique endpoints
        
        # Check specific unique endpoints
        expected_endpoints = [
            "/api/v1/users",
            "/admin/login",
            "/dashboard"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_complex_endpoint_paths(self):
        """Test handling of complex endpoint paths"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /api/v2/data/endpoint
[+] Found: /admin/dashboard/settings
[+] Found: /api/v3/users/123/profile
[+] Found: /config/api/v1/settings
[+] Found: /public/assets/js/main.js
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify complex paths are parsed correctly
        self.assertEqual(len(endpoints), 6)
        
        # Check specific complex paths
        expected_endpoints = [
            "/api/v1/users",
            "/api/v2/data/endpoint",
            "/admin/dashboard/settings",
            "/api/v3/users/123/profile",
            "/config/api/v1/settings",
            "/public/assets/js/main.js"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_api_endpoint_categorization(self):
        """Test API endpoint categorization functionality"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /api/v2/data
[+] Found: /api/v3/endpoint
[+] Found: /admin/login
[+] Found: /dashboard
[+] Found: /config.js
[+] Found: /api/v1/settings
[+] Found: /api/v2/config
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify API endpoint categorization
        api_endpoints = [endpoint for endpoint in endpoints if endpoint.startswith('/api/')]
        admin_endpoints = [endpoint for endpoint in endpoints if 'admin' in endpoint]
        dashboard_endpoints = [endpoint for endpoint in endpoints if 'dashboard' in endpoint]
        config_endpoints = [endpoint for endpoint in endpoints if 'config' in endpoint]

        self.assertEqual(len(api_endpoints), 5)
        self.assertEqual(len(admin_endpoints), 1)
        self.assertEqual(len(dashboard_endpoints), 1)
        self.assertEqual(len(config_endpoints), 2)

    def test_special_characters_in_paths(self):
        """Test handling of endpoints with special characters"""
        linkfinder_output = """
[+] Found: /api/v1/users with spaces
[+] Found: /admin/login%20page
[+] Found: /dashboard/settings-v2
[+] Found: /config/api_v1_settings
[+] Found: /api/v2/data/endpoint_123
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify special characters are handled
        self.assertEqual(len(endpoints), 5)
        
        # Check specific endpoints with special characters
        expected_endpoints = [
            "/api/v1/users with spaces",
            "/admin/login%20page",
            "/dashboard/settings-v2",
            "/config/api_v1_settings",
            "/api/v2/data/endpoint_123"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        linkfinder_output = """

[+] Found: /api/v1/users

[+] Found: /admin/login

[+] Found: /dashboard

"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(endpoints), 3)
        
        # Check specific endpoints
        expected_endpoints = [
            "/api/v1/users",
            "/admin/login",
            "/dashboard"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_very_long_endpoint_paths(self):
        """Test handling of very long endpoint paths"""
        long_path = "/" + "a" * 1000 + "/endpoint"
        linkfinder_output = f"""
[+] Found: /api/v1/users
[+] Found: {long_path}
[+] Found: /dashboard
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify very long paths are handled
        self.assertEqual(len(endpoints), 3)
        
        # Check specific endpoints
        expected_endpoints = [
            "/api/v1/users",
            long_path,
            "/dashboard"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_invalid_endpoint_filtering(self):
        """Test filtering of invalid endpoints"""
        linkfinder_output = """
[+] Found: /api/v1/users
not a valid line
[+] Found: /admin/login
also not valid
[+] Found: ftp://example.com/file
[+] Found: /dashboard
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Should only parse valid endpoints
        self.assertEqual(len(endpoints), 3)
        
        # Check that only valid endpoints are parsed
        expected_endpoints = [
            "/api/v1/users",
            "/admin/login",
            "/dashboard"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)

    def test_endpoint_parameter_handling(self):
        """Test handling of endpoints with parameters"""
        linkfinder_output = """
[+] Found: /api/v1/users?id=123
[+] Found: /api/v2/data?format=json
[+] Found: /search?q=test&page=1
[+] Found: /dashboard?user=admin&token=abc123
[+] Found: /api/v3/endpoint?param1=value1&param2=value2
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify endpoints with parameters are handled
        self.assertEqual(len(endpoints), 5)
        
        # Check specific endpoints with parameters
        expected_endpoints = [
            "/api/v1/users?id=123",
            "/api/v2/data?format=json",
            "/search?q=test&page=1",
            "/dashboard?user=admin&token=abc123",
            "/api/v3/endpoint?param1=value1&param2=value2"
        ]
        
        for endpoint in expected_endpoints:
            self.assertIn(endpoint, endpoints)


class TestLinkFinderIntegration(unittest.TestCase):
    """Integration tests for LinkFinder runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.linkfinder_dir = os.path.join(self.test_output_dir, "javascript_analysis")
        os.makedirs(self.linkfinder_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete LinkFinder workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.linkfinder_dir, "linkfinder_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock linkfinder output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
[+] Found: /api/v1/users
[+] Found: /admin/login
[+] Found: /api/v2/data
[+] Found: /dashboard
[+] Found: /config.js
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock linkfinder output content"
                
                result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['endpoints']), 5)
        self.assertEqual(result['summary']['total_endpoints'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different types of endpoints are found
        api_endpoints = [endpoint for endpoint in result['endpoints'] if endpoint.startswith('/api/')]
        admin_endpoints = [endpoint for endpoint in result['endpoints'] if 'admin' in endpoint]
        dashboard_endpoints = [endpoint for endpoint in result['endpoints'] if 'dashboard' in endpoint]

        self.assertEqual(len(api_endpoints), 2)
        self.assertEqual(len(admin_endpoints), 1)
        self.assertEqual(len(dashboard_endpoints), 1)

    def test_output_format_integration(self):
        """Test output format integration"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /admin/login
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify output format is consistent
        self.assertIsInstance(endpoints, list)
        
        for endpoint in endpoints:
            self.assertIsInstance(endpoint, str)
            self.assertTrue(endpoint.startswith('/'))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "linkfinder", stderr="First failure"),
                MagicMock(returncode=0, stdout="[+] Found: /api/v1/users", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_linkfinder(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_endpoint_analysis_integration(self):
        """Test endpoint analysis integration"""
        linkfinder_output = """
[+] Found: /api/v1/users
[+] Found: /api/v2/data
[+] Found: /api/v3/endpoint
[+] Found: /admin/login
[+] Found: /admin/dashboard
[+] Found: /dashboard
[+] Found: /config/api/v1/settings
[+] Found: /public/assets/js/main.js
"""

        endpoints = parse_linkfinder_output(linkfinder_output)

        # Verify different endpoint categories are found
        api_endpoints = [endpoint for endpoint in endpoints if endpoint.startswith('/api/')]
        admin_endpoints = [endpoint for endpoint in endpoints if 'admin' in endpoint]
        dashboard_endpoints = [endpoint for endpoint in endpoints if 'dashboard' in endpoint]
        config_endpoints = [endpoint for endpoint in endpoints if 'config' in endpoint]
        public_endpoints = [endpoint for endpoint in endpoints if 'public' in endpoint]

        self.assertEqual(len(api_endpoints), 3)
        self.assertEqual(len(admin_endpoints), 2)
        self.assertEqual(len(dashboard_endpoints), 2)
        self.assertEqual(len(config_endpoints), 1)
        self.assertEqual(len(public_endpoints), 1)


if __name__ == '__main__':
    unittest.main() 