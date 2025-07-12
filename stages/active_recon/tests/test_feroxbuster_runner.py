#!/usr/bin/env python3
"""
Unit tests for Feroxbuster runner
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import subprocess
from typing import List, Dict, Any
from datetime import datetime

# Add parent directory to path to import the runner
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'runners'))

from run_feroxbuster import run_feroxbuster, parse_feroxbuster_output


class TestFeroxbusterRunner(unittest.TestCase):
    """Test cases for Feroxbuster runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.feroxbuster_dir = os.path.join(self.test_output_dir, "directory_enumeration")
        os.makedirs(self.feroxbuster_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_feroxbuster_success(self, mock_run):
        """Test successful Feroxbuster execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
200      GET        http://example.com/admin
200      GET        http://example.com/login
404      GET        http://example.com/notfound
200      GET        https://test.example.com/dashboard
403      GET        https://test.example.com/private
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('urls', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['urls']), 5)
        self.assertEqual(result['summary']['total_urls'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_feroxbuster_failure(self, mock_run):
        """Test Feroxbuster execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_urls'], 0)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_feroxbuster_timeout(self, mock_run):
        """Test Feroxbuster execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="feroxbuster", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_feroxbuster_output_success(self):
        """Test successful Feroxbuster output parsing"""
        feroxbuster_output = """
200      GET        http://example.com/admin
200      GET        http://example.com/login
404      GET        http://example.com/notfound
200      GET        https://test.example.com/dashboard
403      GET        https://test.example.com/private
500      GET        https://test.example.com/error
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify parsing
        self.assertEqual(len(urls), 6)
        
        # Check specific URLs with status codes
        expected_urls = [
            {"url": "http://example.com/admin", "status": 200, "method": "GET"},
            {"url": "http://example.com/login", "status": 200, "method": "GET"},
            {"url": "http://example.com/notfound", "status": 404, "method": "GET"},
            {"url": "https://test.example.com/dashboard", "status": 200, "method": "GET"},
            {"url": "https://test.example.com/private", "status": 403, "method": "GET"},
            {"url": "https://test.example.com/error", "status": 500, "method": "GET"}
        ]
        
        for expected in expected_urls:
            found = False
            for url_data in urls:
                if (url_data['url'] == expected['url'] and 
                    url_data['status'] == expected['status'] and
                    url_data['method'] == expected['method']):
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected}")

    def test_parse_feroxbuster_output_empty(self):
        """Test Feroxbuster output parsing with empty output"""
        feroxbuster_output = ""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify no URLs found
        self.assertEqual(len(urls), 0)

    def test_parse_feroxbuster_output_invalid_format(self):
        """Test Feroxbuster output parsing with invalid format"""
        invalid_output = "This is not valid feroxbuster output"

        urls = parse_feroxbuster_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(urls), 0)

    def test_parse_feroxbuster_output_mixed_formats(self):
        """Test Feroxbuster output parsing with mixed valid and invalid lines"""
        mixed_output = """
200      GET        http://example.com/admin
invalid line
404      GET        https://test.example.com/notfound
another invalid line
200      POST       http://example.com/api/v1/users
"""

        urls = parse_feroxbuster_output(mixed_output)

        # Should only parse valid lines
        self.assertEqual(len(urls), 3)
        
        # Check that valid URLs are parsed
        expected_urls = [
            {"url": "http://example.com/admin", "status": 200, "method": "GET"},
            {"url": "https://test.example.com/notfound", "status": 404, "method": "GET"},
            {"url": "http://example.com/api/v1/users", "status": 200, "method": "POST"}
        ]
        
        for expected in expected_urls:
            found = False
            for url_data in urls:
                if (url_data['url'] == expected['url'] and 
                    url_data['status'] == expected['status'] and
                    url_data['method'] == expected['method']):
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected}")

    def test_command_construction(self):
        """Test that Feroxbuster command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "200      GET        http://example.com/admin"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('feroxbuster', command)
        self.assertIn('--urls', command)  # URL parameter
        self.assertIn('--wordlist', command)  # Wordlist parameter
        self.assertIn('--threads', command)  # Threads parameter

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_feroxbuster(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_feroxbuster(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "200      GET        http://example.com/admin"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(large_targets, self.test_output_dir)

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
            mock_result.stdout = "200      GET        http://example.com/admin"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_status_code_categorization(self):
        """Test status code categorization functionality"""
        feroxbuster_output = """
200      GET        http://example.com/admin
200      GET        http://example.com/login
404      GET        http://example.com/notfound
403      GET        https://test.example.com/private
500      GET        https://test.example.com/error
301      GET        https://test.example.com/redirect
302      GET        https://test.example.com/moved
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify status code categorization
        status_200 = [url for url in urls if url['status'] == 200]
        status_404 = [url for url in urls if url['status'] == 404]
        status_403 = [url for url in urls if url['status'] == 403]
        status_500 = [url for url in urls if url['status'] == 500]
        status_redirect = [url for url in urls if url['status'] in [301, 302]]

        self.assertEqual(len(status_200), 2)
        self.assertEqual(len(status_404), 1)
        self.assertEqual(len(status_403), 1)
        self.assertEqual(len(status_500), 1)
        self.assertEqual(len(status_redirect), 2)

    def test_http_method_handling(self):
        """Test HTTP method handling"""
        feroxbuster_output = """
200      GET        http://example.com/admin
200      POST       http://example.com/api/v1/users
200      PUT        http://example.com/api/v1/users/123
200      DELETE     http://example.com/api/v1/users/123
404      GET        http://example.com/notfound
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify HTTP methods are parsed correctly
        get_methods = [url for url in urls if url['method'] == 'GET']
        post_methods = [url for url in urls if url['method'] == 'POST']
        put_methods = [url for url in urls if url['method'] == 'PUT']
        delete_methods = [url for url in urls if url['method'] == 'DELETE']

        self.assertEqual(len(get_methods), 2)
        self.assertEqual(len(post_methods), 1)
        self.assertEqual(len(put_methods), 1)
        self.assertEqual(len(delete_methods), 1)

    def test_url_deduplication(self):
        """Test URL deduplication functionality"""
        feroxbuster_output = """
200      GET        http://example.com/admin
200      GET        http://example.com/admin
200      GET        http://example.com/login
200      GET        http://example.com/login
404      GET        https://test.example.com/notfound
404      GET        https://test.example.com/notfound
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify duplicates are handled (should be unique)
        unique_urls = set()
        for url_data in urls:
            unique_urls.add(url_data['url'])

        self.assertEqual(len(unique_urls), 3)  # admin, login, notfound
        self.assertIn("http://example.com/admin", unique_urls)
        self.assertIn("http://example.com/login", unique_urls)
        self.assertIn("https://test.example.com/notfound", unique_urls)

    def test_complex_url_handling(self):
        """Test handling of complex URLs with parameters"""
        feroxbuster_output = """
200      GET        http://example.com/api/v1/users?id=123&type=admin
200      POST       http://example.com/api/v1/users?format=json
404      GET        https://test.example.com/search?q=test&page=1&sort=date
403      GET        https://test.example.com/dashboard?user=admin&token=abc123
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify complex URLs are parsed correctly
        self.assertEqual(len(urls), 4)
        
        # Check specific complex URLs
        expected_urls = [
            "http://example.com/api/v1/users?id=123&type=admin",
            "http://example.com/api/v1/users?format=json",
            "https://test.example.com/search?q=test&page=1&sort=date",
            "https://test.example.com/dashboard?user=admin&token=abc123"
        ]
        
        for expected_url in expected_urls:
            found = False
            for url_data in urls:
                if url_data['url'] == expected_url:
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected_url}")

    def test_special_characters_in_urls(self):
        """Test handling of URLs with special characters"""
        feroxbuster_output = """
200      GET        http://example.com/path with spaces/
200      GET        http://example.com/path%20with%20encoding/
404      GET        https://test.example.com/api/v1/data?param=value with spaces
403      GET        https://test.example.com/path/with/special/chars/!@#$%^&*()
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify URLs with special characters are handled
        self.assertEqual(len(urls), 4)
        
        # Check specific URLs with special characters
        expected_urls = [
            "http://example.com/path with spaces/",
            "http://example.com/path%20with%20encoding/",
            "https://test.example.com/api/v1/data?param=value with spaces",
            "https://test.example.com/path/with/special/chars/!@#$%^&*()"
        ]
        
        for expected_url in expected_urls:
            found = False
            for url_data in urls:
                if url_data['url'] == expected_url:
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected_url}")

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        feroxbuster_output = """

200      GET        http://example.com/admin

404      GET        https://test.example.com/notfound

200      POST       http://example.com/api/v1/users

"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(urls), 3)
        
        # Check specific URLs
        expected_urls = [
            "http://example.com/admin",
            "https://test.example.com/notfound",
            "http://example.com/api/v1/users"
        ]
        
        for expected_url in expected_urls:
            found = False
            for url_data in urls:
                if url_data['url'] == expected_url:
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected_url}")

    def test_very_long_urls(self):
        """Test handling of very long URLs"""
        long_url = "http://example.com/" + "a" * 1000 + "?param=" + "b" * 500
        feroxbuster_output = f"""
200      GET        http://example.com/admin
200      GET        {long_url}
404      GET        https://test.example.com/notfound
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify very long URLs are handled
        self.assertEqual(len(urls), 3)
        
        # Check specific URLs
        expected_urls = [
            "http://example.com/admin",
            long_url,
            "https://test.example.com/notfound"
        ]
        
        for expected_url in expected_urls:
            found = False
            for url_data in urls:
                if url_data['url'] == expected_url:
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected_url}")

    def test_invalid_url_filtering(self):
        """Test filtering of invalid URLs"""
        feroxbuster_output = """
200      GET        http://example.com/admin
not a valid line
404      GET        https://test.example.com/notfound
also not valid
200      POST       ftp://example.com/file
200      GET        http://example.com/api/v1/users
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Should only parse valid HTTP/HTTPS URLs
        self.assertEqual(len(urls), 3)
        
        # Check that only valid URLs are parsed
        expected_urls = [
            "http://example.com/admin",
            "https://test.example.com/notfound",
            "http://example.com/api/v1/users"
        ]
        
        for expected_url in expected_urls:
            found = False
            for url_data in urls:
                if url_data['url'] == expected_url:
                    found = True
                    break
            self.assertTrue(found, f"Expected URL not found: {expected_url}")


class TestFeroxbusterIntegration(unittest.TestCase):
    """Integration tests for Feroxbuster runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.feroxbuster_dir = os.path.join(self.test_output_dir, "directory_enumeration")
        os.makedirs(self.feroxbuster_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete Feroxbuster workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.feroxbuster_dir, "feroxbuster_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock feroxbuster output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
200      GET        http://example.com/admin
200      GET        http://example.com/login
404      GET        http://example.com/notfound
200      GET        https://test.example.com/dashboard
403      GET        https://test.example.com/private
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock feroxbuster output content"
                
                result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['urls']), 5)
        self.assertEqual(result['summary']['total_urls'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different status codes are found
        status_200 = [url for url in result['urls'] if url['status'] == 200]
        status_404 = [url for url in result['urls'] if url['status'] == 404]
        status_403 = [url for url in result['urls'] if url['status'] == 403]

        self.assertEqual(len(status_200), 3)
        self.assertEqual(len(status_404), 1)
        self.assertEqual(len(status_403), 1)

    def test_threading_integration(self):
        """Test threading integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "200      GET        http://example.com/admin"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify threading is configured
        command = result['command']
        self.assertIn('--threads', command)
        
        # Extract thread value
        import re
        command_str = ' '.join(command)
        thread_match = re.search(r'--threads\s+(\d+)', command_str)
        if thread_match:
            threads = int(thread_match.group(1))
            self.assertGreater(threads, 0)
            self.assertLessEqual(threads, 100)  # Reasonable upper limit

    def test_wordlist_integration(self):
        """Test wordlist integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "200      GET        http://example.com/admin"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify wordlist is specified
        command = result['command']
        self.assertIn('--wordlist', command)

    def test_output_format_integration(self):
        """Test output format integration"""
        feroxbuster_output = """
200      GET        http://example.com/admin
404      GET        https://test.example.com/notfound
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify output format is consistent
        self.assertIsInstance(urls, list)
        
        for url_data in urls:
            self.assertIn('url', url_data)
            self.assertIn('status', url_data)
            self.assertIn('method', url_data)
            self.assertIsInstance(url_data['url'], str)
            self.assertIsInstance(url_data['status'], int)
            self.assertIsInstance(url_data['method'], str)
            self.assertTrue(url_data['url'].startswith(('http://', 'https://')))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "feroxbuster", stderr="First failure"),
                MagicMock(returncode=0, stdout="200      GET        http://example.com/admin", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_url_categorization_integration(self):
        """Test URL categorization integration"""
        feroxbuster_output = """
200      GET        http://example.com/admin
200      GET        http://example.com/login
404      GET        http://example.com/notfound
200      GET        http://example.com/api/v1/users
200      GET        http://example.com/api/v2/data
403      GET        https://test.example.com/private
200      GET        https://test.example.com/dashboard
200      GET        https://test.example.com/api/v1/config
"""

        urls = parse_feroxbuster_output(feroxbuster_output)

        # Verify different URL categories are found
        admin_urls = [url for url in urls if 'admin' in url['url']]
        login_urls = [url for url in urls if 'login' in url['url']]
        api_urls = [url for url in urls if 'api' in url['url']]
        dashboard_urls = [url for url in urls if 'dashboard' in url['url']]
        private_urls = [url for url in urls if 'private' in url['url']]

        self.assertEqual(len(admin_urls), 1)
        self.assertEqual(len(login_urls), 1)
        self.assertEqual(len(api_urls), 3)
        self.assertEqual(len(dashboard_urls), 1)
        self.assertEqual(len(private_urls), 1)


if __name__ == '__main__':
    unittest.main() 