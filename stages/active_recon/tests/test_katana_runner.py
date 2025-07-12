#!/usr/bin/env python3
"""
Unit tests for Katana runner
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

from run_katana import run_katana, parse_katana_output


class TestKatanaRunner(unittest.TestCase):
    """Test cases for Katana runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.katana_dir = os.path.join(self.test_output_dir, "directory_enumeration")
        os.makedirs(self.katana_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_katana_success(self, mock_run):
        """Test successful Katana execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
http://example.com/
http://example.com/admin
http://example.com/login
http://example.com/api/v1/users
https://test.example.com/
https://test.example.com/dashboard
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_katana(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('urls', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['urls']), 6)
        self.assertEqual(result['summary']['total_urls'], 6)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_katana_failure(self, mock_run):
        """Test Katana execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_katana(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_urls'], 0)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_katana_timeout(self, mock_run):
        """Test Katana execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="katana", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_katana(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_katana_output_success(self):
        """Test successful Katana output parsing"""
        katana_output = """
http://example.com/
http://example.com/admin
http://example.com/login
http://example.com/api/v1/users
https://test.example.com/
https://test.example.com/dashboard
https://test.example.com/api/v2/data
"""

        urls = parse_katana_output(katana_output)

        # Verify parsing
        self.assertEqual(len(urls), 7)
        
        # Check specific URLs
        expected_urls = [
            "http://example.com/",
            "http://example.com/admin",
            "http://example.com/login",
            "http://example.com/api/v1/users",
            "https://test.example.com/",
            "https://test.example.com/dashboard",
            "https://test.example.com/api/v2/data"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_parse_katana_output_empty(self):
        """Test Katana output parsing with empty output"""
        katana_output = ""

        urls = parse_katana_output(katana_output)

        # Verify no URLs found
        self.assertEqual(len(urls), 0)

    def test_parse_katana_output_invalid_format(self):
        """Test Katana output parsing with invalid format"""
        invalid_output = "This is not valid katana output"

        urls = parse_katana_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(urls), 0)

    def test_parse_katana_output_mixed_formats(self):
        """Test Katana output parsing with mixed valid and invalid lines"""
        mixed_output = """
http://example.com/
invalid line
https://test.example.com/
another invalid line
http://example.com/api/v1/users
"""

        urls = parse_katana_output(mixed_output)

        # Should only parse valid URLs
        self.assertEqual(len(urls), 3)
        
        # Check that valid URLs are parsed
        expected_urls = [
            "http://example.com/",
            "https://test.example.com/",
            "http://example.com/api/v1/users"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_command_construction(self):
        """Test that Katana command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('katana', command)
        self.assertIn('-silent', command)  # Silent mode
        self.assertIn('-jc', command)      # JavaScript crawling
        self.assertIn('-kf', command)      # Known file extensions

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_katana(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_katana(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(large_targets, self.test_output_dir)

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
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_url_deduplication(self):
        """Test URL deduplication functionality"""
        katana_output = """
http://example.com/
http://example.com/
http://example.com/admin
http://example.com/admin
https://test.example.com/
https://test.example.com/
"""

        urls = parse_katana_output(katana_output)

        # Verify duplicates are removed
        self.assertEqual(len(urls), 3)  # Should be unique URLs
        
        # Check specific unique URLs
        expected_urls = [
            "http://example.com/",
            "http://example.com/admin",
            "https://test.example.com/"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_complex_url_handling(self):
        """Test handling of complex URLs with parameters"""
        katana_output = """
http://example.com/
http://example.com/api/v1/users?id=123&type=admin
http://example.com/search?q=test&page=1&sort=date
https://test.example.com/dashboard?user=admin&token=abc123
https://test.example.com/api/v2/data?format=json&limit=100
"""

        urls = parse_katana_output(katana_output)

        # Verify complex URLs are parsed correctly
        self.assertEqual(len(urls), 5)
        
        # Check specific complex URLs
        expected_urls = [
            "http://example.com/",
            "http://example.com/api/v1/users?id=123&type=admin",
            "http://example.com/search?q=test&page=1&sort=date",
            "https://test.example.com/dashboard?user=admin&token=abc123",
            "https://test.example.com/api/v2/data?format=json&limit=100"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_special_characters_in_urls(self):
        """Test handling of URLs with special characters"""
        katana_output = """
http://example.com/path with spaces/
http://example.com/path%20with%20encoding/
https://test.example.com/api/v1/data?param=value with spaces
https://test.example.com/path/with/special/chars/!@#$%^&*()
"""

        urls = parse_katana_output(katana_output)

        # Verify URLs with special characters are handled
        self.assertEqual(len(urls), 4)
        
        # Check specific URLs with special characters
        expected_urls = [
            "http://example.com/path with spaces/",
            "http://example.com/path%20with%20encoding/",
            "https://test.example.com/api/v1/data?param=value with spaces",
            "https://test.example.com/path/with/special/chars/!@#$%^&*()"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        katana_output = """

http://example.com/

https://test.example.com/

http://example.com/admin

"""

        urls = parse_katana_output(katana_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(urls), 3)
        
        # Check specific URLs
        expected_urls = [
            "http://example.com/",
            "https://test.example.com/",
            "http://example.com/admin"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)

    def test_very_long_urls(self):
        """Test handling of very long URLs"""
        long_url = "http://example.com/" + "a" * 1000 + "?param=" + "b" * 500
        katana_output = f"""
http://example.com/
{long_url}
https://test.example.com/
"""

        urls = parse_katana_output(katana_output)

        # Verify very long URLs are handled
        self.assertEqual(len(urls), 3)
        self.assertIn("http://example.com/", urls)
        self.assertIn(long_url, urls)
        self.assertIn("https://test.example.com/", urls)

    def test_invalid_url_filtering(self):
        """Test filtering of invalid URLs"""
        katana_output = """
http://example.com/
not a url
https://test.example.com/
also not a url
ftp://example.com/
http://example.com/admin
"""

        urls = parse_katana_output(katana_output)

        # Should only parse valid HTTP/HTTPS URLs
        self.assertEqual(len(urls), 3)
        
        # Check that only valid URLs are parsed
        expected_urls = [
            "http://example.com/",
            "https://test.example.com/",
            "http://example.com/admin"
        ]
        
        for url in expected_urls:
            self.assertIn(url, urls)


class TestKatanaIntegration(unittest.TestCase):
    """Integration tests for Katana runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.katana_dir = os.path.join(self.test_output_dir, "directory_enumeration")
        os.makedirs(self.katana_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete Katana workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.katana_dir, "katana_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock katana output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
http://example.com/
http://example.com/admin
http://example.com/login
https://test.example.com/
https://test.example.com/dashboard
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock katana output content"
                
                result = run_katana(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['urls']), 5)
        self.assertEqual(result['summary']['total_urls'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different types of URLs are found
        admin_urls = [url for url in result['urls'] if 'admin' in url.get('url', '')]
        login_urls = [url for url in result['urls'] if 'login' in url.get('url', '')]
        dashboard_urls = [url for url in result['urls'] if 'dashboard' in url.get('url', '')]

        self.assertEqual(len(admin_urls), 1)
        self.assertEqual(len(login_urls), 1)
        self.assertEqual(len(dashboard_urls), 1)

    def test_javascript_crawling_integration(self):
        """Test JavaScript crawling integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(self.test_targets, self.test_output_dir)

        # Verify JavaScript crawling is enabled
        command = result['command']
        self.assertIn('-jc', command)

    def test_known_files_integration(self):
        """Test known files integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(self.test_targets, self.test_output_dir)

        # Verify known files scanning is enabled
        command = result['command']
        self.assertIn('-kf', command)

    def test_silent_mode_integration(self):
        """Test silent mode integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(self.test_targets, self.test_output_dir)

        # Verify silent mode is enabled
        command = result['command']
        self.assertIn('-silent', command)

    def test_output_format_integration(self):
        """Test output format integration"""
        katana_output = """
http://example.com/
http://example.com/admin
https://test.example.com/
"""

        urls = parse_katana_output(katana_output)

        # Verify output format is consistent
        self.assertIsInstance(urls, list)
        
        for url in urls:
            self.assertIsInstance(url, str)
            self.assertTrue(url.startswith(('http://', 'https://')))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "katana", stderr="First failure"),
                MagicMock(returncode=0, stdout="http://example.com/", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_katana(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_url_categorization_integration(self):
        """Test URL categorization integration"""
        katana_output = """
http://example.com/
http://example.com/admin
http://example.com/login
http://example.com/api/v1/users
http://example.com/api/v2/data
https://test.example.com/
https://test.example.com/dashboard
https://test.example.com/api/v1/config
"""

        urls = parse_katana_output(katana_output)

        # Verify different URL categories are found
        admin_urls = [url for url in urls if 'admin' in url]
        login_urls = [url for url in urls if 'login' in url]
        api_urls = [url for url in urls if 'api' in url]
        dashboard_urls = [url for url in urls if 'dashboard' in url]

        self.assertEqual(len(admin_urls), 1)
        self.assertEqual(len(login_urls), 1)
        self.assertEqual(len(api_urls), 3)
        self.assertEqual(len(dashboard_urls), 1)


if __name__ == '__main__':
    unittest.main() 