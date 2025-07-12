#!/usr/bin/env python3
"""
Unit tests for GetJS runner
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

from run_getjs import run_getjs, parse_getjs_output


class TestGetJSRunner(unittest.TestCase):
    """Test cases for GetJS runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.getjs_dir = os.path.join(self.test_output_dir, "javascript_analysis")
        os.makedirs(self.getjs_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_getjs_success(self, mock_run):
        """Test successful GetJS execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
http://example.com/script.js
http://example.com/app.js
http://example.com/vendor/jquery.js
https://test.example.com/main.js
https://test.example.com/api.js
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_getjs(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('js_files', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['js_files']), 5)
        self.assertEqual(result['summary']['total_js_files'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_getjs_failure(self, mock_run):
        """Test GetJS execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_getjs(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_js_files'], 0)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_getjs_timeout(self, mock_run):
        """Test GetJS execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="getjs", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_getjs(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_getjs_output_success(self):
        """Test successful GetJS output parsing"""
        getjs_output = """
http://example.com/script.js
http://example.com/app.js
http://example.com/vendor/jquery.js
https://test.example.com/main.js
https://test.example.com/api.js
https://test.example.com/utils/helper.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify parsing
        self.assertEqual(len(js_files), 6)
        
        # Check specific JS files
        expected_files = [
            "http://example.com/script.js",
            "http://example.com/app.js",
            "http://example.com/vendor/jquery.js",
            "https://test.example.com/main.js",
            "https://test.example.com/api.js",
            "https://test.example.com/utils/helper.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_parse_getjs_output_empty(self):
        """Test GetJS output parsing with empty output"""
        getjs_output = ""

        js_files = parse_getjs_output(getjs_output)

        # Verify no JS files found
        self.assertEqual(len(js_files), 0)

    def test_parse_getjs_output_invalid_format(self):
        """Test GetJS output parsing with invalid format"""
        invalid_output = "This is not valid getjs output"

        js_files = parse_getjs_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(js_files), 0)

    def test_parse_getjs_output_mixed_formats(self):
        """Test GetJS output parsing with mixed valid and invalid lines"""
        mixed_output = """
http://example.com/script.js
invalid line
https://test.example.com/main.js
another invalid line
http://example.com/app.js
"""

        js_files = parse_getjs_output(mixed_output)

        # Should only parse valid JS file URLs
        self.assertEqual(len(js_files), 3)
        
        # Check that valid JS files are parsed
        expected_files = [
            "http://example.com/script.js",
            "https://test.example.com/main.js",
            "http://example.com/app.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_command_construction(self):
        """Test that GetJS command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/script.js"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_getjs(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('getJS', command)
        self.assertIn('--input', command)  # Input parameter
        self.assertIn('--output', command)  # Output parameter

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_getjs(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_getjs(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com/script.js"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_getjs(large_targets, self.test_output_dir)

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
            mock_result.stdout = "http://example.com/script.js"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_getjs(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_js_file_deduplication(self):
        """Test JS file deduplication functionality"""
        getjs_output = """
http://example.com/script.js
http://example.com/script.js
http://example.com/app.js
http://example.com/app.js
https://test.example.com/main.js
https://test.example.com/main.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify duplicates are removed
        self.assertEqual(len(js_files), 3)  # Should be unique files
        
        # Check specific unique files
        expected_files = [
            "http://example.com/script.js",
            "http://example.com/app.js",
            "https://test.example.com/main.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_complex_js_file_paths(self):
        """Test handling of complex JS file paths"""
        getjs_output = """
http://example.com/js/app.js
http://example.com/static/js/vendor/jquery.min.js
http://example.com/assets/js/components/modal.js
https://test.example.com/dist/js/bundle.js
https://test.example.com/public/js/utils/helper.js
https://test.example.com/build/js/main.12345.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify complex paths are parsed correctly
        self.assertEqual(len(js_files), 6)
        
        # Check specific complex paths
        expected_files = [
            "http://example.com/js/app.js",
            "http://example.com/static/js/vendor/jquery.min.js",
            "http://example.com/assets/js/components/modal.js",
            "https://test.example.com/dist/js/bundle.js",
            "https://test.example.com/public/js/utils/helper.js",
            "https://test.example.com/build/js/main.12345.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_js_file_extensions(self):
        """Test handling of different JS file extensions"""
        getjs_output = """
http://example.com/script.js
http://example.com/app.min.js
http://example.com/vendor/jquery.js
https://test.example.com/main.js
https://test.example.com/utils.helper.js
https://test.example.com/bundle.min.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify different extensions are handled
        self.assertEqual(len(js_files), 6)
        
        # Check specific extensions
        expected_files = [
            "http://example.com/script.js",
            "http://example.com/app.min.js",
            "http://example.com/vendor/jquery.js",
            "https://test.example.com/main.js",
            "https://test.example.com/utils.helper.js",
            "https://test.example.com/bundle.min.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_special_characters_in_paths(self):
        """Test handling of JS files with special characters in paths"""
        getjs_output = """
http://example.com/js/app with spaces.js
http://example.com/static/js/vendor/jquery%20min.js
https://test.example.com/assets/js/components/modal-v2.js
https://test.example.com/public/js/utils/helper_123.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify special characters are handled
        self.assertEqual(len(js_files), 4)
        
        # Check specific files with special characters
        expected_files = [
            "http://example.com/js/app with spaces.js",
            "http://example.com/static/js/vendor/jquery%20min.js",
            "https://test.example.com/assets/js/components/modal-v2.js",
            "https://test.example.com/public/js/utils/helper_123.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        getjs_output = """

http://example.com/script.js

https://test.example.com/main.js

http://example.com/app.js

"""

        js_files = parse_getjs_output(getjs_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(js_files), 3)
        
        # Check specific files
        expected_files = [
            "http://example.com/script.js",
            "https://test.example.com/main.js",
            "http://example.com/app.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_very_long_js_file_paths(self):
        """Test handling of very long JS file paths"""
        long_path = "http://example.com/" + "a" * 1000 + "/script.js"
        getjs_output = f"""
http://example.com/script.js
{long_path}
https://test.example.com/main.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify very long paths are handled
        self.assertEqual(len(js_files), 3)
        
        # Check specific files
        expected_files = [
            "http://example.com/script.js",
            long_path,
            "https://test.example.com/main.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_invalid_js_file_filtering(self):
        """Test filtering of invalid JS file URLs"""
        getjs_output = """
http://example.com/script.js
not a valid line
https://test.example.com/main.js
also not valid
http://example.com/image.png
http://example.com/app.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Should only parse valid JS file URLs
        self.assertEqual(len(js_files), 3)
        
        # Check that only valid JS files are parsed
        expected_files = [
            "http://example.com/script.js",
            "https://test.example.com/main.js",
            "http://example.com/app.js"
        ]
        
        for file_url in expected_files:
            self.assertIn(file_url, js_files)

    def test_js_file_categorization(self):
        """Test JS file categorization functionality"""
        getjs_output = """
http://example.com/js/app.js
http://example.com/js/vendor/jquery.js
http://example.com/js/utils/helper.js
http://example.com/js/components/modal.js
https://test.example.com/dist/js/bundle.js
https://test.example.com/public/js/main.js
https://test.example.com/assets/js/config.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify JS file categorization
        app_files = [file_url for file_url in js_files if 'app' in file_url]
        vendor_files = [file_url for file_url in js_files if 'vendor' in file_url]
        utils_files = [file_url for file_url in js_files if 'utils' in file_url]
        components_files = [file_url for file_url in js_files if 'components' in file_url]
        dist_files = [file_url for file_url in js_files if 'dist' in file_url]

        self.assertEqual(len(app_files), 1)
        self.assertEqual(len(vendor_files), 1)
        self.assertEqual(len(utils_files), 1)
        self.assertEqual(len(components_files), 1)
        self.assertEqual(len(dist_files), 1)


class TestGetJSIntegration(unittest.TestCase):
    """Integration tests for GetJS runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.getjs_dir = os.path.join(self.test_output_dir, "javascript_analysis")
        os.makedirs(self.getjs_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete GetJS workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.getjs_dir, "getjs_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock getjs output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
http://example.com/script.js
http://example.com/app.js
http://example.com/vendor/jquery.js
https://test.example.com/main.js
https://test.example.com/api.js
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock getjs output content"
                
                result = run_getjs(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['js_files']), 5)
        self.assertEqual(result['summary']['total_js_files'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different types of JS files are found
        app_files = [file_url for file_url in result['js_files'] if 'app' in file_url]
        vendor_files = [file_url for file_url in result['js_files'] if 'vendor' in file_url]
        api_files = [file_url for file_url in result['js_files'] if 'api' in file_url]

        self.assertEqual(len(app_files), 1)
        self.assertEqual(len(vendor_files), 1)
        self.assertEqual(len(api_files), 1)

    def test_output_format_integration(self):
        """Test output format integration"""
        getjs_output = """
http://example.com/script.js
https://test.example.com/main.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify output format is consistent
        self.assertIsInstance(js_files, list)
        
        for file_url in js_files:
            self.assertIsInstance(file_url, str)
            self.assertTrue(file_url.startswith(('http://', 'https://')))
            self.assertTrue(file_url.endswith('.js'))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "getjs", stderr="First failure"),
                MagicMock(returncode=0, stdout="http://example.com/script.js", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_getjs(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_js_file_analysis_integration(self):
        """Test JS file analysis integration"""
        getjs_output = """
http://example.com/js/app.js
http://example.com/js/vendor/jquery.js
http://example.com/js/utils/helper.js
http://example.com/js/components/modal.js
https://test.example.com/dist/js/bundle.js
https://test.example.com/public/js/main.js
https://test.example.com/assets/js/config.js
https://test.example.com/build/js/api.js
"""

        js_files = parse_getjs_output(getjs_output)

        # Verify different JS file categories are found
        app_files = [file_url for file_url in js_files if 'app' in file_url]
        vendor_files = [file_url for file_url in js_files if 'vendor' in file_url]
        utils_files = [file_url for file_url in js_files if 'utils' in file_url]
        components_files = [file_url for file_url in js_files if 'components' in file_url]
        dist_files = [file_url for file_url in js_files if 'dist' in file_url]
        api_files = [file_url for file_url in js_files if 'api' in file_url]

        self.assertEqual(len(app_files), 1)
        self.assertEqual(len(vendor_files), 1)
        self.assertEqual(len(utils_files), 1)
        self.assertEqual(len(components_files), 1)
        self.assertEqual(len(dist_files), 1)
        self.assertEqual(len(api_files), 1)


if __name__ == '__main__':
    unittest.main() 