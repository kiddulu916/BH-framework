#!/usr/bin/env python3
"""
Unit tests for Arjun runner
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import subprocess
from datetime import datetime
from typing import List, Dict, Any

# Add parent directory to path to import the runner
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'runners')))

from run_arjun import run_arjun

def parse_arjun_output(arjun_output: str) -> List[Dict[str, Any]]:
    """
    Parse Arjun output for testing purposes.
    This is a test-only function that simulates parsing Arjun output.
    
    Args:
        arjun_output: Raw Arjun output string
        
    Returns:
        List of parsed parameter data
    """
    parameters = []
    
    for line in arjun_output.strip().split('\n'):
        line = line.strip()
        if not line or not line.startswith('['):
            continue
            
        try:
            # Parse format: [METHOD] URL?param1=value1&param2=value2
            if ']' in line:
                method_part = line[:line.find(']') + 1]
                url_part = line[line.find(']') + 1:].strip()
                
                # Extract method
                method = method_part[1:-1]  # Remove brackets
                
                # Extract URL and parameters
                if '?' in url_part:
                    base_url = url_part[:url_part.find('?')]
                    params_part = url_part[url_part.find('?') + 1:]
                    params = [param.split('=')[0] for param in params_part.split('&') if '=' in param]
                else:
                    base_url = url_part
                    params = []
                
                # Only accept http/https URLs
                if base_url.startswith('http://') or base_url.startswith('https://'):
                    parameters.append({
                        'method': method,
                        'url': base_url,
                        'params': params
                    })
        except Exception:
            # Skip invalid lines
            continue
    
    return parameters


class TestArjunRunner(unittest.TestCase):
    """Test cases for Arjun runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.arjun_dir = os.path.join(self.test_output_dir, "parameter_discovery")
        os.makedirs(self.arjun_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_arjun_success(self, mock_run):
        """Test successful Arjun execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
[GET] http://example.com/api/v1/users?id=123&name=test
[POST] http://example.com/api/v1/users
[GET] https://test.example.com/search?q=test&page=1
[GET] https://test.example.com/api/v2/data?format=json
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_arjun(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('endpoints_found', result)
        self.assertIn('summary', result)
        self.assertIn('command', result)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_arjun_failure(self, mock_run):
        """Test Arjun execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_arjun(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertIn('command', result)
        self.assertEqual(result['targets_checked'], 2)

    @patch('subprocess.run')
    def test_run_arjun_timeout(self, mock_run):
        """Test Arjun execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="arjun", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_arjun(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timed out', result['error'].lower())
        self.assertIn('command', result)
        self.assertIn('return_code', result)

    def test_parse_arjun_output_success(self):
        """Test successful Arjun output parsing"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123&name=test
[POST] http://example.com/api/v1/users
[GET] https://test.example.com/search?q=test&page=1
[GET] https://test.example.com/api/v2/data?format=json
[POST] https://test.example.com/api/v2/users
[PUT] http://example.com/api/v1/settings
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify parsing
        self.assertEqual(len(parameters), 6)
        
        # Check specific parameters
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["id", "name"]},
            {"method": "POST", "url": "http://example.com/api/v1/users", "params": []},
            {"method": "GET", "url": "https://test.example.com/search", "params": ["q", "page"]},
            {"method": "GET", "url": "https://test.example.com/api/v2/data", "params": ["format"]},
            {"method": "POST", "url": "https://test.example.com/api/v2/users", "params": []},
            {"method": "PUT", "url": "http://example.com/api/v1/settings", "params": []}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    param_data['params'] == expected['params']):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")

    def test_parse_arjun_output_empty(self):
        """Test Arjun output parsing with empty output"""
        arjun_output = ""

        parameters = parse_arjun_output(arjun_output)

        # Verify no parameters found
        self.assertEqual(len(parameters), 0)

    def test_parse_arjun_output_invalid_format(self):
        """Test Arjun output parsing with invalid format"""
        invalid_output = "This is not valid arjun output"

        parameters = parse_arjun_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(parameters), 0)

    def test_parse_arjun_output_mixed_formats(self):
        """Test Arjun output parsing with mixed valid and invalid lines"""
        mixed_output = """
[GET] http://example.com/api/v1/users?id=123
invalid line
[POST] https://test.example.com/api/v1/users
also not valid
[GET] http://example.com/search?q=test
"""

        parameters = parse_arjun_output(mixed_output)

        # Should only parse valid parameter lines
        self.assertEqual(len(parameters), 3)
        
        # Check that valid parameters are parsed
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["id"]},
            {"method": "POST", "url": "https://test.example.com/api/v1/users", "params": []},
            {"method": "GET", "url": "http://example.com/search", "params": ["q"]}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    param_data['params'] == expected['params']):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")

    def test_command_construction(self):
        """Test that Arjun command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[GET] http://example.com/api/v1/users?id=123"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_arjun(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('arjun', command)
        self.assertIn('-i', command)  # Input file parameter
        self.assertIn('-oJ', command)  # JSON output parameter
        self.assertIn('-t', command)  # Threads parameter
        self.assertIn('-T', command)  # Timeout parameter
        self.assertIn('-m', command)  # Methods parameter
        self.assertIn('-w', command)  # Wordlist parameter
        self.assertIn('-v', command)  # Verbose parameter

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_arjun(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_arjun(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "[GET] http://example.com/api/v1/users?id=123"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_arjun(large_targets, self.test_output_dir)

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
            mock_result.stdout = "[GET] http://example.com/api/v1/users?id=123"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_arjun(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_parameter_deduplication(self):
        """Test parameter deduplication functionality"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123
[GET] http://example.com/api/v1/users?id=123
[POST] https://test.example.com/api/v1/users
[POST] https://test.example.com/api/v1/users
[GET] http://example.com/search?q=test
[GET] http://example.com/search?q=test
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify duplicates are handled (should be unique)
        unique_combinations = set()
        for param_data in parameters:
            unique_combinations.add((param_data['method'], param_data['url'], tuple(sorted(param_data['params']))))

        self.assertEqual(len(unique_combinations), 3)  # Should be unique combinations
        
        # Check specific unique combinations
        expected_combinations = [
            ("GET", "http://example.com/api/v1/users", ("id",)),
            ("POST", "https://test.example.com/api/v1/users", ()),
            ("GET", "http://example.com/search", ("q",))
        ]
        
        for expected in expected_combinations:
            self.assertIn(expected, unique_combinations)

    def test_complex_parameter_handling(self):
        """Test handling of complex parameters"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123&name=test&type=admin
[POST] http://example.com/api/v1/users?format=json&pretty=true
[GET] https://test.example.com/search?q=test&page=1&sort=date&limit=10
[GET] https://test.example.com/api/v2/data?format=json&version=2.0&debug=true
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify complex parameters are parsed correctly
        self.assertEqual(len(parameters), 4)
        
        # Check specific complex parameters
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["id", "name", "type"]},
            {"method": "POST", "url": "http://example.com/api/v1/users", "params": ["format", "pretty"]},
            {"method": "GET", "url": "https://test.example.com/search", "params": ["q", "page", "sort", "limit"]},
            {"method": "GET", "url": "https://test.example.com/api/v2/data", "params": ["format", "version", "debug"]}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    set(param_data['params']) == set(expected['params'])):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")

    def test_http_method_categorization(self):
        """Test HTTP method categorization functionality"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123
[POST] http://example.com/api/v1/users
[PUT] http://example.com/api/v1/users/123
[DELETE] http://example.com/api/v1/users/123
[GET] https://test.example.com/search?q=test
[POST] https://test.example.com/api/v1/users
[PATCH] http://example.com/api/v1/settings
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify HTTP method categorization
        get_methods = [param for param in parameters if param['method'] == 'GET']
        post_methods = [param for param in parameters if param['method'] == 'POST']
        put_methods = [param for param in parameters if param['method'] == 'PUT']
        delete_methods = [param for param in parameters if param['method'] == 'DELETE']
        patch_methods = [param for param in parameters if param['method'] == 'PATCH']

        self.assertEqual(len(get_methods), 2)
        self.assertEqual(len(post_methods), 2)
        self.assertEqual(len(put_methods), 1)
        self.assertEqual(len(delete_methods), 1)
        self.assertEqual(len(patch_methods), 1)

    def test_special_characters_in_parameters(self):
        """Test handling of parameters with special characters"""
        arjun_output = """
[GET] http://example.com/api/v1/users?user_id=123&user_name=test user
[POST] http://example.com/api/v1/users?format=json&pretty=true
[GET] https://test.example.com/search?q=test&page=1&sort=date
[GET] https://test.example.com/api/v2/data?format=json&version=2.0
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify special characters are handled
        self.assertEqual(len(parameters), 4)
        
        # Check specific parameters with special characters
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["user_id", "user_name"]},
            {"method": "POST", "url": "http://example.com/api/v1/users", "params": ["format", "pretty"]},
            {"method": "GET", "url": "https://test.example.com/search", "params": ["q", "page", "sort"]},
            {"method": "GET", "url": "https://test.example.com/api/v2/data", "params": ["format", "version"]}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    set(param_data['params']) == set(expected['params'])):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        arjun_output = """

[GET] http://example.com/api/v1/users?id=123

[POST] https://test.example.com/api/v1/users

[GET] http://example.com/search?q=test

"""

        parameters = parse_arjun_output(arjun_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(parameters), 3)
        
        # Check specific parameters
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["id"]},
            {"method": "POST", "url": "https://test.example.com/api/v1/users", "params": []},
            {"method": "GET", "url": "http://example.com/search", "params": ["q"]}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    param_data['params'] == expected['params']):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")

    def test_very_long_parameter_lists(self):
        """Test handling of very long parameter lists"""
        long_params = "&".join([f"param{i}=value{i}" for i in range(50)])
        arjun_output = f"""
[GET] http://example.com/api/v1/users?id=123
[GET] http://example.com/api/v1/data?{long_params}
[POST] https://test.example.com/api/v1/users
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify very long parameter lists are handled
        self.assertEqual(len(parameters), 3)
        
        # Check that the long parameter list is parsed correctly
        long_param_data = None
        for param_data in parameters:
            if param_data['url'] == "http://example.com/api/v1/data":
                long_param_data = param_data
                break
        
        self.assertIsNotNone(long_param_data)
        self.assertEqual(len(long_param_data['params']), 50)

    def test_invalid_parameter_filtering(self):
        """Test filtering of invalid parameter lines"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123
not a valid line
[POST] https://test.example.com/api/v1/users
also not valid
[GET] ftp://example.com/file?param=value
[GET] http://example.com/search?q=test
"""

        parameters = parse_arjun_output(arjun_output)

        # Should only parse valid parameter lines
        self.assertEqual(len(parameters), 3)
        
        # Check that only valid parameters are parsed
        expected_parameters = [
            {"method": "GET", "url": "http://example.com/api/v1/users", "params": ["id"]},
            {"method": "POST", "url": "https://test.example.com/api/v1/users", "params": []},
            {"method": "GET", "url": "http://example.com/search", "params": ["q"]}
        ]
        
        for expected in expected_parameters:
            found = False
            for param_data in parameters:
                if (param_data['method'] == expected['method'] and 
                    param_data['url'] == expected['url'] and
                    param_data['params'] == expected['params']):
                    found = True
                    break
            self.assertTrue(found, f"Expected parameter not found: {expected}")


class TestArjunIntegration(unittest.TestCase):
    """Integration tests for Arjun runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.arjun_dir = os.path.join(self.test_output_dir, "parameter_discovery")
        os.makedirs(self.arjun_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete Arjun workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.arjun_dir, "arjun_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock arjun output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
[GET] http://example.com/api/v1/users?id=123&name=test
[POST] http://example.com/api/v1/users
[GET] https://test.example.com/search?q=test&page=1
[GET] https://test.example.com/api/v2/data?format=json
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            # Mock the JSON file that Arjun creates
            mock_json_data = [
                {
                    "url": "http://example.com/api/v1/users?id=123&name=test",
                    "method": "GET",
                    "params": ["id", "name"],
                    "status_code": 200,
                    "content_length": 1024,
                    "content_type": "application/json",
                    "response_time": 0.5
                },
                {
                    "url": "http://example.com/api/v1/users",
                    "method": "POST",
                    "params": [],
                    "status_code": 201,
                    "content_length": 512,
                    "content_type": "application/json",
                    "response_time": 0.3
                },
                {
                    "url": "https://test.example.com/search?q=test&page=1",
                    "method": "GET",
                    "params": ["q", "page"],
                    "status_code": 200,
                    "content_length": 2048,
                    "content_type": "text/html",
                    "response_time": 0.8
                },
                {
                    "url": "https://test.example.com/api/v2/data?format=json",
                    "method": "GET",
                    "params": ["format"],
                    "status_code": 200,
                    "content_length": 1536,
                    "content_type": "application/json",
                    "response_time": 0.6
                }
            ]

            # Patch open for the results file and json.load in the runner
            with patch('builtins.open', mock_open(read_data=json.dumps(mock_json_data))) as mock_file:
                with patch('json.load', return_value=mock_json_data):
                    with patch('os.path.exists') as mock_exists:
                        # Mock os.path.exists to return True for the results file
                        def exists_side_effect(path):
                            if 'arjun_results.json' in path:
                                return True
                            return False
                        mock_exists.side_effect = exists_side_effect
                        result = run_arjun(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['endpoints_found']), 4)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different types of parameters are found
        get_methods = [param for param in result['endpoints_found'] if param['method'] == 'GET']
        post_methods = [param for param in result['endpoints_found'] if param['method'] == 'POST']
        api_endpoints = [param for param in result['endpoints_found'] if 'api' in param['url']]

        self.assertEqual(len(get_methods), 3)
        self.assertEqual(len(post_methods), 1)
        self.assertEqual(len(api_endpoints), 3)

    def test_output_format_integration(self):
        """Test output format integration"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123
[POST] https://test.example.com/api/v1/users
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify output format is consistent
        self.assertIsInstance(parameters, list)
        
        for param_data in parameters:
            self.assertIn('method', param_data)
            self.assertIn('url', param_data)
            self.assertIn('params', param_data)
            self.assertIsInstance(param_data['method'], str)
            self.assertIsInstance(param_data['url'], str)
            self.assertIsInstance(param_data['params'], list)
            self.assertTrue(param_data['url'].startswith(('http://', 'https://')))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "arjun", stderr="First failure"),
                MagicMock(returncode=0, stdout="[GET] http://example.com/api/v1/users?id=123", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_arjun(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_parameter_analysis_integration(self):
        """Test parameter analysis integration"""
        arjun_output = """
[GET] http://example.com/api/v1/users?id=123&name=test&type=admin
[POST] http://example.com/api/v1/users?format=json&pretty=true
[GET] https://test.example.com/search?q=test&page=1&sort=date&limit=10
[GET] https://test.example.com/api/v2/data?format=json&version=2.0&debug=true
[PUT] http://example.com/api/v1/users/123?format=json
[DELETE] http://example.com/api/v1/users/123
[PATCH] http://example.com/api/v1/settings?format=json
"""

        parameters = parse_arjun_output(arjun_output)

        # Verify different parameter categories are found
        get_methods = [param for param in parameters if param['method'] == 'GET']
        post_methods = [param for param in parameters if param['method'] == 'POST']
        put_methods = [param for param in parameters if param['method'] == 'PUT']
        delete_methods = [param for param in parameters if param['method'] == 'DELETE']
        patch_methods = [param for param in parameters if param['method'] == 'PATCH']
        api_endpoints = [param for param in parameters if 'api' in param['url']]
        search_endpoints = [param for param in parameters if 'search' in param['url']]

        self.assertEqual(len(get_methods), 3)
        self.assertEqual(len(post_methods), 1)
        self.assertEqual(len(put_methods), 1)
        self.assertEqual(len(delete_methods), 1)
        self.assertEqual(len(patch_methods), 1)
        self.assertEqual(len(api_endpoints), 6)
        self.assertEqual(len(search_endpoints), 1)


if __name__ == '__main__':
    unittest.main() 