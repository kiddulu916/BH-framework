#!/usr/bin/env python3
"""
Tests for Active Recon runner utilities
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import sys
from datetime import datetime

# Add parent directory to path to import utils
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'runners'))

from utils import save_raw_to_db, save_parsed_to_db


class TestRunnerUtils(unittest.TestCase):
    """Test cases for runner utility functions"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_api_url = "http://backend:8000/api/results/active_recon"
        self.test_jwt_token = "test_jwt_token"
        self.test_target = "example.com"
        self.test_tool_name = "nmap"

    def tearDown(self):
        """Clean up test fixtures"""
        pass

    @patch('requests.post')
    def test_save_raw_to_db_success(self, mock_post):
        """Test successful raw data submission to database"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'message': 'Raw data saved'}
        mock_post.return_value = mock_response

        # Test data
        test_file_path = "/path/to/raw_data.txt"
        test_data = {'tool_name': self.test_tool_name, 'target_id': self.test_target}

        # Mock file operations
        with patch('builtins.open', mock_open(read_data="raw data content")):
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                test_file_path,
                self.test_api_url,
                self.test_jwt_token
            )

        # Verify result
        self.assertTrue(result)
        mock_post.assert_called_once()

        # Verify API call parameters
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], f"{self.test_api_url}/raw")
        
        # Verify headers
        headers = call_args[1]['headers']
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], f'Bearer {self.test_jwt_token}')

    @patch('requests.post')
    def test_save_raw_to_db_failure(self, mock_post):
        """Test raw data submission failure"""
        # Mock failed API response
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {'success': False, 'error': 'Database error'}
        mock_post.return_value = mock_response

        test_file_path = "/path/to/raw_data.txt"

        with patch('builtins.open', mock_open(read_data="raw data content")):
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                test_file_path,
                self.test_api_url,
                self.test_jwt_token
            )

        # Verify result
        self.assertFalse(result)

    @patch('requests.post')
    def test_save_raw_to_db_file_not_found(self, mock_post):
        """Test raw data submission with non-existent file"""
        test_file_path = "/nonexistent/file.txt"

        with patch('builtins.open', side_effect=FileNotFoundError("File not found")):
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                test_file_path,
                self.test_api_url,
                self.test_jwt_token
            )

        # Verify result
        self.assertFalse(result)
        mock_post.assert_not_called()

    @patch('requests.post')
    def test_save_raw_to_db_network_error(self, mock_post):
        """Test raw data submission with network error"""
        # Mock network error
        mock_post.side_effect = Exception("Network error")

        test_file_path = "/path/to/raw_data.txt"

        with patch('builtins.open', mock_open(read_data="raw data content")):
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                test_file_path,
                self.test_api_url,
                self.test_jwt_token
            )

        # Verify result
        self.assertFalse(result)

    @patch('requests.post')
    def test_save_parsed_to_db_success(self, mock_post):
        """Test successful parsed data submission to database"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'message': 'Parsed data saved'}
        mock_post.return_value = mock_response

        # Test data
        test_data = {
            'tool_name': self.test_tool_name,
            'target_id': self.test_target,
            'target': self.test_target,
            'data': {
                'hosts': [
                    {
                        'hostname': 'example.com',
                        'ports': [{'port': 80, 'service': 'http'}]
                    }
                ],
                'summary': {'total_hosts': 1, 'total_ports': 1}
            }
        }

        result = save_parsed_to_db(
            self.test_tool_name,
            self.test_target,
            test_data,
            self.test_api_url,
            self.test_jwt_token
        )

        # Verify result
        self.assertTrue(result)
        mock_post.assert_called_once()

        # Verify API call parameters
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], f"{self.test_api_url}/parsed")
        
        # Verify payload
        payload = call_args[1]['json']
        self.assertEqual(payload['tool_name'], self.test_tool_name)
        self.assertEqual(payload['target_id'], self.test_target)
        self.assertEqual(payload['target'], self.test_target)
        self.assertIn('data', payload)

        # Verify headers
        headers = call_args[1]['headers']
        self.assertIn('Authorization', headers)
        self.assertEqual(headers['Authorization'], f'Bearer {self.test_jwt_token}')

    @patch('requests.post')
    def test_save_parsed_to_db_failure(self, mock_post):
        """Test parsed data submission failure"""
        # Mock failed API response
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'success': False, 'error': 'Invalid data'}
        mock_post.return_value = mock_response

        test_data = {'tool_name': self.test_tool_name, 'target_id': self.test_target}

        result = save_parsed_to_db(
            self.test_tool_name,
            self.test_target,
            test_data,
            self.test_api_url,
            self.test_jwt_token
        )

        # Verify result
        self.assertFalse(result)

    @patch('requests.post')
    def test_save_parsed_to_db_network_error(self, mock_post):
        """Test parsed data submission with network error"""
        # Mock network error
        mock_post.side_effect = Exception("Network error")

        test_data = {'tool_name': self.test_tool_name, 'target_id': self.test_target}

        result = save_parsed_to_db(
            self.test_tool_name,
            self.test_target,
            test_data,
            self.test_api_url,
            self.test_jwt_token
        )

        # Verify result
        self.assertFalse(result)

    def test_save_raw_to_db_invalid_parameters(self):
        """Test raw data submission with invalid parameters"""
        # Test with None values
        result = save_raw_to_db(None, None, None, None, None)
        self.assertFalse(result)

        # Test with empty strings
        result = save_raw_to_db("", "", "", "", "")
        self.assertFalse(result)

    def test_save_parsed_to_db_invalid_parameters(self):
        """Test parsed data submission with invalid parameters"""
        # Test with None values
        result = save_parsed_to_db(None, None, None, None, None)
        self.assertFalse(result)

        # Test with empty strings
        result = save_parsed_to_db("", "", {}, "", "")
        self.assertFalse(result)

    @patch('requests.post')
    def test_save_raw_to_db_large_file(self, mock_post):
        """Test raw data submission with large file"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'message': 'Large file saved'}
        mock_post.return_value = mock_response

        # Create a large mock file content
        large_content = "x" * 1024 * 1024  # 1MB of data
        test_file_path = "/path/to/large_file.txt"

        with patch('builtins.open', mock_open(read_data=large_content)):
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                test_file_path,
                self.test_api_url,
                self.test_jwt_token
            )

        # Verify result
        self.assertTrue(result)
        mock_post.assert_called_once()

    @patch('requests.post')
    def test_save_parsed_to_db_complex_data(self, mock_post):
        """Test parsed data submission with complex data structure"""
        # Mock successful API response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'message': 'Complex data saved'}
        mock_post.return_value = mock_response

        # Complex test data
        complex_data = {
            'tool_name': self.test_tool_name,
            'target_id': self.test_target,
            'target': self.test_target,
            'data': {
                'hosts': [
                    {
                        'hostname': 'example.com',
                        'ip': '93.184.216.34',
                        'ports': [
                            {'port': 80, 'service': 'http', 'state': 'open'},
                            {'port': 443, 'service': 'https', 'state': 'open'},
                            {'port': 22, 'service': 'ssh', 'state': 'open'}
                        ],
                        'os_info': {'os': 'Linux', 'version': '4.19.0'},
                        'services': [
                            {'port': 80, 'service': 'http', 'product': 'Apache', 'version': '2.4.41'},
                            {'port': 443, 'service': 'https', 'product': 'Apache', 'version': '2.4.41'}
                        ]
                    },
                    {
                        'hostname': 'www.example.com',
                        'ip': '93.184.216.34',
                        'ports': [
                            {'port': 80, 'service': 'http', 'state': 'open'}
                        ],
                        'os_info': {'os': 'Linux', 'version': '4.19.0'},
                        'services': [
                            {'port': 80, 'service': 'http', 'product': 'Apache', 'version': '2.4.41'}
                        ]
                    }
                ],
                'summary': {
                    'total_hosts': 2,
                    'total_ports': 4,
                    'total_services': 3,
                    'open_ports': [80, 443, 22],
                    'web_ports': [80, 443],
                    'technologies': ['Apache', 'Linux']
                },
                'metadata': {
                    'scan_start': '2024-01-01T00:00:00Z',
                    'scan_end': '2024-01-01T00:05:00Z',
                    'scan_duration': 300,
                    'tool_version': '7.80',
                    'scan_type': 'comprehensive'
                }
            }
        }

        result = save_parsed_to_db(
            self.test_tool_name,
            self.test_target,
            complex_data['data'],  # Pass only the data portion
            self.test_api_url,
            self.test_jwt_token
        )

        # Verify result
        self.assertTrue(result)
        mock_post.assert_called_once()

        # Verify complex data was sent correctly
        call_args = mock_post.call_args
        payload = call_args[1]['json']
        
        # Check that complex structure is preserved
        self.assertIn('hosts', payload['data'])
        self.assertEqual(len(payload['data']['hosts']), 2)
        self.assertIn('summary', payload['data'])
        self.assertIn('metadata', payload['data'])
        
        # Verify the structure is preserved correctly
        self.assertIsInstance(payload['data']['hosts'], list)
        self.assertIsInstance(payload['data']['summary'], dict)
        self.assertIsInstance(payload['data']['metadata'], dict)

    @patch('requests.post')
    def test_concurrent_api_calls(self, mock_post):
        """Test concurrent API calls to the utility functions"""
        # Mock successful API responses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'message': 'Data saved'}
        mock_post.return_value = mock_response

        # Test multiple concurrent calls
        import threading
        import time

        results = []

        def make_api_call(call_type, index):
            if call_type == 'raw':
                with patch('builtins.open', mock_open(read_data=f"raw data {index}")):
                    result = save_raw_to_db(
                        f"tool_{index}",
                        f"target_{index}",
                        f"/path/to/file_{index}.txt",
                        self.test_api_url,
                        self.test_jwt_token
                    )
            else:  # parsed
                result = save_parsed_to_db(
                    f"tool_{index}",
                    f"target_{index}",
                    {'data': f'parsed data {index}'},
                    self.test_api_url,
                    self.test_jwt_token
                )
            results.append((call_type, index, result))

        # Create multiple threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_api_call, args=('raw', i))
            threads.append(thread)
            thread = threading.Thread(target=make_api_call, args=('parsed', i))
            threads.append(thread)

        # Start all threads
        for thread in threads:
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all calls were successful
        self.assertEqual(len(results), 20)  # 10 raw + 10 parsed
        for call_type, index, result in results:
            self.assertTrue(result, f"Call {call_type}_{index} failed")

        # Verify all API calls were made
        self.assertEqual(mock_post.call_count, 20)

    def test_error_logging(self):
        """Test error logging in utility functions"""
        # Test that errors are properly logged (this would require checking log output)
        # For now, we'll test that functions handle errors gracefully
        
        with patch('requests.post', side_effect=Exception("Test error")):
            # Test raw data submission error
            result = save_raw_to_db(
                self.test_tool_name,
                self.test_target,
                "/path/to/file.txt",
                self.test_api_url,
                self.test_jwt_token
            )
            self.assertFalse(result)

            # Test parsed data submission error
            result = save_parsed_to_db(
                self.test_tool_name,
                self.test_target,
                {'data': 'test'},
                self.test_api_url,
                self.test_jwt_token
            )
            self.assertFalse(result)


class TestRunnerUtilsEdgeCases(unittest.TestCase):
    """Test edge cases for runner utility functions"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_api_url = "http://backend:8000/api/results/active_recon"
        self.test_jwt_token = "test_jwt_token"

    def test_unicode_handling(self):
        """Test handling of Unicode characters in data"""
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True}
            mock_post.return_value = mock_response

            # Test Unicode characters in file content
            unicode_content = "测试数据 with unicode: 🚀 🔍 💻"
            test_file_path = "/path/to/unicode_file.txt"

            with patch('builtins.open', mock_open(read_data=unicode_content)):
                result = save_raw_to_db(
                    "test_tool",
                    "test_target",
                    test_file_path,
                    self.test_api_url,
                    self.test_jwt_token
                )

            self.assertTrue(result)

            # Test Unicode characters in parsed data
            unicode_data = {
                'tool_name': '测试工具',
                'target_id': 'test_target',
                'target': 'test_target',
                'data': {
                    'hosts': [
                        {
                            'hostname': '测试.example.com',
                            'description': '测试服务器 with unicode 🚀'
                        }
                    ]
                }
            }

            result = save_parsed_to_db(
                "test_tool",
                "test_target",
                unicode_data,
                self.test_api_url,
                self.test_jwt_token
            )

            self.assertTrue(result)

    def test_special_characters_in_filenames(self):
        """Test handling of special characters in filenames"""
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True}
            mock_post.return_value = mock_response

            # Test various special characters in filenames
            special_filenames = [
                "/path/to/file with spaces.txt",
                "/path/to/file-with-dashes.txt",
                "/path/to/file_with_underscores.txt",
                "/path/to/file.with.dots.txt",
                "/path/to/file(with)parentheses.txt",
                "/path/to/file[with]brackets.txt",
                "/path/to/file{with}braces.txt",
                "/path/to/file<with>angles.txt",
                "/path/to/file&with&ampersands.txt",
                "/path/to/file#with#hashes.txt",
                "/path/to/file@with@ats.txt",
                "/path/to/file$with$dollars.txt",
                "/path/to/file%with%percents.txt",
                "/path/to/file^with^carets.txt",
                "/path/to/file*with*asterisks.txt",
                "/path/to/file+with+pluses.txt",
                "/path/to/file=with=equals.txt",
                "/path/to/file|with|pipes.txt",
                "/path/to/file\\with\\backslashes.txt",
                "/path/to/file/with/forward/slashes.txt"
            ]

            for filename in special_filenames:
                with patch('builtins.open', mock_open(read_data="test content")):
                    result = save_raw_to_db(
                        "test_tool",
                        "test_target",
                        filename,
                        self.test_api_url,
                        self.test_jwt_token
                    )
                    self.assertTrue(result, f"Failed with filename: {filename}")

    def test_very_long_data(self):
        """Test handling of very long data structures"""
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True}
            mock_post.return_value = mock_response

            # Create a very long data structure
            long_data = {
                'tool_name': 'test_tool',
                'target_id': 'test_target',
                'target': 'test_target',
                'data': {
                    'hosts': [
                        {
                            'hostname': f'host{i}.example.com',
                            'ports': [{'port': j, 'service': f'service{j}'} for j in range(100)],
                            'description': 'x' * 10000  # Very long description
                        }
                        for i in range(100)  # 100 hosts
                    ],
                    'summary': {
                        'total_hosts': 100,
                        'total_ports': 10000,
                        'details': 'x' * 50000  # Very long details
                    }
                }
            }

            result = save_parsed_to_db(
                "test_tool",
                "test_target",
                long_data,
                self.test_api_url,
                self.test_jwt_token
            )

            self.assertTrue(result)

    def test_empty_data_handling(self):
        """Test handling of empty data structures"""
        with patch('requests.post') as mock_post:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'success': True}
            mock_post.return_value = mock_response

            # Test empty parsed data
            empty_data = {
                'tool_name': 'test_tool',
                'target_id': 'test_target',
                'target': 'test_target',
                'data': {}
            }

            result = save_parsed_to_db(
                "test_tool",
                "test_target",
                empty_data,
                self.test_api_url,
                self.test_jwt_token
            )

            self.assertTrue(result)

            # Test empty file
            with patch('builtins.open', mock_open(read_data="")):
                result = save_raw_to_db(
                    "test_tool",
                    "test_target",
                    "/path/to/empty_file.txt",
                    self.test_api_url,
                    self.test_jwt_token
                )

            self.assertTrue(result)


if __name__ == '__main__':
    unittest.main() 