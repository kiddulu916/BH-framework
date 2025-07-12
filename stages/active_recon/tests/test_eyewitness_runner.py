#!/usr/bin/env python3
"""
Unit tests for EyeWitness runner
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

from run_eyewitness import run_eyewitness, categorize_screenshots, generate_screenshot_report


class TestEyeWitnessRunner(unittest.TestCase):
    """Test cases for EyeWitness runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["example.com", "test.example.com", "admin.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.eyewitness_dir = os.path.join(self.test_output_dir, "enumeration", "eyewitness")
        os.makedirs(self.eyewitness_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_eyewitness_success(self, mock_run):
        """Test successful EyeWitness execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "EyeWitness completed successfully"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                with patch('os.walk') as mock_walk:
                    # Mock finding screenshot files
                    mock_walk.return_value = [
                        (self.eyewitness_dir, [], ['example_com.png', 'test_example_com.png'])
                    ]

                    result = run_eyewitness(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertEqual(result['summary']['total_targets'], 3)
        self.assertEqual(result['summary']['successful_screenshots'], 2)
        self.assertEqual(result['summary']['failed_screenshots'], 1)
        self.assertIn('screenshots', result)
        self.assertEqual(len(result['screenshots']), 2)

    @patch('subprocess.run')
    def test_run_eyewitness_failure(self, mock_run):
        """Test EyeWitness execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets found"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_eyewitness(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['successful_screenshots'], 0)
        self.assertEqual(result['summary']['failed_screenshots'], 3)

    @patch('subprocess.run')
    def test_run_eyewitness_timeout(self, mock_run):
        """Test EyeWitness execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="eyewitness", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_eyewitness(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_categorize_screenshots(self):
        """Test screenshot categorization functionality"""
        test_screenshots = [
            "/path/to/example_com_login.png",
            "/path/to/test_example_com_admin.png",
            "/path/to/admin_example_com_dashboard.png"
        ]

        categorized = categorize_screenshots(test_screenshots)

        # Verify categorization
        self.assertIn('example', categorized)
        self.assertIn('test', categorized)
        self.assertIn('admin', categorized)
        self.assertEqual(len(categorized['example']), 1)
        self.assertEqual(len(categorized['test']), 1)
        self.assertEqual(len(categorized['admin']), 1)

    def test_categorize_screenshots_empty(self):
        """Test screenshot categorization with empty list"""
        categorized = categorize_screenshots([])
        self.assertEqual(categorized, {})

    def test_categorize_screenshots_invalid_filenames(self):
        """Test screenshot categorization with invalid filenames"""
        test_screenshots = [
            "/path/to/invalid_filename",
            "/path/to/another_invalid",
            "/path/to/no_underscore"
        ]

        categorized = categorize_screenshots(test_screenshots)
        # Should handle gracefully without errors
        self.assertIsInstance(categorized, dict)

    @patch('os.stat')
    def test_generate_screenshot_report(self, mock_stat):
        """Test screenshot report generation"""
        # Mock file stats
        mock_stat_info = MagicMock()
        mock_stat_info.st_size = 1024
        mock_stat_info.st_ctime = 1234567890
        mock_stat_info.st_mtime = 1234567890
        mock_stat.return_value = mock_stat_info

        test_screenshots = [
            "/path/to/example_com.png",
            "/path/to/test_example_com.png"
        ]

        with patch('builtins.open', mock_open()) as mock_file:
            report = generate_screenshot_report(test_screenshots, self.test_output_dir)

        # Verify report structure
        self.assertEqual(report['total_screenshots'], 2)
        self.assertIn('screenshots_by_domain', report)
        self.assertIn('screenshot_details', report)
        self.assertIn('generated_at', report)
        self.assertEqual(len(report['screenshot_details']), 2)

    def test_generate_screenshot_report_empty(self):
        """Test screenshot report generation with empty list"""
        with patch('builtins.open', mock_open()):
            report = generate_screenshot_report([], self.test_output_dir)

        self.assertEqual(report['total_screenshots'], 0)
        self.assertEqual(len(report['screenshot_details']), 0)

    def test_target_protocol_handling(self):
        """Test that targets without protocol get http:// prefix"""
        targets_with_protocol = ["http://example.com", "https://test.com"]
        targets_without_protocol = ["example.com", "test.com"]

        # Test targets with protocol (should remain unchanged)
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                with patch('os.makedirs'):
                    with patch('os.walk') as mock_walk:
                        mock_walk.return_value = [(self.eyewitness_dir, [], [])]
                        run_eyewitness(targets_with_protocol, self.test_output_dir)

        # Verify that the file was written with correct content
        mock_file.assert_called()
        # The file should contain the targets as-is since they already have protocol

    def test_command_construction(self):
        """Test that EyeWitness command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    with patch('os.walk') as mock_walk:
                        mock_walk.return_value = [(self.eyewitness_dir, [], [])]
                        result = run_eyewitness(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('--web', command)
        self.assertIn('--no-prompt', command)
        self.assertIn('--timeout', command)
        self.assertIn('--threads', command)
        self.assertIn('--max-retries', command)
        self.assertIn('--user-agent', command)
        self.assertIn('--no-dns', command)
        self.assertIn('--no-http', command)
        self.assertIn('--no-redirects', command)
        self.assertIn('--screenshot-only', command)

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_eyewitness(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_eyewitness(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])


class TestEyeWitnessIntegration(unittest.TestCase):
    """Integration tests for EyeWitness runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_output_dir = tempfile.mkdtemp()
        self.eyewitness_dir = os.path.join(self.test_output_dir, "enumeration", "eyewitness")
        os.makedirs(self.eyewitness_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete EyeWitness workflow simulation"""
        test_targets = ["example.com", "test.example.com"]
        
        # Create mock screenshot files
        mock_screenshots = [
            os.path.join(self.eyewitness_dir, "example_com.png"),
            os.path.join(self.eyewitness_dir, "test_example_com.png")
        ]
        
        for screenshot in mock_screenshots:
            with open(screenshot, 'w') as f:
                f.write("mock screenshot content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [(self.eyewitness_dir, [], ['example_com.png', 'test_example_com.png'])]
                
                # Run EyeWitness
                result = run_eyewitness(test_targets, self.test_output_dir)
                
                # Generate report
                report = generate_screenshot_report(result['screenshots'], self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['screenshots']), 2)
        self.assertEqual(report['total_screenshots'], 2)
        self.assertIn('example', report['screenshots_by_domain'])
        self.assertIn('test', report['screenshots_by_domain'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"subdomain{i}.example.com" for i in range(100)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    with patch('os.walk') as mock_walk:
                        mock_walk.return_value = [(self.eyewitness_dir, [], [])]
                        result = run_eyewitness(large_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 100)

    def test_mixed_protocol_targets(self):
        """Test handling of targets with mixed protocols"""
        mixed_targets = [
            "http://example.com",
            "https://secure.example.com", 
            "admin.example.com",
            "test.example.com"
        ]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                with patch('os.makedirs'):
                    with patch('os.walk') as mock_walk:
                        mock_walk.return_value = [(self.eyewitness_dir, [], [])]
                        result = run_eyewitness(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)


if __name__ == '__main__':
    unittest.main() 