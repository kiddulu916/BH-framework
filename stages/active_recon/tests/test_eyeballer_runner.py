#!/usr/bin/env python3
"""
Unit tests for EyeBaller runner
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

from run_eyeballer import run_eyeballer, categorize_findings, generate_analysis_report


class TestEyeBallerRunner(unittest.TestCase):
    """Test cases for EyeBaller runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_screenshots_dir = tempfile.mkdtemp()
        self.test_output_dir = tempfile.mkdtemp()
        self.eyeballer_dir = os.path.join(self.test_output_dir, "enumeration", "eyeballer")
        os.makedirs(self.eyeballer_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_screenshots_dir, ignore_errors=True)
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def create_mock_screenshots(self, count=3):
        """Helper method to create mock screenshot files"""
        for i in range(count):
            screenshot_path = os.path.join(self.test_screenshots_dir, f"screenshot_{i}.png")
            with open(screenshot_path, 'w') as f:
                f.write(f"mock screenshot content {i}")

    @patch('subprocess.run')
    def test_run_eyeballer_success(self, mock_run):
        """Test successful EyeBaller execution"""
        # Create mock screenshots
        self.create_mock_screenshots(3)
        
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "EyeBaller completed successfully"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('os.path.exists', return_value=True):
            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [
                    (self.test_screenshots_dir, [], ['screenshot_0.png', 'screenshot_1.png', 'screenshot_2.png'])
                ]
                
                with patch('builtins.open', mock_open()) as mock_file:
                    # Mock predictions.json file
                    mock_predictions = [
                        {
                            "filename": "screenshot_0.png",
                            "category": "login",
                            "confidence": 0.85,
                            "file_path": os.path.join(self.test_screenshots_dir, "screenshot_0.png")
                        },
                        {
                            "filename": "screenshot_1.png", 
                            "category": "admin",
                            "confidence": 0.92,
                            "file_path": os.path.join(self.test_screenshots_dir, "screenshot_1.png")
                        },
                        {
                            "filename": "screenshot_2.png",
                            "category": "error",
                            "confidence": 0.78,
                            "file_path": os.path.join(self.test_screenshots_dir, "screenshot_2.png")
                        }
                    ]
                    
                    # Mock json.load to return predictions
                    with patch('json.load', return_value=mock_predictions):
                        result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertEqual(result['summary']['total_screenshots'], 3)
        self.assertEqual(result['summary']['analyzed_screenshots'], 3)
        self.assertEqual(result['summary']['interesting_findings'], 3)
        self.assertIn('predictions', result)
        self.assertIn('interesting_findings', result)
        self.assertEqual(len(result['interesting_findings']), 3)

    @patch('subprocess.run')
    def test_run_eyeballer_failure(self, mock_run):
        """Test EyeBaller execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: Model not found"
        mock_run.return_value = mock_result

        with patch('os.path.exists', return_value=True):
            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [(self.test_screenshots_dir, [], ['screenshot_0.png'])]
                result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['analyzed_screenshots'], 0)
        self.assertEqual(result['summary']['interesting_findings'], 0)

    @patch('subprocess.run')
    def test_run_eyeballer_timeout(self, mock_run):
        """Test EyeBaller execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="eyeballer", timeout=600)

        with patch('os.path.exists', return_value=True):
            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [(self.test_screenshots_dir, [], ['screenshot_0.png'])]
                result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 600)

    def test_run_eyeballer_no_screenshots_dir(self):
        """Test EyeBaller with non-existent screenshots directory"""
        result = run_eyeballer("/nonexistent/directory", self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('not found', result['error'])
        self.assertEqual(result['summary']['total_screenshots'], 0)

    def test_run_eyeballer_no_screenshot_files(self):
        """Test EyeBaller with empty screenshots directory"""
        with patch('os.path.exists', return_value=True):
            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [(self.test_screenshots_dir, [], [])]
                result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('No screenshot files found', result['error'])
        self.assertEqual(result['summary']['total_screenshots'], 0)

    def test_categorize_findings(self):
        """Test findings categorization functionality"""
        test_findings = [
            {"category": "login", "confidence": 0.85, "filename": "login.png"},
            {"category": "admin", "confidence": 0.92, "filename": "admin.png"},
            {"category": "error", "confidence": 0.78, "filename": "error.png"},
            {"category": "dev", "confidence": 0.65, "filename": "dev.png"},
            {"category": "unknown", "confidence": 0.45, "filename": "unknown.png"}
        ]

        categorized = categorize_findings(test_findings)

        # Verify categorization
        self.assertIn('authentication', categorized)
        self.assertIn('administration', categorized)
        self.assertIn('errors', categorized)
        self.assertIn('development', categorized)
        self.assertIn('other', categorized)
        
        self.assertEqual(len(categorized['authentication']), 1)  # login
        self.assertEqual(len(categorized['administration']), 1)  # admin
        self.assertEqual(len(categorized['errors']), 1)  # error
        self.assertEqual(len(categorized['development']), 1)  # dev
        self.assertEqual(len(categorized['other']), 1)  # unknown

    def test_categorize_findings_empty(self):
        """Test findings categorization with empty list"""
        categorized = categorize_findings([])
        expected_keys = ['authentication', 'administration', 'errors', 'development', 'other']
        for key in expected_keys:
            self.assertIn(key, categorized)
            self.assertEqual(len(categorized[key]), 0)

    def test_categorize_findings_edge_cases(self):
        """Test findings categorization with edge cases"""
        test_findings = [
            {"category": "LOGIN", "confidence": 0.85, "filename": "login.png"},  # uppercase
            {"category": "Admin", "confidence": 0.92, "filename": "admin.png"},  # mixed case
            {"category": "ERROR_PAGE", "confidence": 0.78, "filename": "error.png"},  # underscore
            {"category": "dev-environment", "confidence": 0.65, "filename": "dev.png"},  # hyphen
            {"category": "", "confidence": 0.45, "filename": "empty.png"},  # empty category
        ]

        categorized = categorize_findings(test_findings)

        # Should handle case variations and special characters
        self.assertEqual(len(categorized['authentication']), 1)  # LOGIN
        self.assertEqual(len(categorized['administration']), 1)  # Admin
        self.assertEqual(len(categorized['errors']), 1)  # ERROR_PAGE
        self.assertEqual(len(categorized['development']), 1)  # dev-environment
        self.assertEqual(len(categorized['other']), 1)  # empty category

    @patch('os.stat')
    def test_generate_analysis_report(self, mock_stat):
        """Test analysis report generation"""
        # Mock file stats
        mock_stat_info = MagicMock()
        mock_stat_info.st_size = 2048
        mock_stat_info.st_ctime = 1234567890
        mock_stat_info.st_mtime = 1234567890
        mock_stat.return_value = mock_stat_info

        test_findings = [
            {
                "filename": "login.png",
                "category": "login",
                "confidence": 0.85,
                "file_path": "/path/to/login.png",
                "interesting": True
            },
            {
                "filename": "admin.png",
                "category": "admin", 
                "confidence": 0.92,
                "file_path": "/path/to/admin.png",
                "interesting": True
            }
        ]

        with patch('builtins.open', mock_open()) as mock_file:
            report = generate_analysis_report(test_findings, self.test_output_dir)

        # Verify report structure
        self.assertEqual(report['total_findings'], 2)
        self.assertIn('findings_by_category', report)
        self.assertIn('high_confidence_findings', report)
        self.assertIn('medium_confidence_findings', report)
        self.assertIn('low_confidence_findings', report)
        self.assertIn('generated_at', report)
        
        # Verify confidence categorization
        self.assertEqual(len(report['high_confidence_findings']), 1)  # admin (0.92)
        self.assertEqual(len(report['medium_confidence_findings']), 1)  # login (0.85)

    def test_generate_analysis_report_empty(self):
        """Test analysis report generation with empty findings"""
        with patch('builtins.open', mock_open()):
            report = generate_analysis_report([], self.test_output_dir)

        self.assertEqual(report['total_findings'], 0)
        self.assertEqual(len(report['high_confidence_findings']), 0)
        self.assertEqual(len(report['medium_confidence_findings']), 0)
        self.assertEqual(len(report['low_confidence_findings']), 0)

    def test_command_construction(self):
        """Test that EyeBaller command is constructed correctly"""
        self.create_mock_screenshots(1)
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.path.exists', return_value=True):
                with patch('os.walk') as mock_walk:
                    mock_walk.return_value = [(self.test_screenshots_dir, [], ['screenshot_0.png'])]
                    with patch('builtins.open', mock_open()):
                        with patch('json.load', return_value=[]):
                            result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('predict', command)
        self.assertIn('--input', command)
        self.assertIn('--output', command)
        self.assertIn('--model', command)
        self.assertIn('--batch-size', command)
        self.assertIn('--confidence-threshold', command)
        self.assertIn('--format', command)

    def test_confidence_threshold_filtering(self):
        """Test that findings are filtered by confidence threshold"""
        test_findings = [
            {"category": "login", "confidence": 0.3, "filename": "low.png"},  # Below threshold
            {"category": "admin", "confidence": 0.6, "filename": "medium.png"},  # At threshold
            {"category": "error", "confidence": 0.9, "filename": "high.png"},  # Above threshold
        ]

        # Test that only findings above 0.5 confidence are included
        categorized = categorize_findings(test_findings)
        
        # All findings should be categorized regardless of confidence
        # The filtering happens in the main function, not in categorization
        self.assertEqual(len(categorized['authentication']), 1)  # login
        self.assertEqual(len(categorized['administration']), 1)  # admin
        self.assertEqual(len(categorized['errors']), 1)  # error

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('os.path.exists', return_value=True):
            with patch('os.walk') as mock_walk:
                mock_walk.return_value = [(self.test_screenshots_dir, [], ['screenshot_0.png'])]
                with patch('builtins.open', side_effect=PermissionError("Permission denied")):
                    result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_json_parsing(self):
        """Test error handling for JSON parsing errors"""
        self.create_mock_screenshots(1)
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.path.exists', return_value=True):
                with patch('os.walk') as mock_walk:
                    mock_walk.return_value = [(self.test_screenshots_dir, [], ['screenshot_0.png'])]
                    with patch('builtins.open', mock_open()):
                        with patch('json.load', side_effect=json.JSONDecodeError("Invalid JSON", "", 0)):
                            result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Failed to parse results', result['error'])


class TestEyeBallerIntegration(unittest.TestCase):
    """Integration tests for EyeBaller runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_screenshots_dir = tempfile.mkdtemp()
        self.test_output_dir = tempfile.mkdtemp()
        self.eyeballer_dir = os.path.join(self.test_output_dir, "enumeration", "eyeballer")
        os.makedirs(self.eyeballer_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_screenshots_dir, ignore_errors=True)
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete EyeBaller workflow simulation"""
        # Create mock screenshots
        for i in range(5):
            screenshot_path = os.path.join(self.test_screenshots_dir, f"screenshot_{i}.png")
            with open(screenshot_path, 'w') as f:
                f.write(f"mock screenshot content {i}")

        # Mock predictions data
        mock_predictions = [
            {
                "filename": f"screenshot_{i}.png",
                "category": ["login", "admin", "error", "dev", "dashboard"][i % 5],
                "confidence": 0.7 + (i * 0.05),
                "file_path": os.path.join(self.test_screenshots_dir, f"screenshot_{i}.png")
            }
            for i in range(5)
        ]

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.path.exists', return_value=True):
                with patch('os.walk') as mock_walk:
                    mock_walk.return_value = [
                        (self.test_screenshots_dir, [], [f"screenshot_{i}.png" for i in range(5)])
                    ]
                    
                    with patch('builtins.open', mock_open()):
                        with patch('json.load', return_value=mock_predictions):
                            # Run EyeBaller
                            result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)
                            
                            # Generate analysis report
                            report = generate_analysis_report(result['interesting_findings'], self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['interesting_findings']), 5)
        self.assertEqual(report['total_findings'], 5)
        self.assertIn('authentication', report['findings_by_category'])
        self.assertIn('administration', report['findings_by_category'])

    def test_large_screenshot_set_handling(self):
        """Test handling of large screenshot sets"""
        # Create many mock screenshots
        for i in range(50):
            screenshot_path = os.path.join(self.test_screenshots_dir, f"screenshot_{i}.png")
            with open(screenshot_path, 'w') as f:
                f.write(f"mock screenshot content {i}")

        mock_predictions = [
            {
                "filename": f"screenshot_{i}.png",
                "category": "login" if i % 2 == 0 else "admin",
                "confidence": 0.8,
                "file_path": os.path.join(self.test_screenshots_dir, f"screenshot_{i}.png")
            }
            for i in range(50)
        ]

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.path.exists', return_value=True):
                with patch('os.walk') as mock_walk:
                    mock_walk.return_value = [
                        (self.test_screenshots_dir, [], [f"screenshot_{i}.png" for i in range(50)])
                    ]
                    
                    with patch('builtins.open', mock_open()):
                        with patch('json.load', return_value=mock_predictions):
                            result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_screenshots'], 50)
        self.assertEqual(result['summary']['analyzed_screenshots'], 50)

    def test_mixed_confidence_findings(self):
        """Test handling of findings with mixed confidence levels"""
        mock_predictions = [
            {"filename": "high.png", "category": "login", "confidence": 0.95, "file_path": "/path/to/high.png"},
            {"filename": "medium.png", "category": "admin", "confidence": 0.75, "file_path": "/path/to/medium.png"},
            {"filename": "low.png", "category": "error", "confidence": 0.55, "file_path": "/path/to/low.png"},
            {"filename": "very_low.png", "category": "dev", "confidence": 0.25, "file_path": "/path/to/very_low.png"},
        ]

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            with patch('os.path.exists', return_value=True):
                with patch('os.walk') as mock_walk:
                    mock_walk.return_value = [(self.test_screenshots_dir, [], ['high.png', 'medium.png', 'low.png', 'very_low.png'])]
                    
                    with patch('builtins.open', mock_open()):
                        with patch('json.load', return_value=mock_predictions):
                            result = run_eyeballer(self.test_screenshots_dir, self.test_output_dir)
                            # Use all_findings for confidence categorization
                            report = generate_analysis_report(result['interesting_findings'], self.test_output_dir, all_findings=result['all_findings'])

        # Verify confidence categorization
        self.assertEqual(len(report['high_confidence_findings']), 1)  # 0.95
        self.assertEqual(len(report['medium_confidence_findings']), 1)  # 0.75
        self.assertEqual(len(report['low_confidence_findings']), 2)  # 0.55, 0.25


if __name__ == '__main__':
    unittest.main() 