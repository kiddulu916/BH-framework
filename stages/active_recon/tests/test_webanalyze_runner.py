#!/usr/bin/env python3
"""
Unit tests for WebAnalyze runner
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

from run_webanalyze import run_webanalyze, parse_webanalyze_output


class TestWebAnalyzeRunner(unittest.TestCase):
    """Test cases for WebAnalyze runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.webanalyze_dir = os.path.join(self.test_output_dir, "technology_detection")
        os.makedirs(self.webanalyze_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_webanalyze_success(self, mock_run):
        """Test successful WebAnalyze execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
http://example.com,Apache,2.4.41,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,React,17.0.0,JavaScript Frameworks
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('technologies', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['technologies']), 5)
        self.assertEqual(result['summary']['total_technologies'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_webanalyze_failure(self, mock_run):
        """Test WebAnalyze execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_technologies'], 0)
        self.assertEqual(result['summary']['total_targets'], 2)

    @patch('subprocess.run')
    def test_run_webanalyze_timeout(self, mock_run):
        """Test WebAnalyze execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="webanalyze", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_webanalyze_output_success(self):
        """Test successful WebAnalyze output parsing"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,React,17.0.0,JavaScript Frameworks
https://test.example.com,MySQL,8.0.0,Database
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify parsing
        self.assertEqual(len(technologies), 6)
        
        # Check specific technologies
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP", "version": "7.4.0", "category": "Programming Languages"},
            {"url": "http://example.com", "technology": "jQuery", "version": "3.6.0", "category": "JavaScript Libraries"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"},
            {"url": "https://test.example.com", "technology": "React", "version": "17.0.0", "category": "JavaScript Frameworks"},
            {"url": "https://test.example.com", "technology": "MySQL", "version": "8.0.0", "category": "Database"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_parse_webanalyze_output_empty(self):
        """Test WebAnalyze output parsing with empty output"""
        webanalyze_output = ""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify no technologies found
        self.assertEqual(len(technologies), 0)

    def test_parse_webanalyze_output_invalid_format(self):
        """Test WebAnalyze output parsing with invalid format"""
        invalid_output = "This is not valid webanalyze output"

        technologies = parse_webanalyze_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(technologies), 0)

    def test_parse_webanalyze_output_mixed_formats(self):
        """Test WebAnalyze output parsing with mixed valid and invalid lines"""
        mixed_output = """
http://example.com,Apache,2.4.41,Server
invalid line
https://test.example.com,Nginx,1.18.0,Server
another invalid line
http://example.com,PHP,7.4.0,Programming Languages
"""

        technologies = parse_webanalyze_output(mixed_output)

        # Should only parse valid technology lines
        self.assertEqual(len(technologies), 3)
        
        # Check that valid technologies are parsed
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP", "version": "7.4.0", "category": "Programming Languages"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_command_construction(self):
        """Test that WebAnalyze command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com,Apache,2.4.41,Server"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('webanalyze', command)
        self.assertIn('-hosts', command)  # Hosts parameter
        self.assertIn('-output', command)  # Output parameter

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_webanalyze(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_webanalyze(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"http://subdomain{i}.example.com" for i in range(50)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "http://example.com,Apache,2.4.41,Server"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_webanalyze(large_targets, self.test_output_dir)

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
            mock_result.stdout = "http://example.com,Apache,2.4.41,Server"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_webanalyze(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_technology_deduplication(self):
        """Test technology deduplication functionality"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
http://example.com,Apache,2.4.41,Server
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,Nginx,1.18.0,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,PHP,7.4.0,Programming Languages
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify duplicates are handled (should be unique)
        unique_combinations = set()
        for tech_data in technologies:
            unique_combinations.add((tech_data['url'], tech_data['technology'], tech_data['version'], tech_data['category']))

        self.assertEqual(len(unique_combinations), 3)  # Should be unique combinations
        
        # Check specific unique combinations
        expected_combinations = [
            ("http://example.com", "Apache", "2.4.41", "Server"),
            ("https://test.example.com", "Nginx", "1.18.0", "Server"),
            ("http://example.com", "PHP", "7.4.0", "Programming Languages")
        ]
        
        for expected in expected_combinations:
            self.assertIn(expected, unique_combinations)

    def test_complex_technology_handling(self):
        """Test handling of complex technologies"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
http://example.com,Bootstrap,4.6.0,CSS Frameworks
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,React,17.0.0,JavaScript Frameworks
https://test.example.com,MySQL,8.0.0,Database
https://test.example.com,Redis,6.0.0,Database
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify complex technologies are parsed correctly
        self.assertEqual(len(technologies), 8)
        
        # Check specific complex technologies
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP", "version": "7.4.0", "category": "Programming Languages"},
            {"url": "http://example.com", "technology": "jQuery", "version": "3.6.0", "category": "JavaScript Libraries"},
            {"url": "http://example.com", "technology": "Bootstrap", "version": "4.6.0", "category": "CSS Frameworks"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"},
            {"url": "https://test.example.com", "technology": "React", "version": "17.0.0", "category": "JavaScript Frameworks"},
            {"url": "https://test.example.com", "technology": "MySQL", "version": "8.0.0", "category": "Database"},
            {"url": "https://test.example.com", "technology": "Redis", "version": "6.0.0", "category": "Database"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_technology_category_categorization(self):
        """Test technology category categorization functionality"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
http://example.com,Nginx,1.18.0,Server
https://test.example.com,PHP,7.4.0,Programming Languages
https://test.example.com,Python,3.8.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
http://example.com,React,17.0.0,JavaScript Frameworks
https://test.example.com,MySQL,8.0.0,Database
https://test.example.com,Redis,6.0.0,Database
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify technology category categorization
        server_techs = [tech for tech in technologies if tech['category'] == 'Server']
        programming_techs = [tech for tech in technologies if tech['category'] == 'Programming Languages']
        js_techs = [tech for tech in technologies if 'JavaScript' in tech['category']]
        database_techs = [tech for tech in technologies if tech['category'] == 'Database']

        self.assertEqual(len(server_techs), 2)
        self.assertEqual(len(programming_techs), 2)
        self.assertEqual(len(js_techs), 2)
        self.assertEqual(len(database_techs), 2)

    def test_special_characters_in_technologies(self):
        """Test handling of technologies with special characters"""
        webanalyze_output = """
http://example.com,Apache HTTP Server,2.4.41,Server
http://example.com,PHP-FPM,7.4.0,Programming Languages
https://test.example.com,Node.js,14.0.0,Programming Languages
https://test.example.com,React Native,0.63.0,JavaScript Frameworks
http://example.com,MySQL Server,8.0.0,Database
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify special characters are handled
        self.assertEqual(len(technologies), 5)
        
        # Check specific technologies with special characters
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache HTTP Server", "version": "2.4.41", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP-FPM", "version": "7.4.0", "category": "Programming Languages"},
            {"url": "https://test.example.com", "technology": "Node.js", "version": "14.0.0", "category": "Programming Languages"},
            {"url": "https://test.example.com", "technology": "React Native", "version": "0.63.0", "category": "JavaScript Frameworks"},
            {"url": "http://example.com", "technology": "MySQL Server", "version": "8.0.0", "category": "Database"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_empty_lines_and_whitespace(self):
        """Test handling of empty lines and whitespace"""
        webanalyze_output = """

http://example.com,Apache,2.4.41,Server

https://test.example.com,Nginx,1.18.0,Server

http://example.com,PHP,7.4.0,Programming Languages

"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify empty lines and whitespace are handled
        self.assertEqual(len(technologies), 3)
        
        # Check specific technologies
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP", "version": "7.4.0", "category": "Programming Languages"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_very_long_technology_names(self):
        """Test handling of very long technology names"""
        long_tech = "Very Long Technology Name With Many Words And Special Characters"
        webanalyze_output = f"""
http://example.com,Apache,2.4.41,Server
http://example.com,{long_tech},1.0.0,Programming Languages
https://test.example.com,Nginx,1.18.0,Server
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify very long technology names are handled
        self.assertEqual(len(technologies), 3)
        
        # Check specific technologies
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "http://example.com", "technology": long_tech, "version": "1.0.0", "category": "Programming Languages"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")

    def test_invalid_technology_filtering(self):
        """Test filtering of invalid technology lines"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
not a valid line
https://test.example.com,Nginx,1.18.0,Server
also not valid
ftp://example.com,Invalid,1.0.0,Server
http://example.com,PHP,7.4.0,Programming Languages
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Should only parse valid technology lines
        self.assertEqual(len(technologies), 3)
        
        # Check that only valid technologies are parsed
        expected_technologies = [
            {"url": "http://example.com", "technology": "Apache", "version": "2.4.41", "category": "Server"},
            {"url": "https://test.example.com", "technology": "Nginx", "version": "1.18.0", "category": "Server"},
            {"url": "http://example.com", "technology": "PHP", "version": "7.4.0", "category": "Programming Languages"}
        ]
        
        for expected in expected_technologies:
            found = False
            for tech_data in technologies:
                if (tech_data['url'] == expected['url'] and 
                    tech_data['technology'] == expected['technology'] and
                    tech_data['version'] == expected['version'] and
                    tech_data['category'] == expected['category']):
                    found = True
                    break
            self.assertTrue(found, f"Expected technology not found: {expected}")


class TestWebAnalyzeIntegration(unittest.TestCase):
    """Integration tests for WebAnalyze runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["http://example.com", "https://test.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.webanalyze_dir = os.path.join(self.test_output_dir, "technology_detection")
        os.makedirs(self.webanalyze_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete WebAnalyze workflow simulation"""
        # Create mock output file
        output_file = os.path.join(self.webanalyze_dir, "webanalyze_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock webanalyze output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
http://example.com,Apache,2.4.41,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,React,17.0.0,JavaScript Frameworks
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock webanalyze output content"
                
                result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['technologies']), 5)
        self.assertEqual(result['summary']['total_technologies'], 5)
        self.assertEqual(result['summary']['total_targets'], 2)

        # Verify different types of technologies are found
        server_techs = [tech for tech in result['technologies'] if tech['category'] == 'Server']
        programming_techs = [tech for tech in result['technologies'] if tech['category'] == 'Programming Languages']
        js_techs = [tech for tech in result['technologies'] if 'JavaScript' in tech['category']]

        self.assertEqual(len(server_techs), 2)
        self.assertEqual(len(programming_techs), 1)
        self.assertEqual(len(js_techs), 2)

    def test_output_format_integration(self):
        """Test output format integration"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
https://test.example.com,Nginx,1.18.0,Server
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify output format is consistent
        self.assertIsInstance(technologies, list)
        
        for tech_data in technologies:
            self.assertIn('url', tech_data)
            self.assertIn('technology', tech_data)
            self.assertIn('version', tech_data)
            self.assertIn('category', tech_data)
            self.assertIsInstance(tech_data['url'], str)
            self.assertIsInstance(tech_data['technology'], str)
            self.assertIsInstance(tech_data['version'], str)
            self.assertIsInstance(tech_data['category'], str)
            self.assertTrue(tech_data['url'].startswith(('http://', 'https://')))

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "webanalyze", stderr="First failure"),
                MagicMock(returncode=0, stdout="http://example.com,Apache,2.4.41,Server", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_webanalyze(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)

    def test_technology_analysis_integration(self):
        """Test technology analysis integration"""
        webanalyze_output = """
http://example.com,Apache,2.4.41,Server
http://example.com,PHP,7.4.0,Programming Languages
http://example.com,jQuery,3.6.0,JavaScript Libraries
http://example.com,Bootstrap,4.6.0,CSS Frameworks
https://test.example.com,Nginx,1.18.0,Server
https://test.example.com,React,17.0.0,JavaScript Frameworks
https://test.example.com,MySQL,8.0.0,Database
https://test.example.com,Redis,6.0.0,Database
"""

        technologies = parse_webanalyze_output(webanalyze_output)

        # Verify different technology categories are found
        server_techs = [tech for tech in technologies if tech['category'] == 'Server']
        programming_techs = [tech for tech in technologies if tech['category'] == 'Programming Languages']
        js_techs = [tech for tech in technologies if 'JavaScript' in tech['category']]
        css_techs = [tech for tech in technologies if 'CSS' in tech['category']]
        database_techs = [tech for tech in technologies if tech['category'] == 'Database']

        self.assertEqual(len(server_techs), 2)
        self.assertEqual(len(programming_techs), 1)
        self.assertEqual(len(js_techs), 2)
        self.assertEqual(len(css_techs), 1)
        self.assertEqual(len(database_techs), 2)


if __name__ == '__main__':
    unittest.main() 