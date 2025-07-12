#!/usr/bin/env python3
"""
Unit tests for Naabu runner
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

from run_naabu import run_naabu, parse_naabu_output, parse_naabu_results


class TestNaabuRunner(unittest.TestCase):
    """Test cases for Naabu runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["example.com", "test.example.com", "admin.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.naabu_dir = os.path.join(self.test_output_dir, "port_scanning")
        os.makedirs(self.naabu_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_naabu_success(self, mock_run):
        """Test successful Naabu execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
example.com:80
example.com:443
example.com:22
test.example.com:80
test.example.com:8080
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('hosts', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['hosts']), 2)
        self.assertEqual(result['summary']['total_hosts'], 2)
        self.assertEqual(result['summary']['total_ports'], 5)

    @patch('subprocess.run')
    def test_run_naabu_failure(self, mock_run):
        """Test Naabu execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_hosts'], 0)
        self.assertEqual(result['summary']['total_ports'], 0)

    @patch('subprocess.run')
    def test_run_naabu_timeout(self, mock_run):
        """Test Naabu execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="naabu", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_naabu_output_success(self):
        """Test successful Naabu output parsing"""
        naabu_output = """
example.com:80
example.com:443
example.com:22
test.example.com:80
test.example.com:8080
admin.example.com:21
admin.example.com:25
"""

        hosts = parse_naabu_output(naabu_output)

        # Verify parsing
        self.assertEqual(len(hosts), 3)
        
        # Check first host
        host1 = hosts[0]
        self.assertEqual(host1['hostname'], 'example.com')
        self.assertEqual(len(host1['ports']), 3)
        
        # Check ports
        ports = host1['ports']
        self.assertIn(80, ports)
        self.assertIn(443, ports)
        self.assertIn(22, ports)
        
        # Check second host
        host2 = hosts[1]
        self.assertEqual(host2['hostname'], 'test.example.com')
        self.assertEqual(len(host2['ports']), 2)
        self.assertIn(80, host2['ports'])
        self.assertIn(8080, host2['ports'])

    def test_parse_naabu_output_empty(self):
        """Test Naabu output parsing with empty output"""
        naabu_output = ""

        hosts = parse_naabu_output(naabu_output)

        # Verify no hosts found
        self.assertEqual(len(hosts), 0)

    def test_parse_naabu_output_invalid_format(self):
        """Test Naabu output parsing with invalid format"""
        invalid_output = "This is not valid naabu output"

        hosts = parse_naabu_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(hosts), 0)

    def test_parse_naabu_output_mixed_formats(self):
        """Test Naabu output parsing with mixed valid and invalid lines"""
        mixed_output = """
example.com:80
invalid line
test.example.com:443
another invalid line
admin.example.com:22
"""

        hosts = parse_naabu_output(mixed_output)

        # Should only parse valid lines
        self.assertEqual(len(hosts), 3)
        
        # Check that valid hosts are parsed
        hostnames = [host['hostname'] for host in hosts]
        self.assertIn('example.com', hostnames)
        self.assertIn('test.example.com', hostnames)
        self.assertIn('admin.example.com', hostnames)

    def test_command_construction(self):
        """Test that Naabu command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('naabu', command)
        self.assertIn('-silent', command)  # Silent mode
        self.assertIn('-rate', command)    # Rate limiting
        self.assertIn('-timeout', command) # Timeout

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_naabu(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_naabu(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"subdomain{i}.example.com" for i in range(100)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(large_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 100)

    def test_mixed_ip_and_domain_targets(self):
        """Test handling of mixed IP and domain targets"""
        mixed_targets = [
            "example.com",
            "192.168.1.1",
            "test.example.com",
            "10.0.0.1"
        ]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)

    def test_port_range_handling(self):
        """Test handling of different port ranges"""
        naabu_output = """
example.com:80
example.com:443
example.com:8080
example.com:8443
example.com:22
example.com:21
example.com:25
example.com:53
example.com:3306
example.com:5432
"""

        hosts = parse_naabu_output(naabu_output)

        # Verify all ports are parsed correctly
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(len(host['ports']), 10)
        
        # Check specific ports
        expected_ports = [80, 443, 8080, 8443, 22, 21, 25, 53, 3306, 5432]
        for port in expected_ports:
            self.assertIn(port, host['ports'])

    def test_duplicate_port_handling(self):
        """Test handling of duplicate ports for same host"""
        naabu_output = """
example.com:80
example.com:80
example.com:443
example.com:443
test.example.com:80
"""

        hosts = parse_naabu_output(naabu_output)

        # Verify duplicates are handled (should be unique)
        self.assertEqual(len(hosts), 2)
        
        # Check first host (should have unique ports)
        host1 = hosts[0]
        self.assertEqual(len(host1['ports']), 2)  # 80, 443 (unique)
        self.assertIn(80, host1['ports'])
        self.assertIn(443, host1['ports'])
        
        # Check second host
        host2 = hosts[1]
        self.assertEqual(len(host2['ports']), 1)  # 80
        self.assertIn(80, host2['ports'])

    def test_high_port_numbers(self):
        """Test handling of high port numbers"""
        naabu_output = """
example.com:65535
example.com:32768
example.com:49152
"""

        hosts = parse_naabu_output(naabu_output)

        # Verify high port numbers are handled correctly
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(len(host['ports']), 3)
        
        # Check specific high ports
        expected_ports = [65535, 32768, 49152]
        for port in expected_ports:
            self.assertIn(port, host['ports'])

    def test_invalid_port_numbers(self):
        """Test handling of invalid port numbers"""
        naabu_output = """
example.com:80
example.com:invalid
example.com:443
example.com:99999
test.example.com:80
"""

        hosts = parse_naabu_output(naabu_output)

        # Should only parse valid ports
        self.assertEqual(len(hosts), 2)
        
        # Check first host (should only have valid ports)
        host1 = hosts[0]
        self.assertEqual(len(host1['ports']), 2)  # 80, 443 (valid)
        self.assertIn(80, host1['ports'])
        self.assertIn(443, host1['ports'])
        
        # Check second host
        host2 = hosts[1]
        self.assertEqual(len(host2['ports']), 1)  # 80
        self.assertIn(80, host2['ports'])


class TestNaabuIntegration(unittest.TestCase):
    """Integration tests for Naabu runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_targets = ["example.com", "test.example.com", "admin.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.naabu_dir = os.path.join(self.test_output_dir, "port_scanning")
        os.makedirs(self.naabu_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete Naabu workflow simulation"""
        test_targets = ["example.com", "test.example.com"]
        
        # Create mock output file
        output_file = os.path.join(self.naabu_dir, "naabu_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock naabu output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
example.com:80
example.com:443
test.example.com:80
test.example.com:8080
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock naabu output content"
                
                result = run_naabu(test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['hosts']), 2)
        self.assertEqual(result['summary']['total_hosts'], 2)
        self.assertEqual(result['summary']['total_ports'], 4)

        # Verify web ports are identified
        web_ports = []
        for host in result['hosts']:
            for port in host['ports']:
                if port in [80, 443, 8080]:
                    web_ports.append(port)

        self.assertIn(80, web_ports)
        self.assertIn(443, web_ports)
        self.assertIn(8080, web_ports)

    def test_rate_limiting_integration(self):
        """Test rate limiting integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify rate limiting is applied
        command = result['command']
        self.assertIn('-rate', command)
        
        # Extract rate value
        import re
        rate_match = re.search(r'-rate\s+(\d+)', command)
        if rate_match:
            rate = int(rate_match.group(1))
            self.assertGreater(rate, 0)
            self.assertLessEqual(rate, 10000)  # Reasonable upper limit

    def test_timeout_integration(self):
        """Test timeout integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify timeout is applied
        command = result['command']
        self.assertIn('-timeout', command)
        
        # Extract timeout value
        import re
        timeout_match = re.search(r'-timeout\s+(\d+)', command)
        if timeout_match:
            timeout = int(timeout_match.group(1))
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 300)  # Reasonable upper limit

    def test_silent_mode_integration(self):
        """Test silent mode integration"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "example.com:80"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(self.test_targets, self.test_output_dir)

        # Verify silent mode is enabled
        command = result['command']
        self.assertIn('-silent', command)

    def test_output_format_integration(self):
        """Test output format integration"""
        naabu_output = """
example.com:80
example.com:443
test.example.com:80
"""

        hosts = parse_naabu_output(naabu_output)

        # Verify output format is consistent
        for host in hosts:
            self.assertIn('hostname', host)
            self.assertIn('ports', host)
            self.assertIsInstance(host['hostname'], str)
            self.assertIsInstance(host['ports'], list)
            
            # Verify all ports are integers
            for port in host['ports']:
                self.assertIsInstance(port, int)
                self.assertGreater(port, 0)
                self.assertLessEqual(port, 65535)

    def test_error_recovery_integration(self):
        """Test error recovery integration"""
        # Test with partial failure
        with patch('subprocess.run') as mock_run:
            # First call fails, second succeeds
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "naabu", stderr="First failure"),
                MagicMock(returncode=0, stdout="example.com:80", stderr="")
            ]

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_naabu(self.test_targets, self.test_output_dir)

        # Should handle the failure gracefully
        self.assertFalse(result['success'])
        self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main() 