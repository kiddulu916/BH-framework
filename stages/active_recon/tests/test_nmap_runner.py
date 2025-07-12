#!/usr/bin/env python3
"""
Unit tests for Nmap runner
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

from run_nmap import run_nmap, parse_nmap_results, parse_nmap_output, categorize_ports


class TestNmapRunner(unittest.TestCase):
    """Test cases for Nmap runner functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_targets = ["example.com", "test.example.com", "admin.example.com"]
        self.test_output_dir = tempfile.mkdtemp()
        self.nmap_dir = os.path.join(self.test_output_dir, "port_scanning")
        os.makedirs(self.nmap_dir, exist_ok=True)

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_run_nmap_success(self, mock_run):
        """Test successful Nmap execution"""
        # Mock successful subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
22/tcp  open  ssh
Nmap scan report for test.example.com (93.184.216.35)
Host is up (0.092s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Mock file system operations
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('os.makedirs'):
                result = run_nmap(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertTrue(result['success'])
        self.assertEqual(result['return_code'], 0)
        self.assertIn('hosts', result)
        self.assertIn('summary', result)
        self.assertEqual(len(result['hosts']), 2)
        self.assertEqual(result['summary']['total_hosts'], 2)
        self.assertEqual(result['summary']['total_ports'], 4)

    @patch('subprocess.run')
    def test_run_nmap_failure(self, mock_run):
        """Test Nmap execution failure"""
        # Mock failed subprocess execution
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_result.stderr = "Error: No targets specified"
        mock_run.return_value = mock_result

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_nmap(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertEqual(result['return_code'], 1)
        self.assertIn('error', result)
        self.assertEqual(result['summary']['total_hosts'], 0)
        self.assertEqual(result['summary']['total_ports'], 0)

    @patch('subprocess.run')
    def test_run_nmap_timeout(self, mock_run):
        """Test Nmap execution timeout"""
        # Mock timeout exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=300)

        with patch('builtins.open', mock_open()):
            with patch('os.makedirs'):
                result = run_nmap(self.test_targets, self.test_output_dir)

        # Verify results
        self.assertFalse(result['success'])
        self.assertIn('timeout', result['error'].lower())
        self.assertEqual(result['summary']['execution_time_seconds'], 300)

    def test_parse_nmap_output_success(self):
        """Test successful Nmap output parsing"""
        nmap_output = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
22/tcp  open  ssh
Nmap scan report for test.example.com (93.184.216.35)
Host is up (0.092s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
8080/tcp open  http-proxy
"""

        hosts = parse_nmap_output(nmap_output)

        # Verify parsing
        self.assertEqual(len(hosts), 2)
        
        # Check first host
        host1 = hosts[0]
        self.assertEqual(host1['hostname'], 'example.com')
        self.assertEqual(host1['ip'], '93.184.216.34')
        self.assertEqual(len(host1['ports']), 3)
        
        # Check ports
        ports = host1['ports']
        def port_match(ports, port, service, state):
            return any(p['port'] == port and p['service'] == service and p['state'] == state for p in ports)
        self.assertTrue(port_match(ports, 80, 'http', 'open'))
        self.assertTrue(port_match(ports, 443, 'https', 'open'))
        self.assertTrue(port_match(ports, 22, 'ssh', 'open'))
        
        # Check second host
        host2 = hosts[1]
        self.assertEqual(host2['hostname'], 'test.example.com')
        self.assertEqual(host2['ip'], '93.184.216.35')
        self.assertEqual(len(host2['ports']), 2)

    def test_parse_nmap_output_no_hosts(self):
        """Test Nmap output parsing with no hosts found"""
        nmap_output = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host seems down. If it is really up, but blocking our ping probes, try -Pn
"""

        hosts = parse_nmap_output(nmap_output)

        # Verify no hosts found
        self.assertEqual(len(hosts), 0)

    def test_parse_nmap_output_invalid_format(self):
        """Test Nmap output parsing with invalid format"""
        invalid_output = "This is not valid nmap output"

        hosts = parse_nmap_output(invalid_output)

        # Should handle gracefully
        self.assertEqual(len(hosts), 0)

    def test_categorize_ports(self):
        """Test port categorization functionality"""
        ports = [
            {'port': 80, 'service': 'http', 'state': 'open'},
            {'port': 443, 'service': 'https', 'state': 'open'},
            {'port': 22, 'service': 'ssh', 'state': 'open'},
            {'port': 21, 'service': 'ftp', 'state': 'open'},
            {'port': 25, 'service': 'smtp', 'state': 'open'},
            {'port': 53, 'service': 'domain', 'state': 'open'},
            {'port': 3306, 'service': 'mysql', 'state': 'open'},
            {'port': 5432, 'service': 'postgresql', 'state': 'open'}
        ]

        categorized = categorize_ports(ports)

        # Verify categorization
        self.assertIn('web', categorized)
        self.assertIn('database', categorized)
        self.assertIn('remote_access', categorized)
        self.assertIn('email', categorized)
        self.assertIn('file_transfer', categorized)
        self.assertIn('dns', categorized)
        
        # Check specific categorizations
        self.assertEqual(len(categorized['web']), 2)  # 80, 443
        self.assertEqual(len(categorized['database']), 2)  # 3306, 5432
        self.assertEqual(len(categorized['remote_access']), 1)  # 22
        self.assertEqual(len(categorized['email']), 1)  # 25
        self.assertEqual(len(categorized['file_transfer']), 1)  # 21
        self.assertEqual(len(categorized['dns']), 1)  # 53

    def test_categorize_ports_empty(self):
        """Test port categorization with empty list"""
        categorized = categorize_ports([])
        
        # Should return empty categories
        expected_categories = ['web', 'database', 'remote_access', 'email', 'file_transfer', 'dns', 'other']
        for category in expected_categories:
            self.assertIn(category, categorized)
            self.assertEqual(len(categorized[category]), 0)

    def test_categorize_ports_unknown_service(self):
        """Test port categorization with unknown services"""
        ports = [
            {'port': 12345, 'service': 'unknown', 'state': 'open'},
            {'port': 54321, 'service': 'custom', 'state': 'open'}
        ]

        categorized = categorize_ports(ports)

        # Unknown services should go to 'other' category
        self.assertEqual(len(categorized['other']), 2)

    def test_command_construction(self):
        """Test that Nmap command is constructed correctly"""
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "Nmap scan report for example.com"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_nmap(self.test_targets, self.test_output_dir)

        # Verify command contains expected parameters
        command = result['command']
        self.assertIn('nmap', command)
        self.assertIn('-sS', command)  # SYN scan
        self.assertIn('-sV', command)  # Version detection
        self.assertIn('-O', command)   # OS detection
        self.assertIn('-T4', command)  # Timing template
        self.assertIn('--max-retries', command)
        self.assertIn('--host-timeout', command)

    def test_error_handling_file_operations(self):
        """Test error handling for file operations"""
        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            with patch('os.makedirs'):
                result = run_nmap(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Permission denied', result['error'])

    def test_error_handling_directory_creation(self):
        """Test error handling for directory creation"""
        with patch('os.makedirs', side_effect=OSError("Directory creation failed")):
            result = run_nmap(self.test_targets, self.test_output_dir)

        self.assertFalse(result['success'])
        self.assertIn('Directory creation failed', result['error'])

    def test_large_target_list_handling(self):
        """Test handling of large target lists"""
        large_targets = [f"subdomain{i}.example.com" for i in range(100)]
        
        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = "Nmap scan report for example.com"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_nmap(large_targets, self.test_output_dir)

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
            mock_result.stdout = "Nmap scan report for example.com"
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()):
                with patch('os.makedirs'):
                    result = run_nmap(mixed_targets, self.test_output_dir)

        self.assertTrue(result['success'])
        self.assertEqual(result['summary']['total_targets'], 4)


class TestNmapIntegration(unittest.TestCase):
    """Integration tests for Nmap runner"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_output_dir = tempfile.mkdtemp()
        self.nmap_dir = os.path.join(self.test_output_dir, "port_scanning")
        os.makedirs(self.nmap_dir, exist_ok=True)

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    def test_full_workflow_simulation(self):
        """Test the complete Nmap workflow simulation"""
        test_targets = ["example.com", "test.example.com"]
        
        # Create mock output file
        output_file = os.path.join(self.nmap_dir, "nmap_scan.txt")
        with open(output_file, 'w') as f:
            f.write("Mock nmap output content")

        with patch('subprocess.run') as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_result.stdout = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
Nmap scan report for test.example.com (93.184.216.35)
Host is up (0.092s latency).
PORT    STATE SERVICE
80/tcp  open  http
"""
            mock_result.stderr = ""
            mock_run.return_value = mock_result

            with patch('builtins.open', mock_open()) as mock_file:
                # Mock file read for output file
                mock_file.return_value.read.return_value = "Mock nmap output content"
                
                result = run_nmap(test_targets, self.test_output_dir)

        # Verify complete workflow
        self.assertTrue(result['success'])
        self.assertEqual(len(result['hosts']), 2)
        self.assertEqual(result['summary']['total_hosts'], 2)
        self.assertEqual(result['summary']['total_ports'], 3)

        # Verify web ports are identified
        web_ports = []
        for host in result['hosts']:
            for port in host['ports']:
                if port['service'] in ['http', 'https']:
                    web_ports.append(port['port'])

        self.assertIn(80, web_ports)
        self.assertIn(443, web_ports)

    def test_os_detection_integration(self):
        """Test OS detection integration"""
        nmap_output_with_os = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
22/tcp  open  ssh
Device type: general purpose
Running: Linux 4.x|5.x
OS CPE: cpe:/o:linux:linux_kernel:4.19.0
OS details: Linux 4.19.0
"""

        hosts = parse_nmap_output(nmap_output_with_os)

        # Verify OS detection
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertIn('os_info', host)
        self.assertEqual(host['os_info']['os'], 'Linux')
        self.assertEqual(host['os_info']['version'], '4.19.0')

    def test_service_version_detection(self):
        """Test service version detection integration"""
        nmap_output_with_versions = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
PORT    STATE SERVICE    VERSION
80/tcp  open  http       Apache httpd 2.4.41
443/tcp open  https      Apache httpd 2.4.41
22/tcp  open  ssh        OpenSSH 8.2p1
"""

        hosts = parse_nmap_output(nmap_output_with_versions)

        # Verify service version detection
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        
        # Check for service versions
        for port in host['ports']:
            if port['port'] == 80:
                self.assertIn('version', port)
                self.assertEqual(port['version'], 'Apache httpd 2.4.41')
            elif port['port'] == 22:
                self.assertIn('version', port)
                self.assertEqual(port['version'], 'OpenSSH 8.2p1')


if __name__ == '__main__':
    unittest.main() 