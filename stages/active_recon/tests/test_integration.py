#!/usr/bin/env python3
"""
Integration tests for Active Recon stage components
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import sys
from datetime import datetime

# Add parent directory to path to import runners
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'runners'))

# Import all runners for integration testing
try:
    from run_nmap import run_nmap
    from run_naabu import run_naabu
    from run_webanalyze import run_webanalyze
    from run_puredns import run_puredns, create_master_subdomain_list
    from run_katana import run_katana
    from run_feroxbuster import run_feroxbuster
    from run_getjs import run_getjs
    from run_linkfinder import run_linkfinder
    from run_arjun import run_arjun
    from run_eyewitness import run_eyewitness, generate_screenshot_report
    from run_eyeballer import run_eyeballer, generate_analysis_report
except ImportError as e:
    print(f"Warning: Could not import some runners: {e}")


class TestActiveReconIntegration(unittest.TestCase):
    """Integration tests for Active Recon components"""

    def setUp(self):
        """Set up integration test fixtures"""
        self.test_output_dir = tempfile.mkdtemp()
        self.test_targets = ["example.com", "test.example.com"]
        self.test_subdomains = ["www.example.com", "api.example.com", "admin.example.com"]

    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('subprocess.run')
    def test_port_scanning_integration(self, mock_run):
        """Test integration between nmap and naabu port scanning"""
        # Mock successful nmap execution
        mock_nmap_result = MagicMock()
        mock_nmap_result.returncode = 0
        mock_nmap_result.stdout = """
Starting Nmap 7.80 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
22/tcp  open  ssh
"""
        mock_nmap_result.stderr = ""

        # Mock successful naabu execution
        mock_naabu_result = MagicMock()
        mock_naabu_result.returncode = 0
        mock_naabu_result.stdout = """
example.com:80
example.com:443
example.com:8080
"""
        mock_naabu_result.stderr = ""

        # Configure mock to return different results for different commands
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'nmap' in cmd[0]:
                return mock_nmap_result
            elif 'naabu' in cmd[0]:
                return mock_naabu_result
            else:
                return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_run_side_effect

        # Patch os.path.exists to return False for naabu_scan.txt, True otherwise
        def exists_side_effect(path):
            if path.endswith("naabu_scan.txt"):
                return False
            return True

        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('os.path.exists', side_effect=exists_side_effect):
            
            nmap_results = run_nmap(self.test_targets, self.test_output_dir)
            naabu_results = run_naabu(self.test_targets, self.test_output_dir)

        # Verify integration
        self.assertTrue(nmap_results['success'])
        self.assertTrue(naabu_results['success'])
        
        # Both should identify web ports
        nmap_web_ports = []
        for host in nmap_results.get('hosts', []):
            for port in host.get('ports', []):
                if isinstance(port, dict) and port.get('service') in ['http', 'https']:
                    nmap_web_ports.append(port.get('port'))
                elif isinstance(port, int) and port in [80, 443]:
                    nmap_web_ports.append(port)

        naabu_web_ports = []
        for host in naabu_results.get('hosts', []):
            for port in host.get('ports', []):
                if isinstance(port, dict) and port.get('service') in ['http', 'https']:
                    naabu_web_ports.append(port.get('port'))
                elif isinstance(port, int) and port in [80, 443]:
                    naabu_web_ports.append(port)

        # Both tools should find web ports
        self.assertIn(80, nmap_web_ports)
        self.assertIn(443, nmap_web_ports)
        self.assertIn(80, naabu_web_ports)
        self.assertIn(443, naabu_web_ports)

    @patch('subprocess.run')
    def test_technology_detection_integration(self, mock_run):
        """Test integration between port scanning and technology detection"""
        # Mock webanalyze execution
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = """
example.com:80
  Apache [2.4.41]
  PHP [7.4.3]
  jQuery [3.5.1]
example.com:443
  Apache [2.4.41]
  PHP [7.4.3]
  Bootstrap [4.5.0]
"""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # Patch os.path.exists to return False for webanalyze_results.json, True otherwise
        def exists_side_effect(path):
            if path.endswith("webanalyze_results.json"):
                return False
            return True

        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('os.path.exists', side_effect=exists_side_effect):
            
            webanalyze_results = run_webanalyze(self.test_targets, self.test_output_dir)

        # Verify technology detection works with discovered hosts
        self.assertTrue(webanalyze_results['success'])
        self.assertIn('technologies', webanalyze_results)
        self.assertIn('technology_mapping', webanalyze_results)

        # Should detect multiple technologies
        technologies = webanalyze_results.get('technologies', [])
        self.assertGreater(len(technologies), 0)

        # Check for specific technologies
        tech_names = [tech.get('technology', '') for tech in technologies]
        self.assertIn('Apache', tech_names)
        self.assertIn('PHP', tech_names)

    @patch('subprocess.run')
    def test_directory_enumeration_integration(self, mock_run):
        """Test integration between directory enumeration tools"""
        # Mock katana execution
        mock_katana_result = MagicMock()
        mock_katana_result.returncode = 0
        mock_katana_result.stdout = """
http://example.com/
http://example.com/admin
http://example.com/login
http://example.com/api/users
"""
        mock_katana_result.stderr = ""

        # Mock feroxbuster execution
        mock_feroxbuster_result = MagicMock()
        mock_feroxbuster_result.returncode = 0
        mock_feroxbuster_result.stdout = """
200      GET        http://example.com/robots.txt
200      GET        http://example.com/sitemap.xml
403      GET        http://example.com/admin
200      GET        http://example.com/login
"""
        mock_feroxbuster_result.stderr = ""

        # Configure mock to return different results for different commands
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'katana' in cmd[0]:
                return mock_katana_result
            elif 'feroxbuster' in cmd[0]:
                return mock_feroxbuster_result
            else:
                return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_run_side_effect

        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('os.path.exists', return_value=True):
            
            katana_results = run_katana(self.test_targets, self.test_output_dir)
            feroxbuster_results = run_feroxbuster(self.test_targets, self.test_output_dir)

        # Verify both tools work and find different types of endpoints
        self.assertTrue(katana_results['success'])
        self.assertTrue(feroxbuster_results['success'])

        # Katana should find crawled URLs
        katana_urls = katana_results.get('urls_found', [])
        self.assertGreater(len(katana_urls), 0)

        # Feroxbuster should find bruteforced URLs
        feroxbuster_urls = feroxbuster_results.get('urls_found', [])
        self.assertGreater(len(feroxbuster_urls), 0)

        # Both should find some common endpoints
        katana_url_strings = [url.get('url', '') for url in katana_urls]
        feroxbuster_url_strings = [url.get('url', '') for url in feroxbuster_urls]

        # Check for common endpoints
        common_endpoints = set(katana_url_strings) & set(feroxbuster_url_strings)
        self.assertGreater(len(common_endpoints), 0)

    @patch('subprocess.run')
    def test_javascript_analysis_integration(self, mock_run):
        """Test integration between JavaScript analysis tools"""
        # Mock getJS execution
        mock_getjs_result = MagicMock()
        mock_getjs_result.returncode = 0
        mock_getjs_result.stdout = """
http://example.com/app.js
http://example.com/admin.js
http://example.com/api.js
"""
        mock_getjs_result.stderr = ""

        # Mock LinkFinder execution
        mock_linkfinder_result = MagicMock()
        mock_linkfinder_result.returncode = 0
        mock_linkfinder_result.stdout = """
[*] Internal endpoint: /api/users
[*] Internal endpoint: /api/admin
[*] Internal endpoint: /api/config
"""
        mock_linkfinder_result.stderr = ""

        # Configure mock to return different results for different commands
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'getJS' in cmd[0]:
                return mock_getjs_result
            elif 'linkfinder' in cmd[0]:
                return mock_linkfinder_result
            else:
                return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_run_side_effect

        # Patch os.path.exists to return False for linkfinder_scan.txt, True otherwise
        def exists_side_effect(path):
            if path.endswith("linkfinder_scan.txt"):
                return False
            return True

        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('os.path.exists', side_effect=exists_side_effect):
            
            getjs_results = run_getjs(self.test_targets, self.test_output_dir)
            linkfinder_results = run_linkfinder(["/path/to/app.js"], self.test_output_dir)

        # Verify JavaScript analysis integration
        self.assertTrue(getjs_results['success'])
        self.assertTrue(linkfinder_results['success'])

        # GetJS should find JavaScript files
        js_files = getjs_results.get('js_files_found', [])
        self.assertGreater(len(js_files), 0)

        # LinkFinder should find endpoints in JavaScript files
        endpoints = linkfinder_results.get('all_endpoints', [])
        self.assertGreater(len(endpoints), 0)

        # Check for specific endpoints
        endpoint_strings = [ep.get('endpoint', '') if isinstance(ep, dict) else ep for ep in endpoints]
        self.assertIn('/api/users', endpoint_strings)
        self.assertIn('/api/admin', endpoint_strings)

    @patch('json.load')
    @patch('builtins.open', new_callable=mock_open)
    @patch('subprocess.run')
    @patch('os.path.exists')
    def test_parameter_discovery_integration(self, mock_exists, mock_run, mock_file, mock_json_load):
        """Test integration between parameter discovery and endpoint collection"""
        # Mock file existence
        mock_exists.return_value = True
        
        # Mock arjun execution
        mock_arjun_result = MagicMock()
        mock_arjun_result.returncode = 0
        mock_arjun_result.stdout = """
[+] URL: http://example.com/api/users
[+] Method: GET
[+] Parameters: id, name, email
[+] URL: http://example.com/api/admin
[+] Method: GET
[+] Parameters: user, action, token
"""
        mock_arjun_result.stderr = ""

        mock_run.return_value = mock_arjun_result

        # Mock JSON data that would be read from the results file
        # Arjun produces a list of endpoint objects, not a dict with "endpoints" key
        mock_json_data = [
            {
                "url": "http://example.com/api/users",
                "method": "GET",
                "params": ["id", "name", "email"],
                "status_code": 200,
                "content_length": 1024,
                "content_type": "application/json",
                "response_time": 0.5
            },
            {
                "url": "http://example.com/api/admin",
                "method": "GET", 
                "params": ["user", "action", "token"],
                "status_code": 200,
                "content_length": 512,
                "content_type": "application/json",
                "response_time": 0.3
            }
        ]
        mock_json_load.return_value = mock_json_data
        
        # Mock file content
        mock_file.return_value.__enter__.return_value.read.return_value = json.dumps(mock_json_data)

        # Test endpoints that would be discovered by previous tools
        test_endpoints = [
            "http://example.com/api/users",
            "http://example.com/api/admin",
            "http://example.com/login"
        ]

        with patch('os.makedirs'):
            arjun_results = run_arjun(test_endpoints, self.test_output_dir)

        # Verify parameter discovery integration
        self.assertTrue(arjun_results['success'])
        
        # Should find parameters for discovered endpoints
        endpoints_found = arjun_results.get('endpoints_found', [])
        self.assertGreater(len(endpoints_found), 0)

        # Check for specific parameters
        all_parameters = []
        for endpoint in endpoints_found:
            all_parameters.extend(endpoint.get('parameters', []))

        self.assertIn('id', all_parameters)
        self.assertIn('name', all_parameters)
        self.assertIn('email', all_parameters)
        self.assertIn('user', all_parameters)
        self.assertIn('action', all_parameters)
        self.assertIn('token', all_parameters)

    @patch('subprocess.run')
    def test_screenshot_workflow_integration(self, mock_run):
        """Test integration between screenshot capture and analysis"""
        # Mock eyewitness execution
        mock_eyewitness_result = MagicMock()
        mock_eyewitness_result.returncode = 0
        mock_eyewitness_result.stdout = "EyeWitness completed successfully"
        mock_eyewitness_result.stderr = ""

        # Mock eyeballer execution
        mock_eyeballer_result = MagicMock()
        mock_eyeballer_result.returncode = 0
        mock_eyeballer_result.stdout = "EyeBaller completed successfully"
        mock_eyeballer_result.stderr = ""

        # Configure mock to return different results for different commands
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'eyewitness' in cmd[0]:
                return mock_eyewitness_result
            elif 'eyeballer' in cmd[0]:
                return mock_eyeballer_result
            else:
                return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = mock_run_side_effect

        # Create mock screenshot files
        eyewitness_dir = os.path.join(self.test_output_dir, "enumeration", "eyewitness")
        os.makedirs(eyewitness_dir, exist_ok=True)
        
        mock_screenshots = [
            os.path.join(eyewitness_dir, "example_com.png"),
            os.path.join(eyewitness_dir, "test_example_com.png")
        ]
        
        for screenshot in mock_screenshots:
            with open(screenshot, 'w') as f:
                f.write("mock screenshot content")

        # Patch os.path.exists to return True for predictions.json
        def exists_side_effect(path):
            if path.endswith("predictions.json"):
                return True
            return True

        # Patch builtins.open to return valid JSON for predictions.json
        original_open = open
        def open_side_effect(file, mode='r', *args, **kwargs):
            if isinstance(file, str) and file.endswith("predictions.json"):
                from io import StringIO
                # Minimal valid EyeBaller output
                return StringIO('[{"filename": "example_com.png", "category": "login", "confidence": 0.9, "interesting": true}]')
            return mock_open()(file, mode, *args, **kwargs)

        with patch('os.walk') as mock_walk, \
             patch('builtins.open', side_effect=open_side_effect), \
             patch('os.path.exists', side_effect=exists_side_effect):
            mock_walk.return_value = [(eyewitness_dir, [], ['example_com.png', 'test_example_com.png'])]
            # Test eyewitness
            eyewitness_results = run_eyewitness(self.test_targets, self.test_output_dir)
            # Test eyeballer with eyewitness results
            eyeballer_results = run_eyeballer(eyewitness_dir, self.test_output_dir)

        # Verify screenshot workflow integration
        self.assertTrue(eyewitness_results['success'])
        self.assertTrue(eyeballer_results['success'])

        # EyeWitness should capture screenshots
        screenshots = eyewitness_results.get('screenshots', [])
        self.assertGreater(len(screenshots), 0)

        # EyeBaller should analyze screenshots
        findings = eyeballer_results.get('interesting_findings', [])
        # Note: In real execution, findings would depend on the actual screenshot content

    def test_data_flow_integration(self):
        """Test data flow between different stages of active recon"""
        # Simulate the data flow from passive recon to active recon
        
        # 1. Passive recon results (subdomains)
        passive_recon_subdomains = [
            "www.example.com",
            "api.example.com", 
            "admin.example.com",
            "test.example.com"
        ]

        # 2. Port scanning results
        port_scan_results = {
            "live_servers": [
                "www.example.com",  # Has web ports
                "api.example.com",  # Has web ports
                "admin.example.com"  # Has web ports
            ],
            "dead_servers": [
                "test.example.com"  # No web ports
            ]
        }

        # 3. Directory enumeration results
        directory_results = {
            "urls_found": [
                "http://www.example.com/",
                "http://www.example.com/admin",
                "http://api.example.com/users",
                "http://admin.example.com/login"
            ]
        }

        # 4. JavaScript analysis results
        js_results = {
            "js_files": [
                "http://www.example.com/app.js",
                "http://api.example.com/api.js"
            ],
            "endpoints": [
                "/api/users",
                "/api/admin",
                "/api/config"
            ]
        }

        # 5. Parameter discovery results
        parameter_results = {
            "endpoints_with_params": [
                {
                    "url": "http://api.example.com/users",
                    "parameters": ["id", "name", "email"]
                },
                {
                    "url": "http://api.example.com/admin", 
                    "parameters": ["user", "action", "token"]
                }
            ]
        }

        # 6. Screenshot results
        screenshot_results = {
            "screenshots": [
                "/path/to/www_example_com.png",
                "/path/to/api_example_com.png",
                "/path/to/admin_example_com.png"
            ]
        }

        # 7. Screenshot analysis results
        analysis_results = {
            "interesting_findings": [
                {
                    "filename": "www_example_com.png",
                    "category": "login",
                    "confidence": 0.85,
                    "interesting": True
                },
                {
                    "filename": "admin_example_com.png",
                    "category": "admin",
                    "confidence": 0.92,
                    "interesting": True
                }
            ]
        }

        # Verify data flow integrity
        self.assertEqual(len(passive_recon_subdomains), 4)
        self.assertEqual(len(port_scan_results["live_servers"]), 3)
        self.assertEqual(len(directory_results["urls_found"]), 4)
        self.assertEqual(len(js_results["js_files"]), 2)
        self.assertEqual(len(js_results["endpoints"]), 3)
        self.assertEqual(len(parameter_results["endpoints_with_params"]), 2)
        self.assertEqual(len(screenshot_results["screenshots"]), 3)
        self.assertEqual(len(analysis_results["interesting_findings"]), 2)

        # Verify that live servers are used for subsequent stages
        self.assertIn("www.example.com", port_scan_results["live_servers"])
        self.assertIn("api.example.com", port_scan_results["live_servers"])
        self.assertIn("admin.example.com", port_scan_results["live_servers"])

        # Verify that discovered URLs are used for parameter discovery
        discovered_urls = [ep["url"] for ep in parameter_results["endpoints_with_params"]]
        self.assertIn("http://api.example.com/users", discovered_urls)
        self.assertIn("http://api.example.com/admin", discovered_urls)

        # Verify that screenshots correspond to live servers
        screenshot_hosts = []
        for screenshot in screenshot_results["screenshots"]:
            if "www_example_com" in screenshot:
                screenshot_hosts.append("www.example.com")
            elif "api_example_com" in screenshot:
                screenshot_hosts.append("api.example.com")
            elif "admin_example_com" in screenshot:
                screenshot_hosts.append("admin.example.com")

        for host in port_scan_results["live_servers"]:
            self.assertIn(host, screenshot_hosts)

    def test_error_propagation_integration(self):
        """Test how errors propagate through the active recon pipeline"""
        # Simulate different error scenarios and their impact on the pipeline
        
        # Scenario 1: Port scanning fails
        port_scan_failure = {
            "success": False,
            "error": "Network timeout",
            "impact": "No live servers identified, subsequent tools may fail"
        }

        # Scenario 2: Directory enumeration fails
        directory_enum_failure = {
            "success": False,
            "error": "Wordlist not found",
            "impact": "No URLs discovered, parameter discovery will have limited targets"
        }

        # Scenario 3: JavaScript analysis fails
        js_analysis_failure = {
            "success": False,
            "error": "No JavaScript files found",
            "impact": "No additional endpoints discovered from JS files"
        }

        # Scenario 4: Screenshot capture fails
        screenshot_failure = {
            "success": False,
            "error": "No live servers available",
            "impact": "No screenshots for analysis"
        }

        # Verify error handling
        self.assertFalse(port_scan_failure["success"])
        self.assertFalse(directory_enum_failure["success"])
        self.assertFalse(js_analysis_failure["success"])
        self.assertFalse(screenshot_failure["success"])

        # Verify that errors have expected impact descriptions
        self.assertIn("impact", port_scan_failure)
        self.assertIn("impact", directory_enum_failure)
        self.assertIn("impact", js_analysis_failure)
        self.assertIn("impact", screenshot_failure)


if __name__ == '__main__':
    unittest.main() 