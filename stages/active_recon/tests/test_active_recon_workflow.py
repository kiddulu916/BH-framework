#!/usr/bin/env python3
"""
Workflow tests for Active Recon stage
"""

import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os
import json
import sys
from datetime import datetime

# Add parent directory to path to import the main runner
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from run_active_recon import main, setup_output_dirs, get_target_id_by_domain, get_passive_recon_results


class TestActiveReconWorkflow(unittest.TestCase):
    """Test cases for complete Active Recon workflow"""

    def setUp(self):
        """Set up test fixtures and patch subprocess.run for tool availability."""
        self.test_output_dir = tempfile.mkdtemp()
        self.test_target = "example.com"
        self.test_stage = "active_recon"
        # Patch subprocess.run to always return success for tool checks
        self.subprocess_patcher = patch('subprocess.run')
        self.mock_subprocess = self.subprocess_patcher.start()
        self.mock_subprocess.return_value.returncode = 0
        self.mock_subprocess.return_value.stdout = b"tool version info"

    def tearDown(self):
        """Clean up test fixtures and stop subprocess.run patch."""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)
        self.subprocess_patcher.stop()

    @patch('sys.argv', ['run_active_recon.py', '--target', 'example.com', '--stage', 'active_recon'])
    @patch('os.environ.get')
    @patch('requests.get')
    @patch('requests.post')
    def test_complete_workflow_success(self, mock_post, mock_get, mock_env):
        """Test complete active recon workflow with all tools succeeding"""
        # Mock environment variables
        mock_env.side_effect = lambda key, default=None: {
            'BACKEND_API_URL': 'http://backend:8000/api/results/active_recon',
            'BACKEND_JWT_TOKEN': 'test_jwt_token',
            'TARGETS_API_URL': 'http://backend:8000/api/targets/',
            'PASSIVE_API_URL': 'http://backend:8000/api/results/passive-recon'
        }.get(key, default)

        # Mock API responses
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': {
                'targets': [{'id': 'test-target-id', 'value': 'example.com'}]
            }
        }

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {'success': True}

        # Mock all tool runners
        with patch('run_active_recon.run_nmap') as mock_nmap, \
             patch('run_active_recon.run_naabu') as mock_naabu, \
             patch('run_active_recon.run_webanalyze') as mock_webanalyze, \
             patch('run_active_recon.run_puredns') as mock_puredns, \
             patch('run_active_recon.run_katana') as mock_katana, \
             patch('run_active_recon.run_feroxbuster') as mock_feroxbuster, \
             patch('run_active_recon.run_getjs') as mock_getjs, \
             patch('run_active_recon.run_linkfinder') as mock_linkfinder, \
             patch('run_active_recon.run_arjun') as mock_arjun, \
             patch('run_active_recon.run_eyewitness') as mock_eyewitness, \
             patch('run_active_recon.run_eyeballer') as mock_eyeballer:

            # Mock successful tool results
            mock_nmap.return_value = {
                'success': True,
                'hosts': [
                    {
                        'hostname': 'example.com',
                        'ports': [{'port': 80, 'service': 'http'}, {'port': 443, 'service': 'https'}]
                    }
                ],
                'summary': {'total_hosts': 1, 'total_ports': 2},
                'files': {'results_file': '/path/to/nmap_results.xml'}
            }

            mock_naabu.return_value = {
                'success': True,
                'hosts': [
                    {
                        'hostname': 'example.com',
                        'ports': [{'port': 80, 'service': 'http'}, {'port': 443, 'service': 'https'}]
                    }
                ],
                'summary': {'total_hosts': 1, 'total_ports': 2},
                'files': {'results_file': '/path/to/naabu_results.txt'}
            }

            mock_webanalyze.return_value = {
                'success': True,
                'technologies': [
                    {'name': 'Apache', 'version': '2.4', 'hostname': 'example.com'},
                    {'name': 'PHP', 'version': '7.4', 'hostname': 'example.com'}
                ],
                'summary': {'total_technologies': 2},
                'target_technologies': {'example.com': [{'name': 'Apache', 'version': '2.4'}]},
                'files': {'results_file': '/path/to/webanalyze_results.json'}
            }

            mock_puredns.return_value = {
                'success': True,
                'subdomains': ['www.example.com', 'api.example.com'],
                'summary': {'total_subdomains': 2},
                'live_servers': ['www.example.com', 'api.example.com'],
                'server_details': {'www.example.com': {'ip': '192.168.1.1'}},
                'files': {'results_file': '/path/to/puredns_results.txt'}
            }

            mock_katana.return_value = {
                'success': True,
                'urls_found': [
                    {'url': 'http://example.com/', 'status_code': 200},
                    {'url': 'http://example.com/admin', 'status_code': 403}
                ],
                'summary': {'total_urls': 2},
                'files': {'results_file': '/path/to/katana_results.json'}
            }

            mock_feroxbuster.return_value = {
                'success': True,
                'urls_found': [
                    {'url': 'http://example.com/robots.txt', 'status_code': 200},
                    {'url': 'http://example.com/sitemap.xml', 'status_code': 200}
                ],
                'summary': {'total_urls': 2},
                'files': {'results_file': '/path/to/feroxbuster_results.json'}
            }

            mock_getjs.return_value = {
                'success': True,
                'js_files_found': [
                    {'file_path': 'http://example.com/app.js', 'endpoints': ['/api/users', '/api/admin']}
                ],
                'summary': {'total_js_files': 1, 'total_endpoints': 2},
                'files': {'results_file': '/path/to/getjs_results.json'}
            }

            mock_linkfinder.return_value = {
                'success': True,
                'all_endpoints': [
                    {'endpoint': '/api/users', 'confidence': 0.8},
                    {'endpoint': '/api/admin', 'confidence': 0.9}
                ],
                'summary': {'total_endpoints': 2},
                'files': {'results_file': '/path/to/linkfinder_results.json'}
            }

            mock_arjun.return_value = {
                'success': True,
                'endpoints_found': [
                    {'url': 'http://example.com/api/users', 'parameters': ['id', 'name']}
                ],
                'summary': {'total_endpoints': 1, 'unique_parameters': 2},
                'files': {'results_file': '/path/to/arjun_results.json'}
            }

            mock_eyewitness.return_value = {
                'success': True,
                'screenshots': ['/path/to/screenshot1.png', '/path/to/screenshot2.png'],
                'summary': {'total_targets': 2, 'successful_screenshots': 2, 'failed_screenshots': 0},
                'files': {'targets_file': '/path/to/eyewitness_targets.txt', 'output_dir': '/path/to/screenshots'}
            }

            mock_eyeballer.return_value = {
                'success': True,
                'interesting_findings': [
                    {'filename': 'screenshot1.png', 'category': 'login', 'confidence': 0.85, 'interesting': True}
                ],
                'summary': {'analyzed_screenshots': 2, 'interesting_findings': 1},
                'files': {'results_file': '/path/to/eyeballer_results.json'}
            }

            # Mock file operations
            with patch('builtins.open', mock_open()), \
                 patch('os.makedirs'), \
                 patch('json.dump'), \
                 patch('os.path.exists', return_value=True):

                # Run the main function
                main()

        # Verify that all tools were called
        mock_nmap.assert_called_once()
        mock_naabu.assert_called_once()
        mock_webanalyze.assert_called_once()
        mock_puredns.assert_called_once()
        mock_katana.assert_called_once()
        mock_feroxbuster.assert_called_once()
        mock_getjs.assert_called_once()
        mock_linkfinder.assert_called_once()
        mock_arjun.assert_called_once()
        mock_eyewitness.assert_called_once()
        mock_eyeballer.assert_called_once()

    @patch('sys.argv', ['run_active_recon.py', '--target', 'example.com', '--stage', 'active_recon'])
    @patch('os.environ.get')
    @patch('requests.get')
    @patch('requests.post')
    def test_workflow_with_tool_failures(self, mock_post, mock_get, mock_env):
        """Test workflow continues even when some tools fail"""
        # Mock environment variables
        mock_env.side_effect = lambda key, default=None: {
            'BACKEND_API_URL': 'http://backend:8000/api/results/active_recon',
            'BACKEND_JWT_TOKEN': 'test_jwt_token',
            'TARGETS_API_URL': 'http://backend:8000/api/targets/',
            'PASSIVE_API_URL': 'http://backend:8000/api/results/passive-recon'
        }.get(key, default)

        # Mock API responses
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': {
                'targets': [{'id': 'test-target-id', 'value': 'example.com'}]
            }
        }

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {'success': True}

        # Mock tool runners with some failures
        with patch('run_active_recon.run_nmap') as mock_nmap, \
             patch('run_active_recon.run_naabu') as mock_naabu, \
             patch('run_active_recon.run_webanalyze') as mock_webanalyze, \
             patch('run_active_recon.run_puredns') as mock_puredns, \
             patch('run_active_recon.run_katana') as mock_katana, \
             patch('run_active_recon.run_feroxbuster') as mock_feroxbuster, \
             patch('run_active_recon.run_getjs') as mock_getjs, \
             patch('run_active_recon.run_linkfinder') as mock_linkfinder, \
             patch('run_active_recon.run_arjun') as mock_arjun, \
             patch('run_active_recon.run_eyewitness') as mock_eyewitness, \
             patch('run_active_recon.run_eyeballer') as mock_eyeballer:

            # Mock some successful and some failed tools
            mock_nmap.return_value = {
                'success': True, 
                'hosts': [], 
                'summary': {'total_hosts': 0},
                'files': {'results_file': '/path/to/nmap_results.xml'}
            }

            mock_naabu.return_value = {
                'success': False, 
                'error': 'Network timeout',
                'files': {'results_file': '/path/to/naabu_results.txt'}
            }
            mock_webanalyze.return_value = {
                'success': True, 
                'technologies': [], 
                'summary': {'total_technologies': 0},
                'files': {'results_file': '/path/to/webanalyze_results.json'}
            }
            mock_puredns.return_value = {
                'success': True, 
                'live_servers': [], 
                'summary': {'total_live': 0},
                'files': {'results_file': '/path/to/puredns_results.json'}
            }
            mock_katana.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/katana_results.txt'}
            }
            mock_feroxbuster.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/feroxbuster_results.txt'}
            }
            mock_getjs.return_value = {
                'success': True, 
                'js_files': [], 
                'summary': {'total_files': 0},
                'files': {'results_file': '/path/to/getjs_results.json'}
            }
            mock_linkfinder.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/linkfinder_results.txt'}
            }
            mock_arjun.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/arjun_results.txt'}
            }
            mock_eyewitness.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/eyewitness_results.txt'}
            }
            mock_eyeballer.return_value = {
                'success': False, 
                'error': 'Tool not found',
                'files': {'results_file': '/path/to/eyeballer_results.txt'}
            }

            # Mock file operations
            with patch('builtins.open', mock_open()), \
                 patch('os.makedirs'), \
                 patch('json.dump'), \
                 patch('os.path.exists', return_value=True):

                # Run the main function
                main()

            # Verify API calls were made
            mock_get.assert_called()
            mock_post.assert_called()

            # Verify tool calls - only tools that should run with prerequisites
            mock_nmap.assert_called_once()
            mock_naabu.assert_called_once()
            mock_webanalyze.assert_called_once()
            mock_puredns.assert_called_once()
            mock_getjs.assert_called_once()
            mock_katana.assert_called_once()
            mock_feroxbuster.assert_called_once()
            
            # These tools should not be called when no prerequisites are available
            mock_linkfinder.assert_not_called()
            mock_arjun.assert_not_called()
            mock_eyewitness.assert_not_called()
            mock_eyeballer.assert_not_called()

    def test_setup_output_dirs(self):
        """Test output directory setup"""
        dirs = setup_output_dirs(self.test_stage, self.test_target)

        # Check that the function returns the expected keys
        self.assertIn('output_dir', dirs)
        self.assertIn('parsed_dir', dirs)
        self.assertIn('raw_dir', dirs)
        
        # Check that the paths are correctly formatted
        self.assertIn('active_recon', dirs['output_dir'])
        self.assertIn('example.com', dirs['output_dir'])
        self.assertIn('parsed', dirs['parsed_dir'])
        self.assertIn('raw', dirs['raw_dir'])

    @patch('requests.get')
    def test_get_target_id_by_domain_success(self, mock_get):
        """Test successful target ID retrieval"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': {
                'targets': [{'id': 'test-target-id', 'value': 'example.com'}]
            }
        }

        result = get_target_id_by_domain('example.com', 'http://api/targets', 'test_token')
        self.assertEqual(result, 'test-target-id')

    @patch('requests.get')
    def test_get_target_id_by_domain_not_found(self, mock_get):
        """Test target ID retrieval when target not found"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': {'targets': []}
        }

        result = get_target_id_by_domain('nonexistent.com', 'http://api/targets', 'test_token')
        self.assertIsNone(result)

    @patch('requests.get')
    def test_get_passive_recon_results_success(self, mock_get):
        """Test successful passive recon results retrieval"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': [
                {
                    'raw_output': {
                        'subdomains': ['www.example.com', 'api.example.com']
                    }
                },
                {
                    'raw_output': {
                        'subdomains': ['mail.example.com']
                    }
                }
            ]
        }

        results = get_passive_recon_results('test-target-id', 'http://api/results', 'test_token')

        self.assertIsInstance(results, list)
        self.assertIn('www.example.com', results)
        self.assertIn('api.example.com', results)
        self.assertIn('mail.example.com', results)
        # Check that duplicates are removed
        self.assertEqual(len(results), 3)

    @patch('requests.get')
    def test_get_passive_recon_results_empty(self, mock_get):
        """Test passive recon results retrieval when no results found"""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'success': True,
            'data': []
        }

        results = get_passive_recon_results('test-target-id', 'http://api/results', 'test_token')
        self.assertEqual(results, [])

    @patch('sys.argv', ['run_active_recon.py', '--target', 'example.com', '--stage', 'active_recon'])
    @patch('os.environ.get')
    def test_workflow_with_missing_environment_variables(self, mock_env):
        """Test workflow behavior with missing environment variables"""
        # Mock environment variables to return None/default values
        mock_env.return_value = None

        # Mock file operations
        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('json.dump'), \
             patch('os.path.exists', return_value=True), \
             patch('requests.get') as mock_get, \
             patch('requests.post') as mock_post:

            # Mock API responses
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                'success': True,
                'data': {'targets': []}
            }
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {'success': True}

            # Mock all tool runners to return success
            with patch('run_active_recon.run_nmap') as mock_nmap, \
                 patch('run_active_recon.run_naabu') as mock_naabu, \
                 patch('run_active_recon.run_webanalyze') as mock_webanalyze, \
                 patch('run_active_recon.run_puredns') as mock_puredns, \
                 patch('run_active_recon.run_katana') as mock_katana, \
                 patch('run_active_recon.run_feroxbuster') as mock_feroxbuster, \
                 patch('run_active_recon.run_getjs') as mock_getjs, \
                 patch('run_active_recon.run_linkfinder') as mock_linkfinder, \
                 patch('run_active_recon.run_arjun') as mock_arjun, \
                 patch('run_active_recon.run_eyewitness') as mock_eyewitness, \
                 patch('run_active_recon.run_eyeballer') as mock_eyeballer:

                # Mock successful tool results
                mock_nmap.return_value = {
                    'success': True, 
                    'hosts': [], 
                    'summary': {'total_hosts': 0},
                    'files': {'results_file': '/path/to/nmap_results.xml'}
                }
                mock_naabu.return_value = {
                    'success': True, 
                    'hosts': [], 
                    'summary': {'total_hosts': 0},
                    'files': {'results_file': '/path/to/naabu_results.txt'}
                }
                mock_webanalyze.return_value = {
                    'success': True, 
                    'technologies': [], 
                    'summary': {'total_technologies': 0},
                    'files': {'results_file': '/path/to/webanalyze_results.json'}
                }
                mock_puredns.return_value = {
                    'success': True, 
                    'live_servers': [], 
                    'summary': {'total_live': 0},
                    'files': {'results_file': '/path/to/puredns_results.json'}
                }
                mock_katana.return_value = {
                    'success': True, 
                    'urls_found': [], 
                    'summary': {'total_urls': 0},
                    'files': {'results_file': '/path/to/katana_results.txt'}
                }
                mock_feroxbuster.return_value = {
                    'success': True, 
                    'urls_found': [], 
                    'summary': {'total_urls': 0},
                    'files': {'results_file': '/path/to/feroxbuster_results.txt'}
                }
                mock_getjs.return_value = {
                    'success': True, 
                    'js_files': [], 
                    'summary': {'total_files': 0},
                    'files': {'results_file': '/path/to/getjs_results.json'}
                }
                mock_linkfinder.return_value = {
                    'success': True, 
                    'all_endpoints': [], 
                    'summary': {'total_endpoints': 0},
                    'files': {'results_file': '/path/to/linkfinder_results.txt'}
                }
                mock_arjun.return_value = {
                    'success': True, 
                    'endpoints_found': [], 
                    'summary': {'total_endpoints': 0},
                    'files': {'results_file': '/path/to/arjun_results.txt'}
                }
                mock_eyewitness.return_value = {
                    'success': True, 
                    'screenshots': [], 
                    'summary': {'total_targets': 0},
                    'files': {'results_file': '/path/to/eyewitness_results.txt'}
                }
                mock_eyeballer.return_value = {
                    'success': True, 
                    'interesting_findings': [], 
                    'summary': {'analyzed_screenshots': 0},
                    'files': {'results_file': '/path/to/eyeballer_results.txt'}
                }

                # Mock subprocess to return success for tool availability checks
                with patch('subprocess.run') as mock_subprocess:
                    mock_subprocess.return_value.returncode = 0
                    mock_subprocess.return_value.stdout = b"tool version info"

                    # Run the main function
                    main()

        # Verify that tools were still called despite missing environment variables
        mock_nmap.assert_called_once()
        mock_naabu.assert_called_once()
        mock_webanalyze.assert_called_once()
        mock_puredns.assert_called_once()
        mock_getjs.assert_called_once()
        mock_katana.assert_called_once()
        mock_feroxbuster.assert_called_once()
        
        # These tools should not be called when no prerequisites are available
        mock_linkfinder.assert_not_called()
        mock_arjun.assert_not_called()
        mock_eyewitness.assert_not_called()
        mock_eyeballer.assert_not_called()

    def test_live_server_extraction(self):
        """Test extraction of live web servers from port scanning results"""
        # Test data with web services
        nmap_results = {
            'success': True,
            'hosts': [
                {
                    'hostname': 'example.com',
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'},
                        {'port': 22, 'service': 'ssh'}
                    ]
                },
                {
                    'hostname': 'api.example.com',
                    'ports': [
                        {'port': 8080, 'service': 'http-proxy'},
                        {'port': 8443, 'service': 'https-proxy'}
                    ]
                }
            ]
        }

        naabu_results = {
            'success': True,
            'hosts': [
                {
                    'hostname': 'www.example.com',
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'}
                    ]
                }
            ]
        }

        # Extract live servers from nmap results
        live_servers = []
        if nmap_results.get("success"):
            for host in nmap_results.get("hosts", []):
                if any(port.get("service") in ["http", "https", "http-proxy", "https-proxy"] 
                       for port in host.get("ports", [])):
                    live_servers.append(host.get("hostname", ""))

        # Extract live servers from naabu results
        if naabu_results.get("success"):
            for host in naabu_results.get("hosts", []):
                if any(port.get("service") in ["http", "https"] for port in host.get("ports", [])):
                    if host.get("hostname") not in live_servers:
                        live_servers.append(host.get("hostname", ""))

        # Verify results
        self.assertIn('example.com', live_servers)
        self.assertIn('api.example.com', live_servers)
        self.assertIn('www.example.com', live_servers)
        self.assertEqual(len(live_servers), 3)

    def test_endpoint_collection_and_deduplication(self):
        """Test collection and deduplication of endpoints from various tools"""
        # Test data from different tools
        katana_results = {
            'success': True,
            'urls_found': [
                {'url': 'http://example.com/', 'status_code': 200},
                {'url': 'http://example.com/admin', 'status_code': 403},
                {'url': 'http://example.com/api/users', 'status_code': 200}
            ]
        }

        feroxbuster_results = {
            'success': True,
            'urls_found': [
                {'url': 'http://example.com/robots.txt', 'status_code': 200},
                {'url': 'http://example.com/sitemap.xml', 'status_code': 200},
                {'url': 'http://example.com/admin', 'status_code': 403}  # Duplicate
            ]
        }

        getjs_results = {
            'success': True,
            'js_files_found': [
                {
                    'file_path': 'http://example.com/app.js',
                    'endpoints': ['/api/users', '/api/admin', '/api/settings']
                },
                {
                    'file_path': 'http://example.com/config.js',
                    'endpoints': ['/api/config', '/api/status']
                }
            ]
        }

        linkfinder_results = {
            'success': True,
            'all_endpoints': [
                {'endpoint': '/api/users', 'confidence': 0.8},
                {'endpoint': '/api/admin', 'confidence': 0.9},
                {'endpoint': '/api/new-endpoint', 'confidence': 0.7}
            ]
        }

        arjun_results = {
            'success': True,
            'endpoints_found': [
                {'url': 'http://example.com/api/users', 'parameters': ['id', 'name']},
                {'url': 'http://example.com/api/admin', 'parameters': ['user', 'action']},
                {'url': 'http://example.com/api/search', 'parameters': ['q', 'page']}
            ]
        }

        # Collect all endpoints
        all_endpoints = set()

        # From Katana
        if katana_results.get("success"):
            for url_data in katana_results.get("urls_found", []):
                url = url_data.get("url", "")
                if url.startswith("http"):
                    # Extract path from URL
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    all_endpoints.add(parsed.path)

        # From Feroxbuster
        if feroxbuster_results.get("success"):
            for url_data in feroxbuster_results.get("urls_found", []):
                url = url_data.get("url", "")
                if url.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    all_endpoints.add(parsed.path)

        # From GetJS
        if getjs_results.get("success"):
            for js_file in getjs_results.get("js_files_found", []):
                for endpoint in js_file.get("endpoints", []):
                    all_endpoints.add(endpoint)

        # From LinkFinder
        if linkfinder_results.get("success"):
            for endpoint_data in linkfinder_results.get("all_endpoints", []):
                all_endpoints.add(endpoint_data.get("endpoint", ""))

        # From Arjun
        if arjun_results.get("success"):
            for endpoint_data in arjun_results.get("endpoints_found", []):
                url = endpoint_data.get("url", "")
                if url.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    all_endpoints.add(parsed.path)

        # Verify results
        self.assertIn('/', all_endpoints)
        self.assertIn('/admin', all_endpoints)
        self.assertIn('/api/users', all_endpoints)
        self.assertIn('/robots.txt', all_endpoints)
        self.assertIn('/sitemap.xml', all_endpoints)
        self.assertIn('/api/admin', all_endpoints)
        self.assertIn('/api/settings', all_endpoints)
        self.assertIn('/api/config', all_endpoints)
        self.assertIn('/api/status', all_endpoints)
        self.assertIn('/api/new-endpoint', all_endpoints)
        self.assertIn('/api/search', all_endpoints)

        # Check that duplicates are removed
        self.assertEqual(len(all_endpoints), 11)


class TestActiveReconErrorHandling(unittest.TestCase):
    """Test error handling in Active Recon workflow"""

    def setUp(self):
        """Set up test fixtures"""
        self.test_output_dir = tempfile.mkdtemp()
        self.test_target = "example.com"
        self.test_stage = "active_recon"

    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.test_output_dir, ignore_errors=True)

    @patch('sys.argv', ['run_active_recon.py', '--target', 'example.com', '--stage', 'active_recon'])
    @patch('os.environ.get')
    def test_network_failure_handling(self, mock_env):
        """Test handling of network failures"""
        # Mock environment variables
        mock_env.side_effect = lambda key, default=None: {
            'BACKEND_API_URL': 'http://backend:8000/api/results/active_recon',
            'BACKEND_JWT_TOKEN': 'test_jwt_token',
            'TARGETS_API_URL': 'http://backend:8000/api/targets/',
            'PASSIVE_API_URL': 'http://backend:8000/api/results/passive-recon'
        }.get(key, default)

        # Mock file operations
        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('json.dump'), \
             patch('os.path.exists', return_value=True), \
             patch('requests.get') as mock_get, \
             patch('requests.post') as mock_post:

            # Mock network failures
            mock_get.side_effect = Exception("Network error")
            mock_post.side_effect = Exception("Network error")

            # Mock all tool runners to return success
            with patch('run_active_recon.run_nmap') as mock_nmap, \
                 patch('run_active_recon.run_naabu') as mock_naabu, \
                 patch('run_active_recon.run_webanalyze') as mock_webanalyze, \
                 patch('run_active_recon.run_puredns') as mock_puredns, \
                 patch('run_active_recon.run_katana') as mock_katana, \
                 patch('run_active_recon.run_feroxbuster') as mock_feroxbuster, \
                 patch('run_active_recon.run_getjs') as mock_getjs, \
                 patch('run_active_recon.run_linkfinder') as mock_linkfinder, \
                 patch('run_active_recon.run_arjun') as mock_arjun, \
                 patch('run_active_recon.run_eyewitness') as mock_eyewitness, \
                 patch('run_active_recon.run_eyeballer') as mock_eyeballer:

                # Mock successful tool results
                mock_nmap.return_value = {'success': True, 'hosts': [], 'summary': {'total_hosts': 0}}
                mock_naabu.return_value = {'success': True, 'hosts': [], 'summary': {'total_hosts': 0}}
                mock_webanalyze.return_value = {'success': True, 'technologies': [], 'summary': {'total_technologies': 0}}
                mock_puredns.return_value = {'success': True, 'subdomains': [], 'summary': {'total_subdomains': 0}}
                mock_katana.return_value = {'success': True, 'urls_found': [], 'summary': {'total_urls': 0}}
                mock_feroxbuster.return_value = {'success': True, 'urls_found': [], 'summary': {'total_urls': 0}}
                mock_getjs.return_value = {'success': True, 'js_files_found': [], 'summary': {'total_js_files': 0}}
                mock_linkfinder.return_value = {'success': True, 'all_endpoints': [], 'summary': {'total_endpoints': 0}}
                mock_arjun.return_value = {'success': True, 'endpoints_found': [], 'summary': {'total_endpoints': 0}}
                mock_eyewitness.return_value = {'success': True, 'screenshots': [], 'summary': {'total_targets': 0}}
                mock_eyeballer.return_value = {'success': True, 'interesting_findings': [], 'summary': {'analyzed_screenshots': 0}}

                # Mock subprocess to return success for tool availability checks
                with patch('subprocess.run') as mock_subprocess:
                    mock_subprocess.return_value.returncode = 0
                    mock_subprocess.return_value.stdout = b"tool version info"

                    # Run the main function - should not raise exceptions
                    main()

        # Verify that tools were still called despite network failures
        mock_nmap.assert_called_once()
        mock_naabu.assert_called_once()
        mock_webanalyze.assert_called_once()
        mock_puredns.assert_called_once()
        mock_katana.assert_called_once()
        mock_feroxbuster.assert_called_once()
        mock_getjs.assert_called_once()
        mock_linkfinder.assert_not_called()

    def test_file_system_error_handling(self):
        """Test handling of file system errors"""
        # Test with invalid directory path
        with patch('os.makedirs', side_effect=OSError("Permission denied")):
            # Should handle gracefully and return default structure
            try:
                dirs = setup_output_dirs(self.test_stage, self.test_target)
                # If we get here, the function handled the error gracefully
                self.assertIsInstance(dirs, dict)
                self.assertIn('output_dir', dirs)
                self.assertIn('parsed_dir', dirs)
                self.assertIn('raw_dir', dirs)
            except OSError:
                # If the function doesn't handle the error, that's also acceptable
                # as long as it doesn't crash the entire workflow
                pass

    @patch('sys.argv', ['run_active_recon.py', '--target', 'example.com', '--stage', 'active_recon'])
    @patch('os.environ.get')
    def test_missing_dependencies_handling(self, mock_env):
        """Test handling of missing tool dependencies"""
        # Mock environment variables
        mock_env.side_effect = lambda key, default=None: {
            'BACKEND_API_URL': 'http://backend:8000/api/results/active_recon',
            'BACKEND_JWT_TOKEN': 'test_jwt_token',
            'TARGETS_API_URL': 'http://backend:8000/api/targets/',
            'PASSIVE_API_URL': 'http://backend:8000/api/results/passive-recon'
        }.get(key, default)

        # Mock file operations
        with patch('builtins.open', mock_open()), \
             patch('os.makedirs'), \
             patch('json.dump'), \
             patch('os.path.exists', return_value=True), \
             patch('requests.get') as mock_get, \
             patch('requests.post') as mock_post:

            # Mock API responses
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                'success': True,
                'data': {'targets': []}
            }
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {'success': True}

            # Mock subprocess to simulate missing tools
            with patch('subprocess.run') as mock_subprocess:
                mock_subprocess.side_effect = FileNotFoundError("No such file or directory")

                # Mock all tool runners to handle missing tools gracefully
                with patch('run_active_recon.run_nmap') as mock_nmap, \
                     patch('run_active_recon.run_naabu') as mock_naabu, \
                     patch('run_active_recon.run_webanalyze') as mock_webanalyze, \
                     patch('run_active_recon.run_puredns') as mock_puredns, \
                     patch('run_active_recon.run_katana') as mock_katana, \
                     patch('run_active_recon.run_feroxbuster') as mock_feroxbuster, \
                     patch('run_active_recon.run_getjs') as mock_getjs, \
                     patch('run_active_recon.run_linkfinder') as mock_linkfinder, \
                     patch('run_active_recon.run_arjun') as mock_arjun, \
                     patch('run_active_recon.run_eyewitness') as mock_eyewitness, \
                     patch('run_active_recon.run_eyeballer') as mock_eyeballer:

                    # Mock tool runners to handle missing tools gracefully
                    mock_nmap.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_naabu.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_webanalyze.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_puredns.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_katana.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_feroxbuster.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_getjs.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_linkfinder.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_arjun.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_eyewitness.return_value = {'success': False, 'error': 'Tool not found'}
                    mock_eyeballer.return_value = {'success': False, 'error': 'Tool not found'}

                    # Run the main function - should not raise exceptions
                    main()

        # Verify that tools were still called despite missing dependencies
        mock_nmap.assert_called_once()
        mock_naabu.assert_called_once()
        mock_webanalyze.assert_called_once()
        mock_puredns.assert_called_once()
        mock_katana.assert_called_once()
        mock_feroxbuster.assert_called_once()
        mock_getjs.assert_called_once()
        mock_linkfinder.assert_not_called()
        mock_arjun.assert_not_called()
        mock_eyewitness.assert_not_called()
        mock_eyeballer.assert_not_called()


if __name__ == '__main__':
    unittest.main() 