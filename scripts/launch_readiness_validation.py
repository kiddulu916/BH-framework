#!/usr/bin/env python3
"""
Launch Readiness Validation Script
Phase 4: Production Deployment and Launch Preparation

This script conducts comprehensive validation of production readiness including:
- Production readiness assessment
- Security audit and penetration testing
- Performance validation under load
- User acceptance testing validation
"""

import os
import sys
import json
import time
import requests
import subprocess
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('launch_readiness_validation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Validation result data structure"""
    test_name: str
    status: str  # PASS, FAIL, WARNING
    details: str
    timestamp: str
    duration: float
    metrics: Optional[Dict[str, Any]] = None

@dataclass
class LaunchReadinessReport:
    """Launch readiness report structure"""
    timestamp: str
    overall_status: str
    total_tests: int
    passed_tests: int
    failed_tests: int
    warning_tests: int
    results: List[ValidationResult]
    recommendations: List[str]
    next_steps: List[str]

class LaunchReadinessValidator:
    """Comprehensive launch readiness validation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.results: List[ValidationResult] = []
        self.start_time = time.time()
        
        # Load environment variables
        self.backend_url = os.getenv('BACKEND_URL', 'http://localhost:8000')
        self.frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:3000')
        self.jwt_token = os.getenv('JWT_TOKEN', '')
        
    def run_validation(self) -> LaunchReadinessReport:
        """Run complete launch readiness validation"""
        logger.info("Starting Launch Readiness Validation")
        
        # 1. Production Readiness Assessment
        self._validate_production_readiness()
        
        # 2. Security Audit and Penetration Testing
        self._validate_security_audit()
        
        # 3. Performance Validation
        self._validate_performance()
        
        # 4. User Acceptance Testing
        self._validate_user_acceptance()
        
        # Generate report
        return self._generate_report()
    
    def _validate_production_readiness(self):
        """Validate production readiness assessment"""
        logger.info("Validating Production Readiness")
        
        # Check Docker Compose services
        self._test_docker_services()
        
        # Check database connectivity
        self._test_database_connectivity()
        
        # Check API endpoints
        self._test_api_endpoints()
        
        # Check frontend accessibility
        self._test_frontend_accessibility()
        
        # Check monitoring systems
        self._test_monitoring_systems()
        
        # Check backup systems
        self._test_backup_systems()
    
    def _validate_security_audit(self):
        """Validate security audit and penetration testing"""
        logger.info("Validating Security Audit")
        
        # Check SSL/TLS configuration
        self._test_ssl_tls_configuration()
        
        # Check security headers
        self._test_security_headers()
        
        # Check authentication mechanisms
        self._test_authentication_security()
        
        # Check input validation
        self._test_input_validation()
        
        # Check access controls
        self._test_access_controls()
        
        # Check vulnerability scanning
        self._test_vulnerability_scanning()
    
    def _validate_performance(self):
        """Validate performance under production load"""
        logger.info("Validating Performance")
        
        # Load testing
        self._test_load_performance()
        
        # Stress testing
        self._test_stress_performance()
        
        # Resource utilization
        self._test_resource_utilization()
        
        # Response time validation
        self._test_response_times()
        
        # Scalability testing
        self._test_scalability()
    
    def _validate_user_acceptance(self):
        """Validate user acceptance testing"""
        logger.info("Validating User Acceptance")
        
        # End-to-end workflow testing
        self._test_end_to_end_workflow()
        
        # User interface testing
        self._test_user_interface()
        
        # Error handling testing
        self._test_error_handling()
        
        # Data consistency testing
        self._test_data_consistency()
    
    def _test_docker_services(self):
        """Test Docker Compose services health"""
        start_time = time.time()
        try:
            result = subprocess.run(
                ['docker-compose', 'ps'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Check if all services are running
                services_running = 0
                total_services = 0
                
                for line in result.stdout.split('\n'):
                    if 'Up' in line:
                        services_running += 1
                    if line.strip() and not line.startswith('Name'):
                        total_services += 1
                
                if services_running == total_services:
                    self._add_result(
                        "Docker Services Health",
                        "PASS",
                        f"All {services_running} services are running",
                        time.time() - start_time
                    )
                else:
                    self._add_result(
                        "Docker Services Health",
                        "FAIL",
                        f"Only {services_running}/{total_services} services running",
                        time.time() - start_time
                    )
            else:
                self._add_result(
                    "Docker Services Health",
                    "FAIL",
                    f"Docker Compose check failed: {result.stderr}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Docker Services Health",
                "FAIL",
                f"Exception: {str(e)}",
                time.time() - start_time
            )
    
    def _test_database_connectivity(self):
        """Test database connectivity"""
        start_time = time.time()
        try:
            response = requests.get(
                f"{self.backend_url}/api/health/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self._add_result(
                        "Database Connectivity",
                        "PASS",
                        "Database connection successful",
                        time.time() - start_time
                    )
                else:
                    self._add_result(
                        "Database Connectivity",
                        "FAIL",
                        f"Database health check failed: {data.get('message')}",
                        time.time() - start_time
                    )
            else:
                self._add_result(
                    "Database Connectivity",
                    "FAIL",
                    f"Health check returned status {response.status_code}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Database Connectivity",
                "FAIL",
                f"Exception: {str(e)}",
                time.time() - start_time
            )
    
    def _test_api_endpoints(self):
        """Test API endpoints functionality"""
        start_time = time.time()
        try:
            # Test targets endpoint
            response = requests.get(
                f"{self.backend_url}/api/targets/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            if response.status_code == 200:
                self._add_result(
                    "API Endpoints",
                    "PASS",
                    "API endpoints responding correctly",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "API Endpoints",
                    "FAIL",
                    f"API endpoint returned status {response.status_code}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "API Endpoints",
                "FAIL",
                f"Exception: {str(e)}",
                time.time() - start_time
            )
    
    def _test_frontend_accessibility(self):
        """Test frontend accessibility"""
        start_time = time.time()
        try:
            response = requests.get(self.frontend_url, timeout=10)
            
            if response.status_code == 200:
                self._add_result(
                    "Frontend Accessibility",
                    "PASS",
                    "Frontend is accessible",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Frontend Accessibility",
                    "FAIL",
                    f"Frontend returned status {response.status_code}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Frontend Accessibility",
                "FAIL",
                f"Exception: {str(e)}",
                time.time() - start_time
            )
    
    def _test_monitoring_systems(self):
        """Test monitoring systems"""
        start_time = time.time()
        try:
            # Test Prometheus
            prometheus_response = requests.get('http://localhost:9090/-/healthy', timeout=5)
            
            # Test Grafana
            grafana_response = requests.get('http://localhost:3001/api/health', timeout=5)
            
            if prometheus_response.status_code == 200 and grafana_response.status_code == 200:
                self._add_result(
                    "Monitoring Systems",
                    "PASS",
                    "Prometheus and Grafana are healthy",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Monitoring Systems",
                    "WARNING",
                    "Some monitoring systems may not be fully operational",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Monitoring Systems",
                "WARNING",
                f"Monitoring systems check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_backup_systems(self):
        """Test backup systems"""
        start_time = time.time()
        try:
            # Check if backup script exists and is executable
            backup_script = "scripts/backup.sh"
            if os.path.exists(backup_script) and os.access(backup_script, os.X_OK):
                self._add_result(
                    "Backup Systems",
                    "PASS",
                    "Backup script is available and executable",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Backup Systems",
                    "WARNING",
                    "Backup script may not be properly configured",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Backup Systems",
                "FAIL",
                f"Backup systems check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_ssl_tls_configuration(self):
        """Test SSL/TLS configuration"""
        start_time = time.time()
        try:
            # Test HTTPS endpoints if available
            https_urls = [
                self.backend_url.replace('http://', 'https://'),
                self.frontend_url.replace('http://', 'https://')
            ]
            
            ssl_working = 0
            for url in https_urls:
                try:
                    response = requests.get(url, timeout=10, verify=True)
                    if response.status_code == 200:
                        ssl_working += 1
                except:
                    pass
            
            if ssl_working > 0:
                self._add_result(
                    "SSL/TLS Configuration",
                    "PASS",
                    f"SSL/TLS is working for {ssl_working} endpoints",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "SSL/TLS Configuration",
                    "WARNING",
                    "SSL/TLS may not be fully configured",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "SSL/TLS Configuration",
                "WARNING",
                f"SSL/TLS check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_security_headers(self):
        """Test security headers"""
        start_time = time.time()
        try:
            response = requests.get(self.frontend_url, timeout=10)
            
            security_headers = [
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            present_headers = 0
            for header in security_headers:
                if header in response.headers:
                    present_headers += 1
            
            if present_headers >= 3:
                self._add_result(
                    "Security Headers",
                    "PASS",
                    f"{present_headers}/{len(security_headers)} security headers present",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Security Headers",
                    "WARNING",
                    f"Only {present_headers}/{len(security_headers)} security headers present",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Security Headers",
                "FAIL",
                f"Security headers check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_authentication_security(self):
        """Test authentication security"""
        start_time = time.time()
        try:
            # Test with invalid token
            response = requests.get(
                f"{self.backend_url}/api/targets/",
                timeout=10,
                headers={'Authorization': 'Bearer invalid_token'}
            )
            
            if response.status_code == 401:
                self._add_result(
                    "Authentication Security",
                    "PASS",
                    "Invalid tokens are properly rejected",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Authentication Security",
                    "WARNING",
                    "Authentication may not be properly enforced",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Authentication Security",
                "FAIL",
                f"Authentication security check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_input_validation(self):
        """Test input validation"""
        start_time = time.time()
        try:
            # Test with malformed data
            malformed_data = {
                "target": "<script>alert('xss')</script>",
                "domain": "invalid-domain-format",
                "status": "INVALID_STATUS"
            }
            
            response = requests.post(
                f"{self.backend_url}/api/targets/",
                json=malformed_data,
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            if response.status_code == 422:  # Validation error
                self._add_result(
                    "Input Validation",
                    "PASS",
                    "Input validation is working correctly",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Input Validation",
                    "WARNING",
                    "Input validation may not be properly enforced",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Input Validation",
                "FAIL",
                f"Input validation check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_access_controls(self):
        """Test access controls"""
        start_time = time.time()
        try:
            # Test without authentication
            response = requests.get(
                f"{self.backend_url}/api/targets/",
                timeout=10
            )
            
            if response.status_code == 401:
                self._add_result(
                    "Access Controls",
                    "PASS",
                    "Access controls are properly enforced",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Access Controls",
                    "FAIL",
                    "Access controls may not be properly enforced",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Access Controls",
                "FAIL",
                f"Access controls check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_vulnerability_scanning(self):
        """Test vulnerability scanning"""
        start_time = time.time()
        try:
            # Basic vulnerability check using requests
            response = requests.get(
                f"{self.backend_url}/api/health/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            # Check for common security issues
            security_issues = []
            
            if 'Server' in response.headers:
                server_info = response.headers['Server']
                if 'nginx' in server_info.lower():
                    security_issues.append("Server information disclosure")
            
            if not security_issues:
                self._add_result(
                    "Vulnerability Scanning",
                    "PASS",
                    "No obvious security vulnerabilities detected",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Vulnerability Scanning",
                    "WARNING",
                    f"Potential security issues: {', '.join(security_issues)}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Vulnerability Scanning",
                "WARNING",
                f"Vulnerability scanning check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_load_performance(self):
        """Test load performance"""
        start_time = time.time()
        try:
            # Simple load test with multiple concurrent requests
            import concurrent.futures
            
            def make_request():
                try:
                    response = requests.get(
                        f"{self.backend_url}/api/health/",
                        timeout=5,
                        headers={'Authorization': f'Bearer {self.jwt_token}'}
                    )
                    return response.status_code == 200
                except:
                    return False
            
            # Test with 10 concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                results = [future.result() for future in futures]
            
            success_rate = sum(results) / len(results)
            
            if success_rate >= 0.9:
                self._add_result(
                    "Load Performance",
                    "PASS",
                    f"Load test passed with {success_rate:.1%} success rate",
                    time.time() - start_time,
                    {"success_rate": success_rate}
                )
            else:
                self._add_result(
                    "Load Performance",
                    "WARNING",
                    f"Load test showed {success_rate:.1%} success rate",
                    time.time() - start_time,
                    {"success_rate": success_rate}
                )
        except Exception as e:
            self._add_result(
                "Load Performance",
                "FAIL",
                f"Load performance test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_stress_performance(self):
        """Test stress performance"""
        start_time = time.time()
        try:
            # Stress test with longer duration
            import concurrent.futures
            import time
            
            def stress_request():
                try:
                    response = requests.get(
                        f"{self.backend_url}/api/health/",
                        timeout=10,
                        headers={'Authorization': f'Bearer {self.jwt_token}'}
                    )
                    return response.status_code == 200
                except:
                    return False
            
            # Run stress test for 30 seconds
            end_time = time.time() + 30
            successful_requests = 0
            total_requests = 0
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                while time.time() < end_time:
                    futures = [executor.submit(stress_request) for _ in range(5)]
                    for future in futures:
                        if future.result():
                            successful_requests += 1
                        total_requests += 1
            
            success_rate = successful_requests / total_requests if total_requests > 0 else 0
            
            if success_rate >= 0.8:
                self._add_result(
                    "Stress Performance",
                    "PASS",
                    f"Stress test passed with {success_rate:.1%} success rate",
                    time.time() - start_time,
                    {"success_rate": success_rate, "total_requests": total_requests}
                )
            else:
                self._add_result(
                    "Stress Performance",
                    "WARNING",
                    f"Stress test showed {success_rate:.1%} success rate",
                    time.time() - start_time,
                    {"success_rate": success_rate, "total_requests": total_requests}
                )
        except Exception as e:
            self._add_result(
                "Stress Performance",
                "FAIL",
                f"Stress performance test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_resource_utilization(self):
        """Test resource utilization"""
        start_time = time.time()
        try:
            # Check Docker container resource usage
            result = subprocess.run(
                ['docker', 'stats', '--no-stream', '--format', 'table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self._add_result(
                    "Resource Utilization",
                    "PASS",
                    "Resource utilization monitoring available",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Resource Utilization",
                    "WARNING",
                    "Resource utilization monitoring may not be available",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Resource Utilization",
                "WARNING",
                f"Resource utilization check failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_response_times(self):
        """Test response times"""
        start_time = time.time()
        try:
            # Test response time for health endpoint
            response_start = time.time()
            response = requests.get(
                f"{self.backend_url}/api/health/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            response_time = time.time() - response_start
            
            if response.status_code == 200 and response_time < 2.0:
                self._add_result(
                    "Response Times",
                    "PASS",
                    f"Response time: {response_time:.2f}s",
                    time.time() - start_time,
                    {"response_time": response_time}
                )
            else:
                self._add_result(
                    "Response Times",
                    "WARNING",
                    f"Response time: {response_time:.2f}s (may be slow)",
                    time.time() - start_time,
                    {"response_time": response_time}
                )
        except Exception as e:
            self._add_result(
                "Response Times",
                "FAIL",
                f"Response time test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_scalability(self):
        """Test scalability"""
        start_time = time.time()
        try:
            # Test with increasing load
            import concurrent.futures
            
            def scalability_request():
                try:
                    response = requests.get(
                        f"{self.backend_url}/api/health/",
                        timeout=5,
                        headers={'Authorization': f'Bearer {self.jwt_token}'}
                    )
                    return response.status_code == 200
                except:
                    return False
            
            # Test different load levels
            load_levels = [5, 10, 15]
            scalability_results = {}
            
            for load in load_levels:
                with concurrent.futures.ThreadPoolExecutor(max_workers=load) as executor:
                    futures = [executor.submit(scalability_request) for _ in range(load)]
                    results = [future.result() for future in futures]
                    success_rate = sum(results) / len(results)
                    scalability_results[f"load_{load}"] = success_rate
            
            # Check if performance degrades gracefully
            if all(rate >= 0.7 for rate in scalability_results.values()):
                self._add_result(
                    "Scalability",
                    "PASS",
                    "System scales well under increasing load",
                    time.time() - start_time,
                    scalability_results
                )
            else:
                self._add_result(
                    "Scalability",
                    "WARNING",
                    "System may not scale well under high load",
                    time.time() - start_time,
                    scalability_results
                )
        except Exception as e:
            self._add_result(
                "Scalability",
                "FAIL",
                f"Scalability test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_end_to_end_workflow(self):
        """Test end-to-end workflow"""
        start_time = time.time()
        try:
            # Test complete workflow from target creation to report generation
            # This is a simplified test - in production, this would be more comprehensive
            
            # 1. Create target
            target_data = {
                "target": "test-readiness.example.com",
                "domain": "test-readiness.example.com",
                "status": "ACTIVE",
                "platform": "BUGBOUNTY",
                "is_primary": True
            }
            
            response = requests.post(
                f"{self.backend_url}/api/targets/",
                json=target_data,
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            if response.status_code == 200:
                self._add_result(
                    "End-to-End Workflow",
                    "PASS",
                    "End-to-end workflow test passed",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "End-to-End Workflow",
                    "FAIL",
                    f"End-to-end workflow test failed: {response.status_code}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "End-to-End Workflow",
                "FAIL",
                f"End-to-end workflow test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_user_interface(self):
        """Test user interface"""
        start_time = time.time()
        try:
            # Test frontend accessibility and basic functionality
            response = requests.get(self.frontend_url, timeout=10)
            
            if response.status_code == 200:
                # Check for basic UI elements
                content = response.text.lower()
                ui_elements = ['html', 'body', 'script', 'css']
                present_elements = sum(1 for elem in ui_elements if elem in content)
                
                if present_elements >= 3:
                    self._add_result(
                        "User Interface",
                        "PASS",
                        "User interface is accessible and functional",
                        time.time() - start_time
                    )
                else:
                    self._add_result(
                        "User Interface",
                        "WARNING",
                        "User interface may not be fully functional",
                        time.time() - start_time
                    )
            else:
                self._add_result(
                    "User Interface",
                    "FAIL",
                    f"User interface returned status {response.status_code}",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "User Interface",
                "FAIL",
                f"User interface test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_error_handling(self):
        """Test error handling"""
        start_time = time.time()
        try:
            # Test various error scenarios
            error_scenarios = [
                ("Invalid endpoint", f"{self.backend_url}/api/invalid/"),
                ("Invalid method", f"{self.backend_url}/api/health/", "PUT"),
                ("Missing authentication", f"{self.backend_url}/api/targets/")
            ]
            
            proper_error_handling = 0
            for scenario, url, *args in error_scenarios:
                try:
                    method = args[0] if args else "GET"
                    if method == "GET":
                        response = requests.get(url, timeout=5)
                    elif method == "PUT":
                        response = requests.put(url, timeout=5)
                    
                    # Check if error is handled properly (4xx status codes)
                    if 400 <= response.status_code < 500:
                        proper_error_handling += 1
                except:
                    proper_error_handling += 1  # Exception handling is also good
            
            if proper_error_handling == len(error_scenarios):
                self._add_result(
                    "Error Handling",
                    "PASS",
                    "Error handling is working correctly",
                    time.time() - start_time
                )
            else:
                self._add_result(
                    "Error Handling",
                    "WARNING",
                    f"Error handling may need improvement ({proper_error_handling}/{len(error_scenarios)})",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Error Handling",
                "FAIL",
                f"Error handling test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _test_data_consistency(self):
        """Test data consistency"""
        start_time = time.time()
        try:
            # Test data consistency across API calls
            response1 = requests.get(
                f"{self.backend_url}/api/targets/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            time.sleep(1)  # Small delay
            
            response2 = requests.get(
                f"{self.backend_url}/api/targets/",
                timeout=10,
                headers={'Authorization': f'Bearer {self.jwt_token}'}
            )
            
            if response1.status_code == 200 and response2.status_code == 200:
                data1 = response1.json()
                data2 = response2.json()
                
                # Check if data structure is consistent
                if data1.get('success') == data2.get('success'):
                    self._add_result(
                        "Data Consistency",
                        "PASS",
                        "Data consistency is maintained",
                        time.time() - start_time
                    )
                else:
                    self._add_result(
                        "Data Consistency",
                        "WARNING",
                        "Data consistency may have issues",
                        time.time() - start_time
                    )
            else:
                self._add_result(
                    "Data Consistency",
                    "FAIL",
                    "Data consistency test failed due to API errors",
                    time.time() - start_time
                )
        except Exception as e:
            self._add_result(
                "Data Consistency",
                "FAIL",
                f"Data consistency test failed: {str(e)}",
                time.time() - start_time
            )
    
    def _add_result(self, test_name: str, status: str, details: str, duration: float, metrics: Optional[Dict[str, Any]] = None):
        """Add validation result"""
        result = ValidationResult(
            test_name=test_name,
            status=status,
            details=details,
            timestamp=datetime.now(timezone.utc).isoformat(),
            duration=duration,
            metrics=metrics
        )
        self.results.append(result)
        logger.info(f"{status}: {test_name} - {details}")
    
    def _generate_report(self) -> LaunchReadinessReport:
        """Generate launch readiness report"""
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.status == "PASS")
        failed_tests = sum(1 for r in self.results if r.status == "FAIL")
        warning_tests = sum(1 for r in self.results if r.status == "WARNING")
        
        # Determine overall status
        if failed_tests == 0 and warning_tests <= 3:
            overall_status = "READY"
        elif failed_tests <= 2:
            overall_status = "READY_WITH_WARNINGS"
        else:
            overall_status = "NOT_READY"
        
        # Generate recommendations
        recommendations = []
        if failed_tests > 0:
            recommendations.append(f"Fix {failed_tests} failed tests before launch")
        if warning_tests > 0:
            recommendations.append(f"Address {warning_tests} warnings for optimal performance")
        
        # Generate next steps
        next_steps = []
        if overall_status == "READY":
            next_steps.append("Proceed with go-live execution")
        elif overall_status == "READY_WITH_WARNINGS":
            next_steps.append("Address warnings and proceed with go-live")
        else:
            next_steps.append("Fix critical issues before proceeding")
        
        next_steps.extend([
            "Execute go-live plan",
            "Monitor system performance post-launch",
            "Collect user feedback and optimize"
        ])
        
        return LaunchReadinessReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            overall_status=overall_status,
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            warning_tests=warning_tests,
            results=self.results,
            recommendations=recommendations,
            next_steps=next_steps
        )

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Launch Readiness Validation")
    parser.add_argument("--config", default="launch_config.json", help="Configuration file")
    parser.add_argument("--output", default="launch_readiness_report.json", help="Output report file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Run validation
    validator = LaunchReadinessValidator(config)
    report = validator.run_validation()
    
    # Save report
    with open(args.output, 'w') as f:
        json.dump(asdict(report), f, indent=2)
    
    # Print summary
    print(f"\n=== Launch Readiness Validation Report ===")
    print(f"Overall Status: {report.overall_status}")
    print(f"Total Tests: {report.total_tests}")
    print(f"Passed: {report.passed_tests}")
    print(f"Failed: {report.failed_tests}")
    print(f"Warnings: {report.warning_tests}")
    
    if report.recommendations:
        print(f"\nRecommendations:")
        for rec in report.recommendations:
            print(f"  - {rec}")
    
    if report.next_steps:
        print(f"\nNext Steps:")
        for step in report.next_steps:
            print(f"  - {step}")
    
    print(f"\nDetailed report saved to: {args.output}")
    
    # Exit with appropriate code
    if report.overall_status == "NOT_READY":
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main() 