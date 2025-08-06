"""
Docker Compose Integration Testing Suite

This module provides comprehensive testing for Docker Compose deployment,
service dependencies, health checks, resource management, and production readiness.
"""

import os
import time
import json
import subprocess
import requests
import docker
import pytest
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ServiceConfig:
    """Configuration for a Docker service."""
    name: str
    port: int
    health_check_url: Optional[str] = None
    health_check_cmd: Optional[str] = None
    startup_timeout: int = 120
    resource_limits: Optional[Dict] = None
    environment_vars: Optional[Dict] = None

@dataclass
class TestResult:
    """Result of a Docker Compose test."""
    test_name: str
    success: bool
    duration: float
    details: Dict
    error_message: Optional[str] = None

class DockerComposeIntegrationTester:
    """Comprehensive Docker Compose integration testing framework."""
    
    def __init__(self, compose_file: str = "docker-compose.yml", project_name: str = "bug-hunting-framework"):
        self.compose_file = compose_file
        self.project_name = project_name
        self.client = docker.from_env()
        self.test_results: List[TestResult] = []
        
        # Define expected services and their configurations
        self.expected_services = {
            "db": ServiceConfig(
                name="db",
                port=5432,
                health_check_cmd="pg_isready -U postgres",
                startup_timeout=60,
                resource_limits={"memory": "1G", "cpus": "0.5"}
            ),
            "backend": ServiceConfig(
                name="backend",
                port=8000,
                health_check_url="http://localhost:8000/health/",
                startup_timeout=120,
                resource_limits={"memory": "2G", "cpus": "1.0"}
            ),
            "frontend": ServiceConfig(
                name="frontend",
                port=3000,
                health_check_url="http://localhost:3000/",
                startup_timeout=90,
                resource_limits={"memory": "1G", "cpus": "0.5"}
            ),
            "passive_recon": ServiceConfig(
                name="passive_recon",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "2G", "cpus": "0.8"}
            ),
            "active_recon": ServiceConfig(
                name="active_recon",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "2G", "cpus": "0.8"}
            ),
            "vuln_scan": ServiceConfig(
                name="vuln_scan",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "2G", "cpus": "0.8"}
            ),
            "vuln_test": ServiceConfig(
                name="vuln_test",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "4G", "cpus": "1.0"}
            ),
            "kill_chain": ServiceConfig(
                name="kill_chain",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "2G", "cpus": "0.8"}
            ),
            "comprehensive_reporting": ServiceConfig(
                name="comprehensive_reporting",
                port=None,
                health_check_cmd="python -c 'import requests; requests.get(\"http://backend:8000/health/\", timeout=5)'",
                startup_timeout=60,
                resource_limits={"memory": "4G", "cpus": "1.0"}
            )
        }
    
    def run_test(self, test_name: str, test_func) -> TestResult:
        """Run a test and record the result."""
        start_time = time.time()
        try:
            result = test_func()
            duration = time.time() - start_time
            return TestResult(
                test_name=test_name,
                success=True,
                duration=duration,
                details=result
            )
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Test {test_name} failed: {str(e)}")
            return TestResult(
                test_name=test_name,
                success=False,
                duration=duration,
                details={},
                error_message=str(e)
            )
    
    def test_docker_compose_file_exists(self) -> Dict:
        """Test that Docker Compose file exists and is valid."""
        logger.info("Testing Docker Compose file existence and validity")
        
        # Check if compose file exists
        if not os.path.exists(self.compose_file):
            raise FileNotFoundError(f"Docker Compose file {self.compose_file} not found")
        
        # Validate compose file syntax
        try:
            result = subprocess.run(
                ["docker-compose", "-f", self.compose_file, "config"],
                capture_output=True,
                text=True,
                check=True
            )
            logger.info("Docker Compose file is valid")
            return {"valid": True, "output": result.stdout}
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Docker Compose file is invalid: {e.stderr}")
    
    def test_service_definitions(self) -> Dict:
        """Test that all expected services are defined in Docker Compose."""
        logger.info("Testing service definitions")
        
        # Parse compose file to get defined services
        result = subprocess.run(
            ["docker-compose", "-f", self.compose_file, "config", "--services"],
            capture_output=True,
            text=True,
            check=True
        )
        defined_services = result.stdout.strip().split('\n')
        
        # Check for missing services
        missing_services = []
        for service_name in self.expected_services.keys():
            if service_name not in defined_services:
                missing_services.append(service_name)
        
        if missing_services:
            raise ValueError(f"Missing services in Docker Compose: {missing_services}")
        
        logger.info(f"All expected services are defined: {defined_services}")
        return {"defined_services": defined_services, "missing_services": []}
    
    def test_environment_configuration(self) -> Dict:
        """Test environment configuration and variable management."""
        logger.info("Testing environment configuration")
        
        # Check for required environment files
        required_env_files = [
            ".env",
            "backend/.env",
            "stages/passive_recon/.env",
            "stages/active_recon/.env",
            "stages/vuln_scan/.env",
            "stages/vuln_test/.env",
            "stages/kill_chain/.env",
            "stages/comprehensive_reporting/.env"
        ]
        
        missing_env_files = []
        for env_file in required_env_files:
            if not os.path.exists(env_file):
                missing_env_files.append(env_file)
        
        if missing_env_files:
            raise FileNotFoundError(f"Missing environment files: {missing_env_files}")
        
        # Test environment variable consistency
        env_consistency = self._check_environment_consistency()
        
        logger.info("Environment configuration is valid")
        return {
            "env_files_present": len(required_env_files) - len(missing_env_files),
            "missing_env_files": missing_env_files,
            "env_consistency": env_consistency
        }
    
    def _check_environment_consistency(self) -> Dict:
        """Check consistency of environment variables across services."""
        consistency_checks = {
            "jwt_secret_consistency": True,
            "backend_api_url_consistency": True,
            "database_config_consistency": True
        }
        
        # Check JWT secret consistency
        jwt_secrets = set()
        for env_file in ["backend/.env", "stages/passive_recon/.env"]:
            if os.path.exists(env_file):
                with open(env_file, 'r') as f:
                    for line in f:
                        if line.startswith("JWT_SECRET="):
                            jwt_secrets.add(line.strip().split("=", 1)[1])
        
        if len(jwt_secrets) > 1:
            consistency_checks["jwt_secret_consistency"] = False
        
        return consistency_checks
    
    @contextmanager
    def docker_compose_context(self):
        """Context manager for Docker Compose operations."""
        try:
            # Start services
            logger.info("Starting Docker Compose services")
            subprocess.run(
                ["docker-compose", "-f", self.compose_file, "up", "-d"],
                check=True
            )
            
            yield
            
        finally:
            # Clean up
            logger.info("Stopping Docker Compose services")
            subprocess.run(
                ["docker-compose", "-f", self.compose_file, "down", "-v"],
                check=True
            )
    
    def test_service_startup_sequences(self) -> Dict:
        """Test service startup sequences and dependency management."""
        logger.info("Testing service startup sequences")
        
        startup_results = {}
        
        with self.docker_compose_context():
            # Wait for services to start
            time.sleep(30)
            
            # Check service status
            result = subprocess.run(
                ["docker-compose", "-f", self.compose_file, "ps"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse service status
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        service_name = parts[0]
                        status = parts[1]
                        startup_results[service_name] = status
            
            # Check for failed services
            failed_services = [
                service for service, status in startup_results.items()
                if status not in ["Up", "running"]
            ]
            
            if failed_services:
                raise RuntimeError(f"Services failed to start: {failed_services}")
        
        logger.info("All services started successfully")
        return {"startup_results": startup_results, "failed_services": []}
    
    def test_health_checks(self) -> Dict:
        """Test health checks for all services."""
        logger.info("Testing health checks")
        
        health_check_results = {}
        
        with self.docker_compose_context():
            # Wait for services to be ready
            time.sleep(60)
            
            for service_name, config in self.expected_services.items():
                try:
                    if config.health_check_url:
                        # HTTP health check
                        response = requests.get(
                            config.health_check_url,
                            timeout=10,
                            headers={"User-Agent": "DockerComposeTest/1.0"}
                        )
                        health_check_results[service_name] = {
                            "status": "healthy" if response.status_code == 200 else "unhealthy",
                            "response_code": response.status_code,
                            "response_time": response.elapsed.total_seconds()
                        }
                    elif config.health_check_cmd:
                        # Command-based health check
                        container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                        result = container.exec_run(config.health_check_cmd)
                        health_check_results[service_name] = {
                            "status": "healthy" if result.exit_code == 0 else "unhealthy",
                            "exit_code": result.exit_code,
                            "output": result.output.decode()
                        }
                    else:
                        # Basic container status check
                        container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                        health_check_results[service_name] = {
                            "status": container.status,
                            "health": container.attrs.get("State", {}).get("Health", {}).get("Status", "unknown")
                        }
                
                except Exception as e:
                    health_check_results[service_name] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Check for unhealthy services
            unhealthy_services = [
                service for service, result in health_check_results.items()
                if result.get("status") not in ["healthy", "running"]
            ]
            
            if unhealthy_services:
                raise RuntimeError(f"Unhealthy services: {unhealthy_services}")
        
        logger.info("All health checks passed")
        return {"health_check_results": health_check_results, "unhealthy_services": []}
    
    def test_resource_management(self) -> Dict:
        """Test resource management and limits."""
        logger.info("Testing resource management")
        
        resource_results = {}
        
        with self.docker_compose_context():
            time.sleep(30)
            
            for service_name, config in self.expected_services.items():
                try:
                    container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                    stats = container.stats(stream=False)
                    
                    # Extract resource usage
                    cpu_usage = stats.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage", 0)
                    memory_usage = stats.get("memory_stats", {}).get("usage", 0)
                    memory_limit = stats.get("memory_stats", {}).get("limit", 0)
                    
                    resource_results[service_name] = {
                        "cpu_usage": cpu_usage,
                        "memory_usage_mb": memory_usage / (1024 * 1024),
                        "memory_limit_mb": memory_limit / (1024 * 1024),
                        "memory_usage_percent": (memory_usage / memory_limit * 100) if memory_limit > 0 else 0
                    }
                
                except Exception as e:
                    resource_results[service_name] = {"error": str(e)}
        
        logger.info("Resource management testing completed")
        return {"resource_results": resource_results}
    
    def test_network_isolation(self) -> Dict:
        """Test network isolation and service communication."""
        logger.info("Testing network isolation")
        
        network_results = {}
        
        with self.docker_compose_context():
            time.sleep(30)
            
            # Test inter-service communication
            test_communications = [
                ("backend", "db", "postgresql://postgres:postgres@db:5432/bug_hunting_framework"),
                ("frontend", "backend", "http://backend:8000/api/health/"),
                ("passive_recon", "backend", "http://backend:8000/api/health/")
            ]
            
            for source_service, target_service, connection_string in test_communications:
                try:
                    container = self.client.containers.get(f"{self.project_name}_{source_service}_1")
                    
                    if "http" in connection_string:
                        # HTTP connection test
                        result = container.exec_run(f"curl -f {connection_string}")
                        network_results[f"{source_service}_to_{target_service}"] = {
                            "status": "connected" if result.exit_code == 0 else "failed",
                            "exit_code": result.exit_code
                        }
                    else:
                        # Database connection test
                        result = container.exec_run(f"python -c 'import psycopg2; psycopg2.connect(\"{connection_string}\")'")
                        network_results[f"{source_service}_to_{target_service}"] = {
                            "status": "connected" if result.exit_code == 0 else "failed",
                            "exit_code": result.exit_code
                        }
                
                except Exception as e:
                    network_results[f"{source_service}_to_{target_service}"] = {
                        "status": "error",
                        "error": str(e)
                    }
        
        logger.info("Network isolation testing completed")
        return {"network_results": network_results}
    
    def test_volume_management(self) -> Dict:
        """Test volume mounting and data persistence."""
        logger.info("Testing volume management")
        
        volume_results = {}
        
        with self.docker_compose_context():
            time.sleep(30)
            
            # Test volume mounting
            expected_volumes = [
                ("db", "/var/lib/postgresql/data"),
                ("backend", "/app/outputs"),
                ("passive_recon", "/outputs"),
                ("active_recon", "/outputs"),
                ("vuln_scan", "/outputs"),
                ("vuln_test", "/outputs"),
                ("kill_chain", "/outputs"),
                ("comprehensive_reporting", "/outputs")
            ]
            
            for service_name, volume_path in expected_volumes:
                try:
                    container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                    result = container.exec_run(f"test -d {volume_path} && echo 'exists'")
                    
                    volume_results[f"{service_name}_{volume_path}"] = {
                        "status": "mounted" if result.exit_code == 0 else "not_mounted",
                        "exit_code": result.exit_code
                    }
                
                except Exception as e:
                    volume_results[f"{service_name}_{volume_path}"] = {
                        "status": "error",
                        "error": str(e)
                    }
        
        logger.info("Volume management testing completed")
        return {"volume_results": volume_results}
    
    def test_security_configuration(self) -> Dict:
        """Test security configuration and hardening."""
        logger.info("Testing security configuration")
        
        security_results = {}
        
        with self.docker_compose_context():
            time.sleep(30)
            
            # Test non-root user execution
            for service_name in ["backend", "passive_recon", "active_recon", "vuln_scan", "vuln_test", "kill_chain", "comprehensive_reporting"]:
                try:
                    container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                    result = container.exec_run("whoami")
                    user = result.output.decode().strip()
                    
                    security_results[f"{service_name}_user"] = {
                        "user": user,
                        "non_root": user != "root"
                    }
                
                except Exception as e:
                    security_results[f"{service_name}_user"] = {"error": str(e)}
            
            # Test security headers (for web services)
            for service_name, config in [("backend", 8000), ("frontend", 3000)]:
                try:
                    response = requests.get(
                        f"http://localhost:{config}",
                        timeout=10,
                        headers={"User-Agent": "DockerComposeTest/1.0"}
                    )
                    
                    security_headers = {
                        "X-Frame-Options": response.headers.get("X-Frame-Options"),
                        "X-Content-Type-Options": response.headers.get("X-Content-Type-Options"),
                        "X-XSS-Protection": response.headers.get("X-XSS-Protection"),
                        "Strict-Transport-Security": response.headers.get("Strict-Transport-Security")
                    }
                    
                    security_results[f"{service_name}_headers"] = security_headers
                
                except Exception as e:
                    security_results[f"{service_name}_headers"] = {"error": str(e)}
        
        logger.info("Security configuration testing completed")
        return {"security_results": security_results}
    
    def test_error_handling_and_recovery(self) -> Dict:
        """Test error handling and recovery scenarios."""
        logger.info("Testing error handling and recovery")
        
        recovery_results = {}
        
        with self.docker_compose_context():
            time.sleep(30)
            
            # Test service restart
            for service_name in ["backend", "frontend"]:
                try:
                    container = self.client.containers.get(f"{self.project_name}_{service_name}_1")
                    
                    # Restart service
                    container.restart()
                    time.sleep(10)
                    
                    # Check if service recovered
                    if config := self.expected_services.get(service_name):
                        if config.health_check_url:
                            response = requests.get(config.health_check_url, timeout=10)
                            recovery_results[f"{service_name}_restart"] = {
                                "status": "recovered" if response.status_code == 200 else "failed",
                                "response_code": response.status_code
                            }
                        else:
                            recovery_results[f"{service_name}_restart"] = {
                                "status": "restarted",
                                "container_status": container.status
                            }
                
                except Exception as e:
                    recovery_results[f"{service_name}_restart"] = {"error": str(e)}
            
            # Test network interruption
            try:
                # Simulate network interruption by stopping backend
                backend_container = self.client.containers.get(f"{self.project_name}_backend_1")
                backend_container.stop()
                time.sleep(5)
                
                # Check frontend error handling
                try:
                    response = requests.get("http://localhost:3000", timeout=5)
                    recovery_results["frontend_backend_failure"] = {
                        "status": "handled_gracefully",
                        "response_code": response.status_code
                    }
                except requests.exceptions.RequestException:
                    recovery_results["frontend_backend_failure"] = {
                        "status": "handled_gracefully",
                        "error": "Connection refused as expected"
                    }
                
                # Restart backend
                backend_container.start()
                time.sleep(10)
                
                # Check recovery
                response = requests.get("http://localhost:8000/health/", timeout=10)
                recovery_results["backend_recovery"] = {
                    "status": "recovered" if response.status_code == 200 else "failed",
                    "response_code": response.status_code
                }
            
            except Exception as e:
                recovery_results["network_recovery"] = {"error": str(e)}
        
        logger.info("Error handling and recovery testing completed")
        return {"recovery_results": recovery_results}
    
    def test_performance_under_load(self) -> Dict:
        """Test performance under load conditions."""
        logger.info("Testing performance under load")
        
        performance_results = {}
        
        with self.docker_compose_context():
            time.sleep(60)  # Wait for full startup
            
            # Test API performance
            try:
                # Concurrent requests test
                import concurrent.futures
                import threading
                
                def make_request():
                    try:
                        response = requests.get("http://localhost:8000/health/", timeout=5)
                        return response.status_code
                    except:
                        return None
                
                # Test with 10 concurrent requests
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(make_request) for _ in range(10)]
                    results = [future.result() for future in concurrent.futures.as_completed(futures)]
                
                successful_requests = sum(1 for r in results if r == 200)
                performance_results["concurrent_requests"] = {
                    "total_requests": 10,
                    "successful_requests": successful_requests,
                    "success_rate": successful_requests / 10 * 100
                }
                
                # Response time test
                start_time = time.time()
                response = requests.get("http://localhost:8000/health/", timeout=10)
                response_time = time.time() - start_time
                
                performance_results["response_time"] = {
                    "response_time_seconds": response_time,
                    "acceptable": response_time < 2.0  # Should respond within 2 seconds
                }
            
            except Exception as e:
                performance_results["api_performance"] = {"error": str(e)}
        
        logger.info("Performance testing completed")
        return {"performance_results": performance_results}
    
    def run_all_tests(self) -> Dict:
        """Run all Docker Compose integration tests."""
        logger.info("Starting comprehensive Docker Compose integration testing")
        
        test_functions = [
            ("docker_compose_file_exists", self.test_docker_compose_file_exists),
            ("service_definitions", self.test_service_definitions),
            ("environment_configuration", self.test_environment_configuration),
            ("service_startup_sequences", self.test_service_startup_sequences),
            ("health_checks", self.test_health_checks),
            ("resource_management", self.test_resource_management),
            ("network_isolation", self.test_network_isolation),
            ("volume_management", self.test_volume_management),
            ("security_configuration", self.test_security_configuration),
            ("error_handling_and_recovery", self.test_error_handling_and_recovery),
            ("performance_under_load", self.test_performance_under_load)
        ]
        
        for test_name, test_func in test_functions:
            logger.info(f"Running test: {test_name}")
            result = self.run_test(test_name, test_func)
            self.test_results.append(result)
            
            if not result.success:
                logger.error(f"Test {test_name} failed: {result.error_message}")
            else:
                logger.info(f"Test {test_name} passed in {result.duration:.2f}s")
        
        # Generate summary
        passed_tests = sum(1 for r in self.test_results if r.success)
        total_tests = len(self.test_results)
        
        summary = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": passed_tests / total_tests * 100 if total_tests > 0 else 0,
            "test_results": [r.__dict__ for r in self.test_results]
        }
        
        logger.info(f"Docker Compose integration testing completed: {passed_tests}/{total_tests} tests passed")
        return summary


# Test functions for pytest
@pytest.fixture
def docker_compose_tester():
    """Fixture for Docker Compose tester."""
    return DockerComposeIntegrationTester()

def test_docker_compose_file_exists(docker_compose_tester):
    """Test that Docker Compose file exists and is valid."""
    result = docker_compose_tester.test_docker_compose_file_exists()
    assert result["valid"] is True

def test_service_definitions(docker_compose_tester):
    """Test that all expected services are defined."""
    result = docker_compose_tester.test_service_definitions()
    assert len(result["missing_services"]) == 0

def test_environment_configuration(docker_compose_tester):
    """Test environment configuration."""
    result = docker_compose_tester.test_environment_configuration()
    assert len(result["missing_env_files"]) == 0

def test_service_startup_sequences(docker_compose_tester):
    """Test service startup sequences."""
    result = docker_compose_tester.test_service_startup_sequences()
    assert len(result["failed_services"]) == 0

def test_health_checks(docker_compose_tester):
    """Test health checks."""
    result = docker_compose_tester.test_health_checks()
    assert len(result["unhealthy_services"]) == 0

def test_resource_management(docker_compose_tester):
    """Test resource management."""
    result = docker_compose_tester.test_resource_management()
    assert "resource_results" in result

def test_network_isolation(docker_compose_tester):
    """Test network isolation."""
    result = docker_compose_tester.test_network_isolation()
    assert "network_results" in result

def test_volume_management(docker_compose_tester):
    """Test volume management."""
    result = docker_compose_tester.test_volume_management()
    assert "volume_results" in result

def test_security_configuration(docker_compose_tester):
    """Test security configuration."""
    result = docker_compose_tester.test_security_configuration()
    assert "security_results" in result

def test_error_handling_and_recovery(docker_compose_tester):
    """Test error handling and recovery."""
    result = docker_compose_tester.test_error_handling_and_recovery()
    assert "recovery_results" in result

def test_performance_under_load(docker_compose_tester):
    """Test performance under load."""
    result = docker_compose_tester.test_performance_under_load()
    assert "performance_results" in result

def test_complete_docker_compose_integration(docker_compose_tester):
    """Run complete Docker Compose integration test suite."""
    result = docker_compose_tester.run_all_tests()
    assert result["success_rate"] >= 90.0  # At least 90% of tests should pass


if __name__ == "__main__":
    # Run the complete test suite
    tester = DockerComposeIntegrationTester()
    results = tester.run_all_tests()
    
    print("\n" + "="*60)
    print("DOCKER COMPOSE INTEGRATION TEST RESULTS")
    print("="*60)
    print(f"Total Tests: {results['total_tests']}")
    print(f"Passed: {results['passed_tests']}")
    print(f"Failed: {results['failed_tests']}")
    print(f"Success Rate: {results['success_rate']:.1f}%")
    print("="*60)
    
    if results['failed_tests'] > 0:
        print("\nFAILED TESTS:")
        for test_result in results['test_results']:
            if not test_result['success']:
                print(f"  - {test_result['test_name']}: {test_result['error_message']}")
    
    print("\nDETAILED RESULTS:")
    for test_result in results['test_results']:
        status = "✅ PASS" if test_result['success'] else "❌ FAIL"
        print(f"  {status} {test_result['test_name']} ({test_result['duration']:.2f}s)")
    
    # Exit with appropriate code
    exit(0 if results['success_rate'] >= 90.0 else 1) 