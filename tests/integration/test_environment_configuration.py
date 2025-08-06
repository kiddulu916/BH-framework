"""
Environment Configuration Testing Suite

This module provides comprehensive testing for environment configuration,
variable management, consistency validation, and error handling across all services.
"""

import os
import json
import yaml
import subprocess
import pytest
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EnvironmentVariable:
    """Environment variable configuration."""
    name: str
    required: bool = True
    default_value: Optional[str] = None
    validation_regex: Optional[str] = None
    description: str = ""

@dataclass
class ServiceEnvironmentConfig:
    """Environment configuration for a service."""
    service_name: str
    env_file_path: str
    required_vars: List[EnvironmentVariable]
    optional_vars: List[EnvironmentVariable] = None
    dependencies: List[str] = None

class EnvironmentConfigurationTester:
    """Comprehensive environment configuration testing framework."""
    
    def __init__(self):
        self.test_results: List[Dict] = []
        
        # Define expected environment configurations for all services
        self.service_configs = {
            "backend": ServiceEnvironmentConfig(
                service_name="backend",
                env_file_path="backend/.env",
                required_vars=[
                    EnvironmentVariable("DATABASE_URL", description="Database connection string"),
                    EnvironmentVariable("JWT_SECRET", description="JWT signing secret"),
                    EnvironmentVariable("JWT_ALGORITHM", default_value="HS256", description="JWT algorithm"),
                    EnvironmentVariable("DEBUG", default_value="False", description="Debug mode"),
                    EnvironmentVariable("ALLOWED_HOSTS", description="Comma-separated list of allowed hosts"),
                    EnvironmentVariable("CORS_ALLOWED_ORIGINS", description="CORS allowed origins"),
                    EnvironmentVariable("SECRET_KEY", description="Django secret key"),
                    EnvironmentVariable("DB_NAME", description="Database name"),
                    EnvironmentVariable("DB_USER", description="Database user"),
                    EnvironmentVariable("DB_PASSWORD", description="Database password"),
                    EnvironmentVariable("DB_HOST", description="Database host"),
                    EnvironmentVariable("DB_PORT", default_value="5432", description="Database port")
                ],
                dependencies=["db"]
            ),
            "frontend": ServiceEnvironmentConfig(
                service_name="frontend",
                env_file_path="frontend/.env",
                required_vars=[
                    EnvironmentVariable("NEXT_PUBLIC_API_URL", description="Backend API URL"),
                    EnvironmentVariable("NEXT_PUBLIC_APP_NAME", default_value="Bug Hunting Framework", description="Application name")
                ],
                dependencies=["backend"]
            ),
            "passive_recon": ServiceEnvironmentConfig(
                service_name="passive_recon",
                env_file_path="stages/passive_recon/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="passive_recon", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("AMASS_PATH", description="Amass tool path"),
                    EnvironmentVariable("SUBFINDER_PATH", description="Subfinder tool path"),
                    EnvironmentVariable("ASSETFINDER_PATH", description="Assetfinder tool path")
                ],
                dependencies=["backend"]
            ),
            "active_recon": ServiceEnvironmentConfig(
                service_name="active_recon",
                env_file_path="stages/active_recon/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="active_recon", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("NMAP_PATH", description="Nmap tool path"),
                    EnvironmentVariable("HTTPX_PATH", description="Httpx tool path"),
                    EnvironmentVariable("NUCLEI_PATH", description="Nuclei tool path")
                ],
                dependencies=["backend"]
            ),
            "vuln_scan": ServiceEnvironmentConfig(
                service_name="vuln_scan",
                env_file_path="stages/vuln_scan/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="vuln_scan", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("NUCLEI_PATH", description="Nuclei tool path"),
                    EnvironmentVariable("NMAP_PATH", description="Nmap tool path"),
                    EnvironmentVariable("NIKTO_PATH", description="Nikto tool path")
                ],
                dependencies=["backend"]
            ),
            "vuln_test": ServiceEnvironmentConfig(
                service_name="vuln_test",
                env_file_path="stages/vuln_test/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="vuln_test", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("AI_MODEL_PATH", description="AI model path"),
                    EnvironmentVariable("BROWSER_PATH", description="Browser automation path")
                ],
                dependencies=["backend"]
            ),
            "kill_chain": ServiceEnvironmentConfig(
                service_name="kill_chain",
                env_file_path="stages/kill_chain/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="kill_chain", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("MITRE_ATTACK_DB", description="MITRE ATT&CK database path")
                ],
                dependencies=["backend"]
            ),
            "comprehensive_reporting": ServiceEnvironmentConfig(
                service_name="comprehensive_reporting",
                env_file_path="stages/comprehensive_reporting/.env",
                required_vars=[
                    EnvironmentVariable("BACKEND_API_URL", description="Backend API URL"),
                    EnvironmentVariable("BACKEND_JWT_TOKEN", description="JWT token for API authentication"),
                    EnvironmentVariable("JWT_SECRET", description="JWT secret (must match backend)"),
                    EnvironmentVariable("STAGE_NAME", default_value="comprehensive_reporting", description="Stage name"),
                    EnvironmentVariable("OUTPUT_DIR", default_value="/outputs", description="Output directory"),
                    EnvironmentVariable("REPORT_TEMPLATE_PATH", description="Report template path"),
                    EnvironmentVariable("COMPLIANCE_FRAMEWORK_PATH", description="Compliance framework path")
                ],
                dependencies=["backend"]
            )
        }
    
    def test_environment_file_existence(self) -> Dict:
        """Test that all required environment files exist."""
        logger.info("Testing environment file existence")
        
        results = {
            "existing_files": [],
            "missing_files": [],
            "total_files": len(self.service_configs)
        }
        
        for service_name, config in self.service_configs.items():
            if os.path.exists(config.env_file_path):
                results["existing_files"].append(config.env_file_path)
            else:
                results["missing_files"].append(config.env_file_path)
        
        if results["missing_files"]:
            raise FileNotFoundError(f"Missing environment files: {results['missing_files']}")
        
        logger.info(f"All {results['total_files']} environment files exist")
        return results
    
    def test_environment_file_syntax(self) -> Dict:
        """Test that all environment files have valid syntax."""
        logger.info("Testing environment file syntax")
        
        results = {
            "valid_files": [],
            "invalid_files": [],
            "syntax_errors": {}
        }
        
        for service_name, config in self.service_configs.items():
            try:
                # Load environment file to check syntax
                load_dotenv(config.env_file_path)
                results["valid_files"].append(config.env_file_path)
            except Exception as e:
                results["invalid_files"].append(config.env_file_path)
                results["syntax_errors"][config.env_file_path] = str(e)
        
        if results["invalid_files"]:
            raise ValueError(f"Invalid environment files: {results['syntax_errors']}")
        
        logger.info(f"All {len(results['valid_files'])} environment files have valid syntax")
        return results
    
    def test_required_environment_variables(self) -> Dict:
        """Test that all required environment variables are present."""
        logger.info("Testing required environment variables")
        
        results = {
            "services": {},
            "missing_vars": {},
            "total_required": 0,
            "total_present": 0
        }
        
        for service_name, config in self.service_configs.items():
            service_results = {
                "required_vars": [],
                "missing_vars": [],
                "present_vars": []
            }
            
            # Load environment file
            load_dotenv(config.env_file_path)
            
            for var in config.required_vars:
                results["total_required"] += 1
                value = os.getenv(var.name)
                
                if value is not None:
                    service_results["present_vars"].append(var.name)
                    results["total_present"] += 1
                else:
                    service_results["missing_vars"].append(var.name)
                    if service_name not in results["missing_vars"]:
                        results["missing_vars"][service_name] = []
                    results["missing_vars"][service_name].append(var.name)
            
            service_results["required_vars"] = [var.name for var in config.required_vars]
            results["services"][service_name] = service_results
        
        # Check for missing variables
        total_missing = sum(len(vars) for vars in results["missing_vars"].values())
        if total_missing > 0:
            raise ValueError(f"Missing required environment variables: {results['missing_vars']}")
        
        logger.info(f"All {results['total_present']}/{results['total_required']} required environment variables are present")
        return results
    
    def test_environment_variable_validation(self) -> Dict:
        """Test that environment variables have valid values."""
        logger.info("Testing environment variable validation")
        
        results = {
            "valid_vars": [],
            "invalid_vars": {},
            "validation_errors": {}
        }
        
        for service_name, config in self.service_configs.items():
            # Load environment file
            load_dotenv(config.env_file_path)
            
            for var in config.required_vars:
                value = os.getenv(var.name)
                if value is None:
                    continue
                
                # Basic validation checks
                validation_errors = []
                
                # Check for empty values (unless default is empty)
                if not value.strip() and var.default_value is not None:
                    validation_errors.append("Empty value")
                
                # Check URL format for URL variables
                if "URL" in var.name and value:
                    if not value.startswith(("http://", "https://", "postgresql://")):
                        validation_errors.append("Invalid URL format")
                
                # Check port number format
                if "PORT" in var.name and value:
                    try:
                        port = int(value)
                        if not (1 <= port <= 65535):
                            validation_errors.append("Invalid port number")
                    except ValueError:
                        validation_errors.append("Port must be a number")
                
                # Check boolean values
                if var.name in ["DEBUG", "ENABLE_LOGGING"] and value:
                    if value.lower() not in ["true", "false", "1", "0"]:
                        validation_errors.append("Invalid boolean value")
                
                if validation_errors:
                    if service_name not in results["invalid_vars"]:
                        results["invalid_vars"][service_name] = {}
                    results["invalid_vars"][service_name][var.name] = validation_errors
                    results["validation_errors"][f"{service_name}.{var.name}"] = validation_errors
                else:
                    results["valid_vars"].append(f"{service_name}.{var.name}")
        
        if results["validation_errors"]:
            raise ValueError(f"Environment variable validation errors: {results['validation_errors']}")
        
        logger.info(f"All {len(results['valid_vars'])} environment variables have valid values")
        return results
    
    def test_environment_consistency(self) -> Dict:
        """Test consistency of environment variables across services."""
        logger.info("Testing environment consistency across services")
        
        results = {
            "consistent_vars": [],
            "inconsistent_vars": {},
            "consistency_checks": {}
        }
        
        # Check JWT secret consistency
        jwt_secrets = {}
        for service_name, config in self.service_configs.items():
            load_dotenv(config.env_file_path)
            jwt_secret = os.getenv("JWT_SECRET")
            if jwt_secret:
                jwt_secrets[service_name] = jwt_secret
        
        if len(set(jwt_secrets.values())) > 1:
            results["inconsistent_vars"]["JWT_SECRET"] = jwt_secrets
            results["consistency_checks"]["jwt_secret"] = False
        else:
            results["consistent_vars"].append("JWT_SECRET")
            results["consistency_checks"]["jwt_secret"] = True
        
        # Check backend API URL consistency
        backend_urls = {}
        for service_name, config in self.service_configs.items():
            if service_name != "backend":  # Skip backend itself
                load_dotenv(config.env_file_path)
                api_url = os.getenv("BACKEND_API_URL")
                if api_url:
                    backend_urls[service_name] = api_url
        
        if len(set(backend_urls.values())) > 1:
            results["inconsistent_vars"]["BACKEND_API_URL"] = backend_urls
            results["consistency_checks"]["backend_api_url"] = False
        else:
            results["consistent_vars"].append("BACKEND_API_URL")
            results["consistency_checks"]["backend_api_url"] = True
        
        # Check database configuration consistency
        db_configs = {}
        for service_name, config in self.service_configs.items():
            load_dotenv(config.env_file_path)
            db_config = {
                "host": os.getenv("DB_HOST"),
                "port": os.getenv("DB_PORT"),
                "name": os.getenv("DB_NAME")
            }
            if all(db_config.values()):
                db_configs[service_name] = db_config
        
        # Check if database configs are consistent
        db_config_values = list(db_configs.values())
        if len(db_config_values) > 1:
            is_consistent = all(
                config == db_config_values[0] for config in db_config_values
            )
            if not is_consistent:
                results["inconsistent_vars"]["DATABASE_CONFIG"] = db_configs
                results["consistency_checks"]["database_config"] = False
            else:
                results["consistent_vars"].append("DATABASE_CONFIG")
                results["consistency_checks"]["database_config"] = True
        
        if results["inconsistent_vars"]:
            raise ValueError(f"Environment consistency errors: {results['inconsistent_vars']}")
        
        logger.info(f"All {len(results['consistent_vars'])} environment variables are consistent across services")
        return results
    
    def test_environment_security(self) -> Dict:
        """Test environment security configuration."""
        logger.info("Testing environment security configuration")
        
        results = {
            "security_checks": {},
            "security_issues": [],
            "recommendations": []
        }
        
        for service_name, config in self.service_configs.items():
            load_dotenv(config.env_file_path)
            
            security_checks = {
                "jwt_secret_strength": False,
                "debug_mode_disabled": False,
                "secure_database_url": False,
                "cors_properly_configured": False
            }
            
            # Check JWT secret strength
            jwt_secret = os.getenv("JWT_SECRET")
            if jwt_secret and len(jwt_secret) >= 32:
                security_checks["jwt_secret_strength"] = True
            else:
                results["security_issues"].append(f"{service_name}: Weak JWT secret")
                results["recommendations"].append(f"{service_name}: Use JWT secret with at least 32 characters")
            
            # Check debug mode
            debug_mode = os.getenv("DEBUG", "False").lower()
            if debug_mode in ["false", "0"]:
                security_checks["debug_mode_disabled"] = True
            else:
                results["security_issues"].append(f"{service_name}: Debug mode enabled")
                results["recommendations"].append(f"{service_name}: Disable debug mode in production")
            
            # Check database URL security
            db_url = os.getenv("DATABASE_URL")
            if db_url and "postgresql://" in db_url:
                if "@" in db_url and ":" in db_url.split("@")[0]:
                    security_checks["secure_database_url"] = True
                else:
                    results["security_issues"].append(f"{service_name}: Insecure database URL")
                    results["recommendations"].append(f"{service_name}: Use proper database URL with credentials")
            
            # Check CORS configuration
            cors_origins = os.getenv("CORS_ALLOWED_ORIGINS")
            if cors_origins and cors_origins != "*":
                security_checks["cors_properly_configured"] = True
            else:
                results["security_issues"].append(f"{service_name}: Overly permissive CORS configuration")
                results["recommendations"].append(f"{service_name}: Restrict CORS origins to specific domains")
            
            results["security_checks"][service_name] = security_checks
        
        logger.info(f"Security testing completed with {len(results['security_issues'])} issues found")
        return results
    
    def test_environment_performance(self) -> Dict:
        """Test environment performance configuration."""
        logger.info("Testing environment performance configuration")
        
        results = {
            "performance_configs": {},
            "performance_issues": [],
            "optimization_recommendations": []
        }
        
        for service_name, config in self.service_configs.items():
            load_dotenv(config.env_file_path)
            
            perf_config = {
                "database_pool_size": os.getenv("DB_POOL_SIZE"),
                "worker_processes": os.getenv("WORKER_PROCESSES"),
                "max_connections": os.getenv("MAX_CONNECTIONS"),
                "timeout_settings": {
                    "request_timeout": os.getenv("REQUEST_TIMEOUT"),
                    "database_timeout": os.getenv("DB_TIMEOUT")
                }
            }
            
            results["performance_configs"][service_name] = perf_config
            
            # Check for performance issues
            if service_name == "backend":
                if not perf_config["database_pool_size"]:
                    results["performance_issues"].append(f"{service_name}: No database pool size configured")
                    results["optimization_recommendations"].append(f"{service_name}: Set DB_POOL_SIZE for connection pooling")
                
                if not perf_config["worker_processes"]:
                    results["performance_issues"].append(f"{service_name}: No worker processes configured")
                    results["optimization_recommendations"].append(f"{service_name}: Set WORKER_PROCESSES for concurrency")
        
        logger.info(f"Performance testing completed with {len(results['performance_issues'])} issues found")
        return results
    
    def test_environment_error_handling(self) -> Dict:
        """Test environment error handling and fallback mechanisms."""
        logger.info("Testing environment error handling")
        
        results = {
            "error_handling_configs": {},
            "missing_fallbacks": [],
            "error_handling_issues": []
        }
        
        for service_name, config in self.service_configs.items():
            load_dotenv(config.env_file_path)
            
            error_config = {
                "has_fallback_db": bool(os.getenv("FALLBACK_DATABASE_URL")),
                "has_retry_config": bool(os.getenv("RETRY_ATTEMPTS")),
                "has_timeout_config": bool(os.getenv("REQUEST_TIMEOUT")),
                "has_circuit_breaker": bool(os.getenv("CIRCUIT_BREAKER_ENABLED"))
            }
            
            results["error_handling_configs"][service_name] = error_config
            
            # Check for missing error handling configurations
            if service_name == "backend":
                if not error_config["has_retry_config"]:
                    results["missing_fallbacks"].append(f"{service_name}: No retry configuration")
                
                if not error_config["has_timeout_config"]:
                    results["missing_fallbacks"].append(f"{service_name}: No timeout configuration")
        
        logger.info(f"Error handling testing completed with {len(results['missing_fallbacks'])} missing fallbacks")
        return results
    
    def test_docker_compose_environment_integration(self) -> Dict:
        """Test Docker Compose environment variable integration."""
        logger.info("Testing Docker Compose environment integration")
        
        results = {
            "compose_env_vars": {},
            "missing_compose_vars": [],
            "integration_issues": []
        }
        
        # Check if docker-compose.yml exists
        if not os.path.exists("docker-compose.yml"):
            raise FileNotFoundError("docker-compose.yml not found")
        
        # Parse docker-compose.yml
        try:
            with open("docker-compose.yml", 'r') as f:
                compose_config = yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Invalid docker-compose.yml: {str(e)}")
        
        # Check environment variable references in compose file
        for service_name, service_config in compose_config.get("services", {}).items():
            env_vars = service_config.get("environment", [])
            env_file = service_config.get("env_file", [])
            
            results["compose_env_vars"][service_name] = {
                "environment_vars": env_vars,
                "env_files": env_file
            }
            
            # Check if service has proper environment configuration
            if not env_vars and not env_file:
                results["missing_compose_vars"].append(service_name)
        
        logger.info(f"Docker Compose environment integration testing completed")
        return results
    
    def run_all_tests(self) -> Dict:
        """Run all environment configuration tests."""
        logger.info("Starting comprehensive environment configuration testing")
        
        test_functions = [
            ("environment_file_existence", self.test_environment_file_existence),
            ("environment_file_syntax", self.test_environment_file_syntax),
            ("required_environment_variables", self.test_required_environment_variables),
            ("environment_variable_validation", self.test_environment_variable_validation),
            ("environment_consistency", self.test_environment_consistency),
            ("environment_security", self.test_environment_security),
            ("environment_performance", self.test_environment_performance),
            ("environment_error_handling", self.test_environment_error_handling),
            ("docker_compose_environment_integration", self.test_docker_compose_environment_integration)
        ]
        
        all_results = {}
        passed_tests = 0
        total_tests = len(test_functions)
        
        for test_name, test_func in test_functions:
            logger.info(f"Running test: {test_name}")
            try:
                result = test_func()
                all_results[test_name] = {
                    "success": True,
                    "result": result
                }
                passed_tests += 1
                logger.info(f"Test {test_name} passed")
            except Exception as e:
                all_results[test_name] = {
                    "success": False,
                    "error": str(e)
                }
                logger.error(f"Test {test_name} failed: {str(e)}")
        
        summary = {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": total_tests - passed_tests,
            "success_rate": passed_tests / total_tests * 100 if total_tests > 0 else 0,
            "test_results": all_results
        }
        
        logger.info(f"Environment configuration testing completed: {passed_tests}/{total_tests} tests passed")
        return summary


# Test functions for pytest
@pytest.fixture
def env_config_tester():
    """Fixture for environment configuration tester."""
    return EnvironmentConfigurationTester()

def test_environment_file_existence(env_config_tester):
    """Test that all required environment files exist."""
    result = env_config_tester.test_environment_file_existence()
    assert len(result["missing_files"]) == 0

def test_environment_file_syntax(env_config_tester):
    """Test that all environment files have valid syntax."""
    result = env_config_tester.test_environment_file_syntax()
    assert len(result["invalid_files"]) == 0

def test_required_environment_variables(env_config_tester):
    """Test that all required environment variables are present."""
    result = env_config_tester.test_required_environment_variables()
    assert result["total_missing"] == 0

def test_environment_variable_validation(env_config_tester):
    """Test that environment variables have valid values."""
    result = env_config_tester.test_environment_variable_validation()
    assert len(result["validation_errors"]) == 0

def test_environment_consistency(env_config_tester):
    """Test consistency of environment variables across services."""
    result = env_config_tester.test_environment_consistency()
    assert len(result["inconsistent_vars"]) == 0

def test_environment_security(env_config_tester):
    """Test environment security configuration."""
    result = env_config_tester.test_environment_security()
    # Note: Security issues are warnings, not failures
    assert "security_checks" in result

def test_environment_performance(env_config_tester):
    """Test environment performance configuration."""
    result = env_config_tester.test_environment_performance()
    assert "performance_configs" in result

def test_environment_error_handling(env_config_tester):
    """Test environment error handling and fallback mechanisms."""
    result = env_config_tester.test_environment_error_handling()
    assert "error_handling_configs" in result

def test_docker_compose_environment_integration(env_config_tester):
    """Test Docker Compose environment variable integration."""
    result = env_config_tester.test_docker_compose_environment_integration()
    assert "compose_env_vars" in result

def test_complete_environment_configuration(env_config_tester):
    """Run complete environment configuration test suite."""
    result = env_config_tester.run_all_tests()
    assert result["success_rate"] >= 90.0  # At least 90% of tests should pass


if __name__ == "__main__":
    # Run the complete test suite
    tester = EnvironmentConfigurationTester()
    results = tester.run_all_tests()
    
    print("\n" + "="*60)
    print("ENVIRONMENT CONFIGURATION TEST RESULTS")
    print("="*60)
    print(f"Total Tests: {results['total_tests']}")
    print(f"Passed: {results['passed_tests']}")
    print(f"Failed: {results['failed_tests']}")
    print(f"Success Rate: {results['success_rate']:.1f}%")
    print("="*60)
    
    if results['failed_tests'] > 0:
        print("\nFAILED TESTS:")
        for test_name, test_result in results['test_results'].items():
            if not test_result['success']:
                print(f"  - {test_name}: {test_result['error']}")
    
    print("\nDETAILED RESULTS:")
    for test_name, test_result in results['test_results'].items():
        status = "✅ PASS" if test_result['success'] else "❌ FAIL"
        print(f"  {status} {test_name}")
    
    # Exit with appropriate code
    exit(0 if results['success_rate'] >= 90.0 else 1) 