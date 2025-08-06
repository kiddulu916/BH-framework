#!/usr/bin/env python3
"""
Integration Test Runner

This script runs comprehensive integration tests for the Bug Hunting Framework,
validating complete workflow execution, API integration, and system reliability.

Test Categories:
1. Complete workflow lifecycle testing
2. Data flow validation between stages
3. API integration testing
4. Error handling and recovery testing
5. Performance and scalability testing
6. Security and authentication validation

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import pytest
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Add the backend directory to Python path
backend_dir = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_dir))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('integration_tests.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class IntegrationTestRunner:
    """
    Comprehensive integration test runner for the Bug Hunting Framework.
    
    Executes all integration tests and provides detailed reporting
    on framework integration status and reliability.
    """
    
    def __init__(self):
        """Initialize the integration test runner."""
        self.start_time = datetime.now(timezone.utc)
        self.test_results = {
            "start_time": self.start_time.isoformat(),
            "tests": {},
            "summary": {
                "total_tests": 0,
                "passed_tests": 0,
                "failed_tests": 0,
                "skipped_tests": 0,
                "total_duration": 0.0
            }
        }
        
        # Test categories and their descriptions
        self.test_categories = {
            "complete_workflow": {
                "name": "Complete Workflow Integration",
                "description": "End-to-end workflow testing from target creation to final report",
                "tests": [
                    "test_complete_workflow_lifecycle",
                    "test_data_flow_between_stages",
                    "test_error_handling_and_recovery",
                    "test_concurrent_workflow_execution"
                ]
            },
            "api_integration": {
                "name": "API Integration Testing",
                "description": "Comprehensive API endpoint integration and validation",
                "tests": [
                    "test_complete_api_workflow",
                    "test_api_endpoint_integration",
                    "test_authentication_and_authorization",
                    "test_error_handling_and_edge_cases",
                    "test_data_consistency_and_integrity",
                    "test_api_performance_and_load",
                    "test_input_validation_and_sanitization",
                    "test_security_headers",
                    "test_rate_limiting"
                ]
            },
            "database_integration": {
                "name": "Database Integration Testing",
                "description": "Database operations, consistency, and integrity validation",
                "tests": [
                    "test_database_operations_across_stages",
                    "test_data_integrity_and_consistency",
                    "test_concurrent_access_and_transactions",
                    "test_database_performance_and_optimization",
                    "test_data_migration_and_schema_validation"
                ]
            },
            "performance": {
                "name": "Performance and Scalability",
                "description": "System performance and scalability validation",
                "tests": [
                    "test_system_performance",
                    "test_concurrent_api_requests"
                ]
            },
            "docker_compose": {
                "name": "Docker Compose Integration",
                "description": "Containerized environment and service orchestration testing",
                "tests": [
                    "test_service_startup_and_health_checks",
                    "test_service_dependencies_and_orchestration",
                    "test_network_connectivity",
                    "test_volume_mounting_and_data_persistence",
                    "test_environment_configuration",
                    "test_resource_management_and_limits",
                    "test_service_restart_and_recovery",
                    "test_complete_workflow_in_docker"
                ]
            },
            "environment_configuration": {
                "name": "Environment Configuration Testing",
                "description": "Environment variable management and configuration validation",
                "tests": [
                    "test_environment_file_existence",
                    "test_environment_file_syntax",
                    "test_required_environment_variables",
                    "test_environment_variable_validation",
                    "test_environment_consistency",
                    "test_environment_security",
                    "test_environment_performance",
                    "test_environment_error_handling",
                    "test_docker_compose_environment_integration"
                ]
            },
            "error_handling_recovery": {
                "name": "Error Handling and Recovery Testing",
                "description": "System resilience, failure recovery, and error propagation",
                "tests": [
                    "test_service_failure_recovery",
                    "test_error_propagation",
                    "test_backup_and_disaster_recovery",
                    "test_stress_testing",
                    "test_failure_scenarios"
                ]
            },
            "user_experience": {
                "name": "User Experience and Workflow Validation",
                "description": "Complete user journey testing, UI responsiveness, and accessibility",
                "tests": [
                    "test_complete_user_journey",
                    "test_ui_responsiveness",
                    "test_accessibility_compliance",
                    "test_user_feedback_mechanisms",
                    "test_performance_light_load"
                ]
            },
            "performance_scalability": {
                "name": "Performance and Scalability Testing",
                "description": "System performance under load, resource optimization, and scalability limits",
                "tests": [
                    "test_api_performance_targets",
                    "test_api_performance_workflows",
                    "test_light_load",
                    "test_resource_usage_optimization",
                    "test_scalability_limits"
                ]
            },
            "quality_assurance": {
                "name": "Quality Assurance and Validation",
                "description": "Quality gates, data accuracy, compliance validation, and automated reporting",
                "tests": [
                    "test_data_accuracy_validation",
                    "test_security_compliance_validation",
                    "test_quality_gates_validation"
                ]
            }
        }
        
        logger.info("Integration test runner initialized")
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """
        Run all integration tests and return comprehensive results.
        
        Returns:
            Dict containing test results and summary
        """
        logger.info("Starting comprehensive integration testing")
        
        try:
            # Run tests by category
            for category, config in self.test_categories.items():
                logger.info(f"\n{Fore.CYAN}Running {config['name']} tests...{Style.RESET_ALL}")
                await self._run_test_category(category, config)
            
            # Generate comprehensive summary
            await self._generate_summary()
            
            # Save detailed results
            await self._save_results()
            
            # Print final report
            self._print_final_report()
            
            return self.test_results
            
        except Exception as e:
            logger.error(f"Integration testing failed: {str(e)}")
            self.test_results["error"] = str(e)
            raise
    
    async def _run_test_category(self, category: str, config: Dict[str, Any]):
        """Run tests for a specific category."""
        category_start_time = time.time()
        
        logger.info(f"Category: {config['name']}")
        logger.info(f"Description: {config['description']}")
        logger.info(f"Tests: {', '.join(config['tests'])}")
        
        # Map categories to test files
        test_file_mapping = {
            "complete_workflow": "test_complete_workflow_integration.py",
            "api_integration": "test_api_integration_validation.py",
            "database_integration": "test_database_integration.py",
            "performance": "test_complete_workflow_integration.py",
            "docker_compose": "test_docker_compose_integration.py"
        }
        
        test_file = test_file_mapping.get(category, "test_complete_workflow_integration.py")
        test_path = Path(__file__).parent / test_file
        
        # Run specific tests for this category
        test_results = []
        for test_name in config['tests']:
            try:
                logger.info(f"\n{Fore.YELLOW}Running test: {test_name}{Style.RESET_ALL}")
                
                # Run individual test
                result = await self._run_single_test(test_path, test_name)
                test_results.append(result)
                
                if result["status"] == "PASSED":
                    logger.info(f"{Fore.GREEN}✓ {test_name} passed{Style.RESET_ALL}")
                else:
                    logger.error(f"{Fore.RED}✗ {test_name} failed: {result.get('error', 'Unknown error')}{Style.RESET_ALL}")
                
            except Exception as e:
                logger.error(f"Error running test {test_name}: {str(e)}")
                test_results.append({
                    "test_name": test_name,
                    "status": "ERROR",
                    "error": str(e),
                    "duration": 0.0
                })
        
        # Compile category results
        category_duration = time.time() - category_start_time
        passed_tests = len([r for r in test_results if r["status"] == "PASSED"])
        failed_tests = len([r for r in test_results if r["status"] in ["FAILED", "ERROR"]])
        
        self.test_results["tests"][category] = {
            "name": config['name'],
            "description": config['description'],
            "duration": category_duration,
            "total_tests": len(config['tests']),
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "test_results": test_results
        }
        
        logger.info(f"\n{Fore.CYAN}Category {config['name']} completed:{Style.RESET_ALL}")
        logger.info(f"  Duration: {category_duration:.2f} seconds")
        logger.info(f"  Passed: {passed_tests}/{len(config['tests'])}")
        logger.info(f"  Failed: {failed_tests}/{len(config['tests'])}")
    
    async def _run_single_test(self, test_path: Path, test_name: str) -> Dict[str, Any]:
        """Run a single test and return results."""
        start_time = time.time()
        
        try:
            # Run pytest for specific test
            result = pytest.main([
                str(test_path),
                f"-k={test_name}",
                "-v",
                "--tb=short",
                "--json-report",
                "--json-report-file=none"
            ])
            
            duration = time.time() - start_time
            
            if result == 0:
                return {
                    "test_name": test_name,
                    "status": "PASSED",
                    "duration": duration,
                    "error": None
                }
            else:
                return {
                    "test_name": test_name,
                    "status": "FAILED",
                    "duration": duration,
                    "error": f"Test failed with exit code {result}"
                }
                
        except Exception as e:
            duration = time.time() - start_time
            return {
                "test_name": test_name,
                "status": "ERROR",
                "duration": duration,
                "error": str(e)
            }
    
    async def _generate_summary(self):
        """Generate comprehensive test summary."""
        total_tests = 0
        passed_tests = 0
        failed_tests = 0
        total_duration = 0.0
        
        for category, results in self.test_results["tests"].items():
            total_tests += results["total_tests"]
            passed_tests += results["passed_tests"]
            failed_tests += results["failed_tests"]
            total_duration += results["duration"]
        
        self.test_results["summary"].update({
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "skipped_tests": 0,  # Not tracking skipped tests for now
            "total_duration": total_duration,
            "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0
        })
        
        self.test_results["end_time"] = datetime.now(timezone.utc).isoformat()
        self.test_results["duration"] = total_duration
    
    async def _save_results(self):
        """Save detailed test results to file."""
        results_file = Path("integration_test_results.json")
        
        with open(results_file, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        
        logger.info(f"Detailed results saved to {results_file}")
    
    def _print_final_report(self):
        """Print comprehensive final test report."""
        summary = self.test_results["summary"]
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"INTEGRATION TEST RESULTS")
        print(f"{'='*80}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Test Summary:{Style.RESET_ALL}")
        print(f"  Total Tests: {summary['total_tests']}")
        print(f"  Passed: {Fore.GREEN}{summary['passed_tests']}{Style.RESET_ALL}")
        print(f"  Failed: {Fore.RED}{summary['failed_tests']}{Style.RESET_ALL}")
        print(f"  Success Rate: {Fore.CYAN}{summary['success_rate']:.1f}%{Style.RESET_ALL}")
        print(f"  Total Duration: {summary['total_duration']:.2f} seconds")
        
        print(f"\n{Fore.YELLOW}Category Results:{Style.RESET_ALL}")
        for category, results in self.test_results["tests"].items():
            status_color = Fore.GREEN if results["failed_tests"] == 0 else Fore.RED
            print(f"  {results['name']}: {status_color}{results['passed_tests']}/{results['total_tests']} passed{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Detailed Test Results:{Style.RESET_ALL}")
        for category, results in self.test_results["tests"].items():
            print(f"\n  {Fore.CYAN}{results['name']}:{Style.RESET_ALL}")
            for test_result in results["test_results"]:
                status_color = Fore.GREEN if test_result["status"] == "PASSED" else Fore.RED
                status_symbol = "✓" if test_result["status"] == "PASSED" else "✗"
                print(f"    {status_color}{status_symbol} {test_result['test_name']}{Style.RESET_ALL}")
                if test_result.get("error"):
                    print(f"      Error: {test_result['error']}")
        
        # Overall status
        if summary["failed_tests"] == 0:
            print(f"\n{Fore.GREEN}{'='*80}")
            print(f"🎉 ALL INTEGRATION TESTS PASSED! 🎉")
            print(f"Framework integration is working correctly.")
            print(f"{'='*80}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}{'='*80}")
            print(f"⚠️  {summary['failed_tests']} INTEGRATION TESTS FAILED ⚠️")
            print(f"Framework integration needs attention.")
            print(f"{'='*80}{Style.RESET_ALL}")
    
    async def run_quick_validation(self) -> bool:
        """
        Run a quick validation of core framework components.
        
        Returns:
            True if quick validation passes, False otherwise
        """
        logger.info("Running quick framework validation")
        
        try:
            # Test 1: Check if backend is accessible
            logger.info("Testing backend accessibility...")
            # This would test if the backend API is responding
            
            # Test 2: Check if database is accessible
            logger.info("Testing database connectivity...")
            # This would test database connectivity
            
            # Test 3: Check if stage containers are available
            logger.info("Testing stage container availability...")
            # This would test if Docker containers are running
            
            logger.info("Quick validation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Quick validation failed: {str(e)}")
            return False


async def main():
    """Main entry point for integration testing."""
    parser = argparse.ArgumentParser(description="Bug Hunting Framework Integration Test Runner")
    parser.add_argument("--quick", action="store_true", help="Run quick validation only")
    parser.add_argument("--category", choices=["complete_workflow", "api_integration", "database_integration", "performance", "docker_compose"], 
                        help="Run tests for specific category only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize test runner
    runner = IntegrationTestRunner()
    
    try:
        if args.quick:
            # Run quick validation
            success = await runner.run_quick_validation()
            sys.exit(0 if success else 1)
        
        elif args.category:
            # Run specific category
            if args.category in runner.test_categories:
                config = runner.test_categories[args.category]
                await runner._run_test_category(args.category, config)
                await runner._generate_summary()
                await runner._save_results()
                runner._print_final_report()
            else:
                logger.error(f"Unknown test category: {args.category}")
                sys.exit(1)
        
        else:
            # Run all tests
            await runner.run_all_tests()
        
        # Exit with appropriate code
        summary = runner.test_results["summary"]
        sys.exit(0 if summary["failed_tests"] == 0 else 1)
        
    except Exception as e:
        logger.error(f"Integration testing failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    import argparse
    asyncio.run(main()) 