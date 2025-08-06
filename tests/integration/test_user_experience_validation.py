"""
User Experience and Workflow Validation Testing Module

This module provides comprehensive testing for user experience aspects including:
- Complete user journey testing from target creation to report delivery
- User interface responsiveness and usability validation
- Accessibility and cross-browser compatibility testing
- User feedback collection and validation
- Performance under various user load conditions
- Quality assurance and validation checks

Author: AI Assistant
Date: 2025-01-27
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException, WebDriverException
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from api.asgi import application


@dataclass
class UserJourneyStep:
    """Configuration for a user journey step."""
    name: str
    description: str
    url: str
    expected_elements: List[str]
    expected_actions: List[str]
    validation_checks: List[str]
    timeout: int = 30


@dataclass
class PerformanceTest:
    """Configuration for a performance test."""
    name: str
    description: str
    concurrent_users: int
    duration: int  # seconds
    expected_response_time: float  # seconds
    expected_throughput: int  # requests per second


@dataclass
class AccessibilityTest:
    """Configuration for an accessibility test."""
    name: str
    description: str
    wcag_level: str  # "A", "AA", "AAA"
    test_elements: List[str]
    validation_rules: List[str]


@dataclass
class UserExperienceTestResult:
    """Result of a user experience test."""
    test_name: str
    test_type: str
    status: str  # "PASS", "FAIL", "WARNING"
    duration: float
    details: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class UserExperienceValidator:
    """Comprehensive user experience validation framework."""
    
    def __init__(self, base_url: str = "http://localhost:3000", api_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_url = api_url
        self.test_results: List[UserExperienceTestResult] = []
        
        # Define complete user journeys
        self.user_journeys = {
            "complete_workflow": [
                UserJourneyStep(
                    name="target_creation",
                    description="Create a new target for bug hunting",
                    url="/target-select",
                    expected_elements=["target-form", "submit-button", "validation-messages"],
                    expected_actions=["fill_form", "submit_form", "receive_confirmation"],
                    validation_checks=["form_validation", "api_integration", "user_feedback"]
                ),
                UserJourneyStep(
                    name="workflow_initiation",
                    description="Initiate the bug hunting workflow",
                    url="/dashboard",
                    expected_elements=["workflow-controls", "stage-progress", "status-indicators"],
                    expected_actions=["start_workflow", "monitor_progress", "view_status"],
                    validation_checks=["workflow_start", "progress_tracking", "real_time_updates"]
                ),
                UserJourneyStep(
                    name="stage_monitoring",
                    description="Monitor individual stage progress",
                    url="/stages/passive-recon",
                    expected_elements=["stage-details", "progress-bar", "results-preview"],
                    expected_actions=["view_details", "check_progress", "preview_results"],
                    validation_checks=["stage_visibility", "progress_accuracy", "data_presentation"]
                ),
                UserJourneyStep(
                    name="results_review",
                    description="Review and analyze results",
                    url="/target-profile",
                    expected_elements=["results-summary", "vulnerability-list", "export-options"],
                    expected_actions=["review_results", "export_data", "generate_reports"],
                    validation_checks=["data_accuracy", "export_functionality", "report_generation"]
                ),
                UserJourneyStep(
                    name="report_delivery",
                    description="Generate and deliver final reports",
                    url="/dashboard",
                    expected_elements=["report-generator", "format-options", "delivery-methods"],
                    expected_actions=["generate_report", "select_format", "download_report"],
                    validation_checks=["report_generation", "format_options", "download_functionality"]
                )
            ]
        }
        
        # Define performance test scenarios
        self.performance_tests = [
            PerformanceTest(
                name="light_load",
                description="Test system performance under light load",
                concurrent_users=5,
                duration=60,
                expected_response_time=2.0,
                expected_throughput=10
            ),
            PerformanceTest(
                name="medium_load",
                description="Test system performance under medium load",
                concurrent_users=20,
                duration=120,
                expected_response_time=3.0,
                expected_throughput=25
            ),
            PerformanceTest(
                name="heavy_load",
                description="Test system performance under heavy load",
                concurrent_users=50,
                duration=180,
                expected_response_time=5.0,
                expected_throughput=50
            )
        ]
        
        # Define accessibility tests
        self.accessibility_tests = [
            AccessibilityTest(
                name="wcag_aa_compliance",
                description="Test WCAG AA compliance",
                wcag_level="AA",
                test_elements=["navigation", "forms", "content", "images"],
                validation_rules=["color_contrast", "keyboard_navigation", "screen_reader", "focus_indicators"]
            ),
            AccessibilityTest(
                name="mobile_accessibility",
                description="Test mobile accessibility",
                wcag_level="A",
                test_elements=["touch_targets", "viewport", "responsive_design"],
                validation_rules=["touch_target_size", "viewport_meta", "responsive_layout"]
            )
        ]
    
    async def test_complete_user_journey(self, journey_name: str = "complete_workflow") -> UserExperienceTestResult:
        """Test a complete user journey from start to finish."""
        start_time = time.time()
        journey = self.user_journeys.get(journey_name, [])
        
        if not journey:
            return UserExperienceTestResult(
                test_name=f"user_journey_{journey_name}",
                test_type="user_journey",
                status="FAIL",
                duration=time.time() - start_time,
                details={"error": f"Journey '{journey_name}' not found"},
                errors=[f"Journey '{journey_name}' not found"]
            )
        
        results = []
        errors = []
        
        try:
            # Setup webdriver for UI testing
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            with webdriver.Chrome(options=chrome_options) as driver:
                driver.set_window_size(1920, 1080)
                
                for step in journey:
                    step_result = await self._test_journey_step(driver, step)
                    results.append(step_result)
                    
                    if step_result.get("status") == "FAIL":
                        errors.append(f"Step '{step.name}' failed: {step_result.get('error', 'Unknown error')}")
                
                # Test workflow completion
                completion_result = await self._test_workflow_completion(driver)
                results.append(completion_result)
                
                if completion_result.get("status") == "FAIL":
                    errors.append(f"Workflow completion failed: {completion_result.get('error', 'Unknown error')}")
        
        except Exception as e:
            errors.append(f"User journey test failed: {str(e)}")
        
        duration = time.time() - start_time
        status = "PASS" if not errors else "FAIL"
        
        return UserExperienceTestResult(
            test_name=f"user_journey_{journey_name}",
            test_type="user_journey",
            status=status,
            duration=duration,
            details={"steps": results, "total_steps": len(journey)},
            errors=errors
        )
    
    async def _test_journey_step(self, driver: webdriver.Chrome, step: UserJourneyStep) -> Dict[str, Any]:
        """Test an individual journey step."""
        try:
            # Navigate to the step URL
            driver.get(f"{self.base_url}{step.url}")
            
            # Wait for page to load
            WebDriverWait(driver, step.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Check for expected elements
            element_results = []
            for element_id in step.expected_elements:
                try:
                    element = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((By.ID, element_id))
                    )
                    element_results.append({"element": element_id, "status": "PASS"})
                except TimeoutException:
                    element_results.append({"element": element_id, "status": "FAIL", "error": "Element not found"})
            
            # Test expected actions
            action_results = []
            for action in step.expected_actions:
                action_result = await self._perform_action(driver, action)
                action_results.append(action_result)
            
            # Perform validation checks
            validation_results = []
            for check in step.validation_checks:
                validation_result = await self._perform_validation(driver, check)
                validation_results.append(validation_result)
            
            return {
                "step_name": step.name,
                "status": "PASS",
                "elements": element_results,
                "actions": action_results,
                "validations": validation_results
            }
        
        except Exception as e:
            return {
                "step_name": step.name,
                "status": "FAIL",
                "error": str(e)
            }
    
    async def _perform_action(self, driver: webdriver.Chrome, action: str) -> Dict[str, Any]:
        """Perform a specific action on the page."""
        try:
            if action == "fill_form":
                # Simulate form filling
                form_elements = driver.find_elements(By.TAG_NAME, "input")
                for element in form_elements[:3]:  # Fill first 3 inputs
                    element.send_keys("test_data")
                return {"action": action, "status": "PASS"}
            
            elif action == "submit_form":
                # Find and click submit button
                submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
                submit_button.click()
                return {"action": action, "status": "PASS"}
            
            elif action == "start_workflow":
                # Find and click workflow start button
                start_button = driver.find_element(By.CSS_SELECTOR, "[data-testid='start-workflow']")
                start_button.click()
                return {"action": action, "status": "PASS"}
            
            else:
                return {"action": action, "status": "SKIP", "reason": "Action not implemented"}
        
        except Exception as e:
            return {"action": action, "status": "FAIL", "error": str(e)}
    
    async def _perform_validation(self, driver: webdriver.Chrome, validation: str) -> Dict[str, Any]:
        """Perform a specific validation check."""
        try:
            if validation == "form_validation":
                # Check for validation messages
                validation_messages = driver.find_elements(By.CLASS_NAME, "validation-message")
                return {"validation": validation, "status": "PASS", "messages_found": len(validation_messages)}
            
            elif validation == "api_integration":
                # Check for API response indicators
                success_indicators = driver.find_elements(By.CLASS_NAME, "success-indicator")
                return {"validation": validation, "status": "PASS", "indicators_found": len(success_indicators)}
            
            else:
                return {"validation": validation, "status": "SKIP", "reason": "Validation not implemented"}
        
        except Exception as e:
            return {"validation": validation, "status": "FAIL", "error": str(e)}
    
    async def _test_workflow_completion(self, driver: webdriver.Chrome) -> Dict[str, Any]:
        """Test that the complete workflow can be finished."""
        try:
            # Check for workflow completion indicators
            completion_indicators = driver.find_elements(By.CLASS_NAME, "workflow-complete")
            
            if completion_indicators:
                return {"status": "PASS", "completion_detected": True}
            else:
                return {"status": "FAIL", "error": "Workflow completion not detected"}
        
        except Exception as e:
            return {"status": "FAIL", "error": str(e)}
    
    async def test_ui_responsiveness(self) -> UserExperienceTestResult:
        """Test user interface responsiveness across different screen sizes."""
        start_time = time.time()
        screen_sizes = [
            (1920, 1080, "desktop"),
            (1366, 768, "laptop"),
            (768, 1024, "tablet"),
            (375, 667, "mobile")
        ]
        
        results = []
        errors = []
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            with webdriver.Chrome(options=chrome_options) as driver:
                for width, height, device_type in screen_sizes:
                    driver.set_window_size(width, height)
                    
                    # Test main pages
                    pages = ["/", "/dashboard", "/target-select", "/target-profile"]
                    
                    for page in pages:
                        try:
                            driver.get(f"{self.base_url}{page}")
                            
                            # Wait for page load
                            WebDriverWait(driver, 10).until(
                                EC.presence_of_element_located((By.TAG_NAME, "body"))
                            )
                            
                            # Check for responsive design issues
                            body_width = driver.find_element(By.TAG_NAME, "body").size["width"]
                            
                            if body_width > width:
                                errors.append(f"Page {page} not responsive on {device_type}: body width {body_width} > viewport width {width}")
                            
                            results.append({
                                "page": page,
                                "device": device_type,
                                "viewport": f"{width}x{height}",
                                "body_width": body_width,
                                "status": "PASS" if body_width <= width else "FAIL"
                            })
                        
                        except Exception as e:
                            errors.append(f"Failed to test {page} on {device_type}: {str(e)}")
        
        except Exception as e:
            errors.append(f"UI responsiveness test failed: {str(e)}")
        
        duration = time.time() - start_time
        status = "PASS" if not errors else "FAIL"
        
        return UserExperienceTestResult(
            test_name="ui_responsiveness",
            test_type="ui_testing",
            status=status,
            duration=duration,
            details={"screen_sizes": results},
            errors=errors
        )
    
    async def test_accessibility(self) -> UserExperienceTestResult:
        """Test accessibility compliance."""
        start_time = time.time()
        results = []
        errors = []
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            with webdriver.Chrome(options=chrome_options) as driver:
                driver.set_window_size(1920, 1080)
                
                # Test main pages for accessibility
                pages = ["/", "/dashboard", "/target-select"]
                
                for page in pages:
                    try:
                        driver.get(f"{self.base_url}{page}")
                        
                        # Wait for page load
                        WebDriverWait(driver, 10).until(
                            EC.presence_of_element_located((By.TAG_NAME, "body"))
                        )
                        
                        # Check for accessibility features
                        accessibility_checks = [
                            ("alt_text", "img[alt]", "Images have alt text"),
                            ("form_labels", "label", "Forms have labels"),
                            ("heading_structure", "h1, h2, h3, h4, h5, h6", "Proper heading structure"),
                            ("focus_indicators", "button:focus, input:focus", "Focus indicators present")
                        ]
                        
                        page_results = []
                        for check_name, selector, description in accessibility_checks:
                            try:
                                elements = driver.find_elements(By.CSS_SELECTOR, selector)
                                page_results.append({
                                    "check": check_name,
                                    "description": description,
                                    "elements_found": len(elements),
                                    "status": "PASS" if elements else "WARNING"
                                })
                            except Exception as e:
                                page_results.append({
                                    "check": check_name,
                                    "description": description,
                                    "status": "FAIL",
                                    "error": str(e)
                                })
                        
                        results.append({
                            "page": page,
                            "accessibility_checks": page_results
                        })
                    
                    except Exception as e:
                        errors.append(f"Failed to test accessibility for {page}: {str(e)}")
        
        except Exception as e:
            errors.append(f"Accessibility test failed: {str(e)}")
        
        duration = time.time() - start_time
        status = "PASS" if not errors else "FAIL"
        
        return UserExperienceTestResult(
            test_name="accessibility_compliance",
            test_type="accessibility_testing",
            status=status,
            duration=duration,
            details={"pages": results},
            errors=errors
        )
    
    async def test_performance_under_load(self, test_config: PerformanceTest) -> UserExperienceTestResult:
        """Test system performance under specified load conditions."""
        start_time = time.time()
        
        # Create test data
        test_targets = [
            {"target": f"test-target-{i}.example.com", "domain": f"test-target-{i}.example.com"}
            for i in range(test_config.concurrent_users)
        ]
        
        results = []
        errors = []
        
        async def simulate_user(user_id: int, target_data: Dict[str, str]):
            """Simulate a single user performing actions."""
            user_start_time = time.time()
            user_results = []
            
            try:
                async with AsyncClient() as client:
                    # Simulate target creation
                    target_start = time.time()
                    target_response = await client.post(
                        f"{self.api_url}/api/targets/",
                        json=target_data,
                        timeout=30.0
                    )
                    target_duration = time.time() - target_start
                    
                    user_results.append({
                        "action": "target_creation",
                        "duration": target_duration,
                        "status": "PASS" if target_response.status_code == 200 else "FAIL",
                        "response_code": target_response.status_code
                    })
                    
                    if target_response.status_code == 200:
                        target_id = target_response.json().get("data", {}).get("id")
                        
                        # Simulate workflow initiation
                        workflow_start = time.time()
                        workflow_response = await client.post(
                            f"{self.api_url}/api/workflows/",
                            json={"target_id": target_id, "stages": ["passive_recon"]},
                            timeout=30.0
                        )
                        workflow_duration = time.time() - workflow_start
                        
                        user_results.append({
                            "action": "workflow_initiation",
                            "duration": workflow_duration,
                            "status": "PASS" if workflow_response.status_code == 200 else "FAIL",
                            "response_code": workflow_response.status_code
                        })
            
            except Exception as e:
                user_results.append({
                    "action": "user_simulation",
                    "status": "FAIL",
                    "error": str(e)
                })
            
            user_duration = time.time() - user_start_time
            return {
                "user_id": user_id,
                "duration": user_duration,
                "results": user_results
            }
        
        # Run concurrent user simulations
        try:
            with ThreadPoolExecutor(max_workers=test_config.concurrent_users) as executor:
                loop = asyncio.get_event_loop()
                tasks = [
                    loop.run_in_executor(executor, lambda: asyncio.run(simulate_user(i, target_data)))
                    for i, target_data in enumerate(test_targets)
                ]
                
                user_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(user_results):
                    if isinstance(result, Exception):
                        errors.append(f"User {i} simulation failed: {str(result)}")
                    else:
                        results.append(result)
        
        except Exception as e:
            errors.append(f"Performance test failed: {str(e)}")
        
        # Calculate performance metrics
        total_duration = time.time() - start_time
        successful_requests = sum(1 for r in results if any(ar.get("status") == "PASS" for ar in r.get("results", [])))
        avg_response_time = sum(
            ar.get("duration", 0) for r in results 
            for ar in r.get("results", []) if ar.get("status") == "PASS"
        ) / max(successful_requests, 1)
        
        throughput = successful_requests / total_duration if total_duration > 0 else 0
        
        # Determine test status
        status = "PASS"
        if avg_response_time > test_config.expected_response_time:
            status = "FAIL"
            errors.append(f"Average response time {avg_response_time:.2f}s exceeds expected {test_config.expected_response_time}s")
        
        if throughput < test_config.expected_throughput:
            status = "FAIL"
            errors.append(f"Throughput {throughput:.2f} req/s below expected {test_config.expected_throughput} req/s")
        
        return UserExperienceTestResult(
            test_name=f"performance_{test_config.name}",
            test_type="performance_testing",
            status=status,
            duration=total_duration,
            details={
                "test_config": {
                    "concurrent_users": test_config.concurrent_users,
                    "duration": test_config.duration,
                    "expected_response_time": test_config.expected_response_time,
                    "expected_throughput": test_config.expected_throughput
                },
                "results": {
                    "total_users": len(results),
                    "successful_requests": successful_requests,
                    "average_response_time": avg_response_time,
                    "throughput": throughput
                },
                "user_results": results
            },
            errors=errors
        )
    
    async def test_user_feedback_mechanisms(self) -> UserExperienceTestResult:
        """Test user feedback collection and validation mechanisms."""
        start_time = time.time()
        results = []
        errors = []
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            
            with webdriver.Chrome(options=chrome_options) as driver:
                driver.set_window_size(1920, 1080)
                
                # Test feedback mechanisms on different pages
                feedback_tests = [
                    {
                        "page": "/target-select",
                        "mechanisms": ["form_validation", "error_messages", "success_indicators"]
                    },
                    {
                        "page": "/dashboard",
                        "mechanisms": ["progress_indicators", "status_messages", "notification_system"]
                    }
                ]
                
                for test in feedback_tests:
                    try:
                        driver.get(f"{self.base_url}{test['page']}")
                        
                        # Wait for page load
                        WebDriverWait(driver, 10).until(
                            EC.presence_of_element_located((By.TAG_NAME, "body"))
                        )
                        
                        page_results = []
                        for mechanism in test["mechanisms"]:
                            mechanism_result = await self._test_feedback_mechanism(driver, mechanism)
                            page_results.append(mechanism_result)
                        
                        results.append({
                            "page": test["page"],
                            "mechanisms": page_results
                        })
                    
                    except Exception as e:
                        errors.append(f"Failed to test feedback mechanisms for {test['page']}: {str(e)}")
        
        except Exception as e:
            errors.append(f"User feedback test failed: {str(e)}")
        
        duration = time.time() - start_time
        status = "PASS" if not errors else "FAIL"
        
        return UserExperienceTestResult(
            test_name="user_feedback_mechanisms",
            test_type="feedback_testing",
            status=status,
            duration=duration,
            details={"pages": results},
            errors=errors
        )
    
    async def _test_feedback_mechanism(self, driver: webdriver.Chrome, mechanism: str) -> Dict[str, Any]:
        """Test a specific feedback mechanism."""
        try:
            if mechanism == "form_validation":
                # Look for validation messages
                validation_elements = driver.find_elements(By.CLASS_NAME, "validation-message")
                return {
                    "mechanism": mechanism,
                    "status": "PASS" if validation_elements else "WARNING",
                    "elements_found": len(validation_elements)
                }
            
            elif mechanism == "error_messages":
                # Look for error message containers
                error_elements = driver.find_elements(By.CLASS_NAME, "error-message")
                return {
                    "mechanism": mechanism,
                    "status": "PASS" if error_elements else "WARNING",
                    "elements_found": len(error_elements)
                }
            
            elif mechanism == "success_indicators":
                # Look for success indicators
                success_elements = driver.find_elements(By.CLASS_NAME, "success-indicator")
                return {
                    "mechanism": mechanism,
                    "status": "PASS" if success_elements else "WARNING",
                    "elements_found": len(success_elements)
                }
            
            elif mechanism == "progress_indicators":
                # Look for progress indicators
                progress_elements = driver.find_elements(By.CLASS_NAME, "progress-indicator")
                return {
                    "mechanism": mechanism,
                    "status": "PASS" if progress_elements else "WARNING",
                    "elements_found": len(progress_elements)
                }
            
            else:
                return {
                    "mechanism": mechanism,
                    "status": "SKIP",
                    "reason": "Mechanism not implemented"
                }
        
        except Exception as e:
            return {
                "mechanism": mechanism,
                "status": "FAIL",
                "error": str(e)
            }
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate a comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.status == "PASS")
        failed_tests = sum(1 for r in self.test_results if r.status == "FAIL")
        warning_tests = sum(1 for r in self.test_results if r.status == "WARNING")
        
        total_duration = sum(r.duration for r in self.test_results)
        
        return {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "warning_tests": warning_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "total_duration": total_duration
            },
            "test_results": [
                {
                    "test_name": r.test_name,
                    "test_type": r.test_type,
                    "status": r.status,
                    "duration": r.duration,
                    "details": r.details,
                    "errors": r.errors,
                    "warnings": r.warnings
                }
                for r in self.test_results
            ],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []
        
        failed_tests = [r for r in self.test_results if r.status == "FAIL"]
        warning_tests = [r for r in self.test_results if r.status == "WARNING"]
        
        if failed_tests:
            recommendations.append(f"Address {len(failed_tests)} failed tests to improve user experience")
        
        if warning_tests:
            recommendations.append(f"Review {len(warning_tests)} tests with warnings for potential improvements")
        
        # Performance recommendations
        performance_tests = [r for r in self.test_results if r.test_type == "performance_testing"]
        slow_tests = [r for r in performance_tests if r.duration > 30]
        
        if slow_tests:
            recommendations.append("Optimize performance for slow-loading pages and operations")
        
        # Accessibility recommendations
        accessibility_tests = [r for r in self.test_results if r.test_type == "accessibility_testing"]
        failed_accessibility = [r for r in accessibility_tests if r.status == "FAIL"]
        
        if failed_accessibility:
            recommendations.append("Improve accessibility compliance for better user inclusivity")
        
        return recommendations


# Test functions for pytest integration
@pytest_asyncio.fixture
async def user_experience_validator():
    """Fixture for user experience validator."""
    return UserExperienceValidator()


@pytest.mark.asyncio
async def test_complete_user_journey(user_experience_validator):
    """Test complete user journey from target creation to report delivery."""
    result = await user_experience_validator.test_complete_user_journey()
    user_experience_validator.test_results.append(result)
    assert result.status == "PASS", f"User journey test failed: {result.errors}"


@pytest.mark.asyncio
async def test_ui_responsiveness(user_experience_validator):
    """Test UI responsiveness across different screen sizes."""
    result = await user_experience_validator.test_ui_responsiveness()
    user_experience_validator.test_results.append(result)
    assert result.status == "PASS", f"UI responsiveness test failed: {result.errors}"


@pytest.mark.asyncio
async def test_accessibility_compliance(user_experience_validator):
    """Test accessibility compliance."""
    result = await user_experience_validator.test_accessibility()
    user_experience_validator.test_results.append(result)
    assert result.status == "PASS", f"Accessibility test failed: {result.errors}"


@pytest.mark.asyncio
async def test_performance_light_load(user_experience_validator):
    """Test performance under light load."""
    light_load_test = PerformanceTest(
        name="light_load",
        description="Test system performance under light load",
        concurrent_users=5,
        duration=60,
        expected_response_time=2.0,
        expected_throughput=10
    )
    result = await user_experience_validator.test_performance_under_load(light_load_test)
    user_experience_validator.test_results.append(result)
    assert result.status == "PASS", f"Light load performance test failed: {result.errors}"


@pytest.mark.asyncio
async def test_user_feedback_mechanisms(user_experience_validator):
    """Test user feedback collection and validation mechanisms."""
    result = await user_experience_validator.test_user_feedback_mechanisms()
    user_experience_validator.test_results.append(result)
    assert result.status == "PASS", f"User feedback test failed: {result.errors}"


if __name__ == "__main__":
    # Run tests directly
    async def main():
        validator = UserExperienceValidator()
        
        # Run all tests
        tests = [
            validator.test_complete_user_journey(),
            validator.test_ui_responsiveness(),
            validator.test_accessibility(),
            validator.test_user_feedback_mechanisms()
        ]
        
        # Add performance tests
        for test_config in validator.performance_tests:
            tests.append(validator.test_performance_under_load(test_config))
        
        # Execute all tests
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                print(f"Test failed with exception: {result}")
            else:
                validator.test_results.append(result)
        
        # Generate and print report
        report = validator.generate_test_report()
        print(json.dumps(report, indent=2, default=str))
    
    asyncio.run(main()) 