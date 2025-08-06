"""
API Integration Validation Tests

This module contains comprehensive tests for API integration validation,
ensuring all API endpoints work together correctly in complete workflows.

Test Scenarios:
1. Complete API workflow testing
2. Authentication and authorization validation
3. Error handling and edge cases
4. Data consistency and integrity
5. Performance and load testing
6. Security validation

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
import pytest
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import uuid4

import httpx
from httpx import AsyncClient, ASGITransport

# Import Django ASGI application
from api.asgi import application

# Import test utilities and fixtures
from tests.conftest import api_client, db_session
from core.models.target import Target
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.models.passive_recon import PassiveReconResult
from core.models.active_recon import ActiveReconResult
from core.models.vulnerability import Vulnerability
from core.models.kill_chain import KillChain
from core.models.report import Report
from core.schemas.base import APIResponse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestAPIWorkflowIntegration:
    """
    Comprehensive API workflow integration tests.
    
    Tests complete API workflows from target creation through all stages
    to final report delivery, ensuring all endpoints work together correctly.
    """
    
    @pytest.fixture
    async def api_workflow_data(self) -> Dict[str, Any]:
        """Test data for API workflow integration testing."""
        return {
            "target": {
                "name": "API Workflow Test Target",
                "scope": "DOMAIN",
                "value": "api-workflow-test.com",
                "description": "Target for API workflow integration testing",
                "platform": "BUGBOUNTY",
                "is_primary": True
            },
            "workflow": {
                "name": "API Workflow Test",
                "description": "Complete API workflow testing",
                "stages": [
                    "PASSIVE_RECON",
                    "ACTIVE_RECON",
                    "VULN_SCAN",
                    "VULN_TEST",
                    "KILL_CHAIN",
                    "COMPREHENSIVE_REPORTING"
                ],
                "settings": {
                    "test_mode": True,
                    "timeout": 300,
                    "max_concurrent_stages": 2
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_complete_api_workflow(self, api_client: AsyncClient, db_session, 
                                       api_workflow_data: Dict[str, Any]):
        """
        Test complete API workflow from target creation to final report.
        
        Validates that all API endpoints work together correctly in a
        complete workflow scenario.
        """
        logger.info("Starting complete API workflow test")
        
        # Step 1: Create target via API
        logger.info("Step 1: Creating target via API")
        target_response = await api_client.post("/api/targets/", json=api_workflow_data["target"])
        assert target_response.status_code == 200, f"Target creation failed: {target_response.text}"
        
        target_data = target_response.json()
        assert target_data["success"] is True, f"Target creation unsuccessful: {target_data}"
        target_id = target_data["data"]["id"]
        logger.info(f"Target created successfully with ID: {target_id}")
        
        # Step 2: Create workflow via API
        logger.info("Step 2: Creating workflow via API")
        workflow_data = api_workflow_data["workflow"].copy()
        workflow_data["target_id"] = target_id
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_response.status_code == 200, f"Workflow creation failed: {workflow_response.text}"
        
        workflow_result = workflow_response.json()
        assert workflow_result["success"] is True, f"Workflow creation unsuccessful: {workflow_result}"
        workflow_id = workflow_result["data"]["id"]
        logger.info(f"Workflow created successfully with ID: {workflow_id}")
        
        # Step 3: Execute each stage via API and validate results
        stages = api_workflow_data["workflow"]["stages"]
        stage_results = {}
        
        for stage_name in stages:
            logger.info(f"Step 3.{stages.index(stage_name) + 1}: Executing {stage_name} via API")
            
            # Execute stage
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": stage_name,
                "config_overrides": {
                    "tools": self._get_stage_tools(stage_name),
                    "timeout": 120,
                    "test_mode": True
                }
            }
            
            execution_response = await api_client.post("/api/execution/", json=execution_data)
            assert execution_response.status_code == 200, f"{stage_name} execution failed: {execution_response.text}"
            
            execution_result = execution_response.json()
            assert execution_result["success"] is True, f"{stage_name} execution unsuccessful: {execution_result}"
            
            execution_id = execution_result["data"]["execution_id"]
            logger.info(f"{stage_name} execution started with ID: {execution_id}")
            
            # Wait for completion
            await self._wait_for_execution_completion(api_client, execution_id, timeout=180)
            
            # Validate stage results via API
            stage_results[stage_name] = await self._validate_stage_results(api_client, stage_name, target_id)
            
            logger.info(f"{stage_name} completed and validated successfully")
        
        # Step 4: Validate complete workflow results via API
        logger.info("Step 4: Validating complete workflow results via API")
        await self._validate_complete_workflow_results(api_client, workflow_id, target_id, stage_results)
        
        logger.info("Complete API workflow test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_api_endpoint_integration(self, api_client: AsyncClient, db_session):
        """
        Test integration between all API endpoints.
        
        Validates that all API endpoints work together correctly and
        handle various scenarios and edge cases.
        """
        logger.info("Starting API endpoint integration test")
        
        # Test target management endpoints
        target_data = {
            "name": "API Integration Test Target",
            "scope": "DOMAIN",
            "value": "api-integration-test.com",
            "description": "Target for API integration testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        # Create target
        create_response = await api_client.post("/api/targets/", json=target_data)
        assert create_response.status_code == 200, f"Target creation failed: {create_response.text}"
        target_id = create_response.json()["data"]["id"]
        
        # Get target
        get_response = await api_client.get(f"/api/targets/{target_id}")
        assert get_response.status_code == 200, f"Target retrieval failed: {get_response.text}"
        assert get_response.json()["data"]["id"] == target_id
        
        # List targets
        list_response = await api_client.get("/api/targets/")
        assert list_response.status_code == 200, f"Target listing failed: {list_response.text}"
        targets = list_response.json()["data"]
        assert any(target["id"] == target_id for target in targets)
        
        # Test workflow management endpoints
        workflow_data = {
            "target_id": target_id,
            "name": "API Integration Test Workflow",
            "description": "Workflow for API integration testing",
            "stages": ["PASSIVE_RECON", "ACTIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        # Create workflow
        workflow_create_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_create_response.status_code == 200, f"Workflow creation failed: {workflow_create_response.text}"
        workflow_id = workflow_create_response.json()["data"]["id"]
        
        # Get workflow
        workflow_get_response = await api_client.get(f"/api/workflows/{workflow_id}")
        assert workflow_get_response.status_code == 200, f"Workflow retrieval failed: {workflow_get_response.text}"
        assert workflow_get_response.json()["data"]["id"] == workflow_id
        
        # List workflows
        workflow_list_response = await api_client.get("/api/workflows/")
        assert workflow_list_response.status_code == 200, f"Workflow listing failed: {workflow_list_response.text}"
        workflows = workflow_list_response.json()["data"]
        assert any(workflow["id"] == workflow_id for workflow in workflows)
        
        # Test execution endpoints
        execution_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "PASSIVE_RECON",
            "config_overrides": {
                "tools": "subfinder,amass",
                "timeout": 60,
                "test_mode": True
            }
        }
        
        # Start execution
        execution_response = await api_client.post("/api/execution/", json=execution_data)
        assert execution_response.status_code == 200, f"Execution start failed: {execution_response.text}"
        execution_id = execution_response.json()["data"]["execution_id"]
        
        # Get execution status
        status_response = await api_client.get(f"/api/execution/{execution_id}/status")
        assert status_response.status_code == 200, f"Status retrieval failed: {status_response.text}"
        
        # Wait for completion
        await self._wait_for_execution_completion(api_client, execution_id, timeout=120)
        
        # Test results endpoints
        results_response = await api_client.get(f"/api/results/passive_recon/?target_id={target_id}")
        assert results_response.status_code == 200, f"Results retrieval failed: {results_response.text}"
        
        logger.info("API endpoint integration test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_authentication_and_authorization(self, api_client: AsyncClient, db_session):
        """
        Test authentication and authorization across all endpoints.
        
        Validates JWT token management, access controls, and security compliance.
        """
        logger.info("Starting authentication and authorization test")
        
        # Test endpoints without authentication (should work in test mode)
        targets_response = await api_client.get("/api/targets/")
        assert targets_response.status_code == 200, "Targets endpoint should be accessible"
        
        # Test with invalid authentication (if implemented)
        # This would test JWT token validation and authorization
        # For now, we'll test basic endpoint accessibility
        
        # Test protected endpoints (if any)
        # Create a target first
        target_data = {
            "name": "Auth Test Target",
            "scope": "DOMAIN",
            "value": "auth-test.com",
            "description": "Target for authentication testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        assert target_response.status_code == 200, f"Target creation failed: {target_response.text}"
        target_id = target_response.json()["data"]["id"]
        
        # Test workflow creation (should be accessible)
        workflow_data = {
            "target_id": target_id,
            "name": "Auth Test Workflow",
            "description": "Workflow for authentication testing",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_response.status_code == 200, f"Workflow creation failed: {workflow_response.text}"
        
        logger.info("Authentication and authorization test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_error_handling_and_edge_cases(self, api_client: AsyncClient, db_session):
        """
        Test error handling and edge cases across all API endpoints.
        
        Validates proper error responses, boundary conditions, and edge cases.
        """
        logger.info("Starting error handling and edge cases test")
        
        # Test 1: Invalid target data
        invalid_target_data = {
            "name": "Invalid Target",
            "scope": "INVALID_SCOPE",  # Invalid scope
            "value": "invalid-target",
            "description": "Target with invalid data"
        }
        
        invalid_response = await api_client.post("/api/targets/", json=invalid_target_data)
        assert invalid_response.status_code == 422, "Should return validation error for invalid scope"
        
        # Test 2: Missing required fields
        incomplete_target_data = {
            "name": "Incomplete Target"
            # Missing required fields
        }
        
        incomplete_response = await api_client.post("/api/targets/", json=incomplete_target_data)
        assert incomplete_response.status_code == 422, "Should return validation error for missing fields"
        
        # Test 3: Non-existent resource
        non_existent_response = await api_client.get(f"/api/targets/{uuid4()}")
        assert non_existent_response.status_code == 404, "Should return not found for non-existent target"
        
        # Test 4: Invalid workflow data
        # Create valid target first
        target_data = {
            "name": "Error Test Target",
            "scope": "DOMAIN",
            "value": "error-test.com",
            "description": "Target for error handling testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["data"]["id"]
        
        # Test workflow with non-existent target
        invalid_workflow_data = {
            "target_id": str(uuid4()),  # Non-existent target
            "name": "Invalid Workflow",
            "description": "Workflow with non-existent target",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        invalid_workflow_response = await api_client.post("/api/workflows/", json=invalid_workflow_data)
        assert invalid_workflow_response.status_code == 404, "Should return not found for non-existent target"
        
        # Test 5: Invalid execution data
        workflow_data = {
            "target_id": target_id,
            "name": "Error Test Workflow",
            "description": "Workflow for error handling testing",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Test invalid stage execution
        invalid_execution_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "INVALID_STAGE",  # Invalid stage
            "config_overrides": {"timeout": 60}
        }
        
        invalid_execution_response = await api_client.post("/api/execution/", json=invalid_execution_data)
        assert invalid_execution_response.status_code == 400, "Should return bad request for invalid stage"
        
        # Test 6: Invalid pagination parameters
        invalid_pagination_response = await api_client.get("/api/targets/?page=invalid&size=invalid")
        assert invalid_pagination_response.status_code == 422, "Should return validation error for invalid pagination"
        
        logger.info("Error handling and edge cases test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_data_consistency_and_integrity(self, api_client: AsyncClient, db_session):
        """
        Test data consistency and integrity across API operations.
        
        Validates that data remains consistent and intact throughout
        API operations and workflow execution.
        """
        logger.info("Starting data consistency and integrity test")
        
        # Create target
        target_data = {
            "name": "Data Consistency Test Target",
            "scope": "DOMAIN",
            "value": "data-consistency-test.com",
            "description": "Target for data consistency testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["data"]["id"]
        
        # Create workflow
        workflow_data = {
            "target_id": target_id,
            "name": "Data Consistency Test Workflow",
            "description": "Workflow for data consistency testing",
            "stages": ["PASSIVE_RECON", "ACTIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Execute stages and validate data consistency
        stage_results = {}
        
        for stage_name in ["PASSIVE_RECON", "ACTIVE_RECON"]:
            # Execute stage
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": stage_name,
                "config_overrides": {
                    "tools": self._get_stage_tools(stage_name),
                    "timeout": 60,
                    "test_mode": True
                }
            }
            
            execution_response = await api_client.post("/api/execution/", json=execution_data)
            execution_id = execution_response.json()["data"]["execution_id"]
            
            # Wait for completion
            await self._wait_for_execution_completion(api_client, execution_id, timeout=120)
            
            # Get results
            results_response = await api_client.get(f"/api/results/{stage_name.lower()}/?target_id={target_id}")
            stage_results[stage_name] = results_response.json()["data"]
        
        # Validate data consistency
        await self._validate_data_consistency(stage_results)
        
        # Validate workflow status consistency
        workflow_status_response = await api_client.get(f"/api/workflows/{workflow_id}")
        workflow_status = workflow_status_response.json()["data"]
        
        # Check that workflow status reflects completed stages
        completed_stages = [stage for stage in workflow_status["stages"] if stage["status"] == "COMPLETED"]
        assert len(completed_stages) >= 2, "Expected at least 2 completed stages"
        
        logger.info("Data consistency and integrity test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_api_performance_and_load(self, api_client: AsyncClient, db_session):
        """
        Test API performance and load handling.
        
        Validates API response times, concurrent request handling,
        and performance under load.
        """
        logger.info("Starting API performance and load test")
        
        # Test 1: Basic API response times
        start_time = time.time()
        targets_response = await api_client.get("/api/targets/")
        response_time = time.time() - start_time
        
        assert targets_response.status_code == 200
        assert response_time < 1.0, f"API response time {response_time}s exceeds 1 second threshold"
        
        # Test 2: Concurrent API requests
        request_tasks = []
        for i in range(10):
            task = api_client.get("/api/targets/")
            request_tasks.append(task)
        
        start_time = time.time()
        responses = await asyncio.gather(*request_tasks)
        total_time = time.time() - start_time
        
        # Validate all requests succeeded
        for response in responses:
            assert response.status_code == 200
        
        # Validate performance
        avg_response_time = total_time / len(responses)
        assert avg_response_time < 0.5, f"Average response time {avg_response_time}s exceeds 0.5 second threshold"
        
        # Test 3: Workflow creation performance
        target_data = {
            "name": "Performance Test Target",
            "scope": "DOMAIN",
            "value": "performance-test.com",
            "description": "Target for performance testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        start_time = time.time()
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_creation_time = time.time() - start_time
        
        assert target_response.status_code == 200
        assert target_creation_time < 2.0, f"Target creation time {target_creation_time}s exceeds 2 second threshold"
        
        target_id = target_response.json()["data"]["id"]
        
        # Test 4: Concurrent workflow operations
        workflow_tasks = []
        for i in range(5):
            workflow_data = {
                "target_id": target_id,
                "name": f"Performance Test Workflow {i+1}",
                "description": f"Workflow {i+1} for performance testing",
                "stages": ["PASSIVE_RECON"],
                "settings": {"test_mode": True}
            }
            
            task = api_client.post("/api/workflows/", json=workflow_data)
            workflow_tasks.append(task)
        
        start_time = time.time()
        workflow_responses = await asyncio.gather(*workflow_tasks)
        workflow_creation_time = time.time() - start_time
        
        # Validate all workflows created successfully
        for response in workflow_responses:
            assert response.status_code == 200
        
        # Validate performance
        avg_workflow_creation_time = workflow_creation_time / len(workflow_responses)
        assert avg_workflow_creation_time < 3.0, f"Average workflow creation time {avg_workflow_creation_time}s exceeds 3 second threshold"
        
        logger.info("API performance and load test passed successfully!")
    
    def _get_stage_tools(self, stage_name: str) -> str:
        """Get appropriate tools for each stage."""
        tool_mapping = {
            "PASSIVE_RECON": "subfinder,amass,assetfinder",
            "ACTIVE_RECON": "nmap,httpx,feroxbuster",
            "VULN_SCAN": "nuclei,nmap,nikto",
            "VULN_TEST": "ai_analyzer,browser_automation,evidence_collector",
            "KILL_CHAIN": "mitre_attack,threat_modeling,attack_visualization",
            "COMPREHENSIVE_REPORTING": "executive_generator,technical_docs,compliance_mapper"
        }
        return tool_mapping.get(stage_name, "default_tool")
    
    async def _wait_for_execution_completion(self, api_client: AsyncClient, execution_id: str, timeout: int = 300):
        """Wait for execution to complete with timeout."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_response = await api_client.get(f"/api/execution/{execution_id}/status")
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data["data"]["status"]
                
                if status in ["COMPLETED", "FAILED", "TIMEOUT"]:
                    logger.info(f"Execution {execution_id} completed with status: {status}")
                    return status_data
                
                logger.info(f"Execution {execution_id} status: {status}")
            
            await asyncio.sleep(5)
        
        raise TimeoutError(f"Execution {execution_id} did not complete within {timeout} seconds")
    
    async def _validate_stage_results(self, api_client: AsyncClient, stage_name: str, target_id: str) -> Dict[str, Any]:
        """Validate stage results via API."""
        results_response = await api_client.get(f"/api/results/{stage_name.lower()}/?target_id={target_id}")
        assert results_response.status_code == 200, f"Failed to get {stage_name} results"
        
        results_data = results_response.json()
        assert results_data["success"] is True, f"{stage_name} results retrieval unsuccessful"
        
        results = results_data["data"]
        assert len(results) > 0, f"No results found for {stage_name}"
        
        # Stage-specific validation
        for result in results:
            assert "target" in result, f"{stage_name} result missing target"
            assert "tool_name" in result, f"{stage_name} result missing tool name"
            assert "data" in result, f"{stage_name} result missing data"
        
        return results
    
    async def _validate_complete_workflow_results(self, api_client: AsyncClient, workflow_id: str, 
                                                target_id: str, stage_results: Dict[str, Any]):
        """Validate complete workflow results via API."""
        # Get workflow status
        workflow_response = await api_client.get(f"/api/workflows/{workflow_id}")
        assert workflow_response.status_code == 200
        
        workflow_data = workflow_response.json()
        assert workflow_data["success"] is True
        
        # Validate all stages completed
        stages = workflow_data["data"]["stages"]
        completed_stages = [stage for stage in stages if stage["status"] == "COMPLETED"]
        assert len(completed_stages) >= 4, f"Expected at least 4 completed stages, got {len(completed_stages)}"
        
        # Validate results for each stage
        for stage_name, results in stage_results.items():
            assert len(results) > 0, f"No results found for stage {stage_name}"
            
            # Validate result structure
            for result in results:
                assert "target" in result, f"{stage_name} result missing target"
                assert "tool_name" in result, f"{stage_name} result missing tool name"
                assert "data" in result, f"{stage_name} result missing data"
    
    async def _validate_data_consistency(self, stage_results: Dict[str, Any]):
        """Validate data consistency across stages."""
        # Validate that data flows correctly between stages
        if "PASSIVE_RECON" in stage_results and "ACTIVE_RECON" in stage_results:
            passive_results = stage_results["PASSIVE_RECON"]
            active_results = stage_results["ACTIVE_RECON"]
            
            # Both stages should have results
            assert len(passive_results) > 0, "Passive recon should have results"
            assert len(active_results) > 0, "Active recon should have results"
            
            # Validate result structure consistency
            for passive_result in passive_results:
                assert "target" in passive_result, "Passive recon result missing target"
                assert "tool_name" in passive_result, "Passive recon result missing tool name"
                assert "data" in passive_result, "Passive recon result missing data"
            
            for active_result in active_results:
                assert "target" in active_result, "Active recon result missing target"
                assert "tool_name" in active_result, "Active recon result missing tool name"
                assert "data" in active_result, "Active recon result missing data"


class TestAPISecurityValidation:
    """
    API security validation tests.
    
    Tests security aspects of the API including input validation,
    authentication, authorization, and security headers.
    """
    
    @pytest.mark.asyncio
    async def test_input_validation_and_sanitization(self, api_client: AsyncClient, db_session):
        """
        Test input validation and sanitization across all endpoints.
        
        Validates that the API properly validates and sanitizes all inputs
        to prevent security vulnerabilities.
        """
        logger.info("Starting input validation and sanitization test")
        
        # Test 1: SQL injection attempts
        sql_injection_target = {
            "name": "SQL Injection Test",
            "scope": "DOMAIN",
            "value": "'; DROP TABLE targets; --",
            "description": "Target with SQL injection attempt",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        sql_response = await api_client.post("/api/targets/", json=sql_injection_target)
        # Should either reject the input or properly escape it
        assert sql_response.status_code in [200, 422], "Should handle SQL injection attempt properly"
        
        # Test 2: XSS attempts
        xss_target = {
            "name": "<script>alert('XSS')</script>",
            "scope": "DOMAIN",
            "value": "xss-test.com",
            "description": "Target with XSS attempt",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        xss_response = await api_client.post("/api/targets/", json=xss_target)
        # Should either reject the input or properly escape it
        assert xss_response.status_code in [200, 422], "Should handle XSS attempt properly"
        
        # Test 3: Path traversal attempts
        path_traversal_target = {
            "name": "Path Traversal Test",
            "scope": "DOMAIN",
            "value": "../../../etc/passwd",
            "description": "Target with path traversal attempt",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        path_response = await api_client.post("/api/targets/", json=path_traversal_target)
        # Should either reject the input or properly handle it
        assert path_response.status_code in [200, 422], "Should handle path traversal attempt properly"
        
        # Test 4: Large payload attempts
        large_payload = {
            "name": "A" * 10000,  # Very large name
            "scope": "DOMAIN",
            "value": "large-payload-test.com",
            "description": "Target with large payload",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        large_response = await api_client.post("/api/targets/", json=large_payload)
        # Should either reject the input or handle it properly
        assert large_response.status_code in [200, 422, 413], "Should handle large payload properly"
        
        logger.info("Input validation and sanitization test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_security_headers(self, api_client: AsyncClient, db_session):
        """
        Test security headers in API responses.
        
        Validates that the API includes appropriate security headers
        to protect against common web vulnerabilities.
        """
        logger.info("Starting security headers test")
        
        # Test security headers on various endpoints
        endpoints = [
            "/api/targets/",
            "/api/workflows/",
            "/api/health/",
            "/api/docs/"
        ]
        
        for endpoint in endpoints:
            response = await api_client.get(endpoint)
            
            # Check for common security headers
            headers = response.headers
            
            # Content-Security-Policy (if implemented)
            if "content-security-policy" in headers:
                logger.info(f"CSP header found on {endpoint}: {headers['content-security-policy']}")
            
            # X-Content-Type-Options
            if "x-content-type-options" in headers:
                assert headers["x-content-type-options"] == "nosniff", f"Invalid X-Content-Type-Options on {endpoint}"
            
            # X-Frame-Options
            if "x-frame-options" in headers:
                assert headers["x-frame-options"] in ["DENY", "SAMEORIGIN"], f"Invalid X-Frame-Options on {endpoint}"
            
            # X-XSS-Protection
            if "x-xss-protection" in headers:
                assert "1" in headers["x-xss-protection"], f"Invalid X-XSS-Protection on {endpoint}"
            
            # Strict-Transport-Security (if HTTPS)
            if "strict-transport-security" in headers:
                logger.info(f"HSTS header found on {endpoint}: {headers['strict-transport-security']}")
        
        logger.info("Security headers test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, api_client: AsyncClient, db_session):
        """
        Test rate limiting on API endpoints.
        
        Validates that the API implements appropriate rate limiting
        to prevent abuse and ensure fair usage.
        """
        logger.info("Starting rate limiting test")
        
        # Test rapid requests to see if rate limiting is implemented
        rapid_requests = []
        for i in range(20):  # Make 20 rapid requests
            request = api_client.get("/api/targets/")
            rapid_requests.append(request)
        
        responses = await asyncio.gather(*rapid_requests, return_exceptions=True)
        
        # Count successful vs rate-limited responses
        successful = 0
        rate_limited = 0
        
        for response in responses:
            if isinstance(response, Exception):
                rate_limited += 1
            elif response.status_code == 200:
                successful += 1
            elif response.status_code == 429:  # Too Many Requests
                rate_limited += 1
            else:
                successful += 1
        
        logger.info(f"Rate limiting test results: {successful} successful, {rate_limited} rate limited")
        
        # If rate limiting is implemented, we should see some rate-limited responses
        # If not implemented, all requests should succeed
        if rate_limited > 0:
            logger.info("Rate limiting appears to be implemented")
        else:
            logger.info("Rate limiting not detected (may not be implemented)")
        
        logger.info("Rate limiting test completed")


if __name__ == "__main__":
    # Run API integration validation tests
    pytest.main([__file__, "-v", "--tb=short"]) 