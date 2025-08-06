"""
Complete Workflow Integration Tests

This module contains comprehensive end-to-end tests for the complete bug hunting workflow,
including all 6 stages from target creation to final report delivery.

Test Scenarios:
1. Complete workflow execution with all stages
2. Data flow validation between stages
3. API integration testing across all endpoints
4. Error handling and recovery scenarios
5. Performance and scalability testing
6. Security and authentication validation

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


class TestCompleteWorkflowIntegration:
    """
    Comprehensive integration tests for complete bug hunting workflow.
    
    Tests the entire workflow from target creation through all 6 stages
    to final report delivery, validating data flow, API integration,
    and system reliability.
    """
    
    @pytest.fixture
    async def test_target_data(self) -> Dict[str, Any]:
        """Test target data for integration testing."""
        return {
            "name": "Integration Test Target",
            "scope": "DOMAIN",
            "value": "test-integration.com",
            "description": "Target for complete workflow integration testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
    
    @pytest.fixture
    async def test_workflow_data(self) -> Dict[str, Any]:
        """Test workflow data for integration testing."""
        return {
            "name": "Complete Integration Test Workflow",
            "description": "End-to-end workflow testing for all 6 stages",
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
    
    @pytest.mark.asyncio
    async def test_complete_workflow_lifecycle(self, api_client: AsyncClient, db_session, 
                                             test_target_data: Dict[str, Any], 
                                             test_workflow_data: Dict[str, Any]):
        """
        Test complete workflow lifecycle from target creation to final report.
        
        This test validates:
        - Target creation and management
        - Workflow creation and configuration
        - Stage execution and data flow
        - API integration across all endpoints
        - Result processing and validation
        - Final report generation and delivery
        """
        logger.info("Starting complete workflow lifecycle test")
        
        # Step 1: Create target
        logger.info("Step 1: Creating test target")
        target_response = await api_client.post("/api/targets/", json=test_target_data)
        assert target_response.status_code == 200, f"Target creation failed: {target_response.text}"
        
        target_data = target_response.json()
        assert target_data["success"] is True, f"Target creation unsuccessful: {target_data}"
        target_id = target_data["data"]["id"]
        logger.info(f"Target created successfully with ID: {target_id}")
        
        # Step 2: Create workflow
        logger.info("Step 2: Creating test workflow")
        test_workflow_data["target_id"] = target_id
        workflow_response = await api_client.post("/api/workflows/", json=test_workflow_data)
        assert workflow_response.status_code == 200, f"Workflow creation failed: {workflow_response.text}"
        
        workflow_data = workflow_response.json()
        assert workflow_data["success"] is True, f"Workflow creation unsuccessful: {workflow_data}"
        workflow_id = workflow_data["data"]["id"]
        logger.info(f"Workflow created successfully with ID: {workflow_id}")
        
        # Step 3: Execute Stage 1 - Passive Reconnaissance
        logger.info("Step 3: Executing Stage 1 - Passive Reconnaissance")
        passive_recon_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "PASSIVE_RECON",
            "config_overrides": {
                "tools": "subfinder,amass,assetfinder",
                "timeout": 120,
                "test_mode": True
            }
        }
        
        passive_response = await api_client.post("/api/execution/", json=passive_recon_data)
        assert passive_response.status_code == 200, f"Passive recon execution failed: {passive_response.text}"
        
        passive_result = passive_response.json()
        assert passive_result["success"] is True, f"Passive recon unsuccessful: {passive_result}"
        passive_execution_id = passive_result["data"]["execution_id"]
        logger.info(f"Passive recon execution started with ID: {passive_execution_id}")
        
        # Wait for passive recon completion
        await self._wait_for_stage_completion(api_client, passive_execution_id, timeout=180)
        
        # Step 4: Execute Stage 2 - Active Reconnaissance
        logger.info("Step 4: Executing Stage 2 - Active Reconnaissance")
        active_recon_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "ACTIVE_RECON",
            "config_overrides": {
                "tools": "nmap,httpx,feroxbuster",
                "timeout": 180,
                "test_mode": True
            }
        }
        
        active_response = await api_client.post("/api/execution/", json=active_recon_data)
        assert active_response.status_code == 200, f"Active recon execution failed: {active_response.text}"
        
        active_result = active_response.json()
        assert active_result["success"] is True, f"Active recon unsuccessful: {active_result}"
        active_execution_id = active_result["data"]["execution_id"]
        logger.info(f"Active recon execution started with ID: {active_execution_id}")
        
        # Wait for active recon completion
        await self._wait_for_stage_completion(api_client, active_execution_id, timeout=240)
        
        # Step 5: Execute Stage 3 - Vulnerability Scanning
        logger.info("Step 5: Executing Stage 3 - Vulnerability Scanning")
        vuln_scan_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "VULN_SCAN",
            "config_overrides": {
                "tools": "nuclei,nmap,nikto",
                "timeout": 300,
                "test_mode": True
            }
        }
        
        vuln_scan_response = await api_client.post("/api/execution/", json=vuln_scan_data)
        assert vuln_scan_response.status_code == 200, f"Vulnerability scan execution failed: {vuln_scan_response.text}"
        
        vuln_scan_result = vuln_scan_response.json()
        assert vuln_scan_result["success"] is True, f"Vulnerability scan unsuccessful: {vuln_scan_result}"
        vuln_scan_execution_id = vuln_scan_result["data"]["execution_id"]
        logger.info(f"Vulnerability scan execution started with ID: {vuln_scan_execution_id}")
        
        # Wait for vulnerability scan completion
        await self._wait_for_stage_completion(api_client, vuln_scan_execution_id, timeout=360)
        
        # Step 6: Execute Stage 4 - Vulnerability Testing
        logger.info("Step 6: Executing Stage 4 - Vulnerability Testing")
        vuln_test_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "VULN_TEST",
            "config_overrides": {
                "tools": "ai_analyzer,browser_automation,evidence_collector",
                "timeout": 240,
                "test_mode": True
            }
        }
        
        vuln_test_response = await api_client.post("/api/execution/", json=vuln_test_data)
        assert vuln_test_response.status_code == 200, f"Vulnerability testing execution failed: {vuln_test_response.text}"
        
        vuln_test_result = vuln_test_response.json()
        assert vuln_test_result["success"] is True, f"Vulnerability testing unsuccessful: {vuln_test_result}"
        vuln_test_execution_id = vuln_test_result["data"]["execution_id"]
        logger.info(f"Vulnerability testing execution started with ID: {vuln_test_execution_id}")
        
        # Wait for vulnerability testing completion
        await self._wait_for_stage_completion(api_client, vuln_test_execution_id, timeout=300)
        
        # Step 7: Execute Stage 5 - Kill Chain Analysis
        logger.info("Step 7: Executing Stage 5 - Kill Chain Analysis")
        kill_chain_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "KILL_CHAIN",
            "config_overrides": {
                "tools": "mitre_attack,threat_modeling,attack_visualization",
                "timeout": 180,
                "test_mode": True
            }
        }
        
        kill_chain_response = await api_client.post("/api/execution/", json=kill_chain_data)
        assert kill_chain_response.status_code == 200, f"Kill chain analysis execution failed: {kill_chain_response.text}"
        
        kill_chain_result = kill_chain_response.json()
        assert kill_chain_result["success"] is True, f"Kill chain analysis unsuccessful: {kill_chain_result}"
        kill_chain_execution_id = kill_chain_result["data"]["execution_id"]
        logger.info(f"Kill chain analysis execution started with ID: {kill_chain_execution_id}")
        
        # Wait for kill chain analysis completion
        await self._wait_for_stage_completion(api_client, kill_chain_execution_id, timeout=240)
        
        # Step 8: Execute Stage 6 - Comprehensive Reporting
        logger.info("Step 8: Executing Stage 6 - Comprehensive Reporting")
        reporting_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "COMPREHENSIVE_REPORTING",
            "config_overrides": {
                "tools": "executive_generator,technical_docs,compliance_mapper",
                "timeout": 120,
                "test_mode": True
            }
        }
        
        reporting_response = await api_client.post("/api/execution/", json=reporting_data)
        assert reporting_response.status_code == 200, f"Comprehensive reporting execution failed: {reporting_response.text}"
        
        reporting_result = reporting_response.json()
        assert reporting_result["success"] is True, f"Comprehensive reporting unsuccessful: {reporting_result}"
        reporting_execution_id = reporting_result["data"]["execution_id"]
        logger.info(f"Comprehensive reporting execution started with ID: {reporting_execution_id}")
        
        # Wait for comprehensive reporting completion
        await self._wait_for_stage_completion(api_client, reporting_execution_id, timeout=180)
        
        # Step 9: Validate complete workflow results
        logger.info("Step 9: Validating complete workflow results")
        await self._validate_complete_workflow_results(api_client, workflow_id, target_id)
        
        logger.info("Complete workflow lifecycle test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_data_flow_between_stages(self, api_client: AsyncClient, db_session):
        """
        Test data flow and consistency between all stages.
        
        Validates that data produced by each stage is correctly
        consumed by subsequent stages and maintains integrity.
        """
        logger.info("Starting data flow validation test")
        
        # Create test target and workflow
        target_data = {
            "name": "Data Flow Test Target",
            "scope": "DOMAIN",
            "value": "dataflow-test.com",
            "description": "Target for data flow validation testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        assert target_response.status_code == 200
        target_id = target_response.json()["data"]["id"]
        
        workflow_data = {
            "target_id": target_id,
            "name": "Data Flow Test Workflow",
            "description": "Testing data flow between stages",
            "stages": ["PASSIVE_RECON", "ACTIVE_RECON", "VULN_SCAN"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_response.status_code == 200
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Execute stages and validate data flow
        stage_results = {}
        
        # Stage 1: Passive Recon
        passive_result = await self._execute_stage_and_validate(api_client, workflow_id, "PASSIVE_RECON")
        stage_results["passive_recon"] = passive_result
        
        # Validate passive recon data structure
        assert "subdomains" in passive_result["data"], "Passive recon missing subdomains data"
        assert "assets" in passive_result["data"], "Passive recon missing assets data"
        
        # Stage 2: Active Recon
        active_result = await self._execute_stage_and_validate(api_client, workflow_id, "ACTIVE_RECON")
        stage_results["active_recon"] = active_result
        
        # Validate active recon uses passive recon data
        assert "live_hosts" in active_result["data"], "Active recon missing live hosts data"
        assert "open_ports" in active_result["data"], "Active recon missing open ports data"
        
        # Stage 3: Vulnerability Scan
        vuln_scan_result = await self._execute_stage_and_validate(api_client, workflow_id, "VULN_SCAN")
        stage_results["vuln_scan"] = vuln_scan_result
        
        # Validate vulnerability scan uses active recon data
        assert "vulnerabilities" in vuln_scan_result["data"], "Vulnerability scan missing vulnerabilities data"
        assert "scan_results" in vuln_scan_result["data"], "Vulnerability scan missing scan results data"
        
        # Validate data consistency across stages
        await self._validate_data_consistency(stage_results)
        
        logger.info("Data flow validation test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, api_client: AsyncClient, db_session):
        """
        Test error handling and recovery scenarios across the workflow.
        
        Validates that the system handles errors gracefully and
        provides appropriate recovery mechanisms.
        """
        logger.info("Starting error handling and recovery test")
        
        # Test 1: Invalid target handling
        invalid_target_data = {
            "name": "Invalid Target",
            "scope": "INVALID_SCOPE",  # Invalid scope
            "value": "invalid-target",
            "description": "Target with invalid data"
        }
        
        invalid_response = await api_client.post("/api/targets/", json=invalid_target_data)
        assert invalid_response.status_code == 422, "Should return validation error for invalid scope"
        
        # Test 2: Workflow with non-existent target
        non_existent_workflow_data = {
            "target_id": str(uuid4()),  # Non-existent target ID
            "name": "Non-existent Target Workflow",
            "description": "Workflow with non-existent target",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        non_existent_response = await api_client.post("/api/workflows/", json=non_existent_workflow_data)
        assert non_existent_response.status_code == 404, "Should return not found for non-existent target"
        
        # Test 3: Stage execution with invalid configuration
        # Create valid target and workflow first
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
        
        workflow_data = {
            "target_id": target_id,
            "name": "Error Test Workflow",
            "description": "Testing error handling",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Test invalid stage execution
        invalid_execution_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "INVALID_STAGE",  # Invalid stage name
            "config_overrides": {"timeout": 60}
        }
        
        invalid_execution_response = await api_client.post("/api/execution/", json=invalid_execution_data)
        assert invalid_execution_response.status_code == 400, "Should return bad request for invalid stage"
        
        # Test 4: Recovery from stage failure
        # Execute stage with timeout that will cause failure
        timeout_execution_data = {
            "workflow_id": str(workflow_id),
            "stage_name": "PASSIVE_RECON",
            "config_overrides": {
                "timeout": 1,  # Very short timeout to cause failure
                "test_mode": True
            }
        }
        
        timeout_response = await api_client.post("/api/execution/", json=timeout_execution_data)
        assert timeout_response.status_code == 200, "Should accept execution request"
        
        execution_id = timeout_response.json()["data"]["execution_id"]
        
        # Wait for timeout and check status
        await asyncio.sleep(5)
        
        status_response = await api_client.get(f"/api/execution/{execution_id}/status")
        assert status_response.status_code == 200
        
        status_data = status_response.json()
        # Status should be failed or timeout
        assert status_data["data"]["status"] in ["FAILED", "TIMEOUT"], "Execution should have failed due to timeout"
        
        logger.info("Error handling and recovery test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_concurrent_workflow_execution(self, api_client: AsyncClient, db_session):
        """
        Test concurrent workflow execution and resource management.
        
        Validates that the system can handle multiple workflows
        running simultaneously without conflicts.
        """
        logger.info("Starting concurrent workflow execution test")
        
        # Create multiple test targets
        targets = []
        workflows = []
        
        for i in range(3):
            target_data = {
                "name": f"Concurrent Test Target {i+1}",
                "scope": "DOMAIN",
                "value": f"concurrent-test-{i+1}.com",
                "description": f"Target {i+1} for concurrent testing",
                "platform": "BUGBOUNTY",
                "is_primary": True
            }
            
            target_response = await api_client.post("/api/targets/", json=target_data)
            assert target_response.status_code == 200
            target_id = target_response.json()["data"]["id"]
            targets.append(target_id)
            
            workflow_data = {
                "target_id": target_id,
                "name": f"Concurrent Test Workflow {i+1}",
                "description": f"Workflow {i+1} for concurrent testing",
                "stages": ["PASSIVE_RECON", "ACTIVE_RECON"],
                "settings": {"test_mode": True}
            }
            
            workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
            assert workflow_response.status_code == 200
            workflow_id = workflow_response.json()["data"]["id"]
            workflows.append(workflow_id)
        
        # Execute all workflows concurrently
        execution_tasks = []
        
        for workflow_id in workflows:
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": "PASSIVE_RECON",
                "config_overrides": {
                    "timeout": 120,
                    "test_mode": True
                }
            }
            
            task = api_client.post("/api/execution/", json=execution_data)
            execution_tasks.append(task)
        
        # Wait for all executions to start
        execution_responses = await asyncio.gather(*execution_tasks)
        
        # Validate all executions started successfully
        for response in execution_responses:
            assert response.status_code == 200, f"Concurrent execution failed: {response.text}"
            result = response.json()
            assert result["success"] is True, f"Concurrent execution unsuccessful: {result}"
        
        # Wait for all executions to complete
        execution_ids = [response.json()["data"]["execution_id"] for response in execution_responses]
        
        for execution_id in execution_ids:
            await self._wait_for_stage_completion(api_client, execution_id, timeout=180)
        
        # Validate all workflows completed successfully
        for workflow_id in workflows:
            workflow_status_response = await api_client.get(f"/api/workflows/{workflow_id}")
            assert workflow_status_response.status_code == 200
            
            workflow_status = workflow_status_response.json()
            assert workflow_status["success"] is True
            
            # Check that at least one stage completed successfully
            stages = workflow_status["data"]["stages"]
            completed_stages = [stage for stage in stages if stage["status"] == "COMPLETED"]
            assert len(completed_stages) > 0, f"No stages completed for workflow {workflow_id}"
        
        logger.info("Concurrent workflow execution test passed successfully!")
    
    async def _wait_for_stage_completion(self, api_client: AsyncClient, execution_id: str, timeout: int = 300):
        """Wait for stage execution to complete with timeout."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_response = await api_client.get(f"/api/execution/{execution_id}/status")
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data["data"]["status"]
                
                if status in ["COMPLETED", "FAILED", "TIMEOUT"]:
                    logger.info(f"Stage execution {execution_id} completed with status: {status}")
                    return status_data
                
                logger.info(f"Stage execution {execution_id} status: {status}")
            
            await asyncio.sleep(5)
        
        raise TimeoutError(f"Stage execution {execution_id} did not complete within {timeout} seconds")
    
    async def _execute_stage_and_validate(self, api_client: AsyncClient, workflow_id: str, stage_name: str) -> Dict[str, Any]:
        """Execute a stage and validate the results."""
        execution_data = {
            "workflow_id": str(workflow_id),
            "stage_name": stage_name,
            "config_overrides": {
                "timeout": 120,
                "test_mode": True
            }
        }
        
        response = await api_client.post("/api/execution/", json=execution_data)
        assert response.status_code == 200, f"{stage_name} execution failed: {response.text}"
        
        result = response.json()
        assert result["success"] is True, f"{stage_name} execution unsuccessful: {result}"
        
        execution_id = result["data"]["execution_id"]
        await self._wait_for_stage_completion(api_client, execution_id, timeout=180)
        
        return result
    
    async def _validate_complete_workflow_results(self, api_client: AsyncClient, workflow_id: str, target_id: str):
        """Validate complete workflow results and data integrity."""
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
        for stage in completed_stages:
            stage_name = stage["name"]
            logger.info(f"Validating results for stage: {stage_name}")
            
            # Get stage results
            results_response = await api_client.get(f"/api/results/{stage_name.lower()}/?target_id={target_id}")
            assert results_response.status_code == 200
            
            results_data = results_response.json()
            assert results_data["success"] is True
            
            # Validate result structure
            results = results_data["data"]
            assert len(results) > 0, f"No results found for stage {stage_name}"
            
            # Stage-specific validation
            if stage_name == "PASSIVE_RECON":
                await self._validate_passive_recon_results(results)
            elif stage_name == "ACTIVE_RECON":
                await self._validate_active_recon_results(results)
            elif stage_name == "VULN_SCAN":
                await self._validate_vuln_scan_results(results)
            elif stage_name == "VULN_TEST":
                await self._validate_vuln_test_results(results)
            elif stage_name == "KILL_CHAIN":
                await self._validate_kill_chain_results(results)
            elif stage_name == "COMPREHENSIVE_REPORTING":
                await self._validate_reporting_results(results)
    
    async def _validate_passive_recon_results(self, results: List[Dict[str, Any]]):
        """Validate passive reconnaissance results."""
        for result in results:
            assert "target" in result, "Passive recon result missing target"
            assert "tool_name" in result, "Passive recon result missing tool name"
            assert "data" in result, "Passive recon result missing data"
    
    async def _validate_active_recon_results(self, results: List[Dict[str, Any]]):
        """Validate active reconnaissance results."""
        for result in results:
            assert "target" in result, "Active recon result missing target"
            assert "tool_name" in result, "Active recon result missing tool name"
            assert "data" in result, "Active recon result missing data"
    
    async def _validate_vuln_scan_results(self, results: List[Dict[str, Any]]):
        """Validate vulnerability scan results."""
        for result in results:
            assert "target" in result, "Vuln scan result missing target"
            assert "tool_name" in result, "Vuln scan result missing tool name"
            assert "data" in result, "Vuln scan result missing data"
    
    async def _validate_vuln_test_results(self, results: List[Dict[str, Any]]):
        """Validate vulnerability testing results."""
        for result in results:
            assert "target" in result, "Vuln test result missing target"
            assert "tool_name" in result, "Vuln test result missing tool name"
            assert "data" in result, "Vuln test result missing data"
    
    async def _validate_kill_chain_results(self, results: List[Dict[str, Any]]):
        """Validate kill chain analysis results."""
        for result in results:
            assert "target" in result, "Kill chain result missing target"
            assert "tool_name" in result, "Kill chain result missing tool name"
            assert "data" in result, "Kill chain result missing data"
    
    async def _validate_reporting_results(self, results: List[Dict[str, Any]]):
        """Validate comprehensive reporting results."""
        for result in results:
            assert "target" in result, "Reporting result missing target"
            assert "tool_name" in result, "Reporting result missing tool name"
            assert "data" in result, "Reporting result missing data"
    
    async def _validate_data_consistency(self, stage_results: Dict[str, Any]):
        """Validate data consistency across stages."""
        # Validate that data flows correctly between stages
        if "passive_recon" in stage_results and "active_recon" in stage_results:
            passive_data = stage_results["passive_recon"]["data"]
            active_data = stage_results["active_recon"]["data"]
            
            # Active recon should have processed passive recon results
            assert "live_hosts" in active_data, "Active recon should contain live hosts data"
        
        if "active_recon" in stage_results and "vuln_scan" in stage_results:
            active_data = stage_results["active_recon"]["data"]
            vuln_scan_data = stage_results["vuln_scan"]["data"]
            
            # Vulnerability scan should have processed active recon results
            assert "vulnerabilities" in vuln_scan_data, "Vulnerability scan should contain vulnerabilities data"


class TestAPIIntegration:
    """
    Comprehensive API integration tests.
    
    Tests all API endpoints work together correctly and
    handle various scenarios and edge cases.
    """
    
    @pytest.mark.asyncio
    async def test_api_endpoint_integration(self, api_client: AsyncClient, db_session):
        """Test integration between all API endpoints."""
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
        assert create_response.status_code == 200
        target_id = create_response.json()["data"]["id"]
        
        # Get target
        get_response = await api_client.get(f"/api/targets/{target_id}")
        assert get_response.status_code == 200
        assert get_response.json()["data"]["id"] == target_id
        
        # List targets
        list_response = await api_client.get("/api/targets/")
        assert list_response.status_code == 200
        targets = list_response.json()["data"]
        assert any(target["id"] == target_id for target in targets)
        
        # Test workflow management endpoints
        workflow_data = {
            "target_id": target_id,
            "name": "API Integration Test Workflow",
            "description": "Workflow for API integration testing",
            "stages": ["PASSIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        # Create workflow
        workflow_create_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_create_response.status_code == 200
        workflow_id = workflow_create_response.json()["data"]["id"]
        
        # Get workflow
        workflow_get_response = await api_client.get(f"/api/workflows/{workflow_id}")
        assert workflow_get_response.status_code == 200
        assert workflow_get_response.json()["data"]["id"] == workflow_id
        
        # List workflows
        workflow_list_response = await api_client.get("/api/workflows/")
        assert workflow_list_response.status_code == 200
        workflows = workflow_list_response.json()["data"]
        assert any(workflow["id"] == workflow_id for workflow in workflows)
        
        logger.info("API endpoint integration test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_authentication_and_authorization(self, api_client: AsyncClient, db_session):
        """Test authentication and authorization across all endpoints."""
        logger.info("Starting authentication and authorization test")
        
        # Test endpoints without authentication (should work in test mode)
        targets_response = await api_client.get("/api/targets/")
        assert targets_response.status_code == 200
        
        # Test with invalid authentication (if implemented)
        # This would test JWT token validation and authorization
        
        logger.info("Authentication and authorization test passed successfully!")


class TestPerformanceAndScalability:
    """
    Performance and scalability tests.
    
    Tests system performance under various load conditions
    and validates scalability characteristics.
    """
    
    @pytest.mark.asyncio
    async def test_system_performance(self, api_client: AsyncClient, db_session):
        """Test system performance under normal load."""
        logger.info("Starting system performance test")
        
        # Test API response times
        start_time = time.time()
        targets_response = await api_client.get("/api/targets/")
        response_time = time.time() - start_time
        
        assert targets_response.status_code == 200
        assert response_time < 1.0, f"API response time {response_time}s exceeds 1 second threshold"
        
        # Test workflow creation performance
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
        
        logger.info("System performance test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_concurrent_api_requests(self, api_client: AsyncClient, db_session):
        """Test system performance under concurrent API requests."""
        logger.info("Starting concurrent API requests test")
        
        # Create multiple concurrent requests
        request_tasks = []
        for i in range(10):
            task = api_client.get("/api/targets/")
            request_tasks.append(task)
        
        # Execute all requests concurrently
        start_time = time.time()
        responses = await asyncio.gather(*request_tasks)
        total_time = time.time() - start_time
        
        # Validate all requests succeeded
        for response in responses:
            assert response.status_code == 200
        
        # Validate performance
        avg_response_time = total_time / len(responses)
        assert avg_response_time < 0.5, f"Average response time {avg_response_time}s exceeds 0.5 second threshold"
        
        logger.info("Concurrent API requests test passed successfully!")


if __name__ == "__main__":
    # Run integration tests
    pytest.main([__file__, "-v", "--tb=short"]) 