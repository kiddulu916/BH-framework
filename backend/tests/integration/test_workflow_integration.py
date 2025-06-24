"""
Integration tests for complete workflows.

This module contains end-to-end tests for complete bug hunting workflows,
including target creation, workflow execution, and result processing.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock

from core.models.target import Target
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.models.passive_recon import PassiveReconResult
from core.models.active_recon import ActiveReconResult
from core.models.vulnerability import Vulnerability
from core.models.kill_chain import KillChain
from core.schemas.base import APIResponse


class TestWorkflowIntegration:
    """Test suite for complete workflow integration."""
    
    @pytest.mark.asyncio
    async def test_complete_workflow_lifecycle(self, api_client: AsyncClient, db_session):
        """Test complete workflow lifecycle from target creation to report generation."""
        # Step 1: Create target
        target_data = {
            "name": "Integration Test Target",
            "scope": "DOMAIN",
            "value": "test-integration.com",
            "description": "Integration test target"
        }
        
        response = await api_client.post("/api/targets/", json=target_data)
        assert response.status_code == 200
        target_response = response.json()
        assert target_response["success"] is True
        target_id = target_response["data"]["id"]
        
        # Step 2: Create workflow
        workflow_data = {
            "target_id": target_id,
            "name": "Integration Test Workflow",
            "description": "Complete workflow test",
            "stages": [
                "PASSIVE_RECON",
                "ACTIVE_RECON", 
                "VULN_SCAN",
                "VULN_TEST",
                "KILL_CHAIN",
                "REPORT"
            ],
            "settings": {"test_mode": True}
        }
        
        response = await api_client.post("/api/workflows/", json=workflow_data)
        assert response.status_code == 200
        workflow_response = response.json()
        print(f"Workflow response: {workflow_response}")  # Debug print
        assert workflow_response["success"] is True
        workflow_id = workflow_response["data"]["id"]
        
        # Step 3: Execute passive recon stage
        execution_data = {
            "workflow_id": workflow_id,
            "stage_name": "PASSIVE_RECON",
            "config_overrides": {
                "tools": "subfinder,amass",
                "depth": 1
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "passive_recon",
                    "status": "completed",
                    "message": "Passive recon completed",
                    "output": "subdomain1.test-integration.com\nsubdomain2.test-integration.com",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
        
        # Step 4: Submit passive recon results
        passive_recon_data = {
            "target_id": target_id,
            "execution_id": str(workflow_id),
            "tools_used": ["subfinder", "amass"],
            "subdomains": [
                {
                    "target_id": target_id,
                    "subdomain": "test.example.com",
                    "domain": "example.com",
                    "ip_addresses": ["192.168.1.1"],
                    "status": "active",
                    "source": "subfinder",
                    "metadata": {"scan_duration": 120}
                },
                {
                    "target_id": target_id,
                    "subdomain": "api.example.com",
                    "domain": "example.com",
                    "ip_addresses": ["192.168.1.2"],
                    "status": "active",
                    "source": "amass",
                    "metadata": {"scan_duration": 120}
                }
            ],
            "total_subdomains": 2,
            "execution_time": "120.5",
            "raw_output": {
                "subfinder": "test.example.com\napi.example.com",
                "amass": "test.example.com\napi.example.com"
            },
            "metadata": {"scan_duration": 120}
        }
        
        response = await api_client.post("/api/results/passive-recon", json=passive_recon_data)
        print(f"Passive recon response: {response.json()}")  # Debug print
        assert response.status_code == 200
        passive_response = response.json()
        assert passive_response["success"] is True
        
        # Step 5: Execute active recon stage
        execution_data = {
            "stage_name": "active_recon",
            "settings": {
                "ports": "80,443,8080",
                "timeout": 30
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "active_recon",
                    "status": "completed",
                    "message": "Active recon completed",
                    "output": "Port scan results",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is True
        
        # Step 6: Submit active recon results
        active_recon_data = {
            "target_id": target_id,
            "workflow_id": workflow_id,
            "live_hosts": [
                {
                    "host": "subdomain1.test-integration.com",
                    "ip_address": "192.168.1.101",
                    "ports": [
                        {"port": 80, "service": "http", "state": "open"},
                        {"port": 443, "service": "https", "state": "open"}
                    ]
                }
            ],
            "metadata": {
                "scan_type": "tcp_connect",
                "execution_time": 45.2
            }
        }
        
        response = await api_client.post("/api/results/active-recon/", json=active_recon_data)
        assert response.status_code == 200
        active_response = response.json()
        assert active_response["success"] is True
        
        # Step 7: Execute vulnerability scan
        execution_data = {
            "stage_name": "vulnerability_scan",
            "settings": {
                "templates": "cves,vulnerabilities",
                "severity": "low,medium,high,critical"
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "vulnerability_scan",
                    "status": "completed",
                    "message": "Vulnerability scan completed",
                    "output": "Vulnerability scan results",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is True
        
        # Step 8: Submit vulnerability results
        vulnerability_data = {
            "target_id": target_id,
            "workflow_id": workflow_id,
            "vulnerabilities": [
                {
                    "title": "SQL Injection Vulnerability",
                    "description": "SQL injection found in login form",
                    "severity": "high",
                    "cvss_score": 8.5,
                    "affected_url": "https://subdomain1.test-integration.com/login",
                    "evidence": "Payload: ' OR 1=1--",
                    "status": "open"
                }
            ],
            "metadata": {
                "scanner": "nuclei",
                "execution_time": 120.0
            }
        }
        
        response = await api_client.post("/api/results/vulnerabilities/", json=vulnerability_data)
        assert response.status_code == 200
        vuln_response = response.json()
        assert vuln_response["success"] is True
        
        # Step 9: Execute vulnerability testing
        execution_data = {
            "stage_name": "vulnerability_test",
            "settings": {
                "mode": "safe",
                "timeout": 60
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "vulnerability_test",
                    "status": "completed",
                    "message": "Vulnerability testing completed",
                    "output": "Vulnerability testing results",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is True
        
        # Step 10: Execute kill chain analysis
        execution_data = {
            "stage_name": "kill_chain_analysis",
            "settings": {
                "depth": 3,
                "mode": "automated"
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "kill_chain_analysis",
                    "status": "completed",
                    "message": "Kill chain analysis completed",
                    "output": "Kill chain analysis results",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is True
        
        # Step 11: Submit kill chain results
        kill_chain_data = {
            "target_id": target_id,
            "workflow_id": workflow_id,
            "attack_paths": [
                {
                    "name": "SQL Injection to Data Exfiltration",
                    "description": "Attack path from SQL injection to data exfiltration",
                    "steps": [
                        {
                            "step": 1,
                            "action": "SQL Injection",
                            "target": "Login form",
                            "success_probability": 0.8
                        },
                        {
                            "step": 2,
                            "action": "Database Access",
                            "target": "User database",
                            "success_probability": 0.9
                        }
                    ],
                    "overall_risk": "high"
                }
            ],
            "metadata": {
                "analysis_depth": 3,
                "execution_time": 180.0
            }
        }
        
        response = await api_client.post("/api/results/kill-chain/", json=kill_chain_data)
        assert response.status_code == 200
        kill_chain_response = response.json()
        assert kill_chain_response["success"] is True
        
        # Step 12: Generate report
        execution_data = {
            "stage_name": "report_generation",
            "settings": {
                "format": "markdown",
                "template": "default"
            }
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "report_generation",
                    "status": "completed",
                    "message": "Report generation completed",
                    "output": "Report generated successfully",
                    "error": None
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is True
        
        # Step 13: Verify workflow completion
        response = await api_client.get(f"/api/execution/workflows/{workflow_id}/status")
        assert response.status_code == 200
        status_response = response.json()
        assert status_response["success"] is True
        assert status_response["data"]["status"] == "completed"
        
        # Step 14: Get target summary
        response = await api_client.get(f"/api/targets/{target_id}/summary")
        assert response.status_code == 200
        summary_response = response.json()
        assert summary_response["success"] is True
        assert summary_response["data"]["target"]["id"] == target_id
        assert len(summary_response["data"]["workflows"]) >= 1
        assert len(summary_response["data"]["results"]) >= 1
    
    @pytest.mark.asyncio
    async def test_workflow_error_handling(self, api_client: AsyncClient, db_session):
        """Test workflow error handling and recovery."""
        # Create target
        target_data = {
            "name": "Error Handling Test Target",
            "scope": "DOMAIN",
            "value": "error-test.com",
            "description": "Error handling test target"
        }
        
        response = await api_client.post("/api/targets/", json=target_data)
        assert response.status_code == 200
        target_response = response.json()
        target_id = target_response["data"]["id"]
        
        # Create workflow
        workflow_data = {
            "target_id": target_id,
            "name": "Error Test Workflow",
            "description": "Error handling test",
            "stages": ["passive_recon", "active_recon"],
            "settings": {"test_mode": True}
        }
        
        response = await api_client.post("/api/workflows/", json=workflow_data)
        assert response.status_code == 200
        workflow_response = response.json()
        workflow_id = workflow_response["data"]["id"]
        
        # Test stage execution failure
        execution_data = {
            "stage_name": "passive_recon",
            "settings": {}
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=False,
                message="Stage execution failed",
                data={
                    "workflow_id": workflow_id,
                    "stage_name": "passive_recon",
                    "status": "failed",
                    "message": "Tool execution failed",
                    "error": "Connection timeout"
                }
            ).model_dump()
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            assert response.status_code == 200
            execution_response = response.json()
            assert execution_response["success"] is False
            assert "failed" in execution_response["message"].lower()
        
        # Verify workflow status reflects failure
        response = await api_client.get(f"/api/execution/workflows/{workflow_id}/status")
        assert response.status_code == 200
        status_response = response.json()
        assert status_response["success"] is True
        assert status_response["data"]["status"] == "failed"
    
    @pytest.mark.asyncio
    async def test_concurrent_workflow_execution(self, api_client: AsyncClient, db_session):
        """Test concurrent workflow execution handling."""
        # Create multiple targets
        targets = []
        for i in range(3):
            target_data = {
                "name": f"Concurrent Test Target {i}",
                "scope": "DOMAIN",
                "value": f"concurrent-test-{i}.com",
                "description": f"Concurrent test target {i}"
            }
            
            response = await api_client.post("/api/targets/", json=target_data)
            assert response.status_code == 200
            target_response = response.json()
            targets.append(target_response["data"]["id"])
        
        # Create workflows for each target
        workflows = []
        for target_id in targets:
            workflow_data = {
                "target_id": target_id,
                "name": f"Concurrent Workflow {target_id}",
                "description": "Concurrent execution test",
                "stages": ["passive_recon"],
                "settings": {"test_mode": True}
            }
            
            response = await api_client.post("/api/workflows/", json=workflow_data)
            assert response.status_code == 200
            workflow_response = response.json()
            workflows.append(workflow_response["data"]["id"])
        
        # Execute workflows concurrently
        execution_data = {
            "stage_name": "passive_recon",
            "settings": {"tools": "subfinder"}
        }
        
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "status": "completed",
                    "message": "Concurrent execution completed"
                }
            ).model_dump()
            
            # Execute all workflows concurrently
            import asyncio
            tasks = []
            for workflow_id in workflows:
                task = api_client.post(
                    f"/api/execution/workflows/{workflow_id}/execute",
                    json=execution_data
                )
                tasks.append(task)
            
            responses = await asyncio.gather(*tasks)
            
            # Verify all executions completed
            for response in responses:
                assert response.status_code == 200
                response_data = response.json()
                assert response_data["success"] is True
    
    @pytest.mark.asyncio
    async def test_data_persistence_across_stages(self, api_client: AsyncClient, db_session):
        """Test that data persists correctly across workflow stages."""
        # Create target and workflow
        target_data = {
            "name": "Persistence Test Target",
            "scope": "DOMAIN",
            "value": "persistence-test.com",
            "description": "Data persistence test"
        }
        
        response = await api_client.post("/api/targets/", json=target_data)
        assert response.status_code == 200
        target_id = response.json()["data"]["id"]
        
        workflow_data = {
            "target_id": target_id,
            "name": "Persistence Test Workflow",
            "description": "Data persistence test",
            "stages": ["passive_recon", "active_recon"],
            "settings": {"test_mode": True}
        }
        
        response = await api_client.post("/api/workflows/", json=workflow_data)
        assert response.status_code == 200
        workflow_id = response.json()["data"]["id"]
        
        # Submit passive recon results
        passive_data = {
            "target_id": target_id,
            "workflow_id": workflow_id,
            "subdomains": [
                {
                    "subdomain": "api.persistence-test.com",
                    "ip_address": "192.168.1.251",
                    "source": "subfinder"
                }
            ],
            "metadata": {"tools_used": ["subfinder"]}
        }
        
        response = await api_client.post("/api/results/passive-recon/", json=passive_data)
        assert response.status_code == 200
        
        # Submit active recon results that reference passive recon data
        active_data = {
            "target_id": target_id,
            "workflow_id": workflow_id,
            "live_hosts": [
                {
                    "host": "api.persistence-test.com",  # From passive recon
                    "ip_address": "192.168.1.251",
                    "ports": [{"port": 443, "service": "https", "state": "open"}]
                }
            ],
            "metadata": {"scan_type": "tcp_connect"}
        }
        
        response = await api_client.post("/api/results/active-recon/", json=active_data)
        assert response.status_code == 200
        
        # Verify data persistence by retrieving results
        response = await api_client.get(f"/api/results/passive-recon/?target_id={target_id}")
        assert response.status_code == 200
        passive_results = response.json()
        assert passive_results["success"] is True
        assert len(passive_results["data"]["results"]) >= 1
        
        response = await api_client.get(f"/api/results/active-recon/?target_id={target_id}")
        assert response.status_code == 200
        active_results = response.json()
        assert active_results["success"] is True
        assert len(active_results["data"]["results"]) >= 1
        
        # Verify target summary includes all results
        response = await api_client.get(f"/api/targets/{target_id}/summary")
        assert response.status_code == 200
        summary = response.json()
        assert summary["success"] is True
        assert len(summary["data"]["results"]) >= 2  # Passive + Active recon 
