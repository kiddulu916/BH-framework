"""
Integration tests for complete workflows.

This module contains end-to-end tests for complete bug hunting workflows,
including target creation, workflow execution, and result processing.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock
import uuid

from core.models.target import Target
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.models.passive_recon import PassiveReconResult
from core.models.active_recon import ActiveReconResult
from core.models.vulnerability import Vulnerability
from core.models.kill_chain import KillChain
from core.schemas.base import APIResponse
from core.tasks.execution_service import ExecutionService
from core.tasks.workflow_service import WorkflowService


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
            "workflow_id": str(workflow_id),
            "stage_name": "PASSIVE_RECON",
            "config_overrides": {
                "tools": "subfinder,amass",
                "timeout": 300
            }
        }
        with patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": str(workflow_id),
                    "stage_name": "PASSIVE_RECON",
                    "status": "completed",
                    "message": "Passive recon completed",
                    "output": "subdomain1.test-integration.com\nsubdomain2.test-integration.com",
                    "error": None
                },
                errors=None
            )
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        
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
            "workflow_id": workflow_id,
            "stage_name": "ACTIVE_RECON",
            "config_overrides": {
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
                    "stage_name": "ACTIVE_RECON",
                    "status": "completed",
                    "message": "Active recon completed",
                    "output": "Port scan results",
                    "error": None
                },
                errors=None
            )
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        
        # Step 6: Submit active recon results
        port_id = str(uuid.uuid4())
        active_data = {
            "target_id": target_id,
            "execution_id": workflow_id,
            "tools_used": ["nmap"],
            "hosts_scanned": ["api.persistence-test.com"],
            "ports": [
                {
                    "id": port_id,
                    "target_id": target_id,
                    "host": "api.persistence-test.com",
                    "port": 443,
                    "protocol": "tcp",
                    "status": "open",
                    "service_name": "https"
                }
            ],
            "services": [
                {
                    "target_id": target_id,
                    "host": "api.persistence-test.com",
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                    "state": "open",
                    "name": "https",
                    "port_id": port_id
                }
            ],
            "total_ports": 1,
            "total_services": 1,
            "metadata": {"scan_type": "tcp_connect"}
        }
        
        response = await api_client.post("/api/results/active-recon", json=active_data)
        print(f"Active recon response: {response.json()}")  # Debug print
        assert response.status_code == 200
        active_response = response.json()
        if not active_response["success"]:
            print(f"Active recon FAIL: {active_response}")
        assert active_response["success"] is True
        
        # Step 7: Execute vulnerability scan
        execution_data = {
            "workflow_id": workflow_id,
            "stage_name": "VULN_SCAN",
            "config_overrides": {
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
                    "stage_name": "VULN_SCAN",
                    "status": "completed",
                    "message": "Vulnerability scan completed",
                    "output": "Vulnerability scan results",
                    "error": None
                },
                errors=None
            )
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        
        # Step 8: Submit vulnerability results
        vulnerability_data = {
            "target_id": target_id,
            "execution_id": str(workflow_id),
            "tools_used": ["nuclei"],
            "findings": [
                {
                    "target_id": target_id,
                    "title": "SQL Injection Vulnerability",
                    "description": "SQL injection found in login form",
                    "severity": "high",
                    "status": "open",
                    "vulnerability_type": "other",
                    "tool": "nuclei",
                    "host": "subdomain1.test-integration.com",
                    "url": "https://subdomain1.test-integration.com/login",
                    "payload": "Payload: ' OR 1=1--",
                    "evidence": "Payload: ' OR 1=1--",
                    "cvss_score": 8.5
                }
            ],
            "total_findings": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "execution_time": 120.0,
            "scan_config": {},
            "raw_output": {},
            "metadata": {
                "scanner": "nuclei",
                "execution_time": 120.0
            }
        }
        response = await api_client.post("/api/results/vulnerabilities/", json=vulnerability_data)
        assert response.status_code == 200
        vuln_response = response.json()
        print(f"Vulnerability response: {vuln_response}")  # Debug print
        assert vuln_response["success"] is True
        
        # Step 9: Execute vulnerability testing
        execution_data = {
            "workflow_id": workflow_id,
            "stage_name": "VULN_TEST",
            "config_overrides": {
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
                    "stage_name": "VULN_TEST",
                    "status": "completed",
                    "message": "Vulnerability testing completed",
                    "output": "Vulnerability testing results",
                    "error": None
                },
                errors=None
            )
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        # Submit vulnerability testing results (simulate VULN_TEST result)
        vuln_test_data = {
            "target_id": target_id,
            "execution_id": str(workflow_id),
            "tools_used": ["ffuf"],
            "findings": [
                {
                    "target_id": target_id,
                    "title": "Directory brute force",
                    "description": "Found /admin endpoint",
                    "severity": "medium",
                    "status": "open",
                    "vulnerability_type": "other",
                    "tool": "ffuf",
                    "host": "subdomain1.test-integration.com",
                    "url": "https://subdomain1.test-integration.com/admin",
                    "payload": "Payload: /admin",
                    "evidence": "200 OK",
                    "cvss_score": 5.0
                }
            ],
            "total_findings": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "info_count": 0,
            "execution_time": 30.0,
            "scan_config": {},
            "raw_output": {},
            "metadata": {
                "scanner": "ffuf",
                "execution_time": 30.0
            }
        }
        response = await api_client.post("/api/results/vulnerabilities/", json=vuln_test_data)
        assert response.status_code == 200
        vuln_test_response = response.json()
        print(f"VULN_TEST result response: {vuln_test_response}")
        assert vuln_test_response["success"] is True
        
        # Step 10: Execute kill chain analysis
        execution_data = {
            "workflow_id": workflow_id,
            "stage_name": "KILL_CHAIN",
            "config_overrides": {
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
                    "stage_name": "KILL_CHAIN",
                    "status": "completed",
                    "message": "Kill chain analysis completed",
                    "output": "Kill chain analysis results",
                    "error": None
                },
                errors=None
            )
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        
        # Step 11: Submit kill chain results
        kill_chain_data = {
            "target_id": target_id,
            "execution_id": str(workflow_id),
            "attack_paths": [
                {
                    "target_id": target_id,
                    "name": "SQL Injection to Data Exfiltration",
                    "description": "Attack path from SQL injection to data exfiltration",
                    "attack_path_type": "data_exfiltration",
                    "severity": "high",
                    "status": "verified",
                    "stages": ["exploitation", "command_and_control", "actions_on_objectives"],
                    "entry_points": ["https://subdomain1.test-integration.com/login"],
                    "exit_points": ["Database server"],
                    "prerequisites": ["SQL injection vulnerability"],
                    "techniques": ["T1190", "T1055"],
                    "tools_required": ["sqlmap", "custom scripts"],
                    "evidence": "Successfully exploited SQL injection to access database",
                    "proof_of_concept": "Demonstrated data extraction through SQL injection",
                    "screenshots": [],
                    "risk_score": 8.5,
                    "impact_assessment": "High impact - potential data breach",
                    "remediation": "Fix SQL injection vulnerability in login form",
                    "metadata": {
                        "analysis_depth": 3,
                        "execution_time": 180.0
                    }
                }
            ],
            "total_attack_paths": 1,
            "critical_paths": 0,
            "high_paths": 1,
            "medium_paths": 0,
            "low_paths": 0,
            "info_paths": 0,
            "verified_paths": 1,
            "execution_time": 180.0,
            "analysis_config": {
                "depth": 3,
                "mode": "automated"
            },
            "raw_output": {
                "analysis_results": "Kill chain analysis completed"
            },
            "metadata": {
                "analysis_depth": 3,
                "execution_time": 180.0
            }
        }
        
        response = await api_client.post("/api/results/kill-chain", json=kill_chain_data)
        assert response.status_code == 200
        kill_chain_response = response.json()
        print(f"Kill chain response: {kill_chain_response}")  # Debug print
        if not kill_chain_response["success"]:
            print(f"Kill chain FAIL: {kill_chain_response}")
        assert kill_chain_response["success"] is True
        
        # Step 12: Execute report generation
        execution_data = {
            "workflow_id": workflow_id,
            "stage_name": "REPORT",
            "config_overrides": {
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
                    "stage_name": "REPORT",
                    "status": "completed",
                    "message": "Report generation completed",
                    "output": "Report file path",
                    "error": None
                },
                errors=None
            )
            
            response = await api_client.post(
                f"/api/execution/workflows/{workflow_id}/execute",
                json=execution_data
            )
            print(f"Execution response: {response.json()}")  # Debug print
            assert response.status_code == 200
            execution_response = response.json()
            if not execution_response["success"]:
                print(f"FAIL: {execution_response}")
            assert execution_response["success"] is True
        
        # Step 12b: Submit a report to trigger workflow completion
        report_payload = {
            "workflow_id": workflow_id,
            "title": "Integration Test Report",
            "format": "markdown",
            "template": "default"
        }
        response = await api_client.post("/api/reports/", json=report_payload)
        print(f"Report creation response: {response.json()}")
        assert response.status_code == 200
        report_response = response.json()
        assert report_response["success"] is True
        
        # Step 13: Verify workflow completion
        response = await api_client.get(f"/api/execution/workflows/{workflow_id}/status")
        assert response.status_code == 200
        status_response = response.json()
        assert status_response["success"] is True
        assert status_response["data"]["status"] == "COMPLETED"
        
        # Step 14: Get target summary
        response = await api_client.get(f"/api/targets/{target_id}/summary")
        assert response.status_code == 200
        summary_response = response.json()
        assert summary_response["success"] is True
        assert summary_response["data"]["target"]["id"] == target_id
        assert "statistics" in summary_response["data"]
        assert "workflows" in summary_response["data"]["statistics"]
    
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
            "workflow_id": str(workflow_id),
            "stage_name": "passive_recon",
            "priority": 0,
            "config_overrides": {}
        }
        
        with patch('core.tasks.execution_service.ExecutionService._run_container') as mock_run_container:
            # Mock the container execution to return a failed result
            mock_run_container.return_value = {
                "success": False,
                "message": "Container execution failed",
                "error": "Connection timeout"
            }
            
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
        assert status_response["data"]["status"] == "FAILED"
    
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
        with patch('core.tasks.workflow_service.WorkflowService.execute_stage') as mock_workflow_stage, \
             patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            mock_workflow_stage.return_value = APIResponse(
                success=True,
                message="Stage execution validated",
                data={
                    "workflow_id": "test-workflow-id",
                    "stage_name": "passive_recon",
                    "status": "RUNNING",
                    "message": "Concurrent execution validated"
                },
                errors=None
            )
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": "test-workflow-id",
                    "stage_name": "passive_recon",
                    "status": "COMPLETED",
                    "message": "Concurrent execution completed"
                },
                errors=None
            )
            
            # Execute all workflows concurrently
            import asyncio
            tasks = []
            for workflow_id in workflows:
                execution_data = {
                    "workflow_id": workflow_id,
                    "stage_name": "passive_recon",
                    "config_overrides": {"tools": "subfinder"}
                }
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
                print('DEBUG concurrent workflow response:', response_data)
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
            "execution_id": workflow_id,
            "tools_used": ["subfinder"],
            "subdomains": [
                {
                    "target_id": target_id,
                    "subdomain": "api.persistence-test.com",
                    "domain": "persistence-test.com",
                    "ip_addresses": ["192.168.1.251"],
                    "status": "active",
                    "source": "subfinder",
                    "metadata": {}
                }
            ],
            "total_subdomains": 1,
            "execution_time": "10.0",
            "raw_output": {"subfinder": "api.persistence-test.com"},
            "metadata": {"tools_used": ["subfinder"]}
        }
        
        response = await api_client.post("/api/results/passive-recon", json=passive_data)
        print(f"Persistence passive recon response: {response.json()}")  # Debug print
        assert response.status_code == 200
        passive_response = response.json()
        assert passive_response["success"] is True
        
        # Submit active recon results that reference passive recon data
        port_id = str(uuid.uuid4())
        active_data = {
            "target_id": target_id,
            "execution_id": workflow_id,
            "tools_used": ["nmap"],
            "hosts_scanned": ["api.persistence-test.com"],
            "ports": [
                {
                    "id": port_id,
                    "target_id": target_id,
                    "host": "api.persistence-test.com",
                    "port": 443,
                    "protocol": "tcp",
                    "status": "open",
                    "service_name": "https"
                }
            ],
            "services": [
                {
                    "target_id": target_id,
                    "host": "api.persistence-test.com",
                    "port": 443,
                    "protocol": "tcp",
                    "service_name": "https",
                    "state": "open",
                    "name": "https",
                    "port_id": port_id
                }
            ],
            "total_ports": 1,
            "total_services": 1,
            "metadata": {"scan_type": "tcp_connect"}
        }
        
        response = await api_client.post("/api/results/active-recon", json=active_data)
        assert response.status_code == 200
        
        # Verify data persistence by retrieving results
        response = await api_client.get(f"/api/results/{target_id}/passive-recon")
        assert response.status_code == 200
        passive_results = response.json()
        print(f"Passive recon GET response: {passive_results}")  # Debug print
        assert passive_results["success"] is True
        
        response = await api_client.get(f"/api/results/{target_id}/active-recon")
        assert response.status_code == 200
        active_results = response.json()
        if not active_results["success"]:
            print(f"Active recon GET response (failure): {active_results}")
        assert active_results["success"] is True
        assert len(active_results["data"]["results"]) >= 1
        
        # Verify target summary includes all results
        response = await api_client.get(f"/api/targets/{target_id}/summary")
        assert response.status_code == 200
        summary = response.json()
        assert summary["success"] is True
        assert "statistics" in summary["data"]
