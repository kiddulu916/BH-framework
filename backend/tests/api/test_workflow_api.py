"""
Tests for workflow API endpoints.

This module contains tests for all workflow management API endpoints,
including workflow CRUD operations, execution, and status monitoring.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from core.models.target import Target, TargetScope, TargetStatus
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.schemas.workflow import WorkflowCreateRequest, WorkflowUpdateRequest
from core.schemas.base import APIResponse


class TestWorkflowAPI:
    """Test suite for workflow API endpoints."""
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_create_workflow_success(self, api_client: AsyncClient, sample_target):
        """Test successful workflow creation."""
        # Arrange
        workflow_data = {
            "target_id": str(sample_target.id),
            "name": "Test Workflow",
            "description": "Test workflow for bug hunting",
            "settings": {
                "passive_recon": {"tools": ["subfinder", "amass"]},
                "active_recon": {"ports": [80, 443, 8080]},
                "vulnerability_scan": {"templates": ["http-vulns", "cves"]}
            }
        }
        
        # Act
        response = await api_client.post("/api/workflows/", json=workflow_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow created successfully"
        assert data["data"]["name"] == workflow_data["name"]
        assert data["data"]["target_id"] == str(sample_target.id)
        assert data["data"]["status"] == "PENDING"
        assert "id" in data["data"]
        assert "created_at" in data["data"]
        assert "updated_at" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_create_workflow_validation_error(self, api_client: AsyncClient):
        """Test workflow creation with validation errors."""
        # Arrange
        invalid_data = {
            "target_id": "invalid-uuid",
            "name": "",  # Empty name
            "description": "A" * 1001  # Too long description
        }
        
        # Act
        response = await api_client.post("/api/workflows/", json=invalid_data)
        
        # Assert
        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_create_workflow_target_not_found(self, api_client: AsyncClient):
        """Test workflow creation with non-existent target."""
        # Arrange
        non_existent_id = uuid4()
        workflow_data = {
            "target_id": str(non_existent_id),
            "name": "Test Workflow",
            "description": "Test workflow"
        }
        
        # Act
        response = await api_client.post("/api/workflows/", json=workflow_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow retrieval."""
        # Act
        response = await api_client.get(f"/api/workflows/{sample_workflow.id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow retrieved successfully"
        assert data["data"]["id"] == str(sample_workflow.id)
        assert data["data"]["name"] == sample_workflow.name
        assert data["data"]["target_id"] == str(sample_workflow.target_id)
        assert "stages" in data["data"]
        assert "settings" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_not_found(self, api_client: AsyncClient):
        """Test workflow retrieval with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/workflows/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_list_workflows_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow listing."""
        # Act
        response = await api_client.get("/api/workflows/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflows retrieved successfully"
        assert "data" in data
        assert "workflows" in data["data"]
        assert "pagination" in data["data"]
        
        # Check if our sample workflow is in the list
        workflow_ids = [workflow["id"] for workflow in data["data"]["workflows"]]
        assert str(sample_workflow.id) in workflow_ids
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_list_workflows_with_filtering(self, api_client: AsyncClient, sample_workflow):
        """Test workflow listing with status filter."""
        # Act
        response = await api_client.get(f"/api/workflows/?status=PENDING&target_id={sample_workflow.target_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "workflows" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_list_workflows_with_pagination(self, api_client: AsyncClient):
        """Test workflow listing with pagination."""
        # Act
        response = await api_client.get("/api/workflows/?limit=5&offset=0")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "pagination" in data["data"]
        assert data["data"]["pagination"]["limit"] == 5
        assert data["data"]["pagination"]["offset"] == 0
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_update_workflow_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow update."""
        # Arrange
        update_data = {
            "name": "Updated Workflow Name",
            "description": "Updated workflow description",
            "settings": {
                "passive_recon": {"tools": ["subfinder", "amass", "assetfinder"]},
                "active_recon": {"ports": [80, 443, 8080, 8443]}
            }
        }
        
        # Act
        response = await api_client.put(f"/api/workflows/workflows/{sample_workflow.id}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow updated successfully"
        assert data["data"]["name"] == update_data["name"]
        assert data["data"]["description"] == update_data["description"]
        assert data["data"]["id"] == str(sample_workflow.id)
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_update_workflow_not_found(self, api_client: AsyncClient):
        """Test workflow update with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        update_data = {"name": "Updated Name"}
        
        # Act
        response = await api_client.put(f"/api/workflows/workflows/{non_existent_id}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_delete_workflow_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow deletion."""
        # Act
        response = await api_client.delete(f"/api/workflows/workflows/{sample_workflow.id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow deleted successfully"
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_delete_workflow_not_found(self, api_client: AsyncClient):
        """Test workflow deletion with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.delete(f"/api/workflows/workflows/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_summary_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow summary retrieval."""
        # Act
        response = await api_client.get(f"/api/workflows/{sample_workflow.id}/summary")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow summary retrieved successfully"
        assert "data" in data
        assert data["data"]["workflow_id"] == str(sample_workflow.id)
        assert "summary" in data["data"]
        assert "statistics" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_execute_workflow_stage_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow stage execution."""
        # Arrange
        execution_data = {
            "stage_name": "passive_recon",
            "config_overrides": {
                "tools": ["subfinder", "amass"],
                "depth": 2
            }
        }
        
        # Mock both workflow service and execution service
        with patch('core.tasks.workflow_service.WorkflowService.execute_stage') as mock_workflow_execute, \
             patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execution_execute:
            
            # Mock workflow service to return success
            async def mock_workflow_side_effect(*args, **kwargs):
                return APIResponse(
                    success=True,
                    message="Stage execution started",
                    data={
                        "workflow_id": str(sample_workflow.id),
                        "stage_name": "passive_recon",
                        "status": "running"
                    },
                    errors=None
                )
            mock_workflow_execute.side_effect = mock_workflow_side_effect
            
            # Mock execution service to return success
            async def mock_execution_side_effect(*args, **kwargs):
                return APIResponse(
                    success=True,
                    message="Stage execution completed",
                    data={
                        "workflow_id": str(sample_workflow.id),
                        "stage_name": "passive_recon",
                        "status": "completed",
                        "message": "Stage execution completed",
                        "output": "Test output",
                        "error": None
                    },
                    errors=None
                )
            mock_execution_execute.side_effect = mock_execution_side_effect
            
            # Act
            response = await api_client.post(
                f"/api/workflows/{sample_workflow.id}/execute",
                json=execution_data
            )
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Stage execution completed"
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_execute_workflow_stage_invalid_stage(self, api_client: AsyncClient, sample_workflow):
        """Test workflow stage execution with invalid stage name."""
        # Arrange
        execution_data = {
            "stage_name": "invalid_stage",
            "config_overrides": {}
        }
        
        # Act
        response = await api_client.post(
            f"/api/workflows/{sample_workflow.id}/execute",
            json=execution_data
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "invalid" in data["message"].lower() or "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_execute_workflow_stage_workflow_not_found(self, api_client: AsyncClient):
        """Test workflow stage execution with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        execution_data = {
            "stage_name": "passive_recon",
            "config_overrides": {}
        }
        
        # Act
        response = await api_client.post(
            f"/api/workflows/{non_existent_id}/execute",
            json=execution_data
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_statistics_success(self, api_client: AsyncClient):
        """Test successful workflow statistics retrieval."""
        # Act
        response = await api_client.get("/api/workflows/statistics")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow statistics retrieved successfully"
        assert "data" in data
        assert "statistics" in data["data"]
        assert "total_workflows" in data["data"]["statistics"]
        assert "status_distribution" in data["data"]["statistics"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_list_running_containers_success(self, api_client: AsyncClient):
        """Test successful container listing."""
        # Mock Docker client
        with patch('core.tasks.execution_service.docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_container = MagicMock()
            mock_container.name = "test-container"
            mock_container.status = "running"
            mock_container.attrs = {"Created": "2024-01-01T00:00:00Z"}
            mock_client.containers.list.return_value = [mock_container]
            mock_docker.return_value = mock_client
            
            # Act
            response = await api_client.get("/api/execution/containers")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Running containers retrieved successfully"
            assert "data" in data
            assert "containers" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_container_status_success(self, api_client: AsyncClient):
        """Test successful container status retrieval."""
        # Mock Docker client
        with patch('core.tasks.execution_service.docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_container = MagicMock()
            mock_container.status = "running"
            mock_container.attrs = {
                "Created": "2024-01-01T00:00:00Z",
                "State": {"Status": "running", "StartedAt": "2024-01-01T00:00:00Z"}
            }
            mock_client.containers.get.return_value = mock_container
            mock_docker.return_value = mock_client
            
            # Act
            response = await api_client.get("/api/execution/containers/test-container/status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Container status retrieved successfully"
            assert "data" in data
            assert data["data"]["name"] == "test-container"
            assert data["data"]["status"] == "running"
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_container_status_not_found(self, api_client: AsyncClient):
        """Test container status retrieval with non-existent container."""
        # Mock Docker client to raise exception
        with patch('core.tasks.execution_service.docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_client.containers.get.side_effect = Exception("Container not found")
            mock_docker.return_value = mock_client
            
            # Act
            response = await api_client.get("/api/execution/containers/non-existent/status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_stop_container_success(self, api_client: AsyncClient):
        """Test successful container stop."""
        # Mock Docker client
        with patch('core.tasks.execution_service.docker.from_env') as mock_docker:
            mock_client = MagicMock()
            mock_container = MagicMock()
            mock_container.stop.return_value = None
            mock_client.containers.get.return_value = mock_container
            mock_docker.return_value = mock_client
            
            # Act
            response = await api_client.post("/api/execution/containers/test-container/stop")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Container stopped successfully"
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_stop_container_not_found(self, api_client: AsyncClient):
        """Test container stop with non-existent container."""
        # Mock Docker client to raise exception
        with patch('core.tasks.execution_service.docker.from_env') as mock_docker:
            mock_client = MagicMock()
            # Mock the correct docker.errors.NotFound exception
            from docker.errors import NotFound
            mock_client.containers.get.side_effect = NotFound("Container not found")
            mock_docker.return_value = mock_client
            
            # Act
            response = await api_client.post("/api/execution/containers/non-existent/stop")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_api_response_format_consistency(self, api_client: AsyncClient, sample_workflow):
        """Test that all API responses follow the standardized format."""
        # Test multiple endpoints to ensure consistent response format
        endpoints = [
            f"/api/workflows/{sample_workflow.id}",
            f"/api/workflows/{sample_workflow.id}/summary",
            "/api/workflows/",
            "/api/workflows/statistics"
        ]
        
        for endpoint in endpoints:
            response = await api_client.get(endpoint)
            assert response.status_code == 200
            data = response.json()
            
            # Check required fields
            assert "success" in data
            assert "message" in data
            assert isinstance(data["success"], bool)
            assert isinstance(data["message"], str)
            
            # Check optional fields
            if data["success"]:
                assert "data" in data
                assert data["errors"] is None
            else:
                assert "errors" in data
                assert data["data"] is None 