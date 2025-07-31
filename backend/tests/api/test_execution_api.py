"""
Tests for execution API endpoints.

This module contains tests for all execution management API endpoints,
including workflow execution, container management, and status monitoring.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock
from ninja.responses import Response
from datetime import datetime, timezone
import pytest_asyncio
from tests.conftest import override_test_settings

from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.schemas.workflow import WorkflowExecutionRequest, StageStatus
from core.schemas.base import APIResponse
from core.tasks.execution_service import ExecutionService
from core.tasks.workflow_service import WorkflowService
from core.utils.database import get_db_session

from core.models.target import TargetScope


@pytest.fixture(autouse=True)
def mock_docker_client():
    with patch("core.tasks.execution_service.docker.from_env") as mock_from_env:
        # Create a mock Docker client
        mock_client = MagicMock()
        mock_from_env.return_value = mock_client

        # Mock containers.get
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {
            "Created": "2024-01-01T00:00:00Z",
            "State": {"Status": "running"}
        }
        mock_container.logs.return_value = b"container logs"
        mock_client.containers.get.return_value = mock_container

        # Mock containers.list
        mock_client.containers.list.return_value = [mock_container]

        yield  # This will apply the mock for the duration of the test


@pytest_asyncio.fixture
async def sample_workflow(create_tables_once):
    """Create a real workflow and target in the database for testing."""
    from core.models import User, Target, Workflow
    from core.models.target import TargetScope, TargetStatus
    from core.models.workflow import WorkflowStatus
    from core.utils.database import db_manager
    
    async with db_manager.session_factory() as session:
        # Create a test user
        user = User(
            name="Test User",
            email="test@example.com",
            platform="hackerone"
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        
        # Create a test target
        target = Target(
            name="example.com",
            value="example.com",
            scope=TargetScope.DOMAIN,
            status=TargetStatus.ACTIVE,
            user_id=user.id
        )
        session.add(target)
        await session.commit()
        await session.refresh(target)
        
        # Create a test workflow
        workflow = Workflow(
            name="Test Workflow",
            description="A test workflow",
            stages={
                "passive_recon": "PENDING",
                "active_recon": "PENDING",
                "vuln_scan": "PENDING",
                "vuln_test": "PENDING",
                "kill_chain": "PENDING",
                "report": "PENDING"
            },
            status=WorkflowStatus.PENDING,
            target_id=target.id,
            user_id=user.id
        )
        session.add(workflow)
        await session.commit()
        await session.refresh(workflow)
        
        return workflow


class TestExecutionAPI:
    """Test suite for execution API endpoints."""
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_execute_workflow_stage_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow stage execution."""
        # Arrange
        execution_data = {
            "workflow_id": str(sample_workflow.id),
            "stage_name": "passive_recon",
            "config_overrides": {
                "tools": "subfinder,amass",
                "depth": 2
            }
        }
        
        # Mock the workflow service and execution service
        with patch('core.tasks.workflow_service.WorkflowService.execute_stage') as mock_workflow_execute, \
             patch('core.tasks.execution_service.ExecutionService.execute_stage_container') as mock_execute:
            
            # Mock workflow service to return success
            mock_workflow_execute.return_value = APIResponse(
                success=True,
                message="Stage execution started",
                data={
                    "workflow_id": str(sample_workflow.id),
                    "stage_name": "passive_recon",
                    "status": "running",
                    "message": "Stage execution started"
                },
                errors=None
            )
            
            # Mock execution service to return success
            mock_execute.return_value = APIResponse(
                success=True,
                message="Stage execution completed",
                data={
                    "workflow_id": str(sample_workflow.id),
                    "stage_name": "passive_recon",
                    "status": "completed",
                    "message": "Stage execution completed",
                    "output": "Execution output",
                    "error": None
                },
                errors=None
            )
            
            # Act
            response = await api_client.post(
                f"/api/execution/workflows/{sample_workflow.id}/execute",
                json=execution_data
            )
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            print('DEBUG test_execute_workflow_stage_success:', data)
            assert data["success"] is True
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_execute_workflow_stage_invalid_stage(self, api_client: AsyncClient, sample_workflow):
        """Test workflow stage execution with invalid stage name."""
        # Arrange
        execution_data = {
            "workflow_id": str(sample_workflow.id),
            "stage_name": "invalid_stage",
            "config_overrides": {}
        }
        
        # Act
        response = await api_client.post(
            f"/api/execution/workflows/{sample_workflow.id}/execute",
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
            "workflow_id": str(non_existent_id),
            "stage_name": "passive_recon",
            "config_overrides": {}
        }
        
        # Act
        response = await api_client.post(
            f"/api/execution/workflows/{non_existent_id}/execute",
            json=execution_data
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_status_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow status retrieval."""
        # Act
        response = await api_client.get(f"/api/execution/workflows/{sample_workflow.id}/status")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow status retrieved successfully"
        assert data["data"]["workflow_id"] == str(sample_workflow.id)
        assert "status" in data["data"]
        assert "stages" in data["data"]
        assert "created_at" in data["data"]
        assert "updated_at" in data["data"]
    
    @pytest.mark.asyncio
    @pytest.mark.django_db
    async def test_get_workflow_status_not_found(self, api_client: AsyncClient):
        """Test workflow status retrieval with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/execution/workflows/{non_existent_id}/status")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_stage_status_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful stage status retrieval."""
        # Act
        response = await api_client.get(
            f"/api/execution/workflows/{sample_workflow.id}/stages/passive_recon/status"
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Stage status retrieved successfully"
        assert data["data"]["workflow_id"] == str(sample_workflow.id)
        assert data["data"]["stage_name"] == "passive_recon"
        assert "status" in data["data"]
        assert "workflow_status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_stage_status_stage_not_found(self, api_client: AsyncClient, sample_workflow):
        """Test stage status retrieval with non-existent stage."""
        # Act
        response = await api_client.get(
            f"/api/execution/workflows/{sample_workflow.id}/stages/invalid_stage/status"
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_cancel_stage_execution_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful stage execution cancellation."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.cancel_stage_execution') as mock_cancel:
            mock_cancel.return_value = APIResponse(
                success=True,
                message="Stage execution cancelled successfully"
            )
            
            # Act
            response = await api_client.post(
                f"/api/execution/workflows/{sample_workflow.id}/stages/passive_recon/cancel"
            )
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "cancelled" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_cancel_stage_execution_not_running(self, api_client: AsyncClient, sample_workflow):
        """Test stage execution cancellation when stage is not running."""
        # Act
        response = await api_client.post(
            f"/api/execution/workflows/{sample_workflow.id}/stages/passive_recon/cancel"
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        # Should either succeed or fail with appropriate message
        assert "success" in data
        if not data["success"]:
            assert "not running" in data["message"].lower() or "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_stage_logs_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful stage logs retrieval."""
        # Act
        response = await api_client.get(
            f"/api/execution/workflows/{sample_workflow.id}/stages/passive_recon/logs"
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Stage logs retrieved successfully"
        assert data["data"]["workflow_id"] == str(sample_workflow.id)
        assert data["data"]["stage_name"] == "passive_recon"
        assert "logs" in data["data"]
        assert "stage_status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_stage_logs_stage_not_found(self, api_client: AsyncClient, sample_workflow):
        """Test stage logs retrieval with non-existent stage."""
        # Act
        response = await api_client.get(
            f"/api/execution/workflows/{sample_workflow.id}/stages/invalid_stage/logs"
        )
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_list_running_containers_success(self, api_client: AsyncClient):
        """Test successful container listing."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.list_running_containers') as mock_list:
            mock_list.return_value = APIResponse(
                success=True,
                message="Running containers retrieved successfully",
                data={
                    "containers": [
                        {
                            "id": "container1",
                            "name": "passive_recon_123",
                            "status": "running",
                            "image": "bug-hunting-framework/passive_recon:latest",
                            "created": "2024-01-01T00:00:00Z"
                        }
                    ]
                }
            )
            
            # Act
            response = await api_client.get("/api/execution/containers")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Running containers retrieved successfully"
            assert "containers" in data["data"]
            assert len(data["data"]["containers"]) >= 0
    
    @pytest.mark.asyncio
    async def test_get_container_status_success(self, api_client: AsyncClient):
        """Test successful container status retrieval."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.get_container_status') as mock_status:
            mock_status.return_value = APIResponse(
                success=True,
                message="Container status retrieved successfully",
                data={
                    "container_name": "test_container",
                    "status": "running",
                    "created": "2024-01-01T00:00:00Z",
                    "state": {"Status": "running"}
                }
            )
            
            # Act
            response = await api_client.get("/api/execution/containers/test_container/status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Container status retrieved successfully"
            assert data["data"]["container_name"] == "test_container"
            assert data["data"]["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_get_container_status_not_found(self, api_client: AsyncClient):
        """Test container status retrieval with non-existent container."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.get_container_status') as mock_status:
            mock_status.return_value = APIResponse(
                success=False,
                message="Container not found",
                errors=["Container not found"]
            )
            
            # Act
            response = await api_client.get("/api/execution/containers/non_existent/status")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_stop_container_success(self, api_client: AsyncClient):
        """Test successful container stopping."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.stop_container') as mock_stop:
            mock_stop.return_value = APIResponse(
                success=True,
                message="Container stopped successfully"
            )
            
            # Act
            response = await api_client.post("/api/execution/containers/test_container/stop")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "stopped" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_stop_container_not_found(self, api_client: AsyncClient):
        """Test container stopping with non-existent container."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.stop_container') as mock_stop:
            mock_stop.return_value = APIResponse(
                success=False,
                message="Container not found",
                errors=["Container not found"]
            )
            
            # Act
            response = await api_client.post("/api/execution/containers/non_existent/stop")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_container_logs_success(self, api_client: AsyncClient):
        """Test successful container logs retrieval."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.get_container_logs') as mock_logs:
            mock_logs.return_value = APIResponse(
                success=True,
                message="Container logs retrieved successfully",
                data={
                    "container_name": "test_container",
                    "logs": "Container execution logs...",
                    "status": "running"
                }
            )
            
            # Act
            response = await api_client.get("/api/execution/containers/test_container/logs")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert data["message"] == "Container logs retrieved successfully"
            assert data["data"]["container_name"] == "test_container"
            assert "logs" in data["data"]
            assert "status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_container_logs_not_found(self, api_client: AsyncClient):
        """Test container logs retrieval with non-existent container."""
        # Mock the execution service
        with patch('core.tasks.execution_service.ExecutionService.get_container_logs') as mock_logs:
            mock_logs.return_value = APIResponse(
                success=False,
                message="Container not found",
                errors=["Container not found"]
            )
            
            # Act
            response = await api_client.get("/api/execution/containers/non_existent/logs")
            
            # Assert
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is False
            assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_api_response_format_consistency(self, api_client: AsyncClient):
        """Test that all API responses follow the standardized format."""
        # Test health endpoint
        response = await api_client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "message" in data
        assert "data" in data
        assert "errors" in data
        
        # Test API info endpoint
        response = await api_client.get("/api/info")
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "message" in data
        assert "data" in data
        assert "errors" in data 