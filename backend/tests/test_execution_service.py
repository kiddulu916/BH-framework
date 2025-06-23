"""
Unit tests for the execution service.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime

from core.tasks.execution_service import ExecutionService
from core.utils.exceptions import ExecutionError, ContainerError
from core.schemas.base import APIResponse


@pytest.fixture
def mock_repositories():
    """Create mock repositories for testing."""
    return {
        'workflow_repo': AsyncMock(),
        'target_repo': AsyncMock()
    }


@pytest.fixture
def execution_service(mock_repositories):
    """Create execution service with mock repositories."""
    return ExecutionService(
        workflow_repository=mock_repositories['workflow_repo'],
        target_repository=mock_repositories['target_repo']
    )


@pytest.fixture
def sample_target():
    """Create a sample target for testing."""
    target_id = uuid4()
    return MagicMock(
        id=target_id,
        value="example.com",
        name="Test Target"
    )


@pytest.fixture
def sample_workflow():
    """Create a sample workflow for testing."""
    workflow_id = uuid4()
    target_id = uuid4()
    return MagicMock(
        id=workflow_id,
        target_id=target_id,
        stages={
            "passive_recon": "pending",
            "active_recon": "pending"
        }
    )


@pytest.fixture
def mock_docker_client():
    """Create a mock Docker client."""
    return MagicMock()


class TestExecutionService:
    """Test cases for ExecutionService."""

    @pytest.mark.asyncio
    async def test_init_docker_client_success(self, mock_repositories):
        """Test successful Docker client initialization."""
        with patch('core.tasks.execution_service.docker') as mock_docker:
            mock_docker.from_env.return_value = MagicMock()
            service = ExecutionService(
                workflow_repository=mock_repositories['workflow_repo'],
                target_repository=mock_repositories['target_repo']
            )
            assert service.docker_client is not None

    @pytest.mark.asyncio
    async def test_init_docker_client_failure(self, mock_repositories):
        """Test Docker client initialization failure."""
        with patch('core.tasks.execution_service.docker') as mock_docker:
            from docker.errors import DockerException
            mock_docker.from_env.side_effect = DockerException("Docker not available")
            service = ExecutionService(
                workflow_repository=mock_repositories['workflow_repo'],
                target_repository=mock_repositories['target_repo']
            )
            assert service.docker_client is None

    @pytest.mark.asyncio
    async def test_execute_stage_container_success(self, execution_service, mock_repositories, sample_target, sample_workflow):
        """Test successful stage container execution."""
        # Arrange
        workflow_id = sample_workflow.id
        target_id = sample_target.id
        stage_name = "passive_recon"
        execution_config = {"tools": "subfinder,amass"}
        
        mock_repositories['target_repo'].get_by_id.return_value = sample_target
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        
        # Mock Docker container
        mock_container = MagicMock()
        mock_container.wait.return_value = {'StatusCode': 0}
        mock_container.logs.return_value = b"Execution completed successfully"
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.run.return_value = mock_container
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id, execution_config
        )
        
        # Assert
        assert result.success is True
        assert "execution completed" in result.message
        execution_service.docker_client.containers.run.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_stage_container_docker_not_available(self, execution_service, mock_repositories):
        """Test stage execution when Docker client is not available."""
        # Arrange
        workflow_id = uuid4()
        target_id = uuid4()
        stage_name = "passive_recon"
        
        execution_service.docker_client = None
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id
        )
        
        # Assert
        assert result.success is False
        assert "Docker client not available" in result.message

    @pytest.mark.asyncio
    async def test_execute_stage_container_target_not_found(self, execution_service, mock_repositories):
        """Test stage execution with non-existent target."""
        # Arrange
        workflow_id = uuid4()
        target_id = uuid4()
        stage_name = "passive_recon"
        
        mock_repositories['target_repo'].get_by_id.return_value = None
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id
        )
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_execute_stage_container_workflow_not_found(self, execution_service, mock_repositories, sample_target):
        """Test stage execution with non-existent workflow."""
        # Arrange
        workflow_id = uuid4()
        target_id = sample_target.id
        stage_name = "passive_recon"
        
        mock_repositories['target_repo'].get_by_id.return_value = sample_target
        mock_repositories['workflow_repo'].get_by_id.return_value = None
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id
        )
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_execute_stage_container_invalid_stage(self, execution_service, mock_repositories, sample_target, sample_workflow):
        """Test stage execution with invalid stage name."""
        # Arrange
        workflow_id = sample_workflow.id
        target_id = sample_target.id
        stage_name = "invalid_stage"
        
        mock_repositories['target_repo'].get_by_id.return_value = sample_target
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id
        )
        
        # Assert
        assert result.success is False
        assert "Invalid stage name" in result.message

    @pytest.mark.asyncio
    async def test_execute_stage_container_docker_error(self, execution_service, mock_repositories, sample_target, sample_workflow):
        """Test stage execution with Docker error."""
        # Arrange
        workflow_id = sample_workflow.id
        target_id = sample_target.id
        stage_name = "passive_recon"
        
        mock_repositories['target_repo'].get_by_id.return_value = sample_target
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        
        # Mock Docker error
        from docker.errors import DockerException
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.run.side_effect = DockerException("Container error")
        
        # Act
        result = await execution_service.execute_stage_container(
            workflow_id, stage_name, target_id
        )
        
        # Assert
        assert result.success is False
        assert "Container execution failed" in result.message

    @pytest.mark.asyncio
    async def test_prepare_container_config(self, execution_service, sample_target):
        """Test container configuration preparation."""
        # Arrange
        stage_name = "passive_recon"
        workflow_id = uuid4()
        execution_config = {"tools": "subfinder,amass", "depth": 2}
        
        # Act
        config = execution_service._prepare_container_config(
            stage_name, sample_target, workflow_id, execution_config
        )
        
        # Assert
        assert config["image"] == f"bug-hunting-framework/{stage_name}:latest"
        assert config["environment"]["TARGET_DOMAIN"] == sample_target.value
        assert config["environment"]["TARGET_ID"] == str(sample_target.id)
        assert config["environment"]["WORKFLOW_ID"] == str(workflow_id)
        assert config["environment"]["STAGE_NAME"] == stage_name

    @pytest.mark.asyncio
    async def test_get_stage_specific_config_passive_recon(self, execution_service, sample_target):
        """Test stage-specific configuration for passive recon."""
        # Arrange
        stage_name = "passive_recon"
        execution_config = {"tools": "subfinder,amass", "depth": 2}
        
        # Act
        config = execution_service._get_stage_specific_config(stage_name, sample_target, execution_config)
        
        # Assert
        assert config["command"] == ["python", "run_passive_recon.py"]
        assert config["environment"]["RECON_TOOLS"] == "subfinder,amass"
        assert config["environment"]["RECON_DEPTH"] == "2"

    @pytest.mark.asyncio
    async def test_get_stage_specific_config_active_recon(self, execution_service, sample_target):
        """Test stage-specific configuration for active recon."""
        # Arrange
        stage_name = "active_recon"
        execution_config = {"ports": "80,443", "timeout": 30}
        
        # Act
        config = execution_service._get_stage_specific_config(stage_name, sample_target, execution_config)
        
        # Assert
        assert config["command"] == ["python", "run_active_recon.py"]
        assert config["environment"]["SCAN_PORTS"] == "80,443"
        assert config["environment"]["SCAN_TIMEOUT"] == "30"

    @pytest.mark.asyncio
    async def test_get_stage_specific_config_vulnerability_scan(self, execution_service, sample_target):
        """Test stage-specific configuration for vulnerability scan."""
        # Arrange
        stage_name = "vulnerability_scan"
        execution_config = {"templates": "cves,vulnerabilities", "severity": "high,critical"}
        
        # Act
        config = execution_service._get_stage_specific_config(stage_name, sample_target, execution_config)
        
        # Assert
        assert config["command"] == ["python", "run_vuln_scan.py"]
        assert config["environment"]["SCAN_TEMPLATES"] == "cves,vulnerabilities"
        assert config["environment"]["SCAN_SEVERITY"] == "high,critical"

    @pytest.mark.asyncio
    async def test_run_container_success(self, execution_service):
        """Test successful container execution."""
        # Arrange
        container_config = {
            "image": "test-image",
            "name": "test-container"
        }
        
        mock_container = MagicMock()
        mock_container.wait.return_value = {'StatusCode': 0}
        mock_container.logs.return_value = b"Success output"
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.run.return_value = mock_container
        
        # Act
        result = await execution_service._run_container(container_config)
        
        # Assert
        assert result["success"] is True
        assert "completed successfully" in result["message"]
        assert result["output"] == "Success output"

    @pytest.mark.asyncio
    async def test_run_container_failure(self, execution_service):
        """Test container execution failure."""
        # Arrange
        container_config = {
            "image": "test-image",
            "name": "test-container"
        }
        
        mock_container = MagicMock()
        mock_container.wait.return_value = {'StatusCode': 1}
        mock_container.logs.return_value = b"Error output"
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.run.return_value = mock_container
        
        # Act
        result = await execution_service._run_container(container_config)
        
        # Assert
        assert result["success"] is False
        assert "failed with exit code 1" in result["message"]
        assert result["error"] == "Error output"

    @pytest.mark.asyncio
    async def test_run_container_docker_exception(self, execution_service):
        """Test container execution with Docker exception."""
        # Arrange
        container_config = {
            "image": "test-image",
            "name": "test-container"
        }
        
        from docker.errors import DockerException
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.run.side_effect = DockerException("Docker error")
        
        # Act
        result = await execution_service._run_container(container_config)
        
        # Assert
        assert result["success"] is False
        assert "Container execution failed" in result["message"]

    @pytest.mark.asyncio
    async def test_update_workflow_status_success(self, execution_service, mock_repositories, sample_workflow):
        """Test successful workflow status update."""
        # Arrange
        workflow_id = sample_workflow.id
        stage_name = "passive_recon"
        execution_result = {"success": True, "message": "Success"}
        
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        
        # Act
        await execution_service._update_workflow_status(workflow_id, stage_name, execution_result)
        
        # Assert
        mock_repositories['workflow_repo'].update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_workflow_status_workflow_not_found(self, execution_service, mock_repositories):
        """Test workflow status update with non-existent workflow."""
        # Arrange
        workflow_id = uuid4()
        stage_name = "passive_recon"
        execution_result = {"success": True, "message": "Success"}
        
        mock_repositories['workflow_repo'].get_by_id.return_value = None
        
        # Act & Assert (should not raise exception)
        await execution_service._update_workflow_status(workflow_id, stage_name, execution_result)

    def test_determine_workflow_status_all_completed(self, execution_service):
        """Test workflow status determination when all stages are completed."""
        # Arrange
        stages = {
            "passive_recon": "completed",
            "active_recon": "completed",
            "vulnerability_scan": "completed"
        }
        
        # Act
        status = execution_service._determine_workflow_status(stages)
        
        # Assert
        assert status == "completed"

    def test_determine_workflow_status_with_failed(self, execution_service):
        """Test workflow status determination when some stages failed."""
        # Arrange
        stages = {
            "passive_recon": "completed",
            "active_recon": "failed",
            "vulnerability_scan": "pending"
        }
        
        # Act
        status = execution_service._determine_workflow_status(stages)
        
        # Assert
        assert status == "failed"

    def test_determine_workflow_status_with_running(self, execution_service):
        """Test workflow status determination when some stages are running."""
        # Arrange
        stages = {
            "passive_recon": "completed",
            "active_recon": "running",
            "vulnerability_scan": "pending"
        }
        
        # Act
        status = execution_service._determine_workflow_status(stages)
        
        # Assert
        assert status == "running"

    def test_determine_workflow_status_all_pending(self, execution_service):
        """Test workflow status determination when all stages are pending."""
        # Arrange
        stages = {
            "passive_recon": "pending",
            "active_recon": "pending",
            "vulnerability_scan": "pending"
        }
        
        # Act
        status = execution_service._determine_workflow_status(stages)
        
        # Assert
        assert status == "pending"

    @pytest.mark.asyncio
    async def test_get_container_status_success(self, execution_service):
        """Test successful container status retrieval."""
        # Arrange
        container_name = "test-container"
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {
            'Created': '2023-01-01T00:00:00Z',
            'State': {'Status': 'running'}
        }
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.get.return_value = mock_container
        
        # Act
        result = await execution_service.get_container_status(container_name)
        
        # Assert
        assert result.success is True
        assert result.data["container_name"] == container_name
        assert result.data["status"] == "running"

    @pytest.mark.asyncio
    async def test_get_container_status_not_found(self, execution_service):
        """Test container status retrieval with non-existent container."""
        # Arrange
        container_name = "test-container"
        
        from docker.errors import NotFound
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.get.side_effect = NotFound("Container not found")
        
        # Act
        result = await execution_service.get_container_status(container_name)
        
        # Assert
        assert result.success is False
        assert "Container not found" in result.message

    @pytest.mark.asyncio
    async def test_stop_container_success(self, execution_service):
        """Test successful container stop."""
        # Arrange
        container_name = "test-container"
        mock_container = MagicMock()
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.get.return_value = mock_container
        
        # Act
        result = await execution_service.stop_container(container_name)
        
        # Assert
        assert result.success is True
        assert "stopped successfully" in result.message
        mock_container.stop.assert_called_once_with(timeout=10)

    @pytest.mark.asyncio
    async def test_stop_container_not_found(self, execution_service):
        """Test container stop with non-existent container."""
        # Arrange
        container_name = "test-container"
        
        from docker.errors import NotFound
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.get.side_effect = NotFound("Container not found")
        
        # Act
        result = await execution_service.stop_container(container_name)
        
        # Assert
        assert result.success is False
        assert "Container not found" in result.message

    @pytest.mark.asyncio
    async def test_list_running_containers_success(self, execution_service):
        """Test successful running containers list."""
        # Arrange
        mock_container1 = MagicMock()
        mock_container1.id = "container1"
        mock_container1.name = "test-container-1"
        mock_container1.status = "running"
        mock_container1.image.tags = ["test-image:latest"]
        mock_container1.attrs = {'Created': '2023-01-01T00:00:00Z'}
        
        mock_container2 = MagicMock()
        mock_container2.id = "container2"
        mock_container2.name = "test-container-2"
        mock_container2.status = "running"
        mock_container2.image.tags = []
        mock_container2.image.id = "image2"
        mock_container2.attrs = {'Created': '2023-01-01T00:00:00Z'}
        
        execution_service.docker_client = MagicMock()
        execution_service.docker_client.containers.list.return_value = [mock_container1, mock_container2]
        
        # Act
        result = await execution_service.list_running_containers()
        
        # Assert
        assert result.success is True
        assert "retrieved successfully" in result.message
        assert len(result.data["containers"]) == 2
        assert result.data["containers"][0]["name"] == "test-container-1"
        assert result.data["containers"][1]["name"] == "test-container-2" 
