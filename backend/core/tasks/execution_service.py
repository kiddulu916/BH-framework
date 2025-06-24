"""
Execution service for managing stage container execution and monitoring.
"""

import logging
import asyncio
import subprocess
import json
from typing import Dict, Any, Optional, List
from uuid import UUID
from datetime import datetime, timezone
import docker
from docker.errors import DockerException

from core.schemas.workflow import (
    WorkflowExecutionRequest,
    WorkflowExecutionResponse,
    StageExecutionResponse,
    StageStatus,
    WorkflowStatus
)
from core.repositories.workflow import WorkflowRepository
from core.repositories.target import TargetRepository
from core.utils.exceptions import (
    ExecutionError,
    StageExecutionError,
    ContainerError
)
from core.schemas.base import APIResponse

logger = logging.getLogger(__name__)


class ExecutionService:
    """
    Service for managing stage container execution and monitoring.
    """
    
    def __init__(
        self,
        workflow_repository: WorkflowRepository,
        target_repository: TargetRepository
    ):
        self.workflow_repository = workflow_repository
        self.target_repository = target_repository
        self.docker_client = None
        self._init_docker_client()
    
    def _init_docker_client(self) -> None:
        """Initialize Docker client."""
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized successfully")
        except DockerException as e:
            logger.error(f"Failed to initialize Docker client: {str(e)}")
            self.docker_client = None
    
    async def execute_stage_container(
        self,
        workflow_id: UUID,
        stage_name: str,
        target_id: UUID,
        execution_config: Optional[Dict[str, Any]] = None
    ) -> APIResponse:
        """
        Execute a stage container for the given workflow and target.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Name of the stage to execute
            target_id: Target ID
            execution_config: Optional execution configuration
            
        Returns:
            APIResponse with execution status
        """
        try:
            # Validate inputs
            if not self.docker_client:
                raise ExecutionError("Docker client not available")
            
            # Get target information
            target = await self.target_repository.get_by_id(target_id)
            if not target:
                raise ExecutionError(f"Target with ID {target_id} not found")
            
            # Get workflow information
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                raise ExecutionError(f"Workflow with ID {workflow_id} not found")
            
            # Validate stage name
            if stage_name not in workflow.stages:
                raise ExecutionError(f"Invalid stage name: {stage_name}")
            
            # Prepare container configuration
            container_config = self._prepare_container_config(
                stage_name=stage_name,
                target=target,
                workflow_id=workflow_id,
                execution_config=execution_config or {}
            )
            
            # Execute container
            execution_result = await self._run_container(container_config)
            
            # Update workflow status
            await self._update_workflow_status(workflow_id, stage_name, execution_result)
            
            logger.info(f"Stage {stage_name} execution completed for workflow {workflow_id}")
            
            return APIResponse(
                success=execution_result["success"],
                message=execution_result["message"],
                data=StageExecutionResponse(
                    workflow_id=workflow_id,
                    stage_name=stage_name,
                    status=StageStatus.COMPLETED if execution_result["success"] else StageStatus.FAILED,
                    message=execution_result["message"],
                    output=execution_result.get("output"),
                    error=execution_result.get("error")
                ).model_dump()
            )
            
        except ExecutionError as e:
            logger.error(f"Execution error for stage {stage_name}: {str(e)}")
            return APIResponse(success=False, message=str(e), errors=[str(e)])
        except Exception as e:
            logger.error(f"Unexpected error during stage execution: {str(e)}")
            return APIResponse(success=False, message="Stage execution failed", errors=[str(e)])
    
    def _prepare_container_config(
        self,
        stage_name: str,
        target,
        workflow_id: UUID,
        execution_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Prepare container configuration for stage execution.
        
        Args:
            stage_name: Name of the stage
            target: Target object
            workflow_id: Workflow ID
            execution_config: Execution configuration
            
        Returns:
            Container configuration dictionary
        """
        # Base container configuration
        container_config = {
            "image": f"bug-hunting-framework/{stage_name}:latest",
            "name": f"{stage_name}_{workflow_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            "environment": {
                "TARGET_DOMAIN": target.value,
                "TARGET_ID": str(target.id),
                "WORKFLOW_ID": str(workflow_id),
                "BACKEND_API_URL": "http://backend:8000",
                "OUTPUT_DIR": f"/outputs/{target.value}/{stage_name}",
                "STAGE_NAME": stage_name
            },
            "volumes": {
                f"./outputs/{target.value}/{stage_name}": {
                    "bind": f"/outputs/{target.value}/{stage_name}",
                    "mode": "rw"
                }
            },
            "network": "bug-hunting-framework_default",
            "detach": True,
            "remove": True
        }
        
        # Add stage-specific configuration
        stage_config = self._get_stage_specific_config(stage_name, target, execution_config)
        
        # Merge environment variables properly
        if "environment" in stage_config:
            container_config["environment"].update(stage_config["environment"])
        
        # Add other stage-specific config (command, etc.)
        for key, value in stage_config.items():
            if key != "environment":
                container_config[key] = value
        
        return container_config
    
    def _get_stage_specific_config(
        self,
        stage_name: str,
        target,
        execution_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Get stage-specific container configuration.
        
        Args:
            stage_name: Name of the stage
            target: Target object
            execution_config: Execution configuration
            
        Returns:
            Stage-specific configuration
        """
        base_config = {}
        
        if stage_name == "passive_recon":
            base_config.update({
                "command": ["python", "run_passive_recon.py"],
                "environment": {
                    "RECON_TOOLS": execution_config.get("tools", "subfinder,amass,assetfinder"),
                    "RECON_DEPTH": str(execution_config.get("depth", 2))
                }
            })
        
        elif stage_name == "active_recon":
            base_config.update({
                "command": ["python", "run_active_recon.py"],
                "environment": {
                    "SCAN_PORTS": execution_config.get("ports", "80,443,8080,8443"),
                    "SCAN_TIMEOUT": str(execution_config.get("timeout", 30))
                }
            })
        
        elif stage_name == "vulnerability_scan":
            base_config.update({
                "command": ["python", "run_vuln_scan.py"],
                "environment": {
                    "SCAN_TEMPLATES": execution_config.get("templates", "cves,vulnerabilities"),
                    "SCAN_SEVERITY": execution_config.get("severity", "low,medium,high,critical")
                }
            })
        
        elif stage_name == "vulnerability_test":
            base_config.update({
                "command": ["python", "run_vuln_test.py"],
                "environment": {
                    "TEST_MODE": execution_config.get("mode", "safe"),
                    "TEST_TIMEOUT": str(execution_config.get("timeout", 60))
                }
            })
        
        elif stage_name == "kill_chain_analysis":
            base_config.update({
                "command": ["python", "analyze_kill_chain.py"],
                "environment": {
                    "ANALYSIS_DEPTH": str(execution_config.get("depth", 3)),
                    "ANALYSIS_MODE": execution_config.get("mode", "automated")
                }
            })
        
        elif stage_name == "report_generation":
            base_config.update({
                "command": ["python", "generate_report.py"],
                "environment": {
                    "REPORT_FORMAT": execution_config.get("format", "markdown"),
                    "REPORT_TEMPLATE": execution_config.get("template", "default")
                }
            })
        
        return base_config
    
    async def _run_container(self, container_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run Docker container with the given configuration.
        
        Args:
            container_config: Container configuration
            
        Returns:
            Execution result dictionary
        """
        try:
            # Create and start container
            container = self.docker_client.containers.run(**container_config)
            
            logger.info(f"Started container {container.id} for {container_config['name']}")
            
            # Monitor container execution
            result = await self._monitor_container(container)
            
            return result
            
        except DockerException as e:
            logger.error(f"Docker error: {str(e)}")
            return {
                "success": False,
                "message": "Container execution failed",
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"Container execution error: {str(e)}")
            return {
                "success": False,
                "message": "Container execution failed",
                "error": str(e)
            }
    
    async def _monitor_container(self, container) -> Dict[str, Any]:
        """
        Monitor container execution and collect results.
        
        Args:
            container: Docker container object
            
        Returns:
            Execution result dictionary
        """
        try:
            # Wait for container to complete
            result = container.wait()
            
            # Get container logs
            logs = container.logs().decode('utf-8')
            
            # Check exit code
            if result['StatusCode'] == 0:
                return {
                    "success": True,
                    "message": "Stage execution completed successfully",
                    "output": logs,
                    "exit_code": result['StatusCode']
                }
            else:
                return {
                    "success": False,
                    "message": f"Stage execution failed with exit code {result['StatusCode']}",
                    "error": logs,
                    "exit_code": result['StatusCode']
                }
                
        except Exception as e:
            logger.error(f"Error monitoring container: {str(e)}")
            return {
                "success": False,
                "message": "Container monitoring failed",
                "error": str(e)
            }
    
    async def _update_workflow_status(
        self,
        workflow_id: UUID,
        stage_name: str,
        execution_result: Dict[str, Any]
    ) -> None:
        """
        Update workflow status based on execution result.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name
            execution_result: Execution result
        """
        try:
            # Get current workflow
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return
            
            # Update stage status
            new_stage_status = StageStatus.COMPLETED if execution_result["success"] else StageStatus.FAILED
            updated_stages = {**workflow.stages, stage_name: new_stage_status}
            
            # Update workflow status
            new_workflow_status = self._determine_workflow_status(updated_stages)
            
            await self.workflow_repository.update(workflow_id, **{
                "stages": updated_stages,
                "status": new_workflow_status,
                "updated_at": datetime.now(timezone.utc)
            })
            
            logger.info(f"Updated workflow {workflow_id} status: {new_workflow_status}")
            
        except Exception as e:
            logger.error(f"Error updating workflow status: {str(e)}")
    
    def _determine_workflow_status(self, stages: Dict[str, StageStatus]) -> WorkflowStatus:
        """
        Determine overall workflow status based on stage statuses.
        
        Args:
            stages: Dictionary of stage statuses
            
        Returns:
            Overall workflow status
        """
        if any(status == StageStatus.FAILED for status in stages.values()):
            return WorkflowStatus.FAILED
        elif all(status == StageStatus.COMPLETED for status in stages.values()):
            return WorkflowStatus.COMPLETED
        elif any(status == StageStatus.RUNNING for status in stages.values()):
            return WorkflowStatus.RUNNING
        else:
            return WorkflowStatus.PENDING
    
    async def get_container_status(self, container_name: str) -> APIResponse:
        """
        Get status of a running container.
        
        Args:
            container_name: Name of the container
            
        Returns:
            APIResponse with container status
        """
        try:
            if not self.docker_client:
                raise ExecutionError("Docker client not available")
            
            container = self.docker_client.containers.get(container_name)
            status = container.status
            
            return APIResponse(
                success=True,
                message="Container status retrieved successfully",
                data={
                    "container_name": container_name,
                    "status": status,
                    "created": container.attrs['Created'],
                    "state": container.attrs['State']
                }
            )
            
        except docker.errors.NotFound:
            return APIResponse(success=False, message="Container not found", errors=["Container not found"])
        except Exception as e:
            logger.error(f"Error getting container status: {str(e)}")
            return APIResponse(success=False, message="Failed to get container status", errors=[str(e)])
    
    async def stop_container(self, container_name: str) -> APIResponse:
        """
        Stop a running container.
        
        Args:
            container_name: Name of the container
            
        Returns:
            APIResponse with stop confirmation
        """
        try:
            if not self.docker_client:
                raise ExecutionError("Docker client not available")
            
            container = self.docker_client.containers.get(container_name)
            container.stop(timeout=10)
            
            logger.info(f"Stopped container {container_name}")
            
            return APIResponse(
                success=True,
                message="Container stopped successfully"
            )
            
        except docker.errors.NotFound:
            return APIResponse(success=False, message="Container not found", errors=["Container not found"])
        except Exception as e:
            logger.error(f"Error stopping container: {str(e)}")
            return APIResponse(success=False, message="Failed to stop container", errors=[str(e)])
    
    async def list_running_containers(self) -> APIResponse:
        """
        List all running stage containers.
        
        Returns:
            APIResponse with list of running containers
        """
        try:
            if not self.docker_client:
                raise ExecutionError("Docker client not available")
            
            containers = self.docker_client.containers.list(
                filters={"label": "com.docker.compose.project=bug-hunting-framework"}
            )
            
            container_list = []
            for container in containers:
                container_list.append({
                    "id": container.id,
                    "name": container.name,
                    "status": container.status,
                    "image": container.image.tags[0] if container.image.tags else container.image.id,
                    "created": container.attrs['Created']
                })
            
            return APIResponse(
                success=True,
                message="Running containers retrieved successfully",
                data={"containers": container_list}
            )
            
        except Exception as e:
            logger.error(f"Error listing containers: {str(e)}")
            return APIResponse(success=False, message="Failed to list containers", errors=[str(e)])
    
    async def get_workflow_status(self, workflow_id: UUID) -> APIResponse:
        """
        Get the current status of a workflow execution.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            APIResponse with workflow status
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return APIResponse(success=False, message="Workflow not found", errors=["Workflow not found"])
            
            return APIResponse(
                success=True,
                message="Workflow status retrieved successfully",
                data={
                    "workflow_id": str(workflow_id),
                    "status": workflow.status.value,
                    "stages": workflow.stages,
                    "created_at": workflow.created_at.isoformat(),
                    "updated_at": workflow.updated_at.isoformat(),
                    "target_id": str(workflow.target_id)
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting workflow status: {str(e)}")
            return APIResponse(success=False, message="Failed to get workflow status", errors=[str(e)])
    
    async def get_stage_status(self, workflow_id: UUID, stage_name: str) -> APIResponse:
        """
        Get the current status of a specific stage execution.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name
            
        Returns:
            APIResponse with stage status
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return APIResponse(success=False, message="Workflow not found", errors=["Workflow not found"])
            
            # Ensure stages is a dictionary
            if not isinstance(workflow.stages, dict):
                return APIResponse(success=False, message="Invalid workflow stages format", errors=["Stages must be a dictionary"])
            
            if stage_name not in workflow.stages:
                return APIResponse(success=False, message="Stage not found", errors=["Stage not found"])
            
            stage_status = workflow.stages[stage_name]
            
            return APIResponse(
                success=True,
                message="Stage status retrieved successfully",
                data={
                    "workflow_id": str(workflow_id),
                    "stage_name": stage_name,
                    "status": stage_status.value if hasattr(stage_status, 'value') else str(stage_status),
                    "workflow_status": workflow.status.value
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting stage status: {str(e)}")
            return APIResponse(success=False, message="Failed to get stage status", errors=[str(e)])
    
    async def cancel_stage_execution(self, workflow_id: UUID, stage_name: str) -> APIResponse:
        """
        Cancel a running stage execution.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name
            
        Returns:
            APIResponse with cancellation status
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return APIResponse(success=False, message="Workflow not found", errors=["Workflow not found"])
            
            # Ensure stages is a dictionary
            if not isinstance(workflow.stages, dict):
                return APIResponse(success=False, message="Invalid workflow stages format", errors=["Stages must be a dictionary"])
            
            if stage_name not in workflow.stages:
                return APIResponse(success=False, message="Stage not found", errors=["Stage not found"])
            
            # Check if stage is running
            stage_status = workflow.stages[stage_name]
            if stage_status != StageStatus.RUNNING:
                return APIResponse(success=False, message="Stage is not running", errors=["Stage is not running"])
            
            # Try to stop the container
            container_name = f"{stage_name}_{workflow_id}"
            try:
                if self.docker_client:
                    container = self.docker_client.containers.get(container_name)
                    container.stop(timeout=10)
                    logger.info(f"Stopped container {container_name}")
            except docker.errors.NotFound:
                logger.warning(f"Container {container_name} not found")
            except Exception as e:
                logger.warning(f"Error stopping container {container_name}: {str(e)}")
            
            # Update workflow status
            updated_stages = {**workflow.stages, stage_name: StageStatus.FAILED}
            new_workflow_status = self._determine_workflow_status(updated_stages)
            
            await self.workflow_repository.update(workflow_id, **{
                "stages": updated_stages,
                "status": new_workflow_status,
                "updated_at": datetime.now(timezone.utc)
            })
            
            logger.info(f"Cancelled stage {stage_name} for workflow {workflow_id}")
            
            return APIResponse(
                success=True,
                message=f"Stage {stage_name} execution cancelled successfully"
            )
            
        except Exception as e:
            logger.error(f"Error cancelling stage execution: {str(e)}")
            return APIResponse(success=False, message="Failed to cancel stage execution", errors=[str(e)])
    
    async def get_stage_logs(self, workflow_id: UUID, stage_name: str) -> APIResponse:
        """
        Get execution logs for a specific stage.
        
        Args:
            workflow_id: Workflow ID
            stage_name: Stage name
            
        Returns:
            APIResponse with stage logs
        """
        try:
            workflow = await self.workflow_repository.get_by_id(workflow_id)
            if not workflow:
                return APIResponse(success=False, message="Workflow not found", errors=["Workflow not found"])
            
            # Ensure stages is a dictionary
            if not isinstance(workflow.stages, dict):
                return APIResponse(success=False, message="Invalid workflow stages format", errors=["Stages must be a dictionary"])
            
            if stage_name not in workflow.stages:
                return APIResponse(success=False, message="Stage not found", errors=["Stage not found"])
            
            # Try to get container logs
            container_name = f"{stage_name}_{workflow_id}"
            logs = ""
            
            try:
                if self.docker_client:
                    container = self.docker_client.containers.get(container_name)
                    logs = container.logs().decode('utf-8')
            except docker.errors.NotFound:
                logs = "Container not found or already removed"
            except Exception as e:
                logs = f"Error retrieving logs: {str(e)}"
            
            stage_status = workflow.stages[stage_name]
            return APIResponse(
                success=True,
                message="Stage logs retrieved successfully",
                data={
                    "workflow_id": str(workflow_id),
                    "stage_name": stage_name,
                    "logs": logs,
                    "stage_status": stage_status.value if hasattr(stage_status, 'value') else str(stage_status)
                }
            )
            
        except Exception as e:
            logger.error(f"Error getting stage logs: {str(e)}")
            return APIResponse(success=False, message="Failed to get stage logs", errors=[str(e)])
    
    async def get_container_logs(self, container_name: str) -> APIResponse:
        """
        Get logs from a container.
        
        Args:
            container_name: Name of the container
            
        Returns:
            APIResponse with container logs
        """
        try:
            if not self.docker_client:
                raise ExecutionError("Docker client not available")
            
            container = self.docker_client.containers.get(container_name)
            logs = container.logs().decode('utf-8')
            
            return APIResponse(
                success=True,
                message="Container logs retrieved successfully",
                data={
                    "container_name": container_name,
                    "logs": logs,
                    "status": container.status
                }
            )
            
        except docker.errors.NotFound:
            return APIResponse(success=False, message="Container not found", errors=["Container not found"])
        except Exception as e:
            logger.error(f"Error getting container logs: {str(e)}")
            return APIResponse(success=False, message="Failed to get container logs", errors=[str(e)]) 
