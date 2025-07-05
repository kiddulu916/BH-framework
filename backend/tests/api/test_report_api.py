"""
Tests for report API endpoints.

This module contains tests for all report management API endpoints,
including report creation, generation, export, and template management.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from core.models.target import Target, TargetScope, TargetStatus
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.models.report import Report, ReportStatus, ReportFormat
from core.schemas.report import ReportCreateRequest, ReportUpdateRequest, ReportExportRequest
from core.schemas.base import APIResponse


class TestReportAPI:
    """Test suite for report API endpoints."""
    
    @pytest.mark.asyncio
    async def test_create_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report creation."""
        # Arrange
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report for bug hunting results",
            "template": "default",
            "format": "pdf",
            "include_passive_recon": True,
            "include_active_recon": True,
            "include_vulnerabilities": True,
            "include_kill_chain": True,
            "include_screenshots": True,
            "include_raw_data": False
        }
        
        # Act
        response = await api_client.post("/api/reports/", json=report_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report created successfully"
        assert data["data"]["title"] == report_data["title"]
        assert data["data"]["execution_id"] == str(sample_workflow.id)
        assert data["data"]["status"] == "generating"
        assert "id" in data["data"]
        assert "created_at" in data["data"]
        assert "updated_at" in data["data"]
    
    @pytest.mark.asyncio
    async def test_create_report_validation_error(self, api_client: AsyncClient):
        """Test report creation with validation errors."""
        # Arrange
        invalid_data = {
            "workflow_id": "invalid-uuid",
            "name": "",  # Empty name
            "description": "A" * 1001,  # Too long description
            "format": "INVALID_FORMAT"  # Invalid format
        }
        
        # Act
        response = await api_client.post("/api/reports/", json=invalid_data)
        
        # Assert
        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data
    
    @pytest.mark.asyncio
    async def test_create_report_workflow_not_found(self, api_client: AsyncClient):
        """Test report creation with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        report_data = {
            "workflow_id": str(non_existent_id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        
        # Act
        response = await api_client.post("/api/reports/", json=report_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report retrieval."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        
        # Act
        response = await api_client.get(f"/api/reports/{created_report['id']}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report retrieved successfully"
        assert data["data"]["id"] == created_report["id"]
        assert data["data"]["title"] == report_data["title"]
        assert data["data"]["execution_id"] == str(sample_workflow.id)
    
    @pytest.mark.asyncio
    async def test_get_report_not_found(self, api_client: AsyncClient):
        """Test report retrieval with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/reports/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_list_reports_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report listing."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        await api_client.post("/api/reports/", json=report_data)
        
        # Act
        response = await api_client.get("/api/reports/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Reports retrieved successfully"
        assert "data" in data
        assert "reports" in data["data"]
        assert "pagination" in data["data"]
    
    @pytest.mark.asyncio
    async def test_list_reports_with_filtering(self, api_client: AsyncClient, sample_workflow):
        """Test report listing with workflow and status filter."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        status = created_report["status"]

        # Act
        response = await api_client.get(f"/api/reports/?workflow_id={sample_workflow.id}&status={status}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "reports" in data["data"]
    
    @pytest.mark.asyncio
    async def test_list_reports_with_pagination(self, api_client: AsyncClient):
        """Test report listing with pagination."""
        # Act
        response = await api_client.get("/api/reports/?limit=5&offset=0")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "pagination" in data["data"]
        assert data["data"]["pagination"]["per_page"] == 5
        assert data["data"]["pagination"]["page"] == 1
    
    @pytest.mark.asyncio
    async def test_update_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report update."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        
        # Arrange
        update_data = {
            "title": "Updated Report Name",
            "description": "Updated report description",
            "settings": {
                "include_executive_summary": False,
                "include_technical_details": True,
                "include_recommendations": True
            }
        }
        
        # Act
        response = await api_client.put(f"/api/reports/{created_report['id']}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report updated successfully"
        assert data["data"]["title"] == update_data["title"]
        assert data["data"]["description"] == update_data["description"]
        assert data["data"]["id"] == created_report["id"]
    
    @pytest.mark.asyncio
    async def test_update_report_not_found(self, api_client: AsyncClient):
        """Test report update with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        update_data = {"name": "Updated Name"}
        
        # Act
        response = await api_client.put(f"/api/reports/{non_existent_id}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_delete_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report deletion."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        
        # Act
        response = await api_client.delete(f"/api/reports/{created_report['id']}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report deleted successfully"
    
    @pytest.mark.asyncio
    async def test_delete_report_not_found(self, api_client: AsyncClient):
        """Test report deletion with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.delete(f"/api/reports/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_generate_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report generation."""
        # Act
        response = await api_client.post(f"/api/reports/generate/{sample_workflow.id}?template=default")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report generation started successfully"
        assert "data" in data
        assert "report_id" in data["data"]
        assert "status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_generate_report_workflow_not_found(self, api_client: AsyncClient):
        """Test report generation with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.post(f"/api/reports/generate/{non_existent_id}?template=default")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_export_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful report export."""
        # First create a report
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        
        # Arrange
        export_data = {
            "format": "pdf",
            "include_attachments": True,
            "compression": False
        }
        
        # Act
        response = await api_client.post(f"/api/reports/{created_report['id']}/export", json=export_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report export started successfully"
        assert "data" in data
        assert "export_id" in data["data"]
        assert "status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_export_report_not_found(self, api_client: AsyncClient):
        """Test report export with non-existent report."""
        # Arrange
        non_existent_id = uuid4()
        export_data = {"format": "pdf"}
        
        # Act
        response = await api_client.post(f"/api/reports/{non_existent_id}/export", json=export_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_report_templates_success(self, api_client: AsyncClient):
        """Test successful report templates retrieval."""
        # Act
        response = await api_client.get("/api/reports/templates")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Report templates retrieved successfully"
        assert "data" in data
        assert "templates" in data["data"]
        assert len(data["data"]["templates"]) > 0
        
        # Check template structure
        template = data["data"]["templates"][0]
        assert "name" in template
        assert "description" in template
        assert "version" in template
    
    @pytest.mark.asyncio
    async def test_get_workflow_reports_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow reports retrieval."""
        # First create a report for the workflow
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        await api_client.post("/api/reports/", json=report_data)
        
        # Act
        response = await api_client.get(f"/api/reports/workflows/{sample_workflow.id}/reports")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow reports retrieved successfully"
        assert "data" in data
        assert "reports" in data["data"]
        assert "pagination" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_workflow_reports_not_found(self, api_client: AsyncClient):
        """Test workflow reports retrieval with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/reports/workflows/{non_existent_id}/reports")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_generate_workflow_report_success(self, api_client: AsyncClient, sample_workflow):
        """Test successful workflow report generation."""
        # Act
        response = await api_client.post(f"/api/reports/workflows/{sample_workflow.id}/reports/generate?template=default")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Workflow report generation started successfully"
        assert "data" in data
        assert "report_id" in data["data"]
        assert "status" in data["data"]
    
    @pytest.mark.asyncio
    async def test_generate_workflow_report_workflow_not_found(self, api_client: AsyncClient):
        """Test workflow report generation with non-existent workflow."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.post(f"/api/reports/workflows/{non_existent_id}/reports/generate?template=default")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_api_response_format_consistency(self, api_client: AsyncClient, sample_workflow):
        """Test that all API responses follow the standardized format."""
        # First create a report for testing
        report_data = {
            "workflow_id": str(sample_workflow.id),
            "title": "Test Report",
            "description": "Test report",
            "template": "default",
            "format": "pdf"
        }
        create_response = await api_client.post("/api/reports/", json=report_data)
        created_report = create_response.json()["data"]
        
        # Test multiple endpoints to ensure consistent response format
        endpoints = [
            f"/api/reports/{created_report['id']}",
            "/api/reports/",
            "/api/reports/templates",
            f"/api/reports/workflows/{sample_workflow.id}/reports"
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