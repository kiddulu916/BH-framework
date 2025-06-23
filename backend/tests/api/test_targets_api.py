"""
Tests for target API endpoints.

This module contains tests for all target management API endpoints,
including CRUD operations, validation, and error handling.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient

from core.models.target import Target, TargetScope, TargetStatus
from core.schemas.target import TargetCreateRequest, TargetUpdateRequest


class TestTargetsAPI:
    """Test suite for target API endpoints."""
    
    @pytest.mark.asyncio
    async def test_create_target_success(self, api_client: AsyncClient, sample_target_data):
        """Test successful target creation."""
        # Arrange
        target_data = {
            "name": "Test Target",
            "value": "test.example.com",
            "scope": "domain",
            "scope_config": {"subdomains": ["*.test.example.com"]}
        }
        
        # Act
        response = await api_client.post("/api/targets/", json=target_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target created successfully"
        assert data["data"]["name"] == target_data["name"]
        assert data["data"]["value"] == target_data["value"]
        assert data["data"]["scope"] == target_data["scope"]
        assert "id" in data["data"]
        assert "created_at" in data["data"]
        assert "updated_at" in data["data"]
    
    @pytest.mark.asyncio
    async def test_create_target_validation_error(self, api_client: AsyncClient):
        """Test target creation with validation errors."""
        # Arrange
        invalid_target_data = {
            "value": "",  # Empty value
            "scope_config": ["invalid-ip"],  # Invalid IP
            "scope": "invalid-scope",
            "name": "A" * 1001  # Too long name
        }
        
        # Act
        response = await api_client.post("/api/targets/", json=invalid_target_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is False
        assert "validation" in data["message"].lower()
        assert len(data["errors"]) > 0
    
    @pytest.mark.asyncio
    async def test_get_target_success(self, api_client: AsyncClient, sample_target):
        """Test successful target retrieval."""
        # Act
        response = await api_client.get(f"/api/targets/{sample_target.id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target retrieved successfully"
        assert data["data"]["id"] == str(sample_target.id)
        assert data["data"]["value"] == sample_target.value
        assert data["data"]["scope_config"] == sample_target.scope_config
        assert data["data"]["scope"] == sample_target.scope
        assert data["data"]["name"] == sample_target.name
    
    @pytest.mark.asyncio
    async def test_get_target_not_found(self, api_client: AsyncClient):
        """Test target retrieval with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/targets/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_update_target_success(self, api_client: AsyncClient, sample_target):
        """Test successful target update."""
        # Arrange
        update_data = {
            "value": "updated.example.com",
            "name": "Updated name",
            "scope": "*.updated.example.com"
        }
        
        # Act
        response = await api_client.put(f"/api/targets/{sample_target.id}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target updated successfully"
        assert data["data"]["value"] == update_data["value"]
        assert data["data"]["name"] == update_data["name"]
        assert data["data"]["scope"] == update_data["scope"]
        assert data["data"]["id"] == str(sample_target.id)
    
    @pytest.mark.asyncio
    async def test_update_target_not_found(self, api_client: AsyncClient):
        """Test target update with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        update_data = {"value": "updated.example.com"}
        
        # Act
        response = await api_client.put(f"/api/targets/{non_existent_id}", json=update_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_delete_target_success(self, api_client: AsyncClient, sample_target):
        """Test successful target deletion."""
        # Act
        response = await api_client.delete(f"/api/targets/{sample_target.id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target deleted successfully"
    
    @pytest.mark.asyncio
    async def test_delete_target_not_found(self, api_client: AsyncClient):
        """Test target deletion with non-existent ID."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.delete(f"/api/targets/{non_existent_id}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_list_targets_success(self, api_client: AsyncClient, sample_target):
        """Test successful target listing."""
        # Act
        response = await api_client.get("/api/targets/")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Targets retrieved successfully"
        assert "targets" in data["data"]
        assert "total" in data["data"]
        assert "page" in data["data"]
        assert "per_page" in data["data"]
        assert len(data["data"]["targets"]) >= 1
        
        # Check if our sample target is in the list
        target_ids = [target["id"] for target in data["data"]["targets"]]
        assert str(sample_target.id) in target_ids
    
    @pytest.mark.asyncio
    async def test_list_targets_with_pagination(self, api_client: AsyncClient):
        """Test target listing with pagination."""
        # Act
        response = await api_client.get("/api/targets/?page=1&per_page=5")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["data"]["page"] == 1
        assert data["data"]["per_page"] == 5
    
    @pytest.mark.asyncio
    async def test_list_targets_with_filtering(self, api_client: AsyncClient, sample_target):
        """Test target listing with value filtering."""
        # Act
        response = await api_client.get(f"/api/targets/?value={sample_target.value}")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert len(data["data"]["targets"]) >= 1
        
        # All returned targets should match the filter
        for target in data["data"]["targets"]:
            assert sample_target.value in target["value"]
    
    @pytest.mark.asyncio
    async def test_get_target_summary(self, api_client: AsyncClient, sample_target):
        """Test target summary endpoint."""
        # Act
        response = await api_client.get(f"/api/targets/{sample_target.id}/summary")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target summary retrieved successfully"
        assert "target" in data["data"]
        assert "workflows" in data["data"]
        assert "results" in data["data"]
        assert data["data"]["target"]["id"] == str(sample_target.id)
    
    @pytest.mark.asyncio
    async def test_validate_target_success(self, api_client: AsyncClient):
        """Test target validation endpoint."""
        # Arrange
        target_data = {
            "value": "valid.example.com",
            "scope_config": ["192.168.1.1"],
            "scope": "*.valid.example.com"
        }
        
        # Act
        response = await api_client.post("/api/targets/validate", json=target_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target validation successful"
        assert "validation_checks" in data["data"]
        assert data["data"]["is_valid"] is True
    
    @pytest.mark.asyncio
    async def test_validate_target_failure(self, api_client: AsyncClient):
        """Test target validation with invalid data."""
        # Arrange
        invalid_target_data = {
            "value": "invalid-value",
            "scope_config": ["invalid-ip"],
            "scope": "invalid-scope"
        }
        
        # Act
        response = await api_client.post("/api/targets/validate", json=invalid_target_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Target validation completed"
        assert "validation_checks" in data["data"]
        assert data["data"]["is_valid"] is False
        assert len(data["data"]["errors"]) > 0
    
    @pytest.mark.asyncio
    async def test_get_targets_overview(self, api_client: AsyncClient):
        """Test targets overview endpoint."""
        # Act
        response = await api_client.get("/api/targets/overview")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        print(f"Response data: {data}")  # Debug print
        assert data["success"] is True
        assert data["message"] == "Targets overview retrieved successfully"
        assert "total_targets" in data["data"]
        assert "active_targets" in data["data"]
        assert "recent_targets" in data["data"]
        assert "targets_by_status" in data["data"]
        assert isinstance(data["data"]["total_targets"], int)
        assert isinstance(data["data"]["active_targets"], int)
        assert isinstance(data["data"]["recent_targets"], list)
        assert isinstance(data["data"]["targets_by_status"], dict) 
