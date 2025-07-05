"""
Tests for results API endpoints.

This module contains tests for all stage result submission API endpoints,
including passive recon, active recon, vulnerability, and kill chain results.
"""

import pytest
from uuid import uuid4
from httpx import AsyncClient
from unittest.mock import patch, MagicMock
import jwt
import os
from datetime import datetime, timezone, timedelta

from core.models.target import Target, TargetScope, TargetStatus
from core.models.passive_recon import PassiveReconResult
from core.models.active_recon import ActiveReconResult
from core.models.vulnerability import Vulnerability
from core.models.kill_chain import KillChain
from core.schemas.passive_recon import PassiveReconResultCreate
from core.schemas.active_recon import ActiveReconResultCreate
from core.schemas.vulnerability import VulnerabilityCreate
from core.schemas.kill_chain import KillChainCreate


class TestResultsAPI:
    """Test suite for results API endpoints."""
    
    @pytest.fixture
    def jwt_token(self):
        """Create a valid JWT token for testing."""
        secret = os.environ.get("JWT_SECRET", "dev-secret")
        payload = {
            "user_id": str(uuid4()),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1)
        }
        return jwt.encode(payload, secret, algorithm="HS256")
    
    @pytest.fixture
    def auth_headers(self, jwt_token):
        """Create authentication headers with JWT token."""
        return {"Authorization": f"Bearer {jwt_token}"}
    
    @pytest.mark.asyncio
    async def test_submit_passive_recon_result_success(self, api_client: AsyncClient, sample_target, auth_headers):
        """Test successful passive recon result submission."""
        # Arrange
        result_data = {
            "target_id": str(sample_target.id),
            "execution_id": "550e8400-e29b-41d4-a716-446655440000",
            "tools_used": ["subfinder", "amass"],
            "subdomains": [
                {
                    "target_id": str(sample_target.id),
                    "subdomain": "test1.example.com",
                    "domain": "example.com",
                    "ip_addresses": ["192.168.1.1"],
                    "status": "active",
                    "source": "subfinder",
                    "metadata": {"protocol": "http"}
                },
                {
                    "target_id": str(sample_target.id),
                    "subdomain": "test2.example.com",
                    "domain": "example.com",
                    "ip_addresses": ["192.168.1.2"],
                    "status": "active",
                    "source": "amass",
                    "metadata": {"protocol": "https"}
                }
            ],
            "total_subdomains": 2,
            "execution_time": "120.5",
            "raw_output": {
                "subfinder": {
                    "subdomains": ["test1.example.com", "test2.example.com"],
                    "ipv4s": ["192.168.1.1", "192.168.1.2"]
                },
                "amass": {
                    "subdomains": ["test2.example.com"],
                    "protocols": ["http", "https"],
                    "cidrs": ["192.168.1.0/24"]
                }
            },
            "metadata": {
                "scan_duration": 120.5,
                "summary": "Found 2 subdomains using 2 tools"
            }
        }
        
        # Act
        response = await api_client.post(
            "/api/results/passive-recon",
            json=result_data,
            headers=auth_headers
        )
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Parsed output saved"
        assert "data" in data
        assert data["data"]["target_id"] == str(sample_target.id)
        assert len(data["data"]["tools_used"]) == 2
        assert "subfinder" in data["data"]["tools_used"]
        assert "amass" in data["data"]["tools_used"]
    
    @pytest.mark.asyncio
    async def test_submit_passive_recon_result_validation_error(self, api_client: AsyncClient, auth_headers):
        """Test passive recon result submission with validation errors."""
        # Arrange
        invalid_data = {
            "target_id": "invalid-uuid",
            "tools_used": [],
            "subdomains": [],
            "total_subdomains": 0
        }
        
        # Act
        response = await api_client.post(
            "/api/results/passive-recon",
            json=invalid_data,
            headers=auth_headers
        )
        
        # Assert
        assert response.status_code == 422  # Validation error
        data = response.json()
        assert "detail" in data
    
    @pytest.mark.asyncio
    async def test_submit_passive_recon_result_unauthorized(self, api_client: AsyncClient, sample_target):
        """Test passive recon result submission without authentication."""
        # Arrange
        result_data = {
            "target_id": str(sample_target.id),
            "tools_used": ["subfinder"],
            "subdomains": [
                {
                    "target_id": str(sample_target.id),
                    "subdomain": "test.example.com",
                    "domain": "example.com",
                    "ip_addresses": ["192.168.1.1"],
                    "status": "active",
                    "source": "subfinder",
                    "metadata": {}
                }
            ],
            "total_subdomains": 1,
            "raw_output": {"subfinder": {"subdomains": ["test.example.com"]}},
            "metadata": {}
        }
        
        # Act
        response = await api_client.post(
            "/api/results/passive-recon",
            json=result_data
        )
        
        # Assert
        assert response.status_code == 401  # Unauthorized
    
    @pytest.mark.asyncio
    async def test_submit_active_recon_result_success(self, api_client: AsyncClient, sample_target):
        """Test successful active recon result submission."""
        # Arrange
        result_data = {
            "target_id": str(sample_target.id),
            "execution_id": "550e8400-e29b-41d4-a716-446655440000",
            "tools_used": ["nmap", "httpx"],
            "hosts_scanned": ["192.168.1.1"],
            "ports": [
                {
                    "target_id": str(sample_target.id),
                    "host": "192.168.1.1",
                    "port": 80,
                    "protocol": "tcp",
                    "status": "open",
                    "service_name": "http",
                    "service_version": "1.1",
                    "service_product": "nginx",
                    "service_extra_info": "",
                    "banner": "nginx banner",
                    "metadata": {}
                },
                {
                    "target_id": str(sample_target.id),
                    "host": "192.168.1.1",
                    "port": 443,
                    "protocol": "tcp",
                    "status": "open",
                    "service_name": "https",
                    "service_version": "1.1",
                    "service_product": "nginx",
                    "service_extra_info": "",
                    "banner": "nginx banner",
                    "metadata": {}
                }
            ],
            "services": [
                {
                    "target_id": str(sample_target.id),
                    "host": "192.168.1.1",
                    "port": 80,
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_version": "1.1",
                    "service_product": "nginx",
                    "service_extra_info": "",
                    "state": "open",
                    "banner": "nginx banner",
                    "http_title": "Welcome",
                    "http_status": 200,
                    "http_headers": {"Server": "nginx"},
                    "technologies": ["nginx", "http"],
                    "metadata": {}
                }
            ],
            "total_ports": 2,
            "total_services": 1,
            "execution_time": 45.2,
            "scan_range": "1-1000",
            "raw_output": {
                "nmap": {
                    "scan_results": [
                        {
                            "host": "192.168.1.1",
                            "ports": [
                                {"port": 80, "state": "open", "service": "http"},
                                {"port": 443, "state": "open", "service": "https"}
                            ]
                        }
                    ]
                }
            },
            "metadata": {
                "scan_type": "tcp_connect"
            }
        }
        
        # Act
        response = await api_client.post("/api/results/active-recon", json=result_data)
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Active reconnaissance results submitted successfully"
        assert data["data"]["target_id"] == str(sample_target.id)
        assert "nmap" in data["data"]["tools_used"]
    
    @pytest.mark.asyncio
    async def test_submit_vulnerability_findings_success(self, api_client: AsyncClient, sample_target):
        """Test successful vulnerability findings submission."""
        # Arrange
        result_data = {
            "target_id": str(sample_target.id),
            "execution_id": "550e8400-e29b-41d4-a716-446655440000",
            "tools_used": ["nuclei"],
            "findings": [
                {
                    "target_id": str(sample_target.id),
                    "title": "SQL Injection",
                    "description": "SQL injection vulnerability detected",
                    "severity": "high",
                    "status": "open",
                    "vulnerability_type": "sql_injection",
                    "tool": "nuclei",
                    "host": "test.example.com",
                    "port": 80,
                    "url": "http://test.example.com/vulnerable",
                    "parameter": "id",
                    "payload": "1' OR '1'='1",
                    "evidence": "Error-based SQLi",
                    "cve_id": "CVE-2023-1234",
                    "cvss_score": 7.5,
                    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234"],
                    "tags": ["sql", "injection"],
                    "metadata": {"template": "http-vulns/sql-injection"}
                }
            ],
            "total_findings": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "execution_time": 180.5,
            "scan_config": {"templates_used": ["http-vulns", "cves"]},
            "raw_output": {
                "nuclei": {
                    "findings": [
                        {
                            "template": "http-vulns/sql-injection",
                            "severity": "high",
                            "url": "http://test.example.com/vulnerable",
                            "description": "SQL injection vulnerability detected"
                        }
                    ]
                }
            },
            "metadata": {"scan_duration": 180.5}
        }
        
        # Act
        response = await api_client.post("/api/results/vulnerabilities", json=result_data)
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Vulnerability findings submitted successfully"
        assert data["data"]["target_id"] == str(sample_target.id)
        assert "nuclei" in data["data"]["tools_used"]
        assert "findings" in data["data"]
        assert isinstance(data["data"]["findings"], list)
    
    @pytest.mark.asyncio
    async def test_submit_kill_chain_results_success(self, api_client: AsyncClient, sample_target):
        """Test successful kill chain analysis results submission."""
        # Arrange
        result_data = {
            "target_id": str(sample_target.id),
            "tool_name": "kill_chain_analyzer",
            "raw_output": {
                "attack_paths": [
                    {
                        "path_id": "path_001",
                        "steps": [
                            {"step": 1, "description": "Initial access via SQL injection"},
                            {"step": 2, "description": "Privilege escalation via weak passwords"}
                        ]
                    }
                ]
            },
            "parsed_output": {
                "attack_paths": [
                    {
                        "id": "path_001",
                        "name": "SQL Injection to Admin Access",
                        "steps": [
                            {
                                "order": 1,
                                "title": "Initial Access",
                                "description": "SQL injection vulnerability",
                                "technique": "T1190"
                            },
                            {
                                "order": 2,
                                "title": "Privilege Escalation",
                                "description": "Weak password exploitation",
                                "technique": "T1078"
                            }
                        ],
                        "severity": "high",
                        "confidence": 0.85
                    }
                ]
            },
            "metadata": {
                "analysis_duration": 300.0,
                "techniques_analyzed": ["T1190", "T1078", "T1005"]
            }
        }
        
        # Act
        response = await api_client.post("/api/results/kill-chain", json=result_data)
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Kill chain analysis results submitted successfully"
        assert data["data"]["target_id"] == str(sample_target.id)
        assert "attack_paths" in data["data"]
        assert isinstance(data["data"]["attack_paths"], list)
    
    @pytest.mark.asyncio
    async def test_get_target_results_summary_success(self, api_client: AsyncClient, sample_target):
        """Test successful target results summary retrieval."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/summary")
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Target results summary retrieved successfully"
        assert "data" in data
        assert data["data"]["target_id"] == str(sample_target.id)
    
    @pytest.mark.asyncio
    async def test_get_target_results_summary_not_found(self, api_client: AsyncClient):
        """Test target results summary retrieval with non-existent target."""
        # Arrange
        non_existent_id = uuid4()
        
        # Act
        response = await api_client.get(f"/api/results/{non_existent_id}/summary")
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "not found" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_get_passive_recon_results_success(self, api_client: AsyncClient, sample_target):
        """Test successful passive recon results retrieval."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/passive-recon")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Passive reconnaissance results retrieved successfully"
        assert "data" in data
        assert "results" in data["data"]
        assert "pagination" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_active_recon_results_success(self, api_client: AsyncClient, sample_target):
        """Test successful active recon results retrieval."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/active-recon")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Active reconnaissance results retrieved successfully"
        assert "data" in data
        assert "results" in data["data"]
        assert "pagination" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_vulnerability_findings_success(self, api_client: AsyncClient, sample_target):
        """Test successful vulnerability findings retrieval."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/vulnerabilities")
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Vulnerability findings retrieved successfully"
        assert "data" in data
        assert "findings" in data["data"]
        assert isinstance(data["data"]["findings"], list)
    
    @pytest.mark.asyncio
    async def test_get_vulnerability_findings_with_severity_filter(self, api_client: AsyncClient, sample_target):
        """Test vulnerability findings retrieval with severity filter."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/vulnerabilities?severity=high")
        
        # Assert
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Vulnerability findings retrieved successfully"
        assert "findings" in data["data"]
        assert isinstance(data["data"]["findings"], list)
    
    @pytest.mark.asyncio
    async def test_get_kill_chain_results_success(self, api_client: AsyncClient, sample_target):
        """Test successful kill chain results retrieval."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/kill-chain")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["message"] == "Kill chain analysis results retrieved successfully"
        assert "data" in data
        assert "results" in data["data"]
        assert "pagination" in data["data"]
    
    @pytest.mark.asyncio
    async def test_get_results_with_pagination(self, api_client: AsyncClient, sample_target):
        """Test results retrieval with pagination."""
        # Act
        response = await api_client.get(f"/api/results/{sample_target.id}/passive-recon?page=2&per_page=5")
        
        # Assert
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data" in data
        assert "pagination" in data["data"]
        assert data["data"]["pagination"]["page"] == 2
        assert data["data"]["pagination"]["per_page"] == 5
    
    @pytest.mark.asyncio
    async def test_api_response_format_consistency(self, api_client: AsyncClient, sample_target):
        """Test that all API responses follow the standardized format."""
        # Test multiple endpoints to ensure consistent response format
        endpoints = [
            f"/api/results/{sample_target.id}/summary",
            f"/api/results/{sample_target.id}/passive-recon",
            f"/api/results/{sample_target.id}/active-recon",
            f"/api/results/{sample_target.id}/vulnerabilities",
            f"/api/results/{sample_target.id}/kill-chain"
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