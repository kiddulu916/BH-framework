"""
Unit tests for the report service.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
from datetime import datetime, timezone

from core.tasks.report_service import ReportService
from core.schemas.report import (
    ReportCreateRequest,
    ReportUpdateRequest,
    ReportExportRequest,
    ReportFormat,
    ReportType,
    ReportStatus
)
from core.utils.exceptions import ValidationError, NotFoundError, ReportGenerationError, ExportError
from core.schemas.base import APIResponse


@pytest.fixture
def mock_repositories():
    """Create mock repositories for testing."""
    return {
        'report_repo': AsyncMock(),
        'workflow_repo': AsyncMock(),
        'target_repo': AsyncMock(),
        'passive_recon_repo': AsyncMock(),
        'active_recon_repo': AsyncMock(),
        'vulnerability_repo': AsyncMock(),
        'kill_chain_repo': AsyncMock()
    }


@pytest.fixture
def report_service(mock_repositories):
    """Create report service with mock repositories."""
    return ReportService(
        report_repository=mock_repositories['report_repo'],
        workflow_repository=mock_repositories['workflow_repo'],
        target_repository=mock_repositories['target_repo'],
        passive_recon_repository=mock_repositories['passive_recon_repo'],
        active_recon_repository=mock_repositories['active_recon_repo'],
        vulnerability_repository=mock_repositories['vulnerability_repo'],
        kill_chain_repository=mock_repositories['kill_chain_repo']
    )


@pytest.fixture
def sample_workflow():
    """Create a sample workflow for testing."""
    workflow_id = uuid4()
    target_id = uuid4()
    return MagicMock(
        id=workflow_id,
        target_id=target_id,
        name="Test Workflow",
        description="Test workflow description"
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
def sample_report():
    """Create a sample report for testing."""
    report_id = uuid4()
    target_id = uuid4()
    execution_id = uuid4()
    user_id = uuid4()
    workflow_id = uuid4()
    return MagicMock(
        id=report_id,
        target_id=target_id,
        execution_id=execution_id,
        user_id=user_id,
        workflow_id=workflow_id,
        title="Test Report",
        description="Test report description",
        report_type=ReportType.EXECUTIVE_SUMMARY,
        format=ReportFormat.MARKDOWN,
        status=ReportStatus.COMPLETED,
        sections=[],
        include_passive_recon=True,
        include_active_recon=True,
        include_vulnerabilities=True,
        include_kill_chain=True,
        include_screenshots=True,
        include_raw_data=False,
        custom_template=None,
        file_path="/path/to/report.md",
        file_size=1024,
        generation_time=5.0,
        error_message=None,
        metadata={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        generated_at=datetime.now(timezone.utc)
    )


class TestReportService:
    """Test cases for ReportService."""

    @pytest.mark.asyncio
    async def test_create_report_success(self, report_service, mock_repositories, sample_workflow):
        """Test successful report creation."""
        # Arrange
        workflow_id = sample_workflow.id
        payload = ReportCreateRequest(
            workflow_id=workflow_id,
            title="Test Report",
            template="default",
            format=ReportFormat.MARKDOWN,
            report_type=ReportType.EXECUTIVE_SUMMARY,
            description="Test description"
        )
        
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        mock_repositories['report_repo'].get_by_workflow_id.return_value = None
        
        # Create a proper mock with real values for ReportResponse
        created_report = MagicMock()
        created_report.id = uuid4()
        created_report.target_id = uuid4()
        created_report.execution_id = None
        created_report.user_id = None
        created_report.title = "Test Report"
        created_report.description = "Test description"
        created_report.report_type = ReportType.EXECUTIVE_SUMMARY
        created_report.format = ReportFormat.MARKDOWN
        created_report.status = ReportStatus.PENDING
        created_report.sections = []
        created_report.include_passive_recon = True
        created_report.include_active_recon = True
        created_report.include_vulnerabilities = True
        created_report.include_kill_chain = True
        created_report.include_screenshots = True
        created_report.include_raw_data = False
        created_report.custom_template = None
        created_report.file_path = None
        created_report.file_size = None
        created_report.generation_time = None
        created_report.error_message = None
        created_report.metadata = {}
        created_report.created_at = datetime.now(timezone.utc)
        created_report.updated_at = datetime.now(timezone.utc)
        created_report.generated_at = None
        
        mock_repositories['report_repo'].create.return_value = created_report
        
        # Act
        result = await report_service.create_report(payload)
        
        # Assert
        assert result.success is True
        assert "created successfully" in result.message
        mock_repositories['workflow_repo'].get_by_id.assert_called_with(workflow_id)
        mock_repositories['report_repo'].get_by_workflow_id.assert_called_once_with(workflow_id)
        mock_repositories['report_repo'].create.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_report_workflow_not_found(self, report_service, mock_repositories):
        """Test report creation with non-existent workflow."""
        # Arrange
        workflow_id = uuid4()
        payload = ReportCreateRequest(
            workflow_id=workflow_id,
            title="Test Report",
            template="default",
            format=ReportFormat.MARKDOWN,
            report_type=ReportType.EXECUTIVE_SUMMARY
        )
        
        mock_repositories['workflow_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.create_report(payload)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message
        mock_repositories['workflow_repo'].get_by_id.assert_called_once_with(workflow_id)

    @pytest.mark.asyncio
    async def test_create_report_already_exists(self, report_service, mock_repositories, sample_workflow):
        """Test report creation when report already exists for workflow."""
        # Arrange
        workflow_id = sample_workflow.id
        payload = ReportCreateRequest(
            workflow_id=workflow_id,
            title="Test Report",
            template="default",
            format=ReportFormat.MARKDOWN,
            report_type=ReportType.EXECUTIVE_SUMMARY
        )
        
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        mock_repositories['report_repo'].get_by_workflow_id.return_value = MagicMock()
        
        # Act
        result = await report_service.create_report(payload)
        
        # Assert
        assert result.success is False
        assert "already exists" in result.message

    @pytest.mark.asyncio
    async def test_get_report_success(self, report_service, mock_repositories, sample_report):
        """Test successful report retrieval."""
        # Arrange
        report_id = sample_report.id
        mock_repositories['report_repo'].get_by_id.return_value = sample_report
        
        # Act
        result = await report_service.get_report(report_id)
        
        # Assert
        assert result.success is True
        assert "retrieved successfully" in result.message
        mock_repositories['report_repo'].get_by_id.assert_called_once_with(report_id)

    @pytest.mark.asyncio
    async def test_get_report_not_found(self, report_service, mock_repositories):
        """Test report retrieval with non-existent report."""
        # Arrange
        report_id = uuid4()
        mock_repositories['report_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.get_report(report_id)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_get_reports_success(self, report_service, mock_repositories, sample_report):
        """Test successful report list retrieval."""
        # Arrange
        reports = [sample_report]
        mock_repositories['report_repo'].list.return_value = reports
        mock_repositories['report_repo'].count.return_value = 1
        
        # Act
        result = await report_service.get_reports(limit=10, offset=0)
        
        # Assert
        assert result.success is True
        assert "retrieved successfully" in result.message
        assert result.data['total'] == 1
        assert len(result.data['reports']) == 1

    @pytest.mark.asyncio
    async def test_update_report_success(self, report_service, mock_repositories, sample_report):
        """Test successful report update."""
        # Arrange
        report_id = sample_report.id
        payload = ReportUpdateRequest(title="Updated Report")
        
        mock_repositories['report_repo'].get_by_id.return_value = sample_report
        mock_repositories['report_repo'].update.return_value = sample_report
        
        # Act
        result = await report_service.update_report(report_id, payload)
        
        # Assert
        assert result.success is True
        assert "updated successfully" in result.message
        mock_repositories['report_repo'].update.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_report_not_found(self, report_service, mock_repositories):
        """Test report update with non-existent report."""
        # Arrange
        report_id = uuid4()
        payload = ReportUpdateRequest(title="Updated Report")
        
        mock_repositories['report_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.update_report(report_id, payload)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_delete_report_success(self, report_service, mock_repositories, sample_report):
        """Test successful report deletion."""
        # Arrange
        report_id = sample_report.id
        mock_repositories['report_repo'].get_by_id.return_value = sample_report
        
        # Act
        result = await report_service.delete_report(report_id)
        
        # Assert
        assert result.success is True
        assert "deleted successfully" in result.message
        mock_repositories['report_repo'].delete.assert_called_once_with(report_id)

    @pytest.mark.asyncio
    async def test_delete_report_not_found(self, report_service, mock_repositories):
        """Test report deletion with non-existent report."""
        # Arrange
        report_id = uuid4()
        mock_repositories['report_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.delete_report(report_id)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_generate_report_success(self, report_service, mock_repositories, sample_workflow, sample_target):
        """Test successful report generation."""
        # Arrange
        workflow_id = sample_workflow.id
        template = "default"
        
        mock_repositories['workflow_repo'].get_by_id.return_value = sample_workflow
        mock_repositories['target_repo'].get_by_id.return_value = sample_target
        mock_repositories['passive_recon_repo'].get_by_workflow_id.return_value = []
        mock_repositories['active_recon_repo'].get_by_workflow_id.return_value = []
        mock_repositories['vulnerability_repo'].get_by_workflow_id.return_value = []
        mock_repositories['kill_chain_repo'].get_by_workflow_id.return_value = []
        mock_repositories['report_repo'].get_by_workflow_id.return_value = None
        
        # Create a proper mock with real values for all required fields
        created_report = MagicMock()
        created_report.id = uuid4()
        created_report.target_id = sample_target.id
        created_report.execution_id = uuid4()
        created_report.user_id = uuid4()
        created_report.title = "Generated Report"
        created_report.description = "Auto-generated report"
        created_report.report_type = ReportType.EXECUTIVE_SUMMARY
        created_report.format = ReportFormat.MARKDOWN
        created_report.status = ReportStatus.COMPLETED
        created_report.custom_template = template
        created_report.file_path = "/path/to/report.md"
        created_report.error_message = None
        created_report.metadata = {}
        created_report.created_at = datetime.now(timezone.utc)
        created_report.updated_at = datetime.now(timezone.utc)
        
        mock_repositories['report_repo'].create.return_value = created_report
        
        # Act
        result = await report_service.generate_report(workflow_id, template)
        
        # Assert
        assert result.success is True
        assert "generated successfully" in result.message
        mock_repositories['workflow_repo'].get_by_id.assert_called_once_with(workflow_id)

    @pytest.mark.asyncio
    async def test_generate_report_workflow_not_found(self, report_service, mock_repositories):
        """Test report generation with non-existent workflow."""
        # Arrange
        workflow_id = uuid4()
        template = "default"
        
        mock_repositories['workflow_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.generate_report(workflow_id, template)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_export_report_success(self, report_service, mock_repositories, sample_report):
        """Test successful report export."""
        # Arrange
        report_id = sample_report.id
        payload = ReportExportRequest(format="json")
        
        # Create a proper mock report with serializable content
        mock_report = MagicMock()
        mock_report.id = report_id
        mock_report.content = {
            "target": {"domain": "example.com"},
            "sections": {
                "executive_summary": {"overview": "Test summary"},
                "findings": {"vulnerabilities": []}
            }
        }
        
        mock_repositories['report_repo'].get_by_id.return_value = mock_report
        
        # Act
        result = await report_service.export_report(report_id, payload)
        
        # Assert
        assert result.success is True
        assert "exported successfully" in result.message
        assert result.data["format"] == "json"
        mock_repositories['report_repo'].get_by_id.assert_called_once_with(report_id)

    @pytest.mark.asyncio
    async def test_export_report_not_found(self, report_service, mock_repositories):
        """Test report export with non-existent report."""
        # Arrange
        report_id = uuid4()
        payload = ReportExportRequest(format="json")
        
        mock_repositories['report_repo'].get_by_id.return_value = None
        
        # Act
        result = await report_service.export_report(report_id, payload)
        
        # Assert
        assert result.success is False
        assert "not found" in result.message

    @pytest.mark.asyncio
    async def test_get_report_templates_success(self, report_service):
        """Test successful report templates retrieval."""
        # Act
        result = await report_service.get_report_templates()
        
        # Assert
        assert result.success is True
        assert "retrieved successfully" in result.message
        assert "templates" in result.data
        assert len(result.data["templates"]) == 4  # default, executive, technical, compliance

    def test_get_template_sections_default(self, report_service):
        """Test getting sections for default template."""
        # Act
        sections = report_service._get_template_sections("default")
        
        # Assert
        expected_sections = ["executive_summary", "methodology", "findings", "recommendations", "appendix"]
        assert sections == expected_sections

    def test_get_template_sections_executive(self, report_service):
        """Test getting sections for executive template."""
        # Act
        sections = report_service._get_template_sections("executive")
        
        # Assert
        expected_sections = ["executive_summary", "findings", "recommendations"]
        assert sections == expected_sections

    def test_get_template_sections_invalid(self, report_service):
        """Test getting sections for invalid template."""
        # Act
        sections = report_service._get_template_sections("invalid_template")
        
        # Assert (should return default sections)
        expected_sections = ["executive_summary", "methodology", "findings", "recommendations", "appendix"]
        assert sections == expected_sections

    def test_generate_executive_summary(self, report_service, sample_target, sample_workflow):
        """Test executive summary generation."""
        # Arrange
        vulnerabilities = [
            MagicMock(severity="critical"),
            MagicMock(severity="high"),
            MagicMock(severity="medium"),
            MagicMock(severity="low")
        ]
        kill_chains = [MagicMock(), MagicMock()]
        
        # Act
        summary = report_service._generate_executive_summary(sample_target, sample_workflow, vulnerabilities, kill_chains)
        
        # Assert
        assert "target_overview" in summary
        assert "key_findings" in summary
        assert summary["key_findings"]["critical_vulnerabilities"] == 1
        assert summary["key_findings"]["high_vulnerabilities"] == 1
        assert summary["key_findings"]["attack_paths"] == 2

    def test_generate_methodology_section(self, report_service, sample_workflow):
        """Test methodology section generation."""
        # Arrange
        passive_recon = [MagicMock(), MagicMock()]
        active_recon = [MagicMock()]
        
        # Act
        methodology = report_service._generate_methodology_section(sample_workflow, passive_recon, active_recon)
        
        # Assert
        assert "approach" in methodology
        assert "stages" in methodology
        assert len(methodology["stages"]) == 3
        assert methodology["stages"][0]["name"] == "Passive Reconnaissance"
        assert methodology["stages"][0]["results_count"] == 2

    def test_generate_findings_section(self, report_service):
        """Test findings section generation."""
        # Arrange
        vulnerabilities = [
            MagicMock(
                id=uuid4(),
                title="SQL Injection",
                severity="high",
                description="SQL injection vulnerability",
                cvss_score=8.5,
                status="open"
            )
        ]
        kill_chains = [
            MagicMock(
                id=uuid4(),
                name="Data Exfiltration Path",
                description="Path to data exfiltration",
                risk_level="high",
                steps=["step1", "step2"]
            )
        ]
        
        # Act
        findings = report_service._generate_findings_section(vulnerabilities, kill_chains)
        
        # Assert
        assert "vulnerabilities" in findings
        assert "attack_paths" in findings
        assert len(findings["vulnerabilities"]) == 1
        assert len(findings["attack_paths"]) == 1
        assert findings["vulnerabilities"][0]["title"] == "SQL Injection"

    def test_generate_recommendations_section(self, report_service):
        """Test recommendations section generation."""
        # Arrange
        vulnerabilities = [
            MagicMock(severity="critical"),
            MagicMock(severity="high"),
            MagicMock(severity="low")
        ]
        kill_chains = [
            MagicMock(risk_level="high"),
            MagicMock(risk_level="low")
        ]
        
        # Act
        recommendations = report_service._generate_recommendations_section(vulnerabilities, kill_chains)
        
        # Assert
        assert "recommendations" in recommendations
        # Should have recommendations for critical and high vulnerabilities, and high risk kill chains
        assert len(recommendations["recommendations"]) == 3

    def test_generate_appendix_section(self, report_service):
        """Test appendix section generation."""
        # Arrange
        passive_recon = [
            MagicMock(
                id=uuid4(),
                subdomain="test.example.com",
                ip_address="192.168.1.1",
                source="subfinder"
            )
        ]
        active_recon = [
            MagicMock(
                id=uuid4(),
                host="test.example.com",
                port=80,
                service="http",
                status="open"
            )
        ]
        vulnerabilities = [MagicMock()]
        
        # Act
        appendix = report_service._generate_appendix_section(passive_recon, active_recon, vulnerabilities)
        
        # Assert
        assert "detailed_results" in appendix
        assert "tools_used" in appendix
        assert len(appendix["detailed_results"]["passive_reconnaissance"]) == 1
        assert len(appendix["detailed_results"]["active_reconnaissance"]) == 1

    @pytest.mark.asyncio
    async def test_export_report_content_json(self, report_service, sample_report):
        """Test report content export in JSON format."""
        # Arrange
        sample_report.content = {"test": "data"}
        
        # Act
        result = await report_service._export_report_content(sample_report, "json")
        
        # Assert
        assert '"test": "data"' in result

    @pytest.mark.asyncio
    async def test_export_report_content_markdown(self, report_service, sample_report):
        """Test report content export in Markdown format."""
        # Arrange
        sample_report.content = {
            "target": {"domain": "example.com"},
            "generated_at": "2023-01-01T00:00:00Z",
            "sections": {
                "executive_summary": {
                    "target_overview": "Test target",
                    "risk_level": "Medium"
                }
            }
        }
        
        # Act
        result = await report_service._export_report_content(sample_report, "markdown")
        
        # Assert
        assert "# example.com" in result
        assert "**Generated:**" in result
        assert "## Executive Summary" in result

    @pytest.mark.asyncio
    async def test_export_report_content_unsupported_format(self, report_service, sample_report):
        """Test report content export with unsupported format."""
        # Act & Assert
        with pytest.raises(ExportError):
            await report_service._export_report_content(sample_report, "unsupported")

    def test_convert_to_markdown(self, report_service):
        """Test Markdown conversion."""
        # Arrange
        content = {
            "target": {"domain": "example.com"},
            "generated_at": "2023-01-01T00:00:00Z",
            "sections": {
                "executive_summary": {
                    "target_overview": "Test target",
                    "risk_level": "Medium",
                    "key_findings": {
                        "critical_vulnerabilities": 1,
                        "high_vulnerabilities": 2
                    }
                },
                "findings": {
                    "vulnerabilities": [
                        {
                            "title": "SQL Injection",
                            "severity": "high",
                            "description": "SQL injection vulnerability",
                            "cvss_score": 8.5,
                            "status": "open"
                        }
                    ]
                },
                "recommendations": {
                    "recommendations": [
                        {
                            "title": "Fix SQL Injection",
                            "priority": "high",
                            "type": "vulnerability_remediation",
                            "description": "Mitigate SQL injection by using parameterized queries."
                        }
                    ]
                }
            }
        }
        
        # Act
        markdown = report_service._convert_to_markdown(content)
        
        # Assert
        assert "# example.com" in markdown
        assert "**Generated:**" in markdown
        assert "## Executive Summary" in markdown
        assert "## Findings" in markdown
        assert "## Recommendations" in markdown
        assert "SQL Injection" in markdown 
