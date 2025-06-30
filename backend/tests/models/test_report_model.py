import pytest
from uuid import uuid4
from datetime import datetime, timezone
from core.models.report import Report, ReportFormat, ReportStatus, ReportType

class TestReportModel:
    def test_report_creation(self):
        report = Report(
            id=uuid4(),
            name="Test Report",
            report_type=ReportType.TECHNICAL_DETAILED,
            format=ReportFormat.PDF,
            status=ReportStatus.GENERATING,
            is_public=False,
            content="Report content",
            file_path="/reports/test_report.pdf",
            file_size="1024",
            template_used="default",
            configuration={"template": "default"},
            summary="Summary text",
            key_findings=["Finding 1", "Finding 2"],
            statistics={"total": 2},
            generation_time="5.0",
            generated_by="system",
            errors=None,
            access_token="token123",
            expires_at="2025-12-31T23:59:59Z",
            target_id=uuid4(),
            user_id=uuid4(),
            workflow_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert report.name == "Test Report"
        assert report.report_type == ReportType.TECHNICAL_DETAILED
        assert report.format == ReportFormat.PDF
        assert report.status == ReportStatus.GENERATING
        assert report.is_public is False
        assert report.file_path == "/reports/test_report.pdf"
        assert report.key_findings == ["Finding 1", "Finding 2"]
        assert report.statistics["total"] == 2
        assert report.access_token == "token123"

    def test_report_to_dict(self):
        report = Report(
            id=uuid4(),
            name="Another Report",
            report_type=ReportType.EXECUTIVE_SUMMARY,
            format=ReportFormat.MARKDOWN,
            status=ReportStatus.COMPLETED,
            is_public=True,
            target_id=uuid4(),
            workflow_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = report.to_dict()
        assert d["name"] == "Another Report"
        assert d["report_type"] == ReportType.EXECUTIVE_SUMMARY.value
        assert d["format"] == ReportFormat.MARKDOWN.value
        assert d["status"] == ReportStatus.COMPLETED.value
        assert d["is_public"] is True
        assert "created_at" in d
        assert "id" in d 