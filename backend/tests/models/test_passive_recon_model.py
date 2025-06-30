import pytest
from uuid import uuid4
from datetime import datetime, timezone
from core.models.passive_recon import PassiveReconResult, Subdomain, ReconSource, SubdomainStatus
from core.models.target import Target

class TestPassiveReconResultModel:
    def test_passive_recon_result_creation(self):
        result = PassiveReconResult(
            id=uuid4(),
            execution_id="exec-123",
            tools_used=[{"name": "subfinder", "version": "2.5.0"}],
            configuration={"depth": 2},
            total_subdomains=5,
            unique_subdomains=4,
            active_subdomains=3,
            raw_output={"subfinder": "output"},
            processed_data={"subdomains": ["a.example.com"]},
            execution_time="10.5",
            errors=None,
            extra_metadata={"note": "test"},
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert result.execution_id == "exec-123"
        assert result.total_subdomains == 5
        assert isinstance(result.tools_used, list)
        assert result.extra_metadata["note"] == "test"

    def test_passive_recon_result_to_dict(self):
        result = PassiveReconResult(
            id=uuid4(),
            execution_id="exec-456",
            tools_used=[{"name": "amass", "version": "3.15.0"}],
            total_subdomains=2,
            unique_subdomains=2,
            active_subdomains=2,
            raw_output={"amass": "output"},
            processed_data={"subdomains": ["b.example.com"]},
            execution_time="5.0",
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = result.to_dict()
        assert d["execution_id"] == "exec-456"
        assert d["total_subdomains"] == 2
        assert "created_at" in d
        assert "id" in d

class TestSubdomainModel:
    def test_subdomain_creation(self):
        sub = Subdomain(
            id=uuid4(),
            name="a.example.com",
            domain="example.com",
            subdomain_part="a",
            status=SubdomainStatus.ACTIVE,
            is_verified=True,
            ip_addresses=["1.2.3.4"],
            cname=None,
            mx_records=None,
            txt_records=None,
            ns_records=None,
            sources=[ReconSource.SUBFINDER.value],
            first_seen="2024-01-01T00:00:00Z",
            last_seen="2024-01-02T00:00:00Z",
            tags=["test"],
            notes="test note",
            extra_metadata={"foo": "bar"},
            passive_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert sub.name == "a.example.com"
        assert sub.status == SubdomainStatus.ACTIVE
        assert sub.is_verified is True
        assert sub.ip_addresses == ["1.2.3.4"]
        assert sub.extra_metadata["foo"] == "bar"

    def test_subdomain_to_dict(self):
        # Case 1: No passive_recon_result relationship
        sub = Subdomain(
            id=uuid4(),
            name="b.example.com",
            domain="example.com",
            subdomain_part="b",
            status=SubdomainStatus.UNKNOWN,
            is_verified=False,
            ip_addresses=None,
            sources=[ReconSource.AMASS.value],
            passive_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = sub.to_dict()
        assert d["subdomain"] == "b.example.com"
        assert d["status"] == SubdomainStatus.UNKNOWN.value
        assert "created_at" in d
        assert "id" in d
        assert d["target_id"] is None

        # Case 2: With passive_recon_result relationship (real instance)
        from core.models.passive_recon import PassiveReconResult
        target_id = uuid4()
        precon = PassiveReconResult(
            id=uuid4(),
            execution_id="exec-xyz",
            tools_used=[],
            total_subdomains=0,
            unique_subdomains=0,
            active_subdomains=0,
            target_id=target_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        sub.passive_recon_result = precon
        d2 = sub.to_dict()
        assert d2["target_id"] == str(target_id) 