import pytest
from uuid import uuid4
from datetime import datetime, timezone
from core.models.active_recon import ActiveReconResult, Port, Service, PortStatus, ServiceStatus

class TestActiveReconResultModel:
    def test_active_recon_result_creation(self):
        result = ActiveReconResult(
            id=uuid4(),
            execution_id="exec-789",
            tools_used=[{"name": "nmap", "version": "7.91"}],
            configuration={"scan_type": "full"},
            scan_type="tcp",
            hosts_scanned=["host1.example.com"],
            total_hosts_scanned=1,
            hosts_with_open_ports=1,
            total_open_ports=2,
            total_services_detected=2,
            raw_output={"nmap": "output"},
            processed_data={"ports": [80, 443]},
            execution_time=12.5,
            errors=None,
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert result.execution_id == "exec-789"
        assert result.total_open_ports == 2
        assert isinstance(result.tools_used, list)
        assert result.scan_type == "tcp"

    def test_active_recon_result_to_dict(self):
        result = ActiveReconResult(
            id=uuid4(),
            execution_id="exec-101",
            tools_used=[{"name": "httpx", "version": "1.2.0"}],
            total_hosts_scanned=1,
            hosts_with_open_ports=1,
            total_open_ports=1,
            total_services_detected=1,
            raw_output={"httpx": "output"},
            processed_data={"services": ["http"]},
            execution_time=8.0,
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = result.to_dict()
        assert d["execution_id"] == "exec-101"
        assert d["total_open_ports"] == 1
        assert "created_at" in d
        assert "id" in d

class TestPortModel:
    def test_port_creation(self):
        port = Port(
            id=uuid4(),
            host="host1.example.com",
            port_number=80,
            protocol="tcp",
            status=PortStatus.OPEN,
            is_open=True,
            service_name="http",
            service_version="1.0",
            service_product="nginx",
            banner="nginx banner",
            script_output={"script": "output"},
            notes="test port",
            active_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert port.host == "host1.example.com"
        assert port.port_number == 80
        assert port.status == PortStatus.OPEN
        assert port.is_open is True
        assert port.service_name == "http"
        assert port.banner == "nginx banner"

    def test_port_to_dict(self):
        port = Port(
            id=uuid4(),
            host="host2.example.com",
            port_number=443,
            protocol="tcp",
            status=PortStatus.CLOSED,
            is_open=False,
            active_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = port.to_dict()
        assert d["host"] == "host2.example.com"
        assert d["port"] == 443
        assert d["status"] == PortStatus.CLOSED.value
        assert "created_at" in d
        assert "id" in d

class TestServiceModel:
    def test_service_creation(self):
        service = Service(
            id=uuid4(),
            name="http",
            version="1.0",
            product="nginx",
            extrainfo="extra",
            status=ServiceStatus.DETECTED,
            is_confirmed=True,
            banner="nginx banner",
            fingerprint={"os": "linux"},
            cpe="cpe:/a:nginx:nginx:1.0",
            tags=["web"],
            notes="test service",
            port_id=uuid4(),
            active_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert service.name == "http"
        assert service.status == ServiceStatus.DETECTED
        assert service.is_confirmed is True
        assert service.banner == "nginx banner"
        assert service.fingerprint["os"] == "linux"

    def test_service_to_dict(self):
        service = Service(
            id=uuid4(),
            name="https",
            status=ServiceStatus.UNKNOWN,
            is_confirmed=False,
            port_id=uuid4(),
            active_recon_result_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = service.to_dict()
        assert d["name"] == "https"
        assert d["status"] == ServiceStatus.UNKNOWN.value
        assert "created_at" in d
        assert "id" in d 