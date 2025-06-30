import pytest
from uuid import uuid4
from datetime import datetime, timezone
from core.models.kill_chain import (
    KillChain, AttackPath, KillChainPhase, AttackPathStatus
)

class TestKillChainModel:
    def test_kill_chain_creation(self):
        kc = KillChain(
            id=uuid4(),
            execution_id="exec-404",
            total_paths_identified=2,
            critical_paths=1,
            high_paths=1,
            medium_paths=0,
            low_paths=0,
            info_paths=0,
            verified_paths=1,
            execution_time=20.0,
            analysis_config={"method": "auto"},
            raw_output={"tool": "output"},
            kill_chain_metadata={"analyst": "test"},
            analysis_type="auto",
            methodology="MITRE",
            configuration={"phases": ["reconnaissance"]},
            exploitable_paths=1,
            blocked_paths=0,
            raw_analysis={"paths": ["path1"]},
            processed_paths={"paths": ["path1"]},
            errors=None,
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert kc.execution_id == "exec-404"
        assert kc.total_paths_identified == 2
        assert kc.critical_paths == 1
        assert kc.analysis_type == "auto"
        assert kc.kill_chain_metadata["analyst"] == "test"

    def test_kill_chain_to_dict(self):
        kc = KillChain(
            id=uuid4(),
            execution_id="exec-505",
            total_paths_identified=1,
            critical_paths=0,
            high_paths=1,
            medium_paths=0,
            low_paths=0,
            info_paths=0,
            verified_paths=0,
            execution_time=10.0,
            analysis_config={"method": "manual"},
            raw_output={"tool": "output"},
            kill_chain_metadata={"analyst": "test2"},
            target_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = kc.to_dict()
        assert d["execution_id"] == "exec-505"
        assert d["total_paths_identified"] == 1
        assert "created_at" in d
        assert "id" in d

class TestAttackPathModel:
    def test_attack_path_creation(self):
        ap = AttackPath(
            id=uuid4(),
            name="Path 1",
            description="Test attack path",
            status=AttackPathStatus.IDENTIFIED,
            attack_path_type="lateral",
            severity="high",
            stages=[KillChainPhase.RECONNAISSANCE.value],
            entry_points=["host1"],
            exit_points=["host2"],
            prerequisites=["access"],
            techniques=["T1046"],
            tools_required=["nmap"],
            evidence="evidence string",
            proof_of_concept="poc string",
            screenshots=["/path/to/screenshot.png"],
            risk_score=8.5,
            impact_assessment="High impact",
            remediation="Apply patch",
            attack_path_metadata={"analyst": "test"},
            phases=[KillChainPhase.RECONNAISSANCE.value],
            tactics=["TA0001"],
            intermediate_nodes=["node1"],
            likelihood="likely",
            impact="high",
            is_verified=True,
            verification_evidence=["log1"],
            verification_notes="Verified",
            is_exploitable=True,
            exploitation_evidence=["exploit1"],
            exploitation_notes="Exploit successful",
            mitigation_controls=["firewall"],
            recommended_controls=["update"],
            tags=["critical"],
            notes="test path",
            kill_chain_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert ap.name == "Path 1"
        assert ap.status == AttackPathStatus.IDENTIFIED
        assert ap.severity == "high"
        assert ap.is_verified is True
        assert ap.is_exploitable is True
        assert ap.attack_path_metadata["analyst"] == "test"

    def test_attack_path_to_dict(self):
        ap = AttackPath(
            id=uuid4(),
            name="Path 2",
            status=AttackPathStatus.VERIFIED,
            is_verified=True,
            kill_chain_id=uuid4(),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        d = ap.to_dict()
        assert d["name"] == "Path 2"
        assert d["status"] == AttackPathStatus.VERIFIED.value
        assert "created_at" in d
        assert "id" in d 