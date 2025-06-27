"""
Result service for the Bug Hunting Framework.

This module contains business logic for result processing operations,
including handling stage results from various tools and containers.
"""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository
from core.schemas.passive_recon import PassiveReconResultCreate, PassiveReconResultResponse
from core.schemas.active_recon import ActiveReconResultCreate, ActiveReconResultResponse, PortResponse, ServiceResponse
from core.schemas.vulnerability import VulnerabilityCreate, VulnerabilityResponse
from core.schemas.kill_chain import KillChainCreate, KillChainResponse
from core.utils.exceptions import NotFoundError, ValidationError
from core.models.active_recon import Port, Service, PortStatus, ActiveReconResult
from core.models.vulnerability import VulnerabilityFinding


class ResultService:
    """Service class for result processing operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the result service with a database session."""
        self.session = session
        self.passive_recon_repo = PassiveReconRepository(session)
        self.active_recon_repo = ActiveReconRepository(session)
        self.vulnerability_repo = VulnerabilityRepository(session)
        self.kill_chain_repo = KillChainRepository(session)
    
    async def create_passive_recon_result(self, payload: PassiveReconResultCreate) -> PassiveReconResultResponse:
        """
        Create a new passive reconnaissance result.
        
        Args:
            payload: Passive recon result data
            
        Returns:
            Created passive recon result response
        """
        # Validate target exists
        await self._validate_target_exists(payload.target_id)
        data = payload.model_dump()
        subdomains = data.pop('subdomains', [])
        result = await self.passive_recon_repo.create_with_subdomains(subdomains=subdomains, **data)
        
<<<<<<< HEAD
        # Return the response using from_attributes=True for ORM compatibility
        return PassiveReconResultResponse.model_validate(result, from_attributes=True)
=======
        # Eagerly reload with subdomains before session closes
        result = await self.passive_recon_repo.get_by_id(result.id, include_relationships=['subdomains'])
        
        # Convert the result to a dict and normalize enum values back to lowercase
        result_dict = result.to_dict()
        
        # Normalize tools_used back to lowercase
        if 'tools_used' in result_dict and result_dict['tools_used']:
            result_dict['tools_used'] = [tool.lower() for tool in result_dict['tools_used']]
        
        # Normalize subdomain enum values back to lowercase
        if 'subdomains' in result_dict and result_dict['subdomains']:
            for subdomain in result_dict['subdomains']:
                if 'status' in subdomain:
                    subdomain['status'] = subdomain['status'].lower()
                if 'source' in subdomain and subdomain['source']:
                    subdomain['source'] = subdomain['source'].lower()
        
        return PassiveReconResultResponse.model_validate(result_dict)
>>>>>>> 104107464cb0d6c74457d543e9bf7f7cb883603f
    
    async def create_active_recon_result(self, payload: ActiveReconResultCreate) -> ActiveReconResultResponse:
        """
        Create a new active reconnaissance result.
        
        Args:
            payload: Active recon result data
            
        Returns:
            Created active recon result response
        """
        # Validate target exists
        await self._validate_target_exists(payload.target_id)
        
        data = payload.model_dump()
        ports_data = data.pop('ports', [])
        services_data = data.pop('services', [])
        # Convert status string to PortStatus enum for each port
        for port in ports_data:
            if "status" in port and isinstance(port["status"], str):
                port["status"] = PortStatus(port["status"])
            # Map 'port' to 'port_number' if present
            if "port" in port and "port_number" not in port:
                port["port_number"] = port.pop("port")
        port_fields = {
            "host", "port_number", "protocol", "status", "is_open",
            "service_name", "service_version", "service_product",
            "banner", "script_output", "notes"
        }
        service_fields = {
            "name", "version", "product", "extrainfo", "status", "is_confirmed",
            "banner", "fingerprint", "cpe", "tags", "notes"
        }
        ports = [Port(**{k: v for k, v in port.items() if k in port_fields}) for port in ports_data]
        services = [Service(**{k: v for k, v in service.items() if k in service_fields}) for service in services_data]
        # Only keep valid fields for ActiveReconResult
        active_recon_fields = {
            "target_id", "execution_id", "tools_used", "hosts_scanned", "raw_output", "processed_data", "execution_time", "errors", "configuration", "scan_type",
            "total_hosts_scanned", "hosts_with_open_ports", "total_open_ports", "total_services_detected"
        }
        filtered_data = {k: v for k, v in data.items() if k in active_recon_fields}
        if "execution_id" in filtered_data and isinstance(filtered_data["execution_id"], UUID):
            filtered_data["execution_id"] = str(filtered_data["execution_id"])
        result = await self.active_recon_repo.create(
            **filtered_data,
            ports=ports,
            services=services
        )
        # Eagerly load relationships using selectinload
        stmt = (
            select(ActiveReconResult)
            .options(selectinload(ActiveReconResult.ports), selectinload(ActiveReconResult.services))
            .where(ActiveReconResult.id == result.id)
        )
        result = (await self.session.execute(stmt)).scalar_one()
        # Compute total_ports and total_services
        total_ports = len(result.ports) if result.ports else 0
        total_services = len(result.services) if result.services else 0
        # Use metadata from input if present, else empty dict
        metadata = data.get("metadata", {})
        # Build response dict
        response_dict = result.to_dict()
        # Convert ports and services to response schemas using to_dict first
        response_dict["ports"] = [PortResponse.model_validate(port.to_dict()).model_dump() for port in result.ports]
        response_dict["services"] = [ServiceResponse.model_validate(service.to_dict()).model_dump() for service in result.services]
        response_dict["total_ports"] = total_ports
        response_dict["total_services"] = total_services
        response_dict["metadata"] = metadata
        return ActiveReconResultResponse(**response_dict)
    
    async def create_vulnerability_result(self, payload: VulnerabilityCreate) -> VulnerabilityResponse:
        """
        Create a new vulnerability result.
        
        Args:
            payload: Vulnerability result data
            
        Returns:
            Created vulnerability result response
        """
        # Validate target exists
        await self._validate_target_exists(payload.target_id)
        data = payload.model_dump()
        findings_data = data.pop('findings', [])
        findings = []
        for finding in findings_data:
            mapped = {
                'title': finding.get('title'),
                'vuln_type': finding.get('vulnerability_type'),
                'severity': finding.get('severity'),
                'status': finding.get('status'),
                'description': finding.get('description'),
                'cve_id': finding.get('cve_id'),
                'cvss_score': finding.get('cvss_score'),
                'cvss_vector': finding.get('cvss_vector'),
                'affected_host': finding.get('host'),
                'affected_port': finding.get('port'),
                'affected_service': None,
                'affected_url': finding.get('url'),
                'proof_of_concept': finding.get('payload') or finding.get('evidence'),
                'remediation': None,
                'references': finding.get('references'),
                'detection_tool': finding.get('tool'),
                'detection_method': None,
                'confidence': None,
                'is_verified': False,
                'verification_notes': None,
                'tags': finding.get('tags'),
                'notes': None,
            }
            findings.append(VulnerabilityFinding(**{k: v for k, v in mapped.items() if v is not None}))
        # Only keep valid fields for Vulnerability
        vuln_fields = {
            "target_id", "execution_id", "tools_used", "configuration", "scan_type", "scan_targets", "total_findings", "critical_findings", "high_findings", "medium_findings", "low_findings", "info_findings", "raw_output", "processed_data", "execution_time", "errors"
        }
        filtered_data = {k: v for k, v in data.items() if k in vuln_fields}
        if "execution_id" in filtered_data and isinstance(filtered_data["execution_id"], UUID):
            filtered_data["execution_id"] = str(filtered_data["execution_id"])
        result = await self.vulnerability_repo.create(
            **filtered_data,
            findings=findings
        )
        return VulnerabilityResponse.model_validate(result, from_attributes=True)
    
    async def create_kill_chain_result(self, payload: KillChainCreate) -> KillChainResponse:
        """
        Create a new kill chain analysis result.
        
        Args:
            payload: Kill chain result data
            
        Returns:
            Created kill chain result response
        """
        # Validate target exists
        await self._validate_target_exists(payload.target_id)
        
        # Create kill chain result
        result = await self.kill_chain_repo.create(**payload.model_dump())
        return KillChainResponse.model_validate(result, from_attributes=True)
    
    async def get_target_results_summary(self, target_id: UUID) -> Dict[str, Any]:
        """
        Get a comprehensive summary of all results for a target.
        
        Args:
            target_id: Target UUID
            
        Returns:
            Target results summary
        """
        # Validate target exists
        await self._validate_target_exists(target_id)
        
        # Get counts for each result type
        passive_recon_count = await self.passive_recon_repo.count_by_target(target_id)
        active_recon_count = await self.active_recon_repo.count_by_target(target_id)
        vulnerability_count = await self.vulnerability_repo.count_by_target(target_id)
        kill_chain_count = await self.kill_chain_repo.count_by_target(target_id)
        
        # Get latest results
        latest_passive_recon = await self.passive_recon_repo.get_latest_by_target(target_id)
        latest_active_recon = await self.active_recon_repo.get_latest_by_target(target_id)
        latest_vulnerability = await self.vulnerability_repo.get_latest_by_target(target_id)
        latest_kill_chain = await self.kill_chain_repo.get_latest_by_target(target_id)
        
        summary = {
            "target_id": str(target_id),
            "statistics": {
                "passive_recon_results": passive_recon_count,
                "active_recon_results": active_recon_count,
                "vulnerability_findings": vulnerability_count,
                "kill_chain_paths": kill_chain_count,
            },
            "latest_results": {
                "passive_recon": latest_passive_recon.created_at if latest_passive_recon else None,
                "active_recon": latest_active_recon.created_at if latest_active_recon else None,
                "vulnerability": latest_vulnerability.created_at if latest_vulnerability else None,
                "kill_chain": latest_kill_chain.created_at if latest_kill_chain else None,
            },
            "last_updated": datetime.utcnow().isoformat()
        }
        
        return summary
    
    async def get_passive_recon_results(
        self,
        target_id: UUID,
        page: int = 1,
        per_page: int = 10
    ) -> Dict[str, Any]:
        """
        Get passive reconnaissance results for a target.
        
        Args:
            target_id: Target UUID
            page: Page number
            per_page: Items per page
            
        Returns:
            Paginated passive recon results
        """
        # Validate target exists
        await self._validate_target_exists(target_id)
        
        # Get results with pagination
        results, total = await self.passive_recon_repo.list_by_target_with_pagination(
            target_id, page=page, per_page=per_page
        )
        
        return {
            "results": [PassiveReconResultResponse.model_validate(result, from_attributes=True) for result in results],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page
            }
        }
    
    async def get_active_recon_results(
        self,
        target_id: UUID,
        page: int = 1,
        per_page: int = 10
    ) -> Dict[str, Any]:
        """
        Get active reconnaissance results for a target.
        
        Args:
            target_id: Target UUID
            page: Page number
            per_page: Items per page
            
        Returns:
            Paginated active recon results
        """
        # Validate target exists
        await self._validate_target_exists(target_id)
        
        # Get results with pagination
        results, total = await self.active_recon_repo.list_by_target_with_pagination(
            target_id, page=page, per_page=per_page
        )
        
        return {
            "results": [ActiveReconResultResponse.model_validate(result, from_attributes=True) for result in results],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page
            }
        }
    
    async def get_vulnerability_findings(
        self,
        target_id: UUID,
        page: int = 1,
        per_page: int = 10,
        severity: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get vulnerability findings for a target.
        
        Args:
            target_id: Target UUID
            page: Page number
            per_page: Items per page
            severity: Filter by severity
            
        Returns:
            Paginated vulnerability findings
        """
        # Validate target exists
        await self._validate_target_exists(target_id)
        
        # Get results with pagination and filtering
        results, total = await self.vulnerability_repo.list_by_target_with_pagination(
            target_id, page=page, per_page=per_page, severity=severity
        )
        
        return {
            "findings": [VulnerabilityResponse.model_validate(result, from_attributes=True) for result in results],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page
            }
        }
    
    async def get_kill_chain_results(
        self,
        target_id: UUID,
        page: int = 1,
        per_page: int = 10
    ) -> Dict[str, Any]:
        """
        Get kill chain analysis results for a target.
        
        Args:
            target_id: Target UUID
            page: Page number
            per_page: Items per page
            
        Returns:
            Paginated kill chain results
        """
        # Validate target exists
        await self._validate_target_exists(target_id)
        
        # Get results with pagination
        results, total = await self.kill_chain_repo.list_by_target_with_pagination(
            target_id, page=page, per_page=per_page
        )
        
        return {
            "results": [KillChainResponse.model_validate(result, from_attributes=True) for result in results],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page
            }
        }
    
    async def _validate_target_exists(self, target_id: UUID) -> None:
        """
        Validate that a target exists.
        
        Args:
            target_id: Target UUID
            
        Raises:
            NotFoundError: If target not found
        """
        # TODO: Implement target validation
        # This would typically check against the target repository
        # For now, we'll assume the target exists
        pass 