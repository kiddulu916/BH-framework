"""
Result service for the Bug Hunting Framework.

This module contains business logic for result processing operations,
including handling stage results from various tools and containers.
"""

from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository
from core.schemas.passive_recon import PassiveReconResultCreate, PassiveReconResultResponse
from core.schemas.active_recon import ActiveReconResultCreate, ActiveReconResultResponse
from core.schemas.vulnerability import VulnerabilityCreate, VulnerabilityResponse
from core.schemas.kill_chain import KillChainCreate, KillChainResponse
from core.utils.exceptions import NotFoundError, ValidationError


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
                if 'sources' in subdomain and subdomain['sources']:
                    subdomain['sources'] = [source.lower() for source in subdomain['sources']]
        
        return PassiveReconResultResponse.model_validate(result_dict)
    
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
        
        # Create active recon result
        result = await self.active_recon_repo.create(**payload.model_dump())
        return ActiveReconResultResponse.model_validate(result, from_attributes=True)
    
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
        
        # Create vulnerability result
        result = await self.vulnerability_repo.create(**payload.model_dump())
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