"""
Results API endpoints for the Bug Hunting Framework.

This module contains Django Ninja API endpoints for stage result submission,
including passive recon, active recon, vulnerability, and kill chain results.
"""

from typing import Optional
from uuid import UUID

from ninja import Router
from django.http import HttpRequest

from core.schemas.base import APIResponse
from core.schemas.passive_recon import (
    PassiveReconResultCreate, PassiveReconResultCreateResponse
)
from core.schemas.active_recon import (
    ActiveReconResultCreate, ActiveReconResultCreateResponse
)
from core.schemas.vulnerability import (
    VulnerabilityCreate, VulnerabilityCreateResponse
)
from core.schemas.kill_chain import (
    KillChainCreate, KillChainCreateResponse
)
from core.tasks.result_service import ResultService
from core.utils.database import get_db_session

router = Router()


@router.post("/passive-recon", response=PassiveReconResultCreateResponse, summary="Submit passive reconnaissance results")
async def submit_passive_recon_results(request: HttpRequest, payload: PassiveReconResultCreate):
    """
    Submit passive reconnaissance results from stage containers.
    
    This endpoint accepts results from passive reconnaissance tools like
    subfinder, amass, and assetfinder, and stores them in the database.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_passive_recon_result(payload)
            
            return PassiveReconResultCreateResponse(
                success=True,
                message="Passive reconnaissance results submitted successfully",
                data=result,
                errors=None
            )
    except Exception as e:
        return PassiveReconResultCreateResponse(
            success=False,
            message="Failed to submit passive reconnaissance results",
            data=None,
            errors=[str(e)]
        )


@router.post("/active-recon", response=ActiveReconResultCreateResponse, summary="Submit active reconnaissance results")
async def submit_active_recon_results(request: HttpRequest, payload: ActiveReconResultCreate):
    """
    Submit active reconnaissance results from stage containers.
    
    This endpoint accepts results from active reconnaissance tools like
    nmap, httpx, and other port scanning tools.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_active_recon_result(payload)
            
            return ActiveReconResultCreateResponse(
                success=True,
                message="Active reconnaissance results submitted successfully",
                data=result,
                errors=None
            )
    except Exception as e:
        return ActiveReconResultCreateResponse(
            success=False,
            message="Failed to submit active reconnaissance results",
            data=None,
            errors=[str(e)]
        )


@router.post("/vulnerabilities", response=VulnerabilityCreateResponse, summary="Submit vulnerability findings")
async def submit_vulnerability_findings(request: HttpRequest, payload: VulnerabilityCreate):
    """
    Submit vulnerability findings from stage containers.
    
    This endpoint accepts vulnerability scan results from tools like
    nuclei, sqlmap, and other vulnerability scanners.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_vulnerability_result(payload)
            
            return VulnerabilityCreateResponse(
                success=True,
                message="Vulnerability findings submitted successfully",
                data=result,
                errors=None
            )
    except Exception as e:
        return VulnerabilityCreateResponse(
            success=False,
            message="Failed to submit vulnerability findings",
            data=None,
            errors=[str(e)]
        )


@router.post("/kill-chain", response=KillChainCreateResponse, summary="Submit kill chain analysis results")
async def submit_kill_chain_results(request: HttpRequest, payload: KillChainCreate):
    """
    Submit kill chain analysis results from stage containers.
    
    This endpoint accepts attack path analysis results from the
    kill chain analysis stage.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_kill_chain_result(payload)
            
            return KillChainCreateResponse(
                success=True,
                message="Kill chain analysis results submitted successfully",
                data=result,
                errors=None
            )
    except Exception as e:
        return KillChainCreateResponse(
            success=False,
            message="Failed to submit kill chain analysis results",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/summary", response=APIResponse, summary="Get target results summary")
async def get_target_results_summary(request: HttpRequest, target_id: UUID):
    """
    Get a summary of all results for a specific target.
    
    Returns aggregated information about reconnaissance results,
    vulnerability findings, and kill chain analysis for the target.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            summary = await result_service.get_target_results_summary(target_id)
            
            return APIResponse(
                success=True,
                message="Target results summary retrieved successfully",
                data=summary,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve target results summary",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/passive-recon", response=APIResponse, summary="Get passive reconnaissance results")
async def get_passive_recon_results(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """
    Get passive reconnaissance results for a specific target.
    
    Returns paginated list of passive reconnaissance results
    with filtering and sorting options.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_passive_recon_results(
                target_id, page=page, per_page=per_page
            )
            
            return APIResponse(
                success=True,
                message="Passive reconnaissance results retrieved successfully",
                data=results,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve passive reconnaissance results",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/active-recon", response=APIResponse, summary="Get active reconnaissance results")
async def get_active_recon_results(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """
    Get active reconnaissance results for a specific target.
    
    Returns paginated list of active reconnaissance results
    including port scans and service detection.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_active_recon_results(
                target_id, page=page, per_page=per_page
            )
            
            return APIResponse(
                success=True,
                message="Active reconnaissance results retrieved successfully",
                data=results,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve active reconnaissance results",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/vulnerabilities", response=APIResponse, summary="Get vulnerability findings")
async def get_vulnerability_findings(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10,
    severity: Optional[str] = None
):
    """
    Get vulnerability findings for a specific target.
    
    Returns paginated list of vulnerability findings with
    optional severity filtering.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_vulnerability_findings(
                target_id, page=page, per_page=per_page, severity=severity
            )
            
            return APIResponse(
                success=True,
                message="Vulnerability findings retrieved successfully",
                data=results,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve vulnerability findings",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/kill-chain", response=APIResponse, summary="Get kill chain analysis results")
async def get_kill_chain_results(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """
    Get kill chain analysis results for a specific target.
    
    Returns paginated list of attack paths and kill chain analysis
    results for the target.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_kill_chain_results(
                target_id, page=page, per_page=per_page
            )
            
            return APIResponse(
                success=True,
                message="Kill chain analysis results retrieved successfully",
                data=results,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve kill chain analysis results",
            data=None,
            errors=[str(e)]
        ) 