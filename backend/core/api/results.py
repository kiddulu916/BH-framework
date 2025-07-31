"""
Results API endpoints for the Bug Hunting Framework.

This module contains Django Ninja API endpoints for stage result submission,
including passive recon, active recon, vulnerability, and kill chain results.
"""

from typing import Optional
from uuid import UUID

from ninja import Router, File, Form
from ninja.files import UploadedFile
from ninja.security import HttpBearer
from django.http import HttpRequest, JsonResponse
import jwt
import os
from datetime import datetime, timezone

from core.schemas.base import APIResponse
from core.schemas.passive_recon import (
    PassiveReconResultCreate, PassiveReconResultCreateResponse,
    WHOISRecordCreate, CertificateLogCreate, RepositoryFindingCreate,
    SearchDorkResultCreate, BreachRecordCreate, InfrastructureExposureCreate,
    ArchiveFindingCreate, SocialMediaIntelCreate, CloudAssetCreate
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

router = Router(tags=["Passive Recon"])

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        """
        Decode and validate JWT. Checks signature and expiry.
        """
        try:
            print(f"[DEBUG] JWT Auth: Attempting to decode token: {token[:20]}...")
            print(f"[DEBUG] JWT Auth: Using secret: {JWT_SECRET[:20]}...")
            print(f"[DEBUG] JWT Auth: Using algorithm: {JWT_ALGORITHM}")
            
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            print(f"[DEBUG] JWT Auth: Decoded payload: {payload}")
            
            exp = payload.get("exp")
            if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
                print(f"[DEBUG] JWT Auth: Token expired")
                return None
            print(f"[DEBUG] JWT Auth: Authentication successful")
            # Optionally, check claims/roles here
            return payload
        except Exception as e:
            print(f"[DEBUG] JWT Auth: Authentication failed with error: {e}")
            return None

auth = JWTAuth()

@router.post("/passive-recon", auth=auth, response=APIResponse, summary="Submit enhanced passive recon results", description="Accepts comprehensive passive recon results including all OSINT data types as JSON, validates, and stores them.\n\nSupports enhanced OSINT data: WHOIS records, certificate logs, repository findings, search dork results, breach records, infrastructure exposures, archive findings, social media intelligence, and cloud assets.\n\nAll data is properly linked to target_id for framework integration.")
async def submit_passive_recon_result(request, payload: PassiveReconResultCreate):
    """
    Accept comprehensive passive recon results as JSON.
    
    Enhanced to support all OSINT data types:
    - WHOIS records and domain information
    - Certificate transparency logs
    - Repository findings and secrets
    - Search engine dorking results
    - Data breach records
    - Infrastructure exposure data
    - Archive and historical findings
    - Social media intelligence
    - Cloud asset discoveries
    
    All data is properly linked to target_id for seamless framework integration.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_enhanced_passive_recon_result(payload)
            return APIResponse(success=True, message="Enhanced passive recon results saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save enhanced passive recon results", errors=[str(e)])

@router.post("/passive-recon/raw", auth=auth, response=APIResponse, summary="Submit raw passive recon output", description="Accepts raw passive recon output as a file upload, validates, and stores it.")
def submit_passive_recon_raw(request, file: UploadedFile = File(...), tool: str = Form(...), target: str = Form(...)):
    """
    Accept raw passive recon output as a file upload.
    """
    try:
        # Save file to disk or storage (implement as needed)
        file_path = f"/outputs/passive_recon/{target}/{tool}_raw_{file.name}"
        with open(file_path, "wb") as out:
            for chunk in file.chunks():
                out.write(chunk)
        # Optionally, link file to DB/model here
        return APIResponse(success=True, message="Raw output saved", data={"file_path": file_path})
    except Exception as e:
        return APIResponse(success=False, message="Failed to save raw output", errors=[str(e)])

# Enhanced OSINT Data Endpoints
@router.post("/passive-recon/whois", auth=auth, response=APIResponse, summary="Submit WHOIS records")
async def submit_whois_records(request, payload: WHOISRecordCreate):
    """Submit WHOIS record data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_whois_record(payload)
            return APIResponse(success=True, message="WHOIS record saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save WHOIS record", errors=[str(e)])

@router.post("/passive-recon/certificates", auth=auth, response=APIResponse, summary="Submit certificate transparency logs")
async def submit_certificate_logs(request, payload: CertificateLogCreate):
    """Submit certificate transparency log data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_certificate_log(payload)
            return APIResponse(success=True, message="Certificate log saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save certificate log", errors=[str(e)])

@router.post("/passive-recon/repositories", auth=auth, response=APIResponse, summary="Submit repository findings")
async def submit_repository_findings(request, payload: RepositoryFindingCreate):
    """Submit repository finding data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_repository_finding(payload)
            return APIResponse(success=True, message="Repository finding saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save repository finding", errors=[str(e)])

@router.post("/passive-recon/search-dorks", auth=auth, response=APIResponse, summary="Submit search engine dorking results")
async def submit_search_dork_results(request, payload: SearchDorkResultCreate):
    """Submit search engine dorking results."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_search_dork_result(payload)
            return APIResponse(success=True, message="Search dork result saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save search dork result", errors=[str(e)])

@router.post("/passive-recon/breaches", auth=auth, response=APIResponse, summary="Submit data breach records")
async def submit_breach_records(request, payload: BreachRecordCreate):
    """Submit data breach record data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_breach_record(payload)
            return APIResponse(success=True, message="Breach record saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save breach record", errors=[str(e)])

@router.post("/passive-recon/infrastructure", auth=auth, response=APIResponse, summary="Submit infrastructure exposure data")
async def submit_infrastructure_exposures(request, payload: InfrastructureExposureCreate):
    """Submit infrastructure exposure data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_infrastructure_exposure(payload)
            return APIResponse(success=True, message="Infrastructure exposure saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save infrastructure exposure", errors=[str(e)])

@router.post("/passive-recon/archives", auth=auth, response=APIResponse, summary="Submit archive findings")
async def submit_archive_findings(request, payload: ArchiveFindingCreate):
    """Submit archive and historical data findings."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_archive_finding(payload)
            return APIResponse(success=True, message="Archive finding saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save archive finding", errors=[str(e)])

@router.post("/passive-recon/social-media", auth=auth, response=APIResponse, summary="Submit social media intelligence")
async def submit_social_media_intel(request, payload: SocialMediaIntelCreate):
    """Submit social media intelligence data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_social_media_intel(payload)
            return APIResponse(success=True, message="Social media intelligence saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save social media intelligence", errors=[str(e)])

@router.post("/passive-recon/cloud-assets", auth=auth, response=APIResponse, summary="Submit cloud asset discoveries")
async def submit_cloud_assets(request, payload: CloudAssetCreate):
    """Submit cloud asset discovery data."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            result = await result_service.create_cloud_asset(payload)
            return APIResponse(success=True, message="Cloud asset saved", data=result.model_dump())
    except Exception as e:
        return APIResponse(success=False, message="Failed to save cloud asset", errors=[str(e)])

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


@router.post("/vulnerabilities/", response=VulnerabilityCreateResponse, summary="Submit vulnerability findings (alias)")
async def submit_vulnerability_findings_alias(request: HttpRequest, payload: VulnerabilityCreate):
    return await submit_vulnerability_findings(request, payload)


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
        import traceback
        import sys
        print("[DEBUG] Kill chain submission error:", file=sys.stderr)
        traceback.print_exc()
        print(f"[DEBUG] Exception: {e}", file=sys.stderr)
        if hasattr(e, 'errors'):
            print(f"[DEBUG] Pydantic errors: {e.errors()}", file=sys.stderr)
        return KillChainCreateResponse(
            success=False,
            message="Failed to submit kill chain analysis results",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/summary", response=APIResponse, summary="Get enhanced target results summary")
async def get_target_results_summary(request: HttpRequest, target_id: UUID):
    """
    Get an enhanced summary of all results for a specific target.
    Returns aggregated information about reconnaissance results,
    vulnerability findings, and kill chain analysis for the target.
    
    Enhanced to include comprehensive OSINT data summaries.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            summary = await result_service.get_enhanced_target_results_summary(target_id)
            return APIResponse(
                success=True,
                message="Enhanced target results summary retrieved successfully",
                data=summary,
                errors=None
            )
    except Exception as e:
        # If the error is NotFoundError, return success: False
        if hasattr(e, 'args') and e.args and 'not found' in str(e.args[0]).lower():
            return APIResponse(
                success=False,
                message="Target not found",
                data=None,
                errors=[str(e)]
            )
        return APIResponse(
            success=False,
            message="Failed to retrieve enhanced target results summary",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/passive-recon", response=APIResponse, summary="Get enhanced passive reconnaissance results")
async def get_passive_recon_results(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10,
    category: Optional[str] = None
):
    """
    Get enhanced passive reconnaissance results for a specific target.
    
    Returns paginated list of passive reconnaissance results
    with filtering and sorting options.
    
    Enhanced to support category filtering for different OSINT types.
    """
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_enhanced_passive_recon_results(
                target_id, page=page, per_page=per_page, category=category
            )
            
            return APIResponse(
                success=True,
                message="Enhanced passive reconnaissance results retrieved successfully",
                data=results,
                errors=None
            )
    except Exception as e:
        return APIResponse(
            success=False,
            message="Failed to retrieve enhanced passive reconnaissance results",
            data=None,
            errors=[str(e)]
        )


@router.get("/{target_id}/passive-recon/whois", response=APIResponse, summary="Get WHOIS records")
async def get_whois_records(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get WHOIS records for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_whois_records(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="WHOIS records retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve WHOIS records", errors=[str(e)])


@router.get("/{target_id}/passive-recon/certificates", response=APIResponse, summary="Get certificate logs")
async def get_certificate_logs(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get certificate transparency logs for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_certificate_logs(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Certificate logs retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve certificate logs", errors=[str(e)])


@router.get("/{target_id}/passive-recon/repositories", response=APIResponse, summary="Get repository findings")
async def get_repository_findings(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get repository findings for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_repository_findings(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Repository findings retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve repository findings", errors=[str(e)])


@router.get("/{target_id}/passive-recon/search-dorks", response=APIResponse, summary="Get search dork results")
async def get_search_dork_results(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get search engine dorking results for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_search_dork_results(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Search dork results retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve search dork results", errors=[str(e)])


@router.get("/{target_id}/passive-recon/breaches", response=APIResponse, summary="Get breach records")
async def get_breach_records(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get data breach records for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_breach_records(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Breach records retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve breach records", errors=[str(e)])


@router.get("/{target_id}/passive-recon/infrastructure", response=APIResponse, summary="Get infrastructure exposures")
async def get_infrastructure_exposures(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get infrastructure exposure data for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_infrastructure_exposures(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Infrastructure exposures retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve infrastructure exposures", errors=[str(e)])


@router.get("/{target_id}/passive-recon/archives", response=APIResponse, summary="Get archive findings")
async def get_archive_findings(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get archive and historical findings for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_archive_findings(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Archive findings retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve archive findings", errors=[str(e)])


@router.get("/{target_id}/passive-recon/social-media", response=APIResponse, summary="Get social media intelligence")
async def get_social_media_intel(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get social media intelligence for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_social_media_intel(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Social media intelligence retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve social media intelligence", errors=[str(e)])


@router.get("/{target_id}/passive-recon/cloud-assets", response=APIResponse, summary="Get cloud assets")
async def get_cloud_assets(
    request: HttpRequest,
    target_id: UUID,
    page: int = 1,
    per_page: int = 10
):
    """Get cloud asset discoveries for a specific target."""
    try:
        async with get_db_session() as session:
            result_service = ResultService(session)
            results = await result_service.get_cloud_assets(target_id, page=page, per_page=per_page)
            return APIResponse(success=True, message="Cloud assets retrieved successfully", data=results)
    except Exception as e:
        return APIResponse(success=False, message="Failed to retrieve cloud assets", errors=[str(e)])


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