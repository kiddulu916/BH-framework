"""
Result service for the Bug Hunting Framework.

This module contains business logic for result processing operations,
including handling stage results from various tools and containers.
"""

import logging
import json
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import SQLAlchemyError

from core.repositories.passive_recon import PassiveReconRepository
from core.repositories.active_recon import ActiveReconRepository, PortRepository, ServiceRepository
from core.repositories.vulnerability import VulnerabilityRepository
from core.repositories.kill_chain import KillChainRepository, AttackPathRepository
from core.repositories.workflow import WorkflowRepository
from core.schemas.passive_recon import PassiveReconResultCreate, PassiveReconResultResponse, SubdomainResponse
from core.schemas.active_recon import ActiveReconResultCreate, ActiveReconResultResponse, PortResponse, ServiceResponse
from core.schemas.vulnerability import VulnerabilityCreate, VulnerabilityResponse
from core.schemas.kill_chain import KillChainCreate, KillChainResponse
from core.schemas.workflow import StageStatus
from core.utils.exceptions import NotFoundError, ValidationError
from core.models.active_recon import Port, Service, PortStatus, ServiceStatus, ActiveReconResult
from core.models.vulnerability import VulnerabilityFinding
from core.models.passive_recon import SubdomainStatus

logger = logging.getLogger(__name__)

class ResultService:
    """Service class for result processing operations."""
    
    def __init__(self, session: AsyncSession):
        """Initialize the result service with a database session."""
        self.session = session
        self.passive_recon_repo = PassiveReconRepository(session)
        self.active_recon_repo = ActiveReconRepository(session)
        self.port_repo = PortRepository(session)
        self.service_repo = ServiceRepository(session)
        self.vulnerability_repo = VulnerabilityRepository(session)
        self.kill_chain_repo = KillChainRepository(session)
        self.attack_path_repo = AttackPathRepository(session)
        self.workflow_repo = WorkflowRepository(session)
    
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
        # Ensure execution_time is a string
        if "execution_time" in data and not isinstance(data["execution_time"], str):
            data["execution_time"] = str(data["execution_time"])
        # Convert execution_id to string if it's a UUID
        if "execution_id" in data and isinstance(data["execution_id"], UUID):
            data["execution_id"] = str(data["execution_id"])
        subdomains = data.pop('subdomains', [])
        # Convert subdomain status to enum before saving; normalize source to lowercase string
        for subdomain in subdomains:
            if 'status' in subdomain and isinstance(subdomain['status'], str):
                try:
                    subdomain['status'] = SubdomainStatus(subdomain['status'].lower())
                except Exception:
                    pass
            if 'source' in subdomain and subdomain['source']:
                subdomain['source'] = str(subdomain['source']).lower()
        result = await self.passive_recon_repo.create_with_subdomains(subdomains=subdomains, **data)
        
        # Update workflow stage status to completed
        await self._update_workflow_stage_status(payload.execution_id, "PASSIVE_RECON", StageStatus.COMPLETED)
        
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
                    status_value = subdomain['status']
                    if hasattr(status_value, 'value'):
                        subdomain['status'] = status_value.value.lower()
                    else:
                        subdomain['status'] = str(status_value).lower()
                if 'source' in subdomain and subdomain['source']:
                    source_value = subdomain['source']
                    if hasattr(source_value, 'value'):
                        subdomain['source'] = source_value.value.lower()
                    else:
                        subdomain['source'] = str(source_value).lower()
        
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
        
        data = payload.model_dump()
        # Ensure execution_time is a float
        if "execution_time" in data and not isinstance(data["execution_time"], float):
            try:
                data["execution_time"] = float(data["execution_time"])
            except Exception:
                data["execution_time"] = 0.0
        # Convert execution_id to string if it's a UUID
        if "execution_id" in data and isinstance(data["execution_id"], UUID):
            data["execution_id"] = str(data["execution_id"])
        # Explicitly convert all string fields to str
        string_fields = ["execution_id", "scan_type"]
        for field in string_fields:
            if field in data and data[field] is not None and not isinstance(data[field], str):
                data[field] = str(data[field])
        ports_data = data.pop('ports', [])
        services_data = data.pop('services', [])
        # Convert tools_used enums to strings if present
        if "tools_used" in data and isinstance(data["tools_used"], list):
            data["tools_used"] = [t.value if hasattr(t, 'value') else str(t) for t in data["tools_used"]]
        
        # JSONB fields should be passed as native Python types (list/dict), not JSON strings
        # SQLAlchemy will handle the serialization automatically
        
        # Only keep valid fields for ActiveReconResult
        active_recon_fields = {
            "target_id", "execution_id", "tools_used", "hosts_scanned", "raw_output", "processed_data", "execution_time", "errors", "configuration", "scan_type",
            "total_hosts_scanned", "hosts_with_open_ports", "total_open_ports", "total_services_detected"
        }
        filtered_data = {k: v for k, v in data.items() if k in active_recon_fields}
        if "execution_id" in filtered_data and isinstance(filtered_data["execution_id"], UUID):
            filtered_data["execution_id"] = str(filtered_data["execution_id"])
        # Explicitly convert all string fields to str in filtered_data
        for field in string_fields:
            if field in filtered_data and filtered_data[field] is not None and not isinstance(filtered_data[field], str):
                filtered_data[field] = str(filtered_data[field])
        
        # Create the ActiveReconResult first
        print(f"DEBUG: Creating ActiveReconResult with filtered_data: {filtered_data}")
        print(f"DEBUG: Type of hosts_scanned: {type(filtered_data.get('hosts_scanned'))}")
        print(f"DEBUG: Value of hosts_scanned: {filtered_data.get('hosts_scanned')}")
        result = await self.active_recon_repo.create(**filtered_data)
        
        # Now create the Port objects with the proper foreign key relationship
        for port_data in ports_data:
            if "status" in port_data and isinstance(port_data["status"], str):
                port_data["status"] = PortStatus(port_data["status"])
            # Map 'port' to 'port_number' if present
            if "port" in port_data and "port_number" not in port_data:
                port_data["port_number"] = port_data.pop("port")
            
            # Add the foreign key relationship
            port_data["active_recon_result_id"] = result.id
            
            # Filter to only include valid port fields
            port_fields = {
                "host", "port_number", "protocol", "status", "is_open",
                "service_name", "service_version", "service_product",
                "banner", "script_output", "notes", "active_recon_result_id"
            }
            filtered_port_data = {k: v for k, v in port_data.items() if k in port_fields}
            
            # Create the Port object
            port = await self.port_repo.create(**filtered_port_data)
            
            # Create associated Service objects if any
            port_services = [s for s in services_data if s.get("port_id") == port_data.get("id")]
            for service_data in port_services:
                # Robust mapping: if 'name' is missing but 'service_name' is present, use it
                if 'name' not in service_data and 'service_name' in service_data:
                    service_data['name'] = service_data['service_name']
                service_data["port_id"] = port.id
                service_data["active_recon_result_id"] = result.id
                
                # Filter to only include valid service fields
                service_fields = {
                    "name", "version", "product", "extrainfo", "status", "is_confirmed",
                    "banner", "fingerprint", "cpe", "tags", "notes", "port_id", "active_recon_result_id"
                }
                filtered_service_data = {k: v for k, v in service_data.items() if k in service_fields}
                
                # Convert status to enum if it's a string
                if "status" in filtered_service_data and isinstance(filtered_service_data["status"], str):
                    filtered_service_data["status"] = ServiceStatus(filtered_service_data["status"])
                
                await self.service_repo.create(**filtered_service_data)
        
        # Update workflow stage status to completed
        await self._update_workflow_stage_status(payload.execution_id, "ACTIVE_RECON", StageStatus.COMPLETED)
        
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
        # Robust mapping for ServiceResponse
        service_responses = []
        for service in result.services:
            sdict = service.to_dict() if hasattr(service, 'to_dict') else dict(service)
            # Map 'name' to 'service_name'
            sdict['service_name'] = sdict.get('name')
            # Map 'status' to 'state' for ServiceResponse
            status = sdict.get('status')
            if status in ('detected', 'confirmed'):
                sdict['state'] = 'open'
            elif status == 'unknown':
                sdict['state'] = 'filtered'
            else:
                sdict['state'] = status or 'filtered'
            # Ensure host, port, protocol, etc. are present (from related port if needed)
            if not sdict.get('host') and getattr(service, 'port', None):
                sdict['host'] = getattr(service.port, 'host', None)
            if not sdict.get('port') and getattr(service, 'port', None):
                sdict['port'] = getattr(service.port, 'port_number', None)
            if not sdict.get('protocol') and getattr(service, 'port', None):
                sdict['protocol'] = getattr(service.port, 'protocol', None)
            # target_id from service.active_recon_result or service.port
            if not sdict.get('target_id'):
                sdict['target_id'] = (
                    getattr(getattr(service, 'active_recon_result', None), 'target_id', None)
                    or (getattr(service.port, 'target_id', None) if getattr(service, 'port', None) else None)
                )
            # Fill in any other required fields with None if missing
            for field in ['host', 'port', 'protocol', 'service_name', 'state', 'target_id']:
                if field not in sdict:
                    sdict[field] = None
            service_responses.append(ServiceResponse.model_validate(sdict).model_dump())
        response_dict["services"] = service_responses
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
        await self._validate_target_exists(payload.target_id)
        data = payload.model_dump()
        # Ensure execution_time is a string
        if "execution_time" in data and not isinstance(data["execution_time"], str):
            data["execution_time"] = str(data["execution_time"])
        
        # Convert execution_id to string if it's a UUID
        if "execution_id" in data and isinstance(data["execution_id"], UUID):
            data["execution_id"] = str(data["execution_id"])
        
        # Map schema field names to model field names
        field_mapping = {
            'critical_count': 'critical_findings',
            'high_count': 'high_findings',
            'medium_count': 'medium_findings',
            'low_count': 'low_findings',
            'info_count': 'info_findings',
            'scan_config': 'configuration'
        }
        
        # Apply field mapping
        for old_key, new_key in field_mapping.items():
            if old_key in data:
                data[new_key] = data.pop(old_key)
        
        findings_data = data.pop('findings', [])
        findings = []
        for finding in findings_data:
            def enum_to_value(val):
                if hasattr(val, 'value'):
                    val_str = val.value if hasattr(val, 'value') else str(val)
                else:
                    val_str = str(val)
                
                # Convert schema enum values to database enum values
                # Vulnerability types
                if val_str == "sql_injection":
                    return "SQL_INJECTION"
                elif val_str == "other":
                    return "OTHER"
                elif val_str == "xss":
                    return "XSS"
                elif val_str == "csrf":
                    return "CSRF"
                elif val_str == "ssrf":
                    return "SSRF"
                elif val_str == "rce":
                    return "RCE"
                elif val_str == "lfi":
                    return "LFI"
                elif val_str == "rfi":
                    return "RFI"
                elif val_str == "idor":
                    return "IDOR"
                elif val_str == "broken_auth":
                    return "BROKEN_AUTH"
                elif val_str == "sensitive_data_exposure":
                    return "SENSITIVE_DATA_EXPOSURE"
                elif val_str == "security_misconfiguration":
                    return "SECURITY_MISCONFIGURATION"
                elif val_str == "insecure_deserialization":
                    return "INSECURE_DESERIALIZATION"
                elif val_str == "components_with_known_vulnerabilities":
                    return "COMPONENTS_WITH_KNOWN_VULNERABILITIES"
                elif val_str == "insufficient_logging":
                    return "INSUFFICIENT_LOGGING"
                # Severity levels
                elif val_str == "critical":
                    return "CRITICAL"
                elif val_str == "high":
                    return "HIGH"
                elif val_str == "medium":
                    return "MEDIUM"
                elif val_str == "low":
                    return "LOW"
                elif val_str == "info":
                    return "INFO"
                # Status values
                elif val_str == "open":
                    return "OPEN"
                elif val_str == "verified":
                    return "VERIFIED"
                elif val_str == "false_positive":
                    return "FALSE_POSITIVE"
                elif val_str == "fixed":
                    return "FIXED"
                elif val_str == "wont_fix":
                    return "WONT_FIX"
                elif val_str == "duplicate":
                    return "DUPLICATE"
                else:
                    return val_str
            mapped = {
                'title': finding.get('title'),
                'vuln_type': enum_to_value(finding.get('vulnerability_type')),
                'severity': enum_to_value(finding.get('severity')),
                'status': enum_to_value(finding.get('status')),
                'description': finding.get('description'),
                'cve_id': finding.get('cve_id'),
                'cvss_score': finding.get('cvss_score'),
                'cvss_vector': finding.get('cvss_vector'),
                'affected_host': finding.get('host'),
                'affected_port': finding.get('port'),
                'affected_service': finding.get('service'),
                'affected_url': finding.get('url'),
                'proof_of_concept': finding.get('payload'),
                'remediation': finding.get('remediation'),
                'references': finding.get('references', []),
                'detection_tool': enum_to_value(finding.get('tool')),
                'detection_method': finding.get('detection_method'),
                'confidence': finding.get('confidence'),
                'is_verified': finding.get('is_verified', False),
                'verification_notes': finding.get('verification_notes'),
                'tags': finding.get('tags', []),
                'notes': finding.get('notes')
            }
            findings.append(mapped)
        result = await self.vulnerability_repo.create_with_findings(findings=findings, **data)
        # Update workflow stage status to completed
        # Determine stage based on tools used
        stage_name = "VULN_SCAN"  # Default to VULN_SCAN
        testing_tools = ["sqlmap", "ffuf", "custom"]  # Tools typically used for testing
        if any(tool.lower() in [t.lower() for t in testing_tools] for tool in payload.tools_used):
            stage_name = "VULN_TEST"
        
        await self._update_workflow_stage_status(payload.execution_id, stage_name, StageStatus.COMPLETED)
        result = await self.vulnerability_repo.get_by_id(result.id, include_relationships=['findings'])
        
        # Create a response that maps model fields to schema fields
        response_data = {
            'id': result.id,
            'target_id': result.target_id,
            'execution_id': result.execution_id,
            'tools_used': result.tools_used or [],
            'findings': [],
            'total_findings': result.total_findings,
            'critical_count': result.critical_findings,
            'high_count': result.high_findings,
            'medium_count': result.medium_findings,
            'low_count': result.low_findings,
            'info_count': result.info_findings,
            'execution_time': result.execution_time,
            'scan_config': result.configuration or {},
            'raw_output': result.raw_output or {},
            'metadata': result.metadata or {},
            'created_at': result.created_at,
            'updated_at': result.updated_at
        }
        
        # Map findings to schema format
        for finding in result.findings:
            finding_data = {
                'id': finding.id,
                'target_id': payload.target_id,  # Use the target_id from payload
                'vulnerability_id': finding.vulnerability_id,
                'title': finding.title,
                'description': finding.description or '',
                'severity': finding.severity.value.lower(),  # Convert to lowercase for schema
                'status': finding.status.value.lower(),  # Convert to lowercase for schema
                'vulnerability_type': finding.vuln_type.value.lower(),  # Convert to lowercase for schema
                'tool': finding.detection_tool or 'custom',  # Use detection_tool or default
                'host': finding.affected_host or '',
                'port': finding.affected_port,
                'url': finding.affected_url,
                'parameter': None,  # Not in model
                'payload': finding.proof_of_concept,
                'evidence': finding.proof_of_concept,  # Use proof_of_concept as evidence
                'cve_id': finding.cve_id,
                'cvss_score': finding.cvss_score,
                'cvss_vector': finding.cvss_vector,
                'references': finding.references or [],
                'tags': finding.tags or [],
                'metadata': {},  # Not in model
                'created_at': finding.created_at,
                'updated_at': finding.updated_at
            }
            response_data['findings'].append(finding_data)
        
        return VulnerabilityResponse.model_validate(response_data)
    
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
        
        # Extract attack paths from payload
        attack_paths_data = payload.attack_paths
        kill_chain_data = payload.model_dump(exclude={'attack_paths'})
        
        # Map schema field names to model field names
        field_mapping = {
            'total_attack_paths': 'total_paths_identified',
            'analysis_config': 'analysis_config',
            'raw_output': 'raw_output',
            'metadata': 'kill_chain_metadata'
        }
        
        mapped_kill_chain_data = {}
        for schema_field, model_field in field_mapping.items():
            if schema_field in kill_chain_data:
                mapped_kill_chain_data[model_field] = kill_chain_data[schema_field]
        
        # Add fields that don't need mapping
        direct_fields = ['critical_paths', 'high_paths', 'medium_paths', 'low_paths', 'info_paths', 'verified_paths', 'execution_time']
        for field in direct_fields:
            if field in kill_chain_data:
                mapped_kill_chain_data[field] = kill_chain_data[field]
        
        # Add required fields
        mapped_kill_chain_data['target_id'] = payload.target_id
        if payload.execution_id:
            mapped_kill_chain_data['execution_id'] = str(payload.execution_id)
        
        # Create kill chain result
        kill_chain = await self.kill_chain_repo.create(**mapped_kill_chain_data)
        
        # Create attack paths if provided
        attack_paths = []
        if attack_paths_data:
            for attack_path_data in attack_paths_data:
                attack_path_dict = attack_path_data.model_dump()
                attack_path_dict['kill_chain_id'] = kill_chain.id
                
                # Map attack path schema fields to model fields
                attack_path_field_mapping = {
                    'name': 'name',
                    'description': 'description',
                    'attack_path_type': 'attack_path_type',
                    'severity': 'severity',
                    'status': 'status',
                    'stages': 'stages',
                    'entry_points': 'entry_points',
                    'exit_points': 'exit_points',
                    'prerequisites': 'prerequisites',
                    'techniques': 'techniques',
                    'tools_required': 'tools_required',
                    'evidence': 'evidence',
                    'proof_of_concept': 'proof_of_concept',
                    'screenshots': 'screenshots',
                    'risk_score': 'risk_score',
                    'impact_assessment': 'impact_assessment',
                    'remediation': 'remediation',
                    'metadata': 'attack_path_metadata'
                }
                
                mapped_attack_path_data = {}
                for schema_field, model_field in attack_path_field_mapping.items():
                    if schema_field in attack_path_dict:
                        mapped_attack_path_data[model_field] = attack_path_dict[schema_field]
                
                # Add required fields
                mapped_attack_path_data['kill_chain_id'] = kill_chain.id
                
                # Convert enum fields to their .value or uppercase string
                enum_fields = ['status', 'attack_path_type', 'severity']
                for field in enum_fields:
                    if field in mapped_attack_path_data:
                        val = mapped_attack_path_data[field]
                        if hasattr(val, 'value'):
                            mapped_attack_path_data[field] = val.value.upper()
                        elif isinstance(val, str):
                            mapped_attack_path_data[field] = val.upper()
                # Convert lists of enums (e.g., stages) to list of values
                if 'stages' in mapped_attack_path_data and isinstance(mapped_attack_path_data['stages'], list):
                    mapped_attack_path_data['stages'] = [s.value if hasattr(s, 'value') else s for s in mapped_attack_path_data['stages']]
                
                # Debug: Print the mapped attack path data before creating
                print(f"Debug: mapped_attack_path_data: {mapped_attack_path_data}")
                for k, v in mapped_attack_path_data.items():
                    print(f"  {k}: type={type(v)}, value={v}")
                
                attack_path = await self.attack_path_repo.create(**mapped_attack_path_data)
                attack_paths.append(attack_path)
        
        # Update workflow stage status if execution_id is provided
        if payload.execution_id:
            await self._update_workflow_stage_status(
                payload.execution_id, 
                'KILL_CHAIN', 
                StageStatus.COMPLETED
            )
        
        # Debug: Print only the most likely problematic fields for the first attack path
        if attack_paths:
            ap = attack_paths[0]
            print(f"Debug: AttackPath object type: {type(ap)}")
            print(f"Debug: AttackPath object: {ap}")
            
            # Check the most likely problematic fields
            problematic_fields = ['status', 'attack_path_type', 'severity', 'stages', 'entry_points', 'exit_points', 'prerequisites', 'techniques', 'tools_required']
            for field in problematic_fields:
                try:
                    value = getattr(ap, field, None)
                    print(f"  {field}: type={type(value)}, value={value}")
                except Exception as e:
                    print(f"  {field}: ERROR accessing field: {e}")
        
        # Continue with response construction
        response_data = {
            'id': kill_chain.id,
            'target_id': kill_chain.target_id,
            'execution_id': kill_chain.execution_id,
            'attack_paths': [
                {
                    'id': ap.id,
                    'target_id': kill_chain.target_id,  # Use parent kill chain's target_id
                    'kill_chain_id': ap.kill_chain_id,
                    'name': ap.name,
                    'description': ap.description,
                    'attack_path_type': getattr(ap, 'attack_path_type', '').lower() if getattr(ap, 'attack_path_type', None) else None,
                    'severity': getattr(ap, 'severity', '').lower() if getattr(ap, 'severity', None) else None,
                    'status': ap.status.value if hasattr(ap.status, 'value') else ap.status,
                    'stages': getattr(ap, 'stages', []),
                    'entry_points': getattr(ap, 'entry_points', []),
                    'exit_points': getattr(ap, 'exit_points', []),
                    'prerequisites': getattr(ap, 'prerequisites', []),
                    'techniques': getattr(ap, 'techniques', []),
                    'tools_required': getattr(ap, 'tools_required', []),
                    'evidence': getattr(ap, 'evidence', None),
                    'proof_of_concept': getattr(ap, 'proof_of_concept', None),
                    'screenshots': getattr(ap, 'screenshots', []),
                    'risk_score': ap.risk_score,
                    'impact_assessment': getattr(ap, 'impact_assessment', None),
                    'remediation': getattr(ap, 'remediation', None),
                    'metadata': getattr(ap, 'attack_path_metadata', {}),
                    'created_at': ap.created_at,
                    'updated_at': ap.updated_at
                } for ap in attack_paths
            ],
            'total_attack_paths': kill_chain.total_paths_identified,
            'critical_paths': getattr(kill_chain, 'critical_paths', 0),
            'high_paths': getattr(kill_chain, 'high_paths', 0),
            'medium_paths': getattr(kill_chain, 'medium_paths', 0),
            'low_paths': getattr(kill_chain, 'low_paths', 0),
            'info_paths': getattr(kill_chain, 'info_paths', 0),
            'verified_paths': kill_chain.verified_paths,
            'execution_time': kill_chain.execution_time,
            'analysis_config': getattr(kill_chain, 'analysis_config', {}),
            'raw_output': getattr(kill_chain, 'raw_output', {}),
            'metadata': getattr(kill_chain, 'kill_chain_metadata', {}),
            'created_at': kill_chain.created_at,
            'updated_at': kill_chain.updated_at
        }
        
        print(f"KillChainResponse input: {response_data}")  # Debug print
        for k, v in response_data.items():
            print(f"  {k}: type={type(v)}, value={v}")
        return KillChainResponse.model_validate(response_data)
    
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

        serialized_results = []
        for result in results:
            result_dict = result.to_dict() if hasattr(result, 'to_dict') else dict(result)
            # Ensure subdomains are serialized as Pydantic models
            if 'subdomains' in result_dict and result_dict['subdomains']:
                result_dict['subdomains'] = [SubdomainResponse.model_validate(sd, from_attributes=True) for sd in result_dict['subdomains']]
            serialized_results.append(PassiveReconResultResponse.model_validate(result_dict))

        return {
            "results": serialized_results,
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
        
        serialized_results = []
        for result in results:
            result_dict = result.to_dict() if hasattr(result, 'to_dict') else dict(result)
            # Ensure all required fields are present
            result_dict.setdefault('ports', [])
            result_dict.setdefault('services', [])
            result_dict.setdefault('total_ports', len(result_dict['ports']))
            result_dict.setdefault('total_services', len(result_dict['services']))
            result_dict.setdefault('hosts_scanned', [])
            result_dict.setdefault('execution_time', 0.0)
            result_dict.setdefault('scan_range', None)
            result_dict.setdefault('raw_output', {})
            result_dict.setdefault('metadata', {})
            # Serialize ports
            if result_dict['ports']:
                result_dict['ports'] = [PortResponse.model_validate(p, from_attributes=True) for p in result_dict['ports']]
            # Serialize services
            if result_dict['services']:
                result_dict['services'] = [ServiceResponse.model_validate(s, from_attributes=True) for s in result_dict['services']]
            serialized_results.append(ActiveReconResultResponse.model_validate(result_dict))
        return {
            "results": serialized_results,
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

    async def _update_workflow_stage_status(self, execution_id: UUID, stage: str, status: StageStatus) -> None:
        """
        Update the status of a workflow stage.
        
        Args:
            execution_id: Execution UUID (which is actually the workflow ID)
            stage: Stage name
            status: New stage status
        """
        try:
            logger.info(f"Attempting to update workflow {execution_id} stage {stage} to {status}")
            
            # Update workflow stage status
            await self.workflow_repo.update_stage_status(execution_id, stage, status)
            
            logger.info(f"Successfully updated workflow {execution_id} stage {stage} to {status}")
            
        except Exception as e:
            logger.error(f"Failed to update workflow stage status: {str(e)}")
            # Don't raise the exception to avoid breaking the result submission