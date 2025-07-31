#!/usr/bin/env python3
"""
Data Preparer Runner for Stage 4: Step 4.1

This module implements the preparation and input data formatting step,
including reconnaissance data collection, AI model initialization,
and structured data preparation for AI consumption.
"""

import json
import logging
import os
import requests
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml
from dotenv import load_dotenv

# AI/ML imports
try:
    import tensorflow as tf
    import torch
    from transformers import AutoTokenizer, AutoModel
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    logging.warning("AI/ML libraries not available. AI features will be disabled.")

logger = logging.getLogger(__name__)


@dataclass
class ReconnaissanceData:
    """Structured reconnaissance data from previous stages."""
    
    endpoints: List[Dict[str, Any]] = None
    technologies: List[str] = None
    open_ports: List[int] = None
    services: Dict[str, str] = None
    cloud_resources: List[str] = None
    subdomains: List[str] = None
    ip_addresses: List[str] = None
    vulnerabilities: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.endpoints is None:
            self.endpoints = []
        if self.technologies is None:
            self.technologies = []
        if self.open_ports is None:
            self.open_ports = []
        if self.services is None:
            self.services = {}
        if self.cloud_resources is None:
            self.cloud_resources = []
        if self.subdomains is None:
            self.subdomains = []
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []


@dataclass
class StructuredInputData:
    """Structured input data for AI model consumption."""
    
    target_info: Dict[str, Any]
    endpoints: List[Dict[str, Any]]
    technologies: List[str]
    network_info: Dict[str, Any]
    cloud_info: Dict[str, Any]
    preliminary_vulns: List[Dict[str, Any]]
    scan_config: Dict[str, Any]
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.__dict__, default=str, indent=2)
    
    def to_yaml(self) -> str:
        """Convert to YAML string."""
        return yaml.dump(self.__dict__, default_flow_style=False, allow_unicode=True)


class DataPreparer:
    """Data preparation and input formatting for Stage 4 vulnerability testing."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.data_dir = self.output_dir / "data_preparation"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load environment variables
        load_dotenv()
        
        # API configuration
        self.backend_api_url = os.getenv("BACKEND_API_URL", "http://localhost:8000/api")
        self.backend_jwt_token = os.getenv("BACKEND_JWT_TOKEN")
        
        # AI model configuration
        self.ai_model = None
        self.ai_tokenizer = None
        
    def prepare_reconnaissance_data(self) -> ReconnaissanceData:
        """
        Collect and prepare reconnaissance data from previous stages.
        
        Returns:
            ReconnaissanceData: Structured reconnaissance data
        """
        logger.info("Preparing reconnaissance data from previous stages...")
        
        recon_data = ReconnaissanceData()
        
        try:
            # Collect data from API (if available)
            if self.backend_jwt_token:
                api_data = self._collect_from_api()
                if api_data:
                    recon_data = self._merge_api_data(recon_data, api_data)
            
            # Collect data from local files
            local_data = self._collect_from_local_files()
            if local_data:
                recon_data = self._merge_local_data(recon_data, local_data)
            
            # Validate and clean data
            recon_data = self._validate_recon_data(recon_data)
            
            # Save structured reconnaissance data
            self._save_recon_data(recon_data)
            
            logger.info(f"Reconnaissance data prepared: {len(recon_data.endpoints)} endpoints, "
                       f"{len(recon_data.technologies)} technologies, {len(recon_data.subdomains)} subdomains")
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Error preparing reconnaissance data: {str(e)}")
            raise
    
    def structure_input_data(self, recon_data: ReconnaissanceData) -> StructuredInputData:
        """
        Structure input data for AI model consumption.
        
        Args:
            recon_data: Reconnaissance data from previous stages
            
        Returns:
            StructuredInputData: Structured data for AI consumption
        """
        logger.info("Structuring input data for AI model consumption...")
        
        try:
            # Create target information
            target_info = {
                "domain": self.config.target,
                "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                "stage": "vuln_test",
                "ai_integration": self.config.enable_ai_analysis
            }
            
            # Structure endpoints with methods and parameters
            structured_endpoints = []
            for endpoint in recon_data.endpoints:
                structured_endpoint = {
                    "url": endpoint.get("url", ""),
                    "method": endpoint.get("method", "GET"),
                    "params": endpoint.get("params", []),
                    "headers": endpoint.get("headers", {}),
                    "technology": endpoint.get("technology", ""),
                    "vulnerability_hints": endpoint.get("vulnerability_hints", [])
                }
                structured_endpoints.append(structured_endpoint)
            
            # Structure network information
            network_info = {
                "open_ports": recon_data.open_ports,
                "services": recon_data.services,
                "ip_addresses": recon_data.ip_addresses
            }
            
            # Structure cloud information
            cloud_info = {
                "cloud_resources": recon_data.cloud_resources,
                "cloud_providers": self._detect_cloud_providers(recon_data.cloud_resources)
            }
            
            # Structure preliminary vulnerabilities
            preliminary_vulns = []
            for vuln in recon_data.vulnerabilities:
                structured_vuln = {
                    "type": vuln.get("type", ""),
                    "severity": vuln.get("severity", "Medium"),
                    "location": vuln.get("location", ""),
                    "description": vuln.get("description", ""),
                    "confidence": vuln.get("confidence", 0.0)
                }
                preliminary_vulns.append(structured_vuln)
            
            # Create scan configuration
            scan_config = {
                "ai_confidence_threshold": self.config.ai_confidence_threshold,
                "rate_limit": self.config.rate_limit,
                "max_concurrent_tests": self.config.max_concurrent_tests,
                "browser_type": self.config.browser_type,
                "headless": self.config.headless,
                "safe_mode": self.config.safe_exploit_mode,
                "scope_boundaries": self.config.scope_boundaries,
                "ethical_limits": self.config.ethical_limits
            }
            
            # Create structured input data
            structured_data = StructuredInputData(
                target_info=target_info,
                endpoints=structured_endpoints,
                technologies=recon_data.technologies,
                network_info=network_info,
                cloud_info=cloud_info,
                preliminary_vulns=preliminary_vulns,
                scan_config=scan_config
            )
            
            # Save structured data
            self._save_structured_data(structured_data)
            
            logger.info(f"Input data structured: {len(structured_endpoints)} endpoints, "
                       f"{len(recon_data.technologies)} technologies")
            
            return structured_data
            
        except Exception as e:
            logger.error(f"Error structuring input data: {str(e)}")
            raise
    
    def initialize_ai_model(self):
        """Initialize the custom AI model for vulnerability analysis."""
        if not self.config.enable_ai_analysis:
            logger.info("AI analysis disabled, skipping model initialization")
            return
            
        if not AI_AVAILABLE:
            logger.warning("AI libraries not available, skipping model initialization")
            return
            
        logger.info("Initializing AI model for vulnerability analysis...")
        
        try:
            model_path = Path(self.config.ai_model_path)
            
            if model_path.exists():
                # Load existing model
                logger.info(f"Loading AI model from {model_path}")
                
                # Load tokenizer and model (example for transformer-based model)
                self.ai_tokenizer = AutoTokenizer.from_pretrained(str(model_path))
                self.ai_model = AutoModel.from_pretrained(str(model_path))
                
                logger.info("AI model loaded successfully")
            else:
                # Initialize default model or create placeholder
                logger.info("No existing model found, initializing default model")
                self._initialize_default_model()
                
        except Exception as e:
            logger.error(f"Error initializing AI model: {str(e)}")
            logger.info("Continuing without AI model")
    
    def setup_output_structures(self):
        """Setup output structures for findings, logs, and evidence."""
        logger.info("Setting up output structures...")
        
        try:
            # Create output structure templates
            output_structures = {
                "findings_schema": self._create_findings_schema(),
                "log_format": self._create_log_format(),
                "evidence_structure": self._create_evidence_structure(),
                "report_template": self._create_report_template()
            }
            
            # Save output structures
            structures_file = self.data_dir / "output_structures.json"
            with open(structures_file, 'w') as f:
                json.dump(output_structures, f, indent=2)
            
            logger.info("Output structures setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up output structures: {str(e)}")
            raise
    
    def _collect_from_api(self) -> Optional[Dict[str, Any]]:
        """Collect reconnaissance data from backend API."""
        try:
            headers = {"Authorization": f"Bearer {self.backend_jwt_token}"}
            
            # Collect data from different endpoints
            endpoints_to_collect = [
                "/targets/",
                "/passive-recon/",
                "/active-recon/", 
                "/vuln-scan/"
            ]
            
            collected_data = {}
            
            for endpoint in endpoints_to_collect:
                try:
                    response = requests.get(
                        f"{self.backend_api_url}{endpoint}",
                        headers=headers,
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get("success"):
                            collected_data[endpoint.strip("/")] = data.get("data", [])
                            
                except Exception as e:
                    logger.warning(f"Failed to collect data from {endpoint}: {str(e)}")
            
            return collected_data if collected_data else None
            
        except Exception as e:
            logger.error(f"Error collecting data from API: {str(e)}")
            return None
    
    def _collect_from_local_files(self) -> Optional[Dict[str, Any]]:
        """Collect reconnaissance data from local output files."""
        try:
            local_data = {}
            
            # Look for output files from previous stages
            output_paths = [
                f"outputs/passive_recon/{self.config.target}",
                f"outputs/active_recon/{self.config.target}",
                f"outputs/vuln_scan/{self.config.target}"
            ]
            
            for output_path in output_paths:
                path = Path(output_path)
                if path.exists():
                    stage_data = self._parse_output_directory(path)
                    if stage_data:
                        stage_name = path.parent.name
                        local_data[stage_name] = stage_data
            
            return local_data if local_data else None
            
        except Exception as e:
            logger.error(f"Error collecting data from local files: {str(e)}")
            return None
    
    def _parse_output_directory(self, directory: Path) -> Optional[Dict[str, Any]]:
        """Parse output directory for reconnaissance data."""
        try:
            data = {}
            
            # Look for common output files
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    if file_path.suffix in [".json", ".yaml", ".yml"]:
                        try:
                            if file_path.suffix == ".json":
                                with open(file_path, 'r') as f:
                                    file_data = json.load(f)
                            else:
                                with open(file_path, 'r') as f:
                                    file_data = yaml.safe_load(f)
                            
                            # Extract relevant data based on file name
                            if "subdomains" in file_path.name:
                                data["subdomains"] = file_data
                            elif "endpoints" in file_path.name:
                                data["endpoints"] = file_data
                            elif "technologies" in file_path.name:
                                data["technologies"] = file_data
                            elif "vulnerabilities" in file_path.name:
                                data["vulnerabilities"] = file_data
                                
                        except Exception as e:
                            logger.warning(f"Failed to parse {file_path}: {str(e)}")
            
            return data if data else None
            
        except Exception as e:
            logger.error(f"Error parsing output directory {directory}: {str(e)}")
            return None
    
    def _merge_api_data(self, recon_data: ReconnaissanceData, api_data: Dict[str, Any]) -> ReconnaissanceData:
        """Merge API data into reconnaissance data structure."""
        try:
            # Merge targets data
            if "targets" in api_data:
                for target in api_data["targets"]:
                    if target.get("domain") == self.config.target:
                        # Extract relevant information
                        pass
            
            # Merge passive recon data
            if "passive-recon" in api_data:
                for item in api_data["passive-recon"]:
                    if item.get("target") == self.config.target:
                        # Extract subdomains, technologies, etc.
                        if "subdomains" in item:
                            recon_data.subdomains.extend(item["subdomains"])
                        if "technologies" in item:
                            recon_data.technologies.extend(item["technologies"])
            
            # Merge active recon data
            if "active-recon" in api_data:
                for item in api_data["active-recon"]:
                    if item.get("target") == self.config.target:
                        # Extract endpoints, services, etc.
                        if "endpoints" in item:
                            recon_data.endpoints.extend(item["endpoints"])
                        if "services" in item:
                            recon_data.services.update(item["services"])
            
            # Merge vulnerability scan data
            if "vuln-scan" in api_data:
                for item in api_data["vuln-scan"]:
                    if item.get("target") == self.config.target:
                        # Extract vulnerabilities
                        if "vulnerabilities" in item:
                            recon_data.vulnerabilities.extend(item["vulnerabilities"])
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Error merging API data: {str(e)}")
            return recon_data
    
    def _merge_local_data(self, recon_data: ReconnaissanceData, local_data: Dict[str, Any]) -> ReconnaissanceData:
        """Merge local data into reconnaissance data structure."""
        try:
            # Merge passive recon data
            if "passive_recon" in local_data:
                passive_data = local_data["passive_recon"]
                if "subdomains" in passive_data:
                    recon_data.subdomains.extend(passive_data["subdomains"])
                if "technologies" in passive_data:
                    recon_data.technologies.extend(passive_data["technologies"])
            
            # Merge active recon data
            if "active_recon" in local_data:
                active_data = local_data["active_recon"]
                if "endpoints" in active_data:
                    recon_data.endpoints.extend(active_data["endpoints"])
                if "services" in active_data:
                    recon_data.services.update(active_data["services"])
            
            # Merge vulnerability scan data
            if "vuln_scan" in local_data:
                vuln_data = local_data["vuln_scan"]
                if "vulnerabilities" in vuln_data:
                    recon_data.vulnerabilities.extend(vuln_data["vulnerabilities"])
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Error merging local data: {str(e)}")
            return recon_data
    
    def _validate_recon_data(self, recon_data: ReconnaissanceData) -> ReconnaissanceData:
        """Validate and clean reconnaissance data."""
        try:
            # Remove duplicates
            recon_data.subdomains = list(set(recon_data.subdomains))
            recon_data.technologies = list(set(recon_data.technologies))
            recon_data.open_ports = list(set(recon_data.open_ports))
            recon_data.cloud_resources = list(set(recon_data.cloud_resources))
            recon_data.ip_addresses = list(set(recon_data.ip_addresses))
            
            # Validate endpoints
            valid_endpoints = []
            for endpoint in recon_data.endpoints:
                if isinstance(endpoint, dict) and "url" in endpoint:
                    valid_endpoints.append(endpoint)
            recon_data.endpoints = valid_endpoints
            
            # Validate vulnerabilities
            valid_vulns = []
            for vuln in recon_data.vulnerabilities:
                if isinstance(vuln, dict) and "type" in vuln:
                    valid_vulns.append(vuln)
            recon_data.vulnerabilities = valid_vulns
            
            return recon_data
            
        except Exception as e:
            logger.error(f"Error validating reconnaissance data: {str(e)}")
            return recon_data
    
    def _detect_cloud_providers(self, cloud_resources: List[str]) -> List[str]:
        """Detect cloud providers from cloud resources."""
        providers = []
        
        for resource in cloud_resources:
            resource_lower = resource.lower()
            if "aws" in resource_lower or "s3" in resource_lower or "amazon" in resource_lower:
                providers.append("AWS")
            elif "azure" in resource_lower or "blob" in resource_lower:
                providers.append("Azure")
            elif "gcp" in resource_lower or "google" in resource_lower:
                providers.append("GCP")
        
        return list(set(providers))
    
    def _save_recon_data(self, recon_data: ReconnaissanceData):
        """Save reconnaissance data to file."""
        try:
            recon_file = self.data_dir / "reconnaissance_data.json"
            with open(recon_file, 'w') as f:
                json.dump(recon_data.__dict__, f, default=str, indent=2)
            
            logger.info(f"Reconnaissance data saved to {recon_file}")
            
        except Exception as e:
            logger.error(f"Error saving reconnaissance data: {str(e)}")
    
    def _save_structured_data(self, structured_data: StructuredInputData):
        """Save structured data to file."""
        try:
            # Save as JSON
            json_file = self.data_dir / "structured_input.json"
            with open(json_file, 'w') as f:
                f.write(structured_data.to_json())
            
            # Save as YAML
            yaml_file = self.data_dir / "structured_input.yaml"
            with open(yaml_file, 'w') as f:
                f.write(structured_data.to_yaml())
            
            logger.info(f"Structured data saved to {json_file} and {yaml_file}")
            
        except Exception as e:
            logger.error(f"Error saving structured data: {str(e)}")
    
    def _initialize_default_model(self):
        """Initialize a default AI model for vulnerability analysis."""
        try:
            # This would typically load a pre-trained model
            # For now, we'll create a placeholder
            logger.info("Initializing default vulnerability analysis model")
            
            # Placeholder for model initialization
            # In a real implementation, this would load a trained model
            self.ai_model = "default_vulnerability_model"
            self.ai_tokenizer = "default_tokenizer"
            
            logger.info("Default model initialized")
            
        except Exception as e:
            logger.error(f"Error initializing default model: {str(e)}")
    
    def _create_findings_schema(self) -> Dict[str, Any]:
        """Create findings schema for output."""
        return {
            "vulnerability_finding": {
                "id": "string",
                "title": "string", 
                "description": "string",
                "endpoint": "string",
                "parameter": "string",
                "severity": "string",
                "confidence": "float",
                "status": "string",
                "cwe_id": "string",
                "cve_references": ["string"],
                "cvss_score": "float",
                "payload_used": "string",
                "evidence_files": ["string"],
                "extracted_data": "string",
                "ai_confidence": "float",
                "ai_recommendations": ["string"],
                "suggested_exploits": ["string"],
                "discovered_at": "datetime",
                "verified_at": "datetime",
                "remediation_advice": "string"
            }
        }
    
    def _create_log_format(self) -> Dict[str, Any]:
        """Create log format specification."""
        return {
            "log_entry": {
                "timestamp": "datetime",
                "action": "string",
                "target": "string",
                "tool": "string",
                "result": "string",
                "payload": "string",
                "evidence_files": ["string"]
            }
        }
    
    def _create_evidence_structure(self) -> Dict[str, Any]:
        """Create evidence structure specification."""
        return {
            "evidence": {
                "vulnerability_id": "string",
                "evidence_type": "string",  # screenshot, log, response, video
                "file_path": "string",
                "description": "string",
                "timestamp": "datetime",
                "metadata": "object"
            }
        }
    
    def _create_report_template(self) -> Dict[str, Any]:
        """Create report template specification."""
        return {
            "report": {
                "target": "string",
                "scan_date": "datetime",
                "total_findings": "integer",
                "confirmed_vulnerabilities": "integer",
                "severity_distribution": "object",
                "findings": ["vulnerability_finding"],
                "summary": "string",
                "recommendations": ["string"]
            }
        } 