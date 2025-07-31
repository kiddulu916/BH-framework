#!/usr/bin/env python3
"""
Target Gatherer for Vulnerability Scanning

This module implements Step 1 of the black-box vulnerability scanning methodology:
"Define Scope and Gather Targets"

It collects targets from previous reconnaissance stages (passive and active recon)
and categorizes them for vulnerability scanning.
"""

import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)

class TargetGatherer:
    """Gathers and categorizes targets from reconnaissance results"""
    
    def __init__(self, target: str, api_url: Optional[str] = None, jwt_token: Optional[str] = None):
        self.target = target
        self.api_url = api_url
        self.jwt_token = jwt_token
        self.targets = {
            "web_apps": [],
            "apis": [],
            "cloud_services": []
        }
    
    def gather_all_targets(self) -> Dict[str, List[str]]:
        """Gather all targets from reconnaissance results"""
        try:
            logger.info(f"Gathering targets for {self.target}")
            
            # Gather from passive reconnaissance
            passive_targets = self.gather_from_passive_recon()
            
            # Gather from active reconnaissance
            active_targets = self.gather_from_active_recon()
            
            # Gather from local output files
            local_targets = self.gather_from_local_outputs()
            
            # Merge and deduplicate targets
            self.merge_targets(passive_targets, active_targets, local_targets)
            
            # Categorize targets
            self.categorize_targets()
            
            # Validate targets
            self.validate_targets()
            
            logger.info(f"Target gathering completed. Found {sum(len(t) for t in self.targets.values())} targets")
            return self.targets
            
        except Exception as e:
            logger.error(f"Error gathering targets: {str(e)}")
            return self.targets
    
    def gather_from_passive_recon(self) -> Dict[str, List[str]]:
        """Gather targets from passive reconnaissance results"""
        targets = {"subdomains": [], "ips": [], "urls": []}
        
        try:
            # Try to get from API first
            if self.api_url and self.jwt_token:
                api_targets = self.get_targets_from_api("passive_recon")
                if api_targets:
                    targets.update(api_targets)
            
            # Fallback to local files
            passive_dir = Path(f"/outputs/passive_recon/{self.target}")
            if passive_dir.exists():
                local_targets = self.parse_passive_recon_files(passive_dir)
                targets.update(local_targets)
            
            logger.info(f"Gathered {sum(len(t) for t in targets.values())} targets from passive recon")
            return targets
            
        except Exception as e:
            logger.error(f"Error gathering from passive recon: {str(e)}")
            return targets
    
    def gather_from_active_recon(self) -> Dict[str, List[str]]:
        """Gather targets from active reconnaissance results"""
        targets = {"endpoints": [], "services": [], "ports": []}
        
        try:
            # Try to get from API first
            if self.api_url and self.jwt_token:
                api_targets = self.get_targets_from_api("active_recon")
                if api_targets:
                    targets.update(api_targets)
            
            # Fallback to local files
            active_dir = Path(f"/outputs/active_recon/{self.target}")
            if active_dir.exists():
                local_targets = self.parse_active_recon_files(active_dir)
                targets.update(local_targets)
            
            logger.info(f"Gathered {sum(len(t) for t in targets.values())} targets from active recon")
            return targets
            
        except Exception as e:
            logger.error(f"Error gathering from active recon: {str(e)}")
            return targets
    
    def gather_from_local_outputs(self) -> Dict[str, List[str]]:
        """Gather targets from local output files"""
        targets = {"local_urls": [], "config_files": []}
        
        try:
            # Check for any additional local files that might contain targets
            outputs_dir = Path("/outputs")
            if outputs_dir.exists():
                for stage_dir in outputs_dir.iterdir():
                    if stage_dir.is_dir() and stage_dir.name in ["passive_recon", "active_recon"]:
                        target_dir = stage_dir / self.target
                        if target_dir.exists():
                            local_targets = self.scan_directory_for_targets(target_dir)
                            targets.update(local_targets)
            
            logger.info(f"Gathered {sum(len(t) for t in targets.values())} targets from local outputs")
            return targets
            
        except Exception as e:
            logger.error(f"Error gathering from local outputs: {str(e)}")
            return targets
    
    def get_targets_from_api(self, stage: str) -> Optional[Dict[str, List[str]]]:
        """Get targets from backend API"""
        try:
            if not self.api_url or not self.jwt_token:
                return None
            
            headers = {
                'Authorization': f'Bearer {self.jwt_token}',
                'Content-Type': 'application/json'
            }
            
            # Get results from the specified stage
            response = requests.get(
                f"{self.api_url}/api/{stage}-results/?target={self.target}",
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    return self.extract_targets_from_api_data(data['data'], stage)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting targets from API: {str(e)}")
            return None
    
    def extract_targets_from_api_data(self, data: List[Dict], stage: str) -> Dict[str, List[str]]:
        """Extract targets from API response data"""
        targets = {}
        
        try:
            for item in data:
                if stage == "passive_recon":
                    # Extract subdomains, IPs, URLs from passive recon data
                    if 'subdomains' in item:
                        targets.setdefault('subdomains', []).extend(item['subdomains'])
                    if 'ips' in item:
                        targets.setdefault('ips', []).extend(item['ips'])
                    if 'urls' in item:
                        targets.setdefault('urls', []).extend(item['urls'])
                
                elif stage == "active_recon":
                    # Extract endpoints, services, ports from active recon data
                    if 'endpoints' in item:
                        targets.setdefault('endpoints', []).extend(item['endpoints'])
                    if 'services' in item:
                        targets.setdefault('services', []).extend(item['services'])
                    if 'ports' in item:
                        targets.setdefault('ports', []).extend(item['ports'])
            
            return targets
            
        except Exception as e:
            logger.error(f"Error extracting targets from API data: {str(e)}")
            return targets
    
    def parse_passive_recon_files(self, passive_dir: Path) -> Dict[str, List[str]]:
        """Parse passive reconnaissance output files"""
        targets = {"subdomains": [], "ips": [], "urls": []}
        
        try:
            # Parse parsed results
            parsed_dir = passive_dir / "parsed"
            if parsed_dir.exists():
                for file_path in parsed_dir.glob("*.json"):
                    try:
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                        
                        # Extract targets based on file name
                        if "subdomains" in file_path.name:
                            if isinstance(data, list):
                                targets["subdomains"].extend(data)
                            elif isinstance(data, dict) and "subdomains" in data:
                                targets["subdomains"].extend(data["subdomains"])
                        
                        elif "urls" in file_path.name:
                            if isinstance(data, list):
                                targets["urls"].extend(data)
                            elif isinstance(data, dict) and "urls" in data:
                                targets["urls"].extend(data["urls"])
                        
                        elif "ips" in file_path.name:
                            if isinstance(data, list):
                                targets["ips"].extend(data)
                            elif isinstance(data, dict) and "ips" in data:
                                targets["ips"].extend(data["ips"])
                    
                    except Exception as e:
                        logger.warning(f"Error parsing {file_path}: {str(e)}")
                        continue
            
            return targets
            
        except Exception as e:
            logger.error(f"Error parsing passive recon files: {str(e)}")
            return targets
    
    def parse_active_recon_files(self, active_dir: Path) -> Dict[str, List[str]]:
        """Parse active reconnaissance output files"""
        targets = {"endpoints": [], "services": [], "ports": []}
        
        try:
            # Parse various active recon outputs
            for subdir in active_dir.iterdir():
                if subdir.is_dir():
                    for file_path in subdir.glob("*.json"):
                        try:
                            with open(file_path, 'r') as f:
                                data = json.load(f)
                            
                            # Extract targets based on file content
                            if isinstance(data, list):
                                for item in data:
                                    if isinstance(item, dict):
                                        if "url" in item:
                                            targets["endpoints"].append(item["url"])
                                        if "service" in item:
                                            targets["services"].append(item["service"])
                                        if "port" in item:
                                            targets["ports"].append(str(item["port"]))
                            
                            elif isinstance(data, dict):
                                if "endpoints" in data:
                                    targets["endpoints"].extend(data["endpoints"])
                                if "services" in data:
                                    targets["services"].extend(data["services"])
                                if "ports" in data:
                                    targets["ports"].extend([str(p) for p in data["ports"]])
                        
                        except Exception as e:
                            logger.warning(f"Error parsing {file_path}: {str(e)}")
                            continue
            
            return targets
            
        except Exception as e:
            logger.error(f"Error parsing active recon files: {str(e)}")
            return targets
    
    def scan_directory_for_targets(self, directory: Path) -> Dict[str, List[str]]:
        """Scan directory for any additional targets"""
        targets = {"local_urls": [], "config_files": []}
        
        try:
            # Look for common files that might contain targets
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    # Check for URLs in various file types
                    if file_path.suffix in ['.txt', '.json', '.csv']:
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            
                            # Extract URLs from content
                            urls = self.extract_urls_from_content(content)
                            targets["local_urls"].extend(urls)
                            
                            # Check for configuration files
                            if any(keyword in file_path.name.lower() for keyword in ['config', 'conf', 'ini', 'yaml', 'yml']):
                                targets["config_files"].append(str(file_path))
                        
                        except Exception as e:
                            logger.debug(f"Error reading {file_path}: {str(e)}")
                            continue
            
            return targets
            
        except Exception as e:
            logger.error(f"Error scanning directory: {str(e)}")
            return targets
    
    def extract_urls_from_content(self, content: str) -> List[str]:
        """Extract URLs from text content"""
        urls = []
        
        try:
            # Simple URL extraction (can be enhanced with regex)
            import re
            
            # Basic URL pattern
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            found_urls = re.findall(url_pattern, content)
            
            # Filter and clean URLs
            for url in found_urls:
                url = url.strip('.,;:!?')
                if url and len(url) > 10:  # Basic validation
                    urls.append(url)
            
            return list(set(urls))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error extracting URLs: {str(e)}")
            return urls
    
    def merge_targets(self, *target_dicts):
        """Merge multiple target dictionaries"""
        try:
            for target_dict in target_dicts:
                for category, targets in target_dict.items():
                    if category not in self.targets:
                        self.targets[category] = []
                    self.targets[category].extend(targets)
            
            # Remove duplicates
            for category in self.targets:
                self.targets[category] = list(set(self.targets[category]))
            
        except Exception as e:
            logger.error(f"Error merging targets: {str(e)}")
    
    def categorize_targets(self):
        """Categorize targets into web apps, APIs, and cloud services"""
        try:
            web_apps = []
            apis = []
            cloud_services = []
            
            # Process all gathered targets
            for category, targets in self.targets.items():
                for target in targets:
                    if self.is_web_application(target):
                        web_apps.append(target)
                    elif self.is_api_endpoint(target):
                        apis.append(target)
                    elif self.is_cloud_service(target):
                        cloud_services.append(target)
                    else:
                        # Default to web app if uncertain
                        web_apps.append(target)
            
            # Update main targets structure
            self.targets = {
                "web_apps": list(set(web_apps)),
                "apis": list(set(apis)),
                "cloud_services": list(set(cloud_services))
            }
            
        except Exception as e:
            logger.error(f"Error categorizing targets: {str(e)}")
    
    def is_web_application(self, target: str) -> bool:
        """Check if target is a web application"""
        try:
            # Check for common web application indicators
            web_indicators = [
                '/api/', '/graphql', '/swagger', '/docs', '/admin', '/login',
                'html', 'php', 'asp', 'jsp', 'js', 'css', 'png', 'jpg', 'gif'
            ]
            
            target_lower = target.lower()
            
            # Check for web indicators
            for indicator in web_indicators:
                if indicator in target_lower:
                    return True
            
            # Check for common web ports
            if ':80' in target or ':443' in target or ':8080' in target:
                return True
            
            # Check for HTTP/HTTPS protocols
            if target.startswith(('http://', 'https://')):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking web application: {str(e)}")
            return False
    
    def is_api_endpoint(self, target: str) -> bool:
        """Check if target is an API endpoint"""
        try:
            # Check for common API indicators
            api_indicators = [
                '/api/', '/rest/', '/graphql', '/swagger', '/openapi',
                '/v1/', '/v2/', '/v3/', '/endpoint', '/service'
            ]
            
            target_lower = target.lower()
            
            # Check for API indicators
            for indicator in api_indicators:
                if indicator in target_lower:
                    return True
            
            # Check for JSON/XML responses (would need to make a request)
            # For now, assume it's an API if it has specific patterns
            if any(pattern in target_lower for pattern in ['json', 'xml', 'soap']):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking API endpoint: {str(e)}")
            return False
    
    def is_cloud_service(self, target: str) -> bool:
        """Check if target is a cloud service"""
        try:
            # Check for common cloud service indicators
            cloud_indicators = [
                's3.amazonaws.com', 'blob.core.windows.net', 'storage.googleapis.com',
                'cloudfront.net', 'elasticbeanstalk.com', 'herokuapp.com',
                'appspot.com', 'azurewebsites.net', 'cloudapp.net'
            ]
            
            target_lower = target.lower()
            
            # Check for cloud indicators
            for indicator in cloud_indicators:
                if indicator in target_lower:
                    return True
            
            # Check for cloud storage patterns
            if any(pattern in target_lower for pattern in ['bucket', 'blob', 'storage']):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking cloud service: {str(e)}")
            return False
    
    def validate_targets(self):
        """Validate gathered targets"""
        try:
            total_targets = sum(len(targets) for targets in self.targets.values())
            
            if total_targets == 0:
                logger.warning("No targets found. Adding default target.")
                # Add the main target as a fallback
                self.targets["web_apps"].append(f"https://{self.target}")
            
            # Log validation results
            logger.info(f"Target validation completed:")
            for category, targets in self.targets.items():
                logger.info(f"  {category}: {len(targets)} targets")
            
        except Exception as e:
            logger.error(f"Error validating targets: {str(e)}") 