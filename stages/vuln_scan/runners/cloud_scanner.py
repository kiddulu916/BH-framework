"""
Cloud Scanner Module for Vulnerability Scanning Stage
Implements Step 5: Scan APIs and Cloud Components (Cloud Scanning)

This module provides comprehensive cloud infrastructure vulnerability scanning:
- AWS S3 bucket enumeration and misconfiguration detection
- Azure Blob Storage scanning
- Google Cloud Storage scanning
- Cloud metadata service testing (SSRF potential)
- Public cloud resource discovery
- Cloud-specific security misconfigurations
"""

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import requests
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)

@dataclass
class CloudScanResult:
    """Cloud scan result data structure"""
    target: str
    scan_type: str
    tool: str
    findings: List[Dict[str, Any]]
    raw_output: str
    scan_time: float
    status: str
    cloud_provider: str
    error_message: Optional[str] = None

class CloudScanner:
    """Cloud infrastructure vulnerability scanner"""

    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        self.output_dir = output_dir / "cloud_scan"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_config = rate_limit_config or {}
        self.results: List[CloudScanResult] = []

    def run_cloud_scanning(self, targets: Dict[str, List[str]]) -> bool:
        """Execute comprehensive cloud infrastructure vulnerability scanning"""
        try:
            logger.info(f"{Fore.CYAN}Starting cloud infrastructure vulnerability scanning{Style.RESET_ALL}")
            
            cloud_targets = targets.get("cloud_services", [])
            if not cloud_targets:
                logger.warning("No cloud targets found for scanning")
                return True

            logger.info(f"Found {len(cloud_targets)} cloud targets for scanning")

            # Step 5.1: AWS S3 Bucket Enumeration and Misconfiguration Detection
            self.scan_aws_s3_buckets(cloud_targets)

            # Step 5.2: Azure Blob Storage Scanning
            self.scan_azure_blob_storage(cloud_targets)

            # Step 5.3: Google Cloud Storage Scanning
            self.scan_gcp_storage(cloud_targets)

            # Step 5.4: Cloud Metadata Service Testing (SSRF Potential)
            self.test_cloud_metadata_services(cloud_targets)

            # Step 5.5: Public Cloud Resource Discovery
            self.discover_public_cloud_resources(cloud_targets)

            # Step 5.6: Cloud-Specific Security Misconfigurations
            self.detect_cloud_misconfigurations(cloud_targets)

            # Save consolidated results
            self.save_cloud_results()

            logger.info(f"{Fore.GREEN}Cloud scanning completed successfully!{Style.RESET_ALL}")
            return True

        except Exception as e:
            logger.error(f"Cloud scanning failed: {str(e)}")
            return False

    def scan_aws_s3_buckets(self, cloud_targets: List[str]) -> None:
        """Step 5.1: AWS S3 bucket enumeration and misconfiguration detection"""
        logger.info("Step 5.1: Scanning AWS S3 buckets")

        for target in cloud_targets:
            try:
                # Extract potential bucket names from target
                bucket_names = self.generate_s3_bucket_names(target)
                
                for bucket_name in bucket_names:
                    self.test_s3_bucket(bucket_name)

            except Exception as e:
                logger.error(f"Error scanning S3 buckets for {target}: {str(e)}")

    def generate_s3_bucket_names(self, target: str) -> List[str]:
        """Generate potential S3 bucket names from target"""
        bucket_names = []
        
        # Extract domain name
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Common S3 bucket naming patterns
        patterns = [
            domain,
            f"{domain}-backup",
            f"{domain}-assets",
            f"{domain}-static",
            f"{domain}-media",
            f"{domain}-uploads",
            f"{domain}-files",
            f"{domain}-data",
            f"{domain}-logs",
            f"{domain}-config",
            f"{domain}-dev",
            f"{domain}-staging",
            f"{domain}-prod",
            f"{domain}-test",
            f"{domain}-temp",
            f"{domain}-archive",
            f"{domain}-backups",
            f"{domain}-storage",
            f"{domain}-bucket",
            f"{domain}-s3"
        ]
        
        bucket_names.extend(patterns)
        
        # Add variations without dots (S3 naming restrictions)
        no_dots = domain.replace(".", "")
        bucket_names.extend([
            no_dots,
            f"{no_dots}-backup",
            f"{no_dots}-assets",
            f"{no_dots}-static"
        ])
        
        return list(set(bucket_names))  # Remove duplicates

    def test_s3_bucket(self, bucket_name: str) -> None:
        """Test a single S3 bucket for misconfigurations"""
        try:
            logger.info(f"Testing S3 bucket: {bucket_name}")

            findings = []
            raw_output = ""

            # Test 1: Direct bucket access
            s3_url = f"https://{bucket_name}.s3.amazonaws.com"
            response = requests.get(s3_url, timeout=10)
            raw_output += f"Direct access {s3_url}: {response.status_code}\n"

            if response.status_code == 200:
                findings.append({
                    "type": "public_s3_bucket",
                    "severity": "high",
                    "description": f"S3 bucket {bucket_name} is publicly accessible",
                    "bucket": bucket_name,
                    "url": s3_url,
                    "recommendation": "Configure bucket permissions to restrict public access"
                })

            # Test 2: List bucket contents
            list_url = f"https://{bucket_name}.s3.amazonaws.com/?list-type=2"
            response = requests.get(list_url, timeout=10)
            raw_output += f"List contents {list_url}: {response.status_code}\n"

            if response.status_code == 200:
                findings.append({
                    "type": "s3_bucket_listing",
                    "severity": "medium",
                    "description": f"S3 bucket {bucket_name} allows public listing",
                    "bucket": bucket_name,
                    "url": list_url,
                    "recommendation": "Disable public listing of bucket contents"
                })

                # Parse and analyze bucket contents
                try:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(response.text)
                    for contents in root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Contents"):
                        key = contents.find(".//{http://s3.amazonaws.com/doc/2006-03-01/}Key")
                        if key is not None:
                            file_key = key.text
                            if self.is_sensitive_file(file_key):
                                findings.append({
                                    "type": "sensitive_file_exposed",
                                    "severity": "high",
                                    "description": f"Sensitive file exposed in S3 bucket: {file_key}",
                                    "bucket": bucket_name,
                                    "file": file_key,
                                    "recommendation": "Remove or secure sensitive files"
                                })
                except Exception as e:
                    logger.debug(f"Error parsing S3 bucket listing: {str(e)}")

            # Test 3: Check for specific sensitive files
            sensitive_files = [
                "config.json",
                "config.yml",
                ".env",
                "secrets.json",
                "credentials.json",
                "backup.sql",
                "database.sql",
                "dump.sql",
                "admin.json",
                "users.json"
            ]

            for file_name in sensitive_files:
                file_url = f"https://{bucket_name}.s3.amazonaws.com/{file_name}"
                try:
                    response = requests.get(file_url, timeout=5)
                    raw_output += f"File {file_url}: {response.status_code}\n"

                    if response.status_code == 200:
                        findings.append({
                            "type": "sensitive_file_accessible",
                            "severity": "high",
                            "description": f"Sensitive file accessible: {file_name}",
                            "bucket": bucket_name,
                            "file": file_name,
                            "url": file_url,
                            "recommendation": "Remove or secure sensitive files"
                        })
                except requests.exceptions.RequestException:
                    continue

            if findings:
                result = CloudScanResult(
                    target=bucket_name,
                    scan_type="aws_s3_scanning",
                    tool="s3-scanner",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="aws"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing S3 bucket {bucket_name}: {str(e)}")

    def is_sensitive_file(self, file_key: str) -> bool:
        """Check if a file key indicates a sensitive file"""
        sensitive_patterns = [
            ".env", ".config", "config", "secret", "credential", "password",
            "key", "token", "backup", "dump", "sql", "admin", "user",
            "private", "internal", "test", "dev", "staging"
        ]
        
        file_lower = file_key.lower()
        return any(pattern in file_lower for pattern in sensitive_patterns)

    def scan_azure_blob_storage(self, cloud_targets: List[str]) -> None:
        """Step 5.2: Azure Blob Storage scanning"""
        logger.info("Step 5.2: Scanning Azure Blob Storage")

        for target in cloud_targets:
            try:
                # Generate potential Azure storage account names
                storage_accounts = self.generate_azure_storage_names(target)
                
                for account_name in storage_accounts:
                    self.test_azure_blob_storage(account_name)

            except Exception as e:
                logger.error(f"Error scanning Azure storage for {target}: {str(e)}")

    def generate_azure_storage_names(self, target: str) -> List[str]:
        """Generate potential Azure storage account names"""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # Azure storage account naming patterns
        patterns = [
            domain.replace(".", "").replace("-", ""),  # Azure naming restrictions
            f"{domain.replace('.', '').replace('-', '')}storage",
            f"{domain.replace('.', '').replace('-', '')}blob",
            f"{domain.replace('.', '').replace('-', '')}data",
            f"{domain.replace('.', '').replace('-', '')}files"
        ]
        
        return list(set(patterns))

    def test_azure_blob_storage(self, account_name: str) -> None:
        """Test Azure Blob Storage for misconfigurations"""
        try:
            logger.info(f"Testing Azure Blob Storage: {account_name}")

            findings = []
            raw_output = ""

            # Test Azure Blob Storage endpoints
            blob_endpoints = [
                f"https://{account_name}.blob.core.windows.net",
                f"https://{account_name}.blob.core.cloudapi.de",  # German cloud
                f"https://{account_name}.blob.core.usgovcloudapi.net",  # US Gov
                f"https://{account_name}.blob.core.chinacloudapi.cn"  # China cloud
            ]

            for endpoint in blob_endpoints:
                try:
                    response = requests.get(endpoint, timeout=10)
                    raw_output += f"Azure blob {endpoint}: {response.status_code}\n"

                    if response.status_code == 200:
                        findings.append({
                            "type": "public_azure_blob",
                            "severity": "high",
                            "description": f"Azure Blob Storage account {account_name} is publicly accessible",
                            "account": account_name,
                            "endpoint": endpoint,
                            "recommendation": "Configure storage account permissions to restrict public access"
                        })

                except requests.exceptions.RequestException:
                    continue

            if findings:
                result = CloudScanResult(
                    target=account_name,
                    scan_type="azure_blob_scanning",
                    tool="azure-blob-scanner",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="azure"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing Azure Blob Storage {account_name}: {str(e)}")

    def scan_gcp_storage(self, cloud_targets: List[str]) -> None:
        """Step 5.3: Google Cloud Storage scanning"""
        logger.info("Step 5.3: Scanning Google Cloud Storage")

        for target in cloud_targets:
            try:
                # Generate potential GCP bucket names
                bucket_names = self.generate_gcp_bucket_names(target)
                
                for bucket_name in bucket_names:
                    self.test_gcp_bucket(bucket_name)

            except Exception as e:
                logger.error(f"Error scanning GCP storage for {target}: {str(e)}")

    def generate_gcp_bucket_names(self, target: str) -> List[str]:
        """Generate potential GCP bucket names"""
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        
        # GCP bucket naming patterns
        patterns = [
            domain,
            f"{domain}-storage",
            f"{domain}-bucket",
            f"{domain}-data",
            f"{domain}-files",
            f"{domain}-backup",
            f"{domain}-assets"
        ]
        
        return list(set(patterns))

    def test_gcp_bucket(self, bucket_name: str) -> None:
        """Test GCP bucket for misconfigurations"""
        try:
            logger.info(f"Testing GCP bucket: {bucket_name}")

            findings = []
            raw_output = ""

            # Test GCP Storage endpoints
            gcp_endpoints = [
                f"https://storage.googleapis.com/{bucket_name}",
                f"https://{bucket_name}.storage.googleapis.com"
            ]

            for endpoint in gcp_endpoints:
                try:
                    response = requests.get(endpoint, timeout=10)
                    raw_output += f"GCP bucket {endpoint}: {response.status_code}\n"

                    if response.status_code == 200:
                        findings.append({
                            "type": "public_gcp_bucket",
                            "severity": "high",
                            "description": f"GCP bucket {bucket_name} is publicly accessible",
                            "bucket": bucket_name,
                            "endpoint": endpoint,
                            "recommendation": "Configure bucket permissions to restrict public access"
                        })

                except requests.exceptions.RequestException:
                    continue

            if findings:
                result = CloudScanResult(
                    target=bucket_name,
                    scan_type="gcp_storage_scanning",
                    tool="gcp-storage-scanner",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="gcp"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing GCP bucket {bucket_name}: {str(e)}")

    def test_cloud_metadata_services(self, cloud_targets: List[str]) -> None:
        """Step 5.4: Cloud metadata service testing (SSRF potential)"""
        logger.info("Step 5.4: Testing cloud metadata services")

        for target in cloud_targets:
            try:
                self.test_target_metadata_services(target)
            except Exception as e:
                logger.error(f"Error testing metadata services for {target}: {str(e)}")

    def test_target_metadata_services(self, target: str) -> None:
        """Test cloud metadata services for a target"""
        try:
            logger.info(f"Testing cloud metadata services for: {target}")

            findings = []
            raw_output = ""

            # Common cloud metadata service endpoints
            metadata_endpoints = [
                # AWS EC2 metadata service
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                
                # Azure metadata service
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
                
                # Google Cloud metadata service
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
                
                # DigitalOcean metadata service
                "http://169.254.169.254/metadata/v1/",
                
                # OpenStack metadata service
                "http://169.254.169.254/openstack/",
                
                # Kubernetes metadata service
                "http://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/pods",
                "http://kubernetes.default.svc/api/v1/namespaces/default/pods"
            ]

            for endpoint in metadata_endpoints:
                try:
                    # Test with different headers that might bypass restrictions
                    headers_variations = [
                        {},
                        {"X-Forwarded-For": "127.0.0.1"},
                        {"X-Forwarded-For": "169.254.169.254"},
                        {"X-Original-URL": endpoint},
                        {"X-Rewrite-URL": endpoint}
                    ]

                    for headers in headers_variations:
                        try:
                            response = requests.get(endpoint, headers=headers, timeout=5)
                            raw_output += f"Metadata {endpoint} with {headers}: {response.status_code}\n"

                            if response.status_code == 200:
                                findings.append({
                                    "type": "metadata_service_accessible",
                                    "severity": "critical",
                                    "description": f"Cloud metadata service accessible: {endpoint}",
                                    "endpoint": endpoint,
                                    "headers": headers,
                                    "response_length": len(response.text),
                                    "recommendation": "Block access to cloud metadata services"
                                })

                                # Check for sensitive information in response
                                if self.contains_sensitive_metadata(response.text):
                                    findings.append({
                                        "type": "sensitive_metadata_exposed",
                                        "severity": "critical",
                                        "description": f"Sensitive metadata exposed: {endpoint}",
                                        "endpoint": endpoint,
                                        "recommendation": "Immediately secure metadata access"
                                    })

                        except requests.exceptions.RequestException:
                            continue

                except Exception as e:
                    logger.debug(f"Error testing metadata endpoint {endpoint}: {str(e)}")

            if findings:
                result = CloudScanResult(
                    target=target,
                    scan_type="metadata_service_testing",
                    tool="metadata-scanner",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="multiple"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing metadata services for {target}: {str(e)}")

    def contains_sensitive_metadata(self, content: str) -> bool:
        """Check if metadata content contains sensitive information"""
        sensitive_patterns = [
            "access_key", "secret_key", "token", "password", "credential",
            "private_key", "ssh_key", "api_key", "aws_access_key_id",
            "aws_secret_access_key", "azure_token", "gcp_token"
        ]
        
        content_lower = content.lower()
        return any(pattern in content_lower for pattern in sensitive_patterns)

    def discover_public_cloud_resources(self, cloud_targets: List[str]) -> None:
        """Step 5.5: Public cloud resource discovery"""
        logger.info("Step 5.5: Discovering public cloud resources")

        for target in cloud_targets:
            try:
                self.discover_target_cloud_resources(target)
            except Exception as e:
                logger.error(f"Error discovering cloud resources for {target}: {str(e)}")

    def discover_target_cloud_resources(self, target: str) -> None:
        """Discover public cloud resources for a target"""
        try:
            logger.info(f"Discovering cloud resources for: {target}")

            findings = []
            raw_output = ""

            # Common cloud service endpoints to check
            cloud_services = [
                # AWS services
                {"name": "aws_elasticbeanstalk", "endpoints": [
                    f"https://{target}.elasticbeanstalk.com",
                    f"https://{target}.us-east-1.elasticbeanstalk.com"
                ]},
                {"name": "aws_cloudfront", "endpoints": [
                    f"https://{target}.cloudfront.net"
                ]},
                {"name": "aws_elb", "endpoints": [
                    f"https://{target}.elb.amazonaws.com"
                ]},
                
                # Azure services
                {"name": "azure_app_service", "endpoints": [
                    f"https://{target}.azurewebsites.net",
                    f"https://{target}.azurewebsites.net"
                ]},
                {"name": "azure_cloudapp", "endpoints": [
                    f"https://{target}.cloudapp.net"
                ]},
                
                # Google Cloud services
                {"name": "gcp_app_engine", "endpoints": [
                    f"https://{target}.appspot.com"
                ]},
                {"name": "gcp_run", "endpoints": [
                    f"https://{target}.run.app"
                ]}
            ]

            for service in cloud_services:
                for endpoint in service["endpoints"]:
                    try:
                        response = requests.get(endpoint, timeout=10)
                        raw_output += f"Cloud service {endpoint}: {response.status_code}\n"

                        if response.status_code == 200:
                            findings.append({
                                "type": "public_cloud_service",
                                "severity": "info",
                                "description": f"Public cloud service discovered: {service['name']}",
                                "service": service["name"],
                                "endpoint": endpoint,
                                "recommendation": "Review service configuration and security"
                            })

                    except requests.exceptions.RequestException:
                        continue

            if findings:
                result = CloudScanResult(
                    target=target,
                    scan_type="cloud_resource_discovery",
                    tool="cloud-discovery",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="multiple"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error discovering cloud resources for {target}: {str(e)}")

    def detect_cloud_misconfigurations(self, cloud_targets: List[str]) -> None:
        """Step 5.6: Cloud-specific security misconfigurations"""
        logger.info("Step 5.6: Detecting cloud-specific security misconfigurations")

        for target in cloud_targets:
            try:
                self.detect_target_misconfigurations(target)
            except Exception as e:
                logger.error(f"Error detecting misconfigurations for {target}: {str(e)}")

    def detect_target_misconfigurations(self, target: str) -> None:
        """Detect cloud-specific security misconfigurations for a target"""
        try:
            logger.info(f"Detecting cloud misconfigurations for: {target}")

            findings = []
            raw_output = ""

            # Test for common cloud misconfigurations
            misconfig_tests = [
                {
                    "name": "cors_misconfiguration",
                    "endpoints": [
                        f"{target}/api/",
                        f"{target}/api/users",
                        f"{target}/api/admin"
                    ],
                    "method": "OPTIONS"
                },
                {
                    "name": "missing_security_headers",
                    "endpoints": [target],
                    "method": "GET"
                },
                {
                    "name": "directory_listing",
                    "endpoints": [
                        f"{target}/",
                        f"{target}/files/",
                        f"{target}/uploads/",
                        f"{target}/backup/"
                    ],
                    "method": "GET"
                }
            ]

            for test in misconfig_tests:
                for endpoint in test["endpoints"]:
                    try:
                        if test["method"] == "OPTIONS":
                            response = requests.options(endpoint, timeout=10)
                            raw_output += f"CORS {endpoint}: {response.status_code}\n"

                            # Check for overly permissive CORS
                            cors_headers = response.headers.get("Access-Control-Allow-Origin", "")
                            if cors_headers == "*":
                                findings.append({
                                    "type": "permissive_cors",
                                    "severity": "medium",
                                    "description": f"Overly permissive CORS configuration: {endpoint}",
                                    "endpoint": endpoint,
                                    "cors_header": cors_headers,
                                    "recommendation": "Restrict CORS to specific origins"
                                })

                        elif test["method"] == "GET":
                            response = requests.get(endpoint, timeout=10)
                            raw_output += f"GET {endpoint}: {response.status_code}\n"

                            # Check for directory listing
                            if test["name"] == "directory_listing":
                                if "Index of" in response.text or "Directory listing" in response.text:
                                    findings.append({
                                        "type": "directory_listing_enabled",
                                        "severity": "medium",
                                        "description": f"Directory listing enabled: {endpoint}",
                                        "endpoint": endpoint,
                                        "recommendation": "Disable directory listing"
                                    })

                            # Check for missing security headers
                            elif test["name"] == "missing_security_headers":
                                missing_headers = []
                                required_headers = [
                                    "X-Frame-Options",
                                    "X-Content-Type-Options",
                                    "X-XSS-Protection",
                                    "Strict-Transport-Security"
                                ]

                                for header in required_headers:
                                    if header not in response.headers:
                                        missing_headers.append(header)

                                if missing_headers:
                                    findings.append({
                                        "type": "missing_security_headers",
                                        "severity": "medium",
                                        "description": f"Missing security headers: {endpoint}",
                                        "endpoint": endpoint,
                                        "missing_headers": missing_headers,
                                        "recommendation": "Implement security headers"
                                    })

                    except requests.exceptions.RequestException:
                        continue

            if findings:
                result = CloudScanResult(
                    target=target,
                    scan_type="cloud_misconfiguration_detection",
                    tool="cloud-misconfig-detector",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed",
                    cloud_provider="multiple"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error detecting misconfigurations for {target}: {str(e)}")

    def save_cloud_results(self) -> None:
        """Save cloud scanning results to files"""
        try:
            # Save individual results
            for i, result in enumerate(self.results):
                result_file = self.output_dir / f"cloud_scan_result_{i}.json"
                with open(result_file, 'w') as f:
                    json.dump(asdict(result), f, indent=2, default=str)

            # Save consolidated results
            consolidated_file = self.output_dir / "cloud_scan_consolidated.json"
            consolidated_data = {
                "scan_summary": {
                    "total_targets": len(set(r.target for r in self.results)),
                    "total_findings": sum(len(r.findings) for r in self.results),
                    "scan_time": time.time(),
                    "cloud_providers": list(set(r.cloud_provider for r in self.results))
                },
                "results": [asdict(r) for r in self.results]
            }
            
            with open(consolidated_file, 'w') as f:
                json.dump(consolidated_data, f, indent=2, default=str)

            logger.info(f"Cloud scan results saved to {self.output_dir}")

        except Exception as e:
            logger.error(f"Error saving cloud results: {str(e)}")

    def get_results_summary(self) -> Dict[str, Any]:
        """Get a summary of cloud scanning results"""
        try:
            total_findings = sum(len(r.findings) for r in self.results)
            severity_counts = {}
            provider_counts = {}
            
            for result in self.results:
                # Count by severity
                for finding in result.findings:
                    severity = finding.get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Count by cloud provider
                provider = result.cloud_provider
                provider_counts[provider] = provider_counts.get(provider, 0) + 1

            return {
                "total_scans": len(self.results),
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "provider_breakdown": provider_counts,
                "scan_types": list(set(r.scan_type for r in self.results))
            }

        except Exception as e:
            logger.error(f"Error generating results summary: {str(e)}")
            return {} 