#!/usr/bin/env python3
"""
API Scanner Runner for Stage 4: Step 4.2

This module implements API endpoint scanning with OpenAPI/Swagger integration,
API fuzzing, and systematic API vulnerability testing.
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlparse

import httpx
import yaml
from pydantic import BaseModel

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Represents an API endpoint discovered during scanning."""
    
    url: str
    method: str
    parameters: List[Dict[str, Any]] = None
    headers: Dict[str, str] = None
    body_schema: Optional[Dict[str, Any]] = None
    response_schema: Optional[Dict[str, Any]] = None
    authentication: Optional[str] = None
    rate_limit: Optional[str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []
        if self.headers is None:
            self.headers = {}


@dataclass
class APIFinding:
    """Represents a vulnerability finding from API scanning."""
    
    id: str
    title: str
    description: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    severity: str = "Medium"
    confidence: float = 0.0
    evidence: str = ""
    payload_used: Optional[str] = None
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    vulnerability_type: str = ""


class OpenAPISpec(BaseModel):
    """OpenAPI specification parser."""
    
    openapi: str
    info: Dict[str, Any]
    paths: Dict[str, Any]
    components: Optional[Dict[str, Any]] = None


class APIScanner:
    """API endpoint scanner for vulnerability testing."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.api_dir = self.output_dir / "api_scanning"
        self.api_dir.mkdir(parents=True, exist_ok=True)
        
        # API scanning configuration
        self.api_fuzzing_enabled = config.api_fuzzing_enabled
        self.openapi_import_enabled = config.openapi_import_enabled
        self.rate_limit = config.rate_limit
        
        # Discovered data
        self.discovered_endpoints: List[APIEndpoint] = []
        self.api_findings: List[APIFinding] = []
        
        # HTTP client
        self.client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            verify=False  # For testing purposes
        )
        
        # API fuzzing payloads
        self.fuzzing_payloads = {
            "sql_injection": [
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users--",
                "' OR '1'='1",
                "admin'--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "'\"><script>alert('XSS')</script>"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "& dir",
                "`id`",
                "$(whoami)"
            ],
            "no_sql_injection": [
                "' || '1'=='1",
                "' || 1==1",
                "' || true",
                "'; return true; //",
                "' || this.constructor.constructor('return true')()"
            ]
        }
        
        # Common API endpoints to test
        self.common_api_endpoints = [
            "/api",
            "/api/v1",
            "/api/v2",
            "/rest",
            "/graphql",
            "/swagger",
            "/swagger-ui",
            "/openapi",
            "/docs",
            "/redoc",
            "/api-docs",
            "/api/docs"
        ]
    
    def run_scan(self) -> List[APIFinding]:
        """
        Run comprehensive API vulnerability scanning.
        
        Returns:
            List[APIFinding]: List of vulnerability findings
        """
        logger.info("Starting API vulnerability scanning...")
        
        try:
            # Load structured input data
            structured_data = self._load_structured_data()
            
            # Discover API endpoints
            self._discover_api_endpoints(structured_data.get("endpoints", []))
            
            # Import OpenAPI/Swagger specifications if available
            if self.openapi_import_enabled:
                self._import_openapi_specs()
            
            # Test each discovered endpoint
            for endpoint in self.discovered_endpoints:
                self._test_api_endpoint(endpoint)
            
            # Perform API fuzzing if enabled
            if self.api_fuzzing_enabled:
                self._perform_api_fuzzing()
            
            # Test for common API vulnerabilities
            self._test_common_api_vulnerabilities()
            
            # Save results
            self.save_results()
            
            logger.info(f"API scanning completed. Found {len(self.api_findings)} potential vulnerabilities")
            
            return self.api_findings
            
        except Exception as e:
            logger.error(f"Error in API scanning: {str(e)}")
            raise
    
    def _load_structured_data(self) -> Dict[str, Any]:
        """Load structured input data from data preparation step."""
        try:
            structured_file = self.output_dir / "data_preparation" / "structured_input.json"
            
            if structured_file.exists():
                with open(structured_file, 'r') as f:
                    return json.load(f)
            else:
                logger.warning("Structured input data not found, using default data")
                return self._create_default_structured_data()
                
        except Exception as e:
            logger.error(f"Error loading structured data: {str(e)}")
            return self._create_default_structured_data()
    
    def _create_default_structured_data(self) -> Dict[str, Any]:
        """Create default structured data if none exists."""
        return {
            "target_info": {
                "domain": self.config.target,
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            },
            "endpoints": [
                {
                    "url": f"https://{self.config.target}/api",
                    "method": "GET",
                    "params": [],
                    "technology": "",
                    "vulnerability_hints": []
                }
            ],
            "technologies": [],
            "network_info": {},
            "cloud_info": {},
            "preliminary_vulns": [],
            "scan_config": {}
        }
    
    def _discover_api_endpoints(self, known_endpoints: List[Dict[str, Any]]):
        """Discover API endpoints through various methods."""
        logger.info("Discovering API endpoints...")
        
        try:
            # Add known endpoints
            for endpoint_data in known_endpoints:
                if "api" in endpoint_data.get("url", "").lower():
                    endpoint = APIEndpoint(
                        url=endpoint_data.get("url", ""),
                        method=endpoint_data.get("method", "GET"),
                        parameters=endpoint_data.get("params", [])
                    )
                    self.discovered_endpoints.append(endpoint)
            
            # Discover common API endpoints
            self._discover_common_api_endpoints()
            
            # Discover through directory traversal
            self._discover_api_directories()
            
            # Discover through response analysis
            self._discover_from_responses()
            
            logger.info(f"API endpoint discovery completed. Found {len(self.discovered_endpoints)} endpoints")
            
        except Exception as e:
            logger.error(f"Error discovering API endpoints: {str(e)}")
    
    def _discover_common_api_endpoints(self):
        """Discover common API endpoints."""
        try:
            base_url = f"https://{self.config.target}"
            
            for path in self.common_api_endpoints:
                url = urljoin(base_url, path)
                endpoint = APIEndpoint(url=url, method="GET")
                self.discovered_endpoints.append(endpoint)
                
        except Exception as e:
            logger.error(f"Error discovering common API endpoints: {str(e)}")
    
    def _discover_api_directories(self):
        """Discover API endpoints through directory traversal."""
        try:
            # This would typically use tools like dirb, gobuster, or custom wordlists
            # For now, we'll test some common API-related paths
            api_paths = [
                "/api/users", "/api/admin", "/api/auth", "/api/data",
                "/v1/users", "/v1/admin", "/v1/auth", "/v1/data",
                "/rest/users", "/rest/admin", "/rest/auth", "/rest/data"
            ]
            
            base_url = f"https://{self.config.target}"
            
            for path in api_paths:
                url = urljoin(base_url, path)
                endpoint = APIEndpoint(url=url, method="GET")
                self.discovered_endpoints.append(endpoint)
                
        except Exception as e:
            logger.error(f"Error discovering API directories: {str(e)}")
    
    def _discover_from_responses(self):
        """Discover API endpoints from response analysis."""
        try:
            # Test main domain for API-related responses
            main_url = f"https://{self.config.target}"
            
            # This would analyze responses for API endpoints
            # For now, we'll add some common patterns
            logger.info("Analyzing responses for API endpoint discovery")
            
        except Exception as e:
            logger.error(f"Error discovering from responses: {str(e)}")
    
    def _import_openapi_specs(self):
        """Import OpenAPI/Swagger specifications."""
        try:
            logger.info("Importing OpenAPI/Swagger specifications...")
            
            # Common OpenAPI spec locations
            spec_urls = [
                f"https://{self.config.target}/swagger.json",
                f"https://{self.config.target}/openapi.json",
                f"https://{self.config.target}/api/swagger.json",
                f"https://{self.config.target}/api/openapi.json",
                f"https://{self.config.target}/swagger/v1/swagger.json"
            ]
            
            for spec_url in spec_urls:
                try:
                    spec_data = self._fetch_openapi_spec(spec_url)
                    if spec_data:
                        self._parse_openapi_spec(spec_data, spec_url)
                        break
                except Exception as e:
                    logger.debug(f"Failed to fetch OpenAPI spec from {spec_url}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error importing OpenAPI specs: {str(e)}")
    
    def _fetch_openapi_spec(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch OpenAPI specification from URL."""
        try:
            response = httpx.get(url, timeout=10)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if "json" in content_type:
                    return response.json()
                elif "yaml" in content_type or "yml" in content_type:
                    return yaml.safe_load(response.text)
            return None
        except Exception as e:
            logger.debug(f"Error fetching OpenAPI spec from {url}: {str(e)}")
            return None
    
    def _parse_openapi_spec(self, spec_data: Dict[str, Any], base_url: str):
        """Parse OpenAPI specification and extract endpoints."""
        try:
            spec = OpenAPISpec(**spec_data)
            
            for path, path_data in spec.paths.items():
                for method, method_data in path_data.items():
                    if method.upper() in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                        # Construct full URL
                        full_url = urljoin(base_url, path)
                        
                        # Extract parameters
                        parameters = []
                        if "parameters" in method_data:
                            for param in method_data["parameters"]:
                                parameters.append({
                                    "name": param.get("name", ""),
                                    "in": param.get("in", ""),
                                    "type": param.get("type", ""),
                                    "required": param.get("required", False)
                                })
                        
                        # Extract request body schema
                        body_schema = None
                        if "requestBody" in method_data:
                            body_schema = method_data["requestBody"]
                        
                        # Extract response schema
                        response_schema = None
                        if "responses" in method_data:
                            response_schema = method_data["responses"]
                        
                        endpoint = APIEndpoint(
                            url=full_url,
                            method=method.upper(),
                            parameters=parameters,
                            body_schema=body_schema,
                            response_schema=response_schema
                        )
                        
                        self.discovered_endpoints.append(endpoint)
            
            logger.info(f"Imported {len(spec.paths)} paths from OpenAPI specification")
            
        except Exception as e:
            logger.error(f"Error parsing OpenAPI spec: {str(e)}")
    
    def _test_api_endpoint(self, endpoint: APIEndpoint):
        """Test a single API endpoint for vulnerabilities."""
        try:
            logger.info(f"Testing API endpoint: {endpoint.method} {endpoint.url}")
            
            # Test for common API vulnerabilities
            self._test_authentication_bypass(endpoint)
            self._test_rate_limiting_bypass(endpoint)
            self._test_parameter_pollution(endpoint)
            self._test_method_override(endpoint)
            self._test_content_type_bypass(endpoint)
            
            # Test parameters for injection vulnerabilities
            for param in endpoint.parameters:
                self._test_parameter_injection(endpoint, param)
            
            # Rate limiting
            time.sleep(1 / self.rate_limit)
            
        except Exception as e:
            logger.error(f"Error testing API endpoint {endpoint.url}: {str(e)}")
    
    def _test_authentication_bypass(self, endpoint: APIEndpoint):
        """Test for authentication bypass vulnerabilities."""
        try:
            # Test without authentication
            response = httpx.get(endpoint.url, timeout=10)
            
            # Check if endpoint is accessible without auth
            if response.status_code == 200:
                finding = APIFinding(
                    id=f"api_{len(self.api_findings) + 1}",
                    title="Potential Authentication Bypass",
                    description="API endpoint accessible without authentication",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    severity="High",
                    confidence=0.8,
                    evidence=f"Endpoint returned {response.status_code} without authentication",
                    response_code=response.status_code,
                    vulnerability_type="Authentication Bypass"
                )
                self.api_findings.append(finding)
            
            # Test with common authentication bypass headers
            bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Original-URL": "/admin"},
                {"X-Rewrite-URL": "/admin"},
                {"X-Custom-IP-Authorization": "127.0.0.1"}
            ]
            
            for headers in bypass_headers:
                response = httpx.get(endpoint.url, headers=headers, timeout=10)
                if response.status_code == 200:
                    finding = APIFinding(
                        id=f"api_{len(self.api_findings) + 1}",
                        title="Potential Authentication Bypass via Headers",
                        description="API endpoint accessible with bypass headers",
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        severity="High",
                        confidence=0.7,
                        evidence=f"Endpoint returned {response.status_code} with bypass headers: {headers}",
                        response_code=response.status_code,
                        vulnerability_type="Authentication Bypass"
                    )
                    self.api_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing authentication bypass: {str(e)}")
    
    def _test_rate_limiting_bypass(self, endpoint: APIEndpoint):
        """Test for rate limiting bypass vulnerabilities."""
        try:
            # Send multiple requests rapidly
            responses = []
            for i in range(10):
                response = httpx.get(endpoint.url, timeout=5)
                responses.append(response)
                time.sleep(0.1)  # Small delay between requests
            
            # Check if all requests succeeded (potential rate limiting bypass)
            success_count = sum(1 for r in responses if r.status_code == 200)
            if success_count == len(responses):
                finding = APIFinding(
                    id=f"api_{len(self.api_findings) + 1}",
                    title="Potential Rate Limiting Bypass",
                    description="API endpoint may not have proper rate limiting",
                    endpoint=endpoint.url,
                    method=endpoint.method,
                    severity="Medium",
                    confidence=0.6,
                    evidence=f"All {len(responses)} rapid requests returned success",
                    response_code=200,
                    vulnerability_type="Rate Limiting Bypass"
                )
                self.api_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing rate limiting bypass: {str(e)}")
    
    def _test_parameter_pollution(self, endpoint: APIEndpoint):
        """Test for HTTP parameter pollution vulnerabilities."""
        try:
            # Test with duplicate parameters
            test_params = {
                "id": "1",
                "id": "2",  # Duplicate parameter
                "user": "admin",
                "user": "guest"  # Duplicate parameter
            }
            
            response = httpx.get(endpoint.url, params=test_params, timeout=10)
            
            # Analyze response for potential parameter pollution
            if response.status_code == 200:
                # Check if response contains sensitive information
                response_text = response.text.lower()
                sensitive_indicators = ["admin", "root", "password", "secret", "token"]
                
                for indicator in sensitive_indicators:
                    if indicator in response_text:
                        finding = APIFinding(
                            id=f"api_{len(self.api_findings) + 1}",
                            title="Potential HTTP Parameter Pollution",
                            description="Sensitive information exposed with duplicate parameters",
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            severity="Medium",
                            confidence=0.7,
                            evidence=f"Found '{indicator}' in response with duplicate parameters",
                            response_code=response.status_code,
                            vulnerability_type="HTTP Parameter Pollution"
                        )
                        self.api_findings.append(finding)
                        break
                        
        except Exception as e:
            logger.error(f"Error testing parameter pollution: {str(e)}")
    
    def _test_method_override(self, endpoint: APIEndpoint):
        """Test for HTTP method override vulnerabilities."""
        try:
            # Test method override headers
            override_headers = [
                {"X-HTTP-Method": "DELETE"},
                {"X-HTTP-Method-Override": "DELETE"},
                {"X-Method-Override": "DELETE"},
                {"_method": "DELETE"}
            ]
            
            for headers in override_headers:
                response = httpx.post(endpoint.url, headers=headers, timeout=10)
                
                # Check if method override worked
                if response.status_code in [200, 204, 405]:
                    finding = APIFinding(
                        id=f"api_{len(self.api_findings) + 1}",
                        title="Potential HTTP Method Override",
                        description="HTTP method override may be possible",
                        endpoint=endpoint.url,
                        method="POST",
                        severity="Medium",
                        confidence=0.6,
                        evidence=f"Method override headers returned {response.status_code}",
                        response_code=response.status_code,
                        vulnerability_type="HTTP Method Override"
                    )
                    self.api_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing method override: {str(e)}")
    
    def _test_content_type_bypass(self, endpoint: APIEndpoint):
        """Test for content type bypass vulnerabilities."""
        try:
            # Test with different content types
            content_types = [
                "application/json",
                "application/xml",
                "text/plain",
                "application/x-www-form-urlencoded"
            ]
            
            test_data = {"test": "data"}
            
            for content_type in content_types:
                headers = {"Content-Type": content_type}
                response = httpx.post(endpoint.url, json=test_data, headers=headers, timeout=10)
                
                # Check if content type bypass worked
                if response.status_code == 200:
                    finding = APIFinding(
                        id=f"api_{len(self.api_findings) + 1}",
                        title="Potential Content Type Bypass",
                        description="API may accept unexpected content types",
                        endpoint=endpoint.url,
                        method="POST",
                        severity="Low",
                        confidence=0.5,
                        evidence=f"Content type {content_type} returned {response.status_code}",
                        response_code=response.status_code,
                        vulnerability_type="Content Type Bypass"
                    )
                    self.api_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing content type bypass: {str(e)}")
    
    def _test_parameter_injection(self, endpoint: APIEndpoint, parameter: Dict[str, Any]):
        """Test a parameter for injection vulnerabilities."""
        try:
            param_name = parameter.get("name", "")
            param_type = parameter.get("type", "")
            
            # Test SQL injection
            for payload in self.fuzzing_payloads["sql_injection"]:
                test_params = {param_name: payload}
                response = httpx.get(endpoint.url, params=test_params, timeout=10)
                
                # Check for SQL error indicators
                response_text = response.text.lower()
                sql_errors = ["sql syntax", "mysql error", "oracle error", "postgresql error"]
                
                for error in sql_errors:
                    if error in response_text:
                        finding = APIFinding(
                            id=f"api_{len(self.api_findings) + 1}",
                            title="Potential SQL Injection",
                            description=f"SQL injection detected in parameter '{param_name}'",
                            endpoint=endpoint.url,
                            method=endpoint.method,
                            parameter=param_name,
                            severity="Critical",
                            confidence=0.9,
                            evidence=f"SQL error '{error}' found with payload '{payload}'",
                            payload_used=payload,
                            response_code=response.status_code,
                            vulnerability_type="SQL Injection"
                        )
                        self.api_findings.append(finding)
                        break
            
            # Test XSS
            for payload in self.fuzzing_payloads["xss"]:
                test_params = {param_name: payload}
                response = httpx.get(endpoint.url, params=test_params, timeout=10)
                
                # Check if payload is reflected
                if payload in response.text:
                    finding = APIFinding(
                        id=f"api_{len(self.api_findings) + 1}",
                        title="Potential Reflected XSS",
                        description=f"XSS payload reflected in parameter '{param_name}'",
                        endpoint=endpoint.url,
                        method=endpoint.method,
                        parameter=param_name,
                        severity="High",
                        confidence=0.8,
                        evidence=f"XSS payload '{payload}' reflected in response",
                        payload_used=payload,
                        response_code=response.status_code,
                        vulnerability_type="XSS"
                    )
                    self.api_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing parameter injection: {str(e)}")
    
    def _perform_api_fuzzing(self):
        """Perform comprehensive API fuzzing."""
        try:
            logger.info("Performing API fuzzing...")
            
            # Fuzz common API paths
            fuzz_paths = [
                "/api/user/", "/api/admin/", "/api/data/", "/api/config/",
                "/v1/user/", "/v1/admin/", "/v1/data/", "/v1/config/",
                "/rest/user/", "/rest/admin/", "/rest/data/", "/rest/config/"
            ]
            
            base_url = f"https://{self.config.target}"
            
            for path in fuzz_paths:
                url = urljoin(base_url, path)
                
                # Test with different HTTP methods
                for method in ["GET", "POST", "PUT", "DELETE"]:
                    self._fuzz_endpoint(url, method)
                    
        except Exception as e:
            logger.error(f"Error performing API fuzzing: {str(e)}")
    
    def _fuzz_endpoint(self, url: str, method: str):
        """Fuzz a single endpoint with various payloads."""
        try:
            # Test with different payload types
            for payload_type, payloads in self.fuzzing_payloads.items():
                for payload in payloads[:3]:  # Limit to first 3 payloads per type
                    try:
                        if method == "GET":
                            response = httpx.get(url, params={"test": payload}, timeout=10)
                        else:
                            response = httpx.request(method, url, json={"test": payload}, timeout=10)
                        
                        # Analyze response for vulnerabilities
                        self._analyze_fuzz_response(url, method, payload, payload_type, response)
                        
                        # Rate limiting
                        time.sleep(1 / self.rate_limit)
                        
                    except Exception as e:
                        logger.debug(f"Error fuzzing {url} with {payload}: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Error fuzzing endpoint {url}: {str(e)}")
    
    def _analyze_fuzz_response(self, url: str, method: str, payload: str, payload_type: str, response):
        """Analyze fuzzing response for vulnerabilities."""
        try:
            response_text = response.text.lower()
            
            # Check for error messages
            if response.status_code >= 400:
                error_indicators = {
                    "sql_injection": ["sql syntax", "mysql error", "oracle error"],
                    "xss": ["<script>", "javascript:"],
                    "path_traversal": ["root:", "windows", "system32"],
                    "command_injection": ["uid=", "gid=", "groups="],
                    "no_sql_injection": ["mongodb", "nosql", "mongo"]
                }
                
                if payload_type in error_indicators:
                    for indicator in error_indicators[payload_type]:
                        if indicator in response_text:
                            finding = APIFinding(
                                id=f"api_{len(self.api_findings) + 1}",
                                title=f"Potential {payload_type.replace('_', ' ').title()}",
                                description=f"{payload_type.replace('_', ' ').title()} detected during fuzzing",
                                endpoint=url,
                                method=method,
                                severity="High",
                                confidence=0.8,
                                evidence=f"Found '{indicator}' in error response with payload '{payload}'",
                                payload_used=payload,
                                response_code=response.status_code,
                                vulnerability_type=payload_type.replace('_', ' ').title()
                            )
                            self.api_findings.append(finding)
                            break
                            
        except Exception as e:
            logger.error(f"Error analyzing fuzz response: {str(e)}")
    
    def _test_common_api_vulnerabilities(self):
        """Test for common API vulnerabilities."""
        try:
            logger.info("Testing for common API vulnerabilities...")
            
            # Test for information disclosure
            self._test_information_disclosure()
            
            # Test for CORS misconfiguration
            self._test_cors_misconfiguration()
            
            # Test for security headers
            self._test_security_headers()
            
        except Exception as e:
            logger.error(f"Error testing common API vulnerabilities: {str(e)}")
    
    def _test_information_disclosure(self):
        """Test for information disclosure vulnerabilities."""
        try:
            # Test common information disclosure endpoints
            info_endpoints = [
                "/api/version", "/api/info", "/api/status", "/api/health",
                "/v1/version", "/v1/info", "/v1/status", "/v1/health",
                "/rest/version", "/rest/info", "/rest/status", "/rest/health"
            ]
            
            base_url = f"https://{self.config.target}"
            
            for path in info_endpoints:
                url = urljoin(base_url, path)
                try:
                    response = httpx.get(url, timeout=10)
                    
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        
                        # Check for sensitive information
                        sensitive_patterns = [
                            "version", "build", "environment", "debug",
                            "database", "config", "secret", "key", "token"
                        ]
                        
                        for pattern in sensitive_patterns:
                            if pattern in response_text:
                                finding = APIFinding(
                                    id=f"api_{len(self.api_findings) + 1}",
                                    title="Potential Information Disclosure",
                                    description=f"Sensitive information '{pattern}' found in API response",
                                    endpoint=url,
                                    method="GET",
                                    severity="Medium",
                                    confidence=0.7,
                                    evidence=f"Found '{pattern}' in response from {url}",
                                    response_code=response.status_code,
                                    vulnerability_type="Information Disclosure"
                                )
                                self.api_findings.append(finding)
                                break
                                
                except Exception as e:
                    logger.debug(f"Error testing {url}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error testing information disclosure: {str(e)}")
    
    def _test_cors_misconfiguration(self):
        """Test for CORS misconfiguration vulnerabilities."""
        try:
            # Test CORS with different origins
            test_origins = [
                "https://evil.com",
                "http://evil.com",
                "null",
                "https://attacker.com"
            ]
            
            base_url = f"https://{self.config.target}/api"
            
            for origin in test_origins:
                headers = {"Origin": origin}
                try:
                    response = httpx.get(base_url, headers=headers, timeout=10)
                    
                    # Check for CORS headers
                    cors_header = response.headers.get("Access-Control-Allow-Origin", "")
                    
                    if cors_header == "*" or origin in cors_header:
                        finding = APIFinding(
                            id=f"api_{len(self.api_findings) + 1}",
                            title="Potential CORS Misconfiguration",
                            description="CORS policy may be too permissive",
                            endpoint=base_url,
                            method="GET",
                            severity="Medium",
                            confidence=0.7,
                            evidence=f"CORS header allows origin '{origin}': {cors_header}",
                            response_code=response.status_code,
                            vulnerability_type="CORS Misconfiguration"
                        )
                        self.api_findings.append(finding)
                        
                except Exception as e:
                    logger.debug(f"Error testing CORS with origin {origin}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error testing CORS misconfiguration: {str(e)}")
    
    def _test_security_headers(self):
        """Test for missing security headers."""
        try:
            base_url = f"https://{self.config.target}/api"
            
            response = httpx.get(base_url, timeout=10)
            
            # Check for important security headers
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Strict-Transport-Security",
                "Content-Security-Policy"
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in response.headers:
                    missing_headers.append(header)
            
            if missing_headers:
                finding = APIFinding(
                    id=f"api_{len(self.api_findings) + 1}",
                    title="Missing Security Headers",
                    description="Important security headers are missing",
                    endpoint=base_url,
                    method="GET",
                    severity="Low",
                    confidence=0.8,
                    evidence=f"Missing security headers: {', '.join(missing_headers)}",
                    response_code=response.status_code,
                    vulnerability_type="Missing Security Headers"
                )
                self.api_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing security headers: {str(e)}")
    
    def save_results(self):
        """Save API scanning results to files."""
        try:
            # Save discovered endpoints
            endpoints_file = self.api_dir / "discovered_endpoints.json"
            with open(endpoints_file, 'w') as f:
                json.dump([endpoint.__dict__ for endpoint in self.discovered_endpoints], f, indent=2)
            
            # Save vulnerability findings
            findings_file = self.api_dir / "api_findings.json"
            with open(findings_file, 'w') as f:
                json.dump([finding.__dict__ for finding in self.api_findings], f, indent=2)
            
            logger.info(f"API scanning results saved to {self.api_dir}")
            
        except Exception as e:
            logger.error(f"Error saving API scanning results: {str(e)}") 