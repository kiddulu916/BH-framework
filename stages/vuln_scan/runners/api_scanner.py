"""
API Scanner Module for Vulnerability Scanning Stage
Implements Step 5: Scan APIs and Cloud Components (API Scanning)

This module provides comprehensive API vulnerability scanning capabilities:
- OpenAPI/Swagger specification analysis
- GraphQL endpoint testing
- REST API fuzzing and parameter testing
- Authentication bypass testing
- Rate limiting and security header analysis
- API-specific vulnerability detection
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
class APIScanResult:
    """API scan result data structure"""
    target: str
    scan_type: str
    tool: str
    findings: List[Dict[str, Any]]
    raw_output: str
    scan_time: float
    status: str
    error_message: Optional[str] = None

class APIScanner:
    """API vulnerability scanner for comprehensive API testing"""

    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        self.output_dir = output_dir / "api_scan"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limit_config = rate_limit_config or {}
        self.results: List[APIScanResult] = []

    def run_api_scanning(self, targets: Dict[str, List[str]]) -> bool:
        """Execute comprehensive API vulnerability scanning"""
        try:
            logger.info(f"{Fore.CYAN}Starting API vulnerability scanning{Style.RESET_ALL}")
            
            api_targets = targets.get("apis", [])
            if not api_targets:
                logger.warning("No API targets found for scanning")
                return True

            logger.info(f"Found {len(api_targets)} API targets for scanning")

            # Step 5.1: OpenAPI/Swagger Specification Analysis
            self.scan_openapi_specifications(api_targets)

            # Step 5.2: GraphQL Endpoint Testing
            self.scan_graphql_endpoints(api_targets)

            # Step 5.3: REST API Fuzzing and Parameter Testing
            self.scan_rest_apis(api_targets)

            # Step 5.4: Authentication Bypass Testing
            self.test_authentication_bypass(api_targets)

            # Step 5.5: Rate Limiting and Security Header Analysis
            self.analyze_security_headers(api_targets)

            # Step 5.6: API-Specific Vulnerability Detection
            self.detect_api_vulnerabilities(api_targets)

            # Save consolidated results
            self.save_api_results()

            logger.info(f"{Fore.GREEN}API scanning completed successfully!{Style.RESET_ALL}")
            return True

        except Exception as e:
            logger.error(f"API scanning failed: {str(e)}")
            return False

    def scan_openapi_specifications(self, api_targets: List[str]) -> None:
        """Step 5.1: Analyze OpenAPI/Swagger specifications"""
        logger.info("Step 5.1: Analyzing OpenAPI/Swagger specifications")

        for target in api_targets:
            try:
                # Common OpenAPI specification endpoints
                spec_endpoints = [
                    f"{target}/swagger.json",
                    f"{target}/api-docs",
                    f"{target}/openapi.json",
                    f"{target}/swagger/v1/swagger.json",
                    f"{target}/api/swagger.json",
                    f"{target}/docs/swagger.json"
                ]

                for spec_endpoint in spec_endpoints:
                    if self.analyze_openapi_spec(spec_endpoint):
                        break

            except Exception as e:
                logger.error(f"Error scanning OpenAPI spec for {target}: {str(e)}")

    def analyze_openapi_spec(self, spec_url: str) -> bool:
        """Analyze a single OpenAPI specification"""
        try:
            logger.info(f"Analyzing OpenAPI spec: {spec_url}")
            
            response = requests.get(spec_url, timeout=10)
            if response.status_code != 200:
                return False

            spec_data = response.json()
            findings = []

            # Analyze specification for security issues
            findings.extend(self.analyze_openapi_security(spec_data))
            findings.extend(self.analyze_openapi_endpoints(spec_data))
            findings.extend(self.analyze_openapi_parameters(spec_data))

            if findings:
                result = APIScanResult(
                    target=spec_url,
                    scan_type="openapi_analysis",
                    tool="openapi-validator",
                    findings=findings,
                    raw_output=json.dumps(spec_data, indent=2),
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

            return True

        except Exception as e:
            logger.error(f"Error analyzing OpenAPI spec {spec_url}: {str(e)}")
            return False

    def analyze_openapi_security(self, spec_data: Dict) -> List[Dict]:
        """Analyze OpenAPI specification for security issues"""
        findings = []

        # Check for missing security definitions
        if "securityDefinitions" not in spec_data and "components" not in spec_data:
            findings.append({
                "type": "missing_security",
                "severity": "medium",
                "description": "No security definitions found in OpenAPI specification",
                "recommendation": "Define security schemes for API endpoints"
            })

        # Check for insecure schemes
        security_defs = spec_data.get("securityDefinitions", {})
        for scheme_name, scheme_def in security_defs.items():
            if scheme_def.get("type") == "http" and scheme_def.get("scheme") != "bearer":
                findings.append({
                    "type": "insecure_auth_scheme",
                    "severity": "high",
                    "description": f"Insecure authentication scheme: {scheme_name}",
                    "scheme": scheme_def,
                    "recommendation": "Use Bearer token authentication"
                })

        return findings

    def analyze_openapi_endpoints(self, spec_data: Dict) -> List[Dict]:
        """Analyze OpenAPI endpoints for potential vulnerabilities"""
        findings = []

        paths = spec_data.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "delete"]:
                    # Check for sensitive operations without authentication
                    if not details.get("security"):
                        findings.append({
                            "type": "unprotected_endpoint",
                            "severity": "medium",
                            "description": f"Endpoint {method.upper()} {path} has no security requirements",
                            "endpoint": f"{method.upper()} {path}",
                            "recommendation": "Add authentication requirements"
                        })

                    # Check for potentially dangerous operations
                    if method.lower() in ["delete", "put"] and not details.get("security"):
                        findings.append({
                            "type": "dangerous_unprotected_operation",
                            "severity": "high",
                            "description": f"Dangerous operation {method.upper()} {path} has no security requirements",
                            "endpoint": f"{method.upper()} {path}",
                            "recommendation": "Add strong authentication and authorization"
                        })

        return findings

    def analyze_openapi_parameters(self, spec_data: Dict) -> List[Dict]:
        """Analyze OpenAPI parameters for potential injection vulnerabilities"""
        findings = []

        paths = spec_data.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                parameters = details.get("parameters", [])
                for param in parameters:
                    if param.get("in") == "query" and not param.get("required"):
                        findings.append({
                            "type": "optional_query_parameter",
                            "severity": "low",
                            "description": f"Optional query parameter in {method.upper()} {path}",
                            "parameter": param.get("name"),
                            "endpoint": f"{method.upper()} {path}",
                            "recommendation": "Validate all query parameters"
                        })

        return findings

    def scan_graphql_endpoints(self, api_targets: List[str]) -> None:
        """Step 5.2: Test GraphQL endpoints for vulnerabilities"""
        logger.info("Step 5.2: Testing GraphQL endpoints")

        for target in api_targets:
            try:
                # Common GraphQL endpoints
                graphql_endpoints = [
                    f"{target}/graphql",
                    f"{target}/graphiql",
                    f"{target}/api/graphql",
                    f"{target}/gql"
                ]

                for endpoint in graphql_endpoints:
                    self.test_graphql_endpoint(endpoint)

            except Exception as e:
                logger.error(f"Error scanning GraphQL for {target}: {str(e)}")

    def test_graphql_endpoint(self, endpoint: str) -> None:
        """Test a single GraphQL endpoint for vulnerabilities"""
        try:
            logger.info(f"Testing GraphQL endpoint: {endpoint}")

            # Test 1: Introspection query
            introspection_result = self.test_graphql_introspection(endpoint)
            
            # Test 2: Common GraphQL vulnerabilities
            vuln_result = self.test_graphql_vulnerabilities(endpoint)

            # Combine results
            if introspection_result or vuln_result:
                findings = []
                if introspection_result:
                    findings.extend(introspection_result.findings)
                if vuln_result:
                    findings.extend(vuln_result.findings)

                result = APIScanResult(
                    target=endpoint,
                    scan_type="graphql_testing",
                    tool="graphql-scanner",
                    findings=findings,
                    raw_output=f"Introspection: {introspection_result.raw_output if introspection_result else 'N/A'}\nVulns: {vuln_result.raw_output if vuln_result else 'N/A'}",
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing GraphQL endpoint {endpoint}: {str(e)}")

    def test_graphql_introspection(self, endpoint: str) -> Optional[APIScanResult]:
        """Test GraphQL introspection query"""
        try:
            introspection_query = """
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  description
                  locations
                  args {
                    ...InputValue
                  }
                }
              }
            }

            fragment FullType on __Type {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }

            fragment InputValue on __InputValue {
              name
              description
              type { ...TypeRef }
              defaultValue
            }

            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """

            headers = {"Content-Type": "application/json"}
            payload = {"query": introspection_query}

            response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "data" in data and "__schema" in data["data"]:
                    return APIScanResult(
                        target=endpoint,
                        scan_type="graphql_introspection",
                        tool="graphql-introspection",
                        findings=[{
                            "type": "introspection_enabled",
                            "severity": "medium",
                            "description": "GraphQL introspection is enabled",
                            "recommendation": "Disable introspection in production"
                        }],
                        raw_output=json.dumps(data, indent=2),
                        scan_time=time.time(),
                        status="completed"
                    )

        except Exception as e:
            logger.error(f"Error testing GraphQL introspection for {endpoint}: {str(e)}")

        return None

    def test_graphql_vulnerabilities(self, endpoint: str) -> Optional[APIScanResult]:
        """Test for common GraphQL vulnerabilities"""
        try:
            findings = []

            # Test 1: NoSQL injection via GraphQL
            nosql_payload = {
                "query": """
                query {
                  users(filter: {username: {"$ne": null}}) {
                    id
                    username
                    email
                  }
                }
                """
            }

            response = requests.post(endpoint, json=nosql_payload, timeout=10)
            if response.status_code == 200:
                findings.append({
                    "type": "potential_nosql_injection",
                    "severity": "high",
                    "description": "Potential NoSQL injection vulnerability detected",
                    "recommendation": "Implement proper input validation and sanitization"
                })

            # Test 2: Batch query attack
            batch_payload = [
                {"query": "query { users { id } }"},
                {"query": "query { users { id } }"},
                {"query": "query { users { id } }"}
            ]

            response = requests.post(endpoint, json=batch_payload, timeout=10)
            if response.status_code == 200:
                findings.append({
                    "type": "batch_query_vulnerability",
                    "severity": "medium",
                    "description": "Batch query processing detected",
                    "recommendation": "Implement query complexity analysis and rate limiting"
                })

            if findings:
                return APIScanResult(
                    target=endpoint,
                    scan_type="graphql_vulnerabilities",
                    tool="graphql-vuln-scanner",
                    findings=findings,
                    raw_output=json.dumps(batch_payload, indent=2),
                    scan_time=time.time(),
                    status="completed"
                )

        except Exception as e:
            logger.error(f"Error testing GraphQL vulnerabilities for {endpoint}: {str(e)}")

        return None

    def scan_rest_apis(self, api_targets: List[str]) -> None:
        """Step 5.3: REST API fuzzing and parameter testing"""
        logger.info("Step 5.3: REST API fuzzing and parameter testing")

        for target in api_targets:
            try:
                self.fuzz_rest_api(target)
            except Exception as e:
                logger.error(f"Error fuzzing REST API for {target}: {str(e)}")

    def fuzz_rest_api(self, target: str) -> None:
        """Fuzz a REST API for vulnerabilities"""
        try:
            logger.info(f"Fuzzing REST API: {target}")

            # Common API endpoints to test
            common_endpoints = [
                "/api/users",
                "/api/admin",
                "/api/config",
                "/api/health",
                "/api/status",
                "/api/v1/users",
                "/api/v2/users",
                "/users",
                "/admin",
                "/config"
            ]

            findings = []
            raw_output = ""

            for endpoint in common_endpoints:
                full_url = f"{target}{endpoint}"
                
                # Test different HTTP methods
                for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
                    try:
                        response = requests.request(
                            method, 
                            full_url, 
                            timeout=5,
                            allow_redirects=False
                        )
                        
                        raw_output += f"{method} {full_url}: {response.status_code}\n"

                        # Check for interesting responses
                        if response.status_code in [200, 201, 403, 500]:
                            findings.append({
                                "type": "endpoint_discovered",
                                "severity": "info",
                                "description": f"Endpoint {method} {full_url} returned {response.status_code}",
                                "endpoint": f"{method} {full_url}",
                                "status_code": response.status_code
                            })

                        # Check for potential information disclosure
                        if response.status_code == 500 and "error" in response.text.lower():
                            findings.append({
                                "type": "information_disclosure",
                                "severity": "medium",
                                "description": f"Potential information disclosure in {method} {full_url}",
                                "endpoint": f"{method} {full_url}",
                                "recommendation": "Implement proper error handling"
                            })

                    except requests.exceptions.RequestException:
                        continue

            if findings:
                result = APIScanResult(
                    target=target,
                    scan_type="rest_api_fuzzing",
                    tool="api-fuzzer",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error fuzzing REST API {target}: {str(e)}")

    def test_authentication_bypass(self, api_targets: List[str]) -> None:
        """Step 5.4: Test for authentication bypass vulnerabilities"""
        logger.info("Step 5.4: Testing authentication bypass")

        for target in api_targets:
            try:
                self.test_auth_bypass_techniques(target)
            except Exception as e:
                logger.error(f"Error testing auth bypass for {target}: {str(e)}")

    def test_auth_bypass_techniques(self, target: str) -> None:
        """Test various authentication bypass techniques"""
        try:
            logger.info(f"Testing authentication bypass for: {target}")

            findings = []
            raw_output = ""

            # Test 1: Missing authentication headers
            response = requests.get(f"{target}/api/users", timeout=5)
            raw_output += f"Missing auth: {response.status_code}\n"
            
            if response.status_code == 200:
                findings.append({
                    "type": "missing_authentication",
                    "severity": "high",
                    "description": "Endpoint accessible without authentication",
                    "endpoint": f"{target}/api/users",
                    "recommendation": "Implement authentication requirements"
                })

            # Test 2: Weak authentication headers
            weak_headers = [
                {"Authorization": "Bearer null"},
                {"Authorization": "Bearer undefined"},
                {"Authorization": "Bearer "},
                {"X-API-Key": "test"},
                {"X-API-Key": "demo"}
            ]

            for header in weak_headers:
                response = requests.get(f"{target}/api/users", headers=header, timeout=5)
                raw_output += f"Weak auth {header}: {response.status_code}\n"
                
                if response.status_code == 200:
                    findings.append({
                        "type": "weak_authentication",
                        "severity": "high",
                        "description": f"Endpoint accessible with weak authentication: {header}",
                        "endpoint": f"{target}/api/users",
                        "header": header,
                        "recommendation": "Implement strong authentication validation"
                    })

            if findings:
                result = APIScanResult(
                    target=target,
                    scan_type="authentication_bypass",
                    tool="auth-bypass-tester",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error testing auth bypass for {target}: {str(e)}")

    def analyze_security_headers(self, api_targets: List[str]) -> None:
        """Step 5.5: Analyze security headers and rate limiting"""
        logger.info("Step 5.5: Analyzing security headers")

        for target in api_targets:
            try:
                self.analyze_target_security_headers(target)
            except Exception as e:
                logger.error(f"Error analyzing security headers for {target}: {str(e)}")

    def analyze_target_security_headers(self, target: str) -> None:
        """Analyze security headers for a specific target"""
        try:
            logger.info(f"Analyzing security headers for: {target}")

            response = requests.get(target, timeout=10)
            headers = response.headers

            findings = []
            raw_output = f"Headers: {dict(headers)}\n"

            # Check for missing security headers
            security_headers = {
                "X-Frame-Options": "Missing X-Frame-Options header",
                "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                "X-XSS-Protection": "Missing X-XSS-Protection header",
                "Strict-Transport-Security": "Missing HSTS header",
                "Content-Security-Policy": "Missing CSP header"
            }

            for header, description in security_headers.items():
                if header not in headers:
                    findings.append({
                        "type": "missing_security_header",
                        "severity": "medium",
                        "description": description,
                        "header": header,
                        "recommendation": f"Implement {header} header"
                    })

            # Check for weak security header values
            if "X-Frame-Options" in headers and headers["X-Frame-Options"] == "ALLOWALL":
                findings.append({
                    "type": "weak_security_header",
                    "severity": "medium",
                    "description": "Weak X-Frame-Options value",
                    "header": "X-Frame-Options",
                    "value": headers["X-Frame-Options"],
                    "recommendation": "Use DENY or SAMEORIGIN"
                })

            # Check for rate limiting headers
            rate_limit_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"]
            rate_limit_found = any(header in headers for header in rate_limit_headers)
            
            if not rate_limit_found:
                findings.append({
                    "type": "missing_rate_limiting",
                    "severity": "medium",
                    "description": "No rate limiting headers detected",
                    "recommendation": "Implement rate limiting with appropriate headers"
                })

            if findings:
                result = APIScanResult(
                    target=target,
                    scan_type="security_headers",
                    tool="header-analyzer",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error analyzing security headers for {target}: {str(e)}")

    def detect_api_vulnerabilities(self, api_targets: List[str]) -> None:
        """Step 5.6: Detect API-specific vulnerabilities"""
        logger.info("Step 5.6: Detecting API-specific vulnerabilities")

        for target in api_targets:
            try:
                self.detect_target_vulnerabilities(target)
            except Exception as e:
                logger.error(f"Error detecting vulnerabilities for {target}: {str(e)}")

    def detect_target_vulnerabilities(self, target: str) -> None:
        """Detect API-specific vulnerabilities for a target"""
        try:
            logger.info(f"Detecting API vulnerabilities for: {target}")

            findings = []
            raw_output = ""

            # Test for common API vulnerabilities
            vuln_tests = [
                {
                    "name": "sql_injection",
                    "payloads": ["'", "1' OR '1'='1", "1; DROP TABLE users;--"],
                    "endpoint": "/api/users?id="
                },
                {
                    "name": "xss",
                    "payloads": ["<script>alert('xss')</script>", "javascript:alert('xss')"],
                    "endpoint": "/api/search?q="
                },
                {
                    "name": "path_traversal",
                    "payloads": ["../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
                    "endpoint": "/api/files?path="
                }
            ]

            for test in vuln_tests:
                for payload in test["payloads"]:
                    try:
                        test_url = f"{target}{test['endpoint']}{payload}"
                        response = requests.get(test_url, timeout=5)
                        raw_output += f"{test['name']} {test_url}: {response.status_code}\n"

                        # Analyze response for potential vulnerabilities
                        if self.analyze_vulnerability_response(response, test["name"]):
                            findings.append({
                                "type": f"potential_{test['name']}",
                                "severity": "high",
                                "description": f"Potential {test['name'].upper()} vulnerability detected",
                                "endpoint": test_url,
                                "payload": payload,
                                "recommendation": f"Implement proper {test['name']} protection"
                            })

                    except requests.exceptions.RequestException:
                        continue

            if findings:
                result = APIScanResult(
                    target=target,
                    scan_type="api_vulnerability_detection",
                    tool="api-vuln-detector",
                    findings=findings,
                    raw_output=raw_output,
                    scan_time=time.time(),
                    status="completed"
                )
                self.results.append(result)

        except Exception as e:
            logger.error(f"Error detecting vulnerabilities for {target}: {str(e)}")

    def analyze_vulnerability_response(self, response: requests.Response, vuln_type: str) -> bool:
        """Analyze response for potential vulnerability indicators"""
        try:
            content = response.text.lower()
            
            if vuln_type == "sql_injection":
                # Check for SQL error messages
                sql_errors = [
                    "sql syntax", "mysql error", "oracle error", "postgresql error",
                    "sqlite error", "database error", "syntax error"
                ]
                return any(error in content for error in sql_errors)
            
            elif vuln_type == "xss":
                # Check if payload is reflected
                return "<script>" in content or "javascript:" in content
            
            elif vuln_type == "path_traversal":
                # Check for file content disclosure
                file_indicators = [
                    "root:x:", "windows", "system32", "etc/passwd", "hosts"
                ]
                return any(indicator in content for indicator in file_indicators)
            
            return False

        except Exception:
            return False

    def save_api_results(self) -> None:
        """Save API scanning results to files"""
        try:
            # Save individual results
            for i, result in enumerate(self.results):
                result_file = self.output_dir / f"api_scan_result_{i}.json"
                with open(result_file, 'w') as f:
                    json.dump(asdict(result), f, indent=2, default=str)

            # Save consolidated results
            consolidated_file = self.output_dir / "api_scan_consolidated.json"
            consolidated_data = {
                "scan_summary": {
                    "total_targets": len(set(r.target for r in self.results)),
                    "total_findings": sum(len(r.findings) for r in self.results),
                    "scan_time": time.time()
                },
                "results": [asdict(r) for r in self.results]
            }
            
            with open(consolidated_file, 'w') as f:
                json.dump(consolidated_data, f, indent=2, default=str)

            logger.info(f"API scan results saved to {self.output_dir}")

        except Exception as e:
            logger.error(f"Error saving API results: {str(e)}")

    def get_results_summary(self) -> Dict[str, Any]:
        """Get a summary of API scanning results"""
        try:
            total_findings = sum(len(r.findings) for r in self.results)
            severity_counts = {}
            
            for result in self.results:
                for finding in result.findings:
                    severity = finding.get("severity", "unknown")
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

            return {
                "total_scans": len(self.results),
                "total_findings": total_findings,
                "severity_breakdown": severity_counts,
                "scan_types": list(set(r.scan_type for r in self.results))
            }

        except Exception as e:
            logger.error(f"Error generating results summary: {str(e)}")
            return {} 