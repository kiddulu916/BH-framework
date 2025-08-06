#!/usr/bin/env python3
"""
Bug Hunting Framework - Security Audit and Penetration Testing Script

This script performs comprehensive security auditing and penetration testing
of the framework to identify vulnerabilities and security weaknesses.

Usage:
    python security_audit.py [--verbose] [--output-format json|html|text]
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import subprocess
import requests
import socket
import ssl
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import nmap
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_audit.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityFinding:
    """Represents a security finding."""
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

@dataclass
class SecurityAuditSummary:
    """Summary of security audit results."""
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    overall_risk_score: float
    recommendations: List[str]
    timestamp: str

class SecurityAuditor:
    """Comprehensive security auditor for the Bug Hunting Framework."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.findings: List[SecurityFinding] = []
        self.base_url = os.getenv('BASE_URL', 'http://localhost:8000')
        self.nm = nmap.PortScanner()
        
    def add_finding(self, category: str, severity: str, title: str, 
                   description: str, evidence: Optional[str] = None,
                   remediation: Optional[str] = None, cve_id: Optional[str] = None,
                   cvss_score: Optional[float] = None):
        """Add a security finding."""
        finding = SecurityFinding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cve_id=cve_id,
            cvss_score=cvss_score
        )
        self.findings.append(finding)
        
        if self.verbose:
            logger.info(f"[{severity}] {category} - {title}: {description}")
        else:
            if severity in ["CRITICAL", "HIGH"]:
                logger.error(f"[{severity}] {category} - {title}: {description}")
            elif severity == "MEDIUM":
                logger.warning(f"[{severity}] {category} - {title}: {description}")
    
    async def audit_network_security(self) -> None:
        """Audit network security and port scanning."""
        logger.info("Auditing network security...")
        
        # Port scanning
        try:
            # Scan localhost for open ports
            self.nm.scan('localhost', '1-65535', arguments='-sS -sV --version-intensity 5')
            
            open_ports = []
            for host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        open_ports.append({
                            'port': port,
                            'service': service.get('name', 'unknown'),
                            'version': service.get('version', 'unknown'),
                            'state': service.get('state', 'unknown')
                        })
            
            # Check for unnecessary open ports
            expected_ports = [80, 443, 8000, 3000, 5432, 6379, 3001, 9090, 9200, 5601]
            unexpected_ports = [p for p in open_ports if p['port'] not in expected_ports]
            
            if unexpected_ports:
                self.add_finding(
                    "Network Security",
                    "MEDIUM",
                    "Unexpected Open Ports",
                    f"Found {len(unexpected_ports)} unexpected open ports",
                    evidence=f"Open ports: {unexpected_ports}",
                    remediation="Close unnecessary ports and configure firewall rules"
                )
            else:
                self.add_finding(
                    "Network Security",
                    "INFO",
                    "Port Configuration",
                    "All open ports are expected and necessary",
                    evidence=f"Open ports: {[p['port'] for p in open_ports]}"
                )
                
        except Exception as e:
            self.add_finding(
                "Network Security",
                "MEDIUM",
                "Port Scan Failed",
                f"Could not perform port scan: {str(e)}",
                remediation="Ensure nmap is installed and accessible"
            )
        
        # Check for default credentials
        await self._check_default_credentials()
    
    async def _check_default_credentials(self) -> None:
        """Check for default credentials in services."""
        logger.info("Checking for default credentials...")
        
        # Check PostgreSQL default credentials
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                database="postgres",
                user="postgres",
                password="postgres"
            )
            self.add_finding(
                "Authentication",
                "CRITICAL",
                "Default PostgreSQL Credentials",
                "PostgreSQL is accessible with default credentials",
                evidence="Successfully connected with postgres/postgres",
                remediation="Change default PostgreSQL password immediately"
            )
            conn.close()
        except Exception:
            # This is expected - default credentials should not work
            pass
        
        # Check Redis default configuration
        try:
            import redis
            r = redis.Redis(host='localhost', port=6379, db=0)
            r.ping()
            self.add_finding(
                "Authentication",
                "HIGH",
                "Redis No Authentication",
                "Redis is accessible without authentication",
                evidence="Successfully connected to Redis without password",
                remediation="Configure Redis authentication with strong password"
            )
        except Exception:
            # This is expected - Redis should require authentication
            pass
    
    async def audit_web_application_security(self) -> None:
        """Audit web application security."""
        logger.info("Auditing web application security...")
        
        # Check for common web vulnerabilities
        await self._check_sql_injection()
        await self._check_xss_vulnerabilities()
        await self._check_csrf_vulnerabilities()
        await self._check_information_disclosure()
        await self._check_security_headers()
        await self._check_ssl_tls_configuration()
    
    async def _check_sql_injection(self) -> None:
        """Check for SQL injection vulnerabilities."""
        logger.info("Checking for SQL injection vulnerabilities...")
        
        # Test common SQL injection payloads
        sql_payloads = [
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT * FROM users--",
            "admin'--",
            "1' OR '1'='1"
        ]
        
        test_endpoints = [
            "/api/targets/",
            "/api/workflows/",
            "/api/results/"
        ]
        
        for endpoint in test_endpoints:
            for payload in sql_payloads:
                try:
                    response = requests.get(
                        f"{self.base_url}{endpoint}",
                        params={'search': payload},
                        timeout=10
                    )
                    
                    # Check for SQL error messages in response
                    sql_errors = [
                        'sql syntax',
                        'mysql_fetch',
                        'ora-',
                        'postgresql',
                        'sqlite',
                        'microsoft ole db'
                    ]
                    
                    response_text = response.text.lower()
                    for error in sql_errors:
                        if error in response_text:
                            self.add_finding(
                                "Web Security",
                                "CRITICAL",
                                "SQL Injection Vulnerability",
                                f"SQL injection detected in {endpoint}",
                                evidence=f"Payload: {payload}, Error: {error}",
                                remediation="Implement proper input validation and parameterized queries"
                            )
                            break
                            
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"SQL injection test failed for {endpoint}: {str(e)}")
    
    async def _check_xss_vulnerabilities(self) -> None:
        """Check for XSS vulnerabilities."""
        logger.info("Checking for XSS vulnerabilities...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>"
        ]
        
        test_endpoints = [
            "/api/targets/",
            "/api/workflows/"
        ]
        
        for endpoint in test_endpoints:
            for payload in xss_payloads:
                try:
                    response = requests.get(
                        f"{self.base_url}{endpoint}",
                        params={'name': payload},
                        timeout=10
                    )
                    
                    # Check if payload is reflected in response
                    if payload in response.text:
                        self.add_finding(
                            "Web Security",
                            "HIGH",
                            "Cross-Site Scripting (XSS)",
                            f"XSS vulnerability detected in {endpoint}",
                            evidence=f"Payload: {payload}",
                            remediation="Implement proper output encoding and input validation"
                        )
                        
                except Exception as e:
                    if self.verbose:
                        logger.debug(f"XSS test failed for {endpoint}: {str(e)}")
    
    async def _check_csrf_vulnerabilities(self) -> None:
        """Check for CSRF vulnerabilities."""
        logger.info("Checking for CSRF vulnerabilities...")
        
        # Check if CSRF protection is implemented
        try:
            response = requests.get(f"{self.base_url}/api/health/", timeout=10)
            headers = response.headers
            
            # Check for CSRF token in cookies or headers
            csrf_indicators = [
                'csrftoken',
                'csrf_token',
                'x-csrf-token',
                'x-xsrf-token'
            ]
            
            csrf_protected = False
            for indicator in csrf_indicators:
                if indicator in headers or indicator in response.cookies:
                    csrf_protected = True
                    break
            
            if not csrf_protected:
                self.add_finding(
                    "Web Security",
                    "MEDIUM",
                    "Missing CSRF Protection",
                    "No CSRF protection detected",
                    evidence="No CSRF tokens found in response",
                    remediation="Implement CSRF protection with tokens"
                )
            else:
                self.add_finding(
                    "Web Security",
                    "INFO",
                    "CSRF Protection",
                    "CSRF protection appears to be implemented",
                    evidence="CSRF tokens detected in response"
                )
                
        except Exception as e:
            self.add_finding(
                "Web Security",
                "MEDIUM",
                "CSRF Check Failed",
                f"Could not check CSRF protection: {str(e)}"
            )
    
    async def _check_information_disclosure(self) -> None:
        """Check for information disclosure vulnerabilities."""
        logger.info("Checking for information disclosure...")
        
        # Check for sensitive information in responses
        sensitive_patterns = [
            'password',
            'secret',
            'key',
            'token',
            'api_key',
            'database',
            'config'
        ]
        
        try:
            response = requests.get(f"{self.base_url}/api/health/", timeout=10)
            response_text = response.text.lower()
            
            for pattern in sensitive_patterns:
                if pattern in response_text:
                    self.add_finding(
                        "Information Security",
                        "MEDIUM",
                        "Information Disclosure",
                        f"Sensitive information disclosure detected",
                        evidence=f"Pattern '{pattern}' found in response",
                        remediation="Remove sensitive information from responses"
                    )
                    
        except Exception as e:
            self.add_finding(
                "Information Security",
                "MEDIUM",
                "Information Disclosure Check Failed",
                f"Could not check for information disclosure: {str(e)}"
            )
    
    async def _check_security_headers(self) -> None:
        """Check security headers configuration."""
        logger.info("Checking security headers...")
        
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            headers = response.headers
            
            required_headers = {
                'X-Frame-Options': 'Prevents clickjacking attacks',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'X-XSS-Protection': 'Enables XSS protection',
                'Strict-Transport-Security': 'Enforces HTTPS',
                'Content-Security-Policy': 'Prevents XSS and injection attacks'
            }
            
            for header, description in required_headers.items():
                if header in headers:
                    value = headers[header]
                    if header == 'X-Frame-Options' and value.lower() != 'deny':
                        self.add_finding(
                            "Security Headers",
                            "MEDIUM",
                            f"Weak {header} Configuration",
                            f"{header} is set but not optimally configured",
                            evidence=f"{header}: {value}",
                            remediation=f"Set {header} to 'DENY' for maximum security"
                        )
                    else:
                        self.add_finding(
                            "Security Headers",
                            "INFO",
                            f"{header} Configured",
                            f"{header} is properly configured",
                            evidence=f"{header}: {value}"
                        )
                else:
                    self.add_finding(
                        "Security Headers",
                        "MEDIUM",
                        f"Missing {header}",
                        f"{header} is not configured",
                        remediation=f"Add {header} to improve security"
                    )
                    
        except Exception as e:
            self.add_finding(
                "Security Headers",
                "MEDIUM",
                "Security Headers Check Failed",
                f"Could not check security headers: {str(e)}"
            )
    
    async def _check_ssl_tls_configuration(self) -> None:
        """Check SSL/TLS configuration."""
        logger.info("Checking SSL/TLS configuration...")
        
        try:
            # Check SSL certificate
            response = requests.get(f"{self.base_url}/", timeout=10, verify=False)
            
            if response.url.startswith('https'):
                # Get SSL certificate info
                hostname = response.url.split('/')[2]
                context = ssl.create_default_context()
                
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        not_after = cert['notAfter']
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        
                        if days_until_expiry < 30:
                            self.add_finding(
                                "SSL/TLS",
                                "HIGH",
                                "SSL Certificate Expiring Soon",
                                f"SSL certificate expires in {days_until_expiry} days",
                                evidence=f"Expiry date: {not_after}",
                                remediation="Renew SSL certificate before expiration"
                            )
                        else:
                            self.add_finding(
                                "SSL/TLS",
                                "INFO",
                                "SSL Certificate Valid",
                                f"SSL certificate is valid for {days_until_expiry} days",
                                evidence=f"Expiry date: {not_after}"
                            )
                        
                        # Check certificate strength
                        if 'subjectAltName' in cert:
                            self.add_finding(
                                "SSL/TLS",
                                "INFO",
                                "SSL Certificate SAN",
                                "SSL certificate includes Subject Alternative Names",
                                evidence="SAN configured"
                            )
                        else:
                            self.add_finding(
                                "SSL/TLS",
                                "MEDIUM",
                                "Missing SSL Certificate SAN",
                                "SSL certificate does not include Subject Alternative Names",
                                remediation="Configure SAN in SSL certificate"
                            )
            else:
                self.add_finding(
                    "SSL/TLS",
                    "HIGH",
                    "No HTTPS",
                    "Application is not using HTTPS",
                    evidence="HTTP connection detected",
                    remediation="Configure HTTPS with valid SSL certificate"
                )
                
        except Exception as e:
            self.add_finding(
                "SSL/TLS",
                "MEDIUM",
                "SSL/TLS Check Failed",
                f"Could not check SSL/TLS configuration: {str(e)}"
            )
    
    async def audit_authentication_security(self) -> None:
        """Audit authentication and authorization security."""
        logger.info("Auditing authentication security...")
        
        # Check for weak password policies
        await self._check_password_policies()
        
        # Check for session management issues
        await self._check_session_management()
        
        # Check for privilege escalation vulnerabilities
        await self._check_privilege_escalation()
    
    async def _check_password_policies(self) -> None:
        """Check password policies and requirements."""
        logger.info("Checking password policies...")
        
        # This would typically check against the application's password policy
        # For now, we'll check if there are any obvious weak password configurations
        
        try:
            # Check if there are any default users with weak passwords
            response = requests.post(
                f"{self.base_url}/api/auth/login/",
                json={
                    "username": "admin",
                    "password": "admin"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                self.add_finding(
                    "Authentication",
                    "CRITICAL",
                    "Weak Default Credentials",
                    "Default admin credentials are working",
                    evidence="admin/admin credentials accepted",
                    remediation="Change default credentials immediately"
                )
            else:
                self.add_finding(
                    "Authentication",
                    "INFO",
                    "Default Credentials Protected",
                    "Default admin credentials are not working",
                    evidence="admin/admin credentials rejected"
                )
                
        except Exception as e:
            self.add_finding(
                "Authentication",
                "MEDIUM",
                "Password Policy Check Failed",
                f"Could not check password policies: {str(e)}"
            )
    
    async def _check_session_management(self) -> None:
        """Check session management security."""
        logger.info("Checking session management...")
        
        try:
            # Check session timeout configuration
            response = requests.get(f"{self.base_url}/api/health/", timeout=10)
            cookies = response.cookies
            
            session_cookies = [c for c in cookies if 'session' in c.name.lower()]
            
            if session_cookies:
                for cookie in session_cookies:
                    if not cookie.secure:
                        self.add_finding(
                            "Session Management",
                            "MEDIUM",
                            "Insecure Session Cookie",
                            "Session cookie is not marked as secure",
                            evidence=f"Cookie {cookie.name} not secure",
                            remediation="Mark session cookies as secure"
                        )
                    
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        self.add_finding(
                            "Session Management",
                            "MEDIUM",
                            "Session Cookie Not HttpOnly",
                            "Session cookie is not marked as HttpOnly",
                            evidence=f"Cookie {cookie.name} not HttpOnly",
                            remediation="Mark session cookies as HttpOnly"
                        )
            else:
                self.add_finding(
                    "Session Management",
                    "INFO",
                    "No Session Cookies",
                    "No session cookies detected in response"
                )
                
        except Exception as e:
            self.add_finding(
                "Session Management",
                "MEDIUM",
                "Session Management Check Failed",
                f"Could not check session management: {str(e)}"
            )
    
    async def _check_privilege_escalation(self) -> None:
        """Check for privilege escalation vulnerabilities."""
        logger.info("Checking for privilege escalation vulnerabilities...")
        
        # This would typically involve testing different user roles
        # and checking if lower-privileged users can access higher-privileged functions
        
        try:
            # Test if unauthenticated users can access protected endpoints
            protected_endpoints = [
                "/api/targets/",
                "/api/workflows/",
                "/api/results/",
                "/api/users/"
            ]
            
            for endpoint in protected_endpoints:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                
                if response.status_code == 200:
                    self.add_finding(
                        "Authorization",
                        "CRITICAL",
                        "Unauthorized Access",
                        f"Unauthenticated access to protected endpoint {endpoint}",
                        evidence=f"Status code: {response.status_code}",
                        remediation="Implement proper authentication and authorization"
                    )
                elif response.status_code == 401:
                    self.add_finding(
                        "Authorization",
                        "INFO",
                        "Proper Authentication Required",
                        f"Endpoint {endpoint} properly requires authentication",
                        evidence=f"Status code: {response.status_code}"
                    )
                else:
                    self.add_finding(
                        "Authorization",
                        "MEDIUM",
                        "Unexpected Response",
                        f"Unexpected response from {endpoint}",
                        evidence=f"Status code: {response.status_code}"
                    )
                    
        except Exception as e:
            self.add_finding(
                "Authorization",
                "MEDIUM",
                "Privilege Escalation Check Failed",
                f"Could not check privilege escalation: {str(e)}"
            )
    
    async def audit_data_protection(self) -> None:
        """Audit data protection and privacy measures."""
        logger.info("Auditing data protection...")
        
        # Check for data encryption
        await self._check_data_encryption()
        
        # Check for backup security
        await self._check_backup_security()
        
        # Check for logging security
        await self._check_logging_security()
    
    async def _check_data_encryption(self) -> None:
        """Check data encryption measures."""
        logger.info("Checking data encryption...")
        
        # Check if database connection uses SSL
        try:
            import psycopg2
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                database="postgres",
                user="postgres",
                sslmode="require"
            )
            self.add_finding(
                "Data Protection",
                "INFO",
                "Database SSL Enabled",
                "Database connection uses SSL encryption",
                evidence="SSL connection successful"
            )
            conn.close()
        except Exception:
            self.add_finding(
                "Data Protection",
                "MEDIUM",
                "Database SSL Not Required",
                "Database connection does not require SSL",
                remediation="Configure database to require SSL connections"
            )
        
        # Check for encryption at rest
        backup_dir = Path('backups')
        if backup_dir.exists():
            backup_files = list(backup_dir.glob('*.enc'))
            if backup_files:
                self.add_finding(
                    "Data Protection",
                    "INFO",
                    "Encrypted Backups",
                    "Backup files are encrypted",
                    evidence=f"Found {len(backup_files)} encrypted backup files"
                )
            else:
                self.add_finding(
                    "Data Protection",
                    "MEDIUM",
                    "Unencrypted Backups",
                    "Backup files are not encrypted",
                    remediation="Implement backup encryption"
                )
    
    async def _check_backup_security(self) -> None:
        """Check backup security measures."""
        logger.info("Checking backup security...")
        
        backup_dir = Path('backups')
        if backup_dir.exists():
            # Check backup file permissions
            backup_files = list(backup_dir.glob('*'))
            for backup_file in backup_files:
                stat = backup_file.stat()
                if stat.st_mode & 0o777 != 0o600:  # Should be 600 (owner read/write only)
                    self.add_finding(
                        "Data Protection",
                        "MEDIUM",
                        "Insecure Backup Permissions",
                        f"Backup file {backup_file.name} has insecure permissions",
                        evidence=f"Permissions: {oct(stat.st_mode)[-3:]}",
                        remediation="Set backup file permissions to 600"
                    )
                else:
                    self.add_finding(
                        "Data Protection",
                        "INFO",
                        "Secure Backup Permissions",
                        f"Backup file {backup_file.name} has secure permissions",
                        evidence=f"Permissions: {oct(stat.st_mode)[-3:]}"
                    )
        else:
            self.add_finding(
                "Data Protection",
                "MEDIUM",
                "No Backup Directory",
                "Backup directory does not exist",
                remediation="Create backup directory and implement backup procedures"
            )
    
    async def _check_logging_security(self) -> None:
        """Check logging security measures."""
        logger.info("Checking logging security...")
        
        log_files = [
            'logs/django.log',
            'logs/nginx.log',
            'logs/application.log'
        ]
        
        for log_file in log_files:
            log_path = Path(log_file)
            if log_path.exists():
                # Check log file permissions
                stat = log_path.stat()
                if stat.st_mode & 0o777 != 0o600:  # Should be 600
                    self.add_finding(
                        "Data Protection",
                        "MEDIUM",
                        "Insecure Log Permissions",
                        f"Log file {log_file} has insecure permissions",
                        evidence=f"Permissions: {oct(stat.st_mode)[-3:]}",
                        remediation="Set log file permissions to 600"
                    )
                else:
                    self.add_finding(
                        "Data Protection",
                        "INFO",
                        "Secure Log Permissions",
                        f"Log file {log_file} has secure permissions",
                        evidence=f"Permissions: {oct(stat.st_mode)[-3:]}"
                    )
                
                # Check for sensitive information in logs
                try:
                    with open(log_path, 'r') as f:
                        content = f.read().lower()
                        sensitive_patterns = ['password', 'secret', 'key', 'token']
                        
                        for pattern in sensitive_patterns:
                            if pattern in content:
                                self.add_finding(
                                    "Data Protection",
                                    "HIGH",
                                    "Sensitive Information in Logs",
                                    f"Sensitive information found in {log_file}",
                                    evidence=f"Pattern '{pattern}' found in logs",
                                    remediation="Remove sensitive information from logs"
                                )
                                break
                except Exception as e:
                    self.add_finding(
                        "Data Protection",
                        "MEDIUM",
                        "Log Content Check Failed",
                        f"Could not check log content for {log_file}: {str(e)}"
                    )
            else:
                self.add_finding(
                    "Data Protection",
                    "INFO",
                    "Log File Not Found",
                    f"Log file {log_file} does not exist"
                )
    
    async def run_all_audits(self) -> SecurityAuditSummary:
        """Run all security audits."""
        logger.info("Starting comprehensive security audit...")
        
        audit_methods = [
            self.audit_network_security,
            self.audit_web_application_security,
            self.audit_authentication_security,
            self.audit_data_protection
        ]
        
        for method in audit_methods:
            try:
                await method()
            except Exception as e:
                logger.error(f"Error in audit method {method.__name__}: {str(e)}")
                self.add_finding(
                    "System",
                    f"Audit {method.__name__}",
                    "MEDIUM",
                    f"Audit method failed: {str(e)}"
                )
        
        return self._generate_summary()
    
    def _generate_summary(self) -> SecurityAuditSummary:
        """Generate security audit summary."""
        total_findings = len(self.findings)
        critical_findings = len([f for f in self.findings if f.severity == "CRITICAL"])
        high_findings = len([f for f in self.findings if f.severity == "HIGH"])
        medium_findings = len([f for f in self.findings if f.severity == "MEDIUM"])
        low_findings = len([f for f in self.findings if f.severity == "LOW"])
        info_findings = len([f for f in self.findings if f.severity == "INFO"])
        
        # Calculate overall risk score (0-10)
        risk_score = (
            critical_findings * 10 +
            high_findings * 7 +
            medium_findings * 4 +
            low_findings * 1
        ) / max(total_findings, 1)
        
        # Generate recommendations
        recommendations = []
        if critical_findings > 0:
            recommendations.append(f"Address {critical_findings} critical findings immediately")
        if high_findings > 0:
            recommendations.append(f"Address {high_findings} high-severity findings")
        if medium_findings > 0:
            recommendations.append(f"Consider addressing {medium_findings} medium-severity findings")
        if risk_score > 7:
            recommendations.append("System has high security risk - do not proceed with launch")
        elif risk_score > 4:
            recommendations.append("System has moderate security risk - address findings before launch")
        else:
            recommendations.append("System has acceptable security posture")
        
        return SecurityAuditSummary(
            total_findings=total_findings,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            info_findings=info_findings,
            overall_risk_score=risk_score,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def export_results(self, output_format: str = "json", output_file: str = None) -> None:
        """Export audit results in specified format."""
        summary = self._generate_summary()
        
        if output_format == "json":
            output_data = {
                "summary": asdict(summary),
                "findings": [asdict(finding) for finding in self.findings]
            }
            output_content = json.dumps(output_data, indent=2)
        elif output_format == "html":
            output_content = self._generate_html_report(summary)
        else:  # text
            output_content = self._generate_text_report(summary)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_content)
            logger.info(f"Results exported to {output_file}")
        else:
            print(output_content)
    
    def _generate_html_report(self, summary: SecurityAuditSummary) -> str:
        """Generate HTML report."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; font-weight: bold; }
        .medium { color: #ffc107; font-weight: bold; }
        .low { color: #28a745; font-weight: bold; }
        .info { color: #17a2b8; font-weight: bold; }
        .finding { margin: 10px 0; padding: 10px; border-radius: 3px; }
        .finding.critical { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .finding.high { background-color: #fff3cd; border: 1px solid #ffeaa7; }
        .finding.medium { background-color: #d1ecf1; border: 1px solid #bee5eb; }
        .finding.low { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .finding.info { background-color: #e2e3e5; border: 1px solid #d6d8db; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Bug Hunting Framework - Security Audit Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Total Findings</th><td>{total_findings}</td></tr>
            <tr><th>Critical</th><td class="critical">{critical_findings}</td></tr>
            <tr><th>High</th><td class="high">{high_findings}</td></tr>
            <tr><th>Medium</th><td class="medium">{medium_findings}</td></tr>
            <tr><th>Low</th><td class="low">{low_findings}</td></tr>
            <tr><th>Info</th><td class="info">{info_findings}</td></tr>
            <tr><th>Risk Score</th><td>{risk_score:.2f}/10</td></tr>
        </table>
    </div>
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
            {recommendations}
        </ul>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
        {findings}
    </div>
</body>
</html>
        """
        
        recommendations_html = '\n'.join([f'<li>{rec}</li>' for rec in summary.recommendations])
        
        findings_html = ""
        for finding in self.findings:
            severity_class = finding.severity.lower()
            findings_html += f"""
            <div class="finding {severity_class}">
                <strong>{finding.category} - {finding.title}</strong><br>
                Severity: {finding.severity}<br>
                Description: {finding.description}<br>
                {f'Evidence: {finding.evidence}<br>' if finding.evidence else ''}
                {f'Remediation: {finding.remediation}<br>' if finding.remediation else ''}
                {f'CVE: {finding.cve_id}<br>' if finding.cve_id else ''}
                {f'CVSS Score: {finding.cvss_score}<br>' if finding.cvss_score else ''}
                Time: {finding.timestamp}
            </div>
            """
        
        return html_template.format(
            timestamp=summary.timestamp,
            total_findings=summary.total_findings,
            critical_findings=summary.critical_findings,
            high_findings=summary.high_findings,
            medium_findings=summary.medium_findings,
            low_findings=summary.low_findings,
            info_findings=summary.info_findings,
            risk_score=summary.overall_risk_score,
            recommendations=recommendations_html,
            findings=findings_html
        )
    
    def _generate_text_report(self, summary: SecurityAuditSummary) -> str:
        """Generate text report."""
        report = f"""
Bug Hunting Framework - Security Audit Report
Generated: {summary.timestamp}

SUMMARY:
========
Total Findings: {summary.total_findings}
Critical: {summary.critical_findings}
High: {summary.high_findings}
Medium: {summary.medium_findings}
Low: {summary.low_findings}
Info: {summary.info_findings}
Risk Score: {summary.overall_risk_score:.2f}/10

RECOMMENDATIONS:
===============
"""
        for rec in summary.recommendations:
            report += f"- {rec}\n"
        
        report += "\nDETAILED FINDINGS:\n"
        report += "==================\n"
        
        for finding in self.findings:
            report += f"""
{finding.category} - {finding.title}
Severity: {finding.severity}
Description: {finding.description}
{f'Evidence: {finding.evidence}' if finding.evidence else ''}
{f'Remediation: {finding.remediation}' if finding.remediation else ''}
{f'CVE: {finding.cve_id}' if finding.cve_id else ''}
{f'CVSS Score: {finding.cvss_score}' if finding.cvss_score else ''}
Time: {finding.timestamp}
"""
        
        return report

async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Security Audit and Penetration Testing')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output-format', choices=['json', 'html', 'text'], 
                       default='text', help='Output format')
    parser.add_argument('--output-file', help='Output file path')
    
    args = parser.parse_args()
    
    auditor = SecurityAuditor(verbose=args.verbose)
    summary = await auditor.run_all_audits()
    
    # Export results
    auditor.export_results(args.output_format, args.output_file)
    
    # Exit with appropriate code based on risk score
    if summary.overall_risk_score > 7:
        sys.exit(1)  # High risk
    elif summary.overall_risk_score > 4:
        sys.exit(2)  # Medium risk
    else:
        sys.exit(0)  # Low risk

if __name__ == "__main__":
    asyncio.run(main()) 