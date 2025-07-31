#!/usr/bin/env python3
"""
Network Scanner Runner for Stage 4: Step 4.2

This module implements network and port scanning with CLI tool integration,
service version detection, and network vulnerability testing.
"""

import json
import logging
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import nmap
import requests

logger = logging.getLogger(__name__)


@dataclass
class NetworkService:
    """Represents a network service discovered during scanning."""
    
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    state: str = "open"
    banner: Optional[str] = None
    script_output: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.script_output is None:
            self.script_output = {}


@dataclass
class NetworkFinding:
    """Represents a vulnerability finding from network scanning."""
    
    id: str
    title: str
    description: str
    target: str
    port: Optional[int] = None
    service: Optional[str] = None
    severity: str = "Medium"
    confidence: float = 0.0
    evidence: str = ""
    cve_references: List[str] = None
    cvss_score: Optional[float] = None
    vulnerability_type: str = ""
    
    def __post_init__(self):
        if self.cve_references is None:
            self.cve_references = []


class NetworkScanner:
    """Network and port scanner for vulnerability testing."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.network_dir = self.output_dir / "network_scanning"
        self.network_dir.mkdir(parents=True, exist_ok=True)
        
        # Network scanning configuration
        self.port_scanning_enabled = config.port_scanning_enabled
        self.service_detection_enabled = config.service_detection_enabled
        self.rate_limit = config.rate_limit
        
        # Discovered data
        self.discovered_services: List[NetworkService] = []
        self.network_findings: List[NetworkFinding] = []
        
        # Nmap scanner
        self.nmap_scanner = nmap.PortScanner()
        
        # Common ports to scan
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 9000, 9090
        ]
        
        # Service-specific vulnerability checks
        self.service_vulnerabilities = {
            "ssh": self._check_ssh_vulnerabilities,
            "ftp": self._check_ftp_vulnerabilities,
            "telnet": self._check_telnet_vulnerabilities,
            "smtp": self._check_smtp_vulnerabilities,
            "http": self._check_http_vulnerabilities,
            "https": self._check_https_vulnerabilities,
            "mysql": self._check_mysql_vulnerabilities,
            "rdp": self._check_rdp_vulnerabilities,
            "vnc": self._check_vnc_vulnerabilities
        }
    
    def run_scan(self) -> List[NetworkFinding]:
        """
        Run comprehensive network vulnerability scanning.
        
        Returns:
            List[NetworkFinding]: List of vulnerability findings
        """
        logger.info("Starting network vulnerability scanning...")
        
        try:
            # Load structured input data
            structured_data = self._load_structured_data()
            
            # Perform port scanning
            if self.port_scanning_enabled:
                self._perform_port_scanning(structured_data.get("network_info", {}))
            
            # Perform service detection
            if self.service_detection_enabled:
                self._perform_service_detection()
            
            # Test discovered services for vulnerabilities
            self._test_service_vulnerabilities()
            
            # Perform additional network scans
            self._perform_additional_scans()
            
            # Save results
            self.save_results()
            
            logger.info(f"Network scanning completed. Found {len(self.network_findings)} potential vulnerabilities")
            
            return self.network_findings
            
        except Exception as e:
            logger.error(f"Error in network scanning: {str(e)}")
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
            "endpoints": [],
            "technologies": [],
            "network_info": {
                "open_ports": [],
                "services": {},
                "ip_addresses": [self.config.target]
            },
            "cloud_info": {},
            "preliminary_vulns": [],
            "scan_config": {}
        }
    
    def _perform_port_scanning(self, network_info: Dict[str, Any]):
        """Perform comprehensive port scanning."""
        logger.info("Performing port scanning...")
        
        try:
            # Get target IP addresses
            target_ips = network_info.get("ip_addresses", [self.config.target])
            known_ports = network_info.get("open_ports", [])
            
            for target_ip in target_ips:
                logger.info(f"Scanning target: {target_ip}")
                
                # Perform TCP SYN scan on common ports
                self._tcp_syn_scan(target_ip, self.common_ports)
                
                # Scan known ports from previous stages
                if known_ports:
                    self._tcp_syn_scan(target_ip, known_ports)
                
                # Perform UDP scan on common UDP ports
                self._udp_scan(target_ip, [53, 67, 68, 69, 123, 161, 162, 514])
                
                # Rate limiting
                time.sleep(1 / self.rate_limit)
                
        except Exception as e:
            logger.error(f"Error performing port scanning: {str(e)}")
    
    def _tcp_syn_scan(self, target: str, ports: List[int]):
        """Perform TCP SYN scan on specified ports."""
        try:
            port_list = ",".join(map(str, ports))
            
            # Run nmap TCP SYN scan
            scan_args = f"-sS -p {port_list} --version-intensity 5 --script=banner,version"
            
            logger.info(f"Running TCP SYN scan on {target}:{port_list}")
            
            # Use nmap-python library
            self.nmap_scanner.scan(target, arguments=scan_args)
            
            # Parse results
            if target in self.nmap_scanner.all_hosts():
                for proto in self.nmap_scanner[target].all_protocols():
                    if proto == "tcp":
                        for port in self.nmap_scanner[target][proto]:
                            port_info = self.nmap_scanner[target][proto][port]
                            
                            if port_info["state"] == "open":
                                service = NetworkService(
                                    port=port,
                                    protocol=proto,
                                    service=port_info.get("name", "unknown"),
                                    version=port_info.get("version", ""),
                                    banner=port_info.get("product", ""),
                                    script_output=port_info.get("script", {})
                                )
                                self.discovered_services.append(service)
                                
        except Exception as e:
            logger.error(f"Error in TCP SYN scan: {str(e)}")
    
    def _udp_scan(self, target: str, ports: List[int]):
        """Perform UDP scan on specified ports."""
        try:
            port_list = ",".join(map(str, ports))
            
            # Run nmap UDP scan
            scan_args = f"-sU -p {port_list} --version-intensity 3"
            
            logger.info(f"Running UDP scan on {target}:{port_list}")
            
            # Use nmap-python library
            self.nmap_scanner.scan(target, arguments=scan_args)
            
            # Parse results
            if target in self.nmap_scanner.all_hosts():
                for proto in self.nmap_scanner[target].all_protocols():
                    if proto == "udp":
                        for port in self.nmap_scanner[target][proto]:
                            port_info = self.nmap_scanner[target][proto][port]
                            
                            if port_info["state"] == "open":
                                service = NetworkService(
                                    port=port,
                                    protocol=proto,
                                    service=port_info.get("name", "unknown"),
                                    version=port_info.get("version", ""),
                                    banner=port_info.get("product", ""),
                                    script_output=port_info.get("script", {})
                                )
                                self.discovered_services.append(service)
                                
        except Exception as e:
            logger.error(f"Error in UDP scan: {str(e)}")
    
    def _perform_service_detection(self):
        """Perform detailed service detection and version identification."""
        logger.info("Performing service detection...")
        
        try:
            # Group services by target
            services_by_target = {}
            for service in self.discovered_services:
                # This is a simplified grouping - in practice, you'd track which target each service belongs to
                target = self.config.target
                if target not in services_by_target:
                    services_by_target[target] = []
                services_by_target[target].append(service)
            
            # Perform detailed service detection for each target
            for target, services in services_by_target.items():
                if services:
                    self._detailed_service_detection(target, services)
                    
        except Exception as e:
            logger.error(f"Error performing service detection: {str(e)}")
    
    def _detailed_service_detection(self, target: str, services: List[NetworkService]):
        """Perform detailed service detection for a specific target."""
        try:
            # Run additional nmap scripts for service detection
            for service in services:
                if service.service in ["http", "https", "ssh", "ftp", "smtp"]:
                    self._run_service_specific_scripts(target, service)
                    
        except Exception as e:
            logger.error(f"Error in detailed service detection: {str(e)}")
    
    def _run_service_specific_scripts(self, target: str, service: NetworkService):
        """Run service-specific nmap scripts."""
        try:
            script_map = {
                "http": "http-title,http-headers,http-security-headers",
                "https": "ssl-cert,ssl-enum-ciphers",
                "ssh": "ssh-hostkey,ssh2-enum-algos",
                "ftp": "ftp-anon,ftp-syst",
                "smtp": "smtp-commands,smtp-enum-users"
            }
            
            if service.service in script_map:
                scripts = script_map[service.service]
                scan_args = f"-sV -p {service.port} --script={scripts}"
                
                logger.info(f"Running {service.service} scripts on {target}:{service.port}")
                
                # Run nmap scan
                self.nmap_scanner.scan(target, arguments=scan_args)
                
                # Update service information
                if target in self.nmap_scanner.all_hosts():
                    for proto in self.nmap_scanner[target].all_protocols():
                        if service.port in self.nmap_scanner[target][proto]:
                            port_info = self.nmap_scanner[target][proto][service.port]
                            service.script_output.update(port_info.get("script", {}))
                            
        except Exception as e:
            logger.error(f"Error running service-specific scripts: {str(e)}")
    
    def _test_service_vulnerabilities(self):
        """Test discovered services for vulnerabilities."""
        logger.info("Testing service vulnerabilities...")
        
        try:
            for service in self.discovered_services:
                logger.info(f"Testing service: {service.service} on port {service.port}")
                
                # Test for common vulnerabilities based on service type
                if service.service in self.service_vulnerabilities:
                    self.service_vulnerabilities[service.service](service)
                
                # Test for default credentials
                self._test_default_credentials(service)
                
                # Test for misconfigurations
                self._test_misconfigurations(service)
                
                # Rate limiting
                time.sleep(1 / self.rate_limit)
                
        except Exception as e:
            logger.error(f"Error testing service vulnerabilities: {str(e)}")
    
    def _check_ssh_vulnerabilities(self, service: NetworkService):
        """Check SSH service for vulnerabilities."""
        try:
            # Check for weak algorithms
            if "ssh2-enum-algos" in service.script_output:
                algos = service.script_output["ssh2-enum-algos"]
                
                # Check for weak encryption algorithms
                weak_algorithms = ["des", "3des", "blowfish", "arcfour"]
                for algo in weak_algorithms:
                    if algo in algos.lower():
                        finding = NetworkFinding(
                            id=f"network_{len(self.network_findings) + 1}",
                            title="Weak SSH Encryption Algorithm",
                            description=f"SSH service uses weak encryption algorithm: {algo}",
                            target=self.config.target,
                            port=service.port,
                            service=service.service,
                            severity="Medium",
                            confidence=0.8,
                            evidence=f"Found weak algorithm '{algo}' in SSH configuration",
                            vulnerability_type="Weak Encryption"
                        )
                        self.network_findings.append(finding)
            
            # Check for default SSH banner
            if service.banner and "openssh" in service.banner.lower():
                if "ubuntu" in service.banner.lower() or "debian" in service.banner.lower():
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Default SSH Banner",
                        description="SSH service reveals default system information",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Low",
                        confidence=0.7,
                        evidence=f"Default SSH banner: {service.banner}",
                        vulnerability_type="Information Disclosure"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error checking SSH vulnerabilities: {str(e)}")
    
    def _check_ftp_vulnerabilities(self, service: NetworkService):
        """Check FTP service for vulnerabilities."""
        try:
            # Check for anonymous access
            if "ftp-anon" in service.script_output:
                anon_result = service.script_output["ftp-anon"]
                if "Anonymous FTP login allowed" in anon_result:
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Anonymous FTP Access",
                        description="FTP service allows anonymous access",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Medium",
                        confidence=0.9,
                        evidence="Anonymous FTP login allowed",
                        vulnerability_type="Anonymous Access"
                    )
                    self.network_findings.append(finding)
            
            # Check for FTP banner information
            if service.banner:
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="FTP Banner Information",
                    description="FTP service reveals version information",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Low",
                    confidence=0.6,
                    evidence=f"FTP banner: {service.banner}",
                    vulnerability_type="Information Disclosure"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking FTP vulnerabilities: {str(e)}")
    
    def _check_telnet_vulnerabilities(self, service: NetworkService):
        """Check Telnet service for vulnerabilities."""
        try:
            # Telnet is inherently insecure
            finding = NetworkFinding(
                id=f"network_{len(self.network_findings) + 1}",
                title="Telnet Service Detected",
                description="Telnet service is inherently insecure (cleartext communication)",
                target=self.config.target,
                port=service.port,
                service=service.service,
                severity="High",
                confidence=1.0,
                evidence="Telnet service found - cleartext communication",
                vulnerability_type="Cleartext Communication"
            )
            self.network_findings.append(finding)
            
            # Check for banner information
            if service.banner:
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="Telnet Banner Information",
                    description="Telnet service reveals system information",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Medium",
                    confidence=0.7,
                    evidence=f"Telnet banner: {service.banner}",
                    vulnerability_type="Information Disclosure"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking Telnet vulnerabilities: {str(e)}")
    
    def _check_smtp_vulnerabilities(self, service: NetworkService):
        """Check SMTP service for vulnerabilities."""
        try:
            # Check for open relay
            if "smtp-commands" in service.script_output:
                commands = service.script_output["smtp-commands"]
                if "250" in commands and "relay" in commands.lower():
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Potential SMTP Open Relay",
                        description="SMTP service may allow open relay",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="High",
                        confidence=0.7,
                        evidence="SMTP commands indicate potential open relay",
                        vulnerability_type="Open Relay"
                    )
                    self.network_findings.append(finding)
            
            # Check for user enumeration
            if "smtp-enum-users" in service.script_output:
                enum_result = service.script_output["smtp-enum-users"]
                if "found" in enum_result.lower():
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="SMTP User Enumeration",
                        description="SMTP service allows user enumeration",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Medium",
                        confidence=0.8,
                        evidence="SMTP user enumeration possible",
                        vulnerability_type="User Enumeration"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error checking SMTP vulnerabilities: {str(e)}")
    
    def _check_http_vulnerabilities(self, service: NetworkService):
        """Check HTTP service for vulnerabilities."""
        try:
            # Check for missing security headers
            if "http-security-headers" in service.script_output:
                headers = service.script_output["http-security-headers"]
                
                missing_headers = []
                required_headers = [
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "X-XSS-Protection",
                    "Strict-Transport-Security"
                ]
                
                for header in required_headers:
                    if header not in headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Missing HTTP Security Headers",
                        description="HTTP service missing important security headers",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Medium",
                        confidence=0.8,
                        evidence=f"Missing security headers: {', '.join(missing_headers)}",
                        vulnerability_type="Missing Security Headers"
                    )
                    self.network_findings.append(finding)
            
            # Check for HTTP banner information
            if "http-title" in service.script_output:
                title = service.script_output["http-title"]
                if title and title != "Site doesn't have a title":
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="HTTP Title Information",
                        description="HTTP service reveals title information",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Low",
                        confidence=0.6,
                        evidence=f"HTTP title: {title}",
                        vulnerability_type="Information Disclosure"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error checking HTTP vulnerabilities: {str(e)}")
    
    def _check_https_vulnerabilities(self, service: NetworkService):
        """Check HTTPS service for vulnerabilities."""
        try:
            # Check SSL/TLS configuration
            if "ssl-cert" in service.script_output:
                cert_info = service.script_output["ssl-cert"]
                
                # Check for weak SSL/TLS versions
                if "ssl-enum-ciphers" in service.script_output:
                    ciphers = service.script_output["ssl-enum-ciphers"]
                    
                    weak_protocols = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]
                    for protocol in weak_protocols:
                        if protocol in ciphers:
                            finding = NetworkFinding(
                                id=f"network_{len(self.network_findings) + 1}",
                                title=f"Weak SSL/TLS Protocol: {protocol}",
                                description=f"HTTPS service uses weak SSL/TLS protocol: {protocol}",
                                target=self.config.target,
                                port=service.port,
                                service=service.service,
                                severity="High",
                                confidence=0.9,
                                evidence=f"Found weak protocol '{protocol}' in SSL/TLS configuration",
                                vulnerability_type="Weak SSL/TLS"
                            )
                            self.network_findings.append(finding)
            
            # Check for certificate issues
            if "ssl-cert" in service.script_output:
                cert_info = service.script_output["ssl-cert"]
                
                # Check for self-signed certificates
                if "self signed" in cert_info.lower():
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Self-Signed SSL Certificate",
                        description="HTTPS service uses self-signed certificate",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Medium",
                        confidence=0.8,
                        evidence="Self-signed SSL certificate detected",
                        vulnerability_type="Self-Signed Certificate"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error checking HTTPS vulnerabilities: {str(e)}")
    
    def _check_mysql_vulnerabilities(self, service: NetworkService):
        """Check MySQL service for vulnerabilities."""
        try:
            # Check for default MySQL banner
            if service.banner and "mysql" in service.banner.lower():
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="MySQL Service Information",
                    description="MySQL service reveals version information",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Low",
                    confidence=0.6,
                    evidence=f"MySQL banner: {service.banner}",
                    vulnerability_type="Information Disclosure"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking MySQL vulnerabilities: {str(e)}")
    
    def _check_rdp_vulnerabilities(self, service: NetworkService):
        """Check RDP service for vulnerabilities."""
        try:
            # Check for RDP banner information
            if service.banner:
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="RDP Service Information",
                    description="RDP service reveals system information",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Low",
                    confidence=0.6,
                    evidence=f"RDP banner: {service.banner}",
                    vulnerability_type="Information Disclosure"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking RDP vulnerabilities: {str(e)}")
    
    def _check_vnc_vulnerabilities(self, service: NetworkService):
        """Check VNC service for vulnerabilities."""
        try:
            # Check for VNC banner information
            if service.banner:
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="VNC Service Information",
                    description="VNC service reveals system information",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Low",
                    confidence=0.6,
                    evidence=f"VNC banner: {service.banner}",
                    vulnerability_type="Information Disclosure"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking VNC vulnerabilities: {str(e)}")
    
    def _test_default_credentials(self, service: NetworkService):
        """Test for default credentials on discovered services."""
        try:
            # This would typically use tools like Hydra or custom credential testing
            # For now, we'll create a placeholder finding for services that commonly have default creds
            
            services_with_defaults = ["ftp", "ssh", "telnet", "mysql", "rdp", "vnc"]
            
            if service.service in services_with_defaults:
                finding = NetworkFinding(
                    id=f"network_{len(self.network_findings) + 1}",
                    title="Default Credentials Testing Required",
                    description=f"{service.service.upper()} service requires default credentials testing",
                    target=self.config.target,
                    port=service.port,
                    service=service.service,
                    severity="Medium",
                    confidence=0.5,
                    evidence=f"{service.service.upper()} service detected - test for default credentials",
                    vulnerability_type="Default Credentials"
                )
                self.network_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing default credentials: {str(e)}")
    
    def _test_misconfigurations(self, service: NetworkService):
        """Test for common service misconfigurations."""
        try:
            # Check for services running on non-standard ports
            standard_ports = {
                "ssh": 22, "ftp": 21, "telnet": 23, "smtp": 25,
                "http": 80, "https": 443, "mysql": 3306, "rdp": 3389
            }
            
            if service.service in standard_ports:
                standard_port = standard_ports[service.service]
                if service.port != standard_port:
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title="Non-Standard Port Usage",
                        description=f"{service.service.upper()} service running on non-standard port",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="Low",
                        confidence=0.7,
                        evidence=f"{service.service.upper()} running on port {service.port} instead of {standard_port}",
                        vulnerability_type="Non-Standard Port"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing misconfigurations: {str(e)}")
    
    def _perform_additional_scans(self):
        """Perform additional network scans."""
        try:
            logger.info("Performing additional network scans...")
            
            # Run vulnerability scripts
            self._run_vulnerability_scripts()
            
            # Check for common vulnerabilities
            self._check_common_vulnerabilities()
            
        except Exception as e:
            logger.error(f"Error performing additional scans: {str(e)}")
    
    def _run_vulnerability_scripts(self):
        """Run nmap vulnerability scripts."""
        try:
            # Run common vulnerability scripts
            vuln_scripts = "vuln,auth,default"
            
            for service in self.discovered_services:
                if service.service in ["http", "https", "ssh", "ftp", "smtp"]:
                    scan_args = f"-sV -p {service.port} --script={vuln_scripts}"
                    
                    logger.info(f"Running vulnerability scripts on {self.config.target}:{service.port}")
                    
                    # Run nmap scan
                    self.nmap_scanner.scan(self.config.target, arguments=scan_args)
                    
                    # Parse vulnerability results
                    if self.config.target in self.nmap_scanner.all_hosts():
                        for proto in self.nmap_scanner[self.config.target].all_protocols():
                            if service.port in self.nmap_scanner[self.config.target][proto]:
                                port_info = self.nmap_scanner[self.config.target][proto][service.port]
                                script_output = port_info.get("script", {})
                                
                                # Check for vulnerability findings
                                for script_name, result in script_output.items():
                                    if "vuln" in script_name.lower() or "auth" in script_name.lower():
                                        if "VULNERABLE" in result or "open" in result.lower():
                                            finding = NetworkFinding(
                                                id=f"network_{len(self.network_findings) + 1}",
                                                title=f"Nmap Script Finding: {script_name}",
                                                description=f"Vulnerability detected by nmap script: {script_name}",
                                                target=self.config.target,
                                                port=service.port,
                                                service=service.service,
                                                severity="Medium",
                                                confidence=0.7,
                                                evidence=f"Script {script_name}: {result}",
                                                vulnerability_type="Nmap Script Detection"
                                            )
                                            self.network_findings.append(finding)
                                            
        except Exception as e:
            logger.error(f"Error running vulnerability scripts: {str(e)}")
    
    def _check_common_vulnerabilities(self):
        """Check for common network vulnerabilities."""
        try:
            # Check for services that should not be exposed
            dangerous_services = ["telnet", "ftp", "rsh", "rlogin", "rexec"]
            
            for service in self.discovered_services:
                if service.service in dangerous_services:
                    finding = NetworkFinding(
                        id=f"network_{len(self.network_findings) + 1}",
                        title=f"Dangerous Service: {service.service.upper()}",
                        description=f"{service.service.upper()} service is inherently insecure",
                        target=self.config.target,
                        port=service.port,
                        service=service.service,
                        severity="High",
                        confidence=0.9,
                        evidence=f"Dangerous service {service.service.upper()} found on port {service.port}",
                        vulnerability_type="Dangerous Service"
                    )
                    self.network_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error checking common vulnerabilities: {str(e)}")
    
    def save_results(self):
        """Save network scanning results to files."""
        try:
            # Save discovered services
            services_file = self.network_dir / "discovered_services.json"
            with open(services_file, 'w') as f:
                json.dump([service.__dict__ for service in self.discovered_services], f, indent=2)
            
            # Save vulnerability findings
            findings_file = self.network_dir / "network_findings.json"
            with open(findings_file, 'w') as f:
                json.dump([finding.__dict__ for finding in self.network_findings], f, indent=2)
            
            # Save nmap scan results
            nmap_file = self.network_dir / "nmap_results.json"
            with open(nmap_file, 'w') as f:
                json.dump(self.nmap_scanner.analyse_nmap_xml_scan(), f, indent=2)
            
            logger.info(f"Network scanning results saved to {self.network_dir}")
            
        except Exception as e:
            logger.error(f"Error saving network scanning results: {str(e)}") 