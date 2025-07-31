#!/usr/bin/env python3
"""
OpenVAS Network Vulnerability Scanner Runner

This module provides a comprehensive OpenVAS network vulnerability scanner
that integrates with the bug hunting framework's vulnerability scanning stage.

OpenVAS (Open Vulnerability Assessment System) is a full-featured security scanner
that includes thousands of vulnerability tests and is capable of performing
comprehensive security assessments of networks and systems.
"""

import os
import json
import subprocess
import logging
import time
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class OpenVASFinding:
    """Represents a single OpenVAS finding."""
    target: str
    nvt_id: str
    name: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    port: Optional[str] = None
    protocol: Optional[str] = None
    solution: str = ""
    references: List[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.references is None:
            self.references = []


@dataclass
class OpenVASScanResult:
    """Represents the complete result of an OpenVAS scan."""
    target: str
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    findings: List[OpenVASFinding]
    summary: Dict[str, Any]
    raw_output: str
    scan_config: Dict[str, Any]


class OpenVASRunner:
    """
    OpenVAS Network Vulnerability Scanner Runner
    
    Provides comprehensive network vulnerability scanning using OpenVAS,
    including configuration management, scan execution, and result parsing.
    """
    
    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        """
        Initialize the OpenVAS runner.
        
        Args:
            output_dir: Directory to store scan outputs
            rate_limit_config: Rate limiting configuration for scans
        """
        self.output_dir = output_dir
        self.rate_limit_config = rate_limit_config or {}
        self.openvas_dir = output_dir / "openvas"
        self.openvas_dir.mkdir(parents=True, exist_ok=True)
        
        # OpenVAS configuration
        self.openvas_config = {
            "timeout": 3600,  # OpenVAS scans can take a long time
            "max_hosts": 100,
            "user_agent": "Mozilla/5.0 (compatible; OpenVAS/21.4.0)",
            "scan_type": "full",
            "port_range": "1-65535",
            "format": "xml"
        }
        
        # Update config with rate limiting
        if rate_limit_config:
            self.openvas_config.update({
                "delay": rate_limit_config.get("delay", 1),
                "max_requests_per_second": rate_limit_config.get("max_requests_per_second", 10)
            })
    
    def run_scan(self, targets: List[str], scan_config: Optional[Dict] = None) -> Dict[str, OpenVASScanResult]:
        """
        Run OpenVAS scans against the provided targets.
        
        Args:
            targets: List of target IPs/hosts to scan
            scan_config: Optional scan configuration override
            
        Returns:
            Dictionary mapping target IPs to scan results
        """
        logger.info(f"Starting OpenVAS scans for {len(targets)} targets")
        
        if scan_config:
            self.openvas_config.update(scan_config)
        
        results = {}
        
        for target in targets:
            try:
                logger.info(f"Running OpenVAS scan for target: {target}")
                result = self.run_single_scan(target)
                results[target] = result
                
                # Apply rate limiting between scans
                if self.rate_limit_config.get("delay_between_scans"):
                    time.sleep(self.rate_limit_config["delay_between_scans"])
                    
            except Exception as e:
                logger.error(f"Error running OpenVAS scan for {target}: {str(e)}")
                results[target] = self.create_error_result(target, str(e))
        
        return results
    
    def run_single_scan(self, target: str) -> OpenVASScanResult:
        """
        Run a single OpenVAS scan against a target.
        
        Args:
            target: Target IP/host to scan
            
        Returns:
            OpenVASScanResult containing scan findings and metadata
        """
        scan_id = f"openvas_{int(time.time())}_{hash(target) % 10000}"
        start_time = datetime.now(timezone.utc)
        
        # Prepare output files
        output_file = self.openvas_dir / f"{scan_id}_output.xml"
        log_file = self.openvas_dir / f"{scan_id}_log.txt"
        
        # Build OpenVAS command
        cmd = self.build_openvas_command(target, output_file, log_file)
        
        logger.info(f"Executing OpenVAS command: {' '.join(cmd)}")
        
        try:
            # Execute OpenVAS scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.openvas_config.get("timeout", 7200))
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self.parse_openvas_output(output_file, target)
            
            # Generate summary
            summary = self.generate_summary(findings, duration)
            
            # Read raw output
            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text()
            
            return OpenVASScanResult(
                target=target,
                scan_id=scan_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration=duration,
                findings=findings,
                summary=summary,
                raw_output=raw_output,
                scan_config=self.openvas_config.copy()
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"OpenVAS scan timed out for target: {target}")
            return self.create_error_result(target, "Scan timed out")
            
        except Exception as e:
            logger.error(f"Error executing OpenVAS scan for {target}: {str(e)}")
            return self.create_error_result(target, str(e))
    
    def build_openvas_command(self, target: str, output_file: Path, log_file: Path) -> List[str]:
        """
        Build the OpenVAS command with all necessary parameters.
        
        Args:
            target: Target IP/host
            output_file: Output file path for XML results
            log_file: Log file path
            
        Returns:
            List of command arguments
        """
        cmd = ["openvas"]
        
        # Basic target
        cmd.extend(["-T", target])
        
        # Output format
        cmd.extend(["-o", str(output_file)])
        
        # Logging
        cmd.extend(["-l", str(log_file)])
        
        # Scan type
        if self.openvas_config.get("scan_type"):
            cmd.extend(["-s", self.openvas_config["scan_type"]])
        
        # Port range
        if self.openvas_config.get("port_range"):
            cmd.extend(["-p", self.openvas_config["port_range"]])
        
        # Timeout
        if self.openvas_config.get("timeout"):
            cmd.extend(["-t", str(self.openvas_config["timeout"])])
        
        # User agent
        if self.openvas_config.get("user_agent"):
            cmd.extend(["-A", self.openvas_config["user_agent"]])
        
        # Additional options
        cmd.extend(["--xml-output"])
        
        return cmd
    
    def parse_openvas_output(self, output_file: Path, target: str) -> List[OpenVASFinding]:
        """
        Parse OpenVAS XML output into structured findings.
        
        Args:
            output_file: Path to OpenVAS XML output file
            target: Target IP/host
            
        Returns:
            List of OpenVASFinding objects
        """
        findings = []
        
        if not output_file.exists():
            logger.warning(f"OpenVAS output file not found: {output_file}")
            return findings
        
        try:
            tree = ET.parse(output_file)
            root = tree.getroot()
            
            # Parse OpenVAS XML structure
            for result in root.findall(".//result"):
                finding = self.parse_result_element(result, target)
                if finding:
                    findings.append(finding)
            
        except ET.ParseError as e:
            logger.error(f"Error parsing OpenVAS XML output: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing OpenVAS output: {str(e)}")
        
        return findings
    
    def parse_result_element(self, result_elem: ET.Element, target: str) -> Optional[OpenVASFinding]:
        """
        Parse a single result element from OpenVAS XML output.
        
        Args:
            result_elem: Result XML element
            target: Target IP/host
            
        Returns:
            OpenVASFinding object or None if parsing fails
        """
        try:
            # Extract NVT information
            nvt_elem = result_elem.find("nvt")
            if nvt_elem is None:
                return None
            
            nvt_id = nvt_elem.get("oid", "")
            name = self.get_element_text(nvt_elem.find("name"))
            description = self.get_element_text(nvt_elem.find("description"))
            cvss_score = float(self.get_element_text(nvt_elem.find("cvss_base"), "0.0"))
            cvss_vector = self.get_element_text(nvt_elem.find("cvss_base_vector"), "")
            
            # Extract CVE and CWE information
            cve_elem = nvt_elem.find("cve")
            cve_id = cve_elem.text if cve_elem is not None else None
            
            cwe_elem = nvt_elem.find("cwe")
            cwe_id = cwe_elem.text if cwe_elem is not None else None
            
            # Extract port and protocol information
            port_elem = result_elem.find("port")
            port = port_elem.text if port_elem is not None else None
            
            protocol_elem = result_elem.find("protocol")
            protocol = protocol_elem.text if protocol_elem is not None else None
            
            # Extract solution and references
            solution = self.get_element_text(result_elem.find("solution"))
            
            references = []
            refs_elem = result_elem.find("references")
            if refs_elem is not None:
                for ref in refs_elem.findall("reference"):
                    ref_text = self.get_element_text(ref)
                    if ref_text:
                        references.append(ref_text)
            
            # Determine severity based on CVSS score
            severity = self.determine_severity(cvss_score)
            
            return OpenVASFinding(
                target=target,
                nvt_id=nvt_id,
                name=name,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                cve_id=cve_id,
                cwe_id=cwe_id,
                port=port,
                protocol=protocol,
                solution=solution,
                references=references
            )
            
        except Exception as e:
            logger.error(f"Error parsing result element: {str(e)}")
            return None
    
    def get_element_text(self, elem: Optional[ET.Element], default: str = "") -> str:
        """
        Safely get text from an XML element.
        
        Args:
            elem: XML element
            default: Default value if element is None or has no text
            
        Returns:
            Element text or default value
        """
        if elem is not None and elem.text:
            return elem.text.strip()
        return default
    
    def determine_severity(self, cvss_score: float) -> str:
        """
        Determine the severity of a finding based on CVSS score.
        
        Args:
            cvss_score: CVSS base score
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"
        elif cvss_score >= 0.1:
            return "low"
        else:
            return "info"
    
    def generate_summary(self, findings: List[OpenVASFinding], duration: float) -> Dict[str, Any]:
        """
        Generate a summary of the scan results.
        
        Args:
            findings: List of findings
            duration: Scan duration in seconds
            
        Returns:
            Summary dictionary
        """
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        cvss_score_ranges = {
            "9.0-10.0": 0,
            "7.0-8.9": 0,
            "4.0-6.9": 0,
            "0.1-3.9": 0,
            "0.0": 0
        }
        
        cve_counts = {}
        cwe_counts = {}
        port_counts = {}
        
        total_cvss_score = 0
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            total_cvss_score += finding.cvss_score
            
            # CVSS score ranges
            if finding.cvss_score >= 9.0:
                cvss_score_ranges["9.0-10.0"] += 1
            elif finding.cvss_score >= 7.0:
                cvss_score_ranges["7.0-8.9"] += 1
            elif finding.cvss_score >= 4.0:
                cvss_score_ranges["4.0-6.9"] += 1
            elif finding.cvss_score > 0:
                cvss_score_ranges["0.1-3.9"] += 1
            else:
                cvss_score_ranges["0.0"] += 1
            
            # CVE counts
            if finding.cve_id:
                cve_counts[finding.cve_id] = cve_counts.get(finding.cve_id, 0) + 1
            
            # CWE counts
            if finding.cwe_id:
                cwe_counts[finding.cwe_id] = cwe_counts.get(finding.cwe_id, 0) + 1
            
            # Port counts
            if finding.port:
                port_counts[finding.port] = port_counts.get(finding.port, 0) + 1
        
        total_findings = len(findings)
        average_cvss_score = total_cvss_score / total_findings if total_findings > 0 else 0
        
        return {
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "cvss_score_ranges": cvss_score_ranges,
            "average_cvss_score": round(average_cvss_score, 2),
            "cve_breakdown": cve_counts,
            "cwe_breakdown": cwe_counts,
            "port_breakdown": port_counts,
            "scan_duration_seconds": duration,
            "scan_duration_formatted": f"{duration:.2f}s",
            "findings_per_minute": (total_findings / (duration / 60)) if duration > 0 else 0
        }
    
    def create_error_result(self, target: str, error_message: str) -> OpenVASScanResult:
        """
        Create an error result when scan fails.
        
        Args:
            target: Target IP/host
            error_message: Error message
            
        Returns:
            OpenVASScanResult with error information
        """
        return OpenVASScanResult(
            target=target,
            scan_id=f"openvas_error_{int(time.time())}",
            start_time=datetime.now(timezone.utc).isoformat(),
            end_time=datetime.now(timezone.utc).isoformat(),
            duration=0,
            findings=[],
            summary={
                "error": error_message,
                "total_findings": 0,
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            },
            raw_output=f"Error: {error_message}",
            scan_config=self.openvas_config.copy()
        )
    
    def get_results_summary(self) -> Dict[str, Any]:
        """
        Get a summary of all scan results.
        
        Returns:
            Summary of all scans
        """
        summary = {
            "total_scans": 0,
            "successful_scans": 0,
            "failed_scans": 0,
            "total_findings": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "average_scan_duration": 0,
            "total_scan_duration": 0
        }
        
        # This would be populated with actual scan results
        # Implementation depends on how results are stored/retrieved
        
        return summary


def main():
    """Main function for standalone testing."""
    import argparse
    
    parser = argparse.ArgumentParser(description="OpenVAS Network Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target IP/host to scan")
    parser.add_argument("--output-dir", default="./outputs", help="Output directory")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize runner
    output_dir = Path(args.output_dir)
    runner = OpenVASRunner(output_dir)
    
    # Run scan
    results = runner.run_scan([args.target])
    
    # Print results
    for target, result in results.items():
        print(f"\n=== OpenVAS Scan Results for {target} ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.summary.get('scan_duration_formatted', 'N/A')}")
        print(f"Total Findings: {result.summary.get('total_findings', 0)}")
        
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.name} (CVSS: {finding.cvss_score})")


if __name__ == "__main__":
    main() 