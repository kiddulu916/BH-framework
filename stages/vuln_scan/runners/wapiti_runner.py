#!/usr/bin/env python3
"""
Wapiti Web Application Vulnerability Scanner Runner

This module provides a comprehensive Wapiti web application vulnerability scanner
that integrates with the bug hunting framework's vulnerability scanning stage.

Wapiti is a web application vulnerability scanner that can detect various types
of vulnerabilities including SQL injection, XSS, file inclusion, command injection,
and more. It supports both GET and POST parameter testing.
"""

import os
import json
import subprocess
import logging
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class WapitiFinding:
    """Represents a single Wapiti finding."""
    target: str
    vulnerability_type: str
    parameter: str
    method: str
    url: str
    payload: str
    evidence: str
    severity: str = "info"
    confidence: str = "medium"
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class WapitiScanResult:
    """Represents the complete result of a Wapiti scan."""
    target: str
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    findings: List[WapitiFinding]
    summary: Dict[str, Any]
    raw_output: str
    scan_config: Dict[str, Any]


class WapitiRunner:
    """
    Wapiti Web Application Vulnerability Scanner Runner
    
    Provides comprehensive web application vulnerability scanning using Wapiti,
    including configuration management, scan execution, and result parsing.
    """
    
    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        """
        Initialize the Wapiti runner.
        
        Args:
            output_dir: Directory to store scan outputs
            rate_limit_config: Rate limiting configuration for scans
        """
        self.output_dir = output_dir
        self.rate_limit_config = rate_limit_config or {}
        self.wapiti_dir = output_dir / "wapiti"
        self.wapiti_dir.mkdir(parents=True, exist_ok=True)
        
        # Wapiti configuration
        self.wapiti_config = {
            "timeout": 30,
            "max_requests": 1000,
            "user_agent": "Mozilla/5.0 (compatible; Wapiti/3.0.0)",
            "follow_redirects": True,
            "ssl_verify": False,
            "modules": "all",
            "level": 1,
            "format": "json"
        }
        
        # Update config with rate limiting
        if rate_limit_config:
            self.wapiti_config.update({
                "delay": rate_limit_config.get("delay", 1),
                "max_requests_per_second": rate_limit_config.get("max_requests_per_second", 10)
            })
    
    def run_scan(self, targets: List[str], scan_config: Optional[Dict] = None) -> Dict[str, WapitiScanResult]:
        """
        Run Wapiti scans against the provided targets.
        
        Args:
            targets: List of target URLs to scan
            scan_config: Optional scan configuration override
            
        Returns:
            Dictionary mapping target URLs to scan results
        """
        logger.info(f"Starting Wapiti scans for {len(targets)} targets")
        
        if scan_config:
            self.wapiti_config.update(scan_config)
        
        results = {}
        
        for target in targets:
            try:
                logger.info(f"Running Wapiti scan for target: {target}")
                result = self.run_single_scan(target)
                results[target] = result
                
                # Apply rate limiting between scans
                if self.rate_limit_config.get("delay_between_scans"):
                    time.sleep(self.rate_limit_config["delay_between_scans"])
                    
            except Exception as e:
                logger.error(f"Error running Wapiti scan for {target}: {str(e)}")
                results[target] = self.create_error_result(target, str(e))
        
        return results
    
    def run_single_scan(self, target: str) -> WapitiScanResult:
        """
        Run a single Wapiti scan against a target.
        
        Args:
            target: Target URL to scan
            
        Returns:
            WapitiScanResult containing scan findings and metadata
        """
        scan_id = f"wapiti_{int(time.time())}_{hash(target) % 10000}"
        start_time = datetime.now(timezone.utc)
        
        # Prepare output files
        output_file = self.wapiti_dir / f"{scan_id}_output.json"
        log_file = self.wapiti_dir / f"{scan_id}_log.txt"
        
        # Build Wapiti command
        cmd = self.build_wapiti_command(target, output_file, log_file)
        
        logger.info(f"Executing Wapiti command: {' '.join(cmd)}")
        
        try:
            # Execute Wapiti scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.wapiti_config.get("timeout", 3600))
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self.parse_wapiti_output(output_file, target)
            
            # Generate summary
            summary = self.generate_summary(findings, duration)
            
            # Read raw output
            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text()
            
            return WapitiScanResult(
                target=target,
                scan_id=scan_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration=duration,
                findings=findings,
                summary=summary,
                raw_output=raw_output,
                scan_config=self.wapiti_config.copy()
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"Wapiti scan timed out for target: {target}")
            return self.create_error_result(target, "Scan timed out")
            
        except Exception as e:
            logger.error(f"Error executing Wapiti scan for {target}: {str(e)}")
            return self.create_error_result(target, str(e))
    
    def build_wapiti_command(self, target: str, output_file: Path, log_file: Path) -> List[str]:
        """
        Build the Wapiti command with all necessary parameters.
        
        Args:
            target: Target URL
            output_file: Output file path for JSON results
            log_file: Log file path
            
        Returns:
            List of command arguments
        """
        cmd = ["wapiti"]
        
        # Basic target
        cmd.extend(["-u", target])
        
        # Output format
        cmd.extend(["-f", "json"])
        cmd.extend(["-o", str(output_file)])
        
        # Logging
        cmd.extend(["--log", str(log_file)])
        
        # Timeout and rate limiting
        if self.wapiti_config.get("timeout"):
            cmd.extend(["--timeout", str(self.wapiti_config["timeout"])])
        
        if self.wapiti_config.get("delay"):
            cmd.extend(["--delay", str(self.wapiti_config["delay"])])
        
        # User agent
        if self.wapiti_config.get("user_agent"):
            cmd.extend(["--user-agent", self.wapiti_config["user_agent"]])
        
        # SSL/TLS options
        if not self.wapiti_config.get("ssl_verify", True):
            cmd.extend(["--skip-ssl-check"])
        
        # Module options
        if self.wapiti_config.get("modules") == "all":
            cmd.extend(["-m", "all"])
        elif self.wapiti_config.get("modules"):
            cmd.extend(["-m", self.wapiti_config["modules"]])
        
        # Scan level
        if self.wapiti_config.get("level"):
            cmd.extend(["--level", str(self.wapiti_config["level"])])
        
        # Additional options
        if self.wapiti_config.get("follow_redirects"):
            cmd.extend(["--follow-redirects"])
        
        # Maximum requests
        if self.wapiti_config.get("max_requests"):
            cmd.extend(["--max-requests", str(self.wapiti_config["max_requests"])])
        
        # Scope options
        cmd.extend(["--scope", "page"])
        
        return cmd
    
    def parse_wapiti_output(self, output_file: Path, target: str) -> List[WapitiFinding]:
        """
        Parse Wapiti JSON output into structured findings.
        
        Args:
            output_file: Path to Wapiti JSON output file
            target: Target URL
            
        Returns:
            List of WapitiFinding objects
        """
        findings = []
        
        if not output_file.exists():
            logger.warning(f"Wapiti output file not found: {output_file}")
            return findings
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Parse Wapiti JSON structure
            if isinstance(data, dict) and "vulnerabilities" in data:
                for vuln in data["vulnerabilities"]:
                    finding = self.parse_vulnerability(vuln, target)
                    if finding:
                        findings.append(finding)
            
            # Also check for direct array format
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        finding = self.parse_vulnerability(item, target)
                        if finding:
                            findings.append(finding)
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Wapiti JSON output: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing Wapiti output: {str(e)}")
        
        return findings
    
    def parse_vulnerability(self, vuln_data: Dict, target: str) -> Optional[WapitiFinding]:
        """
        Parse a single vulnerability entry from Wapiti output.
        
        Args:
            vuln_data: Vulnerability data dictionary
            target: Target URL
            
        Returns:
            WapitiFinding object or None if parsing fails
        """
        try:
            # Extract common fields
            vuln_type = vuln_data.get("type", "")
            parameter = vuln_data.get("parameter", "")
            method = vuln_data.get("method", "GET")
            url = vuln_data.get("url", target)
            payload = vuln_data.get("payload", "")
            evidence = vuln_data.get("evidence", "")
            confidence = vuln_data.get("confidence", "medium")
            
            # Determine severity based on vulnerability type
            severity = self.determine_severity(vuln_type)
            
            return WapitiFinding(
                target=target,
                vulnerability_type=vuln_type,
                parameter=parameter,
                method=method,
                url=url,
                payload=payload,
                evidence=evidence,
                severity=severity,
                confidence=confidence
            )
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability: {str(e)}")
            return None
    
    def determine_severity(self, vuln_type: str) -> str:
        """
        Determine the severity of a finding based on the vulnerability type.
        
        Args:
            vuln_type: Wapiti vulnerability type
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        vuln_type_lower = vuln_type.lower()
        
        # Critical findings
        critical_types = [
            "sql injection", "xss", "rce", "command injection",
            "file inclusion", "directory traversal"
        ]
        if any(vtype in vuln_type_lower for vtype in critical_types):
            return "critical"
        
        # High severity findings
        high_types = [
            "xxe", "ssrf", "open redirect", "file upload",
            "authentication bypass", "privilege escalation"
        ]
        if any(vtype in vuln_type_lower for vtype in high_types):
            return "high"
        
        # Medium severity findings
        medium_types = [
            "information disclosure", "weak authentication",
            "session management", "csrf"
        ]
        if any(vtype in vuln_type_lower for vtype in medium_types):
            return "medium"
        
        # Low severity findings
        low_types = [
            "robots.txt", "server info", "headers", "banner"
        ]
        if any(vtype in vuln_type_lower for vtype in low_types):
            return "low"
        
        return "info"
    
    def generate_summary(self, findings: List[WapitiFinding], duration: float) -> Dict[str, Any]:
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
        
        vuln_type_counts = {}
        confidence_counts = {"high": 0, "medium": 0, "low": 0}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            vuln_type_counts[finding.vulnerability_type] = vuln_type_counts.get(finding.vulnerability_type, 0) + 1
            confidence_counts[finding.confidence] += 1
        
        total_findings = len(findings)
        
        return {
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "vulnerability_type_breakdown": vuln_type_counts,
            "confidence_breakdown": confidence_counts,
            "scan_duration_seconds": duration,
            "scan_duration_formatted": f"{duration:.2f}s",
            "findings_per_minute": (total_findings / (duration / 60)) if duration > 0 else 0
        }
    
    def create_error_result(self, target: str, error_message: str) -> WapitiScanResult:
        """
        Create an error result when scan fails.
        
        Args:
            target: Target URL
            error_message: Error message
            
        Returns:
            WapitiScanResult with error information
        """
        return WapitiScanResult(
            target=target,
            scan_id=f"wapiti_error_{int(time.time())}",
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
            scan_config=self.wapiti_config.copy()
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
    
    parser = argparse.ArgumentParser(description="Wapiti Web Application Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--output-dir", default="./outputs", help="Output directory")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize runner
    output_dir = Path(args.output_dir)
    runner = WapitiRunner(output_dir)
    
    # Run scan
    results = runner.run_scan([args.target])
    
    # Print results
    for target, result in results.items():
        print(f"\n=== Wapiti Scan Results for {target} ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.summary.get('scan_duration_formatted', 'N/A')}")
        print(f"Total Findings: {result.summary.get('total_findings', 0)}")
        
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.vulnerability_type}: {finding.message}")


if __name__ == "__main__":
    main() 