#!/usr/bin/env python3
"""
Arachni Web Application Security Scanner Runner

This module provides a comprehensive Arachni web application security scanner
that integrates with the bug hunting framework's vulnerability scanning stage.

Arachni is a feature-full, modular, high-performance Ruby framework aimed towards
helping penetration testers and administrators evaluate the security of web applications.
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
class ArachniFinding:
    """Represents a single Arachni finding."""
    target: str
    vulnerability_type: str
    name: str
    description: str
    severity: str
    confidence: str
    url: str
    method: str
    parameter: str
    proof: str
    references: List[str]
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class ArachniScanResult:
    """Represents the complete result of an Arachni scan."""
    target: str
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    findings: List[ArachniFinding]
    summary: Dict[str, Any]
    raw_output: str
    scan_config: Dict[str, Any]


class ArachniRunner:
    """
    Arachni Web Application Security Scanner Runner
    
    Provides comprehensive web application security scanning using Arachni,
    including configuration management, scan execution, and result parsing.
    """
    
    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        """
        Initialize the Arachni runner.
        
        Args:
            output_dir: Directory to store scan outputs
            rate_limit_config: Rate limiting configuration for scans
        """
        self.output_dir = output_dir
        self.rate_limit_config = rate_limit_config or {}
        self.arachni_dir = output_dir / "arachni"
        self.arachni_dir.mkdir(parents=True, exist_ok=True)
        
        # Arachni configuration
        self.arachni_config = {
            "timeout": 30,
            "max_requests": 1000,
            "user_agent": "Mozilla/5.0 (compatible; Arachni/2.0.0)",
            "follow_redirects": True,
            "ssl_verify": False,
            "modules": "all",
            "checks": "all",
            "scope": "page",
            "format": "json"
        }
        
        # Update config with rate limiting
        if rate_limit_config:
            self.arachni_config.update({
                "delay": rate_limit_config.get("delay", 1),
                "max_requests_per_second": rate_limit_config.get("max_requests_per_second", 10)
            })
    
    def run_scan(self, targets: List[str], scan_config: Optional[Dict] = None) -> Dict[str, ArachniScanResult]:
        """
        Run Arachni scans against the provided targets.
        
        Args:
            targets: List of target URLs to scan
            scan_config: Optional scan configuration override
            
        Returns:
            Dictionary mapping target URLs to scan results
        """
        logger.info(f"Starting Arachni scans for {len(targets)} targets")
        
        if scan_config:
            self.arachni_config.update(scan_config)
        
        results = {}
        
        for target in targets:
            try:
                logger.info(f"Running Arachni scan for target: {target}")
                result = self.run_single_scan(target)
                results[target] = result
                
                # Apply rate limiting between scans
                if self.rate_limit_config.get("delay_between_scans"):
                    time.sleep(self.rate_limit_config["delay_between_scans"])
                    
            except Exception as e:
                logger.error(f"Error running Arachni scan for {target}: {str(e)}")
                results[target] = self.create_error_result(target, str(e))
        
        return results
    
    def run_single_scan(self, target: str) -> ArachniScanResult:
        """
        Run a single Arachni scan against a target.
        
        Args:
            target: Target URL to scan
            
        Returns:
            ArachniScanResult containing scan findings and metadata
        """
        scan_id = f"arachni_{int(time.time())}_{hash(target) % 10000}"
        start_time = datetime.now(timezone.utc)
        
        # Prepare output files
        output_file = self.arachni_dir / f"{scan_id}_output.json"
        log_file = self.arachni_dir / f"{scan_id}_log.txt"
        
        # Build Arachni command
        cmd = self.build_arachni_command(target, output_file, log_file)
        
        logger.info(f"Executing Arachni command: {' '.join(cmd)}")
        
        try:
            # Execute Arachni scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.arachni_config.get("timeout", 3600))
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self.parse_arachni_output(output_file, target)
            
            # Generate summary
            summary = self.generate_summary(findings, duration)
            
            # Read raw output
            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text()
            
            return ArachniScanResult(
                target=target,
                scan_id=scan_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration=duration,
                findings=findings,
                summary=summary,
                raw_output=raw_output,
                scan_config=self.arachni_config.copy()
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"Arachni scan timed out for target: {target}")
            return self.create_error_result(target, "Scan timed out")
            
        except Exception as e:
            logger.error(f"Error executing Arachni scan for {target}: {str(e)}")
            return self.create_error_result(target, str(e))
    
    def build_arachni_command(self, target: str, output_file: Path, log_file: Path) -> List[str]:
        """
        Build the Arachni command with all necessary parameters.
        
        Args:
            target: Target URL
            output_file: Output file path for JSON results
            log_file: Log file path
            
        Returns:
            List of command arguments
        """
        cmd = ["arachni"]
        
        # Basic target
        cmd.extend(["--url", target])
        
        # Output format
        cmd.extend(["--report", "json"])
        cmd.extend(["--report-out", str(output_file)])
        
        # Logging
        cmd.extend(["--log", str(log_file)])
        
        # Timeout and rate limiting
        if self.arachni_config.get("timeout"):
            cmd.extend(["--timeout", str(self.arachni_config["timeout"])])
        
        if self.arachni_config.get("delay"):
            cmd.extend(["--delay", str(self.arachni_config["delay"])])
        
        # User agent
        if self.arachni_config.get("user_agent"):
            cmd.extend(["--user-agent", self.arachni_config["user_agent"]])
        
        # SSL/TLS options
        if not self.arachni_config.get("ssl_verify", True):
            cmd.extend(["--ssl-verify", "false"])
        
        # Module options
        if self.arachni_config.get("modules") == "all":
            cmd.extend(["--modules", "all"])
        elif self.arachni_config.get("modules"):
            cmd.extend(["--modules", self.arachni_config["modules"]])
        
        # Check options
        if self.arachni_config.get("checks") == "all":
            cmd.extend(["--checks", "all"])
        elif self.arachni_config.get("checks"):
            cmd.extend(["--checks", self.arachni_config["checks"]])
        
        # Scope options
        if self.arachni_config.get("scope"):
            cmd.extend(["--scope", self.arachni_config["scope"]])
        
        # Additional options
        if self.arachni_config.get("follow_redirects"):
            cmd.extend(["--follow-redirects"])
        
        # Maximum requests
        if self.arachni_config.get("max_requests"):
            cmd.extend(["--max-requests", str(self.arachni_config["max_requests"])])
        
        return cmd
    
    def parse_arachni_output(self, output_file: Path, target: str) -> List[ArachniFinding]:
        """
        Parse Arachni JSON output into structured findings.
        
        Args:
            output_file: Path to Arachni JSON output file
            target: Target URL
            
        Returns:
            List of ArachniFinding objects
        """
        findings = []
        
        if not output_file.exists():
            logger.warning(f"Arachni output file not found: {output_file}")
            return findings
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Parse Arachni JSON structure
            if isinstance(data, dict) and "issues" in data:
                for issue in data["issues"]:
                    finding = self.parse_issue(issue, target)
                    if finding:
                        findings.append(finding)
            
            # Also check for direct array format
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        finding = self.parse_issue(item, target)
                        if finding:
                            findings.append(finding)
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Arachni JSON output: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing Arachni output: {str(e)}")
        
        return findings
    
    def parse_issue(self, issue_data: Dict, target: str) -> Optional[ArachniFinding]:
        """
        Parse a single issue entry from Arachni output.
        
        Args:
            issue_data: Issue data dictionary
            target: Target URL
            
        Returns:
            ArachniFinding object or None if parsing fails
        """
        try:
            # Extract common fields
            vuln_type = issue_data.get("type", "")
            name = issue_data.get("name", "")
            description = issue_data.get("description", "")
            severity = issue_data.get("severity", "info")
            confidence = issue_data.get("confidence", "medium")
            url = issue_data.get("url", target)
            method = issue_data.get("method", "GET")
            parameter = issue_data.get("parameter", "")
            proof = issue_data.get("proof", "")
            references = issue_data.get("references", [])
            
            return ArachniFinding(
                target=target,
                vulnerability_type=vuln_type,
                name=name,
                description=description,
                severity=severity,
                confidence=confidence,
                url=url,
                method=method,
                parameter=parameter,
                proof=proof,
                references=references
            )
            
        except Exception as e:
            logger.error(f"Error parsing issue: {str(e)}")
            return None
    
    def generate_summary(self, findings: List[ArachniFinding], duration: float) -> Dict[str, Any]:
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
    
    def create_error_result(self, target: str, error_message: str) -> ArachniScanResult:
        """
        Create an error result when scan fails.
        
        Args:
            target: Target URL
            error_message: Error message
            
        Returns:
            ArachniScanResult with error information
        """
        return ArachniScanResult(
            target=target,
            scan_id=f"arachni_error_{int(time.time())}",
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
            scan_config=self.arachni_config.copy()
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
    
    parser = argparse.ArgumentParser(description="Arachni Web Application Security Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--output-dir", default="./outputs", help="Output directory")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize runner
    output_dir = Path(args.output_dir)
    runner = ArachniRunner(output_dir)
    
    # Run scan
    results = runner.run_scan([args.target])
    
    # Print results
    for target, result in results.items():
        print(f"\n=== Arachni Scan Results for {target} ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.summary.get('scan_duration_formatted', 'N/A')}")
        print(f"Total Findings: {result.summary.get('total_findings', 0)}")
        
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.name}: {finding.description}")


if __name__ == "__main__":
    main() 