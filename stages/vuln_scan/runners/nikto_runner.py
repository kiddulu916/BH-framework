#!/usr/bin/env python3
"""
Nikto Web Server Scanner Runner

This module provides a comprehensive Nikto web server vulnerability scanner
that integrates with the bug hunting framework's vulnerability scanning stage.

Nikto is a web server scanner that performs comprehensive tests against web servers
for multiple items, including over 6700 potentially dangerous files/programs,
checks for outdated versions of over 1250 servers, and version specific problems
on over 270 servers.
"""

import os
import json
import subprocess
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


@dataclass
class NiktoFinding:
    """Represents a single Nikto finding."""
    target: str
    port: str
    method: str
    message: str
    evidence: str
    osvdb: Optional[str] = None
    severity: str = "info"
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class NiktoScanResult:
    """Represents the complete result of a Nikto scan."""
    target: str
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    findings: List[NiktoFinding]
    summary: Dict[str, Any]
    raw_output: str
    scan_config: Dict[str, Any]


class NiktoRunner:
    """
    Nikto Web Server Scanner Runner
    
    Provides comprehensive web server vulnerability scanning using Nikto,
    including configuration management, scan execution, and result parsing.
    """
    
    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        """
        Initialize the Nikto runner.
        
        Args:
            output_dir: Directory to store scan outputs
            rate_limit_config: Rate limiting configuration for scans
        """
        self.output_dir = output_dir
        self.rate_limit_config = rate_limit_config or {}
        self.nikto_dir = output_dir / "nikto"
        self.nikto_dir.mkdir(parents=True, exist_ok=True)
        
        # Nikto configuration
        self.nikto_config = {
            "timeout": 30,
            "max_requests": 1000,
            "user_agent": "Mozilla/5.0 (compatible; Nikto/2.1.6)",
            "follow_redirects": True,
            "ssl_verify": False,
            "plugins": "all",
            "format": "json"
        }
        
        # Update config with rate limiting
        if rate_limit_config:
            self.nikto_config.update({
                "delay": rate_limit_config.get("delay", 1),
                "max_requests_per_second": rate_limit_config.get("max_requests_per_second", 10)
            })
    
    def run_scan(self, targets: List[str], scan_config: Optional[Dict] = None) -> Dict[str, NiktoScanResult]:
        """
        Run Nikto scans against the provided targets.
        
        Args:
            targets: List of target URLs to scan
            scan_config: Optional scan configuration override
            
        Returns:
            Dictionary mapping target URLs to scan results
        """
        logger.info(f"Starting Nikto scans for {len(targets)} targets")
        
        if scan_config:
            self.nikto_config.update(scan_config)
        
        results = {}
        
        for target in targets:
            try:
                logger.info(f"Running Nikto scan for target: {target}")
                result = self.run_single_scan(target)
                results[target] = result
                
                # Apply rate limiting between scans
                if self.rate_limit_config.get("delay_between_scans"):
                    time.sleep(self.rate_limit_config["delay_between_scans"])
                    
            except Exception as e:
                logger.error(f"Error running Nikto scan for {target}: {str(e)}")
                results[target] = self.create_error_result(target, str(e))
        
        return results
    
    def run_single_scan(self, target: str) -> NiktoScanResult:
        """
        Run a single Nikto scan against a target.
        
        Args:
            target: Target URL to scan
            
        Returns:
            NiktoScanResult containing scan findings and metadata
        """
        scan_id = f"nikto_{int(time.time())}_{hash(target) % 10000}"
        start_time = datetime.now(timezone.utc)
        
        # Prepare output files
        output_file = self.nikto_dir / f"{scan_id}_output.json"
        log_file = self.nikto_dir / f"{scan_id}_log.txt"
        
        # Build Nikto command
        cmd = self.build_nikto_command(target, output_file, log_file)
        
        logger.info(f"Executing Nikto command: {' '.join(cmd)}")
        
        try:
            # Execute Nikto scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.nikto_config.get("timeout", 3600))
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self.parse_nikto_output(output_file, target)
            
            # Generate summary
            summary = self.generate_summary(findings, duration)
            
            # Read raw output
            raw_output = ""
            if output_file.exists():
                raw_output = output_file.read_text()
            
            return NiktoScanResult(
                target=target,
                scan_id=scan_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration=duration,
                findings=findings,
                summary=summary,
                raw_output=raw_output,
                scan_config=self.nikto_config.copy()
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"Nikto scan timed out for target: {target}")
            return self.create_error_result(target, "Scan timed out")
            
        except Exception as e:
            logger.error(f"Error executing Nikto scan for {target}: {str(e)}")
            return self.create_error_result(target, str(e))
    
    def build_nikto_command(self, target: str, output_file: Path, log_file: Path) -> List[str]:
        """
        Build the Nikto command with all necessary parameters.
        
        Args:
            target: Target URL
            output_file: Output file path for JSON results
            log_file: Log file path
            
        Returns:
            List of command arguments
        """
        cmd = ["nikto"]
        
        # Basic target
        cmd.extend(["-h", target])
        
        # Output format
        cmd.extend(["-Format", "json"])
        cmd.extend(["-output", str(output_file)])
        
        # Logging
        cmd.extend(["-log", str(log_file)])
        
        # Timeout and rate limiting
        if self.nikto_config.get("timeout"):
            cmd.extend(["-timeout", str(self.nikto_config["timeout"])])
        
        if self.nikto_config.get("delay"):
            cmd.extend(["-delay", str(self.nikto_config["delay"])])
        
        # User agent
        if self.nikto_config.get("user_agent"):
            cmd.extend(["-useragent", self.nikto_config["user_agent"]])
        
        # SSL/TLS options
        if not self.nikto_config.get("ssl_verify", True):
            cmd.extend(["-nossl"])
        
        # Plugin options
        if self.nikto_config.get("plugins") == "all":
            cmd.extend(["-Plugins", "all"])
        elif self.nikto_config.get("plugins"):
            cmd.extend(["-Plugins", self.nikto_config["plugins"]])
        
        # Additional options
        if self.nikto_config.get("follow_redirects"):
            cmd.extend(["-followredirects"])
        
        # Maximum requests
        if self.nikto_config.get("max_requests"):
            cmd.extend(["-max", str(self.nikto_config["max_requests"])])
        
        return cmd
    
    def parse_nikto_output(self, output_file: Path, target: str) -> List[NiktoFinding]:
        """
        Parse Nikto JSON output into structured findings.
        
        Args:
            output_file: Path to Nikto JSON output file
            target: Target URL
            
        Returns:
            List of NiktoFinding objects
        """
        findings = []
        
        if not output_file.exists():
            logger.warning(f"Nikto output file not found: {output_file}")
            return findings
        
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            # Parse Nikto JSON structure
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
            logger.error(f"Error parsing Nikto JSON output: {str(e)}")
        except Exception as e:
            logger.error(f"Error processing Nikto output: {str(e)}")
        
        return findings
    
    def parse_vulnerability(self, vuln_data: Dict, target: str) -> Optional[NiktoFinding]:
        """
        Parse a single vulnerability entry from Nikto output.
        
        Args:
            vuln_data: Vulnerability data dictionary
            target: Target URL
            
        Returns:
            NiktoFinding object or None if parsing fails
        """
        try:
            # Extract common fields
            message = vuln_data.get("message", "")
            evidence = vuln_data.get("evidence", "")
            method = vuln_data.get("method", "GET")
            port = str(vuln_data.get("port", "80"))
            osvdb = vuln_data.get("osvdb")
            
            # Determine severity based on message content
            severity = self.determine_severity(message)
            
            return NiktoFinding(
                target=target,
                port=port,
                method=method,
                message=message,
                evidence=evidence,
                osvdb=osvdb,
                severity=severity
            )
            
        except Exception as e:
            logger.error(f"Error parsing vulnerability: {str(e)}")
            return None
    
    def determine_severity(self, message: str) -> str:
        """
        Determine the severity of a finding based on the message content.
        
        Args:
            message: Nikto finding message
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        message_lower = message.lower()
        
        # Critical findings
        critical_keywords = [
            "remote code execution", "rce", "sql injection", "xss", 
            "directory traversal", "file inclusion", "command injection"
        ]
        if any(keyword in message_lower for keyword in critical_keywords):
            return "critical"
        
        # High severity findings
        high_keywords = [
            "information disclosure", "sensitive data", "credentials",
            "admin panel", "backup files", "configuration files"
        ]
        if any(keyword in message_lower for keyword in high_keywords):
            return "high"
        
        # Medium severity findings
        medium_keywords = [
            "outdated", "version", "default", "debug", "error messages"
        ]
        if any(keyword in message_lower for keyword in medium_keywords):
            return "medium"
        
        # Low severity findings
        low_keywords = [
            "robots.txt", "server info", "headers", "banner"
        ]
        if any(keyword in message_lower for keyword in low_keywords):
            return "low"
        
        return "info"
    
    def generate_summary(self, findings: List[NiktoFinding], duration: float) -> Dict[str, Any]:
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
        
        for finding in findings:
            severity_counts[finding.severity] += 1
        
        total_findings = len(findings)
        
        return {
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "scan_duration_seconds": duration,
            "scan_duration_formatted": f"{duration:.2f}s",
            "findings_per_minute": (total_findings / (duration / 60)) if duration > 0 else 0
        }
    
    def create_error_result(self, target: str, error_message: str) -> NiktoScanResult:
        """
        Create an error result when scan fails.
        
        Args:
            target: Target URL
            error_message: Error message
            
        Returns:
            NiktoScanResult with error information
        """
        return NiktoScanResult(
            target=target,
            scan_id=f"nikto_error_{int(time.time())}",
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
            scan_config=self.nikto_config.copy()
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
    
    parser = argparse.ArgumentParser(description="Nikto Web Server Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--output-dir", default="./outputs", help="Output directory")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize runner
    output_dir = Path(args.output_dir)
    runner = NiktoRunner(output_dir)
    
    # Run scan
    results = runner.run_scan([args.target])
    
    # Print results
    for target, result in results.items():
        print(f"\n=== Nikto Scan Results for {target} ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.summary.get('scan_duration_formatted', 'N/A')}")
        print(f"Total Findings: {result.summary.get('total_findings', 0)}")
        
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.message}")


if __name__ == "__main__":
    main() 