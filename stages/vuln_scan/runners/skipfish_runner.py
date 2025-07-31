#!/usr/bin/env python3
"""
Skipfish Web Application Security Scanner Runner

This module provides a comprehensive Skipfish web application security scanner
that integrates with the bug hunting framework's vulnerability scanning stage.

Skipfish is a web application security reconnaissance tool that prepares an
interactive sitemap for the targeted site by carrying out a recursive crawl
and dictionary-based probes.
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
class SkipfishFinding:
    """Represents a single Skipfish finding."""
    target: str
    finding_type: str
    severity: str
    url: str
    description: str
    evidence: str
    category: str
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SkipfishScanResult:
    """Represents the complete result of a Skipfish scan."""
    target: str
    scan_id: str
    start_time: str
    end_time: str
    duration: float
    findings: List[SkipfishFinding]
    summary: Dict[str, Any]
    raw_output: str
    scan_config: Dict[str, Any]


class SkipfishRunner:
    """
    Skipfish Web Application Security Scanner Runner
    
    Provides comprehensive web application security scanning using Skipfish,
    including configuration management, scan execution, and result parsing.
    """
    
    def __init__(self, output_dir: Path, rate_limit_config: Optional[Dict] = None):
        """
        Initialize the Skipfish runner.
        
        Args:
            output_dir: Directory to store scan outputs
            rate_limit_config: Rate limiting configuration for scans
        """
        self.output_dir = output_dir
        self.rate_limit_config = rate_limit_config or {}
        self.skipfish_dir = output_dir / "skipfish"
        self.skipfish_dir.mkdir(parents=True, exist_ok=True)
        
        # Skipfish configuration
        self.skipfish_config = {
            "timeout": 30,
            "max_requests": 1000,
            "user_agent": "Mozilla/5.0 (compatible; Skipfish/2.10b)",
            "follow_redirects": True,
            "ssl_verify": False,
            "depth": 6,
            "rate_limit": 10,
            "format": "json"
        }
        
        # Update config with rate limiting
        if rate_limit_config:
            self.skipfish_config.update({
                "delay": rate_limit_config.get("delay", 1),
                "max_requests_per_second": rate_limit_config.get("max_requests_per_second", 10)
            })
    
    def run_scan(self, targets: List[str], scan_config: Optional[Dict] = None) -> Dict[str, SkipfishScanResult]:
        """
        Run Skipfish scans against the provided targets.
        
        Args:
            targets: List of target URLs to scan
            scan_config: Optional scan configuration override
            
        Returns:
            Dictionary mapping target URLs to scan results
        """
        logger.info(f"Starting Skipfish scans for {len(targets)} targets")
        
        if scan_config:
            self.skipfish_config.update(scan_config)
        
        results = {}
        
        for target in targets:
            try:
                logger.info(f"Running Skipfish scan for target: {target}")
                result = self.run_single_scan(target)
                results[target] = result
                
                # Apply rate limiting between scans
                if self.rate_limit_config.get("delay_between_scans"):
                    time.sleep(self.rate_limit_config["delay_between_scans"])
                    
            except Exception as e:
                logger.error(f"Error running Skipfish scan for {target}: {str(e)}")
                results[target] = self.create_error_result(target, str(e))
        
        return results
    
    def run_single_scan(self, target: str) -> SkipfishScanResult:
        """
        Run a single Skipfish scan against a target.
        
        Args:
            target: Target URL to scan
            
        Returns:
            SkipfishScanResult containing scan findings and metadata
        """
        scan_id = f"skipfish_{int(time.time())}_{hash(target) % 10000}"
        start_time = datetime.now(timezone.utc)
        
        # Prepare output files
        output_dir = self.skipfish_dir / scan_id
        log_file = self.skipfish_dir / f"{scan_id}_log.txt"
        
        # Build Skipfish command
        cmd = self.build_skipfish_command(target, output_dir, log_file)
        
        logger.info(f"Executing Skipfish command: {' '.join(cmd)}")
        
        try:
            # Execute Skipfish scan
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate(timeout=self.skipfish_config.get("timeout", 3600))
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            # Parse results
            findings = self.parse_skipfish_output(output_dir, target)
            
            # Generate summary
            summary = self.generate_summary(findings, duration)
            
            # Read raw output
            raw_output = stdout + stderr
            
            return SkipfishScanResult(
                target=target,
                scan_id=scan_id,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                duration=duration,
                findings=findings,
                summary=summary,
                raw_output=raw_output,
                scan_config=self.skipfish_config.copy()
            )
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error(f"Skipfish scan timed out for target: {target}")
            return self.create_error_result(target, "Scan timed out")
            
        except Exception as e:
            logger.error(f"Error executing Skipfish scan for {target}: {str(e)}")
            return self.create_error_result(target, str(e))
    
    def build_skipfish_command(self, target: str, output_dir: Path, log_file: Path) -> List[str]:
        """
        Build the Skipfish command with all necessary parameters.
        
        Args:
            target: Target URL
            output_dir: Output directory for scan results
            log_file: Log file path
            
        Returns:
            List of command arguments
        """
        cmd = ["skipfish"]
        
        # Basic target
        cmd.extend(["-o", str(output_dir)])
        cmd.extend(["-u", target])
        
        # Logging
        cmd.extend(["-l", str(log_file)])
        
        # Timeout and rate limiting
        if self.skipfish_config.get("timeout"):
            cmd.extend(["-t", str(self.skipfish_config["timeout"])])
        
        if self.skipfish_config.get("rate_limit"):
            cmd.extend(["-r", str(self.skipfish_config["rate_limit"])])
        
        # User agent
        if self.skipfish_config.get("user_agent"):
            cmd.extend(["-A", self.skipfish_config["user_agent"]])
        
        # SSL/TLS options
        if not self.skipfish_config.get("ssl_verify", True):
            cmd.extend(["-S"])
        
        # Depth options
        if self.skipfish_config.get("depth"):
            cmd.extend(["-d", str(self.skipfish_config["depth"])])
        
        # Additional options
        if self.skipfish_config.get("follow_redirects"):
            cmd.extend(["-R"])
        
        # Maximum requests
        if self.skipfish_config.get("max_requests"):
            cmd.extend(["-m", str(self.skipfish_config["max_requests"])])
        
        # Output format
        cmd.extend(["-f", "json"])
        
        return cmd
    
    def parse_skipfish_output(self, output_dir: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse Skipfish output directory into structured findings.
        
        Args:
            output_dir: Path to Skipfish output directory
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        if not output_dir.exists():
            logger.warning(f"Skipfish output directory not found: {output_dir}")
            return findings
        
        try:
            # Parse different Skipfish output files
            findings.extend(self.parse_skipfish_report(output_dir, target))
            findings.extend(self.parse_skipfish_alerts(output_dir, target))
            findings.extend(self.parse_skipfish_issues(output_dir, target))
            
        except Exception as e:
            logger.error(f"Error processing Skipfish output: {str(e)}")
        
        return findings
    
    def parse_skipfish_report(self, output_dir: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse Skipfish report files for findings.
        
        Args:
            output_dir: Skipfish output directory
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        # Look for report files
        report_files = [
            output_dir / "index.html",
            output_dir / "report.html",
            output_dir / "summary.html"
        ]
        
        for report_file in report_files:
            if report_file.exists():
                try:
                    content = report_file.read_text()
                    findings.extend(self.extract_findings_from_html(content, target))
                except Exception as e:
                    logger.error(f"Error parsing report file {report_file}: {str(e)}")
        
        return findings
    
    def parse_skipfish_alerts(self, output_dir: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse Skipfish alert files for findings.
        
        Args:
            output_dir: Skipfish output directory
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        # Look for alert files
        alert_files = [
            output_dir / "alerts.html",
            output_dir / "alerts.json",
            output_dir / "issues.html"
        ]
        
        for alert_file in alert_files:
            if alert_file.exists():
                try:
                    if alert_file.suffix == ".json":
                        findings.extend(self.parse_json_alerts(alert_file, target))
                    else:
                        content = alert_file.read_text()
                        findings.extend(self.extract_findings_from_html(content, target))
                except Exception as e:
                    logger.error(f"Error parsing alert file {alert_file}: {str(e)}")
        
        return findings
    
    def parse_skipfish_issues(self, output_dir: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse Skipfish issue files for findings.
        
        Args:
            output_dir: Skipfish output directory
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        # Look for issue files
        issue_files = [
            output_dir / "issues.json",
            output_dir / "vulnerabilities.html",
            output_dir / "security.html"
        ]
        
        for issue_file in issue_files:
            if issue_file.exists():
                try:
                    if issue_file.suffix == ".json":
                        findings.extend(self.parse_json_issues(issue_file, target))
                    else:
                        content = issue_file.read_text()
                        findings.extend(self.extract_findings_from_html(content, target))
                except Exception as e:
                    logger.error(f"Error parsing issue file {issue_file}: {str(e)}")
        
        return findings
    
    def parse_json_alerts(self, alert_file: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse JSON alert file.
        
        Args:
            alert_file: Path to JSON alert file
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        try:
            with open(alert_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                for alert in data:
                    finding = self.parse_alert_entry(alert, target)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict) and "alerts" in data:
                for alert in data["alerts"]:
                    finding = self.parse_alert_entry(alert, target)
                    if finding:
                        findings.append(finding)
                        
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON alert file: {str(e)}")
        
        return findings
    
    def parse_json_issues(self, issue_file: Path, target: str) -> List[SkipfishFinding]:
        """
        Parse JSON issue file.
        
        Args:
            issue_file: Path to JSON issue file
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        try:
            with open(issue_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                for issue in data:
                    finding = self.parse_issue_entry(issue, target)
                    if finding:
                        findings.append(finding)
            elif isinstance(data, dict) and "issues" in data:
                for issue in data["issues"]:
                    finding = self.parse_issue_entry(issue, target)
                    if finding:
                        findings.append(finding)
                        
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON issue file: {str(e)}")
        
        return findings
    
    def parse_alert_entry(self, alert_data: Dict, target: str) -> Optional[SkipfishFinding]:
        """
        Parse a single alert entry.
        
        Args:
            alert_data: Alert data dictionary
            target: Target URL
            
        Returns:
            SkipfishFinding object or None if parsing fails
        """
        try:
            finding_type = alert_data.get("type", "")
            severity = alert_data.get("severity", "info")
            url = alert_data.get("url", target)
            description = alert_data.get("description", "")
            evidence = alert_data.get("evidence", "")
            category = alert_data.get("category", "")
            
            return SkipfishFinding(
                target=target,
                finding_type=finding_type,
                severity=severity,
                url=url,
                description=description,
                evidence=evidence,
                category=category
            )
            
        except Exception as e:
            logger.error(f"Error parsing alert entry: {str(e)}")
            return None
    
    def parse_issue_entry(self, issue_data: Dict, target: str) -> Optional[SkipfishFinding]:
        """
        Parse a single issue entry.
        
        Args:
            issue_data: Issue data dictionary
            target: Target URL
            
        Returns:
            SkipfishFinding object or None if parsing fails
        """
        try:
            finding_type = issue_data.get("type", "")
            severity = issue_data.get("severity", "info")
            url = issue_data.get("url", target)
            description = issue_data.get("description", "")
            evidence = issue_data.get("evidence", "")
            category = issue_data.get("category", "")
            
            return SkipfishFinding(
                target=target,
                finding_type=finding_type,
                severity=severity,
                url=url,
                description=description,
                evidence=evidence,
                category=category
            )
            
        except Exception as e:
            logger.error(f"Error parsing issue entry: {str(e)}")
            return None
    
    def extract_findings_from_html(self, html_content: str, target: str) -> List[SkipfishFinding]:
        """
        Extract findings from HTML content using regex patterns.
        
        Args:
            html_content: HTML content to parse
            target: Target URL
            
        Returns:
            List of SkipfishFinding objects
        """
        findings = []
        
        # Common patterns for Skipfish HTML output
        patterns = [
            # Alert patterns
            r'<tr[^>]*class="[^"]*alert[^"]*"[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>',
            # Issue patterns
            r'<tr[^>]*class="[^"]*issue[^"]*"[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>',
            # Vulnerability patterns
            r'<tr[^>]*class="[^"]*vuln[^"]*"[^>]*>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>.*?<td[^>]*>([^<]+)</td>'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                if len(match) >= 3:
                    finding = SkipfishFinding(
                        target=target,
                        finding_type=match[0].strip(),
                        severity=self.determine_severity(match[1].strip()),
                        url=target,
                        description=match[1].strip(),
                        evidence=match[2].strip(),
                        category="html_parsed"
                    )
                    findings.append(finding)
        
        return findings
    
    def determine_severity(self, description: str) -> str:
        """
        Determine the severity of a finding based on the description.
        
        Args:
            description: Finding description
            
        Returns:
            Severity level (critical, high, medium, low, info)
        """
        description_lower = description.lower()
        
        # Critical findings
        critical_keywords = [
            "remote code execution", "rce", "sql injection", "xss", 
            "directory traversal", "file inclusion", "command injection"
        ]
        if any(keyword in description_lower for keyword in critical_keywords):
            return "critical"
        
        # High severity findings
        high_keywords = [
            "information disclosure", "sensitive data", "credentials",
            "admin panel", "backup files", "configuration files"
        ]
        if any(keyword in description_lower for keyword in high_keywords):
            return "high"
        
        # Medium severity findings
        medium_keywords = [
            "outdated", "version", "default", "debug", "error messages"
        ]
        if any(keyword in description_lower for keyword in medium_keywords):
            return "medium"
        
        # Low severity findings
        low_keywords = [
            "robots.txt", "server info", "headers", "banner"
        ]
        if any(keyword in description_lower for keyword in low_keywords):
            return "low"
        
        return "info"
    
    def generate_summary(self, findings: List[SkipfishFinding], duration: float) -> Dict[str, Any]:
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
        
        finding_type_counts = {}
        category_counts = {}
        
        for finding in findings:
            severity_counts[finding.severity] += 1
            finding_type_counts[finding.finding_type] = finding_type_counts.get(finding.finding_type, 0) + 1
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        total_findings = len(findings)
        
        return {
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "finding_type_breakdown": finding_type_counts,
            "category_breakdown": category_counts,
            "scan_duration_seconds": duration,
            "scan_duration_formatted": f"{duration:.2f}s",
            "findings_per_minute": (total_findings / (duration / 60)) if duration > 0 else 0
        }
    
    def create_error_result(self, target: str, error_message: str) -> SkipfishScanResult:
        """
        Create an error result when scan fails.
        
        Args:
            target: Target URL
            error_message: Error message
            
        Returns:
            SkipfishScanResult with error information
        """
        return SkipfishScanResult(
            target=target,
            scan_id=f"skipfish_error_{int(time.time())}",
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
            scan_config=self.skipfish_config.copy()
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
    
    parser = argparse.ArgumentParser(description="Skipfish Web Application Security Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    parser.add_argument("--output-dir", default="./outputs", help="Output directory")
    parser.add_argument("--config", help="Configuration file path")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize runner
    output_dir = Path(args.output_dir)
    runner = SkipfishRunner(output_dir)
    
    # Run scan
    results = runner.run_scan([args.target])
    
    # Print results
    for target, result in results.items():
        print(f"\n=== Skipfish Scan Results for {target} ===")
        print(f"Scan ID: {result.scan_id}")
        print(f"Duration: {result.summary.get('scan_duration_formatted', 'N/A')}")
        print(f"Total Findings: {result.summary.get('total_findings', 0)}")
        
        for finding in result.findings:
            print(f"[{finding.severity.upper()}] {finding.finding_type}: {finding.description}")


if __name__ == "__main__":
    main() 