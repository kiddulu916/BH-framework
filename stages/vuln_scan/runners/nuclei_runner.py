#!/usr/bin/env python3
"""
Nuclei Runner for Vulnerability Scanning

This module implements Step 3 of the black-box vulnerability scanning methodology:
"Leverage Nuclei (Including Extended Fuzzing Templates)"

It runs Nuclei vulnerability scanner with community templates and extended fuzzing templates
to identify known vulnerabilities across all tech stacks.
"""

import os
import json
import logging
import subprocess
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import concurrent.futures

logger = logging.getLogger(__name__)

@dataclass
class NucleiResult:
    """Structure for Nuclei scan results"""
    template_id: str
    template_name: str
    severity: str
    target: str
    url: str
    description: str
    evidence: str
    matcher_name: str = ""
    extractor_name: str = ""
    timestamp: str = ""
    false_positive: bool = False
    verified: bool = False
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

class NucleiRunner:
    """Runs Nuclei vulnerability scanner with comprehensive template coverage"""
    
    def __init__(self, output_dir: Path, enable_fuzzing: bool = True, severity_filter: List[str] = None):
        self.output_dir = output_dir
        self.enable_fuzzing = enable_fuzzing
        self.severity_filter = severity_filter or ["critical", "high", "medium", "low"]
        
        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "raw").mkdir(exist_ok=True)
        (self.output_dir / "parsed").mkdir(exist_ok=True)
        (self.output_dir / "fuzzing").mkdir(exist_ok=True)
        
        # Nuclei configuration
        self.nuclei_config = {
            "rate_limit": 150,
            "concurrency": 25,
            "timeout": 30,
            "retries": 3,
            "silent": False,
            "verbose": False,
            "json_output": True
        }
        
        # Template categories to scan
        self.template_categories = [
            "cves", "vulnerabilities", "misconfiguration", "exposures",
            "technologies", "default-logins", "files", "panels"
        ]
    
    def run_scan(self, targets: List[str]) -> List[NucleiResult]:
        """Run comprehensive Nuclei scan on targets"""
        try:
            logger.info(f"Starting Nuclei scan on {len(targets)} targets")
            
            all_results = []
            
            # Step 1: Run basic vulnerability scan with community templates
            logger.info("Step 1: Running basic vulnerability scan...")
            basic_results = self.run_basic_scan(targets)
            all_results.extend(basic_results)
            
            # Step 2: Run extended fuzzing scan if enabled
            if self.enable_fuzzing:
                logger.info("Step 2: Running extended fuzzing scan...")
                fuzzing_results = self.run_fuzzing_scan(targets)
                all_results.extend(fuzzing_results)
            
            # Step 3: Run technology detection scan
            logger.info("Step 3: Running technology detection scan...")
            tech_results = self.run_technology_scan(targets)
            all_results.extend(tech_results)
            
            # Step 4: Run custom template scan
            logger.info("Step 4: Running custom template scan...")
            custom_results = self.run_custom_scan(targets)
            all_results.extend(custom_results)
            
            # Process and save results
            self.process_results(all_results)
            
            logger.info(f"Nuclei scan completed. Found {len(all_results)} vulnerabilities")
            return all_results
            
        except Exception as e:
            logger.error(f"Error running Nuclei scan: {str(e)}")
            return []
    
    def run_basic_scan(self, targets: List[str]) -> List[NucleiResult]:
        """Run basic vulnerability scan with community templates"""
        try:
            logger.info("Running basic vulnerability scan...")
            
            # Prepare command
            cmd = self.build_nuclei_command(
                targets=targets,
                templates="cves,vulnerabilities,misconfiguration,exposures",
                severity=self.severity_filter,
                output_file=self.output_dir / "raw" / "basic_scan.json"
            )
            
            # Run scan
            results = self.execute_nuclei_scan(cmd, "basic_scan")
            
            logger.info(f"Basic scan completed. Found {len(results)} vulnerabilities")
            return results
            
        except Exception as e:
            logger.error(f"Error in basic scan: {str(e)}")
            return []
    
    def run_fuzzing_scan(self, targets: List[str]) -> List[NucleiResult]:
        """Run extended fuzzing scan with fuzzing templates"""
        try:
            logger.info("Running extended fuzzing scan...")
            
            # Prepare command with fuzzing templates
            cmd = self.build_nuclei_command(
                targets=targets,
                templates="fuzzing",
                severity=self.severity_filter,
                output_file=self.output_dir / "raw" / "fuzzing_scan.json",
                fuzzing=True
            )
            
            # Run scan
            results = self.execute_nuclei_scan(cmd, "fuzzing_scan")
            
            logger.info(f"Fuzzing scan completed. Found {len(results)} vulnerabilities")
            return results
            
        except Exception as e:
            logger.error(f"Error in fuzzing scan: {str(e)}")
            return []
    
    def run_technology_scan(self, targets: List[str]) -> List[NucleiResult]:
        """Run technology detection scan"""
        try:
            logger.info("Running technology detection scan...")
            
            # Prepare command for technology detection
            cmd = self.build_nuclei_command(
                targets=targets,
                templates="technologies",
                severity=["info", "low", "medium", "high", "critical"],
                output_file=self.output_dir / "raw" / "technology_scan.json"
            )
            
            # Run scan
            results = self.execute_nuclei_scan(cmd, "technology_scan")
            
            logger.info(f"Technology scan completed. Found {len(results)} technologies")
            return results
            
        except Exception as e:
            logger.error(f"Error in technology scan: {str(e)}")
            return []
    
    def run_custom_scan(self, targets: List[str]) -> List[NucleiResult]:
        """Run custom template scan for specific vulnerabilities"""
        try:
            logger.info("Running custom template scan...")
            
            # Define custom scan scenarios
            custom_scenarios = [
                {
                    "name": "default_logins",
                    "templates": "default-logins",
                    "description": "Default credential testing"
                },
                {
                    "name": "exposed_files",
                    "templates": "files",
                    "description": "Exposed sensitive files"
                },
                {
                    "name": "admin_panels",
                    "templates": "panels",
                    "description": "Admin panel detection"
                }
            ]
            
            all_results = []
            
            for scenario in custom_scenarios:
                logger.info(f"Running {scenario['name']} scan...")
                
                cmd = self.build_nuclei_command(
                    targets=targets,
                    templates=scenario["templates"],
                    severity=self.severity_filter,
                    output_file=self.output_dir / "raw" / f"{scenario['name']}_scan.json"
                )
                
                results = self.execute_nuclei_scan(cmd, scenario["name"])
                all_results.extend(results)
                
                logger.info(f"{scenario['name']} scan completed. Found {len(results)} vulnerabilities")
            
            return all_results
            
        except Exception as e:
            logger.error(f"Error in custom scan: {str(e)}")
            return []
    
    def build_nuclei_command(self, targets: List[str], templates: str, severity: List[str], 
                           output_file: Path, fuzzing: bool = False) -> List[str]:
        """Build Nuclei command with appropriate parameters"""
        try:
            # Base command
            cmd = ["nuclei"]
            
            # Add targets
            if len(targets) == 1:
                cmd.extend(["-u", targets[0]])
            else:
                # Create targets file for multiple targets
                targets_file = self.output_dir / "targets.txt"
                with open(targets_file, 'w') as f:
                    for target in targets:
                        f.write(f"{target}\n")
                cmd.extend(["-l", str(targets_file)])
            
            # Add templates
            cmd.extend(["-t", templates])
            
            # Add severity filter
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            # Add fuzzing if enabled
            if fuzzing:
                cmd.append("-fuzz")
            
            # Add rate limiting and performance options
            cmd.extend([
                "-rate-limit", str(self.nuclei_config["rate_limit"]),
                "-concurrency", str(self.nuclei_config["concurrency"]),
                "-timeout", str(self.nuclei_config["timeout"]),
                "-retries", str(self.nuclei_config["retries"])
            ])
            
            # Add output options
            cmd.extend([
                "-json",
                "-o", str(output_file),
                "-silent"
            ])
            
            return cmd
            
        except Exception as e:
            logger.error(f"Error building Nuclei command: {str(e)}")
            return []
    
    def execute_nuclei_scan(self, cmd: List[str], scan_type: str) -> List[NucleiResult]:
        """Execute Nuclei scan and parse results"""
        try:
            logger.info(f"Executing {scan_type} scan with command: {' '.join(cmd)}")
            
            # Run Nuclei
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            end_time = time.time()
            
            # Log execution details
            logger.info(f"{scan_type} scan completed in {end_time - start_time:.2f} seconds")
            
            if result.returncode != 0:
                logger.warning(f"Nuclei {scan_type} scan returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    logger.warning(f"Stderr: {result.stderr}")
            
            # Parse results
            results = self.parse_nuclei_output(result.stdout, scan_type)
            
            # Save raw output
            raw_output_file = self.output_dir / "raw" / f"{scan_type}_raw.txt"
            with open(raw_output_file, 'w') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n\nSTDERR:\n{result.stderr}")
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nuclei {scan_type} scan timed out")
            return []
        except Exception as e:
            logger.error(f"Error executing Nuclei {scan_type} scan: {str(e)}")
            return []
    
    def parse_nuclei_output(self, output: str, scan_type: str) -> List[NucleiResult]:
        """Parse Nuclei JSON output into structured results"""
        results = []
        
        try:
            # Split output into lines and parse each JSON object
            lines = output.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                try:
                    data = json.loads(line)
                    result = self.parse_nuclei_result(data, scan_type)
                    if result:
                        results.append(result)
                
                except json.JSONDecodeError:
                    logger.debug(f"Failed to parse JSON line: {line}")
                    continue
            
            logger.info(f"Parsed {len(results)} results from {scan_type} scan")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing Nuclei output: {str(e)}")
            return results
    
    def parse_nuclei_result(self, data: Dict[str, Any], scan_type: str) -> Optional[NucleiResult]:
        """Parse individual Nuclei result"""
        try:
            # Extract required fields
            template_id = data.get("template-id", "")
            template_name = data.get("template", "")
            severity = data.get("info", {}).get("severity", "unknown").lower()
            target = data.get("host", "")
            url = data.get("matched-at", "")
            description = data.get("info", {}).get("description", "")
            evidence = data.get("extracted-results", [])
            
            # Convert evidence to string
            if isinstance(evidence, list):
                evidence = ", ".join(evidence)
            elif not isinstance(evidence, str):
                evidence = str(evidence)
            
            # Extract additional fields
            matcher_name = data.get("matcher-name", "")
            extractor_name = data.get("extractor-name", "")
            
            # Create result object
            result = NucleiResult(
                template_id=template_id,
                template_name=template_name,
                severity=severity,
                target=target,
                url=url,
                description=description,
                evidence=evidence,
                matcher_name=matcher_name,
                extractor_name=extractor_name
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing Nuclei result: {str(e)}")
            return None
    
    def process_results(self, results: List[NucleiResult]):
        """Process and save scan results"""
        try:
            logger.info(f"Processing {len(results)} Nuclei results...")
            
            # Group results by severity
            results_by_severity = {}
            for result in results:
                severity = result.severity
                if severity not in results_by_severity:
                    results_by_severity[severity] = []
                results_by_severity[severity].append(result)
            
            # Save results by severity
            for severity, severity_results in results_by_severity.items():
                output_file = self.output_dir / "parsed" / f"{severity}_vulnerabilities.json"
                with open(output_file, 'w') as f:
                    json.dump([self.result_to_dict(result) for result in severity_results], f, indent=2)
            
            # Save all results
            all_results_file = self.output_dir / "parsed" / "all_vulnerabilities.json"
            with open(all_results_file, 'w') as f:
                json.dump([self.result_to_dict(result) for result in results], f, indent=2)
            
            # Generate summary
            self.generate_summary(results)
            
            logger.info("Results processing completed")
            
        except Exception as e:
            logger.error(f"Error processing results: {str(e)}")
    
    def result_to_dict(self, result: NucleiResult) -> Dict[str, Any]:
        """Convert NucleiResult to dictionary"""
        return {
            "template_id": result.template_id,
            "template_name": result.template_name,
            "severity": result.severity,
            "target": result.target,
            "url": result.url,
            "description": result.description,
            "evidence": result.evidence,
            "matcher_name": result.matcher_name,
            "extractor_name": result.extractor_name,
            "timestamp": result.timestamp,
            "false_positive": result.false_positive,
            "verified": result.verified
        }
    
    def generate_summary(self, results: List[NucleiResult]):
        """Generate scan summary"""
        try:
            summary = {
                "scan_timestamp": datetime.utcnow().isoformat(),
                "total_vulnerabilities": len(results),
                "by_severity": {},
                "by_template": {},
                "by_target": {},
                "scan_config": self.nuclei_config
            }
            
            # Count by severity
            for result in results:
                severity = result.severity
                summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
            
            # Count by template
            for result in results:
                template = result.template_id
                summary["by_template"][template] = summary["by_template"].get(template, 0) + 1
            
            # Count by target
            for result in results:
                target = result.target
                summary["by_target"][target] = summary["by_target"].get(target, 0) + 1
            
            # Save summary
            summary_file = self.output_dir / "parsed" / "scan_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            # Log summary
            logger.info("Scan Summary:")
            logger.info(f"  Total vulnerabilities: {summary['total_vulnerabilities']}")
            for severity, count in summary["by_severity"].items():
                logger.info(f"  {severity}: {count}")
            
        except Exception as e:
            logger.error(f"Error generating summary: {str(e)}")
    
    def run_concurrent_scans(self, targets: List[str], max_workers: int = 3) -> List[NucleiResult]:
        """Run multiple Nuclei scans concurrently"""
        try:
            logger.info(f"Running concurrent Nuclei scans with {max_workers} workers")
            
            # Define scan tasks
            scan_tasks = [
                ("basic", self.run_basic_scan),
                ("technology", self.run_technology_scan),
                ("custom", self.run_custom_scan)
            ]
            
            if self.enable_fuzzing:
                scan_tasks.append(("fuzzing", self.run_fuzzing_scan))
            
            all_results = []
            
            # Run scans concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit scan tasks
                future_to_scan = {
                    executor.submit(scan_func, targets): scan_name 
                    for scan_name, scan_func in scan_tasks
                }
                
                # Collect results
                for future in concurrent.futures.as_completed(future_to_scan):
                    scan_name = future_to_scan[future]
                    try:
                        results = future.result()
                        all_results.extend(results)
                        logger.info(f"Concurrent {scan_name} scan completed with {len(results)} results")
                    except Exception as e:
                        logger.error(f"Concurrent {scan_name} scan failed: {str(e)}")
            
            logger.info(f"Concurrent scans completed. Total results: {len(all_results)}")
            return all_results
            
        except Exception as e:
            logger.error(f"Error running concurrent scans: {str(e)}")
            return [] 