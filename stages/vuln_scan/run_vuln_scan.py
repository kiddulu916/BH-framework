#!/usr/bin/env python3
"""
Stage 3: Black-Box Vulnerability Scanning - Step-by-Step Implementation

This script implements comprehensive black-box vulnerability scanning following a 7-step methodology:
1. Define Scope and Gather Targets
2. Prepare Vulnerability Scanning Tools
3. Leverage Nuclei (Including Extended Fuzzing Templates)
4. Automated Scanning of Web Applications (Black-Box Testing)
5. Scan APIs and Cloud Components
6. Collect, Consolidate, and Interpret Scan Results
7. Continuous Improvement and Re-Scanning

The script assumes no internal access (no source code or credentials) and simulates a real attacker
by probing from the outside using automation-first tooling.
"""

import os
import sys
import json
import time
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from dotenv import load_dotenv
from colorama import init, Fore, Style
from tqdm import tqdm

# Import custom runners
from runners.nuclei_runner import NucleiRunner
from runners.zap_runner import ZAPRunner
from runners.api_scanner import APIScanner
from runners.cloud_scanner import CloudScanner
from runners.result_analyzer import ResultAnalyzer
from runners.target_gatherer import TargetGatherer
from runners.tool_preparer import ToolPreparer
from runners.continuous_improvement import ContinuousImprovement
from runners.nikto_runner import NiktoRunner
from runners.wapiti_runner import WapitiRunner
from runners.arachni_runner import ArachniRunner
from runners.skipfish_runner import SkipfishRunner
from runners.openvas_runner import OpenVASRunner

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_scan.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for vulnerability scanning"""
    target: str
    stage: str = "vuln_scan"
    enable_nuclei: bool = True
    enable_zap: bool = True
    enable_api_scanning: bool = True
    enable_cloud_scanning: bool = True
    enable_fuzzing: bool = True
    enable_nikto: bool = True
    enable_wapiti: bool = True
    enable_arachni: bool = True
    enable_skipfish: bool = True
    enable_openvas: bool = True
    rate_limit: int = 10  # requests per second
    max_concurrent_scans: int = 5
    severity_filter: List[str] = None
    output_format: str = "json"
    api_url: str = None
    jwt_token: str = None
    
    def __post_init__(self):
        if self.severity_filter is None:
            self.severity_filter = ["critical", "high", "medium", "low"]

@dataclass
class ScanResult:
    """Structure for scan results"""
    tool_name: str
    target: str
    vulnerability_type: str
    severity: str
    description: str
    evidence: str
    url: str = None
    parameter: str = None
    timestamp: str = None
    false_positive: bool = False
    verified: bool = False
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

class VulnerabilityScanner:
    """Main vulnerability scanning orchestrator"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.results: List[ScanResult] = []
        self.targets: Dict[str, List[str]] = {
            "web_apps": [],
            "apis": [],
            "cloud_services": []
        }
        
        # Initialize output directories
        self.setup_output_dirs()
        
        # Load environment variables
        load_dotenv()
        
        # Initialize API configuration
        self.api_url = config.api_url or os.getenv("BACKEND_API_URL")
        self.jwt_token = config.jwt_token or os.getenv("BACKEND_JWT_TOKEN")
        
        if not self.api_url or not self.jwt_token:
            logger.warning("API URL or JWT token not configured. Results will not be submitted to backend.")
    
    def setup_output_dirs(self):
        """Setup output directory structure"""
        base_dir = Path(f"/outputs/{self.config.stage}/{self.config.target}")
        
        # Create main directories
        directories = [
            "targets",
            "nuclei",
            "zap",
            "api_scan",
            "cloud_scan",
            "nikto",
            "wapiti",
            "arachni",
            "skipfish",
            "openvas",
            "consolidated",
            "reports"
        ]
        
        for dir_name in directories:
            (base_dir / dir_name).mkdir(parents=True, exist_ok=True)
        
        self.output_dir = base_dir
        logger.info(f"Output directory setup: {self.output_dir}")
    
    def run(self) -> bool:
        """Execute the complete vulnerability scanning workflow"""
        try:
            logger.info(f"Starting black-box vulnerability scanning for target: {self.config.target}")
            logger.info("Following 7-step methodology for comprehensive coverage")
            
            # Step 1: Define Scope and Gather Targets
            logger.info(f"{Fore.CYAN}Step 1: Define Scope and Gather Targets{Style.RESET_ALL}")
            if not self.step1_gather_targets():
                logger.error("Failed to gather targets from reconnaissance results")
                return False
            
            # Step 2: Prepare Vulnerability Scanning Tools
            logger.info(f"{Fore.CYAN}Step 2: Prepare Vulnerability Scanning Tools{Style.RESET_ALL}")
            if not self.step2_prepare_tools():
                logger.error("Failed to prepare vulnerability scanning tools")
                return False
            
            # Step 3: Leverage Nuclei (Including Extended Fuzzing Templates)
            logger.info(f"{Fore.CYAN}Step 3: Leverage Nuclei (Including Extended Fuzzing Templates){Style.RESET_ALL}")
            if self.config.enable_nuclei:
                self.step3_nuclei_scanning()
            
            # Step 4: Automated Scanning of Web Applications (Black-Box Testing)
            logger.info(f"{Fore.CYAN}Step 4: Automated Scanning of Web Applications (Black-Box Testing){Style.RESET_ALL}")
            if self.config.enable_zap:
                self.step4_web_application_scanning()
            if self.config.enable_nikto:
                self.step4b_nikto_scanning()
            if self.config.enable_wapiti:
                self.step4c_wapiti_scanning()
            if self.config.enable_arachni:
                self.step4d_arachni_scanning()
            if self.config.enable_skipfish:
                self.step4e_skipfish_scanning()
            if self.config.enable_openvas:
                self.step4f_openvas_scanning()
            
            # Step 5: Scan APIs and Cloud Components
            logger.info(f"{Fore.CYAN}Step 5: Scan APIs and Cloud Components{Style.RESET_ALL}")
            if self.config.enable_api_scanning:
                self.step5_api_scanning()
            if self.config.enable_cloud_scanning:
                self.step5_cloud_scanning()
            
            # Step 6: Collect, Consolidate, and Interpret Scan Results
            logger.info(f"{Fore.CYAN}Step 6: Collect, Consolidate, and Interpret Scan Results{Style.RESET_ALL}")
            self.step6_consolidate_results()
            
            # Step 7: Continuous Improvement and Re-Scanning
            logger.info(f"{Fore.CYAN}Step 7: Continuous Improvement and Re-Scanning{Style.RESET_ALL}")
            self.step7_continuous_improvement()
            
            # Submit results to backend API
            if self.api_url and self.jwt_token:
                self.submit_results_to_api()
            
            logger.info(f"{Fore.GREEN}Vulnerability scanning completed successfully!{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            logger.error(f"Vulnerability scanning failed: {str(e)}")
            return False
    
    def step1_gather_targets(self) -> bool:
        """Step 1: Define Scope and Gather Targets"""
        try:
            logger.info("Gathering targets from reconnaissance results...")
            
            # Initialize target gatherer
            gatherer = TargetGatherer(self.config.target, self.api_url, self.jwt_token)
            
            # Gather targets from passive and active reconnaissance
            self.targets = gatherer.gather_all_targets()
            
            # Save target list
            targets_file = self.output_dir / "targets" / "target_list.json"
            with open(targets_file, 'w') as f:
                json.dump(self.targets, f, indent=2)
            
            # Log target summary
            total_targets = sum(len(targets) for targets in self.targets.values())
            logger.info(f"Gathered {total_targets} total targets:")
            for category, targets in self.targets.items():
                logger.info(f"  {category}: {len(targets)} targets")
            
            return True
            
        except Exception as e:
            logger.error(f"Error gathering targets: {str(e)}")
            return False
    
    def step2_prepare_tools(self) -> bool:
        """Step 2: Prepare Vulnerability Scanning Tools"""
        try:
            logger.info("Preparing vulnerability scanning tools...")
            
            # Initialize tool preparer
            preparer = ToolPreparer(self.config.rate_limit)
            
            # Prepare OWASP ZAP
            if self.config.enable_zap:
                logger.info("Preparing OWASP ZAP...")
                preparer.prepare_zap()
            
            # Prepare Nuclei
            if self.config.enable_nuclei:
                logger.info("Preparing Nuclei...")
                preparer.prepare_nuclei()
            
            # Prepare additional scanners
            logger.info("Preparing additional scanners...")
            preparer.prepare_additional_scanners()
            
            logger.info("All tools prepared successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error preparing tools: {str(e)}")
            return False
    
    def step3_nuclei_scanning(self):
        """Step 3: Leverage Nuclei (Including Extended Fuzzing Templates)"""
        try:
            logger.info("Starting Nuclei vulnerability scanning...")
            
            # Initialize Nuclei runner
            nuclei_runner = NucleiRunner(
                output_dir=self.output_dir / "nuclei",
                enable_fuzzing=self.config.enable_fuzzing,
                severity_filter=self.config.severity_filter
            )
            
            # Get all targets for Nuclei scanning
            all_targets = []
            for targets in self.targets.values():
                all_targets.extend(targets)
            
            if not all_targets:
                logger.warning("No targets available for Nuclei scanning")
                return
            
            # Run Nuclei scans
            logger.info(f"Running Nuclei on {len(all_targets)} targets...")
            nuclei_results = nuclei_runner.run_scan(all_targets)
            
            # Process and store results
            self.results.extend(nuclei_results)
            
            logger.info(f"Nuclei scanning completed. Found {len(nuclei_results)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error in Nuclei scanning: {str(e)}")
    
    def step4_web_application_scanning(self):
        """Step 4: Automated Scanning of Web Applications (Black-Box Testing)"""
        try:
            logger.info("Starting automated web application scanning...")
            
            # Initialize ZAP runner
            zap_runner = ZAPRunner(
                output_dir=self.output_dir / "zap",
                rate_limit=self.config.rate_limit,
                max_concurrent=self.config.max_concurrent_scans
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            
            if not web_targets:
                logger.warning("No web application targets available")
                return
            
            # Run ZAP scans
            logger.info(f"Running ZAP on {len(web_targets)} web applications...")
            zap_results = zap_runner.run_scan(web_targets)
            
            # Process and store results
            self.results.extend(zap_results)
            
            logger.info(f"ZAP scanning completed. Found {len(zap_results)} vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error in ZAP scanning: {str(e)}")
    
    def step4b_nikto_scanning(self):
        """Step 4b: Nikto Web Server Vulnerability Scanning"""
        try:
            logger.info("Starting Nikto web server vulnerability scanning...")
            
            # Initialize Nikto runner
            nikto_runner = NiktoRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Nikto scanning")
                return
            
            # Run Nikto scans
            nikto_results = nikto_runner.run_scan(web_targets)
            
            # Process results
            for target, result in nikto_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="nikto",
                        target=target,
                        vulnerability_type=finding.message,
                        severity=finding.severity,
                        description=finding.message,
                        evidence=finding.evidence,
                        url=target,
                        parameter=finding.parameter
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Nikto scanning completed. Found {len(nikto_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Nikto scanning: {str(e)}")
    
    def step4c_wapiti_scanning(self):
        """Step 4c: Wapiti Web Application Vulnerability Scanning"""
        try:
            logger.info("Starting Wapiti web application vulnerability scanning...")
            
            # Initialize Wapiti runner
            wapiti_runner = WapitiRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Wapiti scanning")
                return
            
            # Run Wapiti scans
            wapiti_results = wapiti_runner.run_scan(web_targets)
            
            # Process results
            for target, result in wapiti_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="arachni",
                        target=target,
                        vulnerability_type=finding.vulnerability_type,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.proof,
                        url=finding.url,
                        parameter=finding.parameter
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Arachni scanning completed. Found {len(arachni_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Arachni scanning: {str(e)}")
    
    def step4e_skipfish_scanning(self):
        """Step 4e: Skipfish Web Application Security Scanning"""
        try:
            logger.info("Starting Skipfish web application security scanning...")
            
            # Initialize Skipfish runner
            skipfish_runner = SkipfishRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Skipfish scanning")
                return
            
            # Run Skipfish scans
            skipfish_results = skipfish_runner.run_scan(web_targets)
            
            # Process results
            for target, result in skipfish_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="skipfish",
                        target=target,
                        vulnerability_type=finding.finding_type,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        url=finding.url
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Skipfish scanning completed. Found {len(skipfish_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Skipfish scanning: {str(e)}")
    
    def step4f_openvas_scanning(self):
        """Step 4f: OpenVAS Network Vulnerability Scanning"""
        try:
            logger.info("Starting OpenVAS network vulnerability scanning...")
            
            # Initialize OpenVAS runner
            openvas_runner = OpenVASRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get all targets (web apps, APIs, cloud services)
            all_targets = []
            all_targets.extend(self.targets.get("web_apps", []))
            all_targets.extend(self.targets.get("apis", []))
            all_targets.extend(self.targets.get("cloud_services", []))
            
            if not all_targets:
                logger.warning("No targets found for OpenVAS scanning")
                return
            
            # Run OpenVAS scans
            openvas_results = openvas_runner.run_scan(all_targets)
            
            # Process results
            for target, result in openvas_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="openvas",
                        target=target,
                        vulnerability_type=finding.name,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.proof,
                        url=target,
                        parameter=finding.port
                    )
                    self.results.append(scan_result)
            
            logger.info(f"OpenVAS scanning completed. Found {len(openvas_results)} results")
            
        except Exception as e:
            logger.error(f"Error in OpenVAS scanning: {str(e)}")
    
    def step5_api_scanning(self):
        """Step 5: Scan APIs and Cloud Components - API Scanning"""
        try:
            logger.info("Starting API vulnerability scanning...")
            
            # Initialize API scanner
            api_scanner = APIScanner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Run API scanning
            success = api_scanner.run_api_scanning(self.targets)
            
            if success:
                # Get results summary
                api_summary = api_scanner.get_results_summary()
                logger.info(f"API scanning completed successfully. Summary: {api_summary}")
            else:
                logger.error("API scanning failed")
            
        except Exception as e:
            logger.error(f"Error in API scanning: {str(e)}")
    
    def step5_cloud_scanning(self):
        """Step 5: Scan APIs and Cloud Components - Cloud Scanning"""
        try:
            logger.info("Starting cloud component vulnerability scanning...")
            
            # Initialize cloud scanner
            cloud_scanner = CloudScanner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Run cloud scanning
            success = cloud_scanner.run_cloud_scanning(self.targets)
            
            if success:
                # Get results summary
                cloud_summary = cloud_scanner.get_results_summary()
                logger.info(f"Cloud scanning completed successfully. Summary: {cloud_summary}")
            else:
                logger.error("Cloud scanning failed")
            
        except Exception as e:
            logger.error(f"Error in cloud scanning: {str(e)}")
    
    def step6_consolidate_results(self):
        """Step 6: Collect, Consolidate, and Interpret Scan Results"""
        try:
            logger.info("Consolidating and interpreting scan results...")
            
            # Initialize result analyzer
            analyzer = ResultAnalyzer(output_dir=self.output_dir)
            
            # Collect results from all scanning tools
            scan_results = {
                'nuclei': self.results,  # This will be populated by previous steps
                'zap': [],  # Will be populated when ZAP integration is complete
                'api_scanner': [],  # Will be populated when API scanner is complete
                'cloud_scanner': [],  # Will be populated when cloud scanner is complete
                'nikto': [],  # Will be populated when Nikto scanning is complete
                'wapiti': [],  # Will be populated when Wapiti scanning is complete
                'arachni': [],  # Will be populated when Arachni scanning is complete
                'skipfish': [],  # Will be populated when Skipfish scanning is complete
                'openvas': []  # Will be populated when OpenVAS scanning is complete
            }
            
            # Analyze and consolidate all results
            success = analyzer.analyze_all_results(scan_results)
            
            if success:
                # Get analysis summary
                analysis_summary = analyzer.get_analysis_summary()
                logger.info(f"Result analysis completed successfully. Summary: {analysis_summary}")
            else:
                logger.error("Result analysis failed")
            
        except Exception as e:
            logger.error(f"Error consolidating results: {str(e)}")
    
    def step7_continuous_improvement(self):
        """Step 7: Continuous Improvement and Re-Scanning"""
        try:
            logger.info("Implementing continuous improvement measures...")
            
            # Initialize continuous improvement manager
            improvement_manager = ContinuousImprovement(
                output_dir=self.output_dir,
                config={"rate_limit": self.config.rate_limit}
            )
            
            # Prepare scan results for analysis
            scan_results = {
                'findings': [asdict(result) for result in self.results],
                'scan_summary': {
                    'total_findings': len(self.results),
                    'scan_duration': time.time(),  # This should be calculated from actual start time
                    'targets': self.targets
                }
            }
            
            # Run continuous improvement workflow
            success = improvement_manager.run_continuous_improvement(scan_results, self.targets)
            
            if success:
                # Get improvement summary
                improvement_summary = improvement_manager.get_improvement_summary()
                logger.info(f"Continuous improvement completed successfully. Summary: {improvement_summary}")
            else:
                logger.error("Continuous improvement failed")
            
        except Exception as e:
            logger.error(f"Error in continuous improvement: {str(e)}")
    
    def step4b_nikto_scanning(self):
        """Step 4b: Nikto Web Server Vulnerability Scanning"""
        try:
            logger.info("Starting Nikto web server vulnerability scanning...")
            
            # Initialize Nikto runner
            nikto_runner = NiktoRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Nikto scanning")
                return
            
            # Run Nikto scans
            nikto_results = nikto_runner.run_scan(web_targets)
            
            # Process results
            for target, result in nikto_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="nikto",
                        target=target,
                        vulnerability_type=finding.message,
                        severity=finding.severity,
                        description=finding.message,
                        evidence=finding.evidence,
                        url=target,
                        parameter=finding.parameter
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Nikto scanning completed. Found {len(nikto_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Nikto scanning: {str(e)}")
    
    def step4c_wapiti_scanning(self):
        """Step 4c: Wapiti Web Application Vulnerability Scanning"""
        try:
            logger.info("Starting Wapiti web application vulnerability scanning...")
            
            # Initialize Wapiti runner
            wapiti_runner = WapitiRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Wapiti scanning")
                return
            
            # Run Wapiti scans
            wapiti_results = wapiti_runner.run_scan(web_targets)
            
            # Process results
            for target, result in wapiti_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="wapiti",
                        target=target,
                        vulnerability_type=finding.vulnerability_type,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        url=finding.url,
                        parameter=finding.parameter
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Wapiti scanning completed. Found {len(wapiti_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Wapiti scanning: {str(e)}")
    
    def step4d_arachni_scanning(self):
        """Step 4d: Arachni Web Application Security Scanning"""
        try:
            logger.info("Starting Arachni web application security scanning...")
            
            # Initialize Arachni runner
            arachni_runner = ArachniRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Arachni scanning")
                return
            
            # Run Arachni scans
            arachni_results = arachni_runner.run_scan(web_targets)
            
            # Process results
            for target, result in arachni_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="arachni",
                        target=target,
                        vulnerability_type=finding.vulnerability_type,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.proof,
                        url=finding.url,
                        parameter=finding.parameter
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Arachni scanning completed. Found {len(arachni_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Arachni scanning: {str(e)}")
    
    def step4e_skipfish_scanning(self):
        """Step 4e: Skipfish Web Application Security Scanning"""
        try:
            logger.info("Starting Skipfish web application security scanning...")
            
            # Initialize Skipfish runner
            skipfish_runner = SkipfishRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get web application targets
            web_targets = self.targets.get("web_apps", [])
            if not web_targets:
                logger.warning("No web application targets found for Skipfish scanning")
                return
            
            # Run Skipfish scans
            skipfish_results = skipfish_runner.run_scan(web_targets)
            
            # Process results
            for target, result in skipfish_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="skipfish",
                        target=target,
                        vulnerability_type=finding.finding_type,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.evidence,
                        url=finding.url
                    )
                    self.results.append(scan_result)
            
            logger.info(f"Skipfish scanning completed. Found {len(skipfish_results)} results")
            
        except Exception as e:
            logger.error(f"Error in Skipfish scanning: {str(e)}")
    
    def step4f_openvas_scanning(self):
        """Step 4f: OpenVAS Network Vulnerability Scanning"""
        try:
            logger.info("Starting OpenVAS network vulnerability scanning...")
            
            # Initialize OpenVAS runner
            openvas_runner = OpenVASRunner(
                output_dir=self.output_dir,
                rate_limit_config={"rate_limit": self.config.rate_limit}
            )
            
            # Get all targets (web apps, APIs, cloud services)
            all_targets = []
            all_targets.extend(self.targets.get("web_apps", []))
            all_targets.extend(self.targets.get("apis", []))
            all_targets.extend(self.targets.get("cloud_services", []))
            
            if not all_targets:
                logger.warning("No targets found for OpenVAS scanning")
                return
            
            # Run OpenVAS scans
            openvas_results = openvas_runner.run_scan(all_targets)
            
            # Process results
            for target, result in openvas_results.items():
                for finding in result.findings:
                    scan_result = ScanResult(
                        tool_name="openvas",
                        target=target,
                        vulnerability_type=finding.name,
                        severity=finding.severity,
                        description=finding.description,
                        evidence=finding.proof,
                        url=target,
                        parameter=finding.port
                    )
                    self.results.append(scan_result)
            
            logger.info(f"OpenVAS scanning completed. Found {len(openvas_results)} results")
            
        except Exception as e:
            logger.error(f"Error in OpenVAS scanning: {str(e)}")
    

    
    def submit_results_to_api(self):
        """Submit scan results to backend API"""
        try:
            if not self.api_url or not self.jwt_token:
                logger.warning("API URL or JWT token not available. Skipping API submission.")
                return
            
            logger.info("Submitting results to backend API...")
            
            headers = {
                'Authorization': f'Bearer {self.jwt_token}',
                'Content-Type': 'application/json'
            }
            
            # Prepare payload
            payload = {
                'target': self.config.target,
                'stage': self.config.stage,
                'scan_config': asdict(self.config),
                'results': [asdict(result) for result in self.results],
                'summary': {
                    'total_vulnerabilities': len(self.results),
                    'by_severity': self.get_severity_summary(),
                    'by_type': self.get_type_summary(),
                    'scan_timestamp': datetime.utcnow().isoformat()
                }
            }
            
            # Submit to API
            response = requests.post(
                f"{self.api_url}/api/vulnerability-scan-results/",
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                logger.info("Results submitted to backend API successfully")
            else:
                logger.error(f"Failed to submit results to API: {response.status_code} - {response.text}")
                
        except Exception as e:
            logger.error(f"Error submitting results to API: {str(e)}")
    
    def get_severity_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by severity"""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for result in self.results:
            if result.severity in summary:
                summary[result.severity] += 1
        return summary
    
    def get_type_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by type"""
        summary = {}
        for result in self.results:
            vuln_type = result.vulnerability_type
            summary[vuln_type] = summary.get(vuln_type, 0) + 1
        return summary

def main():
    """Main entry point for vulnerability scanning"""
    parser = argparse.ArgumentParser(description="Black-Box Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--stage", default="vuln_scan", help="Stage name")
    parser.add_argument("--enable-nuclei", action="store_true", default=True, help="Enable Nuclei scanning")
    parser.add_argument("--enable-zap", action="store_true", default=True, help="Enable OWASP ZAP scanning")
    parser.add_argument("--enable-api-scanning", action="store_true", default=True, help="Enable API scanning")
    parser.add_argument("--enable-cloud-scanning", action="store_true", default=True, help="Enable cloud scanning")
    parser.add_argument("--enable-fuzzing", action="store_true", default=True, help="Enable Nuclei fuzzing templates")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit (requests per second)")
    parser.add_argument("--max-concurrent", type=int, default=5, help="Maximum concurrent scans")
    parser.add_argument("--severity", nargs="+", default=["critical", "high", "medium", "low"], 
                       help="Severity levels to scan")
    parser.add_argument("--output-format", default="json", help="Output format")
    parser.add_argument("--api-url", help="Backend API URL")
    parser.add_argument("--jwt-token", help="JWT token for API authentication")
    
    args = parser.parse_args()
    
    # Create configuration
    config = ScanConfig(
        target=args.target,
        stage=args.stage,
        enable_nuclei=args.enable_nuclei,
        enable_zap=args.enable_zap,
        enable_api_scanning=args.enable_api_scanning,
        enable_cloud_scanning=args.enable_cloud_scanning,
        enable_fuzzing=args.enable_fuzzing,
        rate_limit=args.rate_limit,
        max_concurrent_scans=args.max_concurrent,
        severity_filter=args.severity,
        output_format=args.output_format,
        api_url=args.api_url,
        jwt_token=args.jwt_token
    )
    
    # Initialize and run scanner
    scanner = VulnerabilityScanner(config)
    success = scanner.run()
    
    if success:
        logger.info(f"{Fore.GREEN}Vulnerability scanning completed successfully!{Style.RESET_ALL}")
        sys.exit(0)
    else:
        logger.error(f"{Fore.RED}Vulnerability scanning failed!{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
