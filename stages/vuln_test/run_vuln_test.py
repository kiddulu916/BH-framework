#!/usr/bin/env python3
"""
Stage 4: Vulnerability Scanning (Black-Box with AI Integration)

This stage implements comprehensive black-box vulnerability scanning with AI integration,
following a 6-step methodology for automated vulnerability discovery and verification.

Steps:
4.1: Preparation and Input Data Formatting
4.2: Automated Black-Box Scanning with Browser and CLI Tools
4.3: AI-Driven Vulnerability Analysis (Real-time)
4.4: Safe Exploit Testing and Verification
4.5: Recording Every Step – Evidence and Logging
4.6: Output Summary and Handoff to Next Stage
"""

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import yaml
from colorama import Fore, Style, init
from dotenv import load_dotenv
from pydantic import BaseModel

# Import our custom runners
from runners.data_preparer import DataPreparer
from runners.browser_scanner import BrowserScanner
from runners.api_scanner import APIScanner
from runners.network_scanner import NetworkScanner
from runners.ai_analyzer import AIAnalyzer
from runners.exploit_tester import ExploitTester
from runners.evidence_collector import EvidenceCollector
from runners.output_generator import OutputGenerator

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('vuln_test.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@dataclass
class TestConfig:
    """Configuration for Stage 4 vulnerability testing."""
    
    # Basic configuration
    target: str
    stage_name: str = "vuln_test"
    
    # AI Model configuration
    ai_model_path: str = "models/vulnerability_analyzer"
    ai_confidence_threshold: float = 0.8
    enable_ai_analysis: bool = True
    
    # Browser automation configuration
    enable_browser_scanning: bool = True
    browser_type: str = "playwright"  # selenium, playwright, puppeteer
    headless: bool = True
    screenshot_evidence: bool = True
    
    # API scanning configuration
    enable_api_scanning: bool = True
    api_fuzzing_enabled: bool = True
    openapi_import_enabled: bool = True
    
    # Network scanning configuration
    enable_network_scanning: bool = True
    port_scanning_enabled: bool = True
    service_detection_enabled: bool = True
    
    # Exploit testing configuration
    enable_exploit_testing: bool = True
    safe_exploit_mode: bool = True
    max_exploit_attempts: int = 3
    
    # Evidence collection configuration
    enable_evidence_collection: bool = True
    screenshot_quality: str = "high"
    video_recording: bool = False
    
    # Safety and ethical controls
    rate_limit: int = 10  # requests per second
    max_concurrent_tests: int = 5
    scope_boundaries: List[str] = field(default_factory=list)
    ethical_limits: Dict[str, Any] = field(default_factory=dict)
    
    # Output configuration
    output_formats: List[str] = field(default_factory=lambda: ["json", "yaml", "tfrecord"])
    enable_ml_training_export: bool = True


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding with all associated data."""
    
    id: str
    title: str
    description: str
    endpoint: str
    parameter: Optional[str] = None
    severity: str = "Medium"
    confidence: float = 0.0
    status: str = "Potential"  # Potential, Confirmed, False_Positive
    cwe_id: Optional[str] = None
    cve_references: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    
    # Technical details
    payload_used: Optional[str] = None
    evidence_files: List[str] = field(default_factory=list)
    extracted_data: Optional[str] = None
    error_messages: List[str] = field(default_factory=list)
    
    # AI analysis
    ai_confidence: float = 0.0
    ai_recommendations: List[str] = field(default_factory=list)
    suggested_exploits: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None
    remediation_advice: Optional[str] = None


class Stage4VulnerabilityTesting:
    """Main orchestrator for Stage 4: Vulnerability Scanning (Black-Box with AI Integration)."""
    
    def __init__(self, config: TestConfig):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.findings: List[VulnerabilityFinding] = []
        self.evidence_files: List[str] = []
        self.test_logs: List[Dict[str, Any]] = []
        
        # Initialize runners
        self.data_preparer = DataPreparer(config)
        self.browser_scanner = BrowserScanner(config)
        self.api_scanner = APIScanner(config)
        self.network_scanner = NetworkScanner(config)
        self.ai_analyzer = AIAnalyzer(config)
        self.exploit_tester = ExploitTester(config)
        self.evidence_collector = EvidenceCollector(config)
        self.output_generator = OutputGenerator(config)
        
        # Setup output directories
        self.setup_output_dirs()
        
    def setup_output_dirs(self):
        """Create necessary output directories."""
        directories = [
            "data_preparation",
            "browser_scanning",
            "api_scanning", 
            "network_scanning",
            "ai_analysis",
            "exploit_testing",
            "evidence_collection",
            "outputs",
            "logs",
            "screenshots",
            "videos",
            "reports"
        ]
        
        for directory in directories:
            (self.output_dir / directory).mkdir(parents=True, exist_ok=True)
            
        logger.info(f"Created output directories in {self.output_dir}")
    
    def run(self):
        """Execute the complete Stage 4 vulnerability testing workflow."""
        start_time = time.time()
        
        try:
            logger.info(f"{Fore.CYAN}Starting Stage 4: Vulnerability Scanning (Black-Box with AI Integration){Style.RESET_ALL}")
            logger.info(f"Target: {self.config.target}")
            logger.info(f"AI Integration: {'Enabled' if self.config.enable_ai_analysis else 'Disabled'}")
            
            # Step 4.1: Preparation and Input Data Formatting
            logger.info(f"{Fore.CYAN}Step 4.1: Preparation and Input Data Formatting{Style.RESET_ALL}")
            self.step1_preparation()
            
            # Step 4.2: Automated Black-Box Scanning
            logger.info(f"{Fore.CYAN}Step 4.2: Automated Black-Box Scanning with Browser and CLI Tools{Style.RESET_ALL}")
            self.step2_black_box_scanning()
            
            # Step 4.3: AI-Driven Vulnerability Analysis
            logger.info(f"{Fore.CYAN}Step 4.3: AI-Driven Vulnerability Analysis (Real-time){Style.RESET_ALL}")
            self.step3_ai_analysis()
            
            # Step 4.4: Safe Exploit Testing and Verification
            logger.info(f"{Fore.CYAN}Step 4.4: Safe Exploit Testing and Verification{Style.RESET_ALL}")
            self.step4_exploit_testing()
            
            # Step 4.5: Recording Every Step
            logger.info(f"{Fore.CYAN}Step 4.5: Recording Every Step – Evidence and Logging{Style.RESET_ALL}")
            self.step5_evidence_collection()
            
            # Step 4.6: Output Summary and Handoff
            logger.info(f"{Fore.CYAN}Step 4.6: Output Summary and Handoff to Next Stage{Style.RESET_ALL}")
            self.step6_output_generation()
            
            # Final summary
            elapsed_time = time.time() - start_time
            logger.info(f"{Fore.GREEN}Stage 4 completed successfully in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
            logger.info(f"Total findings: {len(self.findings)}")
            logger.info(f"Confirmed vulnerabilities: {len([f for f in self.findings if f.status == 'Confirmed'])}")
            
        except Exception as e:
            logger.error(f"{Fore.RED}Error in Stage 4 execution: {str(e)}{Style.RESET_ALL}")
            raise
    
    def step1_preparation(self):
        """Step 4.1: Preparation and Input Data Formatting."""
        try:
            logger.info("Starting data preparation and input formatting...")
            
            # Prepare reconnaissance data from previous stages
            recon_data = self.data_preparer.prepare_reconnaissance_data()
            
            # Structure input data for AI model consumption
            structured_data = self.data_preparer.structure_input_data(recon_data)
            
            # Initialize AI model
            if self.config.enable_ai_analysis:
                self.data_preparer.initialize_ai_model()
            
            # Setup output structures
            self.data_preparer.setup_output_structures()
            
            logger.info(f"Data preparation completed. Structured {len(structured_data.get('endpoints', []))} endpoints")
            
        except Exception as e:
            logger.error(f"Error in data preparation: {str(e)}")
            raise
    
    def step2_black_box_scanning(self):
        """Step 4.2: Automated Black-Box Scanning with Browser and CLI Tools."""
        try:
            logger.info("Starting comprehensive black-box scanning...")
            
            # Browser automation for web applications
            if self.config.enable_browser_scanning:
                logger.info("Running browser automation scanning...")
                browser_findings = self.browser_scanner.run_scan()
                self.findings.extend(browser_findings)
            
            # API endpoint scanning
            if self.config.enable_api_scanning:
                logger.info("Running API endpoint scanning...")
                api_findings = self.api_scanner.run_scan()
                self.findings.extend(api_findings)
            
            # Network and port scanning
            if self.config.enable_network_scanning:
                logger.info("Running network and port scanning...")
                network_findings = self.network_scanner.run_scan()
                self.findings.extend(network_findings)
            
            logger.info(f"Black-box scanning completed. Found {len(self.findings)} potential vulnerabilities")
            
        except Exception as e:
            logger.error(f"Error in black-box scanning: {str(e)}")
            raise
    
    def step3_ai_analysis(self):
        """Step 4.3: AI-Driven Vulnerability Analysis (Real-time)."""
        try:
            if not self.config.enable_ai_analysis:
                logger.info("AI analysis disabled, skipping...")
                return
                
            logger.info("Starting AI-driven vulnerability analysis...")
            
            # Correlate and classify findings
            classified_findings = self.ai_analyzer.correlate_and_classify(self.findings)
            
            # Reduce false positives
            filtered_findings = self.ai_analyzer.reduce_false_positives(classified_findings)
            
            # Risk scoring and prioritization
            scored_findings = self.ai_analyzer.score_and_prioritize(filtered_findings)
            
            # Map to standards (CWE/CVE)
            mapped_findings = self.ai_analyzer.map_to_standards(scored_findings)
            
            # Generate suggested exploits
            final_findings = self.ai_analyzer.generate_exploit_suggestions(mapped_findings)
            
            self.findings = final_findings
            
            logger.info(f"AI analysis completed. {len(self.findings)} vulnerabilities after AI filtering")
            
        except Exception as e:
            logger.error(f"Error in AI analysis: {str(e)}")
            raise
    
    def step4_exploit_testing(self):
        """Step 4.4: Safe Exploit Testing and Verification."""
        try:
            if not self.config.enable_exploit_testing:
                logger.info("Exploit testing disabled, skipping...")
                return
                
            logger.info("Starting safe exploit testing and verification...")
            
            # Test each vulnerability safely
            for finding in self.findings:
                if finding.status == "Potential":
                    logger.info(f"Testing vulnerability {finding.id}: {finding.title}")
                    
                    # Run safe exploit test
                    test_result = self.exploit_tester.test_vulnerability(finding)
                    
                    # Update finding status based on test result
                    if test_result.confirmed:
                        finding.status = "Confirmed"
                        finding.verified_at = datetime.now(timezone.utc)
                        finding.evidence_files.extend(test_result.evidence_files)
                        finding.extracted_data = test_result.extracted_data
                    else:
                        finding.status = "False_Positive"
            
            confirmed_count = len([f for f in self.findings if f.status == "Confirmed"])
            logger.info(f"Exploit testing completed. {confirmed_count} vulnerabilities confirmed")
            
        except Exception as e:
            logger.error(f"Error in exploit testing: {str(e)}")
            raise
    
    def step5_evidence_collection(self):
        """Step 4.5: Recording Every Step – Evidence and Logging."""
        try:
            if not self.config.enable_evidence_collection:
                logger.info("Evidence collection disabled, skipping...")
                return
                
            logger.info("Starting comprehensive evidence collection...")
            
            # Collect activity logs
            activity_logs = self.evidence_collector.collect_activity_logs()
            
            # Capture screenshots and videos
            if self.config.screenshot_evidence:
                screenshots = self.evidence_collector.capture_screenshots()
                self.evidence_files.extend(screenshots)
            
            # Capture response data
            response_data = self.evidence_collector.capture_response_data()
            
            # Organize and label evidence
            organized_evidence = self.evidence_collector.organize_evidence()
            
            logger.info(f"Evidence collection completed. {len(self.evidence_files)} evidence files collected")
            
        except Exception as e:
            logger.error(f"Error in evidence collection: {str(e)}")
            raise
    
    def step6_output_generation(self):
        """Step 4.6: Output Summary and Handoff to Next Stage."""
        try:
            logger.info("Generating comprehensive output and preparing Stage 5 handoff...")
            
            # Generate structured findings report
            structured_report = self.output_generator.generate_structured_report(self.findings)
            
            # Compile logs and artifacts
            compiled_logs = self.output_generator.compile_logs_and_artifacts()
            
            # Export training data for ML
            if self.config.enable_ml_training_export:
                training_data = self.output_generator.export_training_data(self.findings)
            
            # Generate stakeholder summary
            stakeholder_summary = self.output_generator.generate_stakeholder_summary(self.findings)
            
            # Prepare Stage 5 handoff
            stage5_package = self.output_generator.prepare_stage5_handoff(self.findings)
            
            logger.info("Output generation completed. Stage 5 handoff package prepared")
            
        except Exception as e:
            logger.error(f"Error in output generation: {str(e)}")
            raise


def main():
    """Main entry point for Stage 4 vulnerability testing."""
    parser = argparse.ArgumentParser(description="Stage 4: Vulnerability Scanning (Black-Box with AI Integration)")
    parser.add_argument("--target", required=True, help="Target domain or IP")
    parser.add_argument("--stage", default="vuln_test", help="Stage name")
    parser.add_argument("--ai-model", default="models/vulnerability_analyzer", help="Path to AI model")
    parser.add_argument("--ai-confidence", type=float, default=0.8, help="AI confidence threshold")
    parser.add_argument("--enable-ai", action="store_true", default=True, help="Enable AI analysis")
    parser.add_argument("--enable-browser", action="store_true", default=True, help="Enable browser scanning")
    parser.add_argument("--enable-api", action="store_true", default=True, help="Enable API scanning")
    parser.add_argument("--enable-network", action="store_true", default=True, help="Enable network scanning")
    parser.add_argument("--enable-exploit", action="store_true", default=True, help="Enable exploit testing")
    parser.add_argument("--enable-evidence", action="store_true", default=True, help="Enable evidence collection")
    parser.add_argument("--browser-type", default="playwright", choices=["selenium", "playwright", "puppeteer"], help="Browser automation type")
    parser.add_argument("--headless", action="store_true", default=True, help="Run browser in headless mode")
    parser.add_argument("--screenshots", action="store_true", default=True, help="Capture screenshots")
    parser.add_argument("--rate-limit", type=int, default=10, help="Rate limit (requests per second)")
    parser.add_argument("--max-concurrent", type=int, default=5, help="Maximum concurrent tests")
    parser.add_argument("--safe-mode", action="store_true", default=True, help="Enable safe exploit mode")
    parser.add_argument("--output-formats", nargs="+", default=["json", "yaml", "tfrecord"], help="Output formats")
    parser.add_argument("--ml-export", action="store_true", default=True, help="Enable ML training data export")
    
    args = parser.parse_args()
    
    # Load environment variables
    load_dotenv()
    
    # Create configuration
    config = TestConfig(
        target=args.target,
        stage_name=args.stage,
        ai_model_path=args.ai_model,
        ai_confidence_threshold=args.ai_confidence,
        enable_ai_analysis=args.enable_ai,
        enable_browser_scanning=args.enable_browser,
        browser_type=args.browser_type,
        headless=args.headless,
        screenshot_evidence=args.screenshots,
        enable_api_scanning=args.enable_api,
        enable_network_scanning=args.enable_network,
        enable_exploit_testing=args.enable_exploit,
        safe_exploit_mode=args.safe_mode,
        rate_limit=args.rate_limit,
        max_concurrent_tests=args.max_concurrent,
        enable_evidence_collection=args.enable_evidence,
        output_formats=args.output_formats,
        enable_ml_training_export=args.ml_export
    )
    
    # Run Stage 4 vulnerability testing
    stage4 = Stage4VulnerabilityTesting(config)
    stage4.run()


if __name__ == "__main__":
    main()
