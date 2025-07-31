#!/usr/bin/env python3
"""
Comprehensive Reporting and Remediation Planning Stage - Final Deliverable Generation

This stage consolidates all previous stage results into comprehensive reports,
remediation roadmaps, and stakeholder deliverables for the Bug Hunting Framework.

Phase 1: Data Consolidation and Analysis
Phase 2: Executive Report Generation
Phase 3: Technical Documentation Creation
Phase 4: Compliance Mapping and Assessment
Phase 5: Remediation Roadmap Development
Phase 6: Stakeholder Communication and Handoff

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from runners.data_consolidator import DataConsolidator
from runners.executive_report_generator import ExecutiveReportGenerator
from runners.technical_documentation import TechnicalDocumentation
from runners.compliance_mapper import ComplianceMapper
from runners.remediation_roadmap import RemediationRoadmap
from runners.stakeholder_communication import StakeholderCommunication

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('comprehensive_reporting.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class ComprehensiveReporting:
    """
    Main orchestrator for comprehensive reporting and remediation planning stage.
    
    This class coordinates the 6-phase methodology for generating comprehensive
    reports, remediation roadmaps, and stakeholder deliverables.
    """
    
    def __init__(self, target: str, stage: str = "comprehensive_reporting"):
        """
        Initialize the comprehensive reporting stage.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.start_time = datetime.now(timezone.utc)
        
        # Load environment variables
        load_dotenv()
        
        # Initialize output directories
        self.setup_output_dirs()
        
        # Initialize components
        self.data_consolidator = DataConsolidator(target, stage)
        self.executive_generator = ExecutiveReportGenerator(target, stage)
        self.technical_docs = TechnicalDocumentation(target, stage)
        self.compliance_mapper = ComplianceMapper(target, stage)
        self.remediation_roadmap = RemediationRoadmap(target, stage)
        self.stakeholder_comm = StakeholderCommunication(target, stage)
        
        # Results storage
        self.results = {
            "target": target,
            "stage": stage,
            "start_time": self.start_time.isoformat(),
            "phases": {},
            "summary": {}
        }
        
        logger.info(f"Initialized Comprehensive Reporting for target: {target}")
    
    def setup_output_dirs(self):
        """Create necessary output directories."""
        base_dir = Path(f"outputs/{self.stage}/{self.target}")
        
        # Create main directories
        directories = [
            base_dir,
            base_dir / "consolidated_data",
            base_dir / "executive_reports",
            base_dir / "technical_docs",
            base_dir / "compliance_assessment",
            base_dir / "remediation_roadmap",
            base_dir / "stakeholder_deliverables",
            base_dir / "presentations",
            base_dir / "final_deliverables"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Created output directories for {self.target}")
    
    async def run_phase_1(self) -> Dict[str, Any]:
        """
        Phase 1: Data Consolidation and Analysis
        
        - Consolidate data from all previous stages
        - Perform comprehensive analysis and correlation
        - Generate summary statistics and key findings
        """
        logger.info("Starting Phase 1: Data Consolidation and Analysis")
        phase_start = time.time()
        
        try:
            # Step 1: Consolidate data from all stages
            logger.info("Step 1.1: Consolidating data from all previous stages")
            consolidated_data = await self.data_consolidator.consolidate_all_data()
            
            # Step 2: Perform comprehensive analysis
            logger.info("Step 1.2: Performing comprehensive analysis and correlation")
            analysis_results = await self.data_consolidator.perform_comprehensive_analysis()
            
            # Step 3: Generate summary statistics
            logger.info("Step 1.3: Generating summary statistics and key findings")
            summary_stats = await self.data_consolidator.generate_summary_statistics()
            
            # Compile phase results
            phase_results = {
                "consolidated_data": consolidated_data,
                "analysis_results": analysis_results,
                "summary_statistics": summary_stats,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_1"] = phase_results
            logger.info(f"Phase 1 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 1: {str(e)}")
            raise
    
    async def run_phase_2(self) -> Dict[str, Any]:
        """
        Phase 2: Executive Report Generation
        
        - Generate executive summary reports
        - Create business impact analysis
        - Develop stakeholder presentations
        """
        logger.info("Starting Phase 2: Executive Report Generation")
        phase_start = time.time()
        
        try:
            # Step 1: Generate executive summary
            logger.info("Step 2.1: Generating executive summary report")
            executive_summary = await self.executive_generator.generate_executive_summary()
            
            # Step 2: Create business impact analysis
            logger.info("Step 2.2: Creating business impact analysis")
            business_impact = await self.executive_generator.analyze_business_impact()
            
            # Step 3: Develop stakeholder presentations
            logger.info("Step 2.3: Developing stakeholder presentations")
            presentations = await self.executive_generator.create_stakeholder_presentations()
            
            # Compile phase results
            phase_results = {
                "executive_summary": executive_summary,
                "business_impact": business_impact,
                "presentations": presentations,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_2"] = phase_results
            logger.info(f"Phase 2 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 2: {str(e)}")
            raise
    
    async def run_phase_3(self) -> Dict[str, Any]:
        """
        Phase 3: Technical Documentation Creation
        
        - Create detailed technical reports
        - Generate findings documentation
        - Develop technical deep-dive materials
        """
        logger.info("Starting Phase 3: Technical Documentation Creation")
        phase_start = time.time()
        
        try:
            # Step 1: Create detailed technical reports
            logger.info("Step 3.1: Creating detailed technical reports")
            technical_reports = await self.technical_docs.create_technical_reports()
            
            # Step 2: Generate findings documentation
            logger.info("Step 3.2: Generating findings documentation")
            findings_docs = await self.technical_docs.generate_findings_documentation()
            
            # Step 3: Develop technical deep-dive materials
            logger.info("Step 3.3: Developing technical deep-dive materials")
            deep_dive_materials = await self.technical_docs.create_deep_dive_materials()
            
            # Compile phase results
            phase_results = {
                "technical_reports": technical_reports,
                "findings_documentation": findings_docs,
                "deep_dive_materials": deep_dive_materials,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_3"] = phase_results
            logger.info(f"Phase 3 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 3: {str(e)}")
            raise
    
    async def run_phase_4(self) -> Dict[str, Any]:
        """
        Phase 4: Compliance Mapping and Assessment
        
        - Map findings to compliance frameworks
        - Assess regulatory impact
        - Generate compliance reports
        """
        logger.info("Starting Phase 4: Compliance Mapping and Assessment")
        phase_start = time.time()
        
        try:
            # Step 1: Map findings to compliance frameworks
            logger.info("Step 4.1: Mapping findings to compliance frameworks")
            compliance_mapping = await self.compliance_mapper.map_to_compliance_frameworks()
            
            # Step 2: Assess regulatory impact
            logger.info("Step 4.2: Assessing regulatory impact")
            regulatory_impact = await self.compliance_mapper.assess_regulatory_impact()
            
            # Step 3: Generate compliance reports
            logger.info("Step 4.3: Generating compliance reports")
            compliance_reports = await self.compliance_mapper.generate_compliance_reports()
            
            # Compile phase results
            phase_results = {
                "compliance_mapping": compliance_mapping,
                "regulatory_impact": regulatory_impact,
                "compliance_reports": compliance_reports,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_4"] = phase_results
            logger.info(f"Phase 4 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 4: {str(e)}")
            raise
    
    async def run_phase_5(self) -> Dict[str, Any]:
        """
        Phase 5: Remediation Roadmap Development
        
        - Create prioritized remediation roadmap
        - Develop implementation timelines
        - Generate resource requirements
        """
        logger.info("Starting Phase 5: Remediation Roadmap Development")
        phase_start = time.time()
        
        try:
            # Step 1: Create prioritized remediation roadmap
            logger.info("Step 5.1: Creating prioritized remediation roadmap")
            remediation_roadmap = await self.remediation_roadmap.create_prioritized_roadmap()
            
            # Step 2: Develop implementation timelines
            logger.info("Step 5.2: Developing implementation timelines")
            implementation_timelines = await self.remediation_roadmap.develop_implementation_timelines()
            
            # Step 3: Generate resource requirements
            logger.info("Step 5.3: Generating resource requirements")
            resource_requirements = await self.remediation_roadmap.generate_resource_requirements()
            
            # Compile phase results
            phase_results = {
                "remediation_roadmap": remediation_roadmap,
                "implementation_timelines": implementation_timelines,
                "resource_requirements": resource_requirements,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_5"] = phase_results
            logger.info(f"Phase 5 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 5: {str(e)}")
            raise
    
    async def run_phase_6(self) -> Dict[str, Any]:
        """
        Phase 6: Stakeholder Communication and Handoff
        
        - Create stakeholder communication materials
        - Develop handoff documentation
        - Package final deliverables
        """
        logger.info("Starting Phase 6: Stakeholder Communication and Handoff")
        phase_start = time.time()
        
        try:
            # Step 1: Create stakeholder communication materials
            logger.info("Step 6.1: Creating stakeholder communication materials")
            communication_materials = await self.stakeholder_comm.create_communication_materials()
            
            # Step 2: Develop handoff documentation
            logger.info("Step 6.2: Developing handoff documentation")
            handoff_docs = await self.stakeholder_comm.develop_handoff_documentation()
            
            # Step 3: Package final deliverables
            logger.info("Step 6.3: Packaging final deliverables")
            final_deliverables = await self.stakeholder_comm.package_final_deliverables()
            
            # Compile phase results
            phase_results = {
                "communication_materials": communication_materials,
                "handoff_documentation": handoff_docs,
                "final_deliverables": final_deliverables,
                "duration": time.time() - phase_start
            }
            
            self.results["phases"]["phase_6"] = phase_results
            logger.info(f"Phase 6 completed in {phase_results['duration']:.2f} seconds")
            
            return phase_results
            
        except Exception as e:
            logger.error(f"Error in Phase 6: {str(e)}")
            raise
    
    async def generate_summary(self):
        """Generate comprehensive summary of all phases."""
        logger.info("Generating comprehensive summary")
        
        end_time = datetime.now(timezone.utc)
        total_duration = (end_time - self.start_time).total_seconds()
        
        # Calculate summary statistics
        summary = {
            "target": self.target,
            "stage": self.stage,
            "start_time": self.start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "total_duration": total_duration,
            "phases_completed": len(self.results["phases"]),
            "status": "completed",
            "key_deliverables": {
                "executive_reports": 0,
                "technical_docs": 0,
                "compliance_reports": 0,
                "remediation_items": 0,
                "presentations": 0,
                "final_deliverables": 0
            }
        }
        
        # Extract key metrics from phases
        if "phase_2" in self.results["phases"]:
            exec_data = self.results["phases"]["phase_2"]
            summary["key_deliverables"]["executive_reports"] = exec_data.get("executive_summary", {}).get("reports_generated", 0)
            summary["key_deliverables"]["presentations"] = exec_data.get("presentations", {}).get("presentations_created", 0)
        
        if "phase_3" in self.results["phases"]:
            tech_data = self.results["phases"]["phase_3"]
            summary["key_deliverables"]["technical_docs"] = tech_data.get("technical_reports", {}).get("reports_generated", 0)
        
        if "phase_4" in self.results["phases"]:
            comp_data = self.results["phases"]["phase_4"]
            summary["key_deliverables"]["compliance_reports"] = comp_data.get("compliance_reports", {}).get("reports_generated", 0)
        
        if "phase_5" in self.results["phases"]:
            rem_data = self.results["phases"]["phase_5"]
            summary["key_deliverables"]["remediation_items"] = rem_data.get("remediation_roadmap", {}).get("remediation_items", 0)
        
        if "phase_6" in self.results["phases"]:
            final_data = self.results["phases"]["phase_6"]
            summary["key_deliverables"]["final_deliverables"] = final_data.get("final_deliverables", {}).get("packages_created", 0)
        
        self.results["summary"] = summary
        logger.info(f"Comprehensive reporting completed in {total_duration:.2f} seconds")
        
        return summary
    
    async def run_complete_reporting(self):
        """
        Run the complete 6-phase comprehensive reporting.
        
        Returns:
            Dict containing all results and summary
        """
        logger.info(f"Starting complete comprehensive reporting for target: {self.target}")
        
        try:
            # Run all phases
            await self.run_phase_1()
            await self.run_phase_2()
            await self.run_phase_3()
            await self.run_phase_4()
            await self.run_phase_5()
            await self.run_phase_6()
            
            # Generate final summary
            summary = await self.generate_summary()
            
            # Save results
            await self.save_results()
            
            logger.info("Comprehensive reporting completed successfully")
            return self.results
            
        except Exception as e:
            logger.error(f"Error in comprehensive reporting: {str(e)}")
            self.results["error"] = str(e)
            self.results["status"] = "failed"
            raise
    
    async def save_results(self):
        """Save all results to output files."""
        output_dir = Path(f"outputs/{self.stage}/{self.target}")
        
        # Save main results
        results_file = output_dir / "comprehensive_reporting_results.json"
        with open(results_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Save summary
        summary_file = output_dir / "summary.json"
        with open(summary_file, 'w') as f:
            json.dump(self.results["summary"], f, indent=2, default=str)
        
        logger.info(f"Results saved to {output_dir}")


async def main():
    """Main entry point for comprehensive reporting."""
    parser = argparse.ArgumentParser(description="Comprehensive Reporting and Remediation Planning Stage")
    parser.add_argument("--target", required=True, help="Target domain or organization")
    parser.add_argument("--stage", default="comprehensive_reporting", help="Stage name")
    parser.add_argument("--phase", type=int, choices=[1, 2, 3, 4, 5, 6], 
                        help="Run specific phase only")
    
    args = parser.parse_args()
    
    # Initialize comprehensive reporting
    comprehensive_reporting = ComprehensiveReporting(args.target, args.stage)
    
    try:
        if args.phase:
            # Run specific phase
            phase_methods = {
                1: comprehensive_reporting.run_phase_1,
                2: comprehensive_reporting.run_phase_2,
                3: comprehensive_reporting.run_phase_3,
                4: comprehensive_reporting.run_phase_4,
                5: comprehensive_reporting.run_phase_5,
                6: comprehensive_reporting.run_phase_6
            }
            
            logger.info(f"Running Phase {args.phase} only")
            await phase_methods[args.phase]()
            
        else:
            # Run complete reporting
            await comprehensive_reporting.run_complete_reporting()
        
        logger.info("Comprehensive reporting completed successfully")
        
    except Exception as e:
        logger.error(f"Comprehensive reporting failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main()) 