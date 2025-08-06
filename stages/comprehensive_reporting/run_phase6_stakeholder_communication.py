#!/usr/bin/env python3
"""
Phase 6 - Stakeholder Communication Runner
Final deliverable generation and stakeholder handoff

This script runs Phase 6 of the comprehensive reporting stage, focusing on:
- Creating stakeholder communication materials
- Developing handoff documentation  
- Packaging final deliverables

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
from runners.stakeholder_communication import StakeholderCommunication

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phase6_stakeholder_communication.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class Phase6StakeholderCommunicationRunner:
    """
    Dedicated runner for Phase 6 - Stakeholder Communication and Handoff.
    
    This class orchestrates the final phase of comprehensive reporting,
    focusing on stakeholder communication, handoff documentation, and
    final deliverable packaging.
    """
    
    def __init__(self, target: str, stage: str = "comprehensive_reporting"):
        """
        Initialize the Phase 6 runner.
        
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
        
        # Initialize stakeholder communication component
        self.stakeholder_comm = StakeholderCommunication(target, stage)
        
        # Results storage
        self.results = {
            "target": target,
            "stage": stage,
            "phase": "phase_6",
            "start_time": self.start_time.isoformat(),
            "steps": {},
            "summary": {}
        }
        
        logger.info(f"Initialized Phase 6 - Stakeholder Communication for target: {target}")
    
    def setup_output_dirs(self):
        """Create necessary output directories."""
        base_dir = Path(f"outputs/{self.stage}/{self.target}")
        base_dir.mkdir(parents=True, exist_ok=True)
        
        # Create phase-specific directories
        phase_dir = base_dir / "phase_6"
        phase_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (phase_dir / "communication_materials").mkdir(exist_ok=True)
        (phase_dir / "handoff_documentation").mkdir(exist_ok=True)
        (phase_dir / "final_deliverables").mkdir(exist_ok=True)
        (phase_dir / "logs").mkdir(exist_ok=True)
        
        logger.info(f"Created output directories for Phase 6")
    
    async def run_step_1_communication_materials(self) -> Dict[str, Any]:
        """
        Step 6.1: Create stakeholder communication materials.
        
        Returns:
            Dict containing communication materials results
        """
        logger.info("Starting Step 6.1: Creating stakeholder communication materials")
        step_start = time.time()
        
        try:
            # Create communication materials
            communication_materials = await self.stakeholder_comm.create_communication_materials()
            
            # Save step results
            step_results = {
                "communication_materials": communication_materials,
                "duration": time.time() - step_start,
                "status": "completed"
            }
            
            self.results["steps"]["step_6_1"] = step_results
            logger.info(f"Step 6.1 completed in {step_results['duration']:.2f} seconds")
            
            return step_results
            
        except Exception as e:
            logger.error(f"Error in Step 6.1: {str(e)}")
            raise
    
    async def run_step_2_handoff_documentation(self) -> Dict[str, Any]:
        """
        Step 6.2: Develop handoff documentation.
        
        Returns:
            Dict containing handoff documentation results
        """
        logger.info("Starting Step 6.2: Developing handoff documentation")
        step_start = time.time()
        
        try:
            # Develop handoff documentation
            handoff_docs = await self.stakeholder_comm.develop_handoff_documentation()
            
            # Save step results
            step_results = {
                "handoff_documentation": handoff_docs,
                "duration": time.time() - step_start,
                "status": "completed"
            }
            
            self.results["steps"]["step_6_2"] = step_results
            logger.info(f"Step 6.2 completed in {step_results['duration']:.2f} seconds")
            
            return step_results
            
        except Exception as e:
            logger.error(f"Error in Step 6.2: {str(e)}")
            raise
    
    async def run_step_3_final_deliverables(self) -> Dict[str, Any]:
        """
        Step 6.3: Package final deliverables.
        
        Returns:
            Dict containing final deliverables results
        """
        logger.info("Starting Step 6.3: Packaging final deliverables")
        step_start = time.time()
        
        try:
            # Package final deliverables
            final_deliverables = await self.stakeholder_comm.package_final_deliverables()
            
            # Save step results
            step_results = {
                "final_deliverables": final_deliverables,
                "duration": time.time() - step_start,
                "status": "completed"
            }
            
            self.results["steps"]["step_6_3"] = step_results
            logger.info(f"Step 6.3 completed in {step_results['duration']:.2f} seconds")
            
            return step_results
            
        except Exception as e:
            logger.error(f"Error in Step 6.3: {str(e)}")
            raise
    
    async def generate_phase_summary(self):
        """Generate comprehensive summary of Phase 6."""
        logger.info("Generating Phase 6 summary")
        
        end_time = datetime.now(timezone.utc)
        total_duration = (end_time - self.start_time).total_seconds()
        
        # Calculate summary statistics
        summary = {
            "target": self.target,
            "stage": self.stage,
            "phase": "phase_6",
            "phase_name": "Stakeholder Communication and Handoff",
            "start_time": self.start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "total_duration": total_duration,
            "steps_completed": len(self.results["steps"]),
            "status": "completed",
            "key_deliverables": {
                "communication_materials": 0,
                "handoff_documents": 0,
                "final_packages": 0
            }
        }
        
        # Extract key metrics from steps
        if "step_6_1" in self.results["steps"]:
            comm_data = self.results["steps"]["step_6_1"]
            summary["key_deliverables"]["communication_materials"] = comm_data.get("communication_materials", {}).get("materials_created", 0)
        
        if "step_6_2" in self.results["steps"]:
            handoff_data = self.results["steps"]["step_6_2"]
            summary["key_deliverables"]["handoff_documents"] = handoff_data.get("handoff_documentation", {}).get("documents_created", 0)
        
        if "step_6_3" in self.results["steps"]:
            final_data = self.results["steps"]["step_6_3"]
            summary["key_deliverables"]["final_packages"] = final_data.get("final_deliverables", {}).get("packages_created", 0)
        
        self.results["summary"] = summary
        logger.info(f"Phase 6 completed in {total_duration:.2f} seconds")
        
        return summary
    
    async def run_phase_6(self):
        """
        Run the complete Phase 6 - Stakeholder Communication and Handoff.
        
        Returns:
            Dict containing all results and summary
        """
        logger.info("Starting Phase 6 - Stakeholder Communication and Handoff")
        
        try:
            # Step 6.1: Create stakeholder communication materials
            await self.run_step_1_communication_materials()
            
            # Step 6.2: Develop handoff documentation
            await self.run_step_2_handoff_documentation()
            
            # Step 6.3: Package final deliverables
            await self.run_step_3_final_deliverables()
            
            # Generate summary
            await self.generate_phase_summary()
            
            # Save results
            await self.save_results()
            
            logger.info("Phase 6 - Stakeholder Communication and Handoff completed successfully")
            return self.results
            
        except Exception as e:
            logger.error(f"Error in Phase 6: {str(e)}")
            raise
    
    async def save_results(self):
        """Save results to output directory."""
        output_file = Path(f"outputs/{self.stage}/{self.target}/phase_6/phase_6_results.json")
        
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        logger.info(f"Results saved to {output_file}")


async def main():
    """Main entry point for Phase 6 runner."""
    parser = argparse.ArgumentParser(description="Phase 6 - Stakeholder Communication Runner")
    parser.add_argument("--target", required=True, help="Target domain or organization name")
    parser.add_argument("--stage", default="comprehensive_reporting", help="Stage name for output organization")
    parser.add_argument("--phase-only", action="store_true", help="Run only Phase 6 (not full comprehensive reporting)")
    
    args = parser.parse_args()
    
    try:
        # Initialize and run Phase 6
        runner = Phase6StakeholderCommunicationRunner(args.target, args.stage)
        results = await runner.run_phase_6()
        
        # Print summary
        summary = results["summary"]
        print(f"\n{'='*60}")
        print(f"PHASE 6 - STAKEHOLDER COMMUNICATION COMPLETED")
        print(f"{'='*60}")
        print(f"Target: {summary['target']}")
        print(f"Duration: {summary['total_duration']:.2f} seconds")
        print(f"Steps Completed: {summary['steps_completed']}")
        print(f"Communication Materials: {summary['key_deliverables']['communication_materials']}")
        print(f"Handoff Documents: {summary['key_deliverables']['handoff_documents']}")
        print(f"Final Packages: {summary['key_deliverables']['final_packages']}")
        print(f"{'='*60}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Phase 6 runner failed: {str(e)}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code) 