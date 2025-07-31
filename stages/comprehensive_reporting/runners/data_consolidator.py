#!/usr/bin/env python3
"""
Data Consolidator - Phase 1: Data Consolidation and Analysis

This module consolidates data from all previous stages (passive_recon, active_recon,
vuln_scan, vuln_test, kill_chain) and performs comprehensive analysis to prepare
for report generation and remediation planning.

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

import pandas as pd
import numpy as np
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ConsolidatedData(BaseModel):
    """Model for consolidated data from all stages."""
    
    target: str = Field(..., description="Target domain or organization")
    consolidation_date: str = Field(..., description="Date of data consolidation")
    stage_data: Dict[str, Any] = Field(..., description="Data from each stage")
    summary_statistics: Dict[str, Any] = Field(..., description="Summary statistics")
    key_findings: List[Dict[str, Any]] = Field(..., description="Key findings across stages")
    data_quality: Dict[str, Any] = Field(..., description="Data quality metrics")


class AnalysisResult(BaseModel):
    """Model for comprehensive analysis results."""
    
    vulnerability_analysis: Dict[str, Any] = Field(..., description="Vulnerability analysis")
    risk_assessment: Dict[str, Any] = Field(..., description="Risk assessment")
    attack_path_analysis: Dict[str, Any] = Field(..., description="Attack path analysis")
    business_impact: Dict[str, Any] = Field(..., description="Business impact analysis")
    compliance_gaps: Dict[str, Any] = Field(..., description="Compliance gaps identified")
    remediation_priorities: List[Dict[str, Any]] = Field(..., description="Remediation priorities")


class SummaryStatistics(BaseModel):
    """Model for summary statistics."""
    
    total_vulnerabilities: int = Field(..., description="Total number of vulnerabilities")
    critical_vulnerabilities: int = Field(..., description="Number of critical vulnerabilities")
    high_vulnerabilities: int = Field(..., description="Number of high vulnerabilities")
    medium_vulnerabilities: int = Field(..., description="Number of medium vulnerabilities")
    low_vulnerabilities: int = Field(..., description="Number of low vulnerabilities")
    attack_paths: int = Field(..., description="Number of attack paths identified")
    compliance_violations: int = Field(..., description="Number of compliance violations")
    business_impact_score: float = Field(..., description="Overall business impact score")
    risk_score: float = Field(..., description="Overall risk score")


class DataConsolidator:
    """
    Data consolidator for comprehensive reporting stage.
    
    This class consolidates data from all previous stages and performs
    comprehensive analysis to prepare for report generation.
    """
    
    def __init__(self, target: str, stage: str = "comprehensive_reporting"):
        """
        Initialize the data consolidator.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_output_dir = Path(f"outputs/{self.stage}/{self.target}")
        self.consolidated_data_dir = self.base_output_dir / "consolidated_data"
        
        # Ensure output directory exists
        self.consolidated_data_dir.mkdir(parents=True, exist_ok=True)
        
        # Stage directories to consolidate
        self.stage_dirs = [
            "passive_recon",
            "active_recon", 
            "vuln_scan",
            "vuln_test",
            "kill_chain"
        ]
        
        logger.info(f"Initialized DataConsolidator for target: {target}")
    
    async def consolidate_all_data(self) -> Dict[str, Any]:
        """
        Consolidate data from all previous stages.
        
        Returns:
            Dictionary containing consolidated data from all stages
        """
        logger.info("Starting data consolidation from all stages")
        
        consolidated_data = {
            "target": self.target,
            "consolidation_date": datetime.now(timezone.utc).isoformat(),
            "stage_data": {},
            "summary_statistics": {},
            "key_findings": [],
            "data_quality": {}
        }
        
        try:
            # Step 1: Load data from each stage
            for stage_dir in self.stage_dirs:
                stage_data = await self._load_stage_data(stage_dir)
                consolidated_data["stage_data"][stage_dir] = stage_data
            
            # Step 2: Perform data quality assessment
            data_quality = await self._assess_data_quality(consolidated_data["stage_data"])
            consolidated_data["data_quality"] = data_quality
            
            # Step 3: Extract key findings
            key_findings = await self._extract_key_findings(consolidated_data["stage_data"])
            consolidated_data["key_findings"] = key_findings
            
            # Step 4: Save consolidated data
            await self._save_consolidated_data(consolidated_data)
            
            logger.info(f"Data consolidation completed. Found data from {len(consolidated_data['stage_data'])} stages")
            
            return consolidated_data
            
        except Exception as e:
            logger.error(f"Error in data consolidation: {str(e)}")
            raise
    
    async def perform_comprehensive_analysis(self) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on consolidated data.
        
        Returns:
            Dictionary containing comprehensive analysis results
        """
        logger.info("Starting comprehensive analysis")
        
        try:
            # Load consolidated data
            consolidated_data = await self._load_consolidated_data()
            
            analysis_results = {
                "vulnerability_analysis": {},
                "risk_assessment": {},
                "attack_path_analysis": {},
                "business_impact": {},
                "compliance_gaps": {},
                "remediation_priorities": []
            }
            
            # Step 1: Vulnerability analysis
            vulnerability_analysis = await self._analyze_vulnerabilities(consolidated_data)
            analysis_results["vulnerability_analysis"] = vulnerability_analysis
            
            # Step 2: Risk assessment
            risk_assessment = await self._assess_risks(consolidated_data)
            analysis_results["risk_assessment"] = risk_assessment
            
            # Step 3: Attack path analysis
            attack_path_analysis = await self._analyze_attack_paths(consolidated_data)
            analysis_results["attack_path_analysis"] = attack_path_analysis
            
            # Step 4: Business impact analysis
            business_impact = await self._analyze_business_impact(consolidated_data)
            analysis_results["business_impact"] = business_impact
            
            # Step 5: Compliance gaps analysis
            compliance_gaps = await self._analyze_compliance_gaps(consolidated_data)
            analysis_results["compliance_gaps"] = compliance_gaps
            
            # Step 6: Remediation priorities
            remediation_priorities = await self._prioritize_remediation(consolidated_data)
            analysis_results["remediation_priorities"] = remediation_priorities
            
            # Save analysis results
            await self._save_analysis_results(analysis_results)
            
            logger.info("Comprehensive analysis completed")
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {str(e)}")
            raise
    
    async def generate_summary_statistics(self) -> Dict[str, Any]:
        """
        Generate summary statistics from consolidated data.
        
        Returns:
            Dictionary containing summary statistics
        """
        logger.info("Generating summary statistics")
        
        try:
            # Load consolidated data
            consolidated_data = await self._load_consolidated_data()
            
            # Calculate summary statistics
            summary_stats = {
                "total_vulnerabilities": 0,
                "critical_vulnerabilities": 0,
                "high_vulnerabilities": 0,
                "medium_vulnerabilities": 0,
                "low_vulnerabilities": 0,
                "attack_paths": 0,
                "compliance_violations": 0,
                "business_impact_score": 0.0,
                "risk_score": 0.0,
                "stage_coverage": {},
                "data_completeness": 0.0
            }
            
            # Extract vulnerability statistics
            if "vuln_scan" in consolidated_data["stage_data"]:
                vuln_data = consolidated_data["stage_data"]["vuln_scan"]
                summary_stats.update(await self._calculate_vulnerability_stats(vuln_data))
            
            # Extract attack path statistics
            if "kill_chain" in consolidated_data["stage_data"]:
                kill_chain_data = consolidated_data["stage_data"]["kill_chain"]
                summary_stats.update(await self._calculate_attack_path_stats(kill_chain_data))
            
            # Calculate stage coverage
            summary_stats["stage_coverage"] = await self._calculate_stage_coverage(consolidated_data["stage_data"])
            
            # Calculate data completeness
            summary_stats["data_completeness"] = await self._calculate_data_completeness(consolidated_data)
            
            # Calculate overall scores
            summary_stats["business_impact_score"] = await self._calculate_business_impact_score(consolidated_data)
            summary_stats["risk_score"] = await self._calculate_risk_score(consolidated_data)
            
            # Save summary statistics
            await self._save_summary_statistics(summary_stats)
            
            logger.info("Summary statistics generated")
            
            return summary_stats
            
        except Exception as e:
            logger.error(f"Error generating summary statistics: {str(e)}")
            raise
    
    async def _load_stage_data(self, stage_dir: str) -> Dict[str, Any]:
        """Load data from a specific stage directory."""
        stage_path = Path(f"outputs/{stage_dir}/{self.target}")
        
        if not stage_path.exists():
            logger.warning(f"Stage directory not found: {stage_path}")
            return {"status": "not_found", "data": {}}
        
        stage_data = {
            "status": "found",
            "data": {},
            "files": [],
            "metadata": {}
        }
        
        try:
            # Look for common output files
            common_files = [
                "results.json",
                "summary.json", 
                "findings.json",
                "vulnerabilities.json",
                "attack_paths.json",
                "scenarios.json"
            ]
            
            for file_name in common_files:
                file_path = stage_path / file_name
                if file_path.exists():
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        stage_data["data"][file_name] = data
                        stage_data["files"].append(file_name)
            
            # Look for parsed data directories
            parsed_dirs = ["parsed", "processed", "analysis"]
            for parsed_dir in parsed_dirs:
                parsed_path = stage_path / parsed_dir
                if parsed_path.exists():
                    parsed_data = await self._load_parsed_data(parsed_path)
                    stage_data["data"][parsed_dir] = parsed_data
            
            # Extract metadata
            stage_data["metadata"] = {
                "last_modified": self._get_last_modified(stage_path),
                "file_count": len(stage_data["files"]),
                "data_size": self._calculate_data_size(stage_data["data"])
            }
            
            logger.info(f"Loaded data from {stage_dir}: {len(stage_data['files'])} files")
            
        except Exception as e:
            logger.error(f"Error loading data from {stage_dir}: {str(e)}")
            stage_data["status"] = "error"
            stage_data["error"] = str(e)
        
        return stage_data
    
    async def _load_parsed_data(self, parsed_path: Path) -> Dict[str, Any]:
        """Load parsed data from a directory."""
        parsed_data = {}
        
        try:
            for file_path in parsed_path.rglob("*.json"):
                relative_path = file_path.relative_to(parsed_path)
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    parsed_data[str(relative_path)] = data
        except Exception as e:
            logger.error(f"Error loading parsed data from {parsed_path}: {str(e)}")
        
        return parsed_data
    
    async def _assess_data_quality(self, stage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the quality of consolidated data."""
        data_quality = {
            "overall_score": 0.0,
            "stage_scores": {},
            "completeness": {},
            "consistency": {},
            "issues": []
        }
        
        total_score = 0.0
        stage_count = 0
        
        for stage_name, stage_info in stage_data.items():
            if stage_info.get("status") == "found":
                stage_score = await self._calculate_stage_quality_score(stage_info)
                data_quality["stage_scores"][stage_name] = stage_score
                total_score += stage_score
                stage_count += 1
                
                # Check completeness
                completeness = await self._check_stage_completeness(stage_name, stage_info)
                data_quality["completeness"][stage_name] = completeness
                
                # Check consistency
                consistency = await self._check_stage_consistency(stage_name, stage_info)
                data_quality["consistency"][stage_name] = consistency
        
        if stage_count > 0:
            data_quality["overall_score"] = total_score / stage_count
        
        return data_quality
    
    async def _extract_key_findings(self, stage_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract key findings from all stages."""
        key_findings = []
        
        try:
            # Extract vulnerability findings
            if "vuln_scan" in stage_data and stage_data["vuln_scan"]["status"] == "found":
                vuln_findings = await self._extract_vulnerability_findings(stage_data["vuln_scan"])
                key_findings.extend(vuln_findings)
            
            # Extract attack path findings
            if "kill_chain" in stage_data and stage_data["kill_chain"]["status"] == "found":
                attack_findings = await self._extract_attack_findings(stage_data["kill_chain"])
                key_findings.extend(attack_findings)
            
            # Extract reconnaissance findings
            if "passive_recon" in stage_data and stage_data["passive_recon"]["status"] == "found":
                recon_findings = await self._extract_recon_findings(stage_data["passive_recon"])
                key_findings.extend(recon_findings)
            
            # Sort findings by severity
            key_findings.sort(key=lambda x: x.get("severity_score", 0), reverse=True)
            
            logger.info(f"Extracted {len(key_findings)} key findings")
            
        except Exception as e:
            logger.error(f"Error extracting key findings: {str(e)}")
        
        return key_findings
    
    async def _analyze_vulnerabilities(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze vulnerabilities from consolidated data."""
        vulnerability_analysis = {
            "total_count": 0,
            "by_severity": {},
            "by_category": {},
            "by_technology": {},
            "trends": {},
            "critical_paths": []
        }
        
        try:
            if "vuln_scan" in consolidated_data["stage_data"]:
                vuln_data = consolidated_data["stage_data"]["vuln_scan"]
                vulnerability_analysis = await self._process_vulnerability_data(vuln_data)
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerabilities: {str(e)}")
        
        return vulnerability_analysis
    
    async def _assess_risks(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risks from consolidated data."""
        risk_assessment = {
            "overall_risk_score": 0.0,
            "risk_categories": {},
            "risk_factors": {},
            "mitigation_priorities": []
        }
        
        try:
            # Calculate overall risk score
            risk_assessment["overall_risk_score"] = await self._calculate_overall_risk_score(consolidated_data)
            
            # Assess risk categories
            risk_assessment["risk_categories"] = await self._assess_risk_categories(consolidated_data)
            
            # Identify risk factors
            risk_assessment["risk_factors"] = await self._identify_risk_factors(consolidated_data)
            
            # Prioritize mitigations
            risk_assessment["mitigation_priorities"] = await self._prioritize_mitigations(consolidated_data)
            
        except Exception as e:
            logger.error(f"Error assessing risks: {str(e)}")
        
        return risk_assessment
    
    async def _analyze_attack_paths(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze attack paths from consolidated data."""
        attack_path_analysis = {
            "total_paths": 0,
            "critical_paths": 0,
            "path_complexity": {},
            "attack_scenarios": [],
            "threat_actors": []
        }
        
        try:
            if "kill_chain" in consolidated_data["stage_data"]:
                kill_chain_data = consolidated_data["stage_data"]["kill_chain"]
                attack_path_analysis = await self._process_attack_path_data(kill_chain_data)
            
        except Exception as e:
            logger.error(f"Error analyzing attack paths: {str(e)}")
        
        return attack_path_analysis
    
    async def _analyze_business_impact(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze business impact from consolidated data."""
        business_impact = {
            "financial_impact": {},
            "operational_impact": {},
            "reputation_impact": {},
            "compliance_impact": {},
            "overall_impact_score": 0.0
        }
        
        try:
            # Calculate financial impact
            business_impact["financial_impact"] = await self._calculate_financial_impact(consolidated_data)
            
            # Calculate operational impact
            business_impact["operational_impact"] = await self._calculate_operational_impact(consolidated_data)
            
            # Calculate reputation impact
            business_impact["reputation_impact"] = await self._calculate_reputation_impact(consolidated_data)
            
            # Calculate compliance impact
            business_impact["compliance_impact"] = await self._calculate_compliance_impact(consolidated_data)
            
            # Calculate overall impact score
            business_impact["overall_impact_score"] = await self._calculate_overall_impact_score(business_impact)
            
        except Exception as e:
            logger.error(f"Error analyzing business impact: {str(e)}")
        
        return business_impact
    
    async def _analyze_compliance_gaps(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance gaps from consolidated data."""
        compliance_gaps = {
            "frameworks": {},
            "violations": [],
            "gaps": [],
            "recommendations": []
        }
        
        try:
            # Analyze compliance frameworks
            compliance_gaps["frameworks"] = await self._analyze_compliance_frameworks(consolidated_data)
            
            # Identify violations
            compliance_gaps["violations"] = await self._identify_compliance_violations(consolidated_data)
            
            # Identify gaps
            compliance_gaps["gaps"] = await self._identify_compliance_gaps(consolidated_data)
            
            # Generate recommendations
            compliance_gaps["recommendations"] = await self._generate_compliance_recommendations(consolidated_data)
            
        except Exception as e:
            logger.error(f"Error analyzing compliance gaps: {str(e)}")
        
        return compliance_gaps
    
    async def _prioritize_remediation(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize remediation items from consolidated data."""
        remediation_priorities = []
        
        try:
            # Extract all remediation items
            all_items = await self._extract_remediation_items(consolidated_data)
            
            # Score and prioritize items
            scored_items = await self._score_remediation_items(all_items)
            
            # Sort by priority
            remediation_priorities = sorted(scored_items, key=lambda x: x.get("priority_score", 0), reverse=True)
            
            logger.info(f"Prioritized {len(remediation_priorities)} remediation items")
            
        except Exception as e:
            logger.error(f"Error prioritizing remediation: {str(e)}")
        
        return remediation_priorities
    
    # Helper methods for data processing
    async def _calculate_vulnerability_stats(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate vulnerability statistics."""
        stats = {
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "medium_vulnerabilities": 0,
            "low_vulnerabilities": 0
        }
        
        try:
            # Extract vulnerability counts from data
            if "findings.json" in vuln_data.get("data", {}):
                findings = vuln_data["data"]["findings.json"]
                stats["total_vulnerabilities"] = len(findings.get("vulnerabilities", []))
                
                for vuln in findings.get("vulnerabilities", []):
                    severity = vuln.get("severity", "medium").lower()
                    if severity == "critical":
                        stats["critical_vulnerabilities"] += 1
                    elif severity == "high":
                        stats["high_vulnerabilities"] += 1
                    elif severity == "medium":
                        stats["medium_vulnerabilities"] += 1
                    elif severity == "low":
                        stats["low_vulnerabilities"] += 1
            
        except Exception as e:
            logger.error(f"Error calculating vulnerability stats: {str(e)}")
        
        return stats
    
    async def _calculate_attack_path_stats(self, kill_chain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate attack path statistics."""
        stats = {
            "attack_paths": 0,
            "compliance_violations": 0
        }
        
        try:
            if "attack_paths.json" in kill_chain_data.get("data", {}):
                attack_paths = kill_chain_data["data"]["attack_paths.json"]
                stats["attack_paths"] = len(attack_paths.get("attack_paths", []))
            
            if "scenarios.json" in kill_chain_data.get("data", {}):
                scenarios = kill_chain_data["data"]["scenarios.json"]
                stats["compliance_violations"] = len(scenarios.get("compliance_violations", []))
            
        except Exception as e:
            logger.error(f"Error calculating attack path stats: {str(e)}")
        
        return stats
    
    async def _calculate_stage_coverage(self, stage_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate stage coverage metrics."""
        coverage = {}
        
        for stage_name, stage_info in stage_data.items():
            if stage_info.get("status") == "found":
                coverage[stage_name] = {
                    "status": "completed",
                    "file_count": stage_info.get("metadata", {}).get("file_count", 0),
                    "data_size": stage_info.get("metadata", {}).get("data_size", 0)
                }
            else:
                coverage[stage_name] = {
                    "status": "missing",
                    "file_count": 0,
                    "data_size": 0
                }
        
        return coverage
    
    async def _calculate_data_completeness(self, consolidated_data: Dict[str, Any]) -> float:
        """Calculate data completeness score."""
        total_stages = len(self.stage_dirs)
        completed_stages = 0
        
        for stage_name in self.stage_dirs:
            if stage_name in consolidated_data["stage_data"]:
                stage_info = consolidated_data["stage_data"][stage_name]
                if stage_info.get("status") == "found" and stage_info.get("files"):
                    completed_stages += 1
        
        return (completed_stages / total_stages) * 100.0 if total_stages > 0 else 0.0
    
    async def _calculate_business_impact_score(self, consolidated_data: Dict[str, Any]) -> float:
        """Calculate business impact score."""
        # Simplified calculation based on vulnerability severity and count
        impact_score = 0.0
        
        try:
            if "vuln_scan" in consolidated_data["stage_data"]:
                vuln_data = consolidated_data["stage_data"]["vuln_scan"]
                if "findings.json" in vuln_data.get("data", {}):
                    findings = vuln_data["data"]["findings.json"]
                    
                    for vuln in findings.get("vulnerabilities", []):
                        severity = vuln.get("severity", "medium").lower()
                        if severity == "critical":
                            impact_score += 10.0
                        elif severity == "high":
                            impact_score += 7.0
                        elif severity == "medium":
                            impact_score += 4.0
                        elif severity == "low":
                            impact_score += 1.0
            
            # Normalize score (0-100)
            impact_score = min(impact_score, 100.0)
            
        except Exception as e:
            logger.error(f"Error calculating business impact score: {str(e)}")
        
        return impact_score
    
    async def _calculate_risk_score(self, consolidated_data: Dict[str, Any]) -> float:
        """Calculate overall risk score."""
        # Simplified calculation based on vulnerabilities and attack paths
        risk_score = 0.0
        
        try:
            # Base risk from vulnerabilities
            if "vuln_scan" in consolidated_data["stage_data"]:
                vuln_data = consolidated_data["stage_data"]["vuln_scan"]
                if "findings.json" in vuln_data.get("data", {}):
                    findings = vuln_data["data"]["findings.json"]
                    
                    for vuln in findings.get("vulnerabilities", []):
                        severity = vuln.get("severity", "medium").lower()
                        if severity == "critical":
                            risk_score += 8.0
                        elif severity == "high":
                            risk_score += 6.0
                        elif severity == "medium":
                            risk_score += 4.0
                        elif severity == "low":
                            risk_score += 2.0
            
            # Additional risk from attack paths
            if "kill_chain" in consolidated_data["stage_data"]:
                kill_chain_data = consolidated_data["stage_data"]["kill_chain"]
                if "attack_paths.json" in kill_chain_data.get("data", {}):
                    attack_paths = kill_chain_data["data"]["attack_paths.json"]
                    risk_score += len(attack_paths.get("attack_paths", [])) * 2.0
            
            # Normalize score (0-100)
            risk_score = min(risk_score, 100.0)
            
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
        
        return risk_score
    
    # File operations
    async def _save_consolidated_data(self, consolidated_data: Dict[str, Any]):
        """Save consolidated data to file."""
        output_file = self.consolidated_data_dir / "consolidated_data.json"
        with open(output_file, 'w') as f:
            json.dump(consolidated_data, f, indent=2, default=str)
        
        logger.info(f"Consolidated data saved to {output_file}")
    
    async def _load_consolidated_data(self) -> Dict[str, Any]:
        """Load consolidated data from file."""
        input_file = self.consolidated_data_dir / "consolidated_data.json"
        
        if not input_file.exists():
            raise FileNotFoundError(f"Consolidated data file not found: {input_file}")
        
        with open(input_file, 'r') as f:
            return json.load(f)
    
    async def _save_analysis_results(self, analysis_results: Dict[str, Any]):
        """Save analysis results to file."""
        output_file = self.consolidated_data_dir / "analysis_results.json"
        with open(output_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)
        
        logger.info(f"Analysis results saved to {output_file}")
    
    async def _save_summary_statistics(self, summary_stats: Dict[str, Any]):
        """Save summary statistics to file."""
        output_file = self.consolidated_data_dir / "summary_statistics.json"
        with open(output_file, 'w') as f:
            json.dump(summary_stats, f, indent=2, default=str)
        
        logger.info(f"Summary statistics saved to {output_file}")
    
    # Utility methods
    def _get_last_modified(self, path: Path) -> str:
        """Get last modified time of a directory."""
        try:
            mtime = max(f.stat().st_mtime for f in path.rglob("*") if f.is_file())
            return datetime.fromtimestamp(mtime, timezone.utc).isoformat()
        except Exception:
            return datetime.now(timezone.utc).isoformat()
    
    def _calculate_data_size(self, data: Dict[str, Any]) -> int:
        """Calculate approximate data size in bytes."""
        try:
            return len(json.dumps(data, default=str))
        except Exception:
            return 0
    
    # Placeholder methods for complex analysis (to be implemented based on specific needs)
    async def _calculate_stage_quality_score(self, stage_info: Dict[str, Any]) -> float:
        """Calculate quality score for a stage."""
        # Simplified quality scoring
        if stage_info.get("status") == "found" and stage_info.get("files"):
            return 85.0  # Good quality
        elif stage_info.get("status") == "found":
            return 60.0  # Basic quality
        else:
            return 0.0  # No data
    
    async def _check_stage_completeness(self, stage_name: str, stage_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check completeness of stage data."""
        return {
            "status": "complete" if stage_info.get("files") else "incomplete",
            "files_found": len(stage_info.get("files", [])),
            "expected_files": 3  # Simplified expectation
        }
    
    async def _check_stage_consistency(self, stage_name: str, stage_info: Dict[str, Any]) -> Dict[str, Any]:
        """Check consistency of stage data."""
        return {
            "status": "consistent",
            "issues": []
        }
    
    # Additional placeholder methods for comprehensive analysis
    async def _extract_vulnerability_findings(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract vulnerability findings."""
        findings = []
        try:
            if "findings.json" in vuln_data.get("data", {}):
                data = vuln_data["data"]["findings.json"]
                for vuln in data.get("vulnerabilities", []):
                    findings.append({
                        "type": "vulnerability",
                        "title": vuln.get("title", "Unknown"),
                        "severity": vuln.get("severity", "medium"),
                        "severity_score": self._severity_to_score(vuln.get("severity", "medium")),
                        "description": vuln.get("description", ""),
                        "source": "vuln_scan"
                    })
        except Exception as e:
            logger.error(f"Error extracting vulnerability findings: {str(e)}")
        
        return findings
    
    async def _extract_attack_findings(self, kill_chain_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract attack findings."""
        findings = []
        try:
            if "attack_paths.json" in kill_chain_data.get("data", {}):
                data = kill_chain_data["data"]["attack_paths.json"]
                for path in data.get("attack_paths", []):
                    findings.append({
                        "type": "attack_path",
                        "title": path.get("name", "Unknown Attack Path"),
                        "severity": "high",
                        "severity_score": 8.0,
                        "description": f"Attack path with {len(path.get('techniques', []))} techniques",
                        "source": "kill_chain"
                    })
        except Exception as e:
            logger.error(f"Error extracting attack findings: {str(e)}")
        
        return findings
    
    async def _extract_recon_findings(self, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract reconnaissance findings."""
        findings = []
        try:
            if "parsed" in recon_data.get("data", {}):
                parsed_data = recon_data["data"]["parsed"]
                for tool, data in parsed_data.items():
                    if isinstance(data, dict) and "subdomains" in data:
                        findings.append({
                            "type": "reconnaissance",
                            "title": f"Subdomain Discovery via {tool}",
                            "severity": "low",
                            "severity_score": 2.0,
                            "description": f"Found {len(data['subdomains'])} subdomains",
                            "source": "passive_recon"
                        })
        except Exception as e:
            logger.error(f"Error extracting recon findings: {str(e)}")
        
        return findings
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity string to numeric score."""
        severity_map = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 2.0
        }
        return severity_map.get(severity.lower(), 5.0)
    
    # Additional placeholder methods for analysis components
    async def _process_vulnerability_data(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process vulnerability data for analysis."""
        return {
            "total_count": 0,
            "by_severity": {},
            "by_category": {},
            "by_technology": {},
            "trends": {},
            "critical_paths": []
        }
    
    async def _calculate_overall_risk_score(self, consolidated_data: Dict[str, Any]) -> float:
        """Calculate overall risk score."""
        return 50.0  # Placeholder
    
    async def _assess_risk_categories(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk categories."""
        return {}
    
    async def _identify_risk_factors(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Identify risk factors."""
        return {}
    
    async def _prioritize_mitigations(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize mitigations."""
        return []
    
    async def _process_attack_path_data(self, kill_chain_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process attack path data for analysis."""
        return {
            "total_paths": 0,
            "critical_paths": 0,
            "path_complexity": {},
            "attack_scenarios": [],
            "threat_actors": []
        }
    
    async def _calculate_financial_impact(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate financial impact."""
        return {}
    
    async def _calculate_operational_impact(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate operational impact."""
        return {}
    
    async def _calculate_reputation_impact(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate reputation impact."""
        return {}
    
    async def _calculate_compliance_impact(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate compliance impact."""
        return {}
    
    async def _calculate_overall_impact_score(self, business_impact: Dict[str, Any]) -> float:
        """Calculate overall impact score."""
        return 50.0  # Placeholder
    
    async def _analyze_compliance_frameworks(self, consolidated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze compliance frameworks."""
        return {}
    
    async def _identify_compliance_violations(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify compliance violations."""
        return []
    
    async def _identify_compliance_gaps(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify compliance gaps."""
        return []
    
    async def _generate_compliance_recommendations(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate compliance recommendations."""
        return []
    
    async def _extract_remediation_items(self, consolidated_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract remediation items."""
        return []
    
    async def _score_remediation_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Score remediation items."""
        return items 