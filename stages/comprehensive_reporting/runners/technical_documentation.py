#!/usr/bin/env python3
"""
Technical Documentation - Phase 3: Technical Documentation Creation

This module creates detailed technical reports, findings documentation,
and technical deep-dive materials for the comprehensive reporting stage.

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import pandas as pd
import numpy as np
from pydantic import BaseModel, Field
from jinja2 import Environment, FileSystemLoader, Template

logger = logging.getLogger(__name__)


class TechnicalReport(BaseModel):
    """Model for technical report."""
    
    report_id: str = Field(..., description="Unique report identifier")
    title: str = Field(..., description="Report title")
    target: str = Field(..., description="Target organization")
    report_date: str = Field(..., description="Report generation date")
    executive_summary: str = Field(..., description="Executive summary")
    methodology: Dict[str, Any] = Field(..., description="Assessment methodology")
    findings: List[Dict[str, Any]] = Field(..., description="Technical findings")
    recommendations: List[Dict[str, Any]] = Field(..., description="Technical recommendations")
    appendices: Dict[str, Any] = Field(..., description="Technical appendices")


class FindingsDocumentation(BaseModel):
    """Model for findings documentation."""
    
    finding_id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Finding title")
    severity: str = Field(..., description="Finding severity")
    category: str = Field(..., description="Finding category")
    description: str = Field(..., description="Detailed description")
    impact: str = Field(..., description="Business impact")
    evidence: List[Dict[str, Any]] = Field(..., description="Supporting evidence")
    remediation: Dict[str, Any] = Field(..., description="Remediation steps")
    references: List[str] = Field(..., description="Technical references")


class DeepDiveMaterial(BaseModel):
    """Model for technical deep-dive materials."""
    
    material_id: str = Field(..., description="Unique material identifier")
    title: str = Field(..., description="Material title")
    type: str = Field(..., description="Material type")
    content: Dict[str, Any] = Field(..., description="Technical content")
    diagrams: List[Dict[str, Any]] = Field(..., description="Technical diagrams")
    code_examples: List[Dict[str, Any]] = Field(..., description="Code examples")
    technical_details: Dict[str, Any] = Field(..., description="Technical details")


class TechnicalDocumentation:
    """
    Technical documentation generator for comprehensive reporting stage.
    
    This class creates detailed technical reports, findings documentation,
    and technical deep-dive materials for technical stakeholders.
    """
    
    def __init__(self, target: str, stage: str = "comprehensive_reporting"):
        """
        Initialize the technical documentation generator.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_output_dir = Path(f"outputs/{self.stage}/{self.target}")
        self.technical_docs_dir = self.base_output_dir / "technical_docs"
        
        # Ensure output directories exist
        self.technical_docs_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.technical_docs_dir / "reports").mkdir(exist_ok=True)
        (self.technical_docs_dir / "findings").mkdir(exist_ok=True)
        (self.technical_docs_dir / "deep_dive").mkdir(exist_ok=True)
        (self.technical_docs_dir / "evidence").mkdir(exist_ok=True)
        
        # Load consolidated data
        self.consolidated_data = None
        self.analysis_results = None
        
        logger.info(f"Initialized TechnicalDocumentation for target: {target}")
    
    async def create_technical_reports(self) -> Dict[str, Any]:
        """
        Create detailed technical reports.
        
        Returns:
            Dictionary containing technical reports
        """
        logger.info("Creating detailed technical reports")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            reports = {
                "vulnerability_report": {},
                "attack_path_report": {},
                "reconnaissance_report": {},
                "compliance_report": {},
                "reports_generated": 0
            }
            
            # Create vulnerability report
            vulnerability_report = await self._create_vulnerability_report()
            reports["vulnerability_report"] = vulnerability_report
            
            # Create attack path report
            attack_path_report = await self._create_attack_path_report()
            reports["attack_path_report"] = attack_path_report
            
            # Create reconnaissance report
            reconnaissance_report = await self._create_reconnaissance_report()
            reports["reconnaissance_report"] = reconnaissance_report
            
            # Create compliance report
            compliance_report = await self._create_compliance_report()
            reports["compliance_report"] = compliance_report
            
            # Update count
            reports["reports_generated"] = 4
            
            # Save technical reports
            await self._save_technical_reports(reports)
            
            # Generate report files
            await self._generate_report_files(reports)
            
            logger.info("Technical reports created successfully")
            
            return reports
            
        except Exception as e:
            logger.error(f"Error creating technical reports: {str(e)}")
            raise
    
    async def generate_findings_documentation(self) -> Dict[str, Any]:
        """
        Generate findings documentation.
        
        Returns:
            Dictionary containing findings documentation
        """
        logger.info("Generating findings documentation")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            findings_docs = {
                "critical_findings": [],
                "high_findings": [],
                "medium_findings": [],
                "low_findings": [],
                "findings_summary": {},
                "findings_generated": 0
            }
            
            # Extract findings from consolidated data
            if self.consolidated_data and "key_findings" in self.consolidated_data:
                findings = self.consolidated_data["key_findings"]
                
                # Categorize findings by severity
                for finding in findings:
                    severity = finding.get("severity", "medium").lower()
                    documented_finding = await self._document_finding(finding)
                    
                    if severity == "critical":
                        findings_docs["critical_findings"].append(documented_finding)
                    elif severity == "high":
                        findings_docs["high_findings"].append(documented_finding)
                    elif severity == "medium":
                        findings_docs["medium_findings"].append(documented_finding)
                    elif severity == "low":
                        findings_docs["low_findings"].append(documented_finding)
            
            # Generate findings summary
            findings_docs["findings_summary"] = await self._generate_findings_summary(findings_docs)
            
            # Update count
            total_findings = (len(findings_docs["critical_findings"]) + 
                            len(findings_docs["high_findings"]) + 
                            len(findings_docs["medium_findings"]) + 
                            len(findings_docs["low_findings"]))
            findings_docs["findings_generated"] = total_findings
            
            # Save findings documentation
            await self._save_findings_documentation(findings_docs)
            
            # Generate findings files
            await self._generate_findings_files(findings_docs)
            
            logger.info(f"Findings documentation generated: {total_findings} findings")
            
            return findings_docs
            
        except Exception as e:
            logger.error(f"Error generating findings documentation: {str(e)}")
            raise
    
    async def create_deep_dive_materials(self) -> Dict[str, Any]:
        """
        Create technical deep-dive materials.
        
        Returns:
            Dictionary containing deep-dive materials
        """
        logger.info("Creating technical deep-dive materials")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            deep_dive_materials = {
                "vulnerability_analysis": {},
                "attack_chain_analysis": {},
                "threat_modeling": {},
                "remediation_guides": {},
                "materials_created": 0
            }
            
            # Create vulnerability analysis deep-dive
            vuln_analysis = await self._create_vulnerability_analysis_deep_dive()
            deep_dive_materials["vulnerability_analysis"] = vuln_analysis
            
            # Create attack chain analysis deep-dive
            attack_chain_analysis = await self._create_attack_chain_analysis_deep_dive()
            deep_dive_materials["attack_chain_analysis"] = attack_chain_analysis
            
            # Create threat modeling deep-dive
            threat_modeling = await self._create_threat_modeling_deep_dive()
            deep_dive_materials["threat_modeling"] = threat_modeling
            
            # Create remediation guides
            remediation_guides = await self._create_remediation_guides()
            deep_dive_materials["remediation_guides"] = remediation_guides
            
            # Update count
            deep_dive_materials["materials_created"] = 4
            
            # Save deep-dive materials
            await self._save_deep_dive_materials(deep_dive_materials)
            
            # Generate deep-dive files
            await self._generate_deep_dive_files(deep_dive_materials)
            
            logger.info("Technical deep-dive materials created successfully")
            
            return deep_dive_materials
            
        except Exception as e:
            logger.error(f"Error creating deep-dive materials: {str(e)}")
            raise
    
    async def _load_data(self):
        """Load consolidated data and analysis results."""
        if self.consolidated_data is None:
            consolidated_data_file = self.base_output_dir / "consolidated_data" / "consolidated_data.json"
            if consolidated_data_file.exists():
                with open(consolidated_data_file, 'r') as f:
                    self.consolidated_data = json.load(f)
            
            analysis_results_file = self.base_output_dir / "consolidated_data" / "analysis_results.json"
            if analysis_results_file.exists():
                with open(analysis_results_file, 'r') as f:
                    self.analysis_results = json.load(f)
    
    async def _create_vulnerability_report(self) -> Dict[str, Any]:
        """Create vulnerability technical report."""
        report = {
            "report_id": f"VULN-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Vulnerability Assessment Technical Report - {self.target}",
            "target": self.target,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "",
            "methodology": {},
            "findings": [],
            "recommendations": [],
            "appendices": {}
        }
        
        # Generate executive summary
        report["executive_summary"] = await self._generate_vulnerability_executive_summary()
        
        # Document methodology
        report["methodology"] = await self._document_vulnerability_methodology()
        
        # Extract vulnerability findings
        report["findings"] = await self._extract_vulnerability_findings()
        
        # Generate recommendations
        report["recommendations"] = await self._generate_vulnerability_recommendations()
        
        # Create appendices
        report["appendices"] = await self._create_vulnerability_appendices()
        
        return report
    
    async def _create_attack_path_report(self) -> Dict[str, Any]:
        """Create attack path technical report."""
        report = {
            "report_id": f"ATTACK-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Attack Path Analysis Technical Report - {self.target}",
            "target": self.target,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "",
            "methodology": {},
            "findings": [],
            "recommendations": [],
            "appendices": {}
        }
        
        # Generate executive summary
        report["executive_summary"] = await self._generate_attack_path_executive_summary()
        
        # Document methodology
        report["methodology"] = await self._document_attack_path_methodology()
        
        # Extract attack path findings
        report["findings"] = await self._extract_attack_path_findings()
        
        # Generate recommendations
        report["recommendations"] = await self._generate_attack_path_recommendations()
        
        # Create appendices
        report["appendices"] = await self._create_attack_path_appendices()
        
        return report
    
    async def _create_reconnaissance_report(self) -> Dict[str, Any]:
        """Create reconnaissance technical report."""
        report = {
            "report_id": f"RECON-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Reconnaissance Assessment Technical Report - {self.target}",
            "target": self.target,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "",
            "methodology": {},
            "findings": [],
            "recommendations": [],
            "appendices": {}
        }
        
        # Generate executive summary
        report["executive_summary"] = await self._generate_reconnaissance_executive_summary()
        
        # Document methodology
        report["methodology"] = await self._document_reconnaissance_methodology()
        
        # Extract reconnaissance findings
        report["findings"] = await self._extract_reconnaissance_findings()
        
        # Generate recommendations
        report["recommendations"] = await self._generate_reconnaissance_recommendations()
        
        # Create appendices
        report["appendices"] = await self._create_reconnaissance_appendices()
        
        return report
    
    async def _create_compliance_report(self) -> Dict[str, Any]:
        """Create compliance technical report."""
        report = {
            "report_id": f"COMP-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Compliance Assessment Technical Report - {self.target}",
            "target": self.target,
            "report_date": datetime.now(timezone.utc).isoformat(),
            "executive_summary": "",
            "methodology": {},
            "findings": [],
            "recommendations": [],
            "appendices": {}
        }
        
        # Generate executive summary
        report["executive_summary"] = await self._generate_compliance_executive_summary()
        
        # Document methodology
        report["methodology"] = await self._document_compliance_methodology()
        
        # Extract compliance findings
        report["findings"] = await self._extract_compliance_findings()
        
        # Generate recommendations
        report["recommendations"] = await self._generate_compliance_recommendations()
        
        # Create appendices
        report["appendices"] = await self._create_compliance_appendices()
        
        return report
    
    async def _document_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Document a finding with detailed information."""
        documented_finding = {
            "finding_id": f"FIND-{len(finding.get('title', ''))}-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "title": finding.get("title", "Unknown Finding"),
            "severity": finding.get("severity", "medium"),
            "category": finding.get("type", "general"),
            "description": finding.get("description", "No description available"),
            "impact": finding.get("impact", "Impact not specified"),
            "evidence": [],
            "remediation": {},
            "references": []
        }
        
        # Add evidence if available
        if "source" in finding:
            documented_finding["evidence"].append({
                "type": "source",
                "description": f"Finding source: {finding['source']}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
        
        # Generate remediation steps
        documented_finding["remediation"] = await self._generate_remediation_steps(finding)
        
        # Add technical references
        documented_finding["references"] = await self._generate_technical_references(finding)
        
        return documented_finding
    
    async def _generate_findings_summary(self, findings_docs: Dict[str, Any]) -> Dict[str, Any]:
        """Generate findings summary."""
        summary = {
            "total_findings": 0,
            "by_severity": {},
            "by_category": {},
            "critical_findings_count": 0,
            "high_findings_count": 0,
            "medium_findings_count": 0,
            "low_findings_count": 0
        }
        
        # Count findings by severity
        summary["critical_findings_count"] = len(findings_docs["critical_findings"])
        summary["high_findings_count"] = len(findings_docs["high_findings"])
        summary["medium_findings_count"] = len(findings_docs["medium_findings"])
        summary["low_findings_count"] = len(findings_docs["low_findings"])
        
        summary["total_findings"] = (summary["critical_findings_count"] + 
                                   summary["high_findings_count"] + 
                                   summary["medium_findings_count"] + 
                                   summary["low_findings_count"])
        
        # Categorize findings
        summary["by_severity"] = {
            "critical": summary["critical_findings_count"],
            "high": summary["high_findings_count"],
            "medium": summary["medium_findings_count"],
            "low": summary["low_findings_count"]
        }
        
        # Count by category
        all_findings = (findings_docs["critical_findings"] + 
                       findings_docs["high_findings"] + 
                       findings_docs["medium_findings"] + 
                       findings_docs["low_findings"])
        
        category_counts = {}
        for finding in all_findings:
            category = finding.get("category", "unknown")
            category_counts[category] = category_counts.get(category, 0) + 1
        
        summary["by_category"] = category_counts
        
        return summary
    
    async def _create_vulnerability_analysis_deep_dive(self) -> Dict[str, Any]:
        """Create vulnerability analysis deep-dive material."""
        material = {
            "material_id": f"VULN-DEEP-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Vulnerability Analysis Deep-Dive - {self.target}",
            "type": "vulnerability_analysis",
            "content": {},
            "diagrams": [],
            "code_examples": [],
            "technical_details": {}
        }
        
        # Generate content
        material["content"] = await self._generate_vulnerability_analysis_content()
        
        # Create diagrams
        material["diagrams"] = await self._create_vulnerability_diagrams()
        
        # Generate code examples
        material["code_examples"] = await self._generate_vulnerability_code_examples()
        
        # Add technical details
        material["technical_details"] = await self._generate_vulnerability_technical_details()
        
        return material
    
    async def _create_attack_chain_analysis_deep_dive(self) -> Dict[str, Any]:
        """Create attack chain analysis deep-dive material."""
        material = {
            "material_id": f"ATTACK-DEEP-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Attack Chain Analysis Deep-Dive - {self.target}",
            "type": "attack_chain_analysis",
            "content": {},
            "diagrams": [],
            "code_examples": [],
            "technical_details": {}
        }
        
        # Generate content
        material["content"] = await self._generate_attack_chain_analysis_content()
        
        # Create diagrams
        material["diagrams"] = await self._create_attack_chain_diagrams()
        
        # Generate code examples
        material["code_examples"] = await self._generate_attack_chain_code_examples()
        
        # Add technical details
        material["technical_details"] = await self._generate_attack_chain_technical_details()
        
        return material
    
    async def _create_threat_modeling_deep_dive(self) -> Dict[str, Any]:
        """Create threat modeling deep-dive material."""
        material = {
            "material_id": f"THREAT-DEEP-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Threat Modeling Deep-Dive - {self.target}",
            "type": "threat_modeling",
            "content": {},
            "diagrams": [],
            "code_examples": [],
            "technical_details": {}
        }
        
        # Generate content
        material["content"] = await self._generate_threat_modeling_content()
        
        # Create diagrams
        material["diagrams"] = await self._create_threat_modeling_diagrams()
        
        # Generate code examples
        material["code_examples"] = await self._generate_threat_modeling_code_examples()
        
        # Add technical details
        material["technical_details"] = await self._generate_threat_modeling_technical_details()
        
        return material
    
    async def _create_remediation_guides(self) -> Dict[str, Any]:
        """Create remediation guides."""
        guides = {
            "critical_remediation": {},
            "high_remediation": {},
            "medium_remediation": {},
            "low_remediation": {},
            "general_remediation": {}
        }
        
        # Create remediation guides for each severity level
        guides["critical_remediation"] = await self._create_critical_remediation_guide()
        guides["high_remediation"] = await self._create_high_remediation_guide()
        guides["medium_remediation"] = await self._create_medium_remediation_guide()
        guides["low_remediation"] = await self._create_low_remediation_guide()
        guides["general_remediation"] = await self._create_general_remediation_guide()
        
        return guides
    
    # Helper methods for report generation
    async def _generate_vulnerability_executive_summary(self) -> str:
        """Generate vulnerability report executive summary."""
        if not self.consolidated_data:
            return "No vulnerability data available for analysis."
        
        summary = f"""
Vulnerability Assessment Executive Summary - {self.target}

This technical report presents the findings from our comprehensive vulnerability assessment of {self.target}. The assessment utilized industry-standard tools and methodologies to identify security weaknesses across the target environment.

Key Technical Findings:
• Comprehensive vulnerability scanning completed
• Multiple vulnerability categories identified
• Risk-based prioritization applied
• Technical remediation guidance provided

The assessment reveals technical security gaps that require immediate attention from the technical team. This report provides detailed technical analysis, evidence, and step-by-step remediation guidance.
        """.strip()
        
        return summary
    
    async def _document_vulnerability_methodology(self) -> Dict[str, Any]:
        """Document vulnerability assessment methodology."""
        methodology = {
            "assessment_approach": "Comprehensive vulnerability scanning and analysis",
            "tools_used": [
                "Automated vulnerability scanners",
                "Manual verification tools",
                "Custom assessment scripts"
            ],
            "scanning_phases": [
                "Initial reconnaissance",
                "Vulnerability discovery",
                "Manual verification",
                "Risk assessment"
            ],
            "coverage_areas": [
                "Network infrastructure",
                "Web applications",
                "API endpoints",
                "System configurations"
            ]
        }
        
        return methodology
    
    async def _extract_vulnerability_findings(self) -> List[Dict[str, Any]]:
        """Extract vulnerability findings from consolidated data."""
        findings = []
        
        if not self.consolidated_data:
            return findings
        
        # Extract from vulnerability scan data
        if "vuln_scan" in self.consolidated_data.get("stage_data", {}):
            vuln_data = self.consolidated_data["stage_data"]["vuln_scan"]
            if "findings.json" in vuln_data.get("data", {}):
                vuln_findings = vuln_data["data"]["findings.json"]
                for vuln in vuln_findings.get("vulnerabilities", []):
                    findings.append({
                        "title": vuln.get("title", "Unknown Vulnerability"),
                        "severity": vuln.get("severity", "medium"),
                        "description": vuln.get("description", "No description"),
                        "category": vuln.get("category", "general"),
                        "cvss_score": vuln.get("cvss_score", 0.0),
                        "affected_components": vuln.get("affected_components", []),
                        "technical_details": vuln.get("technical_details", {})
                    })
        
        return findings
    
    async def _generate_vulnerability_recommendations(self) -> List[Dict[str, Any]]:
        """Generate vulnerability remediation recommendations."""
        recommendations = [
            {
                "priority": "immediate",
                "title": "Address Critical Vulnerabilities",
                "description": "Immediately patch or mitigate all critical vulnerabilities",
                "technical_steps": [
                    "Identify affected systems and components",
                    "Apply security patches where available",
                    "Implement compensating controls for unpatched vulnerabilities",
                    "Verify remediation effectiveness"
                ]
            },
            {
                "priority": "high",
                "title": "Implement Security Hardening",
                "description": "Apply security hardening measures to reduce attack surface",
                "technical_steps": [
                    "Review and update system configurations",
                    "Implement least privilege access controls",
                    "Enable security logging and monitoring",
                    "Regular security assessments"
                ]
            }
        ]
        
        return recommendations
    
    async def _create_vulnerability_appendices(self) -> Dict[str, Any]:
        """Create vulnerability report appendices."""
        appendices = {
            "vulnerability_details": [],
            "scan_results": {},
            "technical_references": [],
            "tools_used": []
        }
        
        return appendices
    
    # Additional helper methods for other reports
    async def _generate_attack_path_executive_summary(self) -> str:
        """Generate attack path report executive summary."""
        return f"Attack Path Analysis Executive Summary - {self.target}"
    
    async def _document_attack_path_methodology(self) -> Dict[str, Any]:
        """Document attack path analysis methodology."""
        return {"methodology": "Graph-based attack path analysis"}
    
    async def _extract_attack_path_findings(self) -> List[Dict[str, Any]]:
        """Extract attack path findings."""
        return []
    
    async def _generate_attack_path_recommendations(self) -> List[Dict[str, Any]]:
        """Generate attack path recommendations."""
        return []
    
    async def _create_attack_path_appendices(self) -> Dict[str, Any]:
        """Create attack path report appendices."""
        return {}
    
    async def _generate_reconnaissance_executive_summary(self) -> str:
        """Generate reconnaissance report executive summary."""
        return f"Reconnaissance Assessment Executive Summary - {self.target}"
    
    async def _document_reconnaissance_methodology(self) -> Dict[str, Any]:
        """Document reconnaissance methodology."""
        return {"methodology": "Comprehensive reconnaissance assessment"}
    
    async def _extract_reconnaissance_findings(self) -> List[Dict[str, Any]]:
        """Extract reconnaissance findings."""
        return []
    
    async def _generate_reconnaissance_recommendations(self) -> List[Dict[str, Any]]:
        """Generate reconnaissance recommendations."""
        return []
    
    async def _create_reconnaissance_appendices(self) -> Dict[str, Any]:
        """Create reconnaissance report appendices."""
        return {}
    
    async def _generate_compliance_executive_summary(self) -> str:
        """Generate compliance report executive summary."""
        return f"Compliance Assessment Executive Summary - {self.target}"
    
    async def _document_compliance_methodology(self) -> Dict[str, Any]:
        """Document compliance methodology."""
        return {"methodology": "Compliance framework assessment"}
    
    async def _extract_compliance_findings(self) -> List[Dict[str, Any]]:
        """Extract compliance findings."""
        return []
    
    async def _generate_compliance_recommendations(self) -> List[Dict[str, Any]]:
        """Generate compliance recommendations."""
        return []
    
    async def _create_compliance_appendices(self) -> Dict[str, Any]:
        """Create compliance report appendices."""
        return {}
    
    # Helper methods for findings documentation
    async def _generate_remediation_steps(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation steps for a finding."""
        return {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "verification_steps": []
        }
    
    async def _generate_technical_references(self, finding: Dict[str, Any]) -> List[str]:
        """Generate technical references for a finding."""
        return [
            "OWASP Top 10",
            "CWE/SANS Top 25",
            "NIST Cybersecurity Framework"
        ]
    
    # Helper methods for deep-dive materials
    async def _generate_vulnerability_analysis_content(self) -> Dict[str, Any]:
        """Generate vulnerability analysis content."""
        return {"content": "Vulnerability analysis deep-dive content"}
    
    async def _create_vulnerability_diagrams(self) -> List[Dict[str, Any]]:
        """Create vulnerability analysis diagrams."""
        return []
    
    async def _generate_vulnerability_code_examples(self) -> List[Dict[str, Any]]:
        """Generate vulnerability code examples."""
        return []
    
    async def _generate_vulnerability_technical_details(self) -> Dict[str, Any]:
        """Generate vulnerability technical details."""
        return {}
    
    async def _generate_attack_chain_analysis_content(self) -> Dict[str, Any]:
        """Generate attack chain analysis content."""
        return {"content": "Attack chain analysis deep-dive content"}
    
    async def _create_attack_chain_diagrams(self) -> List[Dict[str, Any]]:
        """Create attack chain diagrams."""
        return []
    
    async def _generate_attack_chain_code_examples(self) -> List[Dict[str, Any]]:
        """Generate attack chain code examples."""
        return []
    
    async def _generate_attack_chain_technical_details(self) -> Dict[str, Any]:
        """Generate attack chain technical details."""
        return {}
    
    async def _generate_threat_modeling_content(self) -> Dict[str, Any]:
        """Generate threat modeling content."""
        return {"content": "Threat modeling deep-dive content"}
    
    async def _create_threat_modeling_diagrams(self) -> List[Dict[str, Any]]:
        """Create threat modeling diagrams."""
        return []
    
    async def _generate_threat_modeling_code_examples(self) -> List[Dict[str, Any]]:
        """Generate threat modeling code examples."""
        return []
    
    async def _generate_threat_modeling_technical_details(self) -> Dict[str, Any]:
        """Generate threat modeling technical details."""
        return {}
    
    # Helper methods for remediation guides
    async def _create_critical_remediation_guide(self) -> Dict[str, Any]:
        """Create critical remediation guide."""
        return {"guide": "Critical vulnerability remediation guide"}
    
    async def _create_high_remediation_guide(self) -> Dict[str, Any]:
        """Create high remediation guide."""
        return {"guide": "High vulnerability remediation guide"}
    
    async def _create_medium_remediation_guide(self) -> Dict[str, Any]:
        """Create medium remediation guide."""
        return {"guide": "Medium vulnerability remediation guide"}
    
    async def _create_low_remediation_guide(self) -> Dict[str, Any]:
        """Create low remediation guide."""
        return {"guide": "Low vulnerability remediation guide"}
    
    async def _create_general_remediation_guide(self) -> Dict[str, Any]:
        """Create general remediation guide."""
        return {"guide": "General security remediation guide"}
    
    # File operations
    async def _save_technical_reports(self, reports: Dict[str, Any]):
        """Save technical reports."""
        output_file = self.technical_docs_dir / "reports" / "technical_reports.json"
        with open(output_file, 'w') as f:
            json.dump(reports, f, indent=2, default=str)
        
        logger.info(f"Technical reports saved to {output_file}")
    
    async def _save_findings_documentation(self, findings_docs: Dict[str, Any]):
        """Save findings documentation."""
        output_file = self.technical_docs_dir / "findings" / "findings_documentation.json"
        with open(output_file, 'w') as f:
            json.dump(findings_docs, f, indent=2, default=str)
        
        logger.info(f"Findings documentation saved to {output_file}")
    
    async def _save_deep_dive_materials(self, deep_dive_materials: Dict[str, Any]):
        """Save deep-dive materials."""
        output_file = self.technical_docs_dir / "deep_dive" / "deep_dive_materials.json"
        with open(output_file, 'w') as f:
            json.dump(deep_dive_materials, f, indent=2, default=str)
        
        logger.info(f"Deep-dive materials saved to {output_file}")
    
    async def _generate_report_files(self, reports: Dict[str, Any]):
        """Generate report files."""
        # Generate markdown versions of reports
        for report_type, report_data in reports.items():
            if report_type != "reports_generated":
                markdown_file = self.technical_docs_dir / "reports" / f"{report_type}.md"
                await self._generate_markdown_report(report_data, markdown_file)
        
        logger.info("Report files generated")
    
    async def _generate_findings_files(self, findings_docs: Dict[str, Any]):
        """Generate findings files."""
        # Generate markdown version of findings
        markdown_file = self.technical_docs_dir / "findings" / "findings_documentation.md"
        await self._generate_markdown_findings(findings_docs, markdown_file)
        
        logger.info("Findings files generated")
    
    async def _generate_deep_dive_files(self, deep_dive_materials: Dict[str, Any]):
        """Generate deep-dive files."""
        # Generate markdown versions of deep-dive materials
        for material_type, material_data in deep_dive_materials.items():
            if material_type != "materials_created":
                markdown_file = self.technical_docs_dir / "deep_dive" / f"{material_type}.md"
                await self._generate_markdown_deep_dive(material_data, markdown_file)
        
        logger.info("Deep-dive files generated")
    
    async def _generate_markdown_report(self, report: Dict[str, Any], output_file: Path):
        """Generate markdown version of technical report."""
        markdown_content = f"""# {report.get('title', 'Technical Report')}

## Report Information
- **Report ID**: {report.get('report_id', 'N/A')}
- **Target**: {report.get('target', 'N/A')}
- **Report Date**: {report.get('report_date', 'N/A')}

## Executive Summary
{report.get('executive_summary', 'No summary available.')}

## Methodology
{json.dumps(report.get('methodology', {}), indent=2)}

## Findings
"""
        
        for i, finding in enumerate(report.get('findings', []), 1):
            markdown_content += f"""
### {i}. {finding.get('title', 'Unknown Finding')}
- **Severity**: {finding.get('severity', 'Unknown')}
- **Category**: {finding.get('category', 'Unknown')}
- **Description**: {finding.get('description', 'No description available.')}
"""
        
        markdown_content += f"""
## Recommendations
"""
        
        for i, recommendation in enumerate(report.get('recommendations', []), 1):
            markdown_content += f"""
### {i}. {recommendation.get('title', 'Unknown Recommendation')}
- **Priority**: {recommendation.get('priority', 'Unknown')}
- **Description**: {recommendation.get('description', 'No description available.')}
"""
        
        with open(output_file, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown report generated: {output_file}")
    
    async def _generate_markdown_findings(self, findings_docs: Dict[str, Any], output_file: Path):
        """Generate markdown version of findings documentation."""
        markdown_content = f"""# Findings Documentation - {self.target}

## Summary
- **Total Findings**: {findings_docs.get('findings_summary', {}).get('total_findings', 0)}
- **Critical**: {findings_docs.get('findings_summary', {}).get('critical_findings_count', 0)}
- **High**: {findings_docs.get('findings_summary', {}).get('high_findings_count', 0)}
- **Medium**: {findings_docs.get('findings_summary', {}).get('medium_findings_count', 0)}
- **Low**: {findings_docs.get('findings_summary', {}).get('low_findings_count', 0)}

## Critical Findings
"""
        
        for finding in findings_docs.get('critical_findings', []):
            markdown_content += f"""
### {finding.get('title', 'Unknown Finding')}
- **Finding ID**: {finding.get('finding_id', 'N/A')}
- **Severity**: {finding.get('severity', 'Unknown')}
- **Category**: {finding.get('category', 'Unknown')}
- **Description**: {finding.get('description', 'No description available.')}
- **Impact**: {finding.get('impact', 'Impact not specified.')}
"""
        
        with open(output_file, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown findings generated: {output_file}")
    
    async def _generate_markdown_deep_dive(self, material: Dict[str, Any], output_file: Path):
        """Generate markdown version of deep-dive material."""
        markdown_content = f"""# {material.get('title', 'Deep-Dive Material')}

## Material Information
- **Material ID**: {material.get('material_id', 'N/A')}
- **Type**: {material.get('type', 'N/A')}

## Content
{json.dumps(material.get('content', {}), indent=2)}

## Technical Details
{json.dumps(material.get('technical_details', {}), indent=2)}
"""
        
        with open(output_file, 'w') as f:
            f.write(markdown_content)
        
        logger.info(f"Markdown deep-dive generated: {output_file}") 