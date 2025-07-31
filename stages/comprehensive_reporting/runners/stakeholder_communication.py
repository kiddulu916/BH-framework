#!/usr/bin/env python3
"""
Stakeholder Communication - Phase 6: Stakeholder Communication and Handoff

This module creates stakeholder communication materials, handoff documentation,
and final deliverable packaging for the comprehensive reporting stage.

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

import pandas as pd
import numpy as np
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class CommunicationMaterial(BaseModel):
    """Model for communication material."""
    
    material_id: str = Field(..., description="Unique material identifier")
    title: str = Field(..., description="Material title")
    audience: str = Field(..., description="Target audience")
    format: str = Field(..., description="Material format")
    content: Dict[str, Any] = Field(..., description="Material content")
    delivery_method: str = Field(..., description="Delivery method")


class HandoffDocumentation(BaseModel):
    """Model for handoff documentation."""
    
    handoff_id: str = Field(..., description="Handoff identifier")
    from_team: str = Field(..., description="Handing off from")
    to_team: str = Field(..., description="Handing off to")
    handoff_date: str = Field(..., description="Handoff date")
    deliverables: List[str] = Field(..., description="Deliverables")
    next_steps: List[str] = Field(..., description="Next steps")
    contact_information: Dict[str, str] = Field(..., description="Contact information")


class FinalDeliverable(BaseModel):
    """Model for final deliverable."""
    
    deliverable_id: str = Field(..., description="Deliverable identifier")
    title: str = Field(..., description="Deliverable title")
    type: str = Field(..., description="Deliverable type")
    contents: List[str] = Field(..., description="Contents")
    format: str = Field(..., description="Format")
    delivery_date: str = Field(..., description="Delivery date")


class StakeholderCommunication:
    """
    Stakeholder communication generator for comprehensive reporting stage.
    
    This class creates stakeholder communication materials, handoff documentation,
    and final deliverable packaging for project completion.
    """
    
    def __init__(self, target: str, stage: str = "comprehensive_reporting"):
        """
        Initialize the stakeholder communication generator.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_output_dir = Path(f"outputs/{self.stage}/{self.target}")
        self.communication_dir = self.base_output_dir / "stakeholder_communication"
        
        # Ensure output directories exist
        self.communication_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.communication_dir / "materials").mkdir(exist_ok=True)
        (self.communication_dir / "handoff").mkdir(exist_ok=True)
        (self.communication_dir / "deliverables").mkdir(exist_ok=True)
        (self.communication_dir / "templates").mkdir(exist_ok=True)
        
        # Load consolidated data
        self.consolidated_data = None
        self.analysis_results = None
        
        logger.info(f"Initialized StakeholderCommunication for target: {target}")
    
    async def create_communication_materials(self) -> Dict[str, Any]:
        """
        Create stakeholder communication materials.
        
        Returns:
            Dictionary containing communication materials
        """
        logger.info("Creating stakeholder communication materials")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            materials = {
                "executive_briefing": {},
                "technical_briefing": {},
                "board_presentation": {},
                "stakeholder_summary": {},
                "communication_plan": {},
                "materials_created": 0
            }
            
            # Create communication materials for different audiences
            materials["executive_briefing"] = await self._create_executive_briefing()
            materials["technical_briefing"] = await self._create_technical_briefing()
            materials["board_presentation"] = await self._create_board_presentation()
            materials["stakeholder_summary"] = await self._create_stakeholder_summary()
            materials["communication_plan"] = await self._create_communication_plan()
            
            # Update count
            materials["materials_created"] = 5
            
            # Save communication materials
            await self._save_communication_materials(materials)
            
            logger.info("Communication materials created successfully")
            
            return materials
            
        except Exception as e:
            logger.error(f"Error creating communication materials: {str(e)}")
            raise
    
    async def develop_handoff_documentation(self) -> Dict[str, Any]:
        """
        Develop handoff documentation.
        
        Returns:
            Dictionary containing handoff documentation
        """
        logger.info("Developing handoff documentation")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            handoff_docs = {
                "technical_handoff": {},
                "management_handoff": {},
                "compliance_handoff": {},
                "operational_handoff": {},
                "handoff_summary": {},
                "handoffs_created": 0
            }
            
            # Create handoff documentation for different teams
            handoff_docs["technical_handoff"] = await self._create_technical_handoff()
            handoff_docs["management_handoff"] = await self._create_management_handoff()
            handoff_docs["compliance_handoff"] = await self._create_compliance_handoff()
            handoff_docs["operational_handoff"] = await self._create_operational_handoff()
            handoff_docs["handoff_summary"] = await self._create_handoff_summary(handoff_docs)
            
            # Update count
            handoff_docs["handoffs_created"] = 4
            
            # Save handoff documentation
            await self._save_handoff_documentation(handoff_docs)
            
            logger.info("Handoff documentation developed successfully")
            
            return handoff_docs
            
        except Exception as e:
            logger.error(f"Error developing handoff documentation: {str(e)}")
            raise
    
    async def package_final_deliverables(self) -> Dict[str, Any]:
        """
        Package final deliverables.
        
        Returns:
            Dictionary containing final deliverables
        """
        logger.info("Packaging final deliverables")
        
        try:
            # Load consolidated data and analysis results
            await self._load_data()
            
            deliverables = {
                "executive_package": {},
                "technical_package": {},
                "compliance_package": {},
                "complete_package": {},
                "deliverables_created": 0
            }
            
            # Create deliverable packages
            deliverables["executive_package"] = await self._create_executive_package()
            deliverables["technical_package"] = await self._create_technical_package()
            deliverables["compliance_package"] = await self._create_compliance_package()
            deliverables["complete_package"] = await self._create_complete_package()
            
            # Update count
            deliverables["deliverables_created"] = 4
            
            # Save final deliverables
            await self._save_final_deliverables(deliverables)
            
            # Create physical deliverable files
            await self._create_deliverable_files(deliverables)
            
            logger.info("Final deliverables packaged successfully")
            
            return deliverables
            
        except Exception as e:
            logger.error(f"Error packaging final deliverables: {str(e)}")
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
    
    async def _create_executive_briefing(self) -> Dict[str, Any]:
        """Create executive briefing material."""
        briefing = {
            "material_id": f"EXEC-BRIEF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Executive Security Assessment Briefing - {self.target}",
            "audience": "C-Suite and Senior Management",
            "format": "Presentation",
            "content": {
                "key_findings": [],
                "business_impact": {},
                "recommendations": [],
                "next_steps": []
            },
            "delivery_method": "In-person presentation"
        }
        
        # Generate content
        briefing["content"]["key_findings"] = await self._extract_executive_findings()
        briefing["content"]["business_impact"] = await self._generate_business_impact_summary()
        briefing["content"]["recommendations"] = await self._generate_executive_recommendations()
        briefing["content"]["next_steps"] = await self._generate_next_steps()
        
        return briefing
    
    async def _create_technical_briefing(self) -> Dict[str, Any]:
        """Create technical briefing material."""
        briefing = {
            "material_id": f"TECH-BRIEF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Technical Security Assessment Briefing - {self.target}",
            "audience": "IT Security Team and Technical Staff",
            "format": "Technical Report",
            "content": {
                "technical_findings": [],
                "vulnerability_details": {},
                "remediation_guidance": [],
                "implementation_plan": {}
            },
            "delivery_method": "Technical workshop"
        }
        
        # Generate content
        briefing["content"]["technical_findings"] = await self._extract_technical_findings()
        briefing["content"]["vulnerability_details"] = await self._generate_vulnerability_details()
        briefing["content"]["remediation_guidance"] = await self._generate_remediation_guidance()
        briefing["content"]["implementation_plan"] = await self._generate_implementation_plan()
        
        return briefing
    
    async def _create_board_presentation(self) -> Dict[str, Any]:
        """Create board presentation material."""
        presentation = {
            "material_id": f"BOARD-PRES-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Board Security Briefing - {self.target}",
            "audience": "Board of Directors",
            "format": "Board Presentation",
            "content": {
                "risk_overview": {},
                "governance_implications": [],
                "strategic_recommendations": [],
                "oversight_requirements": []
            },
            "delivery_method": "Board meeting presentation"
        }
        
        # Generate content
        presentation["content"]["risk_overview"] = await self._generate_risk_overview()
        presentation["content"]["governance_implications"] = await self._generate_governance_implications()
        presentation["content"]["strategic_recommendations"] = await self._generate_strategic_recommendations()
        presentation["content"]["oversight_requirements"] = await self._generate_oversight_requirements()
        
        return presentation
    
    async def _create_stakeholder_summary(self) -> Dict[str, Any]:
        """Create stakeholder summary material."""
        summary = {
            "material_id": f"STAKE-SUMM-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Security Assessment Summary - {self.target}",
            "audience": "General Stakeholders",
            "format": "Summary Report",
            "content": {
                "assessment_overview": {},
                "key_results": [],
                "impact_assessment": {},
                "action_items": []
            },
            "delivery_method": "Email and web portal"
        }
        
        # Generate content
        summary["content"]["assessment_overview"] = await self._generate_assessment_overview()
        summary["content"]["key_results"] = await self._extract_key_results()
        summary["content"]["impact_assessment"] = await self._generate_impact_assessment()
        summary["content"]["action_items"] = await self._generate_action_items()
        
        return summary
    
    async def _create_communication_plan(self) -> Dict[str, Any]:
        """Create communication plan."""
        plan = {
            "material_id": f"COMM-PLAN-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Stakeholder Communication Plan - {self.target}",
            "audience": "Project Team",
            "format": "Communication Plan",
            "content": {
                "stakeholder_mapping": {},
                "communication_schedule": [],
                "delivery_methods": {},
                "success_metrics": []
            },
            "delivery_method": "Internal document"
        }
        
        # Generate content
        plan["content"]["stakeholder_mapping"] = await self._generate_stakeholder_mapping()
        plan["content"]["communication_schedule"] = await self._generate_communication_schedule()
        plan["content"]["delivery_methods"] = await self._generate_delivery_methods()
        plan["content"]["success_metrics"] = await self._generate_success_metrics()
        
        return plan
    
    async def _create_technical_handoff(self) -> Dict[str, Any]:
        """Create technical handoff documentation."""
        handoff = {
            "handoff_id": f"TECH-HANDOFF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "from_team": "Security Assessment Team",
            "to_team": "IT Security Team",
            "handoff_date": datetime.now(timezone.utc).isoformat(),
            "deliverables": [
                "Vulnerability assessment results",
                "Technical remediation guidance",
                "Implementation timelines",
                "Resource requirements"
            ],
            "next_steps": [
                "Review vulnerability findings",
                "Prioritize remediation efforts",
                "Allocate resources",
                "Begin implementation"
            ],
            "contact_information": {
                "security_team_lead": "security.lead@company.com",
                "technical_contact": "tech.contact@company.com",
                "emergency_contact": "emergency@company.com"
            }
        }
        
        return handoff
    
    async def _create_management_handoff(self) -> Dict[str, Any]:
        """Create management handoff documentation."""
        handoff = {
            "handoff_id": f"MGMT-HANDOFF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "from_team": "Security Assessment Team",
            "to_team": "Senior Management",
            "handoff_date": datetime.now(timezone.utc).isoformat(),
            "deliverables": [
                "Executive summary report",
                "Business impact analysis",
                "Risk assessment",
                "Strategic recommendations"
            ],
            "next_steps": [
                "Review executive summary",
                "Approve remediation budget",
                "Establish oversight committee",
                "Monitor implementation progress"
            ],
            "contact_information": {
                "cio": "cio@company.com",
                "cso": "cso@company.com",
                "cto": "cto@company.com"
            }
        }
        
        return handoff
    
    async def _create_compliance_handoff(self) -> Dict[str, Any]:
        """Create compliance handoff documentation."""
        handoff = {
            "handoff_id": f"COMP-HANDOFF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "from_team": "Security Assessment Team",
            "to_team": "Compliance Team",
            "handoff_date": datetime.now(timezone.utc).isoformat(),
            "deliverables": [
                "Compliance assessment reports",
                "Regulatory gap analysis",
                "Compliance recommendations",
                "Remediation timelines"
            ],
            "next_steps": [
                "Review compliance findings",
                "Update compliance register",
                "Plan compliance improvements",
                "Monitor remediation progress"
            ],
            "contact_information": {
                "compliance_officer": "compliance@company.com",
                "legal_team": "legal@company.com",
                "risk_management": "risk@company.com"
            }
        }
        
        return handoff
    
    async def _create_operational_handoff(self) -> Dict[str, Any]:
        """Create operational handoff documentation."""
        handoff = {
            "handoff_id": f"OPS-HANDOFF-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "from_team": "Security Assessment Team",
            "to_team": "Operations Team",
            "handoff_date": datetime.now(timezone.utc).isoformat(),
            "deliverables": [
                "Operational security findings",
                "Process improvement recommendations",
                "Monitoring enhancements",
                "Incident response updates"
            ],
            "next_steps": [
                "Review operational findings",
                "Update security procedures",
                "Enhance monitoring capabilities",
                "Test incident response procedures"
            ],
            "contact_information": {
                "operations_manager": "ops@company.com",
                "security_operations": "secops@company.com",
                "incident_response": "ir@company.com"
            }
        }
        
        return handoff
    
    async def _create_handoff_summary(self, handoff_docs: Dict[str, Any]) -> Dict[str, Any]:
        """Create handoff summary."""
        summary = {
            "total_handoffs": 4,
            "handoff_teams": [
                "IT Security Team",
                "Senior Management",
                "Compliance Team",
                "Operations Team"
            ],
            "deliverables_count": 16,
            "next_steps_count": 16,
            "handoff_status": "Ready for handoff",
            "follow_up_required": True
        }
        
        return summary
    
    async def _create_executive_package(self) -> Dict[str, Any]:
        """Create executive deliverable package."""
        package = {
            "deliverable_id": f"EXEC-PKG-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Executive Security Assessment Package - {self.target}",
            "type": "Executive Summary",
            "contents": [
                "Executive summary report",
                "Business impact analysis",
                "Risk assessment overview",
                "Strategic recommendations",
                "Executive presentation"
            ],
            "format": "PDF and PowerPoint",
            "delivery_date": datetime.now(timezone.utc).isoformat()
        }
        
        return package
    
    async def _create_technical_package(self) -> Dict[str, Any]:
        """Create technical deliverable package."""
        package = {
            "deliverable_id": f"TECH-PKG-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Technical Security Assessment Package - {self.target}",
            "type": "Technical Documentation",
            "contents": [
                "Technical assessment report",
                "Vulnerability findings",
                "Remediation guidance",
                "Implementation plan",
                "Resource requirements"
            ],
            "format": "PDF and JSON",
            "delivery_date": datetime.now(timezone.utc).isoformat()
        }
        
        return package
    
    async def _create_compliance_package(self) -> Dict[str, Any]:
        """Create compliance deliverable package."""
        package = {
            "deliverable_id": f"COMP-PKG-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Compliance Assessment Package - {self.target}",
            "type": "Compliance Documentation",
            "contents": [
                "GDPR compliance report",
                "SOX compliance report",
                "PCI DSS compliance report",
                "ISO 27001 compliance report",
                "Compliance gap analysis"
            ],
            "format": "PDF and Excel",
            "delivery_date": datetime.now(timezone.utc).isoformat()
        }
        
        return package
    
    async def _create_complete_package(self) -> Dict[str, Any]:
        """Create complete deliverable package."""
        package = {
            "deliverable_id": f"COMPLETE-PKG-{self.target}-{datetime.now().strftime('%Y%m%d')}",
            "title": f"Complete Security Assessment Package - {self.target}",
            "type": "Complete Documentation",
            "contents": [
                "Executive summary",
                "Technical documentation",
                "Compliance reports",
                "Remediation roadmap",
                "Communication materials",
                "Handoff documentation"
            ],
            "format": "Complete package with all formats",
            "delivery_date": datetime.now(timezone.utc).isoformat()
        }
        
        return package
    
    # Helper methods for content generation
    async def _extract_executive_findings(self) -> List[Dict[str, Any]]:
        """Extract executive-level findings."""
        findings = []
        
        if self.consolidated_data and "key_findings" in self.consolidated_data:
            key_findings = self.consolidated_data["key_findings"]
            
            # Take top 3 findings for executive summary
            for finding in key_findings[:3]:
                findings.append({
                    "title": finding.get("title", "Unknown Finding"),
                    "severity": finding.get("severity", "medium"),
                    "business_impact": finding.get("impact", "Impact not specified")
                })
        
        return findings
    
    async def _generate_business_impact_summary(self) -> Dict[str, Any]:
        """Generate business impact summary."""
        return {
            "financial_impact": "Medium to High",
            "operational_impact": "Medium",
            "reputation_impact": "Medium",
            "compliance_impact": "High",
            "overall_risk_level": "Medium"
        }
    
    async def _generate_executive_recommendations(self) -> List[str]:
        """Generate executive recommendations."""
        return [
            "Immediately address critical vulnerabilities",
            "Allocate budget for security improvements",
            "Establish security oversight committee",
            "Implement continuous security monitoring"
        ]
    
    async def _generate_next_steps(self) -> List[str]:
        """Generate next steps."""
        return [
            "Review and approve remediation plan",
            "Allocate resources for implementation",
            "Establish progress tracking mechanisms",
            "Schedule follow-up assessment"
        ]
    
    async def _extract_technical_findings(self) -> List[Dict[str, Any]]:
        """Extract technical findings."""
        findings = []
        
        if self.consolidated_data and "key_findings" in self.consolidated_data:
            key_findings = self.consolidated_data["key_findings"]
            
            for finding in key_findings:
                findings.append({
                    "title": finding.get("title", "Unknown Finding"),
                    "severity": finding.get("severity", "medium"),
                    "description": finding.get("description", "No description"),
                    "technical_details": finding.get("technical_details", {})
                })
        
        return findings
    
    async def _generate_vulnerability_details(self) -> Dict[str, Any]:
        """Generate vulnerability details."""
        return {
            "total_vulnerabilities": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        }
    
    async def _generate_remediation_guidance(self) -> List[str]:
        """Generate remediation guidance."""
        return [
            "Prioritize critical vulnerabilities",
            "Implement security patches",
            "Update security configurations",
            "Enhance monitoring capabilities"
        ]
    
    async def _generate_implementation_plan(self) -> Dict[str, Any]:
        """Generate implementation plan."""
        return {
            "timeline": "6-12 months",
            "phases": ["Immediate", "Short-term", "Medium-term", "Long-term"],
            "resources_required": ["Security team", "IT team", "Management support"]
        }
    
    async def _generate_risk_overview(self) -> Dict[str, Any]:
        """Generate risk overview."""
        return {
            "overall_risk_level": "Medium",
            "risk_categories": ["Technical", "Operational", "Compliance"],
            "risk_trends": "Stable",
            "risk_mitigation": "In progress"
        }
    
    async def _generate_governance_implications(self) -> List[str]:
        """Generate governance implications."""
        return [
            "Enhanced security oversight required",
            "Regular risk reporting to board",
            "Security budget allocation",
            "Compliance monitoring"
        ]
    
    async def _generate_strategic_recommendations(self) -> List[str]:
        """Generate strategic recommendations."""
        return [
            "Establish security governance framework",
            "Invest in security capabilities",
            "Enhance risk management processes",
            "Build security culture"
        ]
    
    async def _generate_oversight_requirements(self) -> List[str]:
        """Generate oversight requirements."""
        return [
            "Quarterly security reviews",
            "Annual risk assessments",
            "Compliance reporting",
            "Security metrics tracking"
        ]
    
    async def _generate_assessment_overview(self) -> Dict[str, Any]:
        """Generate assessment overview."""
        return {
            "assessment_scope": "Comprehensive security assessment",
            "assessment_duration": "4-6 weeks",
            "assessment_methodology": "Industry best practices",
            "assessment_team": "Security professionals"
        }
    
    async def _extract_key_results(self) -> List[Dict[str, Any]]:
        """Extract key results."""
        results = []
        
        if self.consolidated_data and "summary_statistics" in self.consolidated_data:
            stats = self.consolidated_data["summary_statistics"]
            
            results.append({
                "metric": "Total Vulnerabilities",
                "value": stats.get("total_vulnerabilities", 0),
                "trend": "Identified"
            })
            
            results.append({
                "metric": "Risk Score",
                "value": f"{stats.get('risk_score', 0):.1f}/100",
                "trend": "Medium"
            })
        
        return results
    
    async def _generate_impact_assessment(self) -> Dict[str, Any]:
        """Generate impact assessment."""
        return {
            "business_impact": "Medium",
            "operational_impact": "Low to Medium",
            "compliance_impact": "Medium to High",
            "reputation_impact": "Low"
        }
    
    async def _generate_action_items(self) -> List[str]:
        """Generate action items."""
        return [
            "Review assessment findings",
            "Prioritize remediation efforts",
            "Allocate necessary resources",
            "Monitor implementation progress"
        ]
    
    async def _generate_stakeholder_mapping(self) -> Dict[str, Any]:
        """Generate stakeholder mapping."""
        return {
            "executive_stakeholders": ["CEO", "CIO", "CSO", "CTO"],
            "technical_stakeholders": ["IT Security Team", "System Administrators", "Network Engineers"],
            "compliance_stakeholders": ["Compliance Officer", "Legal Team", "Risk Management"],
            "operational_stakeholders": ["Operations Team", "Security Operations", "Incident Response"]
        }
    
    async def _generate_communication_schedule(self) -> List[Dict[str, Any]]:
        """Generate communication schedule."""
        return [
            {
                "audience": "Executive Team",
                "frequency": "Weekly",
                "format": "Executive summary",
                "delivery": "Email and presentation"
            },
            {
                "audience": "Technical Team",
                "frequency": "Daily",
                "format": "Technical updates",
                "delivery": "Email and collaboration platform"
            },
            {
                "audience": "Compliance Team",
                "frequency": "Bi-weekly",
                "format": "Compliance reports",
                "delivery": "Email and compliance portal"
            }
        ]
    
    async def _generate_delivery_methods(self) -> Dict[str, Any]:
        """Generate delivery methods."""
        return {
            "executive": ["In-person presentation", "Email", "Board portal"],
            "technical": ["Email", "Collaboration platform", "Technical documentation"],
            "compliance": ["Email", "Compliance portal", "Regulatory reports"],
            "operational": ["Email", "Operations dashboard", "Incident management system"]
        }
    
    async def _generate_success_metrics(self) -> List[str]:
        """Generate success metrics."""
        return [
            "Stakeholder engagement levels",
            "Communication effectiveness",
            "Action item completion rates",
            "Feedback satisfaction scores"
        ]
    
    # File operations
    async def _save_communication_materials(self, materials: Dict[str, Any]):
        """Save communication materials."""
        output_file = self.communication_dir / "materials" / "communication_materials.json"
        with open(output_file, 'w') as f:
            json.dump(materials, f, indent=2, default=str)
        
        logger.info(f"Communication materials saved to {output_file}")
    
    async def _save_handoff_documentation(self, handoff_docs: Dict[str, Any]):
        """Save handoff documentation."""
        output_file = self.communication_dir / "handoff" / "handoff_documentation.json"
        with open(output_file, 'w') as f:
            json.dump(handoff_docs, f, indent=2, default=str)
        
        logger.info(f"Handoff documentation saved to {output_file}")
    
    async def _save_final_deliverables(self, deliverables: Dict[str, Any]):
        """Save final deliverables."""
        output_file = self.communication_dir / "deliverables" / "final_deliverables.json"
        with open(output_file, 'w') as f:
            json.dump(deliverables, f, indent=2, default=str)
        
        logger.info(f"Final deliverables saved to {output_file}")
    
    async def _create_deliverable_files(self, deliverables: Dict[str, Any]):
        """Create physical deliverable files."""
        # Create deliverable directories
        for deliverable_type, deliverable_data in deliverables.items():
            if deliverable_type != "deliverables_created":
                deliverable_dir = self.communication_dir / "deliverables" / deliverable_type
                deliverable_dir.mkdir(exist_ok=True)
                
                # Create README file for each deliverable
                readme_content = f"""# {deliverable_data.get('title', 'Deliverable Package')}

## Package Information
- **Deliverable ID**: {deliverable_data.get('deliverable_id', 'N/A')}
- **Type**: {deliverable_data.get('type', 'N/A')}
- **Format**: {deliverable_data.get('format', 'N/A')}
- **Delivery Date**: {deliverable_data.get('delivery_date', 'N/A')}

## Contents
"""
                
                for content in deliverable_data.get('contents', []):
                    readme_content += f"- {content}\n"
                
                readme_file = deliverable_dir / "README.md"
                with open(readme_file, 'w') as f:
                    f.write(readme_content)
        
        logger.info("Deliverable files created successfully") 