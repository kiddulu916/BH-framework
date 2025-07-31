#!/usr/bin/env python3
"""
Output Generator Runner for Stage 4: Step 4.6

This module implements comprehensive output generation with multiple formats,
structured reports, ML training export, stakeholder summaries, and Stage 5 handoff.
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import yaml

import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class ReportMetadata:
    """Metadata for generated reports."""
    
    report_id: str
    generated_at: datetime
    target: str
    stage: str
    total_findings: int
    confirmed_vulnerabilities: int
    false_positives: int
    scan_duration: float
    ai_analysis_enabled: bool
    evidence_collected: bool


@dataclass
class StructuredFinding:
    """Structured finding for report generation."""
    
    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float
    status: str
    vulnerability_type: str
    endpoint: str
    evidence: str
    remediation: str
    cwe_ids: List[str]
    cve_references: List[str]
    cvss_score: float
    ai_risk_score: float
    discovered_at: datetime
    verified_at: Optional[datetime] = None


class OutputGenerator:
    """Comprehensive output generator for vulnerability testing results."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.reports_dir = self.output_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Output configuration
        self.output_formats = config.output_formats
        self.enable_ml_training_export = config.enable_ml_training_export
        
        # Generated reports
        self.reports: List[Dict[str, Any]] = []
        
        # Initialize report metadata
        self.report_metadata = ReportMetadata(
            report_id=str(uuid.uuid4()),
            generated_at=datetime.now(timezone.utc),
            target=config.target,
            stage=config.stage_name,
            total_findings=0,
            confirmed_vulnerabilities=0,
            false_positives=0,
            scan_duration=0.0,
            ai_analysis_enabled=config.enable_ai_analysis,
            evidence_collected=config.enable_evidence_collection
        )
    
    def generate_structured_report(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Generate structured findings report.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dict[str, Any]: Structured report
        """
        logger.info("Generating structured findings report...")
        
        try:
            # Update report metadata
            self.report_metadata.total_findings = len(findings)
            self.report_metadata.confirmed_vulnerabilities = len([f for f in findings if getattr(f, 'status', '') == 'Confirmed'])
            self.report_metadata.false_positives = len([f for f in findings if getattr(f, 'status', '') == 'False_Positive'])
            
            # Convert findings to structured format
            structured_findings = []
            for finding in findings:
                structured_finding = StructuredFinding(
                    finding_id=getattr(finding, 'id', ''),
                    title=getattr(finding, 'title', ''),
                    description=getattr(finding, 'description', ''),
                    severity=getattr(finding, 'severity', 'Medium'),
                    confidence=getattr(finding, 'confidence', 0.0),
                    status=getattr(finding, 'status', 'Potential'),
                    vulnerability_type=getattr(finding, 'vulnerability_type', ''),
                    endpoint=getattr(finding, 'endpoint', ''),
                    evidence=getattr(finding, 'evidence', ''),
                    remediation=getattr(finding, 'remediation_advice', ''),
                    cwe_ids=getattr(finding, 'cwe_ids', []),
                    cve_references=getattr(finding, 'cve_references', []),
                    cvss_score=getattr(finding, 'cvss_score', 0.0),
                    ai_risk_score=getattr(finding, 'ai_risk_score', 0.0),
                    discovered_at=getattr(finding, 'discovered_at', datetime.now(timezone.utc)),
                    verified_at=getattr(finding, 'verified_at', None)
                )
                structured_findings.append(structured_finding)
            
            # Create structured report
            report = {
                "metadata": self.report_metadata.__dict__,
                "summary": {
                    "total_findings": len(structured_findings),
                    "by_severity": self._count_by_severity(structured_findings),
                    "by_status": self._count_by_status(structured_findings),
                    "by_vulnerability_type": self._count_by_vulnerability_type(structured_findings),
                    "average_cvss_score": np.mean([f.cvss_score for f in structured_findings]) if structured_findings else 0.0,
                    "average_ai_risk_score": np.mean([f.ai_risk_score for f in structured_findings]) if structured_findings else 0.0
                },
                "findings": [finding.__dict__ for finding in structured_findings],
                "recommendations": self._generate_recommendations(structured_findings),
                "risk_assessment": self._generate_risk_assessment(structured_findings)
            }
            
            logger.info(f"Structured report generated with {len(structured_findings)} findings")
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating structured report: {str(e)}")
            return {}
    
    def _count_by_severity(self, findings: List[StructuredFinding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in findings:
            severity = finding.severity
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _count_by_status(self, findings: List[StructuredFinding]) -> Dict[str, int]:
        """Count findings by status."""
        counts = {}
        for finding in findings:
            status = finding.status
            counts[status] = counts.get(status, 0) + 1
        return counts
    
    def _count_by_vulnerability_type(self, findings: List[StructuredFinding]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for finding in findings:
            vuln_type = finding.vulnerability_type or "Unknown"
            counts[vuln_type] = counts.get(vuln_type, 0) + 1
        return counts
    
    def _generate_recommendations(self, findings: List[StructuredFinding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        # High severity findings
        high_severity = [f for f in findings if f.severity == "Critical" or f.severity == "High"]
        if high_severity:
            recommendations.append(f"Immediate attention required for {len(high_severity)} high-severity vulnerabilities")
        
        # Confirmed vulnerabilities
        confirmed = [f for f in findings if f.status == "Confirmed"]
        if confirmed:
            recommendations.append(f"Prioritize remediation of {len(confirmed)} confirmed vulnerabilities")
        
        # Common vulnerability types
        vuln_counts = self._count_by_vulnerability_type(findings)
        most_common = max(vuln_counts.items(), key=lambda x: x[1]) if vuln_counts else ("", 0)
        if most_common[1] > 1:
            recommendations.append(f"Focus on {most_common[0]} vulnerabilities (most common type)")
        
        # AI risk assessment
        high_risk = [f for f in findings if f.ai_risk_score > 0.8]
        if high_risk:
            recommendations.append(f"AI analysis identifies {len(high_risk)} high-risk vulnerabilities requiring immediate attention")
        
        return recommendations
    
    def _generate_risk_assessment(self, findings: List[StructuredFinding]) -> Dict[str, Any]:
        """Generate risk assessment."""
        if not findings:
            return {"overall_risk": "Low", "risk_score": 0.0, "risk_factors": []}
        
        # Calculate overall risk score
        cvss_scores = [f.cvss_score for f in findings]
        ai_scores = [f.ai_risk_score for f in findings]
        
        avg_cvss = np.mean(cvss_scores)
        avg_ai = np.mean(ai_scores)
        
        # Weighted risk score
        risk_score = (avg_cvss * 0.6) + (avg_ai * 0.4)
        
        # Determine overall risk level
        if risk_score >= 7.0:
            overall_risk = "Critical"
        elif risk_score >= 5.0:
            overall_risk = "High"
        elif risk_score >= 3.0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        # Identify risk factors
        risk_factors = []
        if avg_cvss > 7.0:
            risk_factors.append("High average CVSS score")
        if avg_ai > 0.8:
            risk_factors.append("High AI risk assessment")
        if len([f for f in findings if f.severity in ["Critical", "High"]]) > 0:
            risk_factors.append("Critical/High severity vulnerabilities present")
        
        return {
            "overall_risk": overall_risk,
            "risk_score": round(risk_score, 2),
            "average_cvss": round(avg_cvss, 2),
            "average_ai_risk": round(avg_ai, 2),
            "risk_factors": risk_factors
        }
    
    def compile_logs_and_artifacts(self) -> Dict[str, Any]:
        """
        Compile logs and artifacts from the testing session.
        
        Returns:
            Dict[str, Any]: Compiled logs and artifacts
        """
        logger.info("Compiling logs and artifacts...")
        
        try:
            compiled_data = {
                "metadata": {
                    "compilation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": self.config.target,
                    "stage": self.config.stage_name
                },
                "logs": {},
                "artifacts": {},
                "evidence": {},
                "statistics": {}
            }
            
            # Compile logs from different sources
            log_dirs = [
                self.output_dir / "data_preparation",
                self.output_dir / "browser_scanning",
                self.output_dir / "api_scanning",
                self.output_dir / "network_scanning",
                self.output_dir / "ai_analysis",
                self.output_dir / "exploit_testing",
                self.output_dir / "evidence_collection"
            ]
            
            for log_dir in log_dirs:
                if log_dir.exists():
                    log_files = list(log_dir.glob("*.log"))
                    for log_file in log_files:
                        try:
                            with open(log_file, 'r') as f:
                                log_content = f.read()
                                compiled_data["logs"][log_file.name] = {
                                    "path": str(log_file),
                                    "size": len(log_content),
                                    "last_modified": log_file.stat().st_mtime
                                }
                        except Exception as e:
                            logger.error(f"Error reading log file {log_file}: {str(e)}")
            
            # Compile artifacts
            artifact_dirs = [
                self.output_dir / "screenshots",
                self.output_dir / "videos",
                self.output_dir / "responses",
                self.output_dir / "reports"
            ]
            
            for artifact_dir in artifact_dirs:
                if artifact_dir.exists():
                    artifacts = list(artifact_dir.rglob("*"))
                    for artifact in artifacts:
                        if artifact.is_file():
                            try:
                                compiled_data["artifacts"][artifact.name] = {
                                    "path": str(artifact),
                                    "size": artifact.stat().st_size,
                                    "type": artifact.suffix,
                                    "last_modified": artifact.stat().st_mtime
                                }
                            except Exception as e:
                                logger.error(f"Error processing artifact {artifact}: {str(e)}")
            
            # Calculate statistics
            total_logs = len(compiled_data["logs"])
            total_artifacts = len(compiled_data["artifacts"])
            total_size = sum(artifact["size"] for artifact in compiled_data["artifacts"].values())
            
            compiled_data["statistics"] = {
                "total_log_files": total_logs,
                "total_artifacts": total_artifacts,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2)
            }
            
            logger.info(f"Logs and artifacts compilation completed. {total_logs} logs, {total_artifacts} artifacts")
            
            return compiled_data
            
        except Exception as e:
            logger.error(f"Error compiling logs and artifacts: {str(e)}")
            return {}
    
    def export_training_data(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Export training data for machine learning.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dict[str, Any]: Training data export information
        """
        logger.info("Exporting training data for machine learning...")
        
        try:
            if not self.enable_ml_training_export:
                logger.info("ML training export disabled")
                return {}
            
            training_data = {
                "metadata": {
                    "export_timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": self.config.target,
                    "stage": self.config.stage_name,
                    "total_samples": len(findings)
                },
                "features": [],
                "labels": [],
                "metadata_samples": []
            }
            
            # Extract features and labels from findings
            for finding in findings:
                # Feature vector
                features = {
                    "severity_score": self._severity_to_score(getattr(finding, 'severity', 'Medium')),
                    "confidence": getattr(finding, 'confidence', 0.0),
                    "ai_risk_score": getattr(finding, 'ai_risk_score', 0.0),
                    "cvss_score": getattr(finding, 'cvss_score', 0.0),
                    "text_length": len(getattr(finding, 'description', '') + getattr(finding, 'evidence', '')),
                    "has_payload": 1 if getattr(finding, 'payload_used', None) else 0,
                    "has_evidence": 1 if getattr(finding, 'evidence', '') else 0,
                    "vulnerability_type_encoded": self._encode_vulnerability_type(getattr(finding, 'vulnerability_type', '')),
                    "status_encoded": self._encode_status(getattr(finding, 'status', 'Potential'))
                }
                
                # Label (1 for confirmed vulnerability, 0 for false positive)
                label = 1 if getattr(finding, 'status', '') == 'Confirmed' else 0
                
                # Metadata
                metadata = {
                    "finding_id": getattr(finding, 'id', ''),
                    "title": getattr(finding, 'title', ''),
                    "vulnerability_type": getattr(finding, 'vulnerability_type', ''),
                    "endpoint": getattr(finding, 'endpoint', ''),
                    "discovered_at": getattr(finding, 'discovered_at', datetime.now(timezone.utc)).isoformat()
                }
                
                training_data["features"].append(features)
                training_data["labels"].append(label)
                training_data["metadata_samples"].append(metadata)
            
            # Save training data
            training_file = self.reports_dir / "training_data.json"
            with open(training_file, 'w') as f:
                json.dump(training_data, f, indent=2, default=str)
            
            # Create TFRecords-like structure (simplified)
            tfrecords_data = {
                "format": "tfrecords_simulation",
                "samples": len(training_data["features"]),
                "feature_schema": {
                    "severity_score": "float32",
                    "confidence": "float32",
                    "ai_risk_score": "float32",
                    "cvss_score": "float32",
                    "text_length": "int32",
                    "has_payload": "int32",
                    "has_evidence": "int32",
                    "vulnerability_type_encoded": "int32",
                    "status_encoded": "int32"
                },
                "label_schema": {
                    "is_vulnerability": "int32"
                }
            }
            
            tfrecords_file = self.reports_dir / "training_data_tfrecords.json"
            with open(tfrecords_file, 'w') as f:
                json.dump(tfrecords_data, f, indent=2)
            
            logger.info(f"Training data exported. {len(training_data['features'])} samples")
            
            return {
                "training_data_file": str(training_file),
                "tfrecords_file": str(tfrecords_file),
                "total_samples": len(training_data["features"]),
                "positive_samples": sum(training_data["labels"]),
                "negative_samples": len(training_data["labels"]) - sum(training_data["labels"])
            }
            
        except Exception as e:
            logger.error(f"Error exporting training data: {str(e)}")
            return {}
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to numerical score."""
        severity_map = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.4,
            "Info": 0.2
        }
        return severity_map.get(severity, 0.5)
    
    def _encode_vulnerability_type(self, vuln_type: str) -> int:
        """Encode vulnerability type to integer."""
        type_map = {
            "SQL Injection": 1,
            "XSS": 2,
            "Authentication Bypass": 3,
            "Information Disclosure": 4,
            "Command Injection": 5,
            "Path Traversal": 6,
            "CSRF": 7,
            "Open Redirect": 8
        }
        return type_map.get(vuln_type, 0)
    
    def _encode_status(self, status: str) -> int:
        """Encode status to integer."""
        status_map = {
            "Confirmed": 1,
            "Potential": 2,
            "False_Positive": 3
        }
        return status_map.get(status, 0)
    
    def generate_stakeholder_summary(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Generate human-readable stakeholder summary.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dict[str, Any]: Stakeholder summary
        """
        logger.info("Generating stakeholder summary...")
        
        try:
            # Calculate summary statistics
            total_findings = len(findings)
            confirmed_vulns = len([f for f in findings if getattr(f, 'status', '') == 'Confirmed'])
            high_severity = len([f for f in findings if getattr(f, 'severity', '') in ['Critical', 'High']])
            
            # Group findings by severity
            by_severity = {}
            for finding in findings:
                severity = getattr(finding, 'severity', 'Unknown')
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(finding)
            
            # Generate executive summary
            executive_summary = {
                "overview": f"Vulnerability assessment completed for {self.config.target}",
                "key_findings": total_findings,
                "confirmed_vulnerabilities": confirmed_vulns,
                "high_severity_issues": high_severity,
                "risk_level": self._determine_overall_risk_level(findings),
                "immediate_actions_required": high_severity > 0
            }
            
            # Generate detailed breakdown
            detailed_breakdown = {
                "by_severity": {
                    severity: {
                        "count": len(findings_list),
                        "percentage": round((len(findings_list) / total_findings) * 100, 1) if total_findings > 0 else 0,
                        "examples": [f.title for f in findings_list[:3]]  # Top 3 examples
                    }
                    for severity, findings_list in by_severity.items()
                },
                "by_vulnerability_type": self._group_by_vulnerability_type(findings),
                "by_status": self._group_by_status(findings)
            }
            
            # Generate recommendations
            recommendations = self._generate_stakeholder_recommendations(findings)
            
            # Create stakeholder summary
            summary = {
                "executive_summary": executive_summary,
                "detailed_breakdown": detailed_breakdown,
                "recommendations": recommendations,
                "next_steps": self._generate_next_steps(findings),
                "technical_details": {
                    "ai_analysis_used": self.config.enable_ai_analysis,
                    "evidence_collected": self.config.enable_evidence_collection,
                    "scan_duration": "N/A",  # Would be calculated from actual scan time
                    "tools_used": ["Browser Automation", "API Scanning", "Network Scanning", "AI Analysis", "Exploit Testing"]
                }
            }
            
            logger.info("Stakeholder summary generated successfully")
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating stakeholder summary: {str(e)}")
            return {}
    
    def _determine_overall_risk_level(self, findings: List[Any]) -> str:
        """Determine overall risk level for stakeholder summary."""
        if not findings:
            return "Low"
        
        critical_high = len([f for f in findings if getattr(f, 'severity', '') in ['Critical', 'High']])
        confirmed = len([f for f in findings if getattr(f, 'status', '') == 'Confirmed'])
        
        if critical_high > 0 or confirmed > 0:
            return "High"
        elif len(findings) > 5:
            return "Medium"
        else:
            return "Low"
    
    def _group_by_vulnerability_type(self, findings: List[Any]) -> Dict[str, Dict[str, Any]]:
        """Group findings by vulnerability type."""
        grouped = {}
        for finding in findings:
            vuln_type = getattr(finding, 'vulnerability_type', 'Unknown')
            if vuln_type not in grouped:
                grouped[vuln_type] = {"count": 0, "findings": []}
            grouped[vuln_type]["count"] += 1
            grouped[vuln_type]["findings"].append({
                "title": getattr(finding, 'title', ''),
                "severity": getattr(finding, 'severity', ''),
                "status": getattr(finding, 'status', '')
            })
        return grouped
    
    def _group_by_status(self, findings: List[Any]) -> Dict[str, Dict[str, Any]]:
        """Group findings by status."""
        grouped = {}
        for finding in findings:
            status = getattr(finding, 'status', 'Unknown')
            if status not in grouped:
                grouped[status] = {"count": 0, "findings": []}
            grouped[status]["count"] += 1
            grouped[status]["findings"].append({
                "title": getattr(finding, 'title', ''),
                "severity": getattr(finding, 'severity', ''),
                "vulnerability_type": getattr(finding, 'vulnerability_type', '')
            })
        return grouped
    
    def _generate_stakeholder_recommendations(self, findings: List[Any]) -> List[str]:
        """Generate stakeholder-friendly recommendations."""
        recommendations = []
        
        # High severity findings
        high_severity = [f for f in findings if getattr(f, 'severity', '') in ['Critical', 'High']]
        if high_severity:
            recommendations.append(f"Immediate action required: {len(high_severity)} critical/high-severity vulnerabilities detected")
        
        # Confirmed vulnerabilities
        confirmed = [f for f in findings if getattr(f, 'status', '') == 'Confirmed']
        if confirmed:
            recommendations.append(f"Prioritize remediation: {len(confirmed)} vulnerabilities have been confirmed through testing")
        
        # Common vulnerability types
        vuln_counts = {}
        for finding in findings:
            vuln_type = getattr(finding, 'vulnerability_type', 'Unknown')
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        if vuln_counts:
            most_common = max(vuln_counts.items(), key=lambda x: x[1])
            if most_common[1] > 1:
                recommendations.append(f"Focus area: {most_common[0]} vulnerabilities are most prevalent ({most_common[1]} instances)")
        
        # General recommendations
        if len(findings) > 0:
            recommendations.append("Implement regular security assessments to maintain security posture")
            recommendations.append("Consider implementing automated security testing in CI/CD pipeline")
        
        return recommendations
    
    def _generate_next_steps(self, findings: List[Any]) -> List[str]:
        """Generate next steps for stakeholders."""
        next_steps = []
        
        if len(findings) > 0:
            next_steps.append("Review detailed technical report for specific remediation guidance")
            next_steps.append("Prioritize vulnerabilities based on severity and business impact")
            next_steps.append("Implement recommended security controls and patches")
            next_steps.append("Schedule follow-up assessment to verify remediation effectiveness")
        
        next_steps.append("Proceed to Stage 5: Kill Chain Analysis for advanced threat modeling")
        
        return next_steps
    
    def prepare_stage5_handoff(self, findings: List[Any]) -> Dict[str, Any]:
        """
        Prepare handoff package for Stage 5.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            Dict[str, Any]: Stage 5 handoff package
        """
        logger.info("Preparing Stage 5 handoff package...")
        
        try:
            # Generate all reports
            structured_report = self.generate_structured_report(findings)
            stakeholder_summary = self.generate_stakeholder_summary(findings)
            training_data_export = self.export_training_data(findings)
            logs_artifacts = self.compile_logs_and_artifacts()
            
            # Create handoff package
            handoff_package = {
                "handoff_metadata": {
                    "handoff_id": str(uuid.uuid4()),
                    "from_stage": "Stage 4: Vulnerability Scanning (Black-Box with AI Integration)",
                    "to_stage": "Stage 5: Kill Chain Analysis",
                    "handoff_timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": self.config.target,
                    "total_artifacts": 0  # Will be calculated
                },
                "stage4_results": {
                    "structured_report": structured_report,
                    "stakeholder_summary": stakeholder_summary,
                    "training_data_export": training_data_export,
                    "logs_and_artifacts": logs_artifacts
                },
                "stage5_inputs": {
                    "confirmed_vulnerabilities": [f for f in findings if getattr(f, 'status', '') == 'Confirmed'],
                    "high_risk_findings": [f for f in findings if getattr(f, 'ai_risk_score', 0.0) > 0.8],
                    "attack_vectors": self._extract_attack_vectors(findings),
                    "target_infrastructure": self._extract_target_infrastructure(findings),
                    "evidence_files": self._collect_evidence_files()
                },
                "recommendations": {
                    "stage5_focus_areas": self._identify_stage5_focus_areas(findings),
                    "kill_chain_priorities": self._prioritize_kill_chain_analysis(findings),
                    "threat_modeling_inputs": self._prepare_threat_modeling_inputs(findings)
                }
            }
            
            # Calculate total artifacts
            total_artifacts = 0
            if logs_artifacts:
                total_artifacts += logs_artifacts.get("statistics", {}).get("total_artifacts", 0)
            
            handoff_package["handoff_metadata"]["total_artifacts"] = total_artifacts
            
            # Save handoff package
            handoff_file = self.reports_dir / "stage5_handoff_package.json"
            with open(handoff_file, 'w') as f:
                json.dump(handoff_package, f, indent=2, default=str)
            
            logger.info(f"Stage 5 handoff package prepared: {handoff_file}")
            
            return handoff_package
            
        except Exception as e:
            logger.error(f"Error preparing Stage 5 handoff: {str(e)}")
            return {}
    
    def _extract_attack_vectors(self, findings: List[Any]) -> List[str]:
        """Extract attack vectors from findings."""
        attack_vectors = set()
        
        for finding in findings:
            vuln_type = getattr(finding, 'vulnerability_type', '')
            endpoint = getattr(finding, 'endpoint', '')
            
            if vuln_type:
                attack_vectors.add(vuln_type)
            
            if endpoint and 'api' in endpoint.lower():
                attack_vectors.add('API')
            elif endpoint and 'admin' in endpoint.lower():
                attack_vectors.add('Administrative Interface')
        
        return list(attack_vectors)
    
    def _extract_target_infrastructure(self, findings: List[Any]) -> Dict[str, Any]:
        """Extract target infrastructure information."""
        infrastructure = {
            "web_application": False,
            "api_endpoints": False,
            "network_services": False,
            "authentication_systems": False,
            "database_systems": False
        }
        
        for finding in findings:
            endpoint = getattr(finding, 'endpoint', '')
            vuln_type = getattr(finding, 'vulnerability_type', '')
            
            if endpoint:
                if 'api' in endpoint.lower():
                    infrastructure["api_endpoints"] = True
                if 'admin' in endpoint.lower() or 'login' in endpoint.lower():
                    infrastructure["authentication_systems"] = True
                if 'sql' in vuln_type.lower():
                    infrastructure["database_systems"] = True
            
            if vuln_type in ['Information Disclosure', 'Network Scanning']:
                infrastructure["network_services"] = True
            
            infrastructure["web_application"] = True  # Default assumption
        
        return infrastructure
    
    def _collect_evidence_files(self) -> List[str]:
        """Collect evidence file paths."""
        evidence_files = []
        
        evidence_dir = self.output_dir / "evidence_collection"
        if evidence_dir.exists():
            for file_path in evidence_dir.rglob("*"):
                if file_path.is_file():
                    evidence_files.append(str(file_path))
        
        return evidence_files
    
    def _identify_stage5_focus_areas(self, findings: List[Any]) -> List[str]:
        """Identify focus areas for Stage 5 analysis."""
        focus_areas = []
        
        # High severity confirmed vulnerabilities
        high_severity_confirmed = [f for f in findings 
                                 if getattr(f, 'status', '') == 'Confirmed' 
                                 and getattr(f, 'severity', '') in ['Critical', 'High']]
        
        if high_severity_confirmed:
            focus_areas.append("High-severity confirmed vulnerabilities")
        
        # Authentication bypass vulnerabilities
        auth_bypass = [f for f in findings 
                      if 'auth' in getattr(f, 'vulnerability_type', '').lower()]
        
        if auth_bypass:
            focus_areas.append("Authentication bypass vulnerabilities")
        
        # Data exposure vulnerabilities
        data_exposure = [f for f in findings 
                        if 'information' in getattr(f, 'vulnerability_type', '').lower()]
        
        if data_exposure:
            focus_areas.append("Information disclosure vulnerabilities")
        
        return focus_areas
    
    def _prioritize_kill_chain_analysis(self, findings: List[Any]) -> List[str]:
        """Prioritize kill chain analysis based on findings."""
        priorities = []
        
        # Reconnaissance phase
        if any('information' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            priorities.append("Reconnaissance: Information disclosure vulnerabilities")
        
        # Weaponization phase
        if any('injection' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            priorities.append("Weaponization: Code injection vulnerabilities")
        
        # Delivery phase
        if any('xss' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            priorities.append("Delivery: Cross-site scripting vulnerabilities")
        
        # Exploitation phase
        if any(getattr(f, 'status', '') == 'Confirmed' for f in findings):
            priorities.append("Exploitation: Confirmed vulnerabilities")
        
        return priorities
    
    def _prepare_threat_modeling_inputs(self, findings: List[Any]) -> Dict[str, Any]:
        """Prepare inputs for threat modeling."""
        threat_inputs = {
            "attack_surface": [],
            "vulnerability_vectors": [],
            "risk_actors": [],
            "impact_scenarios": []
        }
        
        # Attack surface
        endpoints = set()
        for finding in findings:
            endpoint = getattr(finding, 'endpoint', '')
            if endpoint:
                endpoints.add(endpoint)
        
        threat_inputs["attack_surface"] = list(endpoints)
        
        # Vulnerability vectors
        vuln_types = set()
        for finding in findings:
            vuln_type = getattr(finding, 'vulnerability_type', '')
            if vuln_type:
                vuln_types.add(vuln_type)
        
        threat_inputs["vulnerability_vectors"] = list(vuln_types)
        
        # Risk actors (based on vulnerability types)
        if any('sql' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            threat_inputs["risk_actors"].append("Database attackers")
        
        if any('xss' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            threat_inputs["risk_actors"].append("Web attackers")
        
        if any('auth' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            threat_inputs["risk_actors"].append("Authentication bypass attackers")
        
        # Impact scenarios
        if any(getattr(f, 'severity', '') == 'Critical' for f in findings):
            threat_inputs["impact_scenarios"].append("Critical system compromise")
        
        if any('information' in getattr(f, 'vulnerability_type', '').lower() for f in findings):
            threat_inputs["impact_scenarios"].append("Sensitive data exposure")
        
        return threat_inputs
    
    def save_results(self):
        """Save all generated outputs."""
        try:
            # Save reports metadata
            reports_metadata = {
                "generated_reports": len(self.reports),
                "generation_timestamp": datetime.now(timezone.utc).isoformat(),
                "target": self.config.target,
                "stage": self.config.stage_name,
                "output_formats": self.output_formats
            }
            
            metadata_file = self.reports_dir / "output_metadata.json"
            with open(metadata_file, 'w') as f:
                json.dump(reports_metadata, f, indent=2)
            
            logger.info(f"Output generation results saved to {self.reports_dir}")
            
        except Exception as e:
            logger.error(f"Error saving output generation results: {str(e)}") 