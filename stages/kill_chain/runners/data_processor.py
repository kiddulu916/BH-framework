#!/usr/bin/env python3
"""
Data Processor Runner - Vulnerability Data Processing and Threat Intelligence Integration

This module handles the processing and enrichment of vulnerability testing results,
integration of threat intelligence feeds, and preparation of data for kill chain analysis.

Features:
- Vulnerability data processing and categorization
- Threat intelligence feed integration
- Data enrichment and correlation
- Asset criticality assessment
- Business impact analysis

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
import aiohttp
import pandas as pd
import numpy as np
from pydantic import BaseModel, Field
import yaml

logger = logging.getLogger(__name__)


class VulnerabilityData(BaseModel):
    """Model for vulnerability data structure."""
    id: str
    title: str
    description: str
    severity: str
    cvss_score: Optional[float]
    cve_id: Optional[str]
    cwe_id: Optional[str]
    location: str
    evidence: Dict[str, Any]
    status: str
    discovered_at: datetime
    category: str
    attack_vector: str
    impact: str
    remediation: str


class ThreatIntelligence(BaseModel):
    """Model for threat intelligence data."""
    source: str
    threat_actor: Optional[str]
    technique_id: Optional[str]
    tactic_id: Optional[str]
    confidence: float
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    description: str
    indicators: List[Dict[str, Any]]
    references: List[str]


class AssetCriticality(BaseModel):
    """Model for asset criticality assessment."""
    asset_id: str
    asset_name: str
    asset_type: str
    business_value: str
    data_classification: str
    compliance_requirements: List[str]
    recovery_time_objective: str
    recovery_point_objective: str
    criticality_score: float


class DataProcessor:
    """
    Data processor for vulnerability testing results and threat intelligence integration.
    
    This class handles the processing and enrichment of vulnerability data,
    integration of threat intelligence feeds, and preparation of data for
    advanced kill chain analysis.
    """
    
    def __init__(self, target: str, stage: str = "kill_chain"):
        """
        Initialize the data processor.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_dir = Path(f"outputs/{stage}/{target}")
        self.processed_dir = self.base_dir / "processed"
        self.threat_intel_dir = self.base_dir / "threat_intelligence"
        
        # Create directories
        self.processed_dir.mkdir(parents=True, exist_ok=True)
        self.threat_intel_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize data storage
        self.vulnerabilities: List[VulnerabilityData] = []
        self.threat_intelligence: List[ThreatIntelligence] = []
        self.assets: List[AssetCriticality] = []
        
        logger.info(f"Initialized DataProcessor for target: {target}")
    
    async def process_vulnerability_data(self) -> Dict[str, Any]:
        """
        Process vulnerability testing results from previous stages.
        
        Returns:
            Dict containing processed vulnerability data and statistics
        """
        logger.info("Processing vulnerability testing results")
        
        try:
            # Load vulnerability data from previous stages
            vuln_data = await self._load_vulnerability_data()
            
            # Process and categorize vulnerabilities
            processed_vulns = await self._process_vulnerabilities(vuln_data)
            
            # Enrich with additional context
            enriched_vulns = await self._enrich_vulnerability_data(processed_vulns)
            
            # Categorize by attack vectors and impact
            categorized_vulns = await self._categorize_vulnerabilities(enriched_vulns)
            
            # Generate statistics and metrics
            statistics = await self._generate_vulnerability_statistics(categorized_vulns)
            
            # Save processed data
            await self._save_processed_data(categorized_vulns, statistics)
            
            result = {
                "vulnerabilities_processed": len(categorized_vulns),
                "statistics": statistics,
                "categories": self._get_vulnerability_categories(categorized_vulns),
                "severity_distribution": self._get_severity_distribution(categorized_vulns),
                "attack_vectors": self._get_attack_vectors(categorized_vulns)
            }
            
            logger.info(f"Processed {len(categorized_vulns)} vulnerabilities")
            return result
            
        except Exception as e:
            logger.error(f"Error processing vulnerability data: {str(e)}")
            raise
    
    async def integrate_threat_intelligence(self) -> Dict[str, Any]:
        """
        Integrate threat intelligence feeds and correlate with vulnerabilities.
        
        Returns:
            Dict containing threat intelligence data and correlations
        """
        logger.info("Integrating threat intelligence feeds")
        
        try:
            # Load threat intelligence feeds
            threat_feeds = await self._load_threat_intelligence_feeds()
            
            # Correlate with vulnerabilities
            correlations = await self._correlate_threat_intelligence(threat_feeds)
            
            # Analyze threat actors and TTPs
            threat_analysis = await self._analyze_threat_actors(correlations)
            
            # Generate threat landscape
            threat_landscape = await self._generate_threat_landscape(threat_analysis)
            
            # Save threat intelligence data
            await self._save_threat_intelligence(threat_analysis, threat_landscape)
            
            result = {
                "threat_feeds_processed": len(threat_feeds),
                "correlations_found": len(correlations),
                "threat_actors_identified": len(threat_analysis.get("threat_actors", [])),
                "techniques_mapped": len(threat_analysis.get("techniques", [])),
                "threat_landscape": threat_landscape
            }
            
            logger.info(f"Integrated {len(threat_feeds)} threat intelligence feeds")
            return result
            
        except Exception as e:
            logger.error(f"Error integrating threat intelligence: {str(e)}")
            raise
    
    async def _load_vulnerability_data(self) -> List[Dict[str, Any]]:
        """Load vulnerability data from previous stages."""
        logger.info("Loading vulnerability data from previous stages")
        
        vuln_data = []
        
        # Check for vulnerability testing results
        vuln_test_dir = Path(f"outputs/vuln_test/{self.target}")
        if vuln_test_dir.exists():
            # Load from vulnerability testing stage
            results_file = vuln_test_dir / "vuln_test_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    data = json.load(f)
                    vuln_data.extend(data.get("findings", []))
        
        # Check for vulnerability scanning results
        vuln_scan_dir = Path(f"outputs/vuln_scan/{self.target}")
        if vuln_scan_dir.exists():
            # Load from vulnerability scanning stage
            results_file = vuln_scan_dir / "vuln_scan_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    data = json.load(f)
                    vuln_data.extend(data.get("vulnerabilities", []))
        
        logger.info(f"Loaded {len(vuln_data)} vulnerability records")
        return vuln_data
    
    async def _process_vulnerabilities(self, vuln_data: List[Dict[str, Any]]) -> List[VulnerabilityData]:
        """Process and validate vulnerability data."""
        logger.info("Processing and validating vulnerability data")
        
        processed_vulns = []
        
        for vuln in vuln_data:
            try:
                # Create VulnerabilityData object
                vuln_obj = VulnerabilityData(
                    id=vuln.get("id", f"vuln_{len(processed_vulns)}"),
                    title=vuln.get("title", "Unknown Vulnerability"),
                    description=vuln.get("description", ""),
                    severity=vuln.get("severity", "medium"),
                    cvss_score=vuln.get("cvss_score"),
                    cve_id=vuln.get("cve_id"),
                    cwe_id=vuln.get("cwe_id"),
                    location=vuln.get("location", ""),
                    evidence=vuln.get("evidence", {}),
                    status=vuln.get("status", "confirmed"),
                    discovered_at=datetime.fromisoformat(vuln.get("discovered_at", datetime.now().isoformat())),
                    category=vuln.get("category", "unknown"),
                    attack_vector=vuln.get("attack_vector", "unknown"),
                    impact=vuln.get("impact", "unknown"),
                    remediation=vuln.get("remediation", "")
                )
                processed_vulns.append(vuln_obj)
                
            except Exception as e:
                logger.warning(f"Error processing vulnerability {vuln.get('id', 'unknown')}: {str(e)}")
                continue
        
        logger.info(f"Processed {len(processed_vulns)} vulnerabilities")
        return processed_vulns
    
    async def _enrich_vulnerability_data(self, vulns: List[VulnerabilityData]) -> List[VulnerabilityData]:
        """Enrich vulnerability data with additional context."""
        logger.info("Enriching vulnerability data with additional context")
        
        enriched_vulns = []
        
        for vuln in vulns:
            # Enrich with CVE information if available
            if vuln.cve_id:
                cve_info = await self._get_cve_information(vuln.cve_id)
                if cve_info:
                    # Update vulnerability with CVE information
                    vuln.description = cve_info.get("description", vuln.description)
                    vuln.cvss_score = cve_info.get("cvss_score", vuln.cvss_score)
            
            # Enrich with CWE information if available
            if vuln.cwe_id:
                cwe_info = await self._get_cwe_information(vuln.cwe_id)
                if cwe_info:
                    # Update vulnerability with CWE information
                    vuln.category = cwe_info.get("category", vuln.category)
                    vuln.remediation = cwe_info.get("remediation", vuln.remediation)
            
            # Calculate risk score
            risk_score = await self._calculate_risk_score(vuln)
            vuln.impact = self._determine_impact_level(risk_score)
            
            enriched_vulns.append(vuln)
        
        logger.info(f"Enriched {len(enriched_vulns)} vulnerabilities")
        return enriched_vulns
    
    async def _categorize_vulnerabilities(self, vulns: List[VulnerabilityData]) -> List[VulnerabilityData]:
        """Categorize vulnerabilities by type, severity, and attack vector."""
        logger.info("Categorizing vulnerabilities")
        
        for vuln in vulns:
            # Categorize by OWASP Top 10
            vuln.category = await self._categorize_owasp_top10(vuln)
            
            # Categorize by attack vector
            vuln.attack_vector = await self._categorize_attack_vector(vuln)
            
            # Categorize by impact
            vuln.impact = await self._categorize_impact(vuln)
        
        logger.info(f"Categorized {len(vulns)} vulnerabilities")
        return vulns
    
    async def _generate_vulnerability_statistics(self, vulns: List[VulnerabilityData]) -> Dict[str, Any]:
        """Generate comprehensive vulnerability statistics."""
        logger.info("Generating vulnerability statistics")
        
        stats = {
            "total_vulnerabilities": len(vulns),
            "severity_distribution": {},
            "category_distribution": {},
            "attack_vector_distribution": {},
            "impact_distribution": {},
            "cvss_score_distribution": {},
            "cve_coverage": 0,
            "cwe_coverage": 0,
            "high_risk_count": 0,
            "critical_count": 0
        }
        
        # Calculate distributions
        for vuln in vulns:
            # Severity distribution
            severity = vuln.severity.lower()
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1
            
            # Category distribution
            category = vuln.category
            stats["category_distribution"][category] = stats["category_distribution"].get(category, 0) + 1
            
            # Attack vector distribution
            attack_vector = vuln.attack_vector
            stats["attack_vector_distribution"][attack_vector] = stats["attack_vector_distribution"].get(attack_vector, 0) + 1
            
            # Impact distribution
            impact = vuln.impact
            stats["impact_distribution"][impact] = stats["impact_distribution"].get(impact, 0) + 1
            
            # CVSS score distribution
            if vuln.cvss_score:
                cvss_range = self._get_cvss_range(vuln.cvss_score)
                stats["cvss_score_distribution"][cvss_range] = stats["cvss_score_distribution"].get(cvss_range, 0) + 1
            
            # CVE/CWE coverage
            if vuln.cve_id:
                stats["cve_coverage"] += 1
            if vuln.cwe_id:
                stats["cwe_coverage"] += 1
            
            # High risk and critical counts
            if vuln.severity.lower() in ["high", "critical"]:
                stats["high_risk_count"] += 1
            if vuln.severity.lower() == "critical":
                stats["critical_count"] += 1
        
        # Calculate percentages
        total = len(vulns)
        if total > 0:
            stats["cve_coverage_percentage"] = (stats["cve_coverage"] / total) * 100
            stats["cwe_coverage_percentage"] = (stats["cwe_coverage"] / total) * 100
        
        logger.info(f"Generated statistics for {len(vulns)} vulnerabilities")
        return stats
    
    async def _load_threat_intelligence_feeds(self) -> List[Dict[str, Any]]:
        """Load threat intelligence feeds from various sources."""
        logger.info("Loading threat intelligence feeds")
        
        feeds = []
        
        # Load from local threat intelligence files
        threat_files = [
            "cve_database.json",
            "threat_actors.json", 
            "attack_patterns.json",
            "malware_families.json"
        ]
        
        for file_name in threat_files:
            file_path = self.threat_intel_dir / file_name
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        feeds.extend(data)
                except Exception as e:
                    logger.warning(f"Error loading {file_name}: {str(e)}")
        
        # Load from online sources (if configured)
        online_feeds = await self._load_online_threat_feeds()
        feeds.extend(online_feeds)
        
        logger.info(f"Loaded {len(feeds)} threat intelligence records")
        return feeds
    
    async def _correlate_threat_intelligence(self, feeds: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate threat intelligence with vulnerabilities."""
        logger.info("Correlating threat intelligence with vulnerabilities")
        
        correlations = []
        
        for vuln in self.vulnerabilities:
            vuln_correlations = []
            
            for feed in feeds:
                # Check for CVE correlation
                if vuln.cve_id and feed.get("cve_id") == vuln.cve_id:
                    vuln_correlations.append({
                        "type": "cve_correlation",
                        "feed": feed,
                        "confidence": 0.9
                    })
                
                # Check for technique correlation
                if feed.get("technique_id") and self._check_technique_correlation(vuln, feed):
                    vuln_correlations.append({
                        "type": "technique_correlation",
                        "feed": feed,
                        "confidence": 0.7
                    })
                
                # Check for threat actor correlation
                if feed.get("threat_actor") and self._check_threat_actor_correlation(vuln, feed):
                    vuln_correlations.append({
                        "type": "threat_actor_correlation",
                        "feed": feed,
                        "confidence": 0.6
                    })
            
            if vuln_correlations:
                correlations.append({
                    "vulnerability_id": vuln.id,
                    "correlations": vuln_correlations
                })
        
        logger.info(f"Found {len(correlations)} threat intelligence correlations")
        return correlations
    
    async def _analyze_threat_actors(self, correlations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze threat actors and their TTPs."""
        logger.info("Analyzing threat actors and TTPs")
        
        threat_actors = {}
        techniques = {}
        tactics = {}
        
        for correlation in correlations:
            for corr in correlation["correlations"]:
                feed = corr["feed"]
                
                # Analyze threat actors
                if "threat_actor" in feed:
                    actor = feed["threat_actor"]
                    if actor not in threat_actors:
                        threat_actors[actor] = {
                            "name": actor,
                            "techniques": set(),
                            "tactics": set(),
                            "vulnerabilities": set(),
                            "confidence": 0.0
                        }
                    
                    threat_actors[actor]["vulnerabilities"].add(correlation["vulnerability_id"])
                    threat_actors[actor]["confidence"] = max(
                        threat_actors[actor]["confidence"], 
                        corr["confidence"]
                    )
                
                # Analyze techniques
                if "technique_id" in feed:
                    technique = feed["technique_id"]
                    if technique not in techniques:
                        techniques[technique] = {
                            "id": technique,
                            "name": feed.get("technique_name", ""),
                            "tactic": feed.get("tactic_id", ""),
                            "vulnerabilities": set(),
                            "threat_actors": set()
                        }
                    
                    techniques[technique]["vulnerabilities"].add(correlation["vulnerability_id"])
                    if "threat_actor" in feed:
                        techniques[technique]["threat_actors"].add(feed["threat_actor"])
                
                # Analyze tactics
                if "tactic_id" in feed:
                    tactic = feed["tactic_id"]
                    if tactic not in tactics:
                        tactics[tactic] = {
                            "id": tactic,
                            "name": feed.get("tactic_name", ""),
                            "techniques": set(),
                            "vulnerabilities": set()
                        }
                    
                    tactics[tactic]["vulnerabilities"].add(correlation["vulnerability_id"])
                    if "technique_id" in feed:
                        tactics[tactic]["techniques"].add(feed["technique_id"])
        
        # Convert sets to lists for JSON serialization
        for actor in threat_actors.values():
            actor["techniques"] = list(actor["techniques"])
            actor["tactics"] = list(actor["tactics"])
            actor["vulnerabilities"] = list(actor["vulnerabilities"])
        
        for technique in techniques.values():
            technique["vulnerabilities"] = list(technique["vulnerabilities"])
            technique["threat_actors"] = list(technique["threat_actors"])
        
        for tactic in tactics.values():
            tactic["techniques"] = list(tactic["techniques"])
            tactic["vulnerabilities"] = list(tactic["vulnerabilities"])
        
        analysis = {
            "threat_actors": list(threat_actors.values()),
            "techniques": list(techniques.values()),
            "tactics": list(tactics.values()),
            "total_actors": len(threat_actors),
            "total_techniques": len(techniques),
            "total_tactics": len(tactics)
        }
        
        logger.info(f"Analyzed {len(threat_actors)} threat actors, {len(techniques)} techniques, {len(tactics)} tactics")
        return analysis
    
    async def _generate_threat_landscape(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive threat landscape."""
        logger.info("Generating threat landscape")
        
        landscape = {
            "overview": {
                "total_threat_actors": analysis["total_actors"],
                "total_techniques": analysis["total_techniques"],
                "total_tactics": analysis["total_tactics"],
                "total_vulnerabilities": len(self.vulnerabilities),
                "risk_level": self._calculate_overall_risk_level(analysis)
            },
            "threat_actors": analysis["threat_actors"],
            "techniques": analysis["techniques"],
            "tactics": analysis["tactics"],
            "risk_assessment": await self._assess_threat_risk(analysis),
            "recommendations": await self._generate_threat_recommendations(analysis)
        }
        
        logger.info("Generated comprehensive threat landscape")
        return landscape
    
    async def _save_processed_data(self, vulns: List[VulnerabilityData], stats: Dict[str, Any]):
        """Save processed vulnerability data."""
        logger.info("Saving processed vulnerability data")
        
        # Save vulnerabilities
        vuln_file = self.processed_dir / "processed_vulnerabilities.json"
        with open(vuln_file, 'w') as f:
            json.dump([vuln.dict() for vuln in vulns], f, indent=2, default=str)
        
        # Save statistics
        stats_file = self.processed_dir / "vulnerability_statistics.json"
        with open(stats_file, 'w') as f:
            json.dump(stats, f, indent=2, default=str)
        
        logger.info(f"Saved processed data to {self.processed_dir}")
    
    async def _save_threat_intelligence(self, analysis: Dict[str, Any], landscape: Dict[str, Any]):
        """Save threat intelligence data."""
        logger.info("Saving threat intelligence data")
        
        # Save threat analysis
        analysis_file = self.threat_intel_dir / "threat_analysis.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        # Save threat landscape
        landscape_file = self.threat_intel_dir / "threat_landscape.json"
        with open(landscape_file, 'w') as f:
            json.dump(landscape, f, indent=2, default=str)
        
        logger.info(f"Saved threat intelligence data to {self.threat_intel_dir}")
    
    # Helper methods
    async def _get_cve_information(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE information from NVD or local cache."""
        # Implementation would fetch from NVD API or local cache
        return None
    
    async def _get_cwe_information(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get CWE information from MITRE or local cache."""
        # Implementation would fetch from MITRE API or local cache
        return None
    
    async def _calculate_risk_score(self, vuln: VulnerabilityData) -> float:
        """Calculate risk score for vulnerability."""
        base_score = 0.0
        
        # Base score from CVSS
        if vuln.cvss_score:
            base_score = vuln.cvss_score
        
        # Adjust based on factors
        if vuln.severity.lower() == "critical":
            base_score += 2.0
        elif vuln.severity.lower() == "high":
            base_score += 1.0
        
        return min(base_score, 10.0)
    
    def _determine_impact_level(self, risk_score: float) -> str:
        """Determine impact level based on risk score."""
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"
    
    async def _categorize_owasp_top10(self, vuln: VulnerabilityData) -> str:
        """Categorize vulnerability by OWASP Top 10."""
        # Implementation would map vulnerability to OWASP Top 10 categories
        return vuln.category
    
    async def _categorize_attack_vector(self, vuln: VulnerabilityData) -> str:
        """Categorize vulnerability by attack vector."""
        # Implementation would determine attack vector
        return vuln.attack_vector
    
    async def _categorize_impact(self, vuln: VulnerabilityData) -> str:
        """Categorize vulnerability by impact."""
        # Implementation would determine impact
        return vuln.impact
    
    def _get_cvss_range(self, cvss_score: float) -> str:
        """Get CVSS score range."""
        if cvss_score >= 9.0:
            return "9.0-10.0"
        elif cvss_score >= 7.0:
            return "7.0-8.9"
        elif cvss_score >= 4.0:
            return "4.0-6.9"
        else:
            return "0.0-3.9"
    
    async def _load_online_threat_feeds(self) -> List[Dict[str, Any]]:
        """Load threat intelligence from online sources."""
        # Implementation would fetch from various online sources
        return []
    
    def _check_technique_correlation(self, vuln: VulnerabilityData, feed: Dict[str, Any]) -> bool:
        """Check if vulnerability correlates with technique."""
        # Implementation would check technique correlation
        return False
    
    def _check_threat_actor_correlation(self, vuln: VulnerabilityData, feed: Dict[str, Any]) -> bool:
        """Check if vulnerability correlates with threat actor."""
        # Implementation would check threat actor correlation
        return False
    
    def _calculate_overall_risk_level(self, analysis: Dict[str, Any]) -> str:
        """Calculate overall risk level."""
        # Implementation would calculate overall risk
        return "medium"
    
    async def _assess_threat_risk(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess threat risk levels."""
        # Implementation would assess threat risk
        return {"overall_risk": "medium"}
    
    async def _generate_threat_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate threat-based recommendations."""
        # Implementation would generate recommendations
        return ["Implement additional monitoring", "Enhance security controls"]
    
    def _get_vulnerability_categories(self, vulns: List[VulnerabilityData]) -> Dict[str, int]:
        """Get vulnerability category distribution."""
        categories = {}
        for vuln in vulns:
            categories[vuln.category] = categories.get(vuln.category, 0) + 1
        return categories
    
    def _get_severity_distribution(self, vulns: List[VulnerabilityData]) -> Dict[str, int]:
        """Get vulnerability severity distribution."""
        severity = {}
        for vuln in vulns:
            severity[vuln.severity] = severity.get(vuln.severity, 0) + 1
        return severity
    
    def _get_attack_vectors(self, vulns: List[VulnerabilityData]) -> Dict[str, int]:
        """Get vulnerability attack vector distribution."""
        vectors = {}
        for vuln in vulns:
            vectors[vuln.attack_vector] = vectors.get(vuln.attack_vector, 0) + 1
        return vectors 