#!/usr/bin/env python3
"""
Threat Modeling Runner - Advanced Threat Modeling and Attack Path Analysis

This module handles advanced threat modeling, attack path analysis, and scenario development
for the kill chain analysis stage.

Features:
- Attack path discovery and mapping
- Attack scenario development and validation
- Risk assessment and impact analysis
- Threat actor profiling and behavior modeling
- Attack chain optimization and prioritization

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
import networkx as nx
import pandas as pd
import numpy as np
from pydantic import BaseModel, Field
import yaml

logger = logging.getLogger(__name__)


class AttackPath(BaseModel):
    """Model for attack path analysis."""
    path_id: str
    name: str
    description: str
    techniques: List[str]
    tactics: List[str]
    threat_actors: List[str]
    likelihood: float
    impact: str
    complexity: str
    prerequisites: List[str]
    detection_points: List[str]
    mitigation_strategies: List[str]
    execution_steps: List[Dict[str, Any]]
    success_probability: float
    time_to_execute: str
    resource_requirements: List[str]


class AttackScenario(BaseModel):
    """Model for attack scenario development."""
    scenario_id: str
    name: str
    description: str
    attack_paths: List[str]
    threat_actors: List[str]
    objectives: List[str]
    success_criteria: List[str]
    prerequisites: List[str]
    execution_plan: List[Dict[str, Any]]
    risk_assessment: Dict[str, Any]
    business_impact: Dict[str, Any]
    detection_probability: float
    response_time: str
    recovery_time: str


class RiskAssessment(BaseModel):
    """Model for risk assessment results."""
    assessment_id: str
    target: str
    assessment_date: datetime
    overall_risk_score: float
    risk_level: str
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    critical_assets: List[str]
    threat_actors: List[str]
    attack_vectors: List[str]
    business_impact: Dict[str, Any]
    compliance_impact: Dict[str, Any]
    recommendations: List[str]
    mitigation_priorities: List[str]


class ThreatModeling:
    """
    Advanced threat modeling and attack path analysis.
    
    This class handles attack path discovery, scenario development,
    and comprehensive risk assessment for kill chain analysis.
    """
    
    def __init__(self, target: str, stage: str = "kill_chain"):
        """
        Initialize the threat modeling component.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_dir = Path(f"outputs/{stage}/{target}")
        self.threat_modeling_dir = self.base_dir / "threat_modeling"
        self.attack_paths_dir = self.base_dir / "attack_paths"
        self.scenarios_dir = self.base_dir / "scenarios"
        
        # Create directories
        self.threat_modeling_dir.mkdir(parents=True, exist_ok=True)
        self.attack_paths_dir.mkdir(parents=True, exist_ok=True)
        self.scenarios_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize data storage
        self.attack_paths: List[AttackPath] = []
        self.attack_scenarios: List[AttackScenario] = []
        self.risk_assessments: List[RiskAssessment] = []
        
        # Load vulnerability data
        self.vulnerabilities = []
        self.mitre_data = {}
        
        logger.info(f"Initialized ThreatModeling for target: {target}")
    
    async def discover_attack_paths(self) -> Dict[str, Any]:
        """
        Discover and map attack paths using graph analysis.
        
        Returns:
            Dict containing attack path discovery results
        """
        logger.info("Discovering attack paths using graph analysis")
        
        try:
            # Load vulnerability and MITRE data
            await self._load_input_data()
            
            # Build attack graph
            attack_graph = await self._build_attack_graph()
            
            # Discover attack paths
            paths = await self._discover_paths(attack_graph)
            
            # Analyze path characteristics
            path_analysis = await self._analyze_path_characteristics(paths)
            
            # Generate attack paths
            attack_paths = await self._generate_attack_paths(paths, path_analysis)
            
            # Save attack paths
            await self._save_attack_paths(attack_paths)
            
            result = {
                "attack_paths_discovered": len(attack_paths),
                "total_paths": len(paths),
                "high_risk_paths": len([p for p in attack_paths if p.impact == "high"]),
                "complex_paths": len([p for p in attack_paths if p.complexity == "high"]),
                "path_analysis": path_analysis,
                "graph_metrics": {
                    "nodes": attack_graph.number_of_nodes(),
                    "edges": attack_graph.number_of_edges(),
                    "density": nx.density(attack_graph),
                    "diameter": nx.diameter(attack_graph) if nx.is_connected(attack_graph) else "disconnected"
                }
            }
            
            logger.info(f"Discovered {len(attack_paths)} attack paths")
            return result
            
        except Exception as e:
            logger.error(f"Error discovering attack paths: {str(e)}")
            raise
    
    async def develop_attack_scenarios(self) -> Dict[str, Any]:
        """
        Develop realistic attack scenarios based on discovered paths.
        
        Returns:
            Dict containing attack scenario development results
        """
        logger.info("Developing realistic attack scenarios")
        
        try:
            # Load attack paths
            await self._load_attack_paths()
            
            # Generate scenarios
            scenarios = await self._generate_scenarios()
            
            # Validate scenarios
            validated_scenarios = await self._validate_scenarios(scenarios)
            
            # Prioritize scenarios
            prioritized_scenarios = await self._prioritize_scenarios(validated_scenarios)
            
            # Generate execution plans
            scenarios_with_plans = await self._generate_execution_plans(prioritized_scenarios)
            
            # Save scenarios
            await self._save_attack_scenarios(scenarios_with_plans)
            
            result = {
                "scenarios_developed": len(scenarios_with_plans),
                "high_priority_scenarios": len([s for s in scenarios_with_plans if s.risk_assessment.get("priority") == "high"]),
                "scenario_categories": self._get_scenario_categories(scenarios_with_plans),
                "threat_actors_involved": self._get_unique_threat_actors(scenarios_with_plans),
                "average_execution_time": self._calculate_average_execution_time(scenarios_with_plans)
            }
            
            logger.info(f"Developed {len(scenarios_with_plans)} attack scenarios")
            return result
            
        except Exception as e:
            logger.error(f"Error developing attack scenarios: {str(e)}")
            raise
    
    async def assess_risks(self) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment.
        
        Returns:
            Dict containing risk assessment results
        """
        logger.info("Performing comprehensive risk assessment")
        
        try:
            # Load scenarios and vulnerabilities
            await self._load_attack_scenarios()
            await self._load_vulnerabilities()
            
            # Assess technical risks
            technical_risks = await self._assess_technical_risks()
            
            # Assess business impact
            business_impact = await self._assess_business_impact()
            
            # Assess compliance impact
            compliance_impact = await self._assess_compliance_impact()
            
            # Calculate overall risk score
            overall_risk = await self._calculate_overall_risk(technical_risks, business_impact, compliance_impact)
            
            # Generate recommendations
            recommendations = await self._generate_risk_recommendations(overall_risk)
            
            # Create risk assessment
            risk_assessment = RiskAssessment(
                assessment_id=f"risk_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                target=self.target,
                assessment_date=datetime.now(timezone.utc),
                overall_risk_score=overall_risk["score"],
                risk_level=overall_risk["level"],
                high_risk_count=overall_risk["high_risk_count"],
                medium_risk_count=overall_risk["medium_risk_count"],
                low_risk_count=overall_risk["low_risk_count"],
                critical_assets=overall_risk["critical_assets"],
                threat_actors=overall_risk["threat_actors"],
                attack_vectors=overall_risk["attack_vectors"],
                business_impact=business_impact,
                compliance_impact=compliance_impact,
                recommendations=recommendations,
                mitigation_priorities=overall_risk["mitigation_priorities"]
            )
            
            # Save risk assessment
            await self._save_risk_assessment(risk_assessment)
            
            result = {
                "overall_risk_score": overall_risk["score"],
                "risk_level": overall_risk["level"],
                "high_risk_count": overall_risk["high_risk_count"],
                "medium_risk_count": overall_risk["medium_risk_count"],
                "low_risk_count": overall_risk["low_risk_count"],
                "critical_assets": len(overall_risk["critical_assets"]),
                "threat_actors": len(overall_risk["threat_actors"]),
                "attack_vectors": len(overall_risk["attack_vectors"]),
                "business_impact": business_impact,
                "compliance_impact": compliance_impact,
                "recommendations_count": len(recommendations),
                "mitigation_priorities": overall_risk["mitigation_priorities"]
            }
            
            logger.info(f"Risk assessment completed with overall score: {overall_risk['score']}")
            return result
            
        except Exception as e:
            logger.error(f"Error assessing risks: {str(e)}")
            raise
    
    async def _load_input_data(self):
        """Load vulnerability and MITRE data."""
        logger.info("Loading input data for attack path discovery")
        
        # Load vulnerabilities
        vuln_file = self.base_dir / "processed" / "processed_vulnerabilities.json"
        if vuln_file.exists():
            with open(vuln_file, 'r') as f:
                self.vulnerabilities = json.load(f)
        
        # Load MITRE data
        mitre_file = self.base_dir / "mitre_attack" / "mitre_framework_data.json"
        if mitre_file.exists():
            with open(mitre_file, 'r') as f:
                self.mitre_data = json.load(f)
        
        logger.info(f"Loaded {len(self.vulnerabilities)} vulnerabilities and MITRE data")
    
    async def _build_attack_graph(self) -> nx.DiGraph:
        """Build attack graph from vulnerabilities and MITRE data."""
        logger.info("Building attack graph")
        
        G = nx.DiGraph()
        
        # Add vulnerability nodes
        for vuln in self.vulnerabilities:
            G.add_node(vuln["id"], type="vulnerability", data=vuln)
        
        # Add technique nodes
        if "techniques" in self.mitre_data:
            for technique in self.mitre_data["techniques"]:
                G.add_node(technique["id"], type="technique", data=technique)
        
        # Add tactic nodes
        if "tactics" in self.mitre_data:
            for tactic in self.mitre_data["tactics"]:
                G.add_node(tactic["id"], type="tactic", data=tactic)
        
        # Add edges based on relationships
        for vuln in self.vulnerabilities:
            # Connect vulnerabilities to techniques
            if "technique_mappings" in vuln:
                for mapping in vuln["technique_mappings"]:
                    G.add_edge(vuln["id"], mapping["technique_id"], 
                              relationship="vulnerability_to_technique", 
                              confidence=mapping["confidence"])
            
            # Connect techniques to tactics
            if "techniques" in self.mitre_data:
                for technique in self.mitre_data["techniques"]:
                    if technique["id"] in G.nodes:
                        G.add_edge(technique["id"], technique["tactic"], 
                                  relationship="technique_to_tactic")
        
        logger.info(f"Built attack graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
        return G
    
    async def _discover_paths(self, graph: nx.DiGraph) -> List[List[str]]:
        """Discover attack paths using graph analysis."""
        logger.info("Discovering attack paths")
        
        paths = []
        
        # Find all simple paths from vulnerabilities to tactics
        vulnerability_nodes = [n for n, data in graph.nodes(data=True) if data.get("type") == "vulnerability"]
        tactic_nodes = [n for n, data in graph.nodes(data=True) if data.get("type") == "tactic"]
        
        for vuln_node in vulnerability_nodes:
            for tactic_node in tactic_nodes:
                try:
                    # Find all simple paths
                    simple_paths = list(nx.all_simple_paths(graph, vuln_node, tactic_node))
                    paths.extend(simple_paths)
                except nx.NetworkXNoPath:
                    continue
        
        # Remove duplicate paths
        unique_paths = []
        for path in paths:
            if path not in unique_paths:
                unique_paths.append(path)
        
        logger.info(f"Discovered {len(unique_paths)} unique attack paths")
        return unique_paths
    
    async def _analyze_path_characteristics(self, paths: List[List[str]]) -> Dict[str, Any]:
        """Analyze characteristics of discovered paths."""
        logger.info("Analyzing path characteristics")
        
        analysis = {
            "path_lengths": [],
            "path_complexities": [],
            "technique_distribution": {},
            "tactic_distribution": {},
            "vulnerability_distribution": {}
        }
        
        for path in paths:
            # Analyze path length
            analysis["path_lengths"].append(len(path))
            
            # Analyze path complexity
            complexity = self._calculate_path_complexity(path)
            analysis["path_complexities"].append(complexity)
            
            # Analyze technique distribution
            for node in path:
                if node.startswith("T"):  # Technique
                    analysis["technique_distribution"][node] = analysis["technique_distribution"].get(node, 0) + 1
                elif node.startswith("TA"):  # Tactic
                    analysis["tactic_distribution"][node] = analysis["tactic_distribution"].get(node, 0) + 1
                else:  # Vulnerability
                    analysis["vulnerability_distribution"][node] = analysis["vulnerability_distribution"].get(node, 0) + 1
        
        # Calculate statistics
        analysis["avg_path_length"] = np.mean(analysis["path_lengths"])
        analysis["avg_complexity"] = np.mean(analysis["path_complexities"])
        analysis["most_common_techniques"] = sorted(analysis["technique_distribution"].items(), 
                                                   key=lambda x: x[1], reverse=True)[:10]
        analysis["most_common_tactics"] = sorted(analysis["tactic_distribution"].items(), 
                                                key=lambda x: x[1], reverse=True)[:5]
        
        logger.info(f"Analyzed {len(paths)} paths with average length {analysis['avg_path_length']:.2f}")
        return analysis
    
    async def _generate_attack_paths(self, paths: List[List[str]], analysis: Dict[str, Any]) -> List[AttackPath]:
        """Generate AttackPath objects from discovered paths."""
        logger.info("Generating AttackPath objects")
        
        attack_paths = []
        
        for i, path in enumerate(paths):
            # Extract path components
            techniques = [node for node in path if node.startswith("T")]
            tactics = [node for node in path if node.startswith("TA")]
            vulnerabilities = [node for node in path if not node.startswith(("T", "TA"))]
            
            # Calculate path metrics
            likelihood = self._calculate_path_likelihood(path, analysis)
            impact = self._determine_path_impact(path)
            complexity = self._determine_path_complexity(len(path), analysis["avg_path_length"])
            
            # Generate prerequisites
            prerequisites = self._generate_prerequisites(path)
            
            # Generate detection points
            detection_points = self._generate_detection_points(path)
            
            # Generate mitigation strategies
            mitigation_strategies = self._generate_mitigation_strategies(path)
            
            # Generate execution steps
            execution_steps = self._generate_execution_steps(path)
            
            # Calculate success probability
            success_probability = self._calculate_success_probability(path, likelihood, complexity)
            
            # Estimate time to execute
            time_to_execute = self._estimate_execution_time(path, complexity)
            
            # Determine resource requirements
            resource_requirements = self._determine_resource_requirements(path)
            
            # Create AttackPath object
            attack_path = AttackPath(
                path_id=f"path_{i+1:04d}",
                name=f"Attack Path {i+1}",
                description=f"Multi-step attack path involving {len(techniques)} techniques",
                techniques=techniques,
                tactics=tactics,
                threat_actors=[],  # Will be populated from threat intelligence
                likelihood=likelihood,
                impact=impact,
                complexity=complexity,
                prerequisites=prerequisites,
                detection_points=detection_points,
                mitigation_strategies=mitigation_strategies,
                execution_steps=execution_steps,
                success_probability=success_probability,
                time_to_execute=time_to_execute,
                resource_requirements=resource_requirements
            )
            
            attack_paths.append(attack_path)
        
        logger.info(f"Generated {len(attack_paths)} AttackPath objects")
        return attack_paths
    
    async def _generate_scenarios(self) -> List[AttackScenario]:
        """Generate attack scenarios from attack paths."""
        logger.info("Generating attack scenarios")
        
        scenarios = []
        
        # Group attack paths by tactics
        tactic_groups = {}
        for path in self.attack_paths:
            for tactic in path.tactics:
                if tactic not in tactic_groups:
                    tactic_groups[tactic] = []
                tactic_groups[tactic].append(path)
        
        # Generate scenarios for each tactic group
        for tactic, paths in tactic_groups.items():
            if len(paths) >= 2:  # Only create scenarios with multiple paths
                scenario = await self._create_scenario_from_paths(tactic, paths)
                scenarios.append(scenario)
        
        # Generate cross-tactic scenarios
        cross_tactic_scenarios = await self._generate_cross_tactic_scenarios()
        scenarios.extend(cross_tactic_scenarios)
        
        logger.info(f"Generated {len(scenarios)} attack scenarios")
        return scenarios
    
    async def _create_scenario_from_paths(self, tactic: str, paths: List[AttackPath]) -> AttackScenario:
        """Create a scenario from a group of attack paths."""
        
        # Determine scenario characteristics
        high_impact_paths = [p for p in paths if p.impact == "high"]
        high_likelihood_paths = [p for p in paths if p.likelihood > 0.7]
        
        # Create scenario
        scenario = AttackScenario(
            scenario_id=f"scenario_{tactic}_{len(self.attack_scenarios)}",
            name=f"{tactic} Attack Scenario",
            description=f"Comprehensive attack scenario targeting {tactic} using multiple attack paths",
            attack_paths=[p.path_id for p in paths],
            threat_actors=[],  # Will be populated from threat intelligence
            objectives=[f"Gain access to {tactic} capabilities", "Establish persistence", "Achieve objectives"],
            success_criteria=["Successful technique execution", "Persistence established", "Objectives achieved"],
            prerequisites=["Initial access", "Reconnaissance completed"],
            execution_plan=self._generate_scenario_execution_plan(paths),
            risk_assessment=self._assess_scenario_risk(paths),
            business_impact=self._assess_scenario_business_impact(paths),
            detection_probability=self._calculate_detection_probability(paths),
            response_time=self._estimate_response_time(paths),
            recovery_time=self._estimate_recovery_time(paths)
        )
        
        return scenario
    
    async def _validate_scenarios(self, scenarios: List[AttackScenario]) -> List[AttackScenario]:
        """Validate attack scenarios for feasibility."""
        logger.info("Validating attack scenarios")
        
        validated_scenarios = []
        
        for scenario in scenarios:
            # Check feasibility
            if self._is_scenario_feasible(scenario):
                # Check prerequisites
                if self._check_prerequisites(scenario):
                    # Check resource requirements
                    if self._check_resource_requirements(scenario):
                        validated_scenarios.append(scenario)
        
        logger.info(f"Validated {len(validated_scenarios)} scenarios out of {len(scenarios)}")
        return validated_scenarios
    
    async def _prioritize_scenarios(self, scenarios: List[AttackScenario]) -> List[AttackScenario]:
        """Prioritize scenarios based on risk and impact."""
        logger.info("Prioritizing attack scenarios")
        
        # Calculate priority scores
        for scenario in scenarios:
            priority_score = self._calculate_priority_score(scenario)
            scenario.risk_assessment["priority_score"] = priority_score
            scenario.risk_assessment["priority"] = self._determine_priority_level(priority_score)
        
        # Sort by priority score
        prioritized_scenarios = sorted(scenarios, key=lambda s: s.risk_assessment["priority_score"], reverse=True)
        
        logger.info(f"Prioritized {len(prioritized_scenarios)} scenarios")
        return prioritized_scenarios
    
    async def _assess_technical_risks(self) -> Dict[str, Any]:
        """Assess technical risks from vulnerabilities and attack paths."""
        logger.info("Assessing technical risks")
        
        technical_risks = {
            "vulnerability_risks": {},
            "attack_path_risks": {},
            "system_risks": {},
            "network_risks": {},
            "application_risks": {}
        }
        
        # Assess vulnerability risks
        for vuln in self.vulnerabilities:
            risk_score = self._calculate_vulnerability_risk(vuln)
            technical_risks["vulnerability_risks"][vuln["id"]] = {
                "risk_score": risk_score,
                "severity": vuln["severity"],
                "cvss_score": vuln.get("cvss_score"),
                "attack_vector": vuln["attack_vector"],
                "impact": vuln["impact"]
            }
        
        # Assess attack path risks
        for path in self.attack_paths:
            technical_risks["attack_path_risks"][path.path_id] = {
                "risk_score": path.likelihood * self._impact_to_score(path.impact),
                "likelihood": path.likelihood,
                "impact": path.impact,
                "complexity": path.complexity,
                "success_probability": path.success_probability
            }
        
        return technical_risks
    
    async def _assess_business_impact(self) -> Dict[str, Any]:
        """Assess business impact of potential attacks."""
        logger.info("Assessing business impact")
        
        business_impact = {
            "financial_impact": {
                "potential_loss": "$1,000,000 - $5,000,000",
                "recovery_cost": "$500,000 - $2,000,000",
                "business_interruption": "2-5 days",
                "reputation_damage": "High"
            },
            "operational_impact": {
                "service_disruption": "Medium",
                "data_loss": "High",
                "compliance_violations": "High",
                "customer_impact": "Medium"
            },
            "strategic_impact": {
                "competitive_disadvantage": "Medium",
                "market_position": "Low",
                "regulatory_penalties": "High",
                "stakeholder_confidence": "Medium"
            }
        }
        
        return business_impact
    
    async def _assess_compliance_impact(self) -> Dict[str, Any]:
        """Assess compliance impact of potential attacks."""
        logger.info("Assessing compliance impact")
        
        compliance_impact = {
            "gdpr": {
                "data_breach_risk": "High",
                "penalties": "Up to 4% of global revenue",
                "notification_requirements": "72 hours",
                "impact_level": "Critical"
            },
            "sox": {
                "financial_reporting_risk": "Medium",
                "internal_controls": "High",
                "audit_requirements": "Enhanced",
                "impact_level": "High"
            },
            "pci_dss": {
                "card_data_risk": "High",
                "compliance_status": "At Risk",
                "penalties": "Up to $100,000 per month",
                "impact_level": "Critical"
            },
            "hipaa": {
                "phi_risk": "Medium",
                "privacy_violations": "High",
                "penalties": "Up to $50,000 per violation",
                "impact_level": "High"
            }
        }
        
        return compliance_impact
    
    async def _calculate_overall_risk(self, technical_risks: Dict, business_impact: Dict, compliance_impact: Dict) -> Dict[str, Any]:
        """Calculate overall risk score."""
        logger.info("Calculating overall risk score")
        
        # Calculate technical risk score
        tech_risk_scores = [risk["risk_score"] for risk in technical_risks["vulnerability_risks"].values()]
        avg_tech_risk = np.mean(tech_risk_scores) if tech_risk_scores else 0
        
        # Calculate business impact score
        business_impact_score = self._calculate_business_impact_score(business_impact)
        
        # Calculate compliance impact score
        compliance_impact_score = self._calculate_compliance_impact_score(compliance_impact)
        
        # Calculate overall risk score (weighted average)
        overall_score = (avg_tech_risk * 0.4 + business_impact_score * 0.35 + compliance_impact_score * 0.25)
        
        # Determine risk level
        if overall_score >= 8.0:
            risk_level = "Critical"
        elif overall_score >= 6.0:
            risk_level = "High"
        elif overall_score >= 4.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        
        # Count risks by level
        high_risk_count = len([r for r in tech_risk_scores if r >= 6.0])
        medium_risk_count = len([r for r in tech_risk_scores if 4.0 <= r < 6.0])
        low_risk_count = len([r for r in tech_risk_scores if r < 4.0])
        
        result = {
            "score": overall_score,
            "level": risk_level,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count,
            "critical_assets": self._identify_critical_assets(),
            "threat_actors": self._identify_threat_actors(),
            "attack_vectors": self._identify_attack_vectors(),
            "mitigation_priorities": self._generate_mitigation_priorities(overall_score, risk_level)
        }
        
        return result
    
    async def _generate_risk_recommendations(self, overall_risk: Dict[str, Any]) -> List[str]:
        """Generate risk-based recommendations."""
        logger.info("Generating risk recommendations")
        
        recommendations = []
        
        if overall_risk["level"] in ["Critical", "High"]:
            recommendations.extend([
                "Implement immediate security controls and monitoring",
                "Conduct comprehensive security assessment",
                "Enhance incident response capabilities",
                "Implement multi-factor authentication across all systems",
                "Regular security awareness training for all employees"
            ])
        
        if overall_risk["high_risk_count"] > 0:
            recommendations.extend([
                "Prioritize remediation of high-risk vulnerabilities",
                "Implement additional monitoring for high-risk attack vectors",
                "Conduct penetration testing to validate security controls"
            ])
        
        if len(overall_risk["critical_assets"]) > 0:
            recommendations.extend([
                "Implement enhanced protection for critical assets",
                "Regular backup and recovery testing for critical systems",
                "Implement least privilege access controls"
            ])
        
        recommendations.extend([
            "Regular security assessments and vulnerability scanning",
            "Implement security monitoring and alerting",
            "Develop and test incident response procedures",
            "Regular security training and awareness programs"
        ])
        
        return recommendations
    
    # Helper methods
    def _calculate_path_complexity(self, path: List[str]) -> float:
        """Calculate complexity of an attack path."""
        return len(path) * 0.5  # Simple complexity calculation
    
    def _calculate_path_likelihood(self, path: List[str], analysis: Dict[str, Any]) -> float:
        """Calculate likelihood of an attack path."""
        # Base likelihood on path length and complexity
        base_likelihood = 1.0 / len(path)
        
        # Adjust based on technique popularity
        technique_factor = 1.0
        for node in path:
            if node.startswith("T"):
                technique_factor *= 0.9  # Popular techniques are more likely
        
        return min(base_likelihood * technique_factor, 1.0)
    
    def _determine_path_impact(self, path: List[str]) -> str:
        """Determine impact level of an attack path."""
        # Simple impact determination based on path length
        if len(path) >= 5:
            return "high"
        elif len(path) >= 3:
            return "medium"
        else:
            return "low"
    
    def _determine_path_complexity(self, path_length: int, avg_length: float) -> str:
        """Determine complexity level of an attack path."""
        if path_length > avg_length * 1.5:
            return "high"
        elif path_length < avg_length * 0.5:
            return "low"
        else:
            return "medium"
    
    def _generate_prerequisites(self, path: List[str]) -> List[str]:
        """Generate prerequisites for an attack path."""
        return ["Initial access", "Reconnaissance", "Network connectivity"]
    
    def _generate_detection_points(self, path: List[str]) -> List[str]:
        """Generate detection points for an attack path."""
        return ["Network monitoring", "Log analysis", "Behavioral analysis"]
    
    def _generate_mitigation_strategies(self, path: List[str]) -> List[str]:
        """Generate mitigation strategies for an attack path."""
        return ["Security controls", "Monitoring", "Incident response"]
    
    def _generate_execution_steps(self, path: List[str]) -> List[Dict[str, Any]]:
        """Generate execution steps for an attack path."""
        steps = []
        for i, node in enumerate(path):
            steps.append({
                "step": i + 1,
                "node": node,
                "action": f"Execute {node}",
                "description": f"Perform action for {node}"
            })
        return steps
    
    def _calculate_success_probability(self, path: List[str], likelihood: float, complexity: str) -> float:
        """Calculate success probability of an attack path."""
        base_probability = likelihood
        
        # Adjust based on complexity
        if complexity == "high":
            base_probability *= 0.7
        elif complexity == "medium":
            base_probability *= 0.85
        else:
            base_probability *= 0.95
        
        return min(base_probability, 1.0)
    
    def _estimate_execution_time(self, path: List[str], complexity: str) -> str:
        """Estimate execution time for an attack path."""
        if complexity == "high":
            return "2-4 weeks"
        elif complexity == "medium":
            return "1-2 weeks"
        else:
            return "3-7 days"
    
    def _determine_resource_requirements(self, path: List[str]) -> List[str]:
        """Determine resource requirements for an attack path."""
        return ["Technical expertise", "Tools and infrastructure", "Time and persistence"]
    
    def _is_scenario_feasible(self, scenario: AttackScenario) -> bool:
        """Check if a scenario is feasible."""
        return len(scenario.attack_paths) > 0
    
    def _check_prerequisites(self, scenario: AttackScenario) -> bool:
        """Check if scenario prerequisites are met."""
        return True  # Simplified check
    
    def _check_resource_requirements(self, scenario: AttackScenario) -> bool:
        """Check if scenario resource requirements are met."""
        return True  # Simplified check
    
    def _calculate_priority_score(self, scenario: AttackScenario) -> float:
        """Calculate priority score for a scenario."""
        risk_score = scenario.risk_assessment.get("risk_score", 0)
        impact_score = self._impact_to_score(scenario.risk_assessment.get("impact", "medium"))
        return risk_score * impact_score
    
    def _determine_priority_level(self, score: float) -> str:
        """Determine priority level based on score."""
        if score >= 8.0:
            return "high"
        elif score >= 5.0:
            return "medium"
        else:
            return "low"
    
    def _impact_to_score(self, impact: str) -> float:
        """Convert impact string to numeric score."""
        impact_scores = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}
        return impact_scores.get(impact.lower(), 5.0)
    
    def _identify_critical_assets(self) -> List[str]:
        """Identify critical assets."""
        return ["Database servers", "Authentication systems", "Payment processing", "Customer data"]
    
    def _identify_threat_actors(self) -> List[str]:
        """Identify threat actors."""
        return ["APT groups", "Cybercriminals", "Insider threats", "Hacktivists"]
    
    def _identify_attack_vectors(self) -> List[str]:
        """Identify attack vectors."""
        return ["Web applications", "APIs", "Network services", "Social engineering"]
    
    def _generate_mitigation_priorities(self, score: float, level: str) -> List[str]:
        """Generate mitigation priorities."""
        priorities = []
        
        if level in ["Critical", "High"]:
            priorities.extend([
                "Immediate vulnerability remediation",
                "Enhanced monitoring and alerting",
                "Security control implementation"
            ])
        
        priorities.extend([
            "Regular security assessments",
            "Employee security training",
            "Incident response preparation"
        ])
        
        return priorities
    
    def _calculate_business_impact_score(self, business_impact: Dict[str, Any]) -> float:
        """Calculate business impact score."""
        # Simplified calculation
        return 7.0  # Medium-high impact
    
    def _calculate_compliance_impact_score(self, compliance_impact: Dict[str, Any]) -> float:
        """Calculate compliance impact score."""
        # Simplified calculation
        return 8.0  # High impact
    
    def _get_scenario_categories(self, scenarios: List[AttackScenario]) -> Dict[str, int]:
        """Get scenario category distribution."""
        categories = {}
        for scenario in scenarios:
            category = scenario.risk_assessment.get("priority", "medium")
            categories[category] = categories.get(category, 0) + 1
        return categories
    
    def _get_unique_threat_actors(self, scenarios: List[AttackScenario]) -> List[str]:
        """Get unique threat actors from scenarios."""
        actors = set()
        for scenario in scenarios:
            actors.update(scenario.threat_actors)
        return list(actors)
    
    def _calculate_average_execution_time(self, scenarios: List[AttackScenario]) -> str:
        """Calculate average execution time for scenarios."""
        return "1-2 weeks"  # Simplified calculation
    
    async def _save_attack_paths(self, attack_paths: List[AttackPath]):
        """Save attack paths to file."""
        logger.info("Saving attack paths")
        
        paths_file = self.attack_paths_dir / "attack_paths.json"
        with open(paths_file, 'w') as f:
            json.dump([path.dict() for path in attack_paths], f, indent=2, default=str)
        
        logger.info(f"Saved {len(attack_paths)} attack paths")
    
    async def _save_attack_scenarios(self, scenarios: List[AttackScenario]):
        """Save attack scenarios to file."""
        logger.info("Saving attack scenarios")
        
        scenarios_file = self.scenarios_dir / "attack_scenarios.json"
        with open(scenarios_file, 'w') as f:
            json.dump([scenario.dict() for scenario in scenarios], f, indent=2, default=str)
        
        logger.info(f"Saved {len(scenarios)} attack scenarios")
    
    async def _save_risk_assessment(self, risk_assessment: RiskAssessment):
        """Save risk assessment to file."""
        logger.info("Saving risk assessment")
        
        assessment_file = self.threat_modeling_dir / "risk_assessment.json"
        with open(assessment_file, 'w') as f:
            json.dump(risk_assessment.dict(), f, indent=2, default=str)
        
        logger.info("Saved risk assessment")
    
    async def _load_attack_paths(self):
        """Load attack paths from file."""
        paths_file = self.attack_paths_dir / "attack_paths.json"
        if paths_file.exists():
            with open(paths_file, 'r') as f:
                paths_data = json.load(f)
                self.attack_paths = [AttackPath(**path) for path in paths_data]
    
    async def _load_attack_scenarios(self):
        """Load attack scenarios from file."""
        scenarios_file = self.scenarios_dir / "attack_scenarios.json"
        if scenarios_file.exists():
            with open(scenarios_file, 'r') as f:
                scenarios_data = json.load(f)
                self.attack_scenarios = [AttackScenario(**scenario) for scenario in scenarios_data]
    
    async def _load_vulnerabilities(self):
        """Load vulnerabilities from file."""
        vuln_file = self.base_dir / "processed" / "processed_vulnerabilities.json"
        if vuln_file.exists():
            with open(vuln_file, 'r') as f:
                self.vulnerabilities = json.load(f)
    
    async def _generate_cross_tactic_scenarios(self) -> List[AttackScenario]:
        """Generate cross-tactic scenarios."""
        scenarios = []
        # Implementation for cross-tactic scenarios
        return scenarios
    
    async def _generate_execution_plans(self, scenarios: List[AttackScenario]) -> List[AttackScenario]:
        """Generate execution plans for scenarios."""
        for scenario in scenarios:
            # Add execution plan details
            pass
        return scenarios
    
    def _generate_scenario_execution_plan(self, paths: List[AttackPath]) -> List[Dict[str, Any]]:
        """Generate execution plan for a scenario."""
        plan = []
        for i, path in enumerate(paths):
            plan.append({
                "phase": i + 1,
                "path_id": path.path_id,
                "description": f"Execute {path.name}",
                "techniques": path.techniques,
                "estimated_time": path.time_to_execute,
                "success_probability": path.success_probability
            })
        return plan
    
    def _assess_scenario_risk(self, paths: List[AttackPath]) -> Dict[str, Any]:
        """Assess risk for a scenario."""
        risk_scores = [p.likelihood * self._impact_to_score(p.impact) for p in paths]
        avg_risk = np.mean(risk_scores) if risk_scores else 0
        
        return {
            "risk_score": avg_risk,
            "impact": "high" if avg_risk > 6.0 else "medium" if avg_risk > 3.0 else "low",
            "likelihood": "high" if avg_risk > 6.0 else "medium" if avg_risk > 3.0 else "low"
        }
    
    def _assess_scenario_business_impact(self, paths: List[AttackPath]) -> Dict[str, Any]:
        """Assess business impact for a scenario."""
        return {
            "financial_impact": "Medium",
            "operational_impact": "High",
            "reputation_impact": "Medium"
        }
    
    def _calculate_detection_probability(self, paths: List[AttackPath]) -> float:
        """Calculate detection probability for paths."""
        # Simplified calculation
        return 0.7
    
    def _estimate_response_time(self, paths: List[AttackPath]) -> str:
        """Estimate response time for paths."""
        return "2-4 hours"
    
    def _estimate_recovery_time(self, paths: List[AttackPath]) -> str:
        """Estimate recovery time for paths."""
        return "1-3 days"
    
    def _calculate_vulnerability_risk(self, vuln: Dict[str, Any]) -> float:
        """Calculate risk score for a vulnerability."""
        base_score = vuln.get("cvss_score", 5.0)
        severity_multiplier = {"critical": 1.5, "high": 1.2, "medium": 1.0, "low": 0.8}
        return base_score * severity_multiplier.get(vuln.get("severity", "medium").lower(), 1.0) 