#!/usr/bin/env python3
"""
MITRE ATT&CK Integration Runner - Framework Setup and Technique Mapping

This module handles the integration with MITRE ATT&CK framework, including
technique mapping, tactic progression analysis, and attack path development.

Features:
- MITRE ATT&CK framework setup and initialization
- Technique mapping for vulnerability findings
- Tactic progression analysis and attack path mapping
- Technique relationship mapping and dependency analysis
- Attack chain development using ATT&CK techniques

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
import networkx as nx
from pydantic import BaseModel, Field
import yaml

# MITRE ATT&CK imports
try:
    from attackcti import attack_client
    from stix2 import AttackPattern, ThreatActor, Campaign, Malware, Tool
    from taxii2client import Collection
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("MITRE ATT&CK libraries not available, using mock data")

logger = logging.getLogger(__name__)


class ATTACKTechnique(BaseModel):
    """Model for MITRE ATT&CK technique."""
    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: List[str] = []
    platforms: List[str] = []
    permissions_required: List[str] = []
    data_sources: List[str] = []
    detection: List[str] = []
    mitigation: List[str] = []
    examples: List[Dict[str, Any]] = []


class ATTACKTactic(BaseModel):
    """Model for MITRE ATT&CK tactic."""
    tactic_id: str
    name: str
    description: str
    techniques: List[str] = []
    shortname: str = ""


class ATTACKThreatActor(BaseModel):
    """Model for MITRE ATT&CK threat actor."""
    actor_id: str
    name: str
    description: str
    aliases: List[str] = []
    techniques: List[str] = []
    tactics: List[str] = []
    malware: List[str] = []
    tools: List[str] = []
    campaigns: List[str] = []


class TechniqueMapping(BaseModel):
    """Model for technique to vulnerability mapping."""
    vulnerability_id: str
    technique_id: str
    confidence: float
    evidence: str
    mapping_type: str  # direct, indirect, inferred
    attack_vector: str
    impact: str


class AttackPath(BaseModel):
    """Model for attack path using ATT&CK techniques."""
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


class MITREAttackIntegration:
    """
    MITRE ATT&CK framework integration for kill chain analysis.
    
    This class handles the integration with MITRE ATT&CK framework,
    technique mapping, and attack path development.
    """
    
    def __init__(self, target: str, stage: str = "kill_chain"):
        """
        Initialize the MITRE ATT&CK integration.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_dir = Path(f"outputs/{stage}/{target}")
        self.mitre_dir = self.base_dir / "mitre_attack"
        
        # Create directories
        self.mitre_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize ATT&CK client
        self.attack_client = None
        self.techniques: Dict[str, ATTACKTechnique] = {}
        self.tactics: Dict[str, ATTACKTactic] = {}
        self.threat_actors: Dict[str, ATTACKThreatActor] = {}
        
        # Initialize attack graph
        self.attack_graph = nx.DiGraph()
        
        logger.info(f"Initialized MITRE ATT&CK Integration for target: {target}")
    
    async def setup_framework(self) -> Dict[str, Any]:
        """
        Set up MITRE ATT&CK framework and load data.
        
        Returns:
            Dict containing framework setup results
        """
        logger.info("Setting up MITRE ATT&CK framework")
        
        try:
            # Initialize ATT&CK client
            await self._initialize_attack_client()
            
            # Load ATT&CK data
            await self._load_attack_data()
            
            # Build attack graph
            await self._build_attack_graph()
            
            # Generate technique mappings
            technique_mappings = await self._generate_technique_mappings()
            
            # Analyze tactic progression
            tactic_progression = await self._analyze_tactic_progression()
            
            # Save framework data
            await self._save_framework_data()
            
            result = {
                "framework_initialized": True,
                "techniques_loaded": len(self.techniques),
                "tactics_loaded": len(self.tactics),
                "threat_actors_loaded": len(self.threat_actors),
                "technique_mappings": len(technique_mappings),
                "attack_paths_generated": len(tactic_progression.get("attack_paths", [])),
                "graph_nodes": self.attack_graph.number_of_nodes(),
                "graph_edges": self.attack_graph.number_of_edges()
            }
            
            logger.info(f"MITRE ATT&CK framework setup completed with {len(self.techniques)} techniques")
            return result
            
        except Exception as e:
            logger.error(f"Error setting up MITRE ATT&CK framework: {str(e)}")
            raise
    
    async def _initialize_attack_client(self):
        """Initialize the ATT&CK client."""
        logger.info("Initializing ATT&CK client")
        
        try:
            # Try to initialize the attack client
            self.attack_client = attack_client()
            logger.info("ATT&CK client initialized successfully")
        except Exception as e:
            logger.warning(f"Could not initialize ATT&CK client: {str(e)}")
            logger.info("Using mock ATT&CK data for development")
            await self._load_mock_attack_data()
    
    async def _load_attack_data(self):
        """Load ATT&CK techniques, tactics, and threat actors."""
        logger.info("Loading ATT&CK data")
        
        if self.attack_client:
            await self._load_live_attack_data()
        else:
            await self._load_mock_attack_data()
        
        logger.info(f"Loaded {len(self.techniques)} techniques, {len(self.tactics)} tactics, {len(self.threat_actors)} threat actors")
    
    async def _load_live_attack_data(self):
        """Load live ATT&CK data from MITRE."""
        logger.info("Loading live ATT&CK data")
        
        try:
            # Load techniques
            techniques = self.attack_client.get_techniques()
            for technique in techniques:
                tech_obj = ATTACKTechnique(
                    technique_id=technique.get("external_references", [{}])[0].get("external_id", ""),
                    name=technique.get("name", ""),
                    description=technique.get("description", ""),
                    tactic=technique.get("kill_chain_phases", [{}])[0].get("phase_name", ""),
                    platforms=technique.get("x_mitre_platforms", []),
                    permissions_required=technique.get("x_mitre_permissions_required", []),
                    data_sources=technique.get("x_mitre_data_sources", []),
                    detection=technique.get("x_mitre_detection", []),
                    mitigation=technique.get("x_mitre_mitigation", [])
                )
                self.techniques[tech_obj.technique_id] = tech_obj
            
            # Load tactics
            tactics = self.attack_client.get_tactics()
            for tactic in tactics:
                tactic_obj = ATTACKTactic(
                    tactic_id=tactic.get("external_references", [{}])[0].get("external_id", ""),
                    name=tactic.get("name", ""),
                    description=tactic.get("description", ""),
                    shortname=tactic.get("x_mitre_shortname", "")
                )
                self.tactics[tactic_obj.tactic_id] = tactic_obj
            
            # Load threat actors
            actors = self.attack_client.get_threat_actors()
            for actor in actors:
                actor_obj = ATTACKThreatActor(
                    actor_id=actor.get("external_references", [{}])[0].get("external_id", ""),
                    name=actor.get("name", ""),
                    description=actor.get("description", ""),
                    aliases=actor.get("aliases", [])
                )
                self.threat_actors[actor_obj.actor_id] = actor_obj
                
        except Exception as e:
            logger.error(f"Error loading live ATT&CK data: {str(e)}")
            await self._load_mock_attack_data()
    
    async def _load_mock_attack_data(self):
        """Load mock ATT&CK data for development."""
        logger.info("Loading mock ATT&CK data")
        
        # Mock techniques
        mock_techniques = [
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.",
                "tactic": "TA0001",
                "platforms": ["Linux", "Windows", "macOS"],
                "permissions_required": ["User"],
                "data_sources": ["Network traffic", "Application logs"],
                "detection": ["Monitor for unusual network traffic", "Review application logs"],
                "mitigation": ["Use application firewalls", "Regular security updates"]
            },
            {
                "technique_id": "T1133",
                "name": "External Remote Services",
                "description": "Adversaries may leverage external-facing remote services to gain access to or persist within a network.",
                "tactic": "TA0001",
                "platforms": ["Linux", "Windows", "macOS"],
                "permissions_required": ["User"],
                "data_sources": ["Authentication logs", "Network traffic"],
                "detection": ["Monitor authentication logs", "Review remote access"],
                "mitigation": ["Multi-factor authentication", "VPN access controls"]
            },
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
                "tactic": "TA0001",
                "platforms": ["Linux", "Windows", "macOS"],
                "permissions_required": ["User", "Administrator"],
                "data_sources": ["Authentication logs", "User account management"],
                "detection": ["Monitor account creation", "Review authentication logs"],
                "mitigation": ["Strong password policies", "Account monitoring"]
            }
        ]
        
        for tech in mock_techniques:
            tech_obj = ATTACKTechnique(**tech)
            self.techniques[tech_obj.technique_id] = tech_obj
        
        # Mock tactics
        mock_tactics = [
            {
                "tactic_id": "TA0001",
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network.",
                "shortname": "initial-access"
            },
            {
                "tactic_id": "TA0002",
                "name": "Execution",
                "description": "The adversary is trying to run malicious code.",
                "shortname": "execution"
            },
            {
                "tactic_id": "TA0003",
                "name": "Persistence",
                "description": "The adversary is trying to maintain their foothold.",
                "shortname": "persistence"
            }
        ]
        
        for tactic in mock_tactics:
            tactic_obj = ATTACKTactic(**tactic)
            self.tactics[tactic_obj.tactic_id] = tactic_obj
        
        # Mock threat actors
        mock_actors = [
            {
                "actor_id": "G0001",
                "name": "APT1",
                "description": "APT1 is a Chinese cyber-espionage group.",
                "aliases": ["Comment Crew", "Comment Panda"]
            },
            {
                "actor_id": "G0002", 
                "name": "APT2",
                "description": "APT2 is a Chinese cyber-espionage group.",
                "aliases": ["Group 2", "Panda"]
            }
        ]
        
        for actor in mock_actors:
            actor_obj = ATTACKThreatActor(**actor)
            self.threat_actors[actor_obj.actor_id] = actor_obj
    
    async def _build_attack_graph(self):
        """Build attack graph from techniques and tactics."""
        logger.info("Building attack graph")
        
        # Add nodes for techniques
        for tech_id, technique in self.techniques.items():
            self.attack_graph.add_node(tech_id, 
                                     type="technique",
                                     name=technique.name,
                                     tactic=technique.tactic)
        
        # Add nodes for tactics
        for tactic_id, tactic in self.tactics.items():
            self.attack_graph.add_node(tactic_id,
                                     type="tactic", 
                                     name=tactic.name)
        
        # Add edges from tactics to techniques
        for tech_id, technique in self.techniques.items():
            if technique.tactic in self.tactics:
                self.attack_graph.add_edge(technique.tactic, tech_id)
        
        # Add technique relationships (simplified)
        technique_relationships = [
            ("T1190", "T1078"),  # Exploit Public-Facing Application -> Valid Accounts
            ("T1133", "T1078"),  # External Remote Services -> Valid Accounts
            ("T1078", "T1059"),  # Valid Accounts -> Command and Scripting Interpreter
        ]
        
        for source, target in technique_relationships:
            if source in self.techniques and target in self.techniques:
                self.attack_graph.add_edge(source, target)
        
        logger.info(f"Built attack graph with {self.attack_graph.number_of_nodes()} nodes and {self.attack_graph.number_of_edges()} edges")
    
    async def _generate_technique_mappings(self) -> List[TechniqueMapping]:
        """Generate technique mappings for vulnerabilities."""
        logger.info("Generating technique mappings")
        
        mappings = []
        
        # Load vulnerability data
        vuln_file = self.base_dir / "processed" / "processed_vulnerabilities.json"
        if vuln_file.exists():
            with open(vuln_file, 'r') as f:
                vulnerabilities = json.load(f)
            
            # Map vulnerabilities to techniques
            for vuln in vulnerabilities:
                technique_mappings = await self._map_vulnerability_to_techniques(vuln)
                mappings.extend(technique_mappings)
        
        # Save mappings
        mappings_file = self.mitre_dir / "technique_mappings.json"
        with open(mappings_file, 'w') as f:
            json.dump([mapping.dict() for mapping in mappings], f, indent=2, default=str)
        
        logger.info(f"Generated {len(mappings)} technique mappings")
        return mappings
    
    async def _map_vulnerability_to_techniques(self, vuln: Dict[str, Any]) -> List[TechniqueMapping]:
        """Map a vulnerability to relevant ATT&CK techniques."""
        mappings = []
        
        # Simple mapping logic based on vulnerability type
        vuln_type = vuln.get("category", "").lower()
        vuln_title = vuln.get("title", "").lower()
        
        # Map common vulnerability types to techniques
        if "sql injection" in vuln_type or "sql injection" in vuln_title:
            mappings.append(TechniqueMapping(
                vulnerability_id=vuln.get("id"),
                technique_id="T1190",
                confidence=0.8,
                evidence="SQL injection vulnerability in public-facing application",
                mapping_type="direct",
                attack_vector="web",
                impact="high"
            ))
        
        if "authentication" in vuln_type or "auth" in vuln_title:
            mappings.append(TechniqueMapping(
                vulnerability_id=vuln.get("id"),
                technique_id="T1078",
                confidence=0.7,
                evidence="Authentication bypass or weak authentication",
                mapping_type="direct",
                attack_vector="authentication",
                impact="high"
            ))
        
        if "remote" in vuln_type or "rce" in vuln_title:
            mappings.append(TechniqueMapping(
                vulnerability_id=vuln.get("id"),
                technique_id="T1133",
                confidence=0.6,
                evidence="Remote code execution or remote access",
                mapping_type="indirect",
                attack_vector="remote",
                impact="critical"
            ))
        
        return mappings
    
    async def _analyze_tactic_progression(self) -> Dict[str, Any]:
        """Analyze tactic progression and generate attack paths."""
        logger.info("Analyzing tactic progression")
        
        attack_paths = []
        
        # Generate attack paths using graph analysis
        for tactic_id in self.tactics:
            paths = await self._generate_attack_paths_from_tactic(tactic_id)
            attack_paths.extend(paths)
        
        # Analyze path complexity and likelihood
        for path in attack_paths:
            path.likelihood = await self._calculate_path_likelihood(path)
            path.complexity = await self._assess_path_complexity(path)
        
        # Sort paths by likelihood and impact
        attack_paths.sort(key=lambda x: (x.likelihood, self._impact_score(x.impact)), reverse=True)
        
        result = {
            "attack_paths": [path.dict() for path in attack_paths],
            "total_paths": len(attack_paths),
            "high_likelihood_paths": len([p for p in attack_paths if p.likelihood >= 0.7]),
            "critical_impact_paths": len([p for p in attack_paths if p.impact == "critical"])
        }
        
        logger.info(f"Generated {len(attack_paths)} attack paths")
        return result
    
    async def _generate_attack_paths_from_tactic(self, tactic_id: str) -> List[AttackPath]:
        """Generate attack paths starting from a specific tactic."""
        paths = []
        
        if tactic_id not in self.tactics:
            return paths
        
        tactic = self.tactics[tactic_id]
        
        # Get techniques for this tactic
        techniques = [tech_id for tech_id, tech in self.techniques.items() 
                     if tech.tactic == tactic_id]
        
        if not techniques:
            return paths
        
        # Generate simple paths (1-3 techniques)
        for i, tech_id in enumerate(techniques):
            path = AttackPath(
                path_id=f"path_{tactic_id}_{i}",
                name=f"{tactic.name} via {self.techniques[tech_id].name}",
                description=f"Attack path using {self.techniques[tech_id].name}",
                techniques=[tech_id],
                tactics=[tactic_id],
                threat_actors=[],
                likelihood=0.5,
                impact="medium",
                complexity="low",
                prerequisites=[],
                detection_points=[],
                mitigation_strategies=[]
            )
            paths.append(path)
        
        # Generate multi-technique paths
        if len(techniques) >= 2:
            for i in range(len(techniques)):
                for j in range(i + 1, len(techniques)):
                    tech1 = techniques[i]
                    tech2 = techniques[j]
                    
                    # Check if there's a path between these techniques
                    if nx.has_path(self.attack_graph, tech1, tech2):
                        path = AttackPath(
                            path_id=f"path_{tactic_id}_{i}_{j}",
                            name=f"{tactic.name} via {self.techniques[tech1].name} -> {self.techniques[tech2].name}",
                            description=f"Multi-step attack path",
                            techniques=[tech1, tech2],
                            tactics=[tactic_id],
                            threat_actors=[],
                            likelihood=0.6,
                            impact="high",
                            complexity="medium",
                            prerequisites=[],
                            detection_points=[],
                            mitigation_strategies=[]
                        )
                        paths.append(path)
        
        return paths
    
    async def _calculate_path_likelihood(self, path: AttackPath) -> float:
        """Calculate likelihood of attack path success."""
        base_likelihood = 0.5
        
        # Adjust based on number of techniques (more techniques = lower likelihood)
        technique_penalty = len(path.techniques) * 0.1
        base_likelihood -= technique_penalty
        
        # Adjust based on complexity
        if path.complexity == "high":
            base_likelihood -= 0.2
        elif path.complexity == "low":
            base_likelihood += 0.1
        
        return max(0.1, min(1.0, base_likelihood))
    
    async def _assess_path_complexity(self, path: AttackPath) -> str:
        """Assess complexity of attack path."""
        if len(path.techniques) <= 1:
            return "low"
        elif len(path.techniques) <= 3:
            return "medium"
        else:
            return "high"
    
    def _impact_score(self, impact: str) -> int:
        """Convert impact string to numeric score."""
        impact_scores = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4
        }
        return impact_scores.get(impact.lower(), 1)
    
    async def _save_framework_data(self):
        """Save framework data to files."""
        logger.info("Saving framework data")
        
        # Save techniques
        techniques_file = self.mitre_dir / "techniques.json"
        with open(techniques_file, 'w') as f:
            json.dump([tech.dict() for tech in self.techniques.values()], f, indent=2, default=str)
        
        # Save tactics
        tactics_file = self.mitre_dir / "tactics.json"
        with open(tactics_file, 'w') as f:
            json.dump([tactic.dict() for tactic in self.tactics.values()], f, indent=2, default=str)
        
        # Save threat actors
        actors_file = self.mitre_dir / "threat_actors.json"
        with open(actors_file, 'w') as f:
            json.dump([actor.dict() for actor in self.threat_actors.values()], f, indent=2, default=str)
        
        # Save attack graph
        graph_file = self.mitre_dir / "attack_graph.json"
        graph_data = nx.node_link_data(self.attack_graph)
        with open(graph_file, 'w') as f:
            json.dump(graph_data, f, indent=2, default=str)
        
        logger.info(f"Saved framework data to {self.mitre_dir}")
    
    async def get_technique_by_id(self, technique_id: str) -> Optional[ATTACKTechnique]:
        """Get technique by ID."""
        return self.techniques.get(technique_id)
    
    async def get_tactic_by_id(self, tactic_id: str) -> Optional[ATTACKTactic]:
        """Get tactic by ID."""
        return self.tactics.get(tactic_id)
    
    async def get_threat_actor_by_id(self, actor_id: str) -> Optional[ATTACKThreatActor]:
        """Get threat actor by ID."""
        return self.threat_actors.get(actor_id)
    
    async def find_techniques_by_tactic(self, tactic_id: str) -> List[ATTACKTechnique]:
        """Find all techniques for a specific tactic."""
        return [tech for tech in self.techniques.values() if tech.tactic == tactic_id]
    
    async def find_attack_paths(self, source_technique: str, target_technique: str) -> List[List[str]]:
        """Find all attack paths between two techniques."""
        if source_technique not in self.techniques or target_technique not in self.techniques:
            return []
        
        try:
            paths = list(nx.all_simple_paths(self.attack_graph, source_technique, target_technique))
            return paths
        except nx.NetworkXNoPath:
            return []
    
    async def get_technique_relationships(self, technique_id: str) -> Dict[str, Any]:
        """Get relationships for a specific technique."""
        if technique_id not in self.attack_graph:
            return {}
        
        predecessors = list(self.attack_graph.predecessors(technique_id))
        successors = list(self.attack_graph.successors(technique_id))
        
        return {
            "technique_id": technique_id,
            "predecessors": predecessors,
            "successors": successors,
            "in_degree": self.attack_graph.in_degree(technique_id),
            "out_degree": self.attack_graph.out_degree(technique_id)
        } 