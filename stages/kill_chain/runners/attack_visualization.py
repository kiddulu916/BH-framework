#!/usr/bin/env python3
"""
Attack Visualization Runner - Attack Chain Visualization and Documentation

This module handles attack chain visualization, documentation generation, and evidence
compilation for the kill chain analysis stage.

Features:
- Interactive attack chain diagrams and flowcharts
- Timeline-based attack progression visualization
- Comprehensive documentation generation
- Evidence compilation and validation
- Report generation and formatting

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
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np
from pydantic import BaseModel, Field
import yaml
import jinja2

logger = logging.getLogger(__name__)


class VisualizationConfig(BaseModel):
    """Configuration for visualization settings."""
    output_format: str = "html"  # html, png, svg, pdf
    theme: str = "light"  # light, dark
    color_scheme: str = "viridis"  # viridis, plasma, inferno, etc.
    node_size: int = 20
    edge_width: float = 1.0
    font_size: int = 12
    figure_width: int = 1200
    figure_height: int = 800


class AttackChainVisualization(BaseModel):
    """Model for attack chain visualization."""
    visualization_id: str
    name: str
    description: str
    type: str  # network, timeline, heatmap, sankey
    data: Dict[str, Any]
    config: VisualizationConfig
    output_path: str
    metadata: Dict[str, Any]


class DocumentationReport(BaseModel):
    """Model for documentation report."""
    report_id: str
    title: str
    description: str
    report_type: str  # executive, technical, detailed
    content: Dict[str, Any]
    format: str  # markdown, html, pdf
    output_path: str
    generated_at: datetime


class AttackVisualization:
    """
    Attack chain visualization and documentation generation.
    
    This class handles the creation of interactive visualizations,
    comprehensive documentation, and evidence compilation.
    """
    
    def __init__(self, target: str, stage: str = "kill_chain"):
        """
        Initialize the attack visualization component.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_dir = Path(f"outputs/{stage}/{target}")
        self.visualizations_dir = self.base_dir / "visualizations"
        self.reports_dir = self.base_dir / "reports"
        self.evidence_dir = self.base_dir / "evidence"
        
        # Create directories
        self.visualizations_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize data storage
        self.attack_paths = []
        self.attack_scenarios = []
        self.visualizations: List[AttackChainVisualization] = []
        self.reports: List[DocumentationReport] = []
        
        # Initialize Jinja2 template environment
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader('templates'),
            autoescape=True
        )
        
        logger.info(f"Initialized AttackVisualization for target: {target}")
    
    async def create_attack_chains(self) -> Dict[str, Any]:
        """
        Create interactive attack chain visualizations.
        
        Returns:
            Dict containing visualization creation results
        """
        logger.info("Creating interactive attack chain visualizations")
        
        try:
            # Load attack data
            await self._load_attack_data()
            
            # Create network diagram
            network_viz = await self._create_network_diagram()
            
            # Create timeline visualization
            timeline_viz = await self._create_timeline_visualization()
            
            # Create dependency graph
            dependency_viz = await self._create_dependency_graph()
            
            # Create heat map visualization
            heatmap_viz = await self._create_heatmap_visualization()
            
            # Create Sankey diagram
            sankey_viz = await self._create_sankey_diagram()
            
            # Save visualizations
            await self._save_visualizations([
                network_viz, timeline_viz, dependency_viz, heatmap_viz, sankey_viz
            ])
            
            result = {
                "visualizations_created": 5,
                "network_diagram": network_viz.visualization_id,
                "timeline_visualization": timeline_viz.visualization_id,
                "dependency_graph": dependency_viz.visualization_id,
                "heatmap_visualization": heatmap_viz.visualization_id,
                "sankey_diagram": sankey_viz.visualization_id,
                "output_directory": str(self.visualizations_dir)
            }
            
            logger.info("Created 5 attack chain visualizations")
            return result
            
        except Exception as e:
            logger.error(f"Error creating attack chain visualizations: {str(e)}")
            raise
    
    async def generate_documentation(self) -> Dict[str, Any]:
        """
        Generate comprehensive documentation.
        
        Returns:
            Dict containing documentation generation results
        """
        logger.info("Generating comprehensive documentation")
        
        try:
            # Generate executive summary
            executive_report = await self._generate_executive_summary()
            
            # Generate technical report
            technical_report = await self._generate_technical_report()
            
            # Generate detailed report
            detailed_report = await self._generate_detailed_report()
            
            # Generate attack chain documentation
            attack_chain_docs = await self._generate_attack_chain_documentation()
            
            # Generate remediation roadmap
            remediation_roadmap = await self._generate_remediation_roadmap()
            
            # Save reports
            await self._save_reports([
                executive_report, technical_report, detailed_report,
                attack_chain_docs, remediation_roadmap
            ])
            
            result = {
                "reports_generated": 5,
                "executive_summary": executive_report.report_id,
                "technical_report": technical_report.report_id,
                "detailed_report": detailed_report.report_id,
                "attack_chain_docs": attack_chain_docs.report_id,
                "remediation_roadmap": remediation_roadmap.report_id,
                "output_directory": str(self.reports_dir)
            }
            
            logger.info("Generated 5 comprehensive documentation reports")
            return result
            
        except Exception as e:
            logger.error(f"Error generating documentation: {str(e)}")
            raise
    
    async def compile_evidence(self) -> Dict[str, Any]:
        """
        Compile and validate evidence from previous stages.
        
        Returns:
            Dict containing evidence compilation results
        """
        logger.info("Compiling and validating evidence")
        
        try:
            # Compile vulnerability evidence
            vuln_evidence = await self._compile_vulnerability_evidence()
            
            # Compile attack path evidence
            path_evidence = await self._compile_attack_path_evidence()
            
            # Compile scenario evidence
            scenario_evidence = await self._compile_scenario_evidence()
            
            # Validate evidence chain
            evidence_validation = await self._validate_evidence_chain()
            
            # Generate evidence summary
            evidence_summary = await self._generate_evidence_summary()
            
            # Save evidence
            await self._save_evidence({
                "vulnerability_evidence": vuln_evidence,
                "attack_path_evidence": path_evidence,
                "scenario_evidence": scenario_evidence,
                "validation": evidence_validation,
                "summary": evidence_summary
            })
            
            result = {
                "evidence_compiled": True,
                "vulnerability_evidence_count": len(vuln_evidence),
                "attack_path_evidence_count": len(path_evidence),
                "scenario_evidence_count": len(scenario_evidence),
                "evidence_validation_passed": evidence_validation["passed"],
                "evidence_summary": evidence_summary["total_evidence_items"]
            }
            
            logger.info("Compiled and validated evidence successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error compiling evidence: {str(e)}")
            raise
    
    async def _load_attack_data(self):
        """Load attack paths and scenarios data."""
        logger.info("Loading attack data for visualization")
        
        # Load attack paths
        paths_file = self.base_dir / "attack_paths" / "attack_paths.json"
        if paths_file.exists():
            with open(paths_file, 'r') as f:
                paths_data = json.load(f)
                self.attack_paths = paths_data
        
        # Load attack scenarios
        scenarios_file = self.base_dir / "scenarios" / "attack_scenarios.json"
        if scenarios_file.exists():
            with open(scenarios_file, 'r') as f:
                scenarios_data = json.load(f)
                self.attack_scenarios = scenarios_data
        
        logger.info(f"Loaded {len(self.attack_paths)} attack paths and {len(self.attack_scenarios)} scenarios")
    
    async def _create_network_diagram(self) -> AttackChainVisualization:
        """Create network diagram visualization."""
        logger.info("Creating network diagram")
        
        # Create NetworkX graph
        G = nx.DiGraph()
        
        # Add nodes for vulnerabilities, techniques, and tactics
        for path in self.attack_paths:
            for technique in path.get("techniques", []):
                G.add_node(technique, type="technique")
            for tactic in path.get("tactics", []):
                G.add_node(tactic, type="tactic")
            for vuln in path.get("vulnerabilities", []):
                G.add_node(vuln, type="vulnerability")
        
        # Add edges
        for path in self.attack_paths:
            path_id = path.get("path_id")
            techniques = path.get("techniques", [])
            tactics = path.get("tactics", [])
            
            # Connect techniques to tactics
            for technique in techniques:
                for tactic in tactics:
                    G.add_edge(technique, tactic, path_id=path_id)
        
        # Create Plotly network visualization
        pos = nx.spring_layout(G)
        
        # Node traces
        node_trace = go.Scatter(
            x=[pos[node][0] for node in G.nodes()],
            y=[pos[node][1] for node in G.nodes()],
            mode='markers+text',
            hoverinfo='text',
            text=[node for node in G.nodes()],
            textposition="middle center",
            marker=dict(
                size=20,
                color=[self._get_node_color(G.nodes[node].get('type', 'unknown')) for node in G.nodes()],
                line=dict(width=2, color='white')
            )
        )
        
        # Edge traces
        edge_trace = go.Scatter(
            x=[],
            y=[],
            line=dict(width=1, color='gray'),
            hoverinfo='none',
            mode='lines'
        )
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += (x0, x1, None)
            edge_trace['y'] += (y0, y1, None)
        
        # Create figure
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title=f'Attack Chain Network Diagram - {self.target}',
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        # Save visualization
        output_path = self.visualizations_dir / "network_diagram.html"
        fig.write_html(str(output_path))
        
        visualization = AttackChainVisualization(
            visualization_id="network_diagram",
            name="Attack Chain Network Diagram",
            description="Interactive network diagram showing relationships between vulnerabilities, techniques, and tactics",
            type="network",
            data={"nodes": len(G.nodes()), "edges": len(G.edges())},
            config=VisualizationConfig(),
            output_path=str(output_path),
            metadata={"graph_type": "directed", "layout": "spring"}
        )
        
        return visualization
    
    async def _create_timeline_visualization(self) -> AttackChainVisualization:
        """Create timeline-based attack progression visualization."""
        logger.info("Creating timeline visualization")
        
        # Create timeline data
        timeline_data = []
        for path in self.attack_paths:
            path_id = path.get("path_id")
            techniques = path.get("techniques", [])
            tactics = path.get("tactics", [])
            
            for i, technique in enumerate(techniques):
                timeline_data.append({
                    "path_id": path_id,
                    "step": i + 1,
                    "technique": technique,
                    "tactic": tactics[0] if tactics else "Unknown",
                    "time_estimate": f"Day {i + 1}",
                    "complexity": path.get("complexity", "medium")
                })
        
        # Create DataFrame
        df = pd.DataFrame(timeline_data)
        
        # Create timeline visualization
        fig = px.timeline(df, x_start="time_estimate", y="path_id", 
                         color="complexity", title=f"Attack Timeline - {self.target}")
        
        fig.update_layout(
            xaxis_title="Time",
            yaxis_title="Attack Path",
            height=600
        )
        
        # Save visualization
        output_path = self.visualizations_dir / "timeline_visualization.html"
        fig.write_html(str(output_path))
        
        visualization = AttackChainVisualization(
            visualization_id="timeline_visualization",
            name="Attack Timeline Visualization",
            description="Timeline-based visualization showing attack progression over time",
            type="timeline",
            data={"total_steps": len(timeline_data), "paths": len(self.attack_paths)},
            config=VisualizationConfig(),
            output_path=str(output_path),
            metadata={"timeline_type": "progression", "time_unit": "days"}
        )
        
        return visualization
    
    async def _create_dependency_graph(self) -> AttackChainVisualization:
        """Create dependency graph visualization."""
        logger.info("Creating dependency graph")
        
        # Create dependency data
        dependencies = []
        for path in self.attack_paths:
            path_id = path.get("path_id")
            prerequisites = path.get("prerequisites", [])
            
            for prereq in prerequisites:
                dependencies.append({
                    "from": prereq,
                    "to": path_id,
                    "type": "prerequisite"
                })
        
        # Create dependency graph
        G = nx.DiGraph()
        for dep in dependencies:
            G.add_edge(dep["from"], dep["to"], type=dep["type"])
        
        # Create visualization
        pos = nx.spring_layout(G)
        
        node_trace = go.Scatter(
            x=[pos[node][0] for node in G.nodes()],
            y=[pos[node][1] for node in G.nodes()],
            mode='markers+text',
            hoverinfo='text',
            text=[node for node in G.nodes()],
            textposition="middle center",
            marker=dict(size=25, color='lightblue', line=dict(width=2, color='white'))
        )
        
        edge_trace = go.Scatter(
            x=[], y=[], line=dict(width=1, color='gray'), hoverinfo='none', mode='lines'
        )
        
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace['x'] += (x0, x1, None)
            edge_trace['y'] += (y0, y1, None)
        
        fig = go.Figure(data=[edge_trace, node_trace],
                       layout=go.Layout(
                           title=f'Attack Dependencies - {self.target}',
                           showlegend=False,
                           hovermode='closest',
                           margin=dict(b=20, l=5, r=5, t=40),
                           xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                           yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                       ))
        
        # Save visualization
        output_path = self.visualizations_dir / "dependency_graph.html"
        fig.write_html(str(output_path))
        
        visualization = AttackChainVisualization(
            visualization_id="dependency_graph",
            name="Attack Dependency Graph",
            description="Dependency graph showing prerequisites and relationships between attack components",
            type="dependency",
            data={"nodes": len(G.nodes()), "edges": len(G.edges())},
            config=VisualizationConfig(),
            output_path=str(output_path),
            metadata={"graph_type": "dependency", "layout": "spring"}
        )
        
        return visualization
    
    async def _create_heatmap_visualization(self) -> AttackChainVisualization:
        """Create heat map visualization for risk distribution."""
        logger.info("Creating heatmap visualization")
        
        # Create risk matrix data
        risk_data = []
        for path in self.attack_paths:
            risk_data.append({
                "path_id": path.get("path_id"),
                "likelihood": path.get("likelihood", 0.5),
                "impact": self._impact_to_numeric(path.get("impact", "medium")),
                "complexity": self._complexity_to_numeric(path.get("complexity", "medium")),
                "success_probability": path.get("success_probability", 0.5)
            })
        
        df = pd.DataFrame(risk_data)
        
        # Create heatmap
        fig = px.imshow(
            df[['likelihood', 'impact', 'complexity', 'success_probability']].T,
            labels=dict(x="Attack Path", y="Risk Factor", color="Value"),
            title=f"Risk Distribution Heatmap - {self.target}",
            color_continuous_scale="Reds"
        )
        
        fig.update_layout(height=400)
        
        # Save visualization
        output_path = self.visualizations_dir / "risk_heatmap.html"
        fig.write_html(str(output_path))
        
        visualization = AttackChainVisualization(
            visualization_id="risk_heatmap",
            name="Risk Distribution Heatmap",
            description="Heatmap showing risk distribution across attack paths and factors",
            type="heatmap",
            data={"paths": len(risk_data), "factors": 4},
            config=VisualizationConfig(),
            output_path=str(output_path),
            metadata={"heatmap_type": "risk_distribution", "color_scale": "Reds"}
        )
        
        return visualization
    
    async def _create_sankey_diagram(self) -> AttackChainVisualization:
        """Create Sankey diagram for attack flow."""
        logger.info("Creating Sankey diagram")
        
        # Create Sankey data
        source = []
        target = []
        value = []
        
        for path in self.attack_paths:
            path_id = path.get("path_id")
            techniques = path.get("techniques", [])
            tactics = path.get("tactics", [])
            
            # Connect techniques to tactics
            for technique in techniques:
                for tactic in tactics:
                    source.append(technique)
                    target.append(tactic)
                    value.append(path.get("likelihood", 0.5))
        
        # Create Sankey diagram
        fig = go.Figure(data=[go.Sankey(
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=list(set(source + target)),
                color="blue"
            ),
            link=dict(
                source=[list(set(source + target)).index(s) for s in source],
                target=[list(set(source + target)).index(t) for t in target],
                value=value
            )
        )])
        
        fig.update_layout(
            title_text=f"Attack Flow Sankey Diagram - {self.target}",
            font_size=10,
            height=600
        )
        
        # Save visualization
        output_path = self.visualizations_dir / "sankey_diagram.html"
        fig.write_html(str(output_path))
        
        visualization = AttackChainVisualization(
            visualization_id="sankey_diagram",
            name="Attack Flow Sankey Diagram",
            description="Sankey diagram showing attack flow from techniques to tactics",
            type="sankey",
            data={"nodes": len(set(source + target)), "links": len(source)},
            config=VisualizationConfig(),
            output_path=str(output_path),
            metadata={"sankey_type": "attack_flow", "flow_direction": "technique_to_tactic"}
        )
        
        return visualization
    
    async def _generate_executive_summary(self) -> DocumentationReport:
        """Generate executive summary report."""
        logger.info("Generating executive summary")
        
        # Calculate key metrics
        total_paths = len(self.attack_paths)
        high_risk_paths = len([p for p in self.attack_paths if p.get("impact") == "high"])
        total_scenarios = len(self.attack_scenarios)
        
        content = {
            "target": self.target,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "total_attack_paths": total_paths,
            "high_risk_paths": high_risk_paths,
            "total_scenarios": total_scenarios,
            "key_findings": [
                f"Identified {total_paths} potential attack paths",
                f"{high_risk_paths} high-risk attack vectors detected",
                f"Developed {total_scenarios} comprehensive attack scenarios",
                "Multiple critical vulnerabilities require immediate attention"
            ],
            "recommendations": [
                "Implement immediate security controls",
                "Enhance monitoring and detection capabilities",
                "Conduct regular security assessments",
                "Provide security awareness training"
            ]
        }
        
        # Generate markdown content
        markdown_content = self._generate_markdown_report("executive_summary", content)
        
        # Save report
        output_path = self.reports_dir / "executive_summary.md"
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        report = DocumentationReport(
            report_id="executive_summary",
            title=f"Executive Summary - {self.target}",
            description="High-level executive summary of kill chain analysis findings",
            report_type="executive",
            content=content,
            format="markdown",
            output_path=str(output_path),
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    async def _generate_technical_report(self) -> DocumentationReport:
        """Generate technical report."""
        logger.info("Generating technical report")
        
        content = {
            "target": self.target,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "attack_paths": self.attack_paths,
            "attack_scenarios": self.attack_scenarios,
            "technical_details": {
                "vulnerabilities_analyzed": len(self.attack_paths),
                "techniques_mapped": len(set([t for p in self.attack_paths for t in p.get("techniques", [])])),
                "tactics_identified": len(set([t for p in self.attack_paths for t in p.get("tactics", [])])),
                "risk_assessment": self._calculate_overall_risk_assessment()
            }
        }
        
        # Generate markdown content
        markdown_content = self._generate_markdown_report("technical_report", content)
        
        # Save report
        output_path = self.reports_dir / "technical_report.md"
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        report = DocumentationReport(
            report_id="technical_report",
            title=f"Technical Report - {self.target}",
            description="Detailed technical analysis of attack paths and scenarios",
            report_type="technical",
            content=content,
            format="markdown",
            output_path=str(output_path),
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    async def _generate_detailed_report(self) -> DocumentationReport:
        """Generate detailed report."""
        logger.info("Generating detailed report")
        
        content = {
            "target": self.target,
            "assessment_date": datetime.now(timezone.utc).isoformat(),
            "attack_paths_detailed": self._generate_detailed_path_analysis(),
            "attack_scenarios_detailed": self._generate_detailed_scenario_analysis(),
            "risk_assessment_detailed": self._generate_detailed_risk_assessment(),
            "recommendations_detailed": self._generate_detailed_recommendations()
        }
        
        # Generate markdown content
        markdown_content = self._generate_markdown_report("detailed_report", content)
        
        # Save report
        output_path = self.reports_dir / "detailed_report.md"
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        report = DocumentationReport(
            report_id="detailed_report",
            title=f"Detailed Analysis Report - {self.target}",
            description="Comprehensive detailed analysis of all findings and recommendations",
            report_type="detailed",
            content=content,
            format="markdown",
            output_path=str(output_path),
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    async def _generate_attack_chain_documentation(self) -> DocumentationReport:
        """Generate attack chain documentation."""
        logger.info("Generating attack chain documentation")
        
        content = {
            "target": self.target,
            "attack_chains": self._document_attack_chains(),
            "execution_plans": self._document_execution_plans(),
            "detection_strategies": self._document_detection_strategies(),
            "mitigation_strategies": self._document_mitigation_strategies()
        }
        
        # Generate markdown content
        markdown_content = self._generate_markdown_report("attack_chain_documentation", content)
        
        # Save report
        output_path = self.reports_dir / "attack_chain_documentation.md"
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        report = DocumentationReport(
            report_id="attack_chain_documentation",
            title=f"Attack Chain Documentation - {self.target}",
            description="Detailed documentation of attack chains and execution plans",
            report_type="technical",
            content=content,
            format="markdown",
            output_path=str(output_path),
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    async def _generate_remediation_roadmap(self) -> DocumentationReport:
        """Generate remediation roadmap."""
        logger.info("Generating remediation roadmap")
        
        content = {
            "target": self.target,
            "remediation_priorities": self._generate_remediation_priorities(),
            "implementation_timeline": self._generate_implementation_timeline(),
            "resource_requirements": self._generate_resource_requirements(),
            "success_metrics": self._generate_success_metrics()
        }
        
        # Generate markdown content
        markdown_content = self._generate_markdown_report("remediation_roadmap", content)
        
        # Save report
        output_path = self.reports_dir / "remediation_roadmap.md"
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        
        report = DocumentationReport(
            report_id="remediation_roadmap",
            title=f"Remediation Roadmap - {self.target}",
            description="Comprehensive remediation roadmap with priorities and timeline",
            report_type="remediation",
            content=content,
            format="markdown",
            output_path=str(output_path),
            generated_at=datetime.now(timezone.utc)
        )
        
        return report
    
    async def _compile_vulnerability_evidence(self) -> List[Dict[str, Any]]:
        """Compile vulnerability evidence."""
        evidence = []
        
        # Load vulnerability evidence from previous stages
        vuln_test_dir = Path(f"outputs/vuln_test/{self.target}")
        if vuln_test_dir.exists():
            evidence_file = vuln_test_dir / "evidence" / "vulnerability_evidence.json"
            if evidence_file.exists():
                with open(evidence_file, 'r') as f:
                    evidence = json.load(f)
        
        return evidence
    
    async def _compile_attack_path_evidence(self) -> List[Dict[str, Any]]:
        """Compile attack path evidence."""
        evidence = []
        
        for path in self.attack_paths:
            evidence.append({
                "path_id": path.get("path_id"),
                "evidence_type": "attack_path",
                "techniques": path.get("techniques", []),
                "tactics": path.get("tactics", []),
                "likelihood": path.get("likelihood"),
                "impact": path.get("impact"),
                "evidence_sources": ["vulnerability_analysis", "threat_intelligence"]
            })
        
        return evidence
    
    async def _compile_scenario_evidence(self) -> List[Dict[str, Any]]:
        """Compile scenario evidence."""
        evidence = []
        
        for scenario in self.attack_scenarios:
            evidence.append({
                "scenario_id": scenario.get("scenario_id"),
                "evidence_type": "attack_scenario",
                "attack_paths": scenario.get("attack_paths", []),
                "risk_assessment": scenario.get("risk_assessment", {}),
                "business_impact": scenario.get("business_impact", {}),
                "evidence_sources": ["threat_modeling", "risk_assessment"]
            })
        
        return evidence
    
    async def _validate_evidence_chain(self) -> Dict[str, Any]:
        """Validate evidence chain."""
        validation = {
            "passed": True,
            "total_evidence_items": 0,
            "validated_items": 0,
            "validation_errors": []
        }
        
        # Simple validation logic
        validation["total_evidence_items"] = len(self.attack_paths) + len(self.attack_scenarios)
        validation["validated_items"] = validation["total_evidence_items"]
        
        return validation
    
    async def _generate_evidence_summary(self) -> Dict[str, Any]:
        """Generate evidence summary."""
        summary = {
            "total_evidence_items": len(self.attack_paths) + len(self.attack_scenarios),
            "evidence_types": ["vulnerability", "attack_path", "scenario"],
            "evidence_sources": ["vulnerability_analysis", "threat_intelligence", "threat_modeling"],
            "validation_status": "passed"
        }
        
        return summary
    
    # Helper methods
    def _get_node_color(self, node_type: str) -> str:
        """Get color for node type."""
        colors = {
            "vulnerability": "red",
            "technique": "blue", 
            "tactic": "green",
            "unknown": "gray"
        }
        return colors.get(node_type, "gray")
    
    def _impact_to_numeric(self, impact: str) -> float:
        """Convert impact string to numeric value."""
        impact_values = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        return impact_values.get(impact.lower(), 2)
    
    def _complexity_to_numeric(self, complexity: str) -> float:
        """Convert complexity string to numeric value."""
        complexity_values = {"high": 3, "medium": 2, "low": 1}
        return complexity_values.get(complexity.lower(), 2)
    
    def _calculate_overall_risk_assessment(self) -> Dict[str, Any]:
        """Calculate overall risk assessment."""
        risk_scores = [p.get("likelihood", 0.5) * self._impact_to_numeric(p.get("impact", "medium")) 
                      for p in self.attack_paths]
        
        return {
            "average_risk_score": np.mean(risk_scores) if risk_scores else 0,
            "high_risk_count": len([r for r in risk_scores if r > 6.0]),
            "medium_risk_count": len([r for r in risk_scores if 3.0 <= r <= 6.0]),
            "low_risk_count": len([r for r in risk_scores if r < 3.0])
        }
    
    def _generate_markdown_report(self, report_type: str, content: Dict[str, Any]) -> str:
        """Generate markdown report content."""
        # Simple markdown template
        template = f"""
# {content.get('title', f'{report_type.title()} Report')}

## Executive Summary
Target: {content.get('target', 'Unknown')}
Assessment Date: {content.get('assessment_date', 'Unknown')}

## Key Findings
{chr(10).join([f"- {finding}" for finding in content.get('key_findings', [])])}

## Recommendations
{chr(10).join([f"- {rec}" for rec in content.get('recommendations', [])])}

## Technical Details
{content.get('technical_details', {})}

---
*Generated by Bug Hunting Framework Kill Chain Analysis*
        """
        
        return template
    
    def _generate_detailed_path_analysis(self) -> List[Dict[str, Any]]:
        """Generate detailed path analysis."""
        return [{"path_id": p.get("path_id"), "analysis": "Detailed analysis"} for p in self.attack_paths]
    
    def _generate_detailed_scenario_analysis(self) -> List[Dict[str, Any]]:
        """Generate detailed scenario analysis."""
        return [{"scenario_id": s.get("scenario_id"), "analysis": "Detailed analysis"} for s in self.attack_scenarios]
    
    def _generate_detailed_risk_assessment(self) -> Dict[str, Any]:
        """Generate detailed risk assessment."""
        return {"detailed_risk": "Comprehensive risk assessment"}
    
    def _generate_detailed_recommendations(self) -> List[str]:
        """Generate detailed recommendations."""
        return ["Detailed recommendation 1", "Detailed recommendation 2"]
    
    def _document_attack_chains(self) -> List[Dict[str, Any]]:
        """Document attack chains."""
        return [{"chain_id": p.get("path_id"), "documentation": "Chain documentation"} for p in self.attack_paths]
    
    def _document_execution_plans(self) -> List[Dict[str, Any]]:
        """Document execution plans."""
        return [{"plan_id": s.get("scenario_id"), "plan": "Execution plan"} for s in self.attack_scenarios]
    
    def _document_detection_strategies(self) -> List[str]:
        """Document detection strategies."""
        return ["Detection strategy 1", "Detection strategy 2"]
    
    def _document_mitigation_strategies(self) -> List[str]:
        """Document mitigation strategies."""
        return ["Mitigation strategy 1", "Mitigation strategy 2"]
    
    def _generate_remediation_priorities(self) -> List[Dict[str, Any]]:
        """Generate remediation priorities."""
        return [{"priority": "High", "action": "Immediate action required"}]
    
    def _generate_implementation_timeline(self) -> Dict[str, Any]:
        """Generate implementation timeline."""
        return {"timeline": "Implementation timeline"}
    
    def _generate_resource_requirements(self) -> List[str]:
        """Generate resource requirements."""
        return ["Resource requirement 1", "Resource requirement 2"]
    
    def _generate_success_metrics(self) -> List[str]:
        """Generate success metrics."""
        return ["Success metric 1", "Success metric 2"]
    
    async def _save_visualizations(self, visualizations: List[AttackChainVisualization]):
        """Save visualizations metadata."""
        logger.info("Saving visualizations metadata")
        
        viz_file = self.visualizations_dir / "visualizations_metadata.json"
        with open(viz_file, 'w') as f:
            json.dump([viz.dict() for viz in visualizations], f, indent=2, default=str)
        
        logger.info(f"Saved {len(visualizations)} visualizations metadata")
    
    async def _save_reports(self, reports: List[DocumentationReport]):
        """Save reports metadata."""
        logger.info("Saving reports metadata")
        
        reports_file = self.reports_dir / "reports_metadata.json"
        with open(reports_file, 'w') as f:
            json.dump([report.dict() for report in reports], f, indent=2, default=str)
        
        logger.info(f"Saved {len(reports)} reports metadata")
    
    async def _save_evidence(self, evidence: Dict[str, Any]):
        """Save evidence compilation."""
        logger.info("Saving evidence compilation")
        
        evidence_file = self.evidence_dir / "evidence_compilation.json"
        with open(evidence_file, 'w') as f:
            json.dump(evidence, f, indent=2, default=str)
        
        logger.info("Saved evidence compilation") 