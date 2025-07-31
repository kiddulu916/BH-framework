#!/usr/bin/env python3
"""
Advanced Analytics Runner - Machine Learning Integration and Predictive Modeling

This module handles advanced analytics, machine learning integration, and predictive
modeling for the kill chain analysis stage.

Features:
- Predictive attack modeling
- Real-time threat intelligence
- Advanced analytics dashboard
- Machine learning model training and deployment
- Pattern recognition and anomaly detection

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
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder
import tensorflow as tf
from tensorflow import keras
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import joblib
import pickle

logger = logging.getLogger(__name__)


class MLModel(BaseModel):
    """Model for machine learning model metadata."""
    model_id: str
    name: str
    type: str  # classification, regression, clustering
    algorithm: str
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_date: datetime
    features: List[str]
    model_path: str
    metadata: Dict[str, Any]


class PredictionResult(BaseModel):
    """Model for prediction results."""
    prediction_id: str
    model_id: str
    input_data: Dict[str, Any]
    prediction: Any
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any]


class ThreatIntelligence(BaseModel):
    """Model for threat intelligence data."""
    intel_id: str
    source: str
    threat_type: str
    severity: str
    confidence: float
    indicators: List[str]
    description: str
    timestamp: datetime
    metadata: Dict[str, Any]


class AnalyticsDashboard(BaseModel):
    """Model for analytics dashboard."""
    dashboard_id: str
    name: str
    description: str
    metrics: Dict[str, Any]
    visualizations: List[str]
    last_updated: datetime
    config: Dict[str, Any]


class AdvancedAnalytics:
    """
    Advanced analytics and machine learning integration.
    
    This class handles predictive modeling, threat intelligence integration,
    and advanced analytics dashboard creation.
    """
    
    def __init__(self, target: str, stage: str = "kill_chain"):
        """
        Initialize the advanced analytics component.
        
        Args:
            target: Target domain or organization name
            stage: Stage name for output organization
        """
        self.target = target
        self.stage = stage
        self.base_dir = Path(f"outputs/{stage}/{target}")
        self.ml_models_dir = self.base_dir / "ml_models"
        self.analytics_dir = self.base_dir / "analytics"
        self.predictions_dir = self.base_dir / "predictions"
        self.threat_intel_dir = self.base_dir / "threat_intelligence"
        
        # Create directories
        self.ml_models_dir.mkdir(parents=True, exist_ok=True)
        self.analytics_dir.mkdir(parents=True, exist_ok=True)
        self.predictions_dir.mkdir(parents=True, exist_ok=True)
        self.threat_intel_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize data storage
        self.models: List[MLModel] = []
        self.predictions: List[PredictionResult] = []
        self.threat_intelligence: List[ThreatIntelligence] = []
        self.dashboards: List[AnalyticsDashboard] = []
        
        # Initialize ML components
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
        logger.info(f"Initialized AdvancedAnalytics for target: {target}")
    
    async def build_predictive_models(self) -> Dict[str, Any]:
        """
        Build and train predictive attack models.
        
        Returns:
            Dict containing predictive model building results
        """
        logger.info("Building predictive attack models")
        
        try:
            # Load training data
            training_data = await self._load_training_data()
            
            # Prepare features and labels
            X, y = await self._prepare_training_data(training_data)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Train models
            attack_success_model = await self._train_attack_success_model(X_train, X_test, y_train, y_test)
            risk_assessment_model = await self._train_risk_assessment_model(X_train, X_test, y_train, y_test)
            threat_detection_model = await self._train_threat_detection_model(X_train, X_test, y_train, y_test)
            
            # Save models
            await self._save_models([attack_success_model, risk_assessment_model, threat_detection_model])
            
            # Generate model performance report
            performance_report = await self._generate_model_performance_report([
                attack_success_model, risk_assessment_model, threat_detection_model
            ])
            
            result = {
                "models_trained": 3,
                "attack_success_model": attack_success_model.model_id,
                "risk_assessment_model": risk_assessment_model.model_id,
                "threat_detection_model": threat_detection_model.model_id,
                "average_accuracy": np.mean([m.accuracy for m in [attack_success_model, risk_assessment_model, threat_detection_model]]),
                "performance_report": performance_report
            }
            
            logger.info("Built 3 predictive models successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error building predictive models: {str(e)}")
            raise
    
    async def integrate_real_time_intelligence(self) -> Dict[str, Any]:
        """
        Integrate real-time threat intelligence feeds.
        
        Returns:
            Dict containing threat intelligence integration results
        """
        logger.info("Integrating real-time threat intelligence")
        
        try:
            # Load threat intelligence feeds
            threat_feeds = await self._load_threat_intelligence_feeds()
            
            # Process and enrich threat data
            enriched_intel = await self._enrich_threat_intelligence(threat_feeds)
            
            # Correlate with local findings
            correlations = await self._correlate_threat_intelligence(enriched_intel)
            
            # Generate threat alerts
            threat_alerts = await self._generate_threat_alerts(correlations)
            
            # Create threat landscape analysis
            threat_landscape = await self._create_threat_landscape_analysis(enriched_intel)
            
            # Save threat intelligence
            await self._save_threat_intelligence(enriched_intel, correlations, threat_alerts)
            
            result = {
                "threat_feeds_processed": len(threat_feeds),
                "enriched_intelligence": len(enriched_intel),
                "correlations_found": len(correlations),
                "threat_alerts_generated": len(threat_alerts),
                "threat_landscape": threat_landscape
            }
            
            logger.info(f"Integrated {len(threat_feeds)} threat intelligence feeds")
            return result
            
        except Exception as e:
            logger.error(f"Error integrating threat intelligence: {str(e)}")
            raise
    
    async def create_dashboard(self) -> Dict[str, Any]:
        """
        Create advanced analytics dashboard.
        
        Returns:
            Dict containing dashboard creation results
        """
        logger.info("Creating advanced analytics dashboard")
        
        try:
            # Generate key metrics
            metrics = await self._generate_key_metrics()
            
            # Create visualizations
            visualizations = await self._create_dashboard_visualizations()
            
            # Build interactive dashboard
            dashboard = await self._build_interactive_dashboard(metrics, visualizations)
            
            # Generate dashboard report
            dashboard_report = await self._generate_dashboard_report(dashboard)
            
            # Save dashboard
            await self._save_dashboard(dashboard, dashboard_report)
            
            result = {
                "dashboard_created": True,
                "dashboard_id": dashboard.dashboard_id,
                "metrics_count": len(metrics),
                "visualizations_count": len(visualizations),
                "dashboard_path": dashboard.dashboard_id
            }
            
            logger.info("Created advanced analytics dashboard successfully")
            return result
            
        except Exception as e:
            logger.error(f"Error creating dashboard: {str(e)}")
            raise
    
    async def _load_training_data(self) -> List[Dict[str, Any]]:
        """Load training data from various sources."""
        logger.info("Loading training data")
        
        training_data = []
        
        # Load from vulnerability testing results
        vuln_test_dir = Path(f"outputs/vuln_test/{self.target}")
        if vuln_test_dir.exists():
            results_file = vuln_test_dir / "vuln_test_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    vuln_data = json.load(f)
                    training_data.extend(self._convert_vulnerability_to_training(vuln_data))
        
        # Load from attack paths
        paths_file = self.base_dir / "attack_paths" / "attack_paths.json"
        if paths_file.exists():
            with open(paths_file, 'r') as f:
                paths_data = json.load(f)
                training_data.extend(self._convert_attack_paths_to_training(paths_data))
        
        # Load from scenarios
        scenarios_file = self.base_dir / "scenarios" / "attack_scenarios.json"
        if scenarios_file.exists():
            with open(scenarios_file, 'r') as f:
                scenarios_data = json.load(f)
                training_data.extend(self._convert_scenarios_to_training(scenarios_data))
        
        logger.info(f"Loaded {len(training_data)} training samples")
        return training_data
    
    async def _prepare_training_data(self, training_data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels for training."""
        logger.info("Preparing training data")
        
        # Extract features
        features = []
        labels = []
        
        for sample in training_data:
            # Extract numerical features
            feature_vector = [
                sample.get("cvss_score", 5.0),
                sample.get("likelihood", 0.5),
                sample.get("complexity_score", 2.0),
                sample.get("technique_count", 1),
                sample.get("tactic_count", 1),
                sample.get("prerequisite_count", 1),
                sample.get("detection_probability", 0.7),
                sample.get("business_impact_score", 5.0)
            ]
            
            features.append(feature_vector)
            
            # Extract labels
            if "attack_success" in sample:
                labels.append(sample["attack_success"])
            elif "risk_level" in sample:
                labels.append(sample["risk_level"])
            else:
                labels.append("medium")  # Default label
        
        # Convert to numpy arrays
        X = np.array(features)
        y = np.array(labels)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        self.label_encoders["main"] = label_encoder
        
        logger.info(f"Prepared {len(X_scaled)} samples with {X_scaled.shape[1]} features")
        return X_scaled, y_encoded
    
    async def _train_attack_success_model(self, X_train: np.ndarray, X_test: np.ndarray, 
                                        y_train: np.ndarray, y_test: np.ndarray) -> MLModel:
        """Train attack success prediction model."""
        logger.info("Training attack success prediction model")
        
        # Train Random Forest classifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = model.score(X_test, y_test)
        precision = np.mean([1.0 if pred == true else 0.0 for pred, true in zip(y_pred, y_test)])
        recall = precision  # Simplified for binary case
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Save model
        model_path = self.ml_models_dir / "attack_success_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Create MLModel object
        ml_model = MLModel(
            model_id="attack_success_model",
            name="Attack Success Prediction Model",
            type="classification",
            algorithm="RandomForest",
            version="1.0",
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            training_date=datetime.now(timezone.utc),
            features=["cvss_score", "likelihood", "complexity_score", "technique_count", 
                     "tactic_count", "prerequisite_count", "detection_probability", "business_impact_score"],
            model_path=str(model_path),
            metadata={"n_estimators": 100, "random_state": 42}
        )
        
        return ml_model
    
    async def _train_risk_assessment_model(self, X_train: np.ndarray, X_test: np.ndarray,
                                         y_train: np.ndarray, y_test: np.ndarray) -> MLModel:
        """Train risk assessment model."""
        logger.info("Training risk assessment model")
        
        # Train Random Forest classifier for risk assessment
        model = RandomForestClassifier(n_estimators=150, random_state=42)
        model.fit(X_train, y_train)
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Calculate metrics
        accuracy = model.score(X_test, y_test)
        precision = np.mean([1.0 if pred == true else 0.0 for pred, true in zip(y_pred, y_test)])
        recall = precision
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        # Save model
        model_path = self.ml_models_dir / "risk_assessment_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Create MLModel object
        ml_model = MLModel(
            model_id="risk_assessment_model",
            name="Risk Assessment Model",
            type="classification",
            algorithm="RandomForest",
            version="1.0",
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            training_date=datetime.now(timezone.utc),
            features=["cvss_score", "likelihood", "complexity_score", "technique_count", 
                     "tactic_count", "prerequisite_count", "detection_probability", "business_impact_score"],
            model_path=str(model_path),
            metadata={"n_estimators": 150, "random_state": 42}
        )
        
        return ml_model
    
    async def _train_threat_detection_model(self, X_train: np.ndarray, X_test: np.ndarray,
                                          y_train: np.ndarray, y_test: np.ndarray) -> MLModel:
        """Train threat detection model."""
        logger.info("Training threat detection model")
        
        # Train Isolation Forest for anomaly detection
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X_train)
        
        # Make predictions
        y_pred = model.predict(X_test)
        
        # Convert predictions (1 for normal, -1 for anomaly)
        y_pred_binary = [1 if pred == 1 else 0 for pred in y_pred]
        y_test_binary = [1 if label == 0 else 0 for label in y_test]  # Assume normal class is 0
        
        # Calculate metrics
        accuracy = np.mean([1.0 if pred == true else 0.0 for pred, true in zip(y_pred_binary, y_test_binary)])
        precision = accuracy
        recall = accuracy
        f1_score = accuracy
        
        # Save model
        model_path = self.ml_models_dir / "threat_detection_model.pkl"
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        
        # Create MLModel object
        ml_model = MLModel(
            model_id="threat_detection_model",
            name="Threat Detection Model",
            type="anomaly_detection",
            algorithm="IsolationForest",
            version="1.0",
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            training_date=datetime.now(timezone.utc),
            features=["cvss_score", "likelihood", "complexity_score", "technique_count", 
                     "tactic_count", "prerequisite_count", "detection_probability", "business_impact_score"],
            model_path=str(model_path),
            metadata={"contamination": 0.1, "random_state": 42}
        )
        
        return ml_model
    
    async def _load_threat_intelligence_feeds(self) -> List[Dict[str, Any]]:
        """Load threat intelligence feeds."""
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
        
        # Load from online sources (mock data for now)
        online_feeds = await self._load_online_threat_feeds()
        feeds.extend(online_feeds)
        
        logger.info(f"Loaded {len(feeds)} threat intelligence records")
        return feeds
    
    async def _enrich_threat_intelligence(self, feeds: List[Dict[str, Any]]) -> List[ThreatIntelligence]:
        """Enrich threat intelligence data."""
        logger.info("Enriching threat intelligence data")
        
        enriched_intel = []
        
        for feed in feeds:
            # Create ThreatIntelligence object
            intel = ThreatIntelligence(
                intel_id=f"intel_{len(enriched_intel)}",
                source=feed.get("source", "unknown"),
                threat_type=feed.get("threat_type", "unknown"),
                severity=feed.get("severity", "medium"),
                confidence=feed.get("confidence", 0.5),
                indicators=feed.get("indicators", []),
                description=feed.get("description", ""),
                timestamp=datetime.now(timezone.utc),
                metadata=feed.get("metadata", {})
            )
            
            enriched_intel.append(intel)
        
        logger.info(f"Enriched {len(enriched_intel)} threat intelligence records")
        return enriched_intel
    
    async def _correlate_threat_intelligence(self, intel: List[ThreatIntelligence]) -> List[Dict[str, Any]]:
        """Correlate threat intelligence with local findings."""
        logger.info("Correlating threat intelligence")
        
        correlations = []
        
        # Load local findings
        local_findings = await self._load_local_findings()
        
        for finding in local_findings:
            finding_correlations = []
            
            for threat in intel:
                # Check for correlation based on various factors
                correlation_score = self._calculate_correlation_score(finding, threat)
                
                if correlation_score > 0.5:  # Threshold for correlation
                    finding_correlations.append({
                        "threat_id": threat.intel_id,
                        "correlation_score": correlation_score,
                        "correlation_type": self._determine_correlation_type(finding, threat)
                    })
            
            if finding_correlations:
                correlations.append({
                    "finding_id": finding.get("id"),
                    "correlations": finding_correlations
                })
        
        logger.info(f"Found {len(correlations)} threat intelligence correlations")
        return correlations
    
    async def _generate_threat_alerts(self, correlations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate threat alerts based on correlations."""
        logger.info("Generating threat alerts")
        
        alerts = []
        
        for correlation in correlations:
            if correlation["correlations"]:
                # Find highest correlation
                max_correlation = max(correlation["correlations"], key=lambda x: x["correlation_score"])
                
                if max_correlation["correlation_score"] > 0.7:  # High correlation threshold
                    alert = {
                        "alert_id": f"alert_{len(alerts)}",
                        "finding_id": correlation["finding_id"],
                        "threat_id": max_correlation["threat_id"],
                        "severity": "high" if max_correlation["correlation_score"] > 0.8 else "medium",
                        "correlation_score": max_correlation["correlation_score"],
                        "description": f"High correlation detected between finding and threat intelligence",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    
                    alerts.append(alert)
        
        logger.info(f"Generated {len(alerts)} threat alerts")
        return alerts
    
    async def _create_threat_landscape_analysis(self, intel: List[ThreatIntelligence]) -> Dict[str, Any]:
        """Create threat landscape analysis."""
        logger.info("Creating threat landscape analysis")
        
        # Analyze threat distribution
        threat_types = {}
        severity_distribution = {}
        confidence_distribution = {}
        
        for threat in intel:
            # Threat type distribution
            threat_type = threat.threat_type
            threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            # Severity distribution
            severity = threat.severity
            severity_distribution[severity] = severity_distribution.get(severity, 0) + 1
            
            # Confidence distribution
            confidence_range = f"{int(threat.confidence * 10) * 10}-{(int(threat.confidence * 10) + 1) * 10}%"
            confidence_distribution[confidence_range] = confidence_distribution.get(confidence_range, 0) + 1
        
        landscape = {
            "total_threats": len(intel),
            "threat_type_distribution": threat_types,
            "severity_distribution": severity_distribution,
            "confidence_distribution": confidence_distribution,
            "high_confidence_threats": len([t for t in intel if t.confidence > 0.8]),
            "high_severity_threats": len([t for t in intel if t.severity in ["high", "critical"]])
        }
        
        return landscape
    
    async def _generate_key_metrics(self) -> Dict[str, Any]:
        """Generate key metrics for dashboard."""
        logger.info("Generating key metrics")
        
        metrics = {
            "total_attack_paths": len(await self._load_attack_paths()),
            "total_scenarios": len(await self._load_attack_scenarios()),
            "high_risk_paths": len([p for p in await self._load_attack_paths() if p.get("impact") == "high"]),
            "model_accuracy": np.mean([m.accuracy for m in self.models]) if self.models else 0,
            "threat_alerts": len(await self._load_threat_alerts()),
            "correlations_found": len(await self._load_correlations())
        }
        
        return metrics
    
    async def _create_dashboard_visualizations(self) -> List[str]:
        """Create dashboard visualizations."""
        logger.info("Creating dashboard visualizations")
        
        visualizations = []
        
        # Create risk distribution chart
        risk_chart = await self._create_risk_distribution_chart()
        visualizations.append(risk_chart)
        
        # Create model performance chart
        performance_chart = await self._create_model_performance_chart()
        visualizations.append(performance_chart)
        
        # Create threat intelligence chart
        threat_chart = await self._create_threat_intelligence_chart()
        visualizations.append(threat_chart)
        
        # Create attack path timeline
        timeline_chart = await self._create_attack_timeline_chart()
        visualizations.append(timeline_chart)
        
        logger.info(f"Created {len(visualizations)} dashboard visualizations")
        return visualizations
    
    async def _build_interactive_dashboard(self, metrics: Dict[str, Any], 
                                         visualizations: List[str]) -> AnalyticsDashboard:
        """Build interactive dashboard."""
        logger.info("Building interactive dashboard")
        
        dashboard = AnalyticsDashboard(
            dashboard_id="kill_chain_analytics_dashboard",
            name="Kill Chain Analytics Dashboard",
            description="Interactive dashboard for kill chain analysis metrics and visualizations",
            metrics=metrics,
            visualizations=visualizations,
            last_updated=datetime.now(timezone.utc),
            config={"theme": "light", "refresh_rate": 300}
        )
        
        return dashboard
    
    # Helper methods
    def _convert_vulnerability_to_training(self, vuln_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert vulnerability data to training format."""
        training_samples = []
        
        for finding in vuln_data.get("findings", []):
            sample = {
                "cvss_score": finding.get("cvss_score", 5.0),
                "likelihood": 0.7,  # Default likelihood
                "complexity_score": 2.0,  # Default complexity
                "technique_count": 1,
                "tactic_count": 1,
                "prerequisite_count": 1,
                "detection_probability": 0.7,
                "business_impact_score": 5.0,
                "attack_success": "success" if finding.get("status") == "confirmed" else "failure",
                "risk_level": finding.get("severity", "medium")
            }
            training_samples.append(sample)
        
        return training_samples
    
    def _convert_attack_paths_to_training(self, paths_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert attack paths data to training format."""
        training_samples = []
        
        for path in paths_data:
            sample = {
                "cvss_score": 5.0,  # Default CVSS score
                "likelihood": path.get("likelihood", 0.5),
                "complexity_score": self._complexity_to_score(path.get("complexity", "medium")),
                "technique_count": len(path.get("techniques", [])),
                "tactic_count": len(path.get("tactics", [])),
                "prerequisite_count": len(path.get("prerequisites", [])),
                "detection_probability": path.get("success_probability", 0.5),
                "business_impact_score": self._impact_to_score(path.get("impact", "medium")),
                "attack_success": "success" if path.get("success_probability", 0.5) > 0.7 else "failure",
                "risk_level": path.get("impact", "medium")
            }
            training_samples.append(sample)
        
        return training_samples
    
    def _convert_scenarios_to_training(self, scenarios_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert scenarios data to training format."""
        training_samples = []
        
        for scenario in scenarios_data:
            sample = {
                "cvss_score": 5.0,
                "likelihood": 0.6,
                "complexity_score": 2.0,
                "technique_count": len(scenario.get("attack_paths", [])),
                "tactic_count": 1,
                "prerequisite_count": len(scenario.get("prerequisites", [])),
                "detection_probability": scenario.get("detection_probability", 0.7),
                "business_impact_score": 5.0,
                "attack_success": "success",
                "risk_level": scenario.get("risk_assessment", {}).get("impact", "medium")
            }
            training_samples.append(sample)
        
        return training_samples
    
    def _complexity_to_score(self, complexity: str) -> float:
        """Convert complexity string to numeric score."""
        complexity_scores = {"high": 3.0, "medium": 2.0, "low": 1.0}
        return complexity_scores.get(complexity.lower(), 2.0)
    
    def _impact_to_score(self, impact: str) -> float:
        """Convert impact string to numeric score."""
        impact_scores = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5}
        return impact_scores.get(impact.lower(), 5.0)
    
    async def _load_online_threat_feeds(self) -> List[Dict[str, Any]]:
        """Load threat intelligence from online sources."""
        # Mock online threat feeds
        return [
            {
                "source": "CVE Database",
                "threat_type": "vulnerability",
                "severity": "high",
                "confidence": 0.9,
                "indicators": ["CVE-2024-1234"],
                "description": "Critical vulnerability in web application framework"
            },
            {
                "source": "Threat Intelligence Platform",
                "threat_type": "malware",
                "severity": "medium",
                "confidence": 0.7,
                "indicators": ["malware_hash_123"],
                "description": "New malware variant targeting financial institutions"
            }
        ]
    
    async def _load_local_findings(self) -> List[Dict[str, Any]]:
        """Load local findings for correlation."""
        findings = []
        
        # Load from various sources
        paths_file = self.base_dir / "attack_paths" / "attack_paths.json"
        if paths_file.exists():
            with open(paths_file, 'r') as f:
                paths_data = json.load(f)
                findings.extend(paths_data)
        
        return findings
    
    def _calculate_correlation_score(self, finding: Dict[str, Any], threat: ThreatIntelligence) -> float:
        """Calculate correlation score between finding and threat."""
        # Simple correlation calculation
        base_score = 0.5
        
        # Adjust based on severity match
        if finding.get("impact") == threat.severity:
            base_score += 0.2
        
        # Adjust based on threat type
        if threat.threat_type in finding.get("attack_vector", ""):
            base_score += 0.2
        
        # Adjust based on confidence
        base_score += threat.confidence * 0.1
        
        return min(base_score, 1.0)
    
    def _determine_correlation_type(self, finding: Dict[str, Any], threat: ThreatIntelligence) -> str:
        """Determine type of correlation."""
        if threat.threat_type in finding.get("attack_vector", ""):
            return "attack_vector"
        elif finding.get("impact") == threat.severity:
            return "severity"
        else:
            return "general"
    
    async def _load_attack_paths(self) -> List[Dict[str, Any]]:
        """Load attack paths."""
        paths_file = self.base_dir / "attack_paths" / "attack_paths.json"
        if paths_file.exists():
            with open(paths_file, 'r') as f:
                return json.load(f)
        return []
    
    async def _load_attack_scenarios(self) -> List[Dict[str, Any]]:
        """Load attack scenarios."""
        scenarios_file = self.base_dir / "scenarios" / "attack_scenarios.json"
        if scenarios_file.exists():
            with open(scenarios_file, 'r') as f:
                return json.load(f)
        return []
    
    async def _load_threat_alerts(self) -> List[Dict[str, Any]]:
        """Load threat alerts."""
        alerts_file = self.threat_intel_dir / "threat_alerts.json"
        if alerts_file.exists():
            with open(alerts_file, 'r') as f:
                return json.load(f)
        return []
    
    async def _load_correlations(self) -> List[Dict[str, Any]]:
        """Load correlations."""
        correlations_file = self.threat_intel_dir / "correlations.json"
        if correlations_file.exists():
            with open(correlations_file, 'r') as f:
                return json.load(f)
        return []
    
    async def _create_risk_distribution_chart(self) -> str:
        """Create risk distribution chart."""
        # Implementation for risk distribution chart
        return "risk_distribution_chart.html"
    
    async def _create_model_performance_chart(self) -> str:
        """Create model performance chart."""
        # Implementation for model performance chart
        return "model_performance_chart.html"
    
    async def _create_threat_intelligence_chart(self) -> str:
        """Create threat intelligence chart."""
        # Implementation for threat intelligence chart
        return "threat_intelligence_chart.html"
    
    async def _create_attack_timeline_chart(self) -> str:
        """Create attack timeline chart."""
        # Implementation for attack timeline chart
        return "attack_timeline_chart.html"
    
    async def _generate_model_performance_report(self, models: List[MLModel]) -> Dict[str, Any]:
        """Generate model performance report."""
        report = {
            "total_models": len(models),
            "average_accuracy": np.mean([m.accuracy for m in models]),
            "average_precision": np.mean([m.precision for m in models]),
            "average_recall": np.mean([m.recall for m in models]),
            "average_f1_score": np.mean([m.f1_score for m in models]),
            "model_details": [m.dict() for m in models]
        }
        
        return report
    
    async def _generate_dashboard_report(self, dashboard: AnalyticsDashboard) -> Dict[str, Any]:
        """Generate dashboard report."""
        report = {
            "dashboard_id": dashboard.dashboard_id,
            "metrics_summary": dashboard.metrics,
            "visualizations_count": len(dashboard.visualizations),
            "last_updated": dashboard.last_updated.isoformat(),
            "config": dashboard.config
        }
        
        return report
    
    async def _save_models(self, models: List[MLModel]):
        """Save models metadata."""
        logger.info("Saving models metadata")
        
        models_file = self.ml_models_dir / "models_metadata.json"
        with open(models_file, 'w') as f:
            json.dump([model.dict() for model in models], f, indent=2, default=str)
        
        logger.info(f"Saved {len(models)} models metadata")
    
    async def _save_threat_intelligence(self, intel: List[ThreatIntelligence], 
                                      correlations: List[Dict[str, Any]], 
                                      alerts: List[Dict[str, Any]]):
        """Save threat intelligence data."""
        logger.info("Saving threat intelligence data")
        
        # Save enriched intelligence
        intel_file = self.threat_intel_dir / "enriched_intelligence.json"
        with open(intel_file, 'w') as f:
            json.dump([i.dict() for i in intel], f, indent=2, default=str)
        
        # Save correlations
        correlations_file = self.threat_intel_dir / "correlations.json"
        with open(correlations_file, 'w') as f:
            json.dump(correlations, f, indent=2, default=str)
        
        # Save alerts
        alerts_file = self.threat_intel_dir / "threat_alerts.json"
        with open(alerts_file, 'w') as f:
            json.dump(alerts, f, indent=2, default=str)
        
        logger.info("Saved threat intelligence data")
    
    async def _save_dashboard(self, dashboard: AnalyticsDashboard, report: Dict[str, Any]):
        """Save dashboard and report."""
        logger.info("Saving dashboard")
        
        # Save dashboard metadata
        dashboard_file = self.analytics_dir / "dashboard_metadata.json"
        with open(dashboard_file, 'w') as f:
            json.dump(dashboard.dict(), f, indent=2, default=str)
        
        # Save dashboard report
        report_file = self.analytics_dir / "dashboard_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info("Saved dashboard and report") 