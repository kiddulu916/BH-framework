#!/usr/bin/env python3
"""
AI Analyzer Runner for Stage 4: Step 4.3

This module implements AI-driven vulnerability analysis with real-time correlation,
false positive reduction, risk scoring, CWE/CVE mapping, and exploit generation.
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import re

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import StandardScaler

# Try to import ML libraries, fallback to basic implementations if not available
try:
    import torch
    import transformers
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logging.warning("PyTorch/Transformers not available, using basic ML implementations")

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    logging.warning("TensorFlow not available, using basic ML implementations")

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityPattern:
    """Represents a vulnerability pattern for AI analysis."""
    
    pattern_id: str
    name: str
    description: str
    category: str
    severity: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cve_examples: List[str] = field(default_factory=list)
    exploit_templates: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)


@dataclass
class AIAnalysisResult:
    """Represents the result of AI analysis on a vulnerability finding."""
    
    finding_id: str
    ai_confidence: float
    false_positive_probability: float
    risk_score: float
    cvss_score: float
    cwe_mappings: List[str] = field(default_factory=list)
    cve_references: List[str] = field(default_factory=list)
    suggested_exploits: List[str] = field(default_factory=list)
    remediation_advice: str = ""
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)


class AIAnalyzer:
    """AI-driven vulnerability analyzer for real-time analysis and correlation."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.ai_dir = self.output_dir / "ai_analysis"
        self.ai_dir.mkdir(parents=True, exist_ok=True)
        
        # AI configuration
        self.ai_confidence_threshold = config.ai_confidence_threshold
        self.enable_ai_analysis = config.enable_ai_analysis
        
        # Analysis results
        self.analysis_results: List[AIAnalysisResult] = []
        
        # Initialize AI models and patterns
        self.vulnerability_patterns = self._initialize_vulnerability_patterns()
        self.false_positive_detector = None
        self.risk_scorer = None
        self.correlation_engine = None
        
        # Initialize AI models if available
        if self.enable_ai_analysis:
            self._initialize_ai_models()
    
    def _initialize_vulnerability_patterns(self) -> List[VulnerabilityPattern]:
        """Initialize vulnerability patterns for AI analysis."""
        patterns = [
            VulnerabilityPattern(
                pattern_id="sql_injection",
                name="SQL Injection",
                description="SQL injection vulnerability allowing database manipulation",
                category="Injection",
                severity="Critical",
                confidence=0.9,
                indicators=[
                    "sql syntax", "mysql error", "oracle error", "postgresql error",
                    "union select", "drop table", "insert into", "delete from"
                ],
                cwe_ids=["CWE-89"],
                cve_examples=["CVE-2021-44228", "CVE-2020-1472"],
                exploit_templates=[
                    "' OR 1=1--",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--"
                ],
                false_positive_indicators=[
                    "intentional error message", "test environment", "debug mode"
                ]
            ),
            VulnerabilityPattern(
                pattern_id="xss_reflected",
                name="Reflected Cross-Site Scripting",
                description="Reflected XSS vulnerability allowing script injection",
                category="XSS",
                severity="High",
                confidence=0.8,
                indicators=[
                    "<script>", "javascript:", "onerror=", "onload=",
                    "alert(", "confirm(", "prompt("
                ],
                cwe_ids=["CWE-79"],
                cve_examples=["CVE-2021-34527", "CVE-2020-1350"],
                exploit_templates=[
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert('XSS')>",
                    "javascript:alert('XSS')"
                ],
                false_positive_indicators=[
                    "content security policy", "xss protection", "sanitized output"
                ]
            ),
            VulnerabilityPattern(
                pattern_id="authentication_bypass",
                name="Authentication Bypass",
                description="Authentication bypass vulnerability",
                category="Authentication",
                severity="High",
                confidence=0.7,
                indicators=[
                    "admin access", "unauthorized access", "bypass auth",
                    "privilege escalation", "root access"
                ],
                cwe_ids=["CWE-287", "CWE-288"],
                cve_examples=["CVE-2021-44228", "CVE-2020-1472"],
                exploit_templates=[
                    "admin:admin",
                    "root:",
                    "guest:guest"
                ],
                false_positive_indicators=[
                    "test environment", "demo mode", "development server"
                ]
            ),
            VulnerabilityPattern(
                pattern_id="information_disclosure",
                name="Information Disclosure",
                description="Sensitive information disclosure vulnerability",
                category="Information Disclosure",
                severity="Medium",
                confidence=0.6,
                indicators=[
                    "version", "build", "environment", "debug",
                    "database", "config", "secret", "key", "token"
                ],
                cwe_ids=["CWE-200"],
                cve_examples=["CVE-2021-34527", "CVE-2020-1350"],
                exploit_templates=[
                    "curl -I http://target/",
                    "wget --spider http://target/",
                    "nmap -sV target"
                ],
                false_positive_indicators=[
                    "public information", "intentional disclosure", "documentation"
                ]
            ),
            VulnerabilityPattern(
                pattern_id="weak_encryption",
                name="Weak Encryption",
                description="Weak encryption or cryptographic implementation",
                category="Cryptography",
                severity="High",
                confidence=0.8,
                indicators=[
                    "md5", "sha1", "des", "3des", "rc4",
                    "weak cipher", "outdated protocol"
                ],
                cwe_ids=["CWE-327", "CWE-326"],
                cve_examples=["CVE-2021-34527", "CVE-2020-1350"],
                exploit_templates=[
                    "hashcat -m 0 hash wordlist",
                    "john --format=raw-md5 hash",
                    "crackmapexec smb target"
                ],
                false_positive_indicators=[
                    "test certificate", "development environment", "legacy system"
                ]
            )
        ]
        
        return patterns
    
    def _initialize_ai_models(self):
        """Initialize AI models for vulnerability analysis."""
        try:
            logger.info("Initializing AI models for vulnerability analysis...")
            
            # Initialize false positive detector
            self.false_positive_detector = self._create_false_positive_detector()
            
            # Initialize risk scorer
            self.risk_scorer = self._create_risk_scorer()
            
            # Initialize correlation engine
            self.correlation_engine = self._create_correlation_engine()
            
            logger.info("AI models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing AI models: {str(e)}")
            # Fallback to basic implementations
            self._initialize_basic_models()
    
    def _create_false_positive_detector(self):
        """Create false positive detection model."""
        try:
            if TENSORFLOW_AVAILABLE:
                # Use TensorFlow for false positive detection
                model = tf.keras.Sequential([
                    tf.keras.layers.Dense(64, activation='relu', input_shape=(10,)),
                    tf.keras.layers.Dropout(0.2),
                    tf.keras.layers.Dense(32, activation='relu'),
                    tf.keras.layers.Dropout(0.2),
                    tf.keras.layers.Dense(1, activation='sigmoid')
                ])
                model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
                return model
            else:
                # Use scikit-learn Isolation Forest
                return IsolationForest(contamination=0.1, random_state=42)
                
        except Exception as e:
            logger.error(f"Error creating false positive detector: {str(e)}")
            return None
    
    def _create_risk_scorer(self):
        """Create risk scoring model."""
        try:
            if TENSORFLOW_AVAILABLE:
                # Use TensorFlow for risk scoring
                model = tf.keras.Sequential([
                    tf.keras.layers.Dense(128, activation='relu', input_shape=(15,)),
                    tf.keras.layers.Dropout(0.3),
                    tf.keras.layers.Dense(64, activation='relu'),
                    tf.keras.layers.Dropout(0.3),
                    tf.keras.layers.Dense(32, activation='relu'),
                    tf.keras.layers.Dense(1, activation='sigmoid')
                ])
                model.compile(optimizer='adam', loss='mse', metrics=['mae'])
                return model
            else:
                # Use Random Forest for risk scoring
                return RandomForestClassifier(n_estimators=100, random_state=42)
                
        except Exception as e:
            logger.error(f"Error creating risk scorer: {str(e)}")
            return None
    
    def _create_correlation_engine(self):
        """Create correlation engine for finding relationships."""
        try:
            # Use TF-IDF vectorizer for text correlation
            return TfidfVectorizer(max_features=1000, stop_words='english')
            
        except Exception as e:
            logger.error(f"Error creating correlation engine: {str(e)}")
            return None
    
    def _initialize_basic_models(self):
        """Initialize basic ML models as fallback."""
        try:
            logger.info("Initializing basic ML models as fallback...")
            
            # Basic false positive detector using Isolation Forest
            self.false_positive_detector = IsolationForest(contamination=0.1, random_state=42)
            
            # Basic risk scorer using Random Forest
            self.risk_scorer = RandomForestClassifier(n_estimators=100, random_state=42)
            
            # Basic correlation engine using TF-IDF
            self.correlation_engine = TfidfVectorizer(max_features=1000, stop_words='english')
            
            logger.info("Basic ML models initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing basic models: {str(e)}")
    
    def correlate_and_classify(self, findings: List[Any]) -> List[Any]:
        """
        Correlate and classify vulnerability findings using AI.
        
        Args:
            findings: List of vulnerability findings from previous stages
            
        Returns:
            List[Any]: Classified and correlated findings
        """
        logger.info("Starting AI-driven correlation and classification...")
        
        try:
            if not self.enable_ai_analysis:
                logger.info("AI analysis disabled, returning original findings")
                return findings
            
            # Extract features from findings
            features = self._extract_finding_features(findings)
            
            # Correlate findings
            correlated_findings = self._correlate_findings(findings, features)
            
            # Classify findings
            classified_findings = self._classify_findings(correlated_findings)
            
            logger.info(f"Correlation and classification completed. Processed {len(classified_findings)} findings")
            
            return classified_findings
            
        except Exception as e:
            logger.error(f"Error in correlation and classification: {str(e)}")
            return findings
    
    def _extract_finding_features(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Extract features from vulnerability findings for AI analysis."""
        features = []
        
        for finding in findings:
            feature_vector = {
                'severity_score': self._severity_to_score(finding.severity),
                'confidence_score': finding.confidence,
                'text_length': len(finding.description + finding.evidence),
                'has_payload': 1 if finding.payload_used else 0,
                'has_evidence': 1 if finding.evidence else 0,
                'has_error_messages': 1 if any(error in finding.evidence.lower() for error in ['error', 'exception', 'fail']) else 0,
                'has_sql_indicators': 1 if any(indicator in finding.evidence.lower() for indicator in ['sql', 'mysql', 'oracle', 'postgres']) else 0,
                'has_xss_indicators': 1 if any(indicator in finding.evidence.lower() for indicator in ['script', 'javascript', 'alert']) else 0,
                'has_auth_indicators': 1 if any(indicator in finding.evidence.lower() for indicator in ['auth', 'login', 'admin', 'root']) else 0,
                'has_info_disclosure': 1 if any(indicator in finding.evidence.lower() for indicator in ['version', 'config', 'debug', 'secret']) else 0
            }
            features.append(feature_vector)
        
        return features
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity string to numerical score."""
        severity_map = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.6,
            "Low": 0.4,
            "Info": 0.2
        }
        return severity_map.get(severity, 0.5)
    
    def _correlate_findings(self, findings: List[Any], features: List[Dict[str, Any]]) -> List[Any]:
        """Correlate findings to identify relationships and patterns."""
        try:
            logger.info("Correlating findings for pattern recognition...")
            
            # Create feature matrix
            feature_matrix = []
            for feature in features:
                feature_matrix.append([
                    feature['severity_score'],
                    feature['confidence_score'],
                    feature['text_length'],
                    feature['has_payload'],
                    feature['has_evidence'],
                    feature['has_error_messages'],
                    feature['has_sql_indicators'],
                    feature['has_xss_indicators'],
                    feature['has_auth_indicators'],
                    feature['has_info_disclosure']
                ])
            
            # Use correlation engine to find similar findings
            if self.correlation_engine and len(feature_matrix) > 1:
                # Convert to numpy array
                feature_array = np.array(feature_matrix)
                
                # Calculate similarity matrix
                similarity_matrix = cosine_similarity(feature_array)
                
                # Group similar findings
                correlated_groups = self._group_similar_findings(findings, similarity_matrix)
                
                # Update findings with correlation information
                for i, finding in enumerate(findings):
                    finding.correlation_group = correlated_groups.get(i, i)
                    finding.similarity_scores = similarity_matrix[i].tolist() if i < len(similarity_matrix) else []
            
            logger.info(f"Correlation completed. Found relationships between findings")
            
            return findings
            
        except Exception as e:
            logger.error(f"Error correlating findings: {str(e)}")
            return findings
    
    def _group_similar_findings(self, findings: List[Any], similarity_matrix: np.ndarray) -> Dict[int, int]:
        """Group similar findings based on similarity matrix."""
        groups = {}
        threshold = 0.7  # Similarity threshold
        
        for i in range(len(similarity_matrix)):
            if i not in groups:
                groups[i] = i
                
                for j in range(i + 1, len(similarity_matrix)):
                    if similarity_matrix[i][j] > threshold:
                        groups[j] = i
        
        return groups
    
    def _classify_findings(self, findings: List[Any]) -> List[Any]:
        """Classify findings using vulnerability patterns."""
        try:
            logger.info("Classifying findings using vulnerability patterns...")
            
            for finding in findings:
                # Match finding against vulnerability patterns
                best_match = self._match_vulnerability_pattern(finding)
                
                if best_match:
                    finding.vulnerability_type = best_match.name
                    finding.cwe_ids = best_match.cwe_ids
                    finding.cve_examples = best_match.cve_examples
                    finding.pattern_confidence = best_match.confidence
                
                # Apply AI classification if models are available
                if self.risk_scorer:
                    risk_score = self._calculate_risk_score(finding)
                    finding.ai_risk_score = risk_score
            
            logger.info(f"Classification completed. Applied patterns to {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            logger.error(f"Error classifying findings: {str(e)}")
            return findings
    
    def _match_vulnerability_pattern(self, finding: Any) -> Optional[VulnerabilityPattern]:
        """Match a finding against vulnerability patterns."""
        best_match = None
        best_score = 0.0
        
        # Combine finding text for pattern matching
        finding_text = f"{finding.title} {finding.description} {finding.evidence}".lower()
        
        for pattern in self.vulnerability_patterns:
            score = 0.0
            matches = 0
            
            # Check for pattern indicators
            for indicator in pattern.indicators:
                if indicator.lower() in finding_text:
                    matches += 1
            
            # Calculate pattern match score
            if matches > 0:
                score = matches / len(pattern.indicators) * pattern.confidence
                
                # Check for false positive indicators
                false_positive_count = 0
                for fp_indicator in pattern.false_positive_indicators:
                    if fp_indicator.lower() in finding_text:
                        false_positive_count += 1
                
                # Reduce score for false positive indicators
                if false_positive_count > 0:
                    score *= (1 - (false_positive_count / len(pattern.false_positive_indicators)) * 0.5)
                
                if score > best_score:
                    best_score = score
                    best_match = pattern
        
        return best_match if best_score > 0.3 else None
    
    def _calculate_risk_score(self, finding: Any) -> float:
        """Calculate AI-based risk score for a finding."""
        try:
            # Create feature vector for risk scoring
            features = [
                self._severity_to_score(finding.severity),
                finding.confidence,
                len(finding.description + finding.evidence) / 1000,  # Normalize text length
                1 if finding.payload_used else 0,
                1 if finding.evidence else 0,
                1 if any(error in finding.evidence.lower() for error in ['error', 'exception', 'fail']) else 0,
                1 if any(indicator in finding.evidence.lower() for indicator in ['sql', 'mysql', 'oracle', 'postgres']) else 0,
                1 if any(indicator in finding.evidence.lower() for indicator in ['script', 'javascript', 'alert']) else 0,
                1 if any(indicator in finding.evidence.lower() for indicator in ['auth', 'login', 'admin', 'root']) else 0,
                1 if any(indicator in finding.evidence.lower() for indicator in ['version', 'config', 'debug', 'secret']) else 0,
                1 if finding.vulnerability_type else 0,
                len(finding.cwe_ids) / 10,  # Normalize CWE count
                len(finding.cve_examples) / 10,  # Normalize CVE count
                1 if hasattr(finding, 'correlation_group') else 0,
                1 if hasattr(finding, 'similarity_scores') and finding.similarity_scores else 0
            ]
            
            # Use risk scorer model if available
            if self.risk_scorer and hasattr(self.risk_scorer, 'predict'):
                # Ensure features array has correct shape
                features_array = np.array(features).reshape(1, -1)
                
                if hasattr(self.risk_scorer, 'predict_proba'):
                    # For classification models
                    risk_score = self.risk_scorer.predict_proba(features_array)[0][1]
                else:
                    # For regression models
                    risk_score = self.risk_scorer.predict(features_array)[0]
                
                return float(risk_score)
            else:
                # Fallback to weighted average
                weights = [0.2, 0.15, 0.05, 0.1, 0.05, 0.05, 0.1, 0.1, 0.1, 0.05, 0.02, 0.01, 0.01, 0.01, 0.01]
                return sum(f * w for f, w in zip(features, weights))
                
        except Exception as e:
            logger.error(f"Error calculating risk score: {str(e)}")
            return 0.5  # Default risk score
    
    def reduce_false_positives(self, findings: List[Any]) -> List[Any]:
        """
        Reduce false positives using AI analysis.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Any]: Filtered findings with reduced false positives
        """
        logger.info("Starting false positive reduction...")
        
        try:
            if not self.enable_ai_analysis:
                logger.info("AI analysis disabled, returning original findings")
                return findings
            
            filtered_findings = []
            
            for finding in findings:
                # Calculate false positive probability
                fp_probability = self._calculate_false_positive_probability(finding)
                
                # Apply confidence threshold
                if fp_probability < (1 - self.ai_confidence_threshold):
                    finding.false_positive_probability = fp_probability
                    filtered_findings.append(finding)
                else:
                    logger.info(f"Filtered out potential false positive: {finding.title} (FP probability: {fp_probability:.2f})")
            
            logger.info(f"False positive reduction completed. Filtered {len(findings) - len(filtered_findings)} findings")
            
            return filtered_findings
            
        except Exception as e:
            logger.error(f"Error in false positive reduction: {str(e)}")
            return findings
    
    def _calculate_false_positive_probability(self, finding: Any) -> float:
        """Calculate false positive probability for a finding."""
        try:
            # Create feature vector for false positive detection
            features = [
                self._severity_to_score(finding.severity),
                finding.confidence,
                len(finding.description + finding.evidence) / 1000,
                1 if finding.payload_used else 0,
                1 if finding.evidence else 0,
                1 if any(fp_indicator in finding.evidence.lower() for fp_indicator in ['test', 'demo', 'example', 'sample']) else 0,
                1 if any(fp_indicator in finding.evidence.lower() for fp_indicator in ['intentional', 'expected', 'normal']) else 0,
                1 if any(fp_indicator in finding.evidence.lower() for fp_indicator in ['debug', 'development', 'staging']) else 0,
                1 if finding.vulnerability_type == 'Information Disclosure' and finding.severity == 'Low' else 0,
                1 if finding.confidence < 0.5 else 0
            ]
            
            # Use false positive detector if available
            if self.false_positive_detector and hasattr(self.false_positive_detector, 'predict'):
                features_array = np.array(features).reshape(1, -1)
                
                if hasattr(self.false_positive_detector, 'predict_proba'):
                    # For classification models
                    fp_probability = self.false_positive_detector.predict_proba(features_array)[0][1]
                elif hasattr(self.false_positive_detector, 'predict'):
                    # For isolation forest (anomaly detection)
                    prediction = self.false_positive_detector.predict(features_array)[0]
                    fp_probability = 0.8 if prediction == -1 else 0.2  # -1 indicates anomaly (potential false positive)
                else:
                    fp_probability = 0.5
                
                return float(fp_probability)
            else:
                # Fallback to rule-based false positive detection
                fp_score = 0.0
                
                # Check for false positive indicators
                if any(fp_indicator in finding.evidence.lower() for fp_indicator in ['test', 'demo', 'example']):
                    fp_score += 0.3
                
                if finding.confidence < 0.5:
                    fp_score += 0.2
                
                if finding.severity == 'Low' and finding.vulnerability_type == 'Information Disclosure':
                    fp_score += 0.1
                
                if any(fp_indicator in finding.evidence.lower() for fp_indicator in ['intentional', 'expected']):
                    fp_score += 0.2
                
                return min(fp_score, 1.0)
                
        except Exception as e:
            logger.error(f"Error calculating false positive probability: {str(e)}")
            return 0.5  # Default false positive probability
    
    def score_and_prioritize(self, findings: List[Any]) -> List[Any]:
        """
        Score and prioritize findings using AI analysis.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Any]: Prioritized findings with risk scores
        """
        logger.info("Starting AI-based risk scoring and prioritization...")
        
        try:
            if not self.enable_ai_analysis:
                logger.info("AI analysis disabled, returning original findings")
                return findings
            
            scored_findings = []
            
            for finding in findings:
                # Calculate comprehensive risk score
                risk_score = self._calculate_comprehensive_risk_score(finding)
                
                # Calculate CVSS score
                cvss_score = self._calculate_cvss_score(finding)
                
                # Update finding with AI analysis results
                finding.ai_risk_score = risk_score
                finding.cvss_score = cvss_score
                finding.priority_score = risk_score * cvss_score
                
                scored_findings.append(finding)
            
            # Sort by priority score (descending)
            scored_findings.sort(key=lambda x: x.priority_score, reverse=True)
            
            logger.info(f"Risk scoring completed. Prioritized {len(scored_findings)} findings")
            
            return scored_findings
            
        except Exception as e:
            logger.error(f"Error in risk scoring: {str(e)}")
            return findings
    
    def _calculate_comprehensive_risk_score(self, finding: Any) -> float:
        """Calculate comprehensive risk score considering multiple factors."""
        try:
            # Base risk score from pattern matching
            base_score = getattr(finding, 'ai_risk_score', 0.5)
            
            # Severity multiplier
            severity_multiplier = {
                "Critical": 1.5,
                "High": 1.2,
                "Medium": 1.0,
                "Low": 0.8,
                "Info": 0.5
            }.get(finding.severity, 1.0)
            
            # Confidence multiplier
            confidence_multiplier = finding.confidence
            
            # Evidence quality multiplier
            evidence_quality = 0.5
            if finding.evidence:
                evidence_quality = min(1.0, len(finding.evidence) / 500)  # Normalize evidence length
            
            # Exploit availability multiplier
            exploit_availability = 1.0
            if hasattr(finding, 'cve_examples') and finding.cve_examples:
                exploit_availability = 1.2  # Known exploits available
            
            # Calculate comprehensive score
            comprehensive_score = (
                base_score * 
                severity_multiplier * 
                confidence_multiplier * 
                evidence_quality * 
                exploit_availability
            )
            
            return min(comprehensive_score, 1.0)  # Cap at 1.0
            
        except Exception as e:
            logger.error(f"Error calculating comprehensive risk score: {str(e)}")
            return 0.5
    
    def _calculate_cvss_score(self, finding: Any) -> float:
        """Calculate CVSS score for a finding."""
        try:
            # Base CVSS calculation (simplified)
            base_score = 0.0
            
            # Attack Vector (AV)
            av_score = 0.6  # Network (default)
            if "local" in finding.evidence.lower():
                av_score = 0.55
            elif "physical" in finding.evidence.lower():
                av_score = 0.2
            
            # Attack Complexity (AC)
            ac_score = 0.77  # Low (default)
            if "complex" in finding.evidence.lower() or "difficult" in finding.evidence.lower():
                ac_score = 0.44
            
            # Privileges Required (PR)
            pr_score = 0.62  # Low (default)
            if "admin" in finding.evidence.lower() or "root" in finding.evidence.lower():
                pr_score = 0.27
            
            # User Interaction (UI)
            ui_score = 0.85  # None (default)
            if "user" in finding.evidence.lower() or "interaction" in finding.evidence.lower():
                ui_score = 0.62
            
            # Scope (S)
            scope_score = 0.56  # Changed (default)
            if "unchanged" in finding.evidence.lower():
                scope_score = 0.45
            
            # Confidentiality Impact (C)
            c_score = 0.56  # High (default)
            if "low" in finding.evidence.lower():
                c_score = 0.22
            elif "none" in finding.evidence.lower():
                c_score = 0.0
            
            # Integrity Impact (I)
            i_score = 0.56  # High (default)
            if "low" in finding.evidence.lower():
                i_score = 0.22
            elif "none" in finding.evidence.lower():
                i_score = 0.0
            
            # Availability Impact (A)
            a_score = 0.56  # High (default)
            if "low" in finding.evidence.lower():
                a_score = 0.22
            elif "none" in finding.evidence.lower():
                a_score = 0.0
            
            # Calculate base score
            exploitability = 8.22 * av_score * ac_score * pr_score * ui_score
            impact = 1 - ((1 - c_score) * (1 - i_score) * (1 - a_score))
            
            if impact <= 0:
                base_score = 0
            elif scope_score == 0.56:  # Changed scope
                base_score = min(10, 1.08 * (impact + exploitability))
            else:  # Unchanged scope
                base_score = min(10, impact + exploitability)
            
            return round(base_score, 1)
            
        except Exception as e:
            logger.error(f"Error calculating CVSS score: {str(e)}")
            return 5.0  # Default CVSS score
    
    def map_to_standards(self, findings: List[Any]) -> List[Any]:
        """
        Map findings to CWE/CVE standards.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Any]: Findings with CWE/CVE mappings
        """
        logger.info("Mapping findings to CWE/CVE standards...")
        
        try:
            for finding in findings:
                # Map to CWE if not already mapped
                if not hasattr(finding, 'cwe_ids') or not finding.cwe_ids:
                    finding.cwe_ids = self._map_to_cwe(finding)
                
                # Map to CVE if not already mapped
                if not hasattr(finding, 'cve_references') or not finding.cve_references:
                    finding.cve_references = self._map_to_cve(finding)
                
                # Add remediation advice
                finding.remediation_advice = self._generate_remediation_advice(finding)
            
            logger.info(f"Standards mapping completed for {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            logger.error(f"Error in standards mapping: {str(e)}")
            return findings
    
    def _map_to_cwe(self, finding: Any) -> List[str]:
        """Map finding to CWE identifiers."""
        cwe_mappings = {
            "SQL Injection": ["CWE-89"],
            "XSS": ["CWE-79"],
            "Authentication Bypass": ["CWE-287", "CWE-288"],
            "Information Disclosure": ["CWE-200"],
            "Weak Encryption": ["CWE-327", "CWE-326"],
            "Command Injection": ["CWE-78"],
            "Path Traversal": ["CWE-22"],
            "CSRF": ["CWE-352"],
            "Open Redirect": ["CWE-601"],
            "XXE": ["CWE-611"],
            "SSRF": ["CWE-918"],
            "Deserialization": ["CWE-502"]
        }
        
        # Try to match by vulnerability type
        if hasattr(finding, 'vulnerability_type') and finding.vulnerability_type:
            return cwe_mappings.get(finding.vulnerability_type, [])
        
        # Try to match by title/description
        finding_text = f"{finding.title} {finding.description}".lower()
        
        for vuln_type, cwe_ids in cwe_mappings.items():
            if vuln_type.lower() in finding_text:
                return cwe_ids
        
        return []
    
    def _map_to_cve(self, finding: Any) -> List[str]:
        """Map finding to CVE references."""
        # This would typically query a CVE database
        # For now, return empty list as placeholder
        return []
    
    def _generate_remediation_advice(self, finding: Any) -> str:
        """Generate remediation advice for a finding."""
        remediation_templates = {
            "SQL Injection": "Use parameterized queries or prepared statements. Validate and sanitize all user inputs. Implement proper input validation and output encoding.",
            "XSS": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize user inputs before rendering.",
            "Authentication Bypass": "Implement proper authentication mechanisms. Use multi-factor authentication. Validate session tokens and implement proper session management.",
            "Information Disclosure": "Remove or secure sensitive information from error messages and responses. Implement proper access controls and data classification.",
            "Weak Encryption": "Use strong encryption algorithms (AES-256, RSA-2048+). Implement proper key management. Use TLS 1.3 for transport encryption.",
            "Command Injection": "Avoid command execution with user input. Use built-in functions instead of system commands. Implement proper input validation.",
            "Path Traversal": "Validate and sanitize file paths. Use whitelist approach for allowed directories. Implement proper access controls.",
            "CSRF": "Implement CSRF tokens. Use SameSite cookie attributes. Validate request origin and referer headers.",
            "Open Redirect": "Validate redirect URLs against whitelist. Use relative URLs when possible. Implement proper input validation.",
            "XXE": "Disable XML external entity processing. Use safe XML parsers. Validate XML input against schema.",
            "SSRF": "Validate and sanitize URLs. Use whitelist approach for allowed domains. Implement proper network segmentation.",
            "Deserialization": "Use safe serialization formats (JSON). Validate serialized data. Implement proper access controls."
        }
        
        if hasattr(finding, 'vulnerability_type') and finding.vulnerability_type:
            return remediation_templates.get(finding.vulnerability_type, "Implement proper security controls and follow secure coding practices.")
        
        return "Implement proper security controls and follow secure coding practices."
    
    def generate_exploit_suggestions(self, findings: List[Any]) -> List[Any]:
        """
        Generate exploit suggestions for findings.
        
        Args:
            findings: List of vulnerability findings
            
        Returns:
            List[Any]: Findings with exploit suggestions
        """
        logger.info("Generating exploit suggestions...")
        
        try:
            for finding in findings:
                # Generate exploit suggestions based on vulnerability type
                exploit_suggestions = self._generate_exploit_suggestions_for_finding(finding)
                finding.suggested_exploits = exploit_suggestions
            
            logger.info(f"Exploit suggestions generated for {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            logger.error(f"Error generating exploit suggestions: {str(e)}")
            return findings
    
    def _generate_exploit_suggestions_for_finding(self, finding: Any) -> List[str]:
        """Generate exploit suggestions for a specific finding."""
        exploit_templates = {
            "SQL Injection": [
                "sqlmap -u 'http://target/page?id=1' --dbs",
                "sqlmap -u 'http://target/page?id=1' --tables",
                "sqlmap -u 'http://target/page?id=1' --dump",
                "Manual testing: ' OR 1=1--",
                "Manual testing: ' UNION SELECT NULL--"
            ],
            "XSS": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "Manual testing with browser developer tools"
            ],
            "Authentication Bypass": [
                "Test default credentials: admin:admin, root:root",
                "Test common credentials: admin:password, admin:123456",
                "Test authentication bypass headers",
                "Test session manipulation",
                "Test privilege escalation"
            ],
            "Information Disclosure": [
                "Directory traversal: ../../../etc/passwd",
                "Error message analysis",
                "Version enumeration",
                "Banner grabbing",
                "Source code analysis"
            ],
            "Weak Encryption": [
                "Hash cracking with hashcat",
                "Password cracking with john",
                "SSL/TLS analysis with sslyze",
                "Certificate analysis",
                "Cipher suite enumeration"
            ]
        }
        
        if hasattr(finding, 'vulnerability_type') and finding.vulnerability_type:
            return exploit_templates.get(finding.vulnerability_type, ["Manual testing and analysis required"])
        
        return ["Manual testing and analysis required"]
    
    def save_results(self):
        """Save AI analysis results to files."""
        try:
            # Save analysis results
            results_file = self.ai_dir / "ai_analysis_results.json"
            with open(results_file, 'w') as f:
                json.dump([result.__dict__ for result in self.analysis_results], f, indent=2)
            
            # Save vulnerability patterns
            patterns_file = self.ai_dir / "vulnerability_patterns.json"
            with open(patterns_file, 'w') as f:
                json.dump([pattern.__dict__ for pattern in self.vulnerability_patterns], f, indent=2)
            
            logger.info(f"AI analysis results saved to {self.ai_dir}")
            
        except Exception as e:
            logger.error(f"Error saving AI analysis results: {str(e)}") 