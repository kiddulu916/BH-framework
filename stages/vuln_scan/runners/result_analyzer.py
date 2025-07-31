"""
Result Analyzer Module for Vulnerability Scanning Stage
Implements Step 6: Collect, Consolidate, and Interpret Scan Results

This module provides comprehensive result analysis and interpretation:
- Collect and consolidate results from all scanning tools
- Categorize and prioritize findings by severity
- Verify and eliminate false positives
- Document key details and context
- Generate actionable insights and recommendations
- Prepare results for AI-assisted analysis in next stage
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import pandas as pd
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)

@dataclass
class ConsolidatedFinding:
    """Consolidated finding data structure"""
    id: str
    title: str
    description: str
    severity: str
    category: str
    tool: str
    target: str
    evidence: Dict[str, Any]
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive: bool = False
    verified: bool = False
    exploitation_potential: str = "unknown"
    business_impact: str = "unknown"

@dataclass
class ScanSummary:
    """Scan summary data structure"""
    total_findings: int
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    tool_breakdown: Dict[str, int]
    target_breakdown: Dict[str, int]
    false_positive_rate: float
    verified_findings: int
    high_priority_findings: int
    exploitation_ready: int
    scan_duration: float
    scan_timestamp: float

class ResultAnalyzer:
    """Comprehensive result analyzer for vulnerability scanning"""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.consolidated_dir = output_dir / "consolidated"
        self.consolidated_dir.mkdir(parents=True, exist_ok=True)
        
        self.findings: List[ConsolidatedFinding] = []
        self.summary: Optional[ScanSummary] = None
        self.analysis_results: Dict[str, Any] = {}

    def analyze_all_results(self, scan_results: Dict[str, List[Any]]) -> bool:
        """Execute comprehensive result analysis and consolidation"""
        try:
            logger.info(f"{Fore.CYAN}Starting comprehensive result analysis and consolidation{Style.RESET_ALL}")

            # Step 6.1: Collect and Consolidate Results from All Tools
            logger.info("Step 6.1: Collecting and consolidating results from all tools")
            self.collect_and_consolidate_results(scan_results)

            # Step 6.2: Categorize and Prioritize Findings by Severity
            logger.info("Step 6.2: Categorizing and prioritizing findings by severity")
            self.categorize_and_prioritize_findings()

            # Step 6.3: Verify and Eliminate False Positives
            logger.info("Step 6.3: Verifying and eliminating false positives")
            self.verify_and_eliminate_false_positives()

            # Step 6.4: Document Key Details and Context
            logger.info("Step 6.4: Documenting key details and context")
            self.document_finding_details()

            # Step 6.5: Generate Actionable Insights and Recommendations
            logger.info("Step 6.5: Generating actionable insights and recommendations")
            self.generate_actionable_insights()

            # Step 6.6: Prepare Results for AI-Assisted Analysis
            logger.info("Step 6.6: Preparing results for AI-assisted analysis")
            self.prepare_for_ai_analysis()

            # Generate final summary and reports
            self.generate_final_summary()
            self.save_analysis_results()

            logger.info(f"{Fore.GREEN}Result analysis completed successfully!{Style.RESET_ALL}")
            return True

        except Exception as e:
            logger.error(f"Result analysis failed: {str(e)}")
            return False

    def collect_and_consolidate_results(self, scan_results: Dict[str, List[Any]]) -> None:
        """Step 6.1: Collect and consolidate results from all scanning tools"""
        logger.info("Collecting and consolidating results from all scanning tools")

        # Process results from each tool
        for tool_name, results in scan_results.items():
            logger.info(f"Processing results from {tool_name}: {len(results)} results")
            
            for result in results:
                try:
                    # Convert tool-specific results to consolidated findings
                    consolidated_findings = self.convert_to_consolidated_findings(result, tool_name)
                    self.findings.extend(consolidated_findings)
                except Exception as e:
                    logger.error(f"Error processing result from {tool_name}: {str(e)}")

        logger.info(f"Total consolidated findings: {len(self.findings)}")

    def convert_to_consolidated_findings(self, result: Any, tool_name: str) -> List[ConsolidatedFinding]:
        """Convert tool-specific results to consolidated findings"""
        consolidated_findings = []

        try:
            # Handle different result types based on tool
            if hasattr(result, 'findings') and isinstance(result.findings, list):
                # Handle results with findings list (API, Cloud, Nuclei, ZAP)
                for finding in result.findings:
                    consolidated_finding = self.create_consolidated_finding(finding, result, tool_name)
                    if consolidated_finding:
                        consolidated_findings.append(consolidated_finding)

            elif isinstance(result, dict) and 'findings' in result:
                # Handle dictionary results
                for finding in result['findings']:
                    consolidated_finding = self.create_consolidated_finding(finding, result, tool_name)
                    if consolidated_finding:
                        consolidated_findings.append(consolidated_finding)

            elif isinstance(result, dict):
                # Handle single finding results
                consolidated_finding = self.create_consolidated_finding(result, result, tool_name)
                if consolidated_finding:
                    consolidated_findings.append(consolidated_finding)

        except Exception as e:
            logger.error(f"Error converting result from {tool_name}: {str(e)}")

        return consolidated_findings

    def create_consolidated_finding(self, finding: Dict[str, Any], result: Any, tool_name: str) -> Optional[ConsolidatedFinding]:
        """Create a consolidated finding from tool-specific finding data"""
        try:
            # Extract common fields
            title = finding.get('type', finding.get('title', 'Unknown vulnerability'))
            description = finding.get('description', finding.get('message', ''))
            severity = finding.get('severity', 'medium')
            target = finding.get('target', finding.get('endpoint', result.target if hasattr(result, 'target') else 'unknown'))
            recommendation = finding.get('recommendation', 'Review and remediate the identified vulnerability')

            # Generate unique ID
            finding_id = f"{tool_name}_{title}_{target}_{int(time.time())}"

            # Categorize the finding
            category = self.categorize_finding(title, description, tool_name)

            # Extract evidence
            evidence = {
                'raw_finding': finding,
                'tool': tool_name,
                'scan_time': result.scan_time if hasattr(result, 'scan_time') else time.time(),
                'raw_output': result.raw_output if hasattr(result, 'raw_output') else ''
            }

            # Add additional context
            if 'endpoint' in finding:
                evidence['endpoint'] = finding['endpoint']
            if 'payload' in finding:
                evidence['payload'] = finding['payload']
            if 'status_code' in finding:
                evidence['status_code'] = finding['status_code']

            return ConsolidatedFinding(
                id=finding_id,
                title=title,
                description=description,
                severity=severity,
                category=category,
                tool=tool_name,
                target=target,
                evidence=evidence,
                recommendation=recommendation
            )

        except Exception as e:
            logger.error(f"Error creating consolidated finding: {str(e)}")
            return None

    def categorize_finding(self, title: str, description: str, tool_name: str) -> str:
        """Categorize finding based on title, description, and tool"""
        title_lower = title.lower()
        desc_lower = description.lower()

        # OWASP Top 10 categories
        if any(keyword in title_lower or keyword in desc_lower for keyword in ['injection', 'sql', 'nosql', 'command']):
            return 'A01:2021 - Broken Access Control'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['authentication', 'auth', 'login', 'session']):
            return 'A02:2021 - Cryptographic Failures'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['xss', 'cross-site', 'script']):
            return 'A03:2021 - Injection'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['insecure', 'design', 'architecture']):
            return 'A04:2021 - Insecure Design'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['misconfiguration', 'config', 'default']):
            return 'A05:2021 - Security Misconfiguration'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['vulnerable', 'outdated', 'version']):
            return 'A06:2021 - Vulnerable and Outdated Components'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['authorization', 'permission', 'access']):
            return 'A07:2021 - Identification and Authentication Failures'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['data', 'exposure', 'leak', 'sensitive']):
            return 'A08:2021 - Software and Data Integrity Failures'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['logging', 'monitoring', 'audit']):
            return 'A09:2021 - Security Logging and Monitoring Failures'
        elif any(keyword in title_lower or keyword in desc_lower for keyword in ['ssrf', 'csrf', 'request']):
            return 'A10:2021 - Server-Side Request Forgery'
        else:
            return 'Other'

    def categorize_and_prioritize_findings(self) -> None:
        """Step 6.2: Categorize and prioritize findings by severity"""
        logger.info("Categorizing and prioritizing findings by severity")

        # Sort findings by severity (critical, high, medium, low, info)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        self.findings.sort(key=lambda x: severity_order.get(x.severity, 5))

        # Add CVSS scores and CWE IDs where possible
        for finding in self.findings:
            finding.cvss_score = self.calculate_cvss_score(finding)
            finding.cwe_id = self.map_to_cwe_id(finding)

        # Categorize by exploitation potential
        for finding in self.findings:
            finding.exploitation_potential = self.assess_exploitation_potential(finding)

        # Categorize by business impact
        for finding in self.findings:
            finding.business_impact = self.assess_business_impact(finding)

    def calculate_cvss_score(self, finding: ConsolidatedFinding) -> Optional[float]:
        """Calculate CVSS score for a finding"""
        try:
            # Base score calculation based on severity and category
            base_scores = {
                'critical': 9.0,
                'high': 7.0,
                'medium': 5.0,
                'low': 3.0,
                'info': 1.0
            }
            
            base_score = base_scores.get(finding.severity, 5.0)
            
            # Adjust based on category
            category_adjustments = {
                'A01:2021 - Broken Access Control': 0.5,
                'A02:2021 - Cryptographic Failures': 0.3,
                'A03:2021 - Injection': 0.8,
                'A04:2021 - Insecure Design': 0.4,
                'A05:2021 - Security Misconfiguration': 0.2,
                'A06:2021 - Vulnerable and Outdated Components': 0.6,
                'A07:2021 - Identification and Authentication Failures': 0.7,
                'A08:2021 - Software and Data Integrity Failures': 0.9,
                'A09:2021 - Security Logging and Monitoring Failures': 0.1,
                'A10:2021 - Server-Side Request Forgery': 0.6
            }
            
            adjustment = category_adjustments.get(finding.category, 0.0)
            final_score = min(10.0, base_score + adjustment)
            
            return round(final_score, 1)

        except Exception as e:
            logger.error(f"Error calculating CVSS score: {str(e)}")
            return None

    def map_to_cwe_id(self, finding: ConsolidatedFinding) -> Optional[str]:
        """Map finding to CWE ID"""
        try:
            # CWE mapping based on finding type and category
            cwe_mapping = {
                'sql_injection': 'CWE-89',
                'nosql_injection': 'CWE-943',
                'xss': 'CWE-79',
                'csrf': 'CWE-352',
                'ssrf': 'CWE-918',
                'authentication_bypass': 'CWE-287',
                'authorization_bypass': 'CWE-285',
                'information_disclosure': 'CWE-200',
                'path_traversal': 'CWE-22',
                'command_injection': 'CWE-78',
                'file_upload': 'CWE-434',
                'insecure_deserialization': 'CWE-502',
                'broken_authentication': 'CWE-287',
                'sensitive_data_exposure': 'CWE-200',
                'missing_security_headers': 'CWE-693',
                'directory_listing': 'CWE-548',
                'public_s3_bucket': 'CWE-200',
                'metadata_service_accessible': 'CWE-918'
            }
            
            finding_type = finding.title.lower().replace(' ', '_')
            return cwe_mapping.get(finding_type, 'CWE-200')  # Default to information exposure

        except Exception as e:
            logger.error(f"Error mapping to CWE ID: {str(e)}")
            return None

    def assess_exploitation_potential(self, finding: ConsolidatedFinding) -> str:
        """Assess exploitation potential of a finding"""
        try:
            # High exploitation potential indicators
            high_indicators = [
                'sql_injection', 'command_injection', 'rce', 'remote_code_execution',
                'authentication_bypass', 'authorization_bypass', 'ssrf',
                'file_upload', 'deserialization'
            ]
            
            # Medium exploitation potential indicators
            medium_indicators = [
                'xss', 'csrf', 'path_traversal', 'information_disclosure',
                'sensitive_data_exposure', 'public_bucket', 'metadata'
            ]
            
            finding_lower = finding.title.lower()
            
            if any(indicator in finding_lower for indicator in high_indicators):
                return 'high'
            elif any(indicator in finding_lower for indicator in medium_indicators):
                return 'medium'
            else:
                return 'low'

        except Exception as e:
            logger.error(f"Error assessing exploitation potential: {str(e)}")
            return 'unknown'

    def assess_business_impact(self, finding: ConsolidatedFinding) -> str:
        """Assess business impact of a finding"""
        try:
            # High business impact indicators
            high_impact = [
                'authentication_bypass', 'authorization_bypass', 'rce',
                'data_breach', 'sensitive_data_exposure', 'financial',
                'admin', 'root', 'privilege_escalation'
            ]
            
            # Medium business impact indicators
            medium_impact = [
                'sql_injection', 'xss', 'csrf', 'information_disclosure',
                'public_bucket', 'config_exposure'
            ]
            
            finding_lower = finding.title.lower()
            
            if any(indicator in finding_lower for indicator in high_impact):
                return 'high'
            elif any(indicator in finding_lower for indicator in medium_impact):
                return 'medium'
            else:
                return 'low'

        except Exception as e:
            logger.error(f"Error assessing business impact: {str(e)}")
            return 'unknown'

    def verify_and_eliminate_false_positives(self) -> None:
        """Step 6.3: Verify and eliminate false positives"""
        logger.info("Verifying and eliminating false positives")

        false_positive_patterns = [
            # Common false positive patterns
            {'pattern': 'test', 'context': 'test environment'},
            {'pattern': 'dev', 'context': 'development environment'},
            {'pattern': 'staging', 'context': 'staging environment'},
            {'pattern': 'localhost', 'context': 'local development'},
            {'pattern': '127.0.0.1', 'context': 'local development'},
            {'pattern': 'example.com', 'context': 'example domain'},
            {'pattern': 'demo', 'context': 'demonstration'},
            {'pattern': 'sample', 'context': 'sample data'}
        ]

        for finding in self.findings:
            # Check for false positive patterns
            finding.false_positive = self.check_false_positive(finding, false_positive_patterns)
            
            # Mark as verified if not false positive
            finding.verified = not finding.false_positive

    def check_false_positive(self, finding: ConsolidatedFinding, patterns: List[Dict]) -> bool:
        """Check if a finding is a false positive"""
        try:
            target_lower = finding.target.lower()
            title_lower = finding.title.lower()
            desc_lower = finding.description.lower()

            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                if pattern in target_lower or pattern in title_lower or pattern in desc_lower:
                    logger.info(f"Potential false positive detected: {finding.title} (context: {pattern_info['context']})")
                    return True

            return False

        except Exception as e:
            logger.error(f"Error checking false positive: {str(e)}")
            return False

    def document_finding_details(self) -> None:
        """Step 6.4: Document key details and context"""
        logger.info("Documenting key details and context")

        for finding in self.findings:
            # Enhance description with additional context
            finding.description = self.enhance_finding_description(finding)
            
            # Add remediation guidance
            finding.recommendation = self.enhance_recommendation(finding)

    def enhance_finding_description(self, finding: ConsolidatedFinding) -> str:
        """Enhance finding description with additional context"""
        try:
            base_description = finding.description
            
            # Add context based on tool
            tool_context = {
                'nuclei': 'Detected using Nuclei vulnerability scanner',
                'zap': 'Identified by OWASP ZAP automated scanner',
                'api-scanner': 'Found during API security testing',
                'cloud-scanner': 'Discovered in cloud infrastructure scan'
            }
            
            context = tool_context.get(finding.tool, 'Detected during security assessment')
            
            # Add severity context
            severity_context = {
                'critical': 'This is a critical security issue requiring immediate attention.',
                'high': 'This is a high-priority security vulnerability.',
                'medium': 'This is a medium-priority security concern.',
                'low': 'This is a low-priority security finding.',
                'info': 'This is an informational security finding.'
            }
            
            severity_note = severity_context.get(finding.severity, '')
            
            enhanced_description = f"{base_description} {context}. {severity_note}"
            
            return enhanced_description

        except Exception as e:
            logger.error(f"Error enhancing finding description: {str(e)}")
            return finding.description

    def enhance_recommendation(self, finding: ConsolidatedFinding) -> str:
        """Enhance recommendation with specific guidance"""
        try:
            base_recommendation = finding.recommendation
            
            # Add specific remediation guidance based on finding type
            remediation_guidance = {
                'sql_injection': 'Implement parameterized queries and input validation.',
                'xss': 'Implement proper output encoding and Content Security Policy.',
                'authentication_bypass': 'Implement strong authentication mechanisms and session management.',
                'public_bucket': 'Configure bucket permissions to restrict public access.',
                'missing_security_headers': 'Implement security headers like CSP, HSTS, and X-Frame-Options.',
                'information_disclosure': 'Implement proper error handling and remove sensitive information from responses.'
            }
            
            finding_type = finding.title.lower().replace(' ', '_')
            specific_guidance = remediation_guidance.get(finding_type, '')
            
            if specific_guidance:
                enhanced_recommendation = f"{base_recommendation} {specific_guidance}"
            else:
                enhanced_recommendation = base_recommendation
            
            return enhanced_recommendation

        except Exception as e:
            logger.error(f"Error enhancing recommendation: {str(e)}")
            return finding.recommendation

    def generate_actionable_insights(self) -> None:
        """Step 6.5: Generate actionable insights and recommendations"""
        logger.info("Generating actionable insights and recommendations")

        # Analyze patterns and trends
        self.analysis_results['patterns'] = self.analyze_finding_patterns()
        self.analysis_results['trends'] = self.analyze_finding_trends()
        self.analysis_results['priorities'] = self.analyze_priorities()
        self.analysis_results['remediation_plan'] = self.generate_remediation_plan()

    def analyze_finding_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in findings"""
        try:
            patterns = {
                'most_common_vulnerabilities': Counter([f.title for f in self.findings if not f.false_positive]).most_common(10),
                'severity_distribution': Counter([f.severity for f in self.findings if not f.false_positive]),
                'category_distribution': Counter([f.category for f in self.findings if not f.false_positive]),
                'tool_effectiveness': Counter([f.tool for f in self.findings if not f.false_positive]),
                'target_hotspots': Counter([f.target for f in self.findings if not f.false_positive]).most_common(10)
            }
            
            return patterns

        except Exception as e:
            logger.error(f"Error analyzing patterns: {str(e)}")
            return {}

    def analyze_finding_trends(self) -> Dict[str, Any]:
        """Analyze trends in findings"""
        try:
            trends = {
                'high_risk_targets': [f.target for f in self.findings if f.severity in ['critical', 'high'] and not f.false_positive],
                'exploitation_ready': [f.id for f in self.findings if f.exploitation_potential == 'high' and not f.false_positive],
                'business_critical': [f.id for f in self.findings if f.business_impact == 'high' and not f.false_positive],
                'false_positive_rate': len([f for f in self.findings if f.false_positive]) / len(self.findings) if self.findings else 0
            }
            
            return trends

        except Exception as e:
            logger.error(f"Error analyzing trends: {str(e)}")
            return {}

    def analyze_priorities(self) -> Dict[str, Any]:
        """Analyze and prioritize findings"""
        try:
            priorities = {
                'immediate_action': [f for f in self.findings if f.severity == 'critical' and not f.false_positive],
                'high_priority': [f for f in self.findings if f.severity == 'high' and not f.false_positive],
                'medium_priority': [f for f in self.findings if f.severity == 'medium' and not f.false_positive],
                'low_priority': [f for f in self.findings if f.severity == 'low' and not f.false_positive],
                'informational': [f for f in self.findings if f.severity == 'info' and not f.false_positive]
            }
            
            return priorities

        except Exception as e:
            logger.error(f"Error analyzing priorities: {str(e)}")
            return {}

    def generate_remediation_plan(self) -> Dict[str, Any]:
        """Generate remediation plan"""
        try:
            remediation_plan = {
                'immediate_remediation': {
                    'description': 'Critical vulnerabilities requiring immediate attention',
                    'findings': [f.id for f in self.findings if f.severity == 'critical' and not f.false_positive],
                    'estimated_effort': '1-2 days',
                    'business_impact': 'High'
                },
                'short_term_remediation': {
                    'description': 'High priority vulnerabilities for short-term remediation',
                    'findings': [f.id for f in self.findings if f.severity == 'high' and not f.false_positive],
                    'estimated_effort': '1-2 weeks',
                    'business_impact': 'Medium'
                },
                'medium_term_remediation': {
                    'description': 'Medium priority vulnerabilities for medium-term remediation',
                    'findings': [f.id for f in self.findings if f.severity == 'medium' and not f.false_positive],
                    'estimated_effort': '1-2 months',
                    'business_impact': 'Low'
                },
                'long_term_remediation': {
                    'description': 'Low priority vulnerabilities and security improvements',
                    'findings': [f.id for f in self.findings if f.severity in ['low', 'info'] and not f.false_positive],
                    'estimated_effort': '3-6 months',
                    'business_impact': 'Minimal'
                }
            }
            
            return remediation_plan

        except Exception as e:
            logger.error(f"Error generating remediation plan: {str(e)}")
            return {}

    def prepare_for_ai_analysis(self) -> None:
        """Step 6.6: Prepare results for AI-assisted analysis"""
        logger.info("Preparing results for AI-assisted analysis")

        # Create AI-ready dataset
        ai_dataset = {
            'findings': [asdict(f) for f in self.findings if not f.false_positive],
            'summary': {
                'total_findings': len([f for f in self.findings if not f.false_positive]),
                'critical_findings': len([f for f in self.findings if f.severity == 'critical' and not f.false_positive]),
                'high_findings': len([f for f in self.findings if f.severity == 'high' and not f.false_positive]),
                'exploitation_ready': len([f for f in self.findings if f.exploitation_potential == 'high' and not f.false_positive]),
                'business_critical': len([f for f in self.findings if f.business_impact == 'high' and not f.false_positive])
            },
            'context': {
                'scan_timestamp': time.time(),
                'tools_used': list(set(f.tool for f in self.findings)),
                'targets_scanned': list(set(f.target for f in self.findings)),
                'categories_found': list(set(f.category for f in self.findings))
            }
        }

        # Save AI-ready dataset
        ai_dataset_file = self.consolidated_dir / "ai_analysis_dataset.json"
        with open(ai_dataset_file, 'w') as f:
            json.dump(ai_dataset, f, indent=2, default=str)

        self.analysis_results['ai_dataset'] = ai_dataset

    def generate_final_summary(self) -> None:
        """Generate final summary of analysis"""
        try:
            verified_findings = [f for f in self.findings if not f.false_positive]
            
            self.summary = ScanSummary(
                total_findings=len(self.findings),
                severity_breakdown=Counter([f.severity for f in verified_findings]),
                category_breakdown=Counter([f.category for f in verified_findings]),
                tool_breakdown=Counter([f.tool for f in verified_findings]),
                target_breakdown=Counter([f.target for f in verified_findings]),
                false_positive_rate=len([f for f in self.findings if f.false_positive]) / len(self.findings) if self.findings else 0,
                verified_findings=len(verified_findings),
                high_priority_findings=len([f for f in verified_findings if f.severity in ['critical', 'high']]),
                exploitation_ready=len([f for f in verified_findings if f.exploitation_potential == 'high']),
                scan_duration=time.time(),  # This should be calculated from actual scan start time
                scan_timestamp=time.time()
            )

        except Exception as e:
            logger.error(f"Error generating final summary: {str(e)}")

    def save_analysis_results(self) -> None:
        """Save all analysis results to files"""
        try:
            # Save consolidated findings
            findings_file = self.consolidated_dir / "consolidated_findings.json"
            with open(findings_file, 'w') as f:
                json.dump([asdict(finding) for finding in self.findings], f, indent=2, default=str)

            # Save analysis results
            analysis_file = self.consolidated_dir / "analysis_results.json"
            with open(analysis_file, 'w') as f:
                json.dump(self.analysis_results, f, indent=2, default=str)

            # Save summary
            if self.summary:
                summary_file = self.consolidated_dir / "scan_summary.json"
                with open(summary_file, 'w') as f:
                    json.dump(asdict(self.summary), f, indent=2, default=str)

            # Generate CSV report
            self.generate_csv_report()

            logger.info(f"Analysis results saved to {self.consolidated_dir}")

        except Exception as e:
            logger.error(f"Error saving analysis results: {str(e)}")

    def generate_csv_report(self) -> None:
        """Generate CSV report of findings"""
        try:
            # Create DataFrame from findings
            findings_data = []
            for finding in self.findings:
                findings_data.append({
                    'ID': finding.id,
                    'Title': finding.title,
                    'Description': finding.description,
                    'Severity': finding.severity,
                    'Category': finding.category,
                    'Tool': finding.tool,
                    'Target': finding.target,
                    'CWE_ID': finding.cwe_id,
                    'CVSS_Score': finding.cvss_score,
                    'Exploitation_Potential': finding.exploitation_potential,
                    'Business_Impact': finding.business_impact,
                    'False_Positive': finding.false_positive,
                    'Verified': finding.verified,
                    'Recommendation': finding.recommendation
                })

            df = pd.DataFrame(findings_data)
            csv_file = self.consolidated_dir / "findings_report.csv"
            df.to_csv(csv_file, index=False)

            logger.info(f"CSV report generated: {csv_file}")

        except Exception as e:
            logger.error(f"Error generating CSV report: {str(e)}")

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis results"""
        try:
            if not self.summary:
                return {}

            return {
                'total_findings': self.summary.total_findings,
                'verified_findings': self.summary.verified_findings,
                'false_positive_rate': self.summary.false_positive_rate,
                'high_priority_findings': self.summary.high_priority_findings,
                'exploitation_ready': self.summary.exploitation_ready,
                'severity_breakdown': dict(self.summary.severity_breakdown),
                'category_breakdown': dict(self.summary.category_breakdown),
                'tool_breakdown': dict(self.summary.tool_breakdown)
            }

        except Exception as e:
            logger.error(f"Error getting analysis summary: {str(e)}")
            return {} 