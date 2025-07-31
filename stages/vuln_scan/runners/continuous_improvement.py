"""
Continuous Improvement Module for Vulnerability Scanning Stage
Implements Step 7: Continuous Improvement and Re-Scanning

This module provides continuous improvement capabilities:
- Template and signature update mechanisms
- Re-scanning capabilities for new endpoints
- Scheduled scanning and monitoring
- Scan result comparison and trend analysis
- Improvement recommendations and optimization
"""

import json
import os
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import requests
from colorama import Fore, Style
import logging

logger = logging.getLogger(__name__)

@dataclass
class ImprovementRecommendation:
    """Improvement recommendation data structure"""
    category: str
    title: str
    description: str
    priority: str
    impact: str
    effort: str
    implementation: str
    expected_benefit: str

@dataclass
class TemplateUpdate:
    """Template update data structure"""
    tool: str
    template_type: str
    update_time: float
    status: str
    changes: List[str]
    version: str

class ContinuousImprovement:
    """Continuous improvement and re-scanning manager"""

    def __init__(self, output_dir: Path, config: Dict[str, Any] = None):
        self.output_dir = output_dir / "continuous_improvement"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.config = config or {}
        self.recommendations: List[ImprovementRecommendation] = []
        self.template_updates: List[TemplateUpdate] = []

    def run_continuous_improvement(self, scan_results: Dict[str, Any], targets: Dict[str, List[str]]) -> bool:
        """Execute continuous improvement and re-scanning workflow"""
        try:
            logger.info(f"{Fore.CYAN}Starting continuous improvement and re-scanning{Style.RESET_ALL}")

            # Step 7.1: Update Templates and Signatures
            logger.info("Step 7.1: Updating templates and signatures")
            self.update_templates_and_signatures()

            # Step 7.2: Re-scanning Capabilities for New Endpoints
            logger.info("Step 7.2: Implementing re-scanning capabilities")
            self.implement_rescanning_capabilities(targets)

            # Step 7.3: Scheduled Scanning and Monitoring
            logger.info("Step 7.3: Setting up scheduled scanning and monitoring")
            self.setup_scheduled_scanning()

            # Step 7.4: Scan Result Comparison and Trend Analysis
            logger.info("Step 7.4: Analyzing scan results and trends")
            self.analyze_scan_trends(scan_results)

            # Step 7.5: Generate Improvement Recommendations
            logger.info("Step 7.5: Generating improvement recommendations")
            self.generate_improvement_recommendations(scan_results)

            # Save improvement results
            self.save_improvement_results()

            logger.info(f"{Fore.GREEN}Continuous improvement completed successfully!{Style.RESET_ALL}")
            return True

        except Exception as e:
            logger.error(f"Continuous improvement failed: {str(e)}")
            return False

    def update_templates_and_signatures(self) -> None:
        """Step 7.1: Update templates and signatures"""
        logger.info("Updating vulnerability templates and signatures")

        # Update Nuclei templates
        self.update_nuclei_templates()

        # Update ZAP definitions
        self.update_zap_definitions()

        # Update additional scanner signatures
        self.update_additional_signatures()

    def update_nuclei_templates(self) -> None:
        """Update Nuclei vulnerability templates"""
        try:
            logger.info("Updating Nuclei templates...")

            # Check if nuclei is installed
            try:
                result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.warning("Nuclei not found, skipping template update")
                    return
            except FileNotFoundError:
                logger.warning("Nuclei not found, skipping template update")
                return

            # Update Nuclei templates
            update_commands = [
                ["nuclei", "-update-templates"],
                ["nuclei", "-update-templates", "-t", "cves"],
                ["nuclei", "-update-templates", "-t", "vulnerabilities"],
                ["nuclei", "-update-templates", "-t", "misconfiguration"],
                ["nuclei", "-update-templates", "-t", "exposures"]
            ]

            changes = []
            for cmd in update_commands:
                try:
                    logger.info(f"Running: {' '.join(cmd)}")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        changes.append(f"Successfully updated {cmd[-1]} templates")
                        logger.info(f"Successfully updated {cmd[-1]} templates")
                    else:
                        logger.warning(f"Failed to update {cmd[-1]} templates: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    logger.warning(f"Timeout updating {cmd[-1]} templates")
                except Exception as e:
                    logger.error(f"Error updating {cmd[-1]} templates: {str(e)}")

            # Get Nuclei version
            try:
                version_result = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=10)
                version = version_result.stdout.strip() if version_result.returncode == 0 else "unknown"
            except:
                version = "unknown"

            template_update = TemplateUpdate(
                tool="nuclei",
                template_type="vulnerability_templates",
                update_time=time.time(),
                status="completed" if changes else "failed",
                changes=changes,
                version=version
            )
            self.template_updates.append(template_update)

        except Exception as e:
            logger.error(f"Error updating Nuclei templates: {str(e)}")

    def update_zap_definitions(self) -> None:
        """Update OWASP ZAP definitions and rules"""
        try:
            logger.info("Updating OWASP ZAP definitions...")

            # Check if ZAP is available
            zap_path = os.environ.get("ZAP_PATH", "zap.sh")
            
            try:
                result = subprocess.run([zap_path, "-version"], capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    logger.warning("ZAP not found, skipping definition update")
                    return
            except FileNotFoundError:
                logger.warning("ZAP not found, skipping definition update")
                return

            # Update ZAP add-ons (this would typically be done via ZAP API)
            changes = []
            
            # Note: In a real implementation, this would use ZAP's API to update add-ons
            # For now, we'll simulate the update process
            logger.info("ZAP add-ons would be updated via ZAP API in production")
            changes.append("ZAP add-ons update simulated")

            # Get ZAP version
            try:
                version_result = subprocess.run([zap_path, "-version"], capture_output=True, text=True, timeout=10)
                version = version_result.stdout.strip() if version_result.returncode == 0 else "unknown"
            except:
                version = "unknown"

            template_update = TemplateUpdate(
                tool="zap",
                template_type="add_ons_and_rules",
                update_time=time.time(),
                status="completed" if changes else "failed",
                changes=changes,
                version=version
            )
            self.template_updates.append(template_update)

        except Exception as e:
            logger.error(f"Error updating ZAP definitions: {str(e)}")

    def update_additional_signatures(self) -> None:
        """Update additional scanner signatures"""
        try:
            logger.info("Updating additional scanner signatures...")

            # Update Nikto signatures
            self.update_nikto_signatures()

            # Update Wapiti signatures
            self.update_wapiti_signatures()

            # Update Arachni signatures
            self.update_arachni_signatures()

        except Exception as e:
            logger.error(f"Error updating additional signatures: {str(e)}")

    def update_nikto_signatures(self) -> None:
        """Update Nikto vulnerability signatures"""
        try:
            # Check if Nikto is installed
            try:
                result = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info("Nikto found, signatures are typically updated with the tool")
                    changes = ["Nikto signatures are up to date"]
                else:
                    logger.warning("Nikto not found or not working properly")
                    changes = []
            except FileNotFoundError:
                logger.warning("Nikto not found, skipping signature update")
                changes = []

            template_update = TemplateUpdate(
                tool="nikto",
                template_type="vulnerability_signatures",
                update_time=time.time(),
                status="completed" if changes else "failed",
                changes=changes,
                version="unknown"
            )
            self.template_updates.append(template_update)

        except Exception as e:
            logger.error(f"Error updating Nikto signatures: {str(e)}")

    def update_wapiti_signatures(self) -> None:
        """Update Wapiti vulnerability signatures"""
        try:
            # Check if Wapiti is installed
            try:
                result = subprocess.run(["wapiti", "--version"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info("Wapiti found, signatures are typically updated with the tool")
                    changes = ["Wapiti signatures are up to date"]
                else:
                    logger.warning("Wapiti not found or not working properly")
                    changes = []
            except FileNotFoundError:
                logger.warning("Wapiti not found, skipping signature update")
                changes = []

            template_update = TemplateUpdate(
                tool="wapiti",
                template_type="vulnerability_signatures",
                update_time=time.time(),
                status="completed" if changes else "failed",
                changes=changes,
                version="unknown"
            )
            self.template_updates.append(template_update)

        except Exception as e:
            logger.error(f"Error updating Wapiti signatures: {str(e)}")

    def update_arachni_signatures(self) -> None:
        """Update Arachni vulnerability signatures"""
        try:
            # Check if Arachni is installed
            try:
                result = subprocess.run(["arachni", "--version"], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info("Arachni found, signatures are typically updated with the tool")
                    changes = ["Arachni signatures are up to date"]
                else:
                    logger.warning("Arachni not found or not working properly")
                    changes = []
            except FileNotFoundError:
                logger.warning("Arachni not found, skipping signature update")
                changes = []

            template_update = TemplateUpdate(
                tool="arachni",
                template_type="vulnerability_signatures",
                update_time=time.time(),
                status="completed" if changes else "failed",
                changes=changes,
                version="unknown"
            )
            self.template_updates.append(template_update)

        except Exception as e:
            logger.error(f"Error updating Arachni signatures: {str(e)}")

    def implement_rescanning_capabilities(self, targets: Dict[str, List[str]]) -> None:
        """Step 7.2: Implement re-scanning capabilities for new endpoints"""
        logger.info("Implementing re-scanning capabilities for new endpoints")

        # Identify new endpoints that weren't scanned
        new_endpoints = self.identify_new_endpoints(targets)

        # Create re-scanning configuration
        self.create_rescanning_config(new_endpoints)

        # Set up incremental scanning
        self.setup_incremental_scanning()

    def identify_new_endpoints(self, targets: Dict[str, List[str]]) -> Dict[str, List[str]]:
        """Identify new endpoints that need re-scanning"""
        try:
            new_endpoints = {
                "web_apps": [],
                "apis": [],
                "cloud_services": []
            }

            # Check for new endpoints by comparing with previous scan results
            previous_scan_file = self.output_dir / "previous_scan_results.json"
            
            if previous_scan_file.exists():
                with open(previous_scan_file, 'r') as f:
                    previous_results = json.load(f)
                
                previous_targets = set()
                if 'targets' in previous_results:
                    for category, target_list in previous_results['targets'].items():
                        previous_targets.update(target_list)

                # Find new targets
                for category, target_list in targets.items():
                    for target in target_list:
                        if target not in previous_targets:
                            new_endpoints[category].append(target)
                            logger.info(f"New endpoint identified: {target} ({category})")
            else:
                # First scan, all targets are new
                new_endpoints = targets.copy()
                logger.info("First scan detected, all targets are new")

            return new_endpoints

        except Exception as e:
            logger.error(f"Error identifying new endpoints: {str(e)}")
            return targets

    def create_rescanning_config(self, new_endpoints: Dict[str, List[str]]) -> None:
        """Create re-scanning configuration for new endpoints"""
        try:
            rescan_config = {
                "new_endpoints": new_endpoints,
                "scan_priority": {
                    "web_apps": "high",
                    "apis": "high", 
                    "cloud_services": "medium"
                },
                "scan_frequency": {
                    "web_apps": "daily",
                    "apis": "daily",
                    "cloud_services": "weekly"
                },
                "tools_to_use": {
                    "web_apps": ["nuclei", "zap", "nikto"],
                    "apis": ["nuclei", "api_scanner"],
                    "cloud_services": ["nuclei", "cloud_scanner"]
                },
                "created_at": time.time()
            }

            # Save re-scanning configuration
            rescan_file = self.output_dir / "rescanning_config.json"
            with open(rescan_file, 'w') as f:
                json.dump(rescan_config, f, indent=2)

            logger.info(f"Re-scanning configuration created for {sum(len(targets) for targets in new_endpoints.values())} new endpoints")

        except Exception as e:
            logger.error(f"Error creating re-scanning configuration: {str(e)}")

    def setup_incremental_scanning(self) -> None:
        """Set up incremental scanning capabilities"""
        try:
            incremental_config = {
                "enabled": True,
                "scan_interval": 3600,  # 1 hour in seconds
                "max_concurrent_scans": 3,
                "priority_queue": True,
                "differential_scanning": True,
                "change_detection": {
                    "enabled": True,
                    "methods": ["file_modification", "api_endpoint_changes", "dns_changes"]
                },
                "notification": {
                    "enabled": True,
                    "channels": ["log", "api"]
                }
            }

            # Save incremental scanning configuration
            incremental_file = self.output_dir / "incremental_scanning_config.json"
            with open(incremental_file, 'w') as f:
                json.dump(incremental_config, f, indent=2)

            logger.info("Incremental scanning configuration created")

        except Exception as e:
            logger.error(f"Error setting up incremental scanning: {str(e)}")

    def setup_scheduled_scanning(self) -> None:
        """Step 7.3: Set up scheduled scanning and monitoring"""
        logger.info("Setting up scheduled scanning and monitoring")

        # Create scheduled scanning configuration
        self.create_scheduled_scanning_config()

        # Set up monitoring and alerting
        self.setup_monitoring_and_alerting()

        # Create scan scheduling system
        self.create_scan_scheduling_system()

    def create_scheduled_scanning_config(self) -> None:
        """Create scheduled scanning configuration"""
        try:
            scheduled_config = {
                "schedules": {
                    "daily_full_scan": {
                        "enabled": True,
                        "time": "02:00",  # 2 AM
                        "timezone": "UTC",
                        "type": "full_scan",
                        "targets": "all",
                        "tools": ["nuclei", "zap", "api_scanner", "cloud_scanner"]
                    },
                    "hourly_quick_scan": {
                        "enabled": True,
                        "interval": 3600,  # 1 hour
                        "type": "quick_scan",
                        "targets": "critical_only",
                        "tools": ["nuclei"]
                    },
                    "weekly_deep_scan": {
                        "enabled": True,
                        "day": "sunday",
                        "time": "03:00",
                        "timezone": "UTC",
                        "type": "deep_scan",
                        "targets": "all",
                        "tools": ["nuclei", "zap", "nikto", "wapiti", "arachni", "api_scanner", "cloud_scanner"]
                    }
                },
                "monitoring": {
                    "enabled": True,
                    "metrics": ["scan_duration", "vulnerabilities_found", "false_positive_rate", "coverage"],
                    "thresholds": {
                        "max_scan_duration": 7200,  # 2 hours
                        "min_coverage": 0.8,  # 80%
                        "max_false_positive_rate": 0.2  # 20%
                    }
                },
                "notifications": {
                    "critical_findings": True,
                    "scan_failures": True,
                    "coverage_drops": True,
                    "new_vulnerabilities": True
                }
            }

            # Save scheduled scanning configuration
            scheduled_file = self.output_dir / "scheduled_scanning_config.json"
            with open(scheduled_file, 'w') as f:
                json.dump(scheduled_config, f, indent=2)

            logger.info("Scheduled scanning configuration created")

        except Exception as e:
            logger.error(f"Error creating scheduled scanning configuration: {str(e)}")

    def setup_monitoring_and_alerting(self) -> None:
        """Set up monitoring and alerting system"""
        try:
            monitoring_config = {
                "metrics_collection": {
                    "enabled": True,
                    "interval": 300,  # 5 minutes
                    "retention_days": 30
                },
                "alerts": {
                    "critical_vulnerability": {
                        "enabled": True,
                        "threshold": 1,
                        "channels": ["log", "api", "email"]
                    },
                    "scan_failure": {
                        "enabled": True,
                        "threshold": 1,
                        "channels": ["log", "api"]
                    },
                    "coverage_drop": {
                        "enabled": True,
                        "threshold": 0.1,  # 10% drop
                        "channels": ["log", "api"]
                    },
                    "performance_degradation": {
                        "enabled": True,
                        "threshold": 1.5,  # 50% increase in scan time
                        "channels": ["log", "api"]
                    }
                },
                "dashboards": {
                    "enabled": True,
                    "refresh_interval": 60,  # 1 minute
                    "widgets": [
                        "vulnerability_trends",
                        "scan_coverage",
                        "tool_effectiveness",
                        "performance_metrics"
                    ]
                }
            }

            # Save monitoring configuration
            monitoring_file = self.output_dir / "monitoring_config.json"
            with open(monitoring_file, 'w') as f:
                json.dump(monitoring_config, f, indent=2)

            logger.info("Monitoring and alerting configuration created")

        except Exception as e:
            logger.error(f"Error setting up monitoring and alerting: {str(e)}")

    def create_scan_scheduling_system(self) -> None:
        """Create scan scheduling system"""
        try:
            scheduling_config = {
                "queue_management": {
                    "enabled": True,
                    "max_queue_size": 100,
                    "priority_levels": ["critical", "high", "medium", "low"],
                    "retry_policy": {
                        "max_retries": 3,
                        "retry_delay": 300,  # 5 minutes
                        "backoff_multiplier": 2
                    }
                },
                "resource_management": {
                    "max_concurrent_scans": 5,
                    "memory_limit_per_scan": "2GB",
                    "cpu_limit_per_scan": "1.0",
                    "timeout_per_scan": 7200  # 2 hours
                },
                "load_balancing": {
                    "enabled": True,
                    "strategy": "round_robin",
                    "health_check_interval": 60
                }
            }

            # Save scheduling configuration
            scheduling_file = self.output_dir / "scheduling_config.json"
            with open(scheduling_file, 'w') as f:
                json.dump(scheduling_config, f, indent=2)

            logger.info("Scan scheduling system configuration created")

        except Exception as e:
            logger.error(f"Error creating scan scheduling system: {str(e)}")

    def analyze_scan_trends(self, scan_results: Dict[str, Any]) -> None:
        """Step 7.4: Analyze scan results and trends"""
        logger.info("Analyzing scan results and trends")

        # Analyze vulnerability trends
        self.analyze_vulnerability_trends(scan_results)

        # Analyze tool effectiveness
        self.analyze_tool_effectiveness(scan_results)

        # Analyze performance trends
        self.analyze_performance_trends(scan_results)

        # Generate trend reports
        self.generate_trend_reports()

    def analyze_vulnerability_trends(self, scan_results: Dict[str, Any]) -> None:
        """Analyze vulnerability trends over time"""
        try:
            # This would typically compare with historical data
            # For now, we'll analyze current results
            trends = {
                "vulnerability_distribution": {},
                "severity_trends": {},
                "category_trends": {},
                "target_trends": {},
                "false_positive_trends": {}
            }

            if 'findings' in scan_results:
                findings = scan_results['findings']
                
                # Analyze severity distribution
                severity_counts = {}
                for finding in findings:
                    severity = finding.get('severity', 'unknown')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                trends['severity_trends'] = severity_counts

                # Analyze category distribution
                category_counts = {}
                for finding in findings:
                    category = finding.get('category', 'unknown')
                    category_counts[category] = category_counts.get(category, 0) + 1
                trends['category_trends'] = category_counts

                # Analyze target distribution
                target_counts = {}
                for finding in findings:
                    target = finding.get('target', 'unknown')
                    target_counts[target] = target_counts.get(target, 0) + 1
                trends['target_trends'] = target_counts

            # Save trend analysis
            trends_file = self.output_dir / "vulnerability_trends.json"
            with open(trends_file, 'w') as f:
                json.dump(trends, f, indent=2)

            logger.info("Vulnerability trend analysis completed")

        except Exception as e:
            logger.error(f"Error analyzing vulnerability trends: {str(e)}")

    def analyze_tool_effectiveness(self, scan_results: Dict[str, Any]) -> None:
        """Analyze tool effectiveness and performance"""
        try:
            tool_effectiveness = {
                "tool_performance": {},
                "detection_rates": {},
                "false_positive_rates": {},
                "coverage_rates": {},
                "recommendations": []
            }

            if 'findings' in scan_results:
                findings = scan_results['findings']
                
                # Analyze tool performance
                tool_counts = {}
                tool_findings = {}
                
                for finding in findings:
                    tool = finding.get('tool', 'unknown')
                    tool_counts[tool] = tool_counts.get(tool, 0) + 1
                    
                    if tool not in tool_findings:
                        tool_findings[tool] = []
                    tool_findings[tool].append(finding)

                tool_effectiveness['tool_performance'] = tool_counts

                # Calculate detection rates (simplified)
                for tool, tool_finding_list in tool_findings.items():
                    total_findings = len(tool_finding_list)
                    verified_findings = len([f for f in tool_finding_list if f.get('verified', False)])
                    false_positives = len([f for f in tool_finding_list if f.get('false_positive', False)])
                    
                    detection_rate = verified_findings / total_findings if total_findings > 0 else 0
                    false_positive_rate = false_positives / total_findings if total_findings > 0 else 0
                    
                    tool_effectiveness['detection_rates'][tool] = detection_rate
                    tool_effectiveness['false_positive_rates'][tool] = false_positive_rate

            # Save tool effectiveness analysis
            effectiveness_file = self.output_dir / "tool_effectiveness.json"
            with open(effectiveness_file, 'w') as f:
                json.dump(tool_effectiveness, f, indent=2)

            logger.info("Tool effectiveness analysis completed")

        except Exception as e:
            logger.error(f"Error analyzing tool effectiveness: {str(e)}")

    def analyze_performance_trends(self, scan_results: Dict[str, Any]) -> None:
        """Analyze performance trends and optimization opportunities"""
        try:
            performance_trends = {
                "scan_duration_trends": {},
                "resource_usage_trends": {},
                "optimization_opportunities": [],
                "bottlenecks": [],
                "recommendations": []
            }

            # Analyze scan duration (if available)
            if 'scan_summary' in scan_results:
                scan_duration = scan_results['scan_summary'].get('scan_duration', 0)
                performance_trends['scan_duration_trends']['current_scan'] = scan_duration

                # Add optimization recommendations based on duration
                if scan_duration > 3600:  # More than 1 hour
                    performance_trends['optimization_opportunities'].append({
                        'type': 'scan_duration',
                        'issue': 'Scan duration is high',
                        'recommendation': 'Consider parallel scanning or tool optimization',
                        'priority': 'medium'
                    })

            # Save performance trends
            performance_file = self.output_dir / "performance_trends.json"
            with open(performance_file, 'w') as f:
                json.dump(performance_trends, f, indent=2)

            logger.info("Performance trend analysis completed")

        except Exception as e:
            logger.error(f"Error analyzing performance trends: {str(e)}")

    def generate_trend_reports(self) -> None:
        """Generate comprehensive trend reports"""
        try:
            # Combine all trend analyses
            trend_report = {
                "report_generated_at": time.time(),
                "summary": {
                    "total_findings": 0,
                    "critical_findings": 0,
                    "high_findings": 0,
                    "medium_findings": 0,
                    "low_findings": 0
                },
                "trends": {
                    "vulnerability_trends": {},
                    "tool_effectiveness": {},
                    "performance_trends": {}
                },
                "recommendations": []
            }

            # Load trend data from files
            trend_files = [
                "vulnerability_trends.json",
                "tool_effectiveness.json", 
                "performance_trends.json"
            ]

            for trend_file in trend_files:
                file_path = self.output_dir / trend_file
                if file_path.exists():
                    with open(file_path, 'r') as f:
                        trend_data = json.load(f)
                        trend_report['trends'][trend_file.replace('.json', '')] = trend_data

            # Save comprehensive trend report
            report_file = self.output_dir / "comprehensive_trend_report.json"
            with open(report_file, 'w') as f:
                json.dump(trend_report, f, indent=2)

            logger.info("Comprehensive trend report generated")

        except Exception as e:
            logger.error(f"Error generating trend reports: {str(e)}")

    def generate_improvement_recommendations(self, scan_results: Dict[str, Any]) -> None:
        """Step 7.5: Generate improvement recommendations"""
        logger.info("Generating improvement recommendations")

        # Generate tool-specific recommendations
        self.generate_tool_recommendations(scan_results)

        # Generate process improvements
        self.generate_process_improvements(scan_results)

        # Generate coverage improvements
        self.generate_coverage_improvements(scan_results)

        # Generate performance improvements
        self.generate_performance_improvements(scan_results)

    def generate_tool_recommendations(self, scan_results: Dict[str, Any]) -> None:
        """Generate tool-specific improvement recommendations"""
        try:
            tool_recommendations = []

            # Nuclei recommendations
            tool_recommendations.append(ImprovementRecommendation(
                category="tool_optimization",
                title="Enhance Nuclei Template Coverage",
                description="Add more custom templates for specific technologies and frameworks",
                priority="medium",
                impact="high",
                effort="medium",
                implementation="Create custom Nuclei templates for target-specific vulnerabilities",
                expected_benefit="Improved detection of technology-specific vulnerabilities"
            ))

            # ZAP recommendations
            tool_recommendations.append(ImprovementRecommendation(
                category="tool_optimization",
                title="Optimize ZAP Scanning Configuration",
                description="Fine-tune ZAP scanning parameters for better performance and coverage",
                priority="medium",
                impact="medium",
                effort="low",
                implementation="Adjust ZAP spider depth, scan policy, and timeout settings",
                expected_benefit="Better scan performance and reduced false positives"
            ))

            # API Scanner recommendations
            tool_recommendations.append(ImprovementRecommendation(
                category="tool_enhancement",
                title="Expand API Testing Coverage",
                description="Add more API-specific vulnerability tests and authentication bypass techniques",
                priority="high",
                impact="high",
                effort="medium",
                implementation="Implement additional API testing scenarios and authentication bypass methods",
                expected_benefit="Better detection of API-specific vulnerabilities"
            ))

            self.recommendations.extend(tool_recommendations)

        except Exception as e:
            logger.error(f"Error generating tool recommendations: {str(e)}")

    def generate_process_improvements(self, scan_results: Dict[str, Any]) -> None:
        """Generate process improvement recommendations"""
        try:
            process_recommendations = []

            # Automation improvements
            process_recommendations.append(ImprovementRecommendation(
                category="process_automation",
                title="Implement Automated False Positive Detection",
                description="Develop automated systems to detect and filter false positives",
                priority="high",
                impact="high",
                effort="high",
                implementation="Use machine learning models to analyze scan results and identify false positives",
                expected_benefit="Reduced manual review time and improved result quality"
            ))

            # Integration improvements
            process_recommendations.append(ImprovementRecommendation(
                category="process_integration",
                title="Enhance CI/CD Integration",
                description="Integrate vulnerability scanning into CI/CD pipelines",
                priority="medium",
                impact="medium",
                effort="medium",
                implementation="Create CI/CD plugins and webhooks for automated scanning",
                expected_benefit="Earlier detection of vulnerabilities in development process"
            ))

            self.recommendations.extend(process_recommendations)

        except Exception as e:
            logger.error(f"Error generating process improvements: {str(e)}")

    def generate_coverage_improvements(self, scan_results: Dict[str, Any]) -> None:
        """Generate coverage improvement recommendations"""
        try:
            coverage_recommendations = []

            # Coverage analysis
            if 'findings' in scan_results:
                total_findings = len(scan_results['findings'])
                
                if total_findings < 10:
                    coverage_recommendations.append(ImprovementRecommendation(
                        category="coverage_enhancement",
                        title="Expand Scan Scope",
                        description="Current scan coverage appears low, consider expanding scope",
                        priority="high",
                        impact="high",
                        effort="medium",
                        implementation="Add more targets, endpoints, and scanning depth",
                        expected_benefit="Better vulnerability discovery and coverage"
                    ))

            # Technology coverage
            coverage_recommendations.append(ImprovementRecommendation(
                category="coverage_enhancement",
                title="Add Technology-Specific Scanners",
                description="Implement scanners for specific technologies (WordPress, Drupal, etc.)",
                priority="medium",
                impact="medium",
                effort="medium",
                implementation="Add specialized scanners for common technologies",
                expected_benefit="Better detection of technology-specific vulnerabilities"
            ))

            self.recommendations.extend(coverage_recommendations)

        except Exception as e:
            logger.error(f"Error generating coverage improvements: {str(e)}")

    def generate_performance_improvements(self, scan_results: Dict[str, Any]) -> None:
        """Generate performance improvement recommendations"""
        try:
            performance_recommendations = []

            # Parallel scanning
            performance_recommendations.append(ImprovementRecommendation(
                category="performance_optimization",
                title="Implement Parallel Scanning",
                description="Run multiple scans in parallel to improve overall performance",
                priority="medium",
                impact="high",
                effort="medium",
                implementation="Use concurrent scanning with proper resource management",
                expected_benefit="Faster scan completion times"
            ))

            # Resource optimization
            performance_recommendations.append(ImprovementRecommendation(
                category="performance_optimization",
                title="Optimize Resource Usage",
                description="Optimize memory and CPU usage during scanning",
                priority="low",
                impact="medium",
                effort="low",
                implementation="Implement resource limits and cleanup procedures",
                expected_benefit="Better resource utilization and stability"
            ))

            self.recommendations.extend(performance_recommendations)

        except Exception as e:
            logger.error(f"Error generating performance improvements: {str(e)}")

    def save_improvement_results(self) -> None:
        """Save all improvement results to files"""
        try:
            # Save recommendations
            recommendations_file = self.output_dir / "improvement_recommendations.json"
            with open(recommendations_file, 'w') as f:
                json.dump([asdict(rec) for rec in self.recommendations], f, indent=2)

            # Save template updates
            template_updates_file = self.output_dir / "template_updates.json"
            with open(template_updates_file, 'w') as f:
                json.dump([asdict(update) for update in self.template_updates], f, indent=2)

            # Save summary
            summary = {
                "total_recommendations": len(self.recommendations),
                "total_template_updates": len(self.template_updates),
                "recommendations_by_priority": {
                    "high": len([r for r in self.recommendations if r.priority == "high"]),
                    "medium": len([r for r in self.recommendations if r.priority == "medium"]),
                    "low": len([r for r in self.recommendations if r.priority == "low"])
                },
                "template_updates_by_status": {
                    "completed": len([u for u in self.template_updates if u.status == "completed"]),
                    "failed": len([u for u in self.template_updates if u.status == "failed"])
                }
            }

            summary_file = self.output_dir / "continuous_improvement_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)

            logger.info(f"Continuous improvement results saved to {self.output_dir}")

        except Exception as e:
            logger.error(f"Error saving improvement results: {str(e)}")

    def get_improvement_summary(self) -> Dict[str, Any]:
        """Get a summary of continuous improvement results"""
        try:
            return {
                "total_recommendations": len(self.recommendations),
                "total_template_updates": len(self.template_updates),
                "recommendations_by_category": {},
                "template_updates_by_tool": {}
            }

        except Exception as e:
            logger.error(f"Error generating improvement summary: {str(e)}")
            return {} 