#!/usr/bin/env python3
"""
ZAP Runner for Vulnerability Scanning

This module implements Step 4 of the black-box vulnerability scanning methodology:
"Automated Scanning of Web Applications (Black-Box Testing)"

It runs OWASP ZAP in automated mode to perform comprehensive web application
vulnerability scanning including spidering, active scanning, and reporting.
"""

import os
import json
import logging
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import requests

logger = logging.getLogger(__name__)

@dataclass
class ZAPResult:
    """Structure for ZAP scan results"""
    alert_id: str
    alert_name: str
    risk: str
    confidence: str
    target: str
    url: str
    parameter: str = ""
    evidence: str = ""
    description: str = ""
    solution: str = ""
    reference: str = ""
    cwe_id: str = ""
    wasc_id: str = ""
    timestamp: str = ""
    false_positive: bool = False
    verified: bool = False
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

class ZAPRunner:
    """Runs OWASP ZAP automated vulnerability scanning"""
    
    def __init__(self, output_dir: Path, rate_limit: int = 10, max_concurrent: int = 5):
        self.output_dir = output_dir
        self.rate_limit = rate_limit
        self.max_concurrent = max_concurrent
        
        # Create output directories
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "raw").mkdir(exist_ok=True)
        (self.output_dir / "parsed").mkdir(exist_ok=True)
        (self.output_dir / "reports").mkdir(exist_ok=True)
        
        # ZAP configuration
        self.zap_config = {
            "port": 8080,
            "host": "localhost",
            "api_key": "",
            "timeout": 300,
            "max_duration": 3600,
            "spider_depth": 5,
            "spider_threads": 10,
            "scan_threads": 10,
            "max_children": 10
        }
        
        # ZAP automation plan
        self.automation_plan = self.create_automation_plan()
    
    def run_scan(self, targets: List[str]) -> List[ZAPResult]:
        """Run comprehensive ZAP scan on targets"""
        try:
            logger.info(f"Starting ZAP scan on {len(targets)} targets")
            
            all_results = []
            
            # Run scans sequentially to avoid overwhelming targets
            for i, target in enumerate(targets):
                logger.info(f"Scanning target {i+1}/{len(targets)}: {target}")
                
                try:
                    # Run ZAP scan on individual target
                    results = self.run_single_scan(target)
                    all_results.extend(results)
                    
                    logger.info(f"Target {target} scan completed. Found {len(results)} vulnerabilities")
                    
                    # Rate limiting between scans
                    if i < len(targets) - 1:
                        time.sleep(60 / self.rate_limit)  # Respect rate limit
                
                except Exception as e:
                    logger.error(f"Error scanning target {target}: {str(e)}")
                    continue
            
            # Process and save results
            self.process_results(all_results)
            
            logger.info(f"ZAP scan completed. Found {len(all_results)} total vulnerabilities")
            return all_results
            
        except Exception as e:
            logger.error(f"Error running ZAP scan: {str(e)}")
            return []
    
    def run_single_scan(self, target: str) -> List[ZAPResult]:
        """Run ZAP scan on a single target"""
        try:
            logger.info(f"Running ZAP scan on {target}")
            
            # Step 1: Start ZAP daemon
            zap_process = self.start_zap_daemon()
            if not zap_process:
                logger.error("Failed to start ZAP daemon")
                return []
            
            try:
                # Step 2: Wait for ZAP to be ready
                if not self.wait_for_zap_ready():
                    logger.error("ZAP daemon not ready")
                    return []
                
                # Step 3: Run automated scan
                results = self.run_automated_scan(target)
                
                return results
            
            finally:
                # Step 4: Stop ZAP daemon
                self.stop_zap_daemon(zap_process)
            
        except Exception as e:
            logger.error(f"Error in single ZAP scan: {str(e)}")
            return []
    
    def start_zap_daemon(self) -> Optional[subprocess.Popen]:
        """Start ZAP daemon"""
        try:
            logger.info("Starting ZAP daemon...")
            
            cmd = [
                "zap.sh",
                "-daemon",
                "-port", str(self.zap_config["port"]),
                "-host", self.zap_config["host"],
                "-config", "api.disablekey=true",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            logger.info(f"ZAP daemon started with PID: {process.pid}")
            return process
            
        except Exception as e:
            logger.error(f"Error starting ZAP daemon: {str(e)}")
            return None
    
    def wait_for_zap_ready(self, timeout: int = 60) -> bool:
        """Wait for ZAP to be ready"""
        try:
            logger.info("Waiting for ZAP to be ready...")
            
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    response = requests.get(
                        f"http://{self.zap_config['host']}:{self.zap_config['port']}/JSON/core/view/version/",
                        timeout=5
                    )
                    if response.status_code == 200:
                        logger.info("ZAP is ready")
                        return True
                except requests.RequestException:
                    pass
                
                time.sleep(2)
            
            logger.error("ZAP not ready within timeout")
            return False
            
        except Exception as e:
            logger.error(f"Error waiting for ZAP: {str(e)}")
            return False
    
    def run_automated_scan(self, target: str) -> List[ZAPResult]:
        """Run automated ZAP scan using automation framework"""
        try:
            logger.info(f"Running automated scan for {target}")
            
            # Create automation plan for this target
            plan_file = self.create_target_plan(target)
            
            # Run automation
            cmd = [
                "zap.sh",
                "-cmd",
                "-autorun", str(plan_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.zap_config["max_duration"]
            )
            
            if result.returncode != 0:
                logger.warning(f"ZAP automation returned non-zero exit code: {result.returncode}")
                if result.stderr:
                    logger.warning(f"Stderr: {result.stderr}")
            
            # Parse results
            results = self.parse_zap_results(target)
            
            # Save raw output
            raw_output_file = self.output_dir / "raw" / f"{target.replace('://', '_').replace('/', '_')}_raw.txt"
            with open(raw_output_file, 'w') as f:
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n\nSTDERR:\n{result.stderr}")
            
            return results
            
        except subprocess.TimeoutExpired:
            logger.error(f"ZAP automation timed out for {target}")
            return []
        except Exception as e:
            logger.error(f"Error running ZAP automation: {str(e)}")
            return []
    
    def create_target_plan(self, target: str) -> Path:
        """Create automation plan for specific target"""
        try:
            plan_content = f"""env:
  contexts:
    - name: "Target Context"
      urls:
        - "{target}"
  parameters:
    failOnError: false
    progressToStdout: true
  vars:
    target: "{target}"
jobs:
  - type: "spider"
    parameters:
      url: "${{target}}"
      maxDuration: 300
      maxDepth: {self.zap_config['spider_depth']}
      maxChildren: {self.zap_config['max_children']}
      context: "Target Context"
      threadCount: {self.zap_config['spider_threads']}
  
  - type: "ajaxSpider"
    parameters:
      url: "${{target}}"
      maxDuration: 300
      context: "Target Context"
      browserId: "chrome-headless"
  
  - type: "activeScan"
    parameters:
      context: "Target Context"
      policy: "Default Policy"
      maxDuration: 600
      maxRuleDurationInMins: 10
      threadCount: {self.zap_config['scan_threads']}
  
  - type: "report"
    parameters:
      template: "traditional-html"
      reportDir: "{self.output_dir / 'reports'}"
      reportFile: "{target.replace('://', '_').replace('/', '_')}_report.html"
      reportTitle: "ZAP Vulnerability Scan Report - {target}"
      reportDescription: "Automated vulnerability scan using OWASP ZAP"
  
  - type: "report"
    parameters:
      template: "json"
      reportDir: "{self.output_dir / 'raw'}"
      reportFile: "{target.replace('://', '_').replace('/', '_')}_alerts.json"
"""
            
            plan_file = self.output_dir / "raw" / f"{target.replace('://', '_').replace('/', '_')}_plan.yaml"
            with open(plan_file, 'w') as f:
                f.write(plan_content)
            
            return plan_file
            
        except Exception as e:
            logger.error(f"Error creating target plan: {str(e)}")
            return Path("")
    
    def parse_zap_results(self, target: str) -> List[ZAPResult]:
        """Parse ZAP scan results"""
        try:
            results = []
            
            # Try to parse JSON alerts
            alerts_file = self.output_dir / "raw" / f"{target.replace('://', '_').replace('/', '_')}_alerts.json"
            if alerts_file.exists():
                results.extend(self.parse_json_alerts(alerts_file, target))
            
            # Try to parse XML alerts
            xml_file = self.output_dir / "raw" / f"{target.replace('://', '_').replace('/', '_')}_alerts.xml"
            if xml_file.exists():
                results.extend(self.parse_xml_alerts(xml_file, target))
            
            # Try to get alerts via API
            api_results = self.get_alerts_via_api(target)
            results.extend(api_results)
            
            logger.info(f"Parsed {len(results)} ZAP results for {target}")
            return results
            
        except Exception as e:
            logger.error(f"Error parsing ZAP results: {str(e)}")
            return []
    
    def parse_json_alerts(self, alerts_file: Path, target: str) -> List[ZAPResult]:
        """Parse ZAP JSON alerts"""
        results = []
        
        try:
            with open(alerts_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                alerts = data
            elif isinstance(data, dict) and "alerts" in data:
                alerts = data["alerts"]
            else:
                alerts = []
            
            for alert in alerts:
                result = self.parse_alert(alert, target)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing JSON alerts: {str(e)}")
            return results
    
    def parse_xml_alerts(self, xml_file: Path, target: str) -> List[ZAPResult]:
        """Parse ZAP XML alerts"""
        results = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for alert_elem in root.findall(".//alert"):
                alert = self.xml_alert_to_dict(alert_elem)
                result = self.parse_alert(alert, target)
                if result:
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error parsing XML alerts: {str(e)}")
            return results
    
    def xml_alert_to_dict(self, alert_elem) -> Dict[str, Any]:
        """Convert XML alert element to dictionary"""
        alert = {}
        
        try:
            # Extract basic fields
            for field in ["alertid", "name", "riskcode", "confidence", "url", "param", "evidence", "description", "solution", "reference", "cweid", "wascid"]:
                elem = alert_elem.find(field)
                if elem is not None:
                    alert[field] = elem.text or ""
                else:
                    alert[field] = ""
            
            return alert
            
        except Exception as e:
            logger.error(f"Error converting XML alert: {str(e)}")
            return {}
    
    def get_alerts_via_api(self, target: str) -> List[ZAPResult]:
        """Get alerts via ZAP API"""
        results = []
        
        try:
            # Get alerts from ZAP API
            response = requests.get(
                f"http://{self.zap_config['host']}:{self.zap_config['port']}/JSON/alert/view/alerts/",
                params={"baseurl": target},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("alerts"):
                    for alert in data["alerts"]:
                        result = self.parse_alert(alert, target)
                        if result:
                            results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting alerts via API: {str(e)}")
            return results
    
    def parse_alert(self, alert: Dict[str, Any], target: str) -> Optional[ZAPResult]:
        """Parse individual ZAP alert"""
        try:
            # Extract fields
            alert_id = str(alert.get("alertid", ""))
            alert_name = alert.get("name", "")
            risk = self.risk_code_to_string(alert.get("riskcode", ""))
            confidence = self.confidence_code_to_string(alert.get("confidence", ""))
            url = alert.get("url", "")
            parameter = alert.get("param", "")
            evidence = alert.get("evidence", "")
            description = alert.get("description", "")
            solution = alert.get("solution", "")
            reference = alert.get("reference", "")
            cwe_id = alert.get("cweid", "")
            wasc_id = alert.get("wascid", "")
            
            # Create result object
            result = ZAPResult(
                alert_id=alert_id,
                alert_name=alert_name,
                risk=risk,
                confidence=confidence,
                target=target,
                url=url,
                parameter=parameter,
                evidence=evidence,
                description=description,
                solution=solution,
                reference=reference,
                cwe_id=cwe_id,
                wasc_id=wasc_id
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error parsing alert: {str(e)}")
            return None
    
    def risk_code_to_string(self, risk_code: str) -> str:
        """Convert risk code to string"""
        risk_map = {
            "0": "info",
            "1": "low",
            "2": "medium",
            "3": "high"
        }
        return risk_map.get(str(risk_code), "unknown")
    
    def confidence_code_to_string(self, confidence_code: str) -> str:
        """Convert confidence code to string"""
        confidence_map = {
            "0": "false_positive",
            "1": "low",
            "2": "medium",
            "3": "high"
        }
        return confidence_map.get(str(confidence_code), "unknown")
    
    def stop_zap_daemon(self, process: subprocess.Popen):
        """Stop ZAP daemon"""
        try:
            logger.info("Stopping ZAP daemon...")
            
            # Try graceful shutdown
            process.terminate()
            
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                logger.warning("ZAP daemon did not terminate gracefully, forcing kill")
                process.kill()
                process.wait()
            
            logger.info("ZAP daemon stopped")
            
        except Exception as e:
            logger.error(f"Error stopping ZAP daemon: {str(e)}")
    
    def process_results(self, results: List[ZAPResult]):
        """Process and save scan results"""
        try:
            logger.info(f"Processing {len(results)} ZAP results...")
            
            # Group results by risk level
            results_by_risk = {}
            for result in results:
                risk = result.risk
                if risk not in results_by_risk:
                    results_by_risk[risk] = []
                results_by_risk[risk].append(result)
            
            # Save results by risk level
            for risk, risk_results in results_by_risk.items():
                output_file = self.output_dir / "parsed" / f"{risk}_vulnerabilities.json"
                with open(output_file, 'w') as f:
                    json.dump([self.result_to_dict(result) for result in risk_results], f, indent=2)
            
            # Save all results
            all_results_file = self.output_dir / "parsed" / "all_vulnerabilities.json"
            with open(all_results_file, 'w') as f:
                json.dump([self.result_to_dict(result) for result in results], f, indent=2)
            
            # Generate summary
            self.generate_summary(results)
            
            logger.info("ZAP results processing completed")
            
        except Exception as e:
            logger.error(f"Error processing ZAP results: {str(e)}")
    
    def result_to_dict(self, result: ZAPResult) -> Dict[str, Any]:
        """Convert ZAPResult to dictionary"""
        return {
            "alert_id": result.alert_id,
            "alert_name": result.alert_name,
            "risk": result.risk,
            "confidence": result.confidence,
            "target": result.target,
            "url": result.url,
            "parameter": result.parameter,
            "evidence": result.evidence,
            "description": result.description,
            "solution": result.solution,
            "reference": result.reference,
            "cwe_id": result.cwe_id,
            "wasc_id": result.wasc_id,
            "timestamp": result.timestamp,
            "false_positive": result.false_positive,
            "verified": result.verified
        }
    
    def generate_summary(self, results: List[ZAPResult]):
        """Generate scan summary"""
        try:
            summary = {
                "scan_timestamp": datetime.utcnow().isoformat(),
                "total_vulnerabilities": len(results),
                "by_risk": {},
                "by_alert": {},
                "by_target": {},
                "scan_config": self.zap_config
            }
            
            # Count by risk
            for result in results:
                risk = result.risk
                summary["by_risk"][risk] = summary["by_risk"].get(risk, 0) + 1
            
            # Count by alert type
            for result in results:
                alert = result.alert_name
                summary["by_alert"][alert] = summary["by_alert"].get(alert, 0) + 1
            
            # Count by target
            for result in results:
                target = result.target
                summary["by_target"][target] = summary["by_target"].get(target, 0) + 1
            
            # Save summary
            summary_file = self.output_dir / "parsed" / "scan_summary.json"
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            
            # Log summary
            logger.info("ZAP Scan Summary:")
            logger.info(f"  Total vulnerabilities: {summary['total_vulnerabilities']}")
            for risk, count in summary["by_risk"].items():
                logger.info(f"  {risk}: {count}")
            
        except Exception as e:
            logger.error(f"Error generating ZAP summary: {str(e)}")
    
    def create_automation_plan(self) -> str:
        """Create default automation plan"""
        return """env:
  contexts:
    - name: "Default Context"
      urls:
        - ".*"
  parameters:
    failOnError: false
    progressToStdout: true
  vars:
    target: "TARGET_URL"
jobs:
  - type: "spider"
    parameters:
      url: "${target}"
      maxDuration: 300
      maxDepth: 5
      maxChildren: 10
      context: "Default Context"
      threadCount: 10
  
  - type: "ajaxSpider"
    parameters:
      url: "${target}"
      maxDuration: 300
      context: "Default Context"
      browserId: "chrome-headless"
  
  - type: "activeScan"
    parameters:
      context: "Default Context"
      policy: "Default Policy"
      maxDuration: 600
      maxRuleDurationInMins: 10
      threadCount: 10
  
  - type: "report"
    parameters:
      template: "traditional-html"
      reportDir: "/outputs/zap/reports"
      reportFile: "zap_report.html"
      reportTitle: "ZAP Vulnerability Scan Report"
      reportDescription: "Automated vulnerability scan using OWASP ZAP"
"""