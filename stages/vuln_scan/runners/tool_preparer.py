#!/usr/bin/env python3
"""
Tool Preparer for Vulnerability Scanning

This module implements Step 2 of the black-box vulnerability scanning methodology:
"Prepare Vulnerability Scanning Tools"

It sets up and configures all the tools needed for vulnerability scanning,
including OWASP ZAP, Nuclei, and additional scanners.
"""

import os
import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
import requests

logger = logging.getLogger(__name__)

class ToolPreparer:
    """Prepares and configures vulnerability scanning tools"""
    
    def __init__(self, rate_limit: int = 10):
        self.rate_limit = rate_limit
        self.tools_config = {}
        self.tools_status = {}
        
        # Define tool paths and configurations
        self.tool_configs = {
            "nuclei": {
                "command": "nuclei",
                "version_check": ["nuclei", "-version"],
                "template_update": ["nuclei", "-update-templates"],
                "config_dir": "/root/.config/nuclei",
                "template_dir": "/root/nuclei-templates"
            },
            "zap": {
                "command": "zap.sh",
                "version_check": ["zap.sh", "-version"],
                "config_dir": "/root/.ZAP",
                "automation_dir": "/root/.ZAP/automation"
            },
            "nikto": {
                "command": "nikto",
                "version_check": ["nikto", "-Version"],
                "config_file": "/etc/nikto.conf"
            },
            "wapiti": {
                "command": "wapiti",
                "version_check": ["wapiti", "--version"],
                "config_dir": "/root/.wapiti"
            },
            "arachni": {
                "command": "arachni",
                "version_check": ["arachni", "--version"],
                "config_dir": "/root/.arachni"
            }
        }
    
    def prepare_all_tools(self) -> bool:
        """Prepare all vulnerability scanning tools"""
        try:
            logger.info("Preparing all vulnerability scanning tools...")
            
            # Prepare each tool
            tools_to_prepare = [
                ("nuclei", self.prepare_nuclei),
                ("zap", self.prepare_zap),
                ("nikto", self.prepare_nikto),
                ("wapiti", self.prepare_wapiti),
                ("arachni", self.prepare_arachni)
            ]
            
            success_count = 0
            for tool_name, prepare_func in tools_to_prepare:
                try:
                    logger.info(f"Preparing {tool_name}...")
                    if prepare_func():
                        self.tools_status[tool_name] = "ready"
                        success_count += 1
                        logger.info(f"{tool_name} prepared successfully")
                    else:
                        self.tools_status[tool_name] = "failed"
                        logger.warning(f"{tool_name} preparation failed")
                except Exception as e:
                    self.tools_status[tool_name] = "error"
                    logger.error(f"Error preparing {tool_name}: {str(e)}")
            
            logger.info(f"Tool preparation completed. {success_count}/{len(tools_to_prepare)} tools ready")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error preparing tools: {str(e)}")
            return False
    
    def prepare_nuclei(self) -> bool:
        """Prepare Nuclei vulnerability scanner"""
        try:
            logger.info("Preparing Nuclei...")
            
            # Check if Nuclei is installed
            if not self.check_tool_installed("nuclei"):
                logger.error("Nuclei is not installed")
                return False
            
            # Check version
            version = self.get_tool_version("nuclei")
            if version:
                logger.info(f"Nuclei version: {version}")
            
            # Update templates
            logger.info("Updating Nuclei templates...")
            if self.update_nuclei_templates():
                logger.info("Nuclei templates updated successfully")
            
            # Configure Nuclei
            config = self.configure_nuclei()
            self.tools_config["nuclei"] = config
            
            # Test Nuclei
            if self.test_nuclei():
                logger.info("Nuclei test completed successfully")
                return True
            else:
                logger.error("Nuclei test failed")
                return False
            
        except Exception as e:
            logger.error(f"Error preparing Nuclei: {str(e)}")
            return False
    
    def prepare_zap(self) -> bool:
        """Prepare OWASP ZAP"""
        try:
            logger.info("Preparing OWASP ZAP...")
            
            # Check if ZAP is installed
            if not self.check_tool_installed("zap"):
                logger.error("OWASP ZAP is not installed")
                return False
            
            # Check version
            version = self.get_tool_version("zap")
            if version:
                logger.info(f"ZAP version: {version}")
            
            # Configure ZAP
            config = self.configure_zap()
            self.tools_config["zap"] = config
            
            # Setup automation framework
            if self.setup_zap_automation():
                logger.info("ZAP automation framework setup completed")
            
            # Test ZAP
            if self.test_zap():
                logger.info("ZAP test completed successfully")
                return True
            else:
                logger.error("ZAP test failed")
                return False
            
        except Exception as e:
            logger.error(f"Error preparing ZAP: {str(e)}")
            return False
    
    def prepare_nikto(self) -> bool:
        """Prepare Nikto web server scanner"""
        try:
            logger.info("Preparing Nikto...")
            
            # Check if Nikto is installed
            if not self.check_tool_installed("nikto"):
                logger.error("Nikto is not installed")
                return False
            
            # Check version
            version = self.get_tool_version("nikto")
            if version:
                logger.info(f"Nikto version: {version}")
            
            # Configure Nikto
            config = self.configure_nikto()
            self.tools_config["nikto"] = config
            
            # Test Nikto
            if self.test_nikto():
                logger.info("Nikto test completed successfully")
                return True
            else:
                logger.error("Nikto test failed")
                return False
            
        except Exception as e:
            logger.error(f"Error preparing Nikto: {str(e)}")
            return False
    
    def prepare_wapiti(self) -> bool:
        """Prepare Wapiti web vulnerability scanner"""
        try:
            logger.info("Preparing Wapiti...")
            
            # Check if Wapiti is installed
            if not self.check_tool_installed("wapiti"):
                logger.error("Wapiti is not installed")
                return False
            
            # Check version
            version = self.get_tool_version("wapiti")
            if version:
                logger.info(f"Wapiti version: {version}")
            
            # Configure Wapiti
            config = self.configure_wapiti()
            self.tools_config["wapiti"] = config
            
            # Test Wapiti
            if self.test_wapiti():
                logger.info("Wapiti test completed successfully")
                return True
            else:
                logger.error("Wapiti test failed")
                return False
            
        except Exception as e:
            logger.error(f"Error preparing Wapiti: {str(e)}")
            return False
    
    def prepare_arachni(self) -> bool:
        """Prepare Arachni web application security scanner"""
        try:
            logger.info("Preparing Arachni...")
            
            # Check if Arachni is installed
            if not self.check_tool_installed("arachni"):
                logger.error("Arachni is not installed")
                return False
            
            # Check version
            version = self.get_tool_version("arachni")
            if version:
                logger.info(f"Arachni version: {version}")
            
            # Configure Arachni
            config = self.configure_arachni()
            self.tools_config["arachni"] = config
            
            # Test Arachni
            if self.test_arachni():
                logger.info("Arachni test completed successfully")
                return True
            else:
                logger.error("Arachni test failed")
                return False
            
        except Exception as e:
            logger.error(f"Error preparing Arachni: {str(e)}")
            return False
    
    def check_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and accessible"""
        try:
            config = self.tool_configs.get(tool_name, {})
            command = config.get("command", tool_name)
            
            result = subprocess.run(
                [command, "--help"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return result.returncode == 0 or result.returncode == 1  # Some tools return 1 for help
            
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False
    
    def get_tool_version(self, tool_name: str) -> Optional[str]:
        """Get the version of a tool"""
        try:
            config = self.tool_configs.get(tool_name, {})
            version_cmd = config.get("version_check", [tool_name, "--version"])
            
            result = subprocess.run(
                version_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error getting {tool_name} version: {str(e)}")
            return None
    
    def update_nuclei_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            config = self.tool_configs["nuclei"]
            update_cmd = config.get("template_update", ["nuclei", "-update-templates"])
            
            result = subprocess.run(
                update_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error updating Nuclei templates: {str(e)}")
            return False
    
    def configure_nuclei(self) -> Dict[str, Any]:
        """Configure Nuclei scanner"""
        config = {
            "rate_limit": self.rate_limit,
            "concurrency": 25,
            "timeout": 30,
            "retries": 3,
            "severity": ["critical", "high", "medium", "low"],
            "enable_fuzzing": True,
            "enable_workflows": True,
            "output_format": "json"
        }
        
        # Create Nuclei configuration file
        config_dir = Path(self.tool_configs["nuclei"]["config_dir"])
        config_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = config_dir / "config.yaml"
        with open(config_file, 'w') as f:
            import yaml
            yaml.dump(config, f)
        
        return config
    
    def configure_zap(self) -> Dict[str, Any]:
        """Configure OWASP ZAP"""
        config = {
            "rate_limit": self.rate_limit,
            "timeout": 30,
            "max_children": 10,
            "max_depth": 5,
            "exclude_urls": [],
            "include_urls": [],
            "scan_policy": "Default Policy",
            "context": "Default Context"
        }
        
        # Create ZAP configuration
        config_dir = Path(self.tool_configs["zap"]["config_dir"])
        config_dir.mkdir(parents=True, exist_ok=True)
        
        config_file = config_dir / "config.xml"
        self.create_zap_config_xml(config_file, config)
        
        return config
    
    def create_zap_config_xml(self, config_file: Path, config: Dict[str, Any]):
        """Create ZAP configuration XML file"""
        xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<zap>
    <config>
        <rate_limit>{config['rate_limit']}</rate_limit>
        <timeout>{config['timeout']}</timeout>
        <max_children>{config['max_children']}</max_children>
        <max_depth>{config['max_depth']}</max_depth>
    </config>
</zap>"""
        
        with open(config_file, 'w') as f:
            f.write(xml_content)
    
    def setup_zap_automation(self) -> bool:
        """Setup ZAP automation framework"""
        try:
            automation_dir = Path(self.tool_configs["zap"]["automation_dir"])
            automation_dir.mkdir(parents=True, exist_ok=True)
            
            # Create automation plan
            plan_file = automation_dir / "vuln_scan_plan.yaml"
            self.create_zap_automation_plan(plan_file)
            
            return True
            
        except Exception as e:
            logger.error(f"Error setting up ZAP automation: {str(e)}")
            return False
    
    def create_zap_automation_plan(self, plan_file: Path):
        """Create ZAP automation plan"""
        plan_content = """env:
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
      maxDuration: 60
      maxDepth: 5
      maxChildren: 10
      context: "Default Context"
  
  - type: "ajaxSpider"
    parameters:
      url: "${target}"
      maxDuration: 60
      context: "Default Context"
  
  - type: "activeScan"
    parameters:
      context: "Default Context"
      policy: "Default Policy"
      maxDuration: 60
      maxRuleDurationInMins: 10
  
  - type: "report"
    parameters:
      template: "traditional-html"
      reportDir: "/outputs/zap"
      reportFile: "zap_report.html"
      reportTitle: "ZAP Vulnerability Scan Report"
      reportDescription: "Automated vulnerability scan using OWASP ZAP"
"""
        
        with open(plan_file, 'w') as f:
            f.write(plan_content)
    
    def configure_nikto(self) -> Dict[str, Any]:
        """Configure Nikto scanner"""
        config = {
            "rate_limit": self.rate_limit,
            "timeout": 30,
            "max_time": 3600,
            "plugins": "all",
            "output_format": "json"
        }
        
        return config
    
    def configure_wapiti(self) -> Dict[str, Any]:
        """Configure Wapiti scanner"""
        config = {
            "rate_limit": self.rate_limit,
            "timeout": 30,
            "max_scan_time": 3600,
            "level": 1,
            "scope": "page",
            "output_format": "json"
        }
        
        return config
    
    def configure_arachni(self) -> Dict[str, Any]:
        """Configure Arachni scanner"""
        config = {
            "rate_limit": self.rate_limit,
            "timeout": 30,
            "max_concurrent": 10,
            "scope": "page",
            "checks": "all",
            "output_format": "json"
        }
        
        return config
    
    def test_nuclei(self) -> bool:
        """Test Nuclei functionality"""
        try:
            # Test with a simple scan
            test_cmd = [
                "nuclei",
                "-u", "https://httpbin.org/get",
                "-t", "http/technologies",
                "-silent",
                "-json"
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error testing Nuclei: {str(e)}")
            return False
    
    def test_zap(self) -> bool:
        """Test ZAP functionality"""
        try:
            # Test ZAP CLI
            test_cmd = [
                "zap.sh",
                "-cmd",
                "-version"
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error testing ZAP: {str(e)}")
            return False
    
    def test_nikto(self) -> bool:
        """Test Nikto functionality"""
        try:
            # Test Nikto with help
            test_cmd = [
                "nikto",
                "-Help"
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error testing Nikto: {str(e)}")
            return False
    
    def test_wapiti(self) -> bool:
        """Test Wapiti functionality"""
        try:
            # Test Wapiti with help
            test_cmd = [
                "wapiti",
                "--help"
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error testing Wapiti: {str(e)}")
            return False
    
    def test_arachni(self) -> bool:
        """Test Arachni functionality"""
        try:
            # Test Arachni with help
            test_cmd = [
                "arachni",
                "--help"
            ]
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error testing Arachni: {str(e)}")
            return False
    
    def get_tools_status(self) -> Dict[str, str]:
        """Get status of all tools"""
        return self.tools_status.copy()
    
    def get_tools_config(self) -> Dict[str, Dict[str, Any]]:
        """Get configuration of all tools"""
        return self.tools_config.copy()
    
    def save_configuration(self, output_dir: Path):
        """Save tool configuration to file"""
        try:
            config_file = output_dir / "tools_config.json"
            
            config_data = {
                "tools_status": self.tools_status,
                "tools_config": self.tools_config,
                "rate_limit": self.rate_limit
            }
            
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Tool configuration saved to {config_file}")
            
        except Exception as e:
            logger.error(f"Error saving tool configuration: {str(e)}") 