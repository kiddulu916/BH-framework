#!/usr/bin/env python3
"""
WebAnalyze Runner for Active Reconnaissance

This module uses webAnalyze to detect web technologies and services
running on discovered ports and subdomains.
"""

import os
import json
import subprocess
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_webanalyze(targets: List[str], output_dir: str, ports: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Run webAnalyze to detect web technologies and services.
    
    Args:
        targets: List of targets (subdomains or URLs) to analyze
        output_dir: Directory to save results
        ports: List of ports to check (default: common web ports)
    
    Returns:
        Dictionary containing technology detection results
    """
    # Initialize cmd variable to avoid UnboundLocalError
    cmd = [
        "webanalyze",
        "-hosts", "targets_file",  # Will be updated
        "-output", "json",
        "-silent"
    ]
    
    try:
        logger.info(f"Starting webAnalyze technology detection for {len(targets)} targets")
        
        # Default ports if none specified
        if not ports:
            ports = ["80", "443", "8080", "8443", "3000", "8000", "8888"]
        
        # Create output files
        targets_file = os.path.join(output_dir, "webanalyze_targets.txt")
        results_file = os.path.join(output_dir, "webanalyze_results.json")
        
        # Prepare targets with ports
        targets_with_ports = []
        for target in targets:
            # Add http/https if not present
            if not target.startswith(('http://', 'https://')):
                for port in ports:
                    if port == "443":
                        targets_with_ports.append(f"https://{target}:{port}")
                    else:
                        targets_with_ports.append(f"http://{target}:{port}")
            else:
                targets_with_ports.append(target)
        
        # Write targets to file
        with open(targets_file, 'w') as f:
            for target in targets_with_ports:
                f.write(f"{target}\n")
        
        logger.info(f"Wrote {len(targets_with_ports)} targets to {targets_file}")
        
        # Update cmd with actual targets file
        cmd = [
            "webanalyze",
            "-hosts", targets_file,
            "-output", "json",
            "-silent"
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            logger.error(f"webAnalyze failed: {result.stderr}")
            return {
                "success": False,
                "error": f"webAnalyze command failed: {result.stderr}",
                "targets_checked": len(targets),
                "technologies": [],
                "command": cmd,
                "return_code": result.returncode,
                "summary": {
                    "total_targets": len(targets),
                    "total_technologies": 0,
                    "unique_technologies": 0,
                    "categories_found": 0
                }
            }
        
        # Parse webAnalyze output
        technologies = []
        if result.stdout.strip():
            # Try JSON parsing first
            json_parsed = False
            try:
                # webAnalyze outputs one JSON object per line
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        tech_data = json.loads(line)
                        technologies.append(tech_data)
                        json_parsed = True
            except json.JSONDecodeError:
                # Fall back to plain text parsing
                logger.info("JSON parsing failed, trying plain text parsing")
                technologies = parse_webanalyze_output(result.stdout)
                json_parsed = True
            
            if not json_parsed:
                logger.error("Failed to parse webAnalyze output")
                return {
                    "success": False,
                    "error": "Failed to parse webAnalyze output",
                    "targets_checked": len(targets),
                    "technologies": [],
                    "command": cmd,
                    "return_code": result.returncode,
                    "summary": {
                        "total_targets": len(targets),
                        "total_technologies": 0,
                        "unique_technologies": 0,
                        "categories_found": 0
                    }
                }
        
        # Group technologies by target
        target_technologies = {}
        for tech in technologies:
            host = tech.get("hostname", "")
            if host not in target_technologies:
                target_technologies[host] = []
            target_technologies[host].append(tech)
        
        # Create summary statistics
        tech_categories = {}
        for tech in technologies:
            category = tech.get("category", "Unknown")
            if category not in tech_categories:
                tech_categories[category] = []
            tech_categories[category].append(tech.get("technology", "Unknown"))
        
        # Prepare results
        results = {
            "success": True,
            "targets_checked": len(targets),
            "targets_with_ports": len(targets_with_ports),
            "technologies_found": len(technologies),
            "targets_with_technologies": len(target_technologies),
            "technologies": technologies,
            "target_technologies": target_technologies,
            "tech_categories": tech_categories,
            "technology_mapping": target_technologies,  # Add for test compatibility
            "command": cmd,
            "return_code": result.returncode,
            "files": {
                "targets_file": targets_file,
                "results_file": results_file
            },
            "summary": {
                "total_targets": len(targets),
                "total_technologies": len(technologies),
                "unique_technologies": len(set(tech.get("technology", "") for tech in technologies)),
                "categories_found": len(tech_categories)
            }
        }
        
        # Save results to JSON
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"webAnalyze completed successfully")
        logger.info(f"  - Targets checked: {len(targets)}")
        logger.info(f"  - Technologies found: {len(technologies)}")
        logger.info(f"  - Targets with technologies: {len(target_technologies)}")
        logger.info(f"  - Technology categories: {len(tech_categories)}")
        
        return results
        
    except subprocess.TimeoutExpired:
        logger.error("webAnalyze command timed out")
        return {
            "success": False,
            "error": "timeout: webAnalyze command timed out",
            "targets_checked": len(targets),
            "technologies": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_technologies": 0,
                "unique_technologies": 0,
                "categories_found": 0,
                "execution_time_seconds": 300
            }
        }
    except Exception as e:
        logger.error(f"Error in webAnalyze runner: {e}")
        error_msg = str(e)
        # Check if it's a directory creation error
        if "No such file or directory" in error_msg or "The system cannot find the file specified" in error_msg:
            error_msg = f"Directory creation failed: {error_msg}"
        
        return {
            "success": False,
            "error": error_msg,
            "targets_checked": len(targets),
            "technologies": [],
            "command": cmd,
            "return_code": None,
            "summary": {
                "total_targets": len(targets),
                "total_technologies": 0,
                "unique_technologies": 0,
                "categories_found": 0
            }
        }

def parse_webanalyze_output(webanalyze_output: str) -> List[Dict[str, Any]]:
    """
    Parse webAnalyze output and return structured results.
    
    Args:
        webanalyze_output: Raw webAnalyze output
        
    Returns:
        List of technology information dictionaries
    """
    technologies = []
    
    lines = webanalyze_output.strip().split('\n')
    current_host = None
    
    for line in lines:
        orig_line = line
        line = line.strip()
        if not line:
            continue
            
        # Try CSV format first: host,technology,version,category
        if ',' in line:
            parts = line.split(',')
            if len(parts) >= 4:
                host = parts[0].strip()
                technology = parts[1].strip()
                version = parts[2].strip()
                category = parts[3].strip()
                
                # Only accept HTTP/HTTPS URLs
                if host.startswith(('http://', 'https://')):
                    url = host
                    tech_info = {
                        "url": url,
                        "technology": technology,
                        "version": version,
                        "category": category
                    }
                    technologies.append(tech_info)
                continue
        
        # Try alternative format: host:port followed by indented technologies
        if ':' in line and not orig_line.startswith(' '):
            # This is a host line (e.g., "example.com:80")
            current_host = line.strip()
            continue
        
        # If we have a current host and this line is indented, it's a technology
        if current_host and orig_line and orig_line[0].isspace():
            # Parse technology line (e.g., "Apache [2.4.41]")
            tech_line = line.strip()
            if '[' in tech_line and ']' in tech_line:
                # Extract technology name and version
                tech_name = tech_line.split('[')[0].strip()
                version = tech_line.split('[')[1].split(']')[0].strip()
                
                url = f"http://{current_host}"
                tech_info = {
                    "url": url,
                    "technology": tech_name,
                    "version": version,
                    "category": "Unknown"
                }
                technologies.append(tech_info)
    
    return technologies

def enhance_port_scan_results(port_scan_results: Dict[str, Any], webanalyze_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhance port scan results with webAnalyze technology detection.
    
    Args:
        port_scan_results: Results from port scanning tools (nmap, naabu)
        webanalyze_results: Results from webAnalyze technology detection
    
    Returns:
        Enhanced port scan results with service information
    """
    try:
        enhanced_results = port_scan_results.copy()
        
        if not webanalyze_results.get("success"):
            logger.warning("webAnalyze results not available for enhancement")
            return enhanced_results
        
        # Create a mapping of target -> technologies
        target_tech_map = {}
        for tech in webanalyze_results.get("technologies", []):
            host = tech.get("hostname", "")
            if host not in target_tech_map:
                target_tech_map[host] = []
            target_tech_map[host].append(tech)
        
        # Enhance port scan results with technology information
        if "hosts" in enhanced_results:
            for host in enhanced_results["hosts"]:
                hostname = host.get("hostname", "")
                # Find matching technologies
                if hostname in target_tech_map:
                    host["technologies"] = target_tech_map[hostname]
                    host["service_count"] = len(target_tech_map[hostname])
                else:
                    host["technologies"] = []
                    host["service_count"] = 0
        
        # Add webAnalyze summary to enhanced results
        enhanced_results["webanalyze_summary"] = webanalyze_results.get("summary", {})
        enhanced_results["technology_categories"] = webanalyze_results.get("tech_categories", {})
        
        logger.info("Successfully enhanced port scan results with technology detection")
        return enhanced_results
        
    except Exception as e:
        logger.error(f"Error enhancing port scan results: {e}")
        return port_scan_results

def main():
    """Main function for testing the webAnalyze runner."""
    import argparse
    
    parser = argparse.ArgumentParser(description="WebAnalyze Runner")
    parser.add_argument("--targets", required=True, help="Comma-separated list of targets")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--ports", help="Comma-separated list of ports")
    
    args = parser.parse_args()
    
    targets = [t.strip() for t in args.targets.split(",")]
    ports = [p.strip() for p in args.ports.split(",")] if args.ports else None
    
    results = run_webanalyze(targets, args.output_dir, ports)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 