import os
import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime

def run_social_intelligence(target: str, output_dir: str) -> Dict:
    """
    Gather social media and public information intelligence about the target.
    """
    output_file = os.path.join(output_dir, f"social_intelligence_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        intel_data = {
            "tool": "social_intelligence",
            "target": target,
            "raw_output_path": output_file,
            "social_media_intel": [],
            "total_findings": 0
        }
        
        # Search for employee information
        employee_results = search_employee_info(target)
        intel_data["social_media_intel"].extend(employee_results)
        
        # Search for tech stack information
        tech_stack_results = search_tech_stack(target)
        intel_data["social_media_intel"].extend(tech_stack_results)
        
        # Search for cloud assets
        cloud_results = search_cloud_assets(target)
        intel_data["social_media_intel"].extend(cloud_results)
        
        # Search for community and news
        community_results = search_community_info(target)
        intel_data["social_media_intel"].extend(community_results)
        
        intel_data["total_findings"] = len(intel_data["social_media_intel"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(intel_data, f, indent=2, default=str)
        
        return intel_data
        
    except Exception as e:
        print(f"[Social Intelligence] Error: {e}")
        return {
            "tool": "social_intelligence",
            "target": target,
            "error": str(e),
            "social_media_intel": [],
            "total_findings": 0
        }

def search_employee_info(target: str) -> List[Dict]:
    """
    Search for employee information and profiles.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common employee search patterns
        employee_patterns = [
            f"site:linkedin.com {domain}",
            f"site:twitter.com {domain}",
            f"site:github.com {domain}",
            f"site:facebook.com {domain}",
            f"site:instagram.com {domain}"
        ]
        
        for pattern in employee_patterns:
            # This is a placeholder for employee search
            # In a real implementation, you'd use search APIs
            
            finding = {
                "platform": "social_media",
                "intel_type": "employee_info",
                "username": None,
                "profile_url": None,
                "content": f"Employee search pattern: {pattern}",
                "intel_metadata": {
                    "domain": domain,
                    "search_pattern": pattern,
                    "note": "Employee search requires specialized APIs"
                },
                "relevance_score": 0.7,
                "source": "social_media_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Employee Info] Error: {e}")
    
    return findings

def search_tech_stack(target: str) -> List[Dict]:
    """
    Search for technology stack information.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common tech stack search patterns
        tech_patterns = [
            f"site:stackshare.io {domain}",
            f"site:builtwith.com {domain}",
            f"site:wappalyzer.com {domain}",
            f"site:github.com {domain}",
            f"site:linkedin.com {domain} tech stack"
        ]
        
        for pattern in tech_patterns:
            finding = {
                "platform": "tech_discovery",
                "intel_type": "tech_stack",
                "username": None,
                "profile_url": None,
                "content": f"Tech stack search pattern: {pattern}",
                "intel_metadata": {
                    "domain": domain,
                    "search_pattern": pattern,
                    "note": "Tech stack discovery requires specialized tools"
                },
                "relevance_score": 0.8,
                "source": "tech_stack_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Tech Stack] Error: {e}")
    
    return findings

def search_cloud_assets(target: str) -> List[Dict]:
    """
    Search for cloud assets and infrastructure.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common cloud asset patterns
        cloud_patterns = [
            f"site:aws.amazon.com {domain}",
            f"site:azure.microsoft.com {domain}",
            f"site:cloud.google.com {domain}",
            f"site:heroku.com {domain}",
            f"site:vercel.com {domain}",
            f"site:netlify.com {domain}"
        ]
        
        for pattern in cloud_patterns:
            finding = {
                "platform": "cloud_discovery",
                "intel_type": "cloud_assets",
                "username": None,
                "profile_url": None,
                "content": f"Cloud asset search pattern: {pattern}",
                "intel_metadata": {
                    "domain": domain,
                    "search_pattern": pattern,
                    "note": "Cloud asset discovery requires specialized APIs"
                },
                "relevance_score": 0.9,
                "source": "cloud_asset_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Cloud Assets] Error: {e}")
    
    return findings

def search_community_info(target: str) -> List[Dict]:
    """
    Search for community and news information.
    """
    findings = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common community search patterns
        community_patterns = [
            f"site:reddit.com {domain}",
            f"site:hackernews.com {domain}",
            f"site:twitter.com {domain}",
            f"site:linkedin.com {domain}",
            f"site:medium.com {domain}",
            f"site:dev.to {domain}"
        ]
        
        for pattern in community_patterns:
            finding = {
                "platform": "community",
                "intel_type": "community_info",
                "username": None,
                "profile_url": None,
                "content": f"Community search pattern: {pattern}",
                "intel_metadata": {
                    "domain": domain,
                    "search_pattern": pattern,
                    "note": "Community search requires specialized APIs"
                },
                "relevance_score": 0.6,
                "source": "community_search"
            }
            findings.append(finding)
            
    except Exception as e:
        print(f"[Community Info] Error: {e}")
    
    return findings

def extract_domain(target: str) -> str:
    """
    Extract domain from target URL or domain.
    """
    # Remove protocol if present
    if target.startswith(('http://', 'https://')):
        target = target.split('://', 1)[1]
    
    # Remove path and query parameters
    target = target.split('/')[0]
    
    # Remove port if present
    target = target.split(':')[0]
    
    return target