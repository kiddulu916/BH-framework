import os
import subprocess
import json
import re
from typing import Dict, List, Optional
from datetime import datetime

def run_whois_lookup(target: str, output_dir: str) -> Dict:
    """
    Run WHOIS lookup on the target domain to gather registration information.
    Returns structured WHOIS data including registrar, registrant, dates, and name servers.
    """
    output_file = os.path.join(output_dir, f"whois_{target}.txt")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Run WHOIS command
        result = subprocess.run([
            "whois", target
        ], capture_output=True, text=True, check=True)
        
        # Save raw output
        with open(output_file, "w") as f:
            f.write(result.stdout)
        
        # Parse WHOIS data
        whois_data = parse_whois_output(result.stdout, target)
        
        return {
            "tool": "whois",
            "target": target,
            "raw_output_path": output_file,
            "whois_records": [whois_data],
            "total_records": 1
        }
        
    except subprocess.CalledProcessError as e:
        print(f"[WHOIS] Error running whois command: {e}")
        return {
            "tool": "whois",
            "target": target,
            "error": str(e),
            "whois_records": [],
            "total_records": 0
        }
    except Exception as e:
        print(f"[WHOIS] Unexpected error: {e}")
        return {
            "tool": "whois",
            "target": target,
            "error": str(e),
            "whois_records": [],
            "total_records": 0
        }

def parse_whois_output(whois_text: str, domain: str) -> Dict:
    """
    Parse WHOIS output and extract structured information.
    """
    whois_data = {
        "domain": domain,
        "registrar": None,
        "registrant_name": None,
        "registrant_email": None,
        "registrant_organization": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "raw_data": whois_text
    }
    
    lines = whois_text.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('%') or line.startswith('#'):
            continue
            
        # Parse registrar
        if re.search(r'registrar:', line, re.IGNORECASE):
            whois_data["registrar"] = line.split(':', 1)[1].strip()
            
        # Parse registrant information
        elif re.search(r'registrant name:', line, re.IGNORECASE):
            whois_data["registrant_name"] = line.split(':', 1)[1].strip()
        elif re.search(r'registrant email:', line, re.IGNORECASE):
            whois_data["registrant_email"] = line.split(':', 1)[1].strip()
        elif re.search(r'registrant organization:', line, re.IGNORECASE):
            whois_data["registrant_organization"] = line.split(':', 1)[1].strip()
            
        # Parse dates
        elif re.search(r'creation date:', line, re.IGNORECASE):
            whois_data["creation_date"] = line.split(':', 1)[1].strip()
        elif re.search(r'expiration date:', line, re.IGNORECASE):
            whois_data["expiration_date"] = line.split(':', 1)[1].strip()
        elif re.search(r'updated date:', line, re.IGNORECASE):
            whois_data["updated_date"] = line.split(':', 1)[1].strip()
            
        # Parse name servers
        elif re.search(r'name server:', line, re.IGNORECASE):
            ns = line.split(':', 1)[1].strip()
            if ns and ns not in whois_data["name_servers"]:
                whois_data["name_servers"].append(ns)
                
        # Parse status
        elif re.search(r'status:', line, re.IGNORECASE):
            status = line.split(':', 1)[1].strip()
            if status and status not in whois_data["status"]:
                whois_data["status"].append(status)
    
    return whois_data

def run_reverse_whois(domain: str, output_dir: str) -> Dict:
    """
    Run reverse WHOIS lookup to find other domains registered by the same entity.
    This is a basic implementation - in production, you'd use specialized APIs.
    """
    output_file = os.path.join(output_dir, f"reverse_whois_{domain}.txt")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # This is a placeholder for reverse WHOIS functionality
        # In a real implementation, you'd use APIs like ViewDNS, SecurityTrails, etc.
        
        # For now, we'll create a basic structure
        reverse_whois_data = {
            "tool": "reverse_whois",
            "target": domain,
            "raw_output_path": output_file,
            "related_domains": [],
            "total_related": 0,
            "note": "Reverse WHOIS requires specialized APIs (ViewDNS, SecurityTrails, etc.)"
        }
        
        # Save placeholder output
        with open(output_file, "w") as f:
            f.write("Reverse WHOIS lookup requires specialized APIs\n")
            f.write("Consider integrating with ViewDNS, SecurityTrails, or similar services\n")
        
        return reverse_whois_data
        
    except Exception as e:
        print(f"[Reverse WHOIS] Error: {e}")
        return {
            "tool": "reverse_whois",
            "target": domain,
            "error": str(e),
            "related_domains": [],
            "total_related": 0
        }