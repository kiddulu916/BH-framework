import os
import requests
import json
import re
from typing import Dict, List, Optional
from datetime import datetime

def run_infrastructure_exposure(target: str, output_dir: str) -> Dict:
    """
    Search for infrastructure exposure using Shodan, Censys, and other infrastructure databases.
    """
    output_file = os.path.join(output_dir, f"infrastructure_exposure_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        infra_data = {
            "tool": "infrastructure_exposure",
            "target": target,
            "raw_output_path": output_file,
            "infrastructure_exposures": [],
            "total_exposures": 0
        }
        
        # Search Shodan
        shodan_results = search_shodan(target)
        infra_data["infrastructure_exposures"].extend(shodan_results)
        
        # Search Censys
        censys_results = search_censys(target)
        infra_data["infrastructure_exposures"].extend(censys_results)
        
        # Search BinaryEdge
        binaryedge_results = search_binaryedge(target)
        infra_data["infrastructure_exposures"].extend(binaryedge_results)
        
        # Search ZoomEye
        zoomeye_results = search_zoomeye(target)
        infra_data["infrastructure_exposures"].extend(zoomeye_results)
        
        # Search for cloud assets
        cloud_results = search_cloud_assets(target)
        infra_data["infrastructure_exposures"].extend(cloud_results)
        
        infra_data["total_exposures"] = len(infra_data["infrastructure_exposures"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(infra_data, f, indent=2, default=str)
        
        return infra_data
        
    except Exception as e:
        print(f"[Infrastructure Exposure] Error: {e}")
        return {
            "tool": "infrastructure_exposure",
            "target": target,
            "error": str(e),
            "infrastructure_exposures": [],
            "total_exposures": 0
        }

def search_shodan(target: str) -> List[Dict]:
    """
    Search Shodan for infrastructure exposure (requires API key).
    """
    exposures = []
    
    # Check for Shodan API key
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    
    if not shodan_api_key:
        print("[Shodan] API key not found. Skipping Shodan search.")
        return exposures
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Search Shodan for the domain
        url = "https://api.shodan.io/shodan/host/search"
        params = {
            "key": shodan_api_key,
            "query": f"hostname:{domain}",
            "facets": "port,product,os"
        }
        
        response = requests.get(url, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for result in data.get("matches", []):
                exposure = {
                    "source": "shodan",
                    "ip_address": result.get("ip_str", ""),
                    "port": result.get("port", ""),
                    "service": result.get("product", ""),
                    "banner": result.get("data", ""),
                    "ssl_info": extract_ssl_info(result),
                    "vulnerabilities": extract_vulnerabilities(result),
                    "location": {
                        "country": result.get("location", {}).get("country_name", ""),
                        "city": result.get("location", {}).get("city", ""),
                        "latitude": result.get("location", {}).get("latitude", ""),
                        "longitude": result.get("location", {}).get("longitude", "")
                    },
                    "organization": result.get("org", ""),
                    "os": result.get("os", ""),
                    "timestamp": result.get("timestamp", "")
                }
                exposures.append(exposure)
                
        elif response.status_code == 401:
            print("[Shodan] Invalid API key")
        elif response.status_code == 429:
            print("[Shodan] Rate limit exceeded")
        else:
            print(f"[Shodan] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[Shodan] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Shodan] JSON decode error: {e}")
    except Exception as e:
        print(f"[Shodan] Unexpected error: {e}")
    
    return exposures

def search_censys(target: str) -> List[Dict]:
    """
    Search Censys for infrastructure exposure (requires API key).
    """
    exposures = []
    
    # Check for Censys API credentials
    censys_api_id = os.getenv("CENSYS_API_ID")
    censys_api_secret = os.getenv("CENSYS_API_SECRET")
    
    if not censys_api_id or not censys_api_secret:
        print("[Censys] API credentials not found. Skipping Censys search.")
        return exposures
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Search Censys hosts index
        url = "https://search.censys.io/api/v2/hosts/search"
        headers = {
            "Authorization": f"Basic {censys_api_id}:{censys_api_secret}"
        }
        params = {
            "q": f"names: {domain}",
            "fields": ["ip", "ports", "services", "location", "autonomous_system"]
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for result in data.get("result", {}).get("hits", []):
                exposure = {
                    "source": "censys",
                    "ip_address": result.get("ip", ""),
                    "port": None,  # Censys returns multiple ports
                    "service": extract_censys_services(result),
                    "banner": extract_censys_banner(result),
                    "ssl_info": extract_censys_ssl_info(result),
                    "vulnerabilities": [],
                    "location": {
                        "country": result.get("location", {}).get("country", ""),
                        "city": result.get("location", {}).get("city", ""),
                        "latitude": result.get("location", {}).get("coordinates", {}).get("latitude", ""),
                        "longitude": result.get("location", {}).get("coordinates", {}).get("longitude", "")
                    },
                    "organization": result.get("autonomous_system", {}).get("organization", ""),
                    "os": None,
                    "timestamp": None
                }
                exposures.append(exposure)
                
        elif response.status_code == 401:
            print("[Censys] Invalid API credentials")
        elif response.status_code == 429:
            print("[Censys] Rate limit exceeded")
        else:
            print(f"[Censys] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[Censys] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Censys] JSON decode error: {e}")
    except Exception as e:
        print(f"[Censys] Unexpected error: {e}")
    
    return exposures

def search_binaryedge(target: str) -> List[Dict]:
    """
    Search BinaryEdge for infrastructure exposure (requires API key).
    """
    exposures = []
    
    # Check for BinaryEdge API key
    binaryedge_api_key = os.getenv("BINARYEDGE_API_KEY")
    
    if not binaryedge_api_key:
        print("[BinaryEdge] API key not found. Skipping BinaryEdge search.")
        return exposures
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Search BinaryEdge for the domain
        url = f"https://api.binaryedge.io/v2/query/ip/domain/{domain}"
        headers = {
            "X-Key": binaryedge_api_key
        }
        
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for ip in data.get("ips", []):
                exposure = {
                    "source": "binaryedge",
                    "ip_address": ip,
                    "port": None,
                    "service": None,
                    "banner": None,
                    "ssl_info": None,
                    "vulnerabilities": [],
                    "location": {},
                    "organization": "",
                    "os": None,
                    "timestamp": None
                }
                exposures.append(exposure)
                
        elif response.status_code == 401:
            print("[BinaryEdge] Invalid API key")
        elif response.status_code == 429:
            print("[BinaryEdge] Rate limit exceeded")
        else:
            print(f"[BinaryEdge] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[BinaryEdge] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[BinaryEdge] JSON decode error: {e}")
    except Exception as e:
        print(f"[BinaryEdge] Unexpected error: {e}")
    
    return exposures

def search_zoomeye(target: str) -> List[Dict]:
    """
    Search ZoomEye for infrastructure exposure (requires API key).
    """
    exposures = []
    
    # Check for ZoomEye API key
    zoomeye_api_key = os.getenv("ZOOMEYE_API_KEY")
    
    if not zoomeye_api_key:
        print("[ZoomEye] API key not found. Skipping ZoomEye search.")
        return exposures
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Search ZoomEye for the domain
        url = "https://api.zoomeye.org/host/search"
        headers = {
            "API-KEY": zoomeye_api_key
        }
        params = {
            "query": f"hostname:{domain}",
            "page": 1,
            "facets": "port,service,os"
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for result in data.get("matches", []):
                exposure = {
                    "source": "zoomeye",
                    "ip_address": result.get("ip", ""),
                    "port": result.get("portinfo", {}).get("port", ""),
                    "service": result.get("portinfo", {}).get("service", ""),
                    "banner": result.get("portinfo", {}).get("banner", ""),
                    "ssl_info": extract_zoomeye_ssl_info(result),
                    "vulnerabilities": [],
                    "location": {
                        "country": result.get("geoinfo", {}).get("country", {}).get("names", {}).get("en", ""),
                        "city": result.get("geoinfo", {}).get("city", {}).get("names", {}).get("en", ""),
                        "latitude": result.get("geoinfo", {}).get("location", {}).get("lat", ""),
                        "longitude": result.get("geoinfo", {}).get("location", {}).get("lon", "")
                    },
                    "organization": result.get("geoinfo", {}).get("organization", ""),
                    "os": result.get("portinfo", {}).get("os", ""),
                    "timestamp": result.get("timestamp", "")
                }
                exposures.append(exposure)
                
        elif response.status_code == 401:
            print("[ZoomEye] Invalid API key")
        elif response.status_code == 429:
            print("[ZoomEye] Rate limit exceeded")
        else:
            print(f"[ZoomEye] Request failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[ZoomEye] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[ZoomEye] JSON decode error: {e}")
    except Exception as e:
        print(f"[ZoomEye] Unexpected error: {e}")
    
    return exposures

def search_cloud_assets(target: str) -> List[Dict]:
    """
    Search for cloud assets and misconfigurations.
    """
    exposures = []
    
    try:
        # Extract domain from target
        domain = extract_domain(target)
        
        # Common cloud asset patterns
        cloud_patterns = [
            # AWS S3 buckets
            f"{domain}.s3.amazonaws.com",
            f"s3-{domain}.amazonaws.com",
            f"{domain}-s3.amazonaws.com",
            
            # Google Cloud Storage
            f"{domain}.storage.googleapis.com",
            
            # Azure Blob Storage
            f"{domain}.blob.core.windows.net",
            
            # CloudFront distributions
            f"{domain}.cloudfront.net",
            
            # Heroku apps
            f"{domain}.herokuapp.com",
            
            # Vercel deployments
            f"{domain}.vercel.app",
            
            # Netlify sites
            f"{domain}.netlify.app"
        ]
        
        for pattern in cloud_patterns:
            # This is a placeholder for cloud asset checking
            # In a real implementation, you'd check if these assets exist
            
            exposure = {
                "source": "cloud_asset_search",
                "ip_address": None,
                "port": None,
                "service": "cloud_storage",
                "banner": f"Potential cloud asset: {pattern}",
                "ssl_info": None,
                "vulnerabilities": [],
                "location": {},
                "organization": "cloud_provider",
                "os": None,
                "timestamp": None
            }
            exposures.append(exposure)
            
    except Exception as e:
        print(f"[Cloud Assets] Error: {e}")
    
    return exposures

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

def extract_ssl_info(result: Dict) -> Optional[Dict]:
    """
    Extract SSL information from Shodan result.
    """
    ssl_data = result.get("ssl", {})
    if ssl_data:
        return {
            "version": ssl_data.get("version", ""),
            "cipher": ssl_data.get("cipher", {}).get("name", ""),
            "certificate": {
                "subject": ssl_data.get("cert", {}).get("subject", {}).get("CN", ""),
                "issuer": ssl_data.get("cert", {}).get("issuer", {}).get("CN", ""),
                "valid_from": ssl_data.get("cert", {}).get("valid_from", ""),
                "valid_to": ssl_data.get("cert", {}).get("valid_to", "")
            }
        }
    return None

def extract_vulnerabilities(result: Dict) -> List[Dict]:
    """
    Extract vulnerability information from Shodan result.
    """
    vulns = []
    vuln_data = result.get("vulns", [])
    
    for vuln in vuln_data:
        vulns.append({
            "id": vuln,
            "severity": "unknown",
            "description": f"Vulnerability: {vuln}"
        })
    
    return vulns

def extract_censys_services(result: Dict) -> str:
    """
    Extract service information from Censys result.
    """
    services = []
    for port, service_data in result.get("services", {}).items():
        service_name = service_data.get("service_name", "")
        if service_name:
            services.append(f"{service_name}:{port}")
    
    return ", ".join(services) if services else "unknown"

def extract_censys_banner(result: Dict) -> str:
    """
    Extract banner information from Censys result.
    """
    banners = []
    for port, service_data in result.get("services", {}).items():
        banner = service_data.get("banner", "")
        if banner:
            banners.append(f"Port {port}: {banner}")
    
    return "\n".join(banners) if banners else ""

def extract_censys_ssl_info(result: Dict) -> Optional[Dict]:
    """
    Extract SSL information from Censys result.
    """
    ssl_data = result.get("services", {}).get("443", {}).get("tls", {})
    if ssl_data:
        return {
            "version": ssl_data.get("version", ""),
            "cipher": ssl_data.get("cipher_suite", {}).get("name", ""),
            "certificate": {
                "subject": ssl_data.get("certificates", {}).get("leaf", {}).get("subject", {}).get("common_name", ""),
                "issuer": ssl_data.get("certificates", {}).get("leaf", {}).get("issuer", {}).get("common_name", ""),
                "valid_from": ssl_data.get("certificates", {}).get("leaf", {}).get("validity", {}).get("start", ""),
                "valid_to": ssl_data.get("certificates", {}).get("leaf", {}).get("validity", {}).get("end", "")
            }
        }
    return None

def extract_zoomeye_ssl_info(result: Dict) -> Optional[Dict]:
    """
    Extract SSL information from ZoomEye result.
    """
    ssl_data = result.get("portinfo", {}).get("ssl", {})
    if ssl_data:
        return {
            "version": ssl_data.get("version", ""),
            "cipher": ssl_data.get("cipher", ""),
            "certificate": {
                "subject": ssl_data.get("cert", {}).get("subject", ""),
                "issuer": ssl_data.get("cert", {}).get("issuer", ""),
                "valid_from": ssl_data.get("cert", {}).get("valid_from", ""),
                "valid_to": ssl_data.get("cert", {}).get("valid_to", "")
            }
        }
    return None

def run_vulnerability_scanning(target: str, output_dir: str) -> Dict:
    """
    Run vulnerability scanning on discovered infrastructure.
    """
    output_file = os.path.join(output_dir, f"vulnerability_scanning_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        vuln_data = {
            "tool": "vulnerability_scanning",
            "target": target,
            "raw_output_path": output_file,
            "infrastructure_exposures": [],
            "total_exposures": 0,
            "note": "Vulnerability scanning requires specialized tools like Nuclei, Nmap, etc."
        }
        
        # This is a placeholder for vulnerability scanning
        # In a real implementation, you'd use tools like Nuclei, Nmap, etc.
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(vuln_data, f, indent=2, default=str)
        
        return vuln_data
        
    except Exception as e:
        print(f"[Vulnerability Scanning] Error: {e}")
        return {
            "tool": "vulnerability_scanning",
            "target": target,
            "error": str(e),
            "infrastructure_exposures": [],
            "total_exposures": 0
        }