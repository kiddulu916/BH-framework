import os
import requests
import json
import re
import time
from typing import Dict, List, Optional
from datetime import datetime
from urllib.parse import quote_plus

def run_search_dorking(target: str, output_dir: str) -> Dict:
    """
    Perform advanced search engine dorking using Google and Bing search operators.
    Discovers files, directories, and sensitive information.
    """
    output_file = os.path.join(output_dir, f"search_dorking_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        dork_data = {
            "tool": "search_dorking",
            "target": target,
            "raw_output_path": output_file,
            "search_dork_results": [],
            "total_results": 0
        }
        
        # Generate dork queries for the target
        dork_queries = generate_dork_queries(target)
        
        # Search Google (if API key available)
        google_results = search_google_dorks(target, dork_queries)
        dork_data["search_dork_results"].extend(google_results)
        
        # Search Bing (if API key available)
        bing_results = search_bing_dorks(target, dork_queries)
        dork_data["search_dork_results"].extend(bing_results)
        
        # Search for specific file types
        file_type_results = search_file_types(target)
        dork_data["search_dork_results"].extend(file_type_results)
        
        # Search for error messages and debug info
        error_results = search_error_messages(target)
        dork_data["search_dork_results"].extend(error_results)
        
        dork_data["total_results"] = len(dork_data["search_dork_results"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(dork_data, f, indent=2, default=str)
        
        return dork_data
        
    except Exception as e:
        print(f"[Search Dorking] Error: {e}")
        return {
            "tool": "search_dorking",
            "target": target,
            "error": str(e),
            "search_dork_results": [],
            "total_results": 0
        }

def generate_dork_queries(target: str) -> List[str]:
    """
    Generate comprehensive dork queries for the target domain.
    """
    queries = [
        # Basic domain searches
        f'site:{target}',
        f'inurl:{target}',
        f'intitle:{target}',
        
        # File discovery
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:doc',
        f'site:{target} filetype:docx',
        f'site:{target} filetype:xls',
        f'site:{target} filetype:xlsx',
        f'site:{target} filetype:ppt',
        f'site:{target} filetype:pptx',
        f'site:{target} filetype:txt',
        f'site:{target} filetype:log',
        f'site:{target} filetype:sql',
        f'site:{target} filetype:bak',
        f'site:{target} filetype:old',
        f'site:{target} filetype:backup',
        
        # Directory listing
        f'site:{target} intitle:"index of"',
        f'site:{target} intitle:"directory listing"',
        f'site:{target} inurl:admin',
        f'site:{target} inurl:login',
        f'site:{target} inurl:config',
        f'site:{target} inurl:backup',
        f'site:{target} inurl:db',
        f'site:{target} inurl:database',
        f'site:{target} inurl:test',
        f'site:{target} inurl:dev',
        f'site:{target} inurl:staging',
        
        # Configuration files
        f'site:{target} inurl:wp-config.php',
        f'site:{target} inurl:config.php',
        f'site:{target} inurl:configuration.php',
        f'site:{target} inurl:web.config',
        f'site:{target} inurl:.env',
        f'site:{target} inurl:config.ini',
        f'site:{target} inurl:config.json',
        f'site:{target} inurl:config.yml',
        f'site:{target} inurl:config.yaml',
        
        # API and endpoints
        f'site:{target} inurl:api',
        f'site:{target} inurl:rest',
        f'site:{target} inurl:graphql',
        f'site:{target} inurl:swagger',
        f'site:{target} inurl:docs',
        f'site:{target} inurl:documentation',
        
        # Error messages and debug info
        f'site:{target} "error"',
        f'site:{target} "debug"',
        f'site:{target} "stack trace"',
        f'site:{target} "exception"',
        f'site:{target} "warning"',
        f'site:{target} "notice"',
        f'site:{target} "undefined"',
        f'site:{target} "null"',
        
        # Sensitive information
        f'site:{target} "password"',
        f'site:{target} "username"',
        f'site:{target} "email"',
        f'site:{target} "phone"',
        f'site:{target} "address"',
        f'site:{target} "credit card"',
        f'site:{target} "ssn"',
        f'site:{target} "social security"',
        
        # Technology stack
        f'site:{target} "powered by"',
        f'site:{target} "built with"',
        f'site:{target} "framework"',
        f'site:{target} "version"',
        f'site:{target} "server"',
        f'site:{target} "database"',
        
        # Cloud and infrastructure
        f'site:{target} "aws"',
        f'site:{target} "azure"',
        f'site:{target} "gcp"',
        f'site:{target} "cloud"',
        f'site:{target} "docker"',
        f'site:{target} "kubernetes"',
        f'site:{target} "jenkins"',
        f'site:{target} "gitlab"',
        f'site:{target} "github"',
        
        # Security and monitoring
        f'site:{target} "security"',
        f'site:{target} "vulnerability"',
        f'site:{target} "penetration test"',
        f'site:{target} "audit"',
        f'site:{target} "compliance"',
        f'site:{target} "certificate"',
        f'site:{target} "ssl"',
        f'site:{target} "tls"'
    ]
    
    return queries

def search_google_dorks(target: str, queries: List[str]) -> List[Dict]:
    """
    Search Google using dork queries (requires API key).
    """
    results = []
    
    # Check for Google Custom Search API credentials
    google_api_key = os.getenv("GOOGLE_API_KEY")
    google_cse_id = os.getenv("GOOGLE_CSE_ID")
    
    if not google_api_key or not google_cse_id:
        print("[Google] API credentials not found. Skipping Google search.")
        return results
    
    try:
        for query in queries[:10]:  # Limit to first 10 queries to avoid rate limiting
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": google_api_key,
                "cx": google_cse_id,
                "q": query,
                "num": 10  # Maximum results per query
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("items", []):
                    result = {
                        "search_query": query,
                        "result_type": "google_search",
                        "url": item.get("link", ""),
                        "title": item.get("title", ""),
                        "snippet": item.get("snippet", ""),
                        "file_type": extract_file_type(item.get("link", "")),
                        "file_size": None,
                        "source": "google"
                    }
                    results.append(result)
                    
            elif response.status_code == 429:
                print("[Google] Rate limit exceeded. Stopping Google search.")
                break
            else:
                print(f"[Google] Search failed with status {response.status_code}")
            
            # Add delay to avoid rate limiting
            time.sleep(1)
            
    except requests.RequestException as e:
        print(f"[Google] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Google] JSON decode error: {e}")
    except Exception as e:
        print(f"[Google] Unexpected error: {e}")
    
    return results

def search_bing_dorks(target: str, queries: List[str]) -> List[Dict]:
    """
    Search Bing using dork queries (requires API key).
    """
    results = []
    
    # Check for Bing Search API key
    bing_api_key = os.getenv("BING_API_KEY")
    
    if not bing_api_key:
        print("[Bing] API key not found. Skipping Bing search.")
        return results
    
    try:
        for query in queries[:10]:  # Limit to first 10 queries
            url = "https://api.bing.microsoft.com/v7.0/search"
            headers = {
                "Ocp-Apim-Subscription-Key": bing_api_key
            }
            params = {
                "q": query,
                "count": 10
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("webPages", {}).get("value", []):
                    result = {
                        "search_query": query,
                        "result_type": "bing_search",
                        "url": item.get("url", ""),
                        "title": item.get("name", ""),
                        "snippet": item.get("snippet", ""),
                        "file_type": extract_file_type(item.get("url", "")),
                        "file_size": None,
                        "source": "bing"
                    }
                    results.append(result)
                    
            elif response.status_code == 429:
                print("[Bing] Rate limit exceeded. Stopping Bing search.")
                break
            else:
                print(f"[Bing] Search failed with status {response.status_code}")
            
            # Add delay to avoid rate limiting
            time.sleep(1)
            
    except requests.RequestException as e:
        print(f"[Bing] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[Bing] JSON decode error: {e}")
    except Exception as e:
        print(f"[Bing] Unexpected error: {e}")
    
    return results

def search_file_types(target: str) -> List[Dict]:
    """
    Search for specific file types that might contain sensitive information.
    """
    results = []
    
    file_types = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "txt", "log", "sql", "bak", "old", "backup",
        "zip", "rar", "tar", "gz", "7z",
        "xml", "json", "yaml", "yml", "ini", "conf",
        "php", "asp", "aspx", "jsp", "py", "rb", "pl"
    ]
    
    for file_type in file_types:
        query = f'site:{target} filetype:{file_type}'
        
        # This is a placeholder for file type search
        # In a real implementation, you'd use search APIs
        
        result = {
            "search_query": query,
            "result_type": "file_type_search",
            "url": "",
            "title": f"Files with extension .{file_type}",
            "snippet": f"Search for {file_type} files on {target}",
            "file_type": file_type,
            "file_size": None,
            "source": "file_type_search"
        }
        results.append(result)
    
    return results

def search_error_messages(target: str) -> List[Dict]:
    """
    Search for error messages and debug information.
    """
    results = []
    
    error_patterns = [
        "error", "debug", "stack trace", "exception", "warning",
        "notice", "undefined", "null", "fatal", "critical",
        "500 error", "404 error", "403 error", "401 error",
        "database error", "connection error", "timeout error"
    ]
    
    for pattern in error_patterns:
        query = f'site:{target} "{pattern}"'
        
        # This is a placeholder for error message search
        # In a real implementation, you'd use search APIs
        
        result = {
            "search_query": query,
            "result_type": "error_message_search",
            "url": "",
            "title": f"Error messages containing '{pattern}'",
            "snippet": f"Search for {pattern} messages on {target}",
            "file_type": None,
            "file_size": None,
            "source": "error_search"
        }
        results.append(result)
    
    return results

def extract_file_type(url: str) -> Optional[str]:
    """
    Extract file type from URL.
    """
    if not url:
        return None
    
    # Extract file extension from URL
    match = re.search(r'\.([a-zA-Z0-9]+)(?:[?#]|$)', url)
    if match:
        return match.group(1).lower()
    
    return None

def run_advanced_dorking(target: str, output_dir: str) -> Dict:
    """
    Run advanced dorking techniques including boolean operators and advanced filters.
    """
    output_file = os.path.join(output_dir, f"advanced_dorking_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        advanced_data = {
            "tool": "advanced_dorking",
            "target": target,
            "raw_output_path": output_file,
            "search_dork_results": [],
            "total_results": 0,
            "note": "Advanced dorking requires specialized search APIs or web scraping"
        }
        
        # Advanced dork queries with boolean operators
        advanced_queries = [
            f'site:{target} AND (password OR secret OR key)',
            f'site:{target} AND (admin OR login OR dashboard)',
            f'site:{target} AND (error OR debug OR exception)',
            f'site:{target} AND (config OR backup OR database)',
            f'site:{target} AND (api OR rest OR graphql)',
            f'site:{target} AND (aws OR azure OR gcp)',
            f'site:{target} AND (docker OR kubernetes OR jenkins)',
            f'site:{target} AND (vulnerability OR security OR audit)'
        ]
        
        # This is a placeholder for advanced dorking
        # In a real implementation, you'd use specialized search APIs
        
        for query in advanced_queries:
            result = {
                "search_query": query,
                "result_type": "advanced_dork",
                "url": "",
                "title": f"Advanced search: {query}",
                "snippet": f"Advanced dork query for {target}",
                "file_type": None,
                "file_size": None,
                "source": "advanced_dorking"
            }
            advanced_data["search_dork_results"].append(result)
        
        advanced_data["total_results"] = len(advanced_data["search_dork_results"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(advanced_data, f, indent=2, default=str)
        
        return advanced_data
        
    except Exception as e:
        print(f"[Advanced Dorking] Error: {e}")
        return {
            "tool": "advanced_dorking",
            "target": target,
            "error": str(e),
            "search_dork_results": [],
            "total_results": 0
        }