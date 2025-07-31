import os
import requests
import json
import re
import base64
from typing import Dict, List, Optional
from datetime import datetime

def run_repository_mining(target: str, output_dir: str) -> Dict:
    """
    Search public repositories (GitHub, GitLab, etc.) for sensitive information related to the target.
    """
    output_file = os.path.join(output_dir, f"repository_mining_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        repo_data = {
            "tool": "repository_mining",
            "target": target,
            "raw_output_path": output_file,
            "repository_findings": [],
            "total_findings": 0
        }
        
        # Search GitHub repositories
        github_results = search_github_repositories(target)
        repo_data["repository_findings"].extend(github_results)
        
        # Search GitLab repositories (if API key available)
        gitlab_results = search_gitlab_repositories(target)
        repo_data["repository_findings"].extend(gitlab_results)
        
        # Search for secrets and sensitive data
        secrets_results = search_for_secrets(target)
        repo_data["repository_findings"].extend(secrets_results)
        
        repo_data["total_findings"] = len(repo_data["repository_findings"])
        
        # Save raw output
        with open(output_file, "w") as f:
            json.dump(repo_data, f, indent=2, default=str)
        
        return repo_data
        
    except Exception as e:
        print(f"[Repository Mining] Error: {e}")
        return {
            "tool": "repository_mining",
            "target": target,
            "error": str(e),
            "repository_findings": [],
            "total_findings": 0
        }

def search_github_repositories(target: str) -> List[Dict]:
    """
    Search GitHub repositories for the target domain.
    """
    findings = []
    
    # Check for GitHub API token
    github_token = os.getenv("GITHUB_TOKEN")
    
    headers = {}
    if github_token:
        headers["Authorization"] = f"token {github_token}"
    
    try:
        # Search for repositories containing the target domain
        search_queries = [
            f'"{target}"',
            f'"{target}" filename:config',
            f'"{target}" filename:env',
            f'"{target}" filename:docker',
            f'"{target}" filename:yml',
            f'"{target}" filename:yaml',
            f'"{target}" filename:json',
            f'"{target}" filename:xml'
        ]
        
        for query in search_queries:
            url = "https://api.github.com/search/code"
            params = {
                "q": query,
                "per_page": 30  # Limit results to avoid rate limiting
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for item in data.get("items", []):
                    finding = {
                        "platform": "github",
                        "repository_url": item.get("repository", {}).get("html_url", ""),
                        "file_path": item.get("path", ""),
                        "finding_type": "domain_reference",
                        "content": item.get("name", ""),  # File name
                        "line_number": None,
                        "commit_hash": item.get("sha", ""),
                        "severity": "medium",
                        "source": "github_search"
                    }
                    findings.append(finding)
            elif response.status_code == 403:
                print("[GitHub] Rate limit exceeded or API token required")
                break
            else:
                print(f"[GitHub] Search failed with status {response.status_code}")
                
    except requests.RequestException as e:
        print(f"[GitHub] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[GitHub] JSON decode error: {e}")
    except Exception as e:
        print(f"[GitHub] Unexpected error: {e}")
    
    return findings

def search_gitlab_repositories(target: str) -> List[Dict]:
    """
    Search GitLab repositories for the target domain (requires API key).
    """
    findings = []
    
    # Check for GitLab API token
    gitlab_token = os.getenv("GITLAB_TOKEN")
    gitlab_url = os.getenv("GITLAB_URL", "https://gitlab.com")
    
    if not gitlab_token:
        print("[GitLab] API token not found. Skipping GitLab search.")
        return findings
    
    try:
        # Search GitLab projects
        url = f"{gitlab_url}/api/v4/search"
        headers = {
            "PRIVATE-TOKEN": gitlab_token
        }
        params = {
            "scope": "blobs",
            "search": target,
            "per_page": 30
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            for item in data:
                finding = {
                    "platform": "gitlab",
                    "repository_url": item.get("project", {}).get("web_url", ""),
                    "file_path": item.get("path", ""),
                    "finding_type": "domain_reference",
                    "content": item.get("filename", ""),
                    "line_number": None,
                    "commit_hash": item.get("commit", {}).get("id", ""),
                    "severity": "medium",
                    "source": "gitlab_search"
                }
                findings.append(finding)
        else:
            print(f"[GitLab] Search failed with status {response.status_code}")
            
    except requests.RequestException as e:
        print(f"[GitLab] Request error: {e}")
    except json.JSONDecodeError as e:
        print(f"[GitLab] JSON decode error: {e}")
    except Exception as e:
        print(f"[GitLab] Unexpected error: {e}")
    
    return findings

def search_for_secrets(target: str) -> List[Dict]:
    """
    Search for common secrets and sensitive data patterns.
    """
    findings = []
    
    # Common secret patterns
    secret_patterns = [
        (r'api[_-]?key["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})', "api_key"),
        (r'secret["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})', "secret"),
        (r'password["\s]*[:=]["\s]*([a-zA-Z0-9@#$%^&*]{8,})', "password"),
        (r'token["\s]*[:=]["\s]*([a-zA-Z0-9]{20,})', "token"),
        (r'aws_access_key_id["\s]*[:=]["\s]*([A-Z0-9]{20})', "aws_access_key"),
        (r'aws_secret_access_key["\s]*[:=]["\s]*([A-Za-z0-9/+=]{40})', "aws_secret_key"),
        (r'private_key["\s]*[:=]["\s]*-----BEGIN', "private_key"),
        (r'-----BEGIN RSA PRIVATE KEY-----', "rsa_private_key"),
        (r'-----BEGIN DSA PRIVATE KEY-----', "dsa_private_key"),
        (r'-----BEGIN EC PRIVATE KEY-----', "ec_private_key"),
        (r'-----BEGIN OPENSSH PRIVATE KEY-----', "openssh_private_key")
    ]
    
    # Search GitHub for secrets (if token available)
    github_token = os.getenv("GITHUB_TOKEN")
    
    if github_token:
        headers = {"Authorization": f"token {github_token}"}
        
        for pattern, secret_type in secret_patterns:
            try:
                url = "https://api.github.com/search/code"
                params = {
                    "q": f'"{pattern}"',
                    "per_page": 20
                }
                
                response = requests.get(url, headers=headers, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for item in data.get("items", []):
                        # Check if the repository is related to the target
                        repo_name = item.get("repository", {}).get("full_name", "").lower()
                        if target.lower() in repo_name:
                            finding = {
                                "platform": "github",
                                "repository_url": item.get("repository", {}).get("html_url", ""),
                                "file_path": item.get("path", ""),
                                "finding_type": f"secret_{secret_type}",
                                "content": f"Potential {secret_type} found",
                                "line_number": None,
                                "commit_hash": item.get("sha", ""),
                                "severity": "high",
                                "source": "github_secret_search"
                            }
                            findings.append(finding)
                            
            except Exception as e:
                print(f"[Secret Search] Error searching for {secret_type}: {e}")
    
    return findings

def run_trufflehog_scan(target: str, output_dir: str) -> Dict:
    """
    Run TruffleHog to scan for secrets in repositories.
    """
    output_file = os.path.join(output_dir, f"trufflehog_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # This is a placeholder for TruffleHog integration
        # In a real implementation, you'd run TruffleHog as a subprocess
        
        trufflehog_data = {
            "tool": "trufflehog",
            "target": target,
            "raw_output_path": output_file,
            "repository_findings": [],
            "total_findings": 0,
            "note": "TruffleHog integration requires subprocess execution"
        }
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(trufflehog_data, f, indent=2, default=str)
        
        return trufflehog_data
        
    except Exception as e:
        print(f"[TruffleHog] Error: {e}")
        return {
            "tool": "trufflehog",
            "target": target,
            "error": str(e),
            "repository_findings": [],
            "total_findings": 0
        }

def search_pastebin_sites(target: str, output_dir: str) -> Dict:
    """
    Search Pastebin and similar sites for the target domain.
    """
    output_file = os.path.join(output_dir, f"pastebin_search_{target}.json")
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        pastebin_data = {
            "tool": "pastebin_search",
            "target": target,
            "raw_output_path": output_file,
            "repository_findings": [],
            "total_findings": 0,
            "note": "Pastebin search requires specialized APIs or web scraping"
        }
        
        # This is a placeholder for Pastebin search functionality
        # In a real implementation, you'd use APIs like Pastebin API or web scraping
        
        # Save placeholder output
        with open(output_file, "w") as f:
            json.dump(pastebin_data, f, indent=2, default=str)
        
        return pastebin_data
        
    except Exception as e:
        print(f"[Pastebin Search] Error: {e}")
        return {
            "tool": "pastebin_search",
            "target": target,
            "error": str(e),
            "repository_findings": [],
            "total_findings": 0
        }