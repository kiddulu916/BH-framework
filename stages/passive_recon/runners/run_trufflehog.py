#!/usr/bin/env python3
"""
TruffleHog runner for GitHub recon to find secrets in repositories.
"""

import os
import json
import subprocess
import re
from typing import List, Dict, Any

def run_trufflehog(target: str, output_dir: str) -> Dict[str, Any]:
    """
    Run TruffleHog to scan for secrets in GitHub repositories related to the target.
    
    Args:
        target: Target domain to search for
        output_dir: Directory to save output files
        
    Returns:
        Dictionary containing scan results
    """
    print(f"[INFO] Running TruffleHog scan for {target}...")
    
    # Create output file path
    output_file = os.path.join(output_dir, f"trufflehog_{target}.json")
    
    try:
        # Search for repositories containing the target domain
        # TruffleHog can scan GitHub repositories for secrets
        # We'll search for repositories that might contain the target domain
        
        # First, try to find GitHub repositories related to the target
        search_terms = [
            target,
            target.replace(".", ""),  # Remove dots for broader search
            target.split(".")[0]  # Just the main domain part
        ]
        
        all_secrets = []
        all_repos = []
        
        for search_term in search_terms:
            try:
                # Use TruffleHog to scan GitHub for secrets
                # Note: This is a simplified approach - in production you'd want more sophisticated GitHub API usage
                cmd = [
                    "trufflehog",
                    "--json",
                    "--only-verified",
                    "--no-update",
                    "https://github.com/search?q=" + search_term
                ]
                
                print(f"[INFO] Running: {' '.join(cmd)}")
                
                # Run TruffleHog
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5 minute timeout
                )
                
                if result.returncode == 0 and result.stdout:
                    # Parse JSON output
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            try:
                                secret_data = json.loads(line)
                                secret_data['search_term'] = search_term
                                all_secrets.append(secret_data)
                            except json.JSONDecodeError:
                                continue
                
                # Also try to find repositories using GitHub search
                # This is a simplified approach - in production you'd use GitHub API
                github_search_cmd = [
                    "curl", "-s",
                    f"https://api.github.com/search/repositories?q={search_term}&sort=stars&order=desc&per_page=10"
                ]
                
                github_result = subprocess.run(
                    github_search_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if github_result.returncode == 0 and github_result.stdout:
                    try:
                        github_data = json.loads(github_result.stdout)
                        if 'items' in github_data:
                            for repo in github_data['items']:
                                repo_info = {
                                    'name': repo.get('full_name', ''),
                                    'description': repo.get('description', ''),
                                    'url': repo.get('html_url', ''),
                                    'stars': repo.get('stargazers_count', 0),
                                    'search_term': search_term
                                }
                                all_repos.append(repo_info)
                    except json.JSONDecodeError:
                        pass
                        
            except subprocess.TimeoutExpired:
                print(f"[WARNING] TruffleHog scan for '{search_term}' timed out")
            except Exception as e:
                print(f"[WARNING] Error scanning for '{search_term}': {e}")
        
        # Create results structure
        results = {
            "target": target,
            "secrets_found": len(all_secrets),
            "repositories_found": len(all_repos),
            "secrets": all_secrets,
            "repositories": all_repos,
            "search_terms_used": search_terms,
            "scan_summary": {
                "total_secrets": len(all_secrets),
                "total_repos": len(all_repos),
                "high_confidence_secrets": len([s for s in all_secrets if s.get('verified', False)]),
                "potential_targets": list(set([s.get('path', '').split('/')[0] for s in all_secrets if s.get('path')]))
            }
        }
        
        # Save results to file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[INFO] TruffleHog scan completed successfully")
        print(f"[INFO] Found {len(all_secrets)} secrets and {len(all_repos)} repositories")
        
        return results
        
    except Exception as e:
        print(f"[ERROR] TruffleHog scan failed: {e}")
        # Return empty results structure
        return {
            "target": target,
            "secrets_found": 0,
            "repositories_found": 0,
            "secrets": [],
            "repositories": [],
            "search_terms_used": search_terms,
            "scan_summary": {
                "total_secrets": 0,
                "total_repos": 0,
                "high_confidence_secrets": 0,
                "potential_targets": []
            },
            "error": str(e)
        }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python run_trufflehog.py <target> <output_dir>")
        sys.exit(1)
    
    target = sys.argv[1]
    output_dir = sys.argv[2]
    
    results = run_trufflehog(target, output_dir)
    print(json.dumps(results, indent=2)) 