#!/usr/bin/env python3
"""
Misconfiguration Detection Runner

This module provides comprehensive misconfiguration detection capabilities for
identifying common security issues and exposed resources.

Features:
- Exposed configuration files and secrets detection
- Default credentials testing
- Open directory listings detection
- Unnecessary services and pages detection
- Security headers analysis
- TLS configuration analysis
"""

import os
import json
import subprocess
import requests
import time
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def detect_exposed_files(target: str) -> Dict[str, Any]:
    """
    Detect exposed configuration files and sensitive resources.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing exposed file detection results
    """
    try:
        print(f"[INFO] Detecting exposed files for {target}")
        
        # Common sensitive files to check
        sensitive_files = [
            # Configuration files
            "/.env", "/config.php", "/config.json", "/config.xml", "/web.config",
            "/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
            "/package.json", "/composer.json", "/requirements.txt",
            
            # Backup files
            "/backup/", "/backups/", "/bak/", "/old/", "/archive/",
            "/.git/", "/.svn/", "/.hg/", "/.bzr/",
            
            # Database files
            "/db.sql", "/database.sql", "/dump.sql", "/backup.sql",
            "/data.sql", "/users.sql", "/admin.sql",
            
            # Log files
            "/logs/", "/log/", "/error.log", "/access.log", "/debug.log",
            "/php_error.log", "/apache.log", "/nginx.log",
            
            # Development files
            "/test/", "/dev/", "/staging/", "/beta/", "/alpha/",
            "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
            
            # IDE files
            "/.idea/", "/.vscode/", "/.sublime-project", "/.sublime-workspace",
            
            # Cloud configuration
            "/.aws/", "/.azure/", "/.gcp/", "/cloudformation.yml",
            "/terraform.tfstate", "/docker-compose.yml", "/dockerfile",
            
            # Security files
            "/.ssh/", "/.cert/", "/.pem", "/.key", "/.crt",
            "/ssl/", "/certificates/", "/keys/"
        ]
        
        exposed_files = []
        
        for file_path in sensitive_files:
            for protocol in ["http", "https"]:
                try:
                    url = f"{protocol}://{target}{file_path}"
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    
                    if response.status_code == 200:
                        file_info = {
                            "url": url,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "content_type": response.headers.get("Content-Type", ""),
                            "file_path": file_path,
                            "protocol": protocol
                        }
                        
                        # Check if it's a directory listing
                        if "Index of" in response.text or "Directory listing" in response.text:
                            file_info["type"] = "directory_listing"
                        elif file_path.endswith(('.php', '.asp', '.aspx', '.jsp')):
                            file_info["type"] = "script_file"
                        elif file_path.endswith(('.sql', '.db', '.sqlite')):
                            file_info["type"] = "database_file"
                        elif file_path.endswith(('.log')):
                            file_info["type"] = "log_file"
                        elif file_path.endswith(('.env', '.config', '.conf')):
                            file_info["type"] = "config_file"
                        else:
                            file_info["type"] = "other"
                        
                        exposed_files.append(file_info)
                        break  # Found with one protocol, don't check the other
                        
                except requests.exceptions.RequestException:
                    continue
        
        return {
            "success": True,
            "exposed_files": exposed_files,
            "total_exposed": len(exposed_files),
            "files_checked": len(sensitive_files)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "exposed_files": [],
            "total_exposed": 0
        }

def test_default_credentials(target: str) -> Dict[str, Any]:
    """
    Test for default credentials on common services and applications.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing default credential test results
    """
    try:
        print(f"[INFO] Testing default credentials for {target}")
        
        # Common default credentials to test
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root", "root"),
            ("root", "password"),
            ("user", "user"),
            ("user", "password"),
            ("test", "test"),
            ("guest", "guest"),
            ("demo", "demo"),
            ("administrator", "administrator"),
            ("administrator", "password"),
            ("tomcat", "tomcat"),
            ("manager", "manager"),
            ("admin", ""),
            ("", "admin")
        ]
        
        # Common admin paths to test
        admin_paths = [
            "/admin", "/admin/", "/administrator", "/administrator/",
            "/login", "/login/", "/auth", "/auth/", "/signin", "/signin/",
            "/wp-admin", "/wp-admin/", "/wp-login.php",
            "/drupal/user/login", "/drupal/admin",
            "/joomla/administrator", "/joomla/admin",
            "/phpmyadmin", "/phpmyadmin/", "/mysql", "/mysql/",
            "/cpanel", "/cpanel/", "/whm", "/whm/",
            "/webmin", "/webmin/", "/plesk", "/plesk/",
            "/jenkins", "/jenkins/", "/sonar", "/sonar/",
            "/kibana", "/kibana/", "/grafana", "/grafana/",
            "/prometheus", "/prometheus/", "/consul", "/consul/"
        ]
        
        successful_logins = []
        
        for admin_path in admin_paths:
            for username, password in default_creds:
                for protocol in ["http", "https"]:
                    try:
                        url = f"{protocol}://{target}{admin_path}"
                        
                        # Test with form data
                        login_data = {
                            "username": username,
                            "password": password,
                            "user": username,
                            "pass": password,
                            "email": username,
                            "login": username,
                            "admin": username
                        }
                        
                        response = requests.post(url, data=login_data, timeout=10, allow_redirects=False)
                        
                        # Check for successful login indicators
                        success_indicators = [
                            "dashboard", "admin", "welcome", "logout",
                            "profile", "settings", "management"
                        ]
                        
                        if response.status_code in [200, 302] and any(indicator in response.text.lower() for indicator in success_indicators):
                            successful_logins.append({
                                "url": url,
                                "username": username,
                                "password": password,
                                "status_code": response.status_code,
                                "protocol": protocol,
                                "path": admin_path
                            })
                            break  # Found working credentials for this path
                        
                    except requests.exceptions.RequestException:
                        continue
        
        return {
            "success": True,
            "successful_logins": successful_logins,
            "total_successful": len(successful_logins),
            "credentials_tested": len(default_creds) * len(admin_paths)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "successful_logins": [],
            "total_successful": 0
        }

def detect_directory_listings(target: str) -> Dict[str, Any]:
    """
    Detect open directory listings.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing directory listing detection results
    """
    try:
        print(f"[INFO] Detecting directory listings for {target}")
        
        # Common directories that might have listings enabled
        common_dirs = [
            "/", "/admin/", "/backup/", "/backups/", "/bak/", "/old/",
            "/archive/", "/files/", "/uploads/", "/images/", "/media/",
            "/static/", "/assets/", "/css/", "/js/", "/img/", "/pic/",
            "/photo/", "/photos/", "/video/", "/videos/", "/audio/",
            "/documents/", "/docs/", "/downloads/", "/temp/", "/tmp/",
            "/cache/", "/logs/", "/log/", "/data/", "/db/", "/database/",
            "/config/", "/conf/", "/settings/", "/includes/", "/lib/",
            "/library/", "/modules/", "/plugins/", "/extensions/",
            "/themes/", "/templates/", "/sources/", "/src/", "/bin/",
            "/sbin/", "/usr/", "/var/", "/etc/", "/home/", "/root/"
        ]
        
        directory_listings = []
        
        for directory in common_dirs:
            for protocol in ["http", "https"]:
                try:
                    url = f"{protocol}://{target}{directory}"
                    response = requests.get(url, timeout=10, allow_redirects=False)
                    
                    if response.status_code == 200:
                        # Check for directory listing indicators
                        listing_indicators = [
                            "Index of", "Directory listing", "Directory of",
                            "Parent Directory", "Last modified", "Size",
                            "Name", "Description", "Apache", "nginx",
                            "Directory Listing For", "Contents of"
                        ]
                        
                        if any(indicator in response.text for indicator in listing_indicators):
                            # Extract file list if possible
                            files = []
                            try:
                                # Simple regex to extract file names from directory listing
                                file_pattern = r'<a[^>]*>([^<]+)</a>'
                                file_matches = re.findall(file_pattern, response.text)
                                for match in file_matches:
                                    if match and not match.startswith('..') and not match.startswith('.'):
                                        files.append(match.strip())
                            except:
                                pass
                            
                            directory_listings.append({
                                "url": url,
                                "directory": directory,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "files_found": files[:20],  # Limit to first 20 files
                                "total_files": len(files),
                                "protocol": protocol
                            })
                            break  # Found with one protocol, don't check the other
                        
                except requests.exceptions.RequestException:
                    continue
        
        return {
            "success": True,
            "directory_listings": directory_listings,
            "total_listings": len(directory_listings),
            "directories_checked": len(common_dirs)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "directory_listings": [],
            "total_listings": 0
        }

def detect_unnecessary_services(target: str) -> Dict[str, Any]:
    """
    Detect unnecessary services and pages that shouldn't be exposed.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing unnecessary service detection results
    """
    try:
        print(f"[INFO] Detecting unnecessary services for {target}")
        
        # Services and pages that shouldn't be exposed
        unnecessary_services = {
            "debug_pages": [
                "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
                "/status.php", "/health.php", "/ping.php", "/version.php"
            ],
            "admin_panels": [
                "/admin", "/administrator", "/manage", "/management",
                "/control", "/console", "/panel", "/cpanel", "/whm",
                "/webmin", "/plesk", "/directadmin", "/ispconfig"
            ],
            "monitoring": [
                "/monitoring", "/status", "/health", "/metrics",
                "/prometheus", "/grafana", "/kibana", "/elasticsearch",
                "/logstash", "/zabbix", "/nagios", "/icinga"
            ],
            "development": [
                "/dev", "/development", "/staging", "/test", "/beta",
                "/alpha", "/sandbox", "/demo", "/playground"
            ],
            "database": [
                "/phpmyadmin", "/mysql", "/postgresql", "/mongodb",
                "/redis", "/memcached", "/couchdb", "/elasticsearch"
            ],
            "version_control": [
                "/.git", "/.svn", "/.hg", "/.bzr", "/git", "/svn"
            ]
        }
        
        exposed_services = {}
        
        for service_type, paths in unnecessary_services.items():
            exposed_services[service_type] = []
            
            for path in paths:
                for protocol in ["http", "https"]:
                    try:
                        url = f"{protocol}://{target}{path}"
                        response = requests.get(url, timeout=10, allow_redirects=False)
                        
                        if response.status_code in [200, 301, 302, 401, 403]:
                            service_info = {
                                "url": url,
                                "path": path,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "content_type": response.headers.get("Content-Type", ""),
                                "protocol": protocol
                            }
                            
                            # Add specific detection for certain services
                            if "phpinfo" in path.lower() and "php" in response.text.lower():
                                service_info["type"] = "php_info_exposure"
                            elif "admin" in path.lower() and response.status_code in [200, 401, 403]:
                                service_info["type"] = "admin_panel"
                            elif "git" in path.lower() and response.status_code == 200:
                                service_info["type"] = "version_control"
                            
                            exposed_services[service_type].append(service_info)
                            break  # Found with one protocol, don't check the other
                        
                    except requests.exceptions.RequestException:
                        continue
        
        return {
            "success": True,
            "exposed_services": exposed_services,
            "total_exposed": sum(len(services) for services in exposed_services.values())
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "exposed_services": {},
            "total_exposed": 0
        }

def analyze_security_headers(target: str) -> Dict[str, Any]:
    """
    Analyze security headers for misconfigurations.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing security header analysis results
    """
    try:
        print(f"[INFO] Analyzing security headers for {target}")
        
        security_headers = {
            "Strict-Transport-Security": "HSTS",
            "Content-Security-Policy": "CSP",
            "X-Frame-Options": "Clickjacking Protection",
            "X-Content-Type-Options": "MIME Sniffing Protection",
            "X-XSS-Protection": "XSS Protection",
            "Referrer-Policy": "Referrer Policy",
            "Permissions-Policy": "Permissions Policy",
            "X-Permitted-Cross-Domain-Policies": "Cross-Domain Policy"
        }
        
        headers_found = {}
        missing_headers = []
        
        for protocol in ["http", "https"]:
            try:
                url = f"{protocol}://{target}"
                response = requests.get(url, timeout=10, allow_redirects=False)
                
                for header_name, description in security_headers.items():
                    if header_name in response.headers:
                        headers_found[header_name] = {
                            "value": response.headers[header_name],
                            "description": description,
                            "protocol": protocol
                        }
                    else:
                        missing_headers.append({
                            "header": header_name,
                            "description": description,
                            "protocol": protocol
                        })
                
                break
                
            except requests.exceptions.RequestException:
                continue
        
        return {
            "success": True,
            "headers_found": headers_found,
            "missing_headers": missing_headers,
            "total_found": len(headers_found),
            "total_missing": len(missing_headers)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "headers_found": {},
            "missing_headers": []
        }

def analyze_tls_configuration(target: str) -> Dict[str, Any]:
    """
    Analyze TLS configuration for security issues.
    
    Args:
        target: Target domain
        
    Returns:
        Dictionary containing TLS configuration analysis results
    """
    try:
        print(f"[INFO] Analyzing TLS configuration for {target}")
        
        tls_issues = []
        tls_info = {}
        
        try:
            # Test HTTPS connection
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    tls_info = {
                        "version": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                        "cert_subject": dict(x[0] for x in cert['subject']) if cert else {},
                        "cert_issuer": dict(x[0] for x in cert['issuer']) if cert else {},
                        "cert_expiry": cert['notAfter'] if cert else None
                    }
                    
                    # Check for weak TLS versions
                    if version in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']:
                        tls_issues.append({
                            "issue": "Weak TLS Version",
                            "details": f"Using {version} which is considered insecure",
                            "severity": "high"
                        })
                    
                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                    if any(cipher in cipher[0] for cipher in weak_ciphers):
                        tls_issues.append({
                            "issue": "Weak Cipher",
                            "details": f"Using weak cipher: {cipher[0]}",
                            "severity": "medium"
                        })
                    
        except Exception as e:
            tls_issues.append({
                "issue": "TLS Connection Failed",
                "details": str(e),
                "severity": "info"
            })
        
        return {
            "success": True,
            "tls_info": tls_info,
            "tls_issues": tls_issues,
            "total_issues": len(tls_issues)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "tls_info": {},
            "tls_issues": []
        }

def run_misconfiguration_detection(target: str, raw_output_path: str) -> Dict[str, Any]:
    """
    Run comprehensive misconfiguration detection.
    
    Args:
        target: Target domain
        raw_output_path: Path to save raw output
        
    Returns:
        Dictionary containing comprehensive misconfiguration detection results
    """
    print(f"[INFO] Starting misconfiguration detection for {target}")
    
    start_time = time.time()
    all_results = {}
    
    # Step 1: Exposed files detection
    print(f"[INFO] Detecting exposed files")
    exposed_files_results = detect_exposed_files(target)
    all_results["exposed_files"] = exposed_files_results
    
    # Step 2: Default credentials testing
    print(f"[INFO] Testing default credentials")
    default_creds_results = test_default_credentials(target)
    all_results["default_credentials"] = default_creds_results
    
    # Step 3: Directory listings detection
    print(f"[INFO] Detecting directory listings")
    directory_listings_results = detect_directory_listings(target)
    all_results["directory_listings"] = directory_listings_results
    
    # Step 4: Unnecessary services detection
    print(f"[INFO] Detecting unnecessary services")
    unnecessary_services_results = detect_unnecessary_services(target)
    all_results["unnecessary_services"] = unnecessary_services_results
    
    # Step 5: Security headers analysis
    print(f"[INFO] Analyzing security headers")
    security_headers_results = analyze_security_headers(target)
    all_results["security_headers"] = security_headers_results
    
    # Step 6: TLS configuration analysis
    print(f"[INFO] Analyzing TLS configuration")
    tls_results = analyze_tls_configuration(target)
    all_results["tls_configuration"] = tls_results
    
    # Step 7: Generate summary
    execution_time = time.time() - start_time
    
    summary = {
        "target": target,
        "execution_time": execution_time,
        "exposed_files": exposed_files_results.get("total_exposed", 0),
        "default_credentials": default_creds_results.get("total_successful", 0),
        "directory_listings": directory_listings_results.get("total_listings", 0),
        "unnecessary_services": unnecessary_services_results.get("total_exposed", 0),
        "missing_security_headers": security_headers_results.get("total_missing", 0),
        "tls_issues": tls_results.get("total_issues", 0)
    }
    
    # Save raw output
    raw_output = {
        "target": target,
        "timestamp": time.time(),
        "exposed_files_results": exposed_files_results,
        "default_creds_results": default_creds_results,
        "directory_listings_results": directory_listings_results,
        "unnecessary_services_results": unnecessary_services_results,
        "security_headers_results": security_headers_results,
        "tls_results": tls_results
    }
    
    with open(raw_output_path, 'w') as f:
        json.dump(raw_output, f, indent=2)
    
    return {
        "success": True,
        "summary": summary,
        "results": all_results,
        "files": {
            "raw_output": raw_output_path
        }
    }

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python run_misconfiguration_detection.py <target> <raw_output_path>")
        sys.exit(1)
    
    target = sys.argv[1]
    raw_output_path = sys.argv[2]
    
    results = run_misconfiguration_detection(target, raw_output_path)
    print(json.dumps(results, indent=2)) 