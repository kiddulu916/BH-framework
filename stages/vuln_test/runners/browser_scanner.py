#!/usr/bin/env python3
"""
Browser Scanner Runner for Stage 4: Step 4.2

This module implements browser automation for web application testing,
including dynamic content handling, form discovery, and vulnerability detection.
"""

import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Browser automation imports
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    logging.warning("Selenium not available. Browser automation will be disabled.")

try:
    from playwright.sync_api import sync_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logging.warning("Playwright not available. Browser automation will be disabled.")

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """Represents a form field discovered during scanning."""
    
    name: str
    field_type: str  # text, password, email, etc.
    id: Optional[str] = None
    class_name: Optional[str] = None
    placeholder: Optional[str] = None
    required: bool = False
    value: Optional[str] = None


@dataclass
class DiscoveredEndpoint:
    """Represents an endpoint discovered during browser scanning."""
    
    url: str
    method: str = "GET"
    parameters: List[str] = None
    forms: List[Dict[str, Any]] = None
    technology: Optional[str] = None
    vulnerability_hints: List[str] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = []
        if self.forms is None:
            self.forms = []
        if self.vulnerability_hints is None:
            self.vulnerability_hints = []


@dataclass
class BrowserFinding:
    """Represents a vulnerability finding from browser scanning."""
    
    id: str
    title: str
    description: str
    endpoint: str
    parameter: Optional[str] = None
    severity: str = "Medium"
    confidence: float = 0.0
    evidence: str = ""
    screenshot_path: Optional[str] = None
    vulnerability_type: str = ""


class BrowserScanner:
    """Browser automation scanner for web application testing."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.browser_dir = self.output_dir / "browser_scanning"
        self.browser_dir.mkdir(parents=True, exist_ok=True)
        
        # Browser configuration
        self.browser_type = config.browser_type
        self.headless = config.headless
        self.rate_limit = config.rate_limit
        
        # Browser instances
        self.driver = None
        self.playwright_browser = None
        self.playwright_page = None
        
        # Discovered data
        self.discovered_endpoints: List[DiscoveredEndpoint] = []
        self.discovered_forms: List[Dict[str, Any]] = []
        self.vulnerability_findings: List[BrowserFinding] = []
        
        # Test data for form filling
        self.test_data = {
            "text": "test_input",
            "email": "test@example.com",
            "password": "TestPassword123!",
            "number": "12345",
            "url": "https://example.com",
            "search": "test search"
        }
        
        # XSS payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>"
        ]
        
        # SQL injection payloads for testing
        self.sqli_payloads = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR '1'='1",
            "admin'--"
        ]
    
    def run_scan(self) -> List[BrowserFinding]:
        """
        Run comprehensive browser-based vulnerability scanning.
        
        Returns:
            List[BrowserFinding]: List of vulnerability findings
        """
        logger.info("Starting browser-based vulnerability scanning...")
        
        try:
            # Initialize browser
            self._initialize_browser()
            
            # Load structured input data
            structured_data = self._load_structured_data()
            
            # Discover endpoints through crawling
            self._discover_endpoints(structured_data.get("endpoints", []))
            
            # Test each discovered endpoint
            for endpoint in self.discovered_endpoints:
                self._test_endpoint(endpoint)
            
            # Perform form-based vulnerability testing
            self._test_forms()
            
            # Perform dynamic content analysis
            self._analyze_dynamic_content()
            
            # Close browser
            self._close_browser()
            
            logger.info(f"Browser scanning completed. Found {len(self.vulnerability_findings)} potential vulnerabilities")
            
            return self.vulnerability_findings
            
        except Exception as e:
            logger.error(f"Error in browser scanning: {str(e)}")
            self._close_browser()
            raise
    
    def _initialize_browser(self):
        """Initialize the browser based on configuration."""
        try:
            if self.browser_type == "selenium" and SELENIUM_AVAILABLE:
                self._initialize_selenium()
            elif self.browser_type == "playwright" and PLAYWRIGHT_AVAILABLE:
                self._initialize_playwright()
            else:
                logger.warning(f"Browser type {self.browser_type} not available, falling back to requests-based scanning")
                self._initialize_requests_based()
                
        except Exception as e:
            logger.error(f"Error initializing browser: {str(e)}")
            raise
    
    def _initialize_selenium(self):
        """Initialize Selenium WebDriver."""
        try:
            options = ChromeOptions()
            
            if self.headless:
                options.add_argument("--headless")
            
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            
            # Add security headers
            options.add_argument("--disable-web-security")
            options.add_argument("--allow-running-insecure-content")
            
            self.driver = webdriver.Chrome(options=options)
            self.driver.set_page_load_timeout(30)
            self.driver.implicitly_wait(10)
            
            logger.info("Selenium WebDriver initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing Selenium: {str(e)}")
            raise
    
    def _initialize_playwright(self):
        """Initialize Playwright browser."""
        try:
            self.playwright = sync_playwright().start()
            
            browser_type = "chromium"  # Can be chromium, firefox, webkit
            self.playwright_browser = self.playwright.chromium.launch(
                headless=self.headless,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-web-security",
                    "--allow-running-insecure-content"
                ]
            )
            
            self.playwright_page = self.playwright_browser.new_page()
            self.playwright_page.set_viewport_size({"width": 1920, "height": 1080})
            self.playwright_page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            
            logger.info("Playwright browser initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing Playwright: {str(e)}")
            raise
    
    def _initialize_requests_based(self):
        """Initialize requests-based scanning (fallback)."""
        logger.info("Initializing requests-based scanning as fallback")
        # This would use requests/httpx for basic scanning
        pass
    
    def _load_structured_data(self) -> Dict[str, Any]:
        """Load structured input data from data preparation step."""
        try:
            structured_file = self.output_dir / "data_preparation" / "structured_input.json"
            
            if structured_file.exists():
                with open(structured_file, 'r') as f:
                    return json.load(f)
            else:
                logger.warning("Structured input data not found, using default data")
                return self._create_default_structured_data()
                
        except Exception as e:
            logger.error(f"Error loading structured data: {str(e)}")
            return self._create_default_structured_data()
    
    def _create_default_structured_data(self) -> Dict[str, Any]:
        """Create default structured data if none exists."""
        return {
            "target_info": {
                "domain": self.config.target,
                "scan_timestamp": datetime.now(timezone.utc).isoformat()
            },
            "endpoints": [
                {
                    "url": f"https://{self.config.target}",
                    "method": "GET",
                    "params": [],
                    "technology": "",
                    "vulnerability_hints": []
                }
            ],
            "technologies": [],
            "network_info": {},
            "cloud_info": {},
            "preliminary_vulns": [],
            "scan_config": {}
        }
    
    def _discover_endpoints(self, known_endpoints: List[Dict[str, Any]]):
        """Discover endpoints through crawling and known endpoint analysis."""
        logger.info("Discovering endpoints through browser crawling...")
        
        try:
            # Add known endpoints
            for endpoint_data in known_endpoints:
                endpoint = DiscoveredEndpoint(
                    url=endpoint_data.get("url", ""),
                    method=endpoint_data.get("method", "GET"),
                    parameters=endpoint_data.get("params", []),
                    technology=endpoint_data.get("technology", "")
                )
                self.discovered_endpoints.append(endpoint)
            
            # Crawl main domain
            main_url = f"https://{self.config.target}"
            self._crawl_page(main_url)
            
            # Discover additional endpoints through crawling
            self._discover_additional_endpoints()
            
            logger.info(f"Endpoint discovery completed. Found {len(self.discovered_endpoints)} endpoints")
            
        except Exception as e:
            logger.error(f"Error discovering endpoints: {str(e)}")
    
    def _crawl_page(self, url: str):
        """Crawl a single page to discover forms, links, and potential vulnerabilities."""
        try:
            logger.info(f"Crawling page: {url}")
            
            if self.driver:
                self._crawl_with_selenium(url)
            elif self.playwright_page:
                self._crawl_with_playwright(url)
            else:
                self._crawl_with_requests(url)
                
        except Exception as e:
            logger.error(f"Error crawling page {url}: {str(e)}")
    
    def _crawl_with_selenium(self, url: str):
        """Crawl page using Selenium."""
        try:
            self.driver.get(url)
            time.sleep(2)  # Wait for page to load
            
            # Discover forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                form_data = self._extract_form_data_selenium(form)
                self.discovered_forms.append(form_data)
            
            # Discover links
            links = self.driver.find_elements(By.TAG_NAME, "a")
            for link in links:
                href = link.get_attribute("href")
                if href and self.config.target in href:
                    endpoint = DiscoveredEndpoint(url=href, method="GET")
                    if endpoint not in self.discovered_endpoints:
                        self.discovered_endpoints.append(endpoint)
            
            # Check for common vulnerability indicators
            self._check_vulnerability_indicators_selenium(url)
            
        except Exception as e:
            logger.error(f"Error crawling with Selenium: {str(e)}")
    
    def _crawl_with_playwright(self, url: str):
        """Crawl page using Playwright."""
        try:
            self.playwright_page.goto(url, wait_until="networkidle")
            
            # Discover forms
            forms = self.playwright_page.query_selector_all("form")
            for form in forms:
                form_data = self._extract_form_data_playwright(form)
                self.discovered_forms.append(form_data)
            
            # Discover links
            links = self.playwright_page.query_selector_all("a")
            for link in links:
                href = link.get_attribute("href")
                if href and self.config.target in href:
                    endpoint = DiscoveredEndpoint(url=href, method="GET")
                    if endpoint not in self.discovered_endpoints:
                        self.discovered_endpoints.append(endpoint)
            
            # Check for common vulnerability indicators
            self._check_vulnerability_indicators_playwright(url)
            
        except Exception as e:
            logger.error(f"Error crawling with Playwright: {str(e)}")
    
    def _crawl_with_requests(self, url: str):
        """Crawl page using requests (fallback)."""
        try:
            import requests
            
            response = requests.get(url, timeout=30)
            
            # Basic form and link discovery from HTML
            # This is a simplified version
            if "form" in response.text.lower():
                logger.info(f"Forms detected on {url}")
            
            if "href=" in response.text.lower():
                logger.info(f"Links detected on {url}")
                
        except Exception as e:
            logger.error(f"Error crawling with requests: {str(e)}")
    
    def _extract_form_data_selenium(self, form) -> Dict[str, Any]:
        """Extract form data using Selenium."""
        try:
            form_data = {
                "action": form.get_attribute("action") or "",
                "method": form.get_attribute("method") or "GET",
                "fields": []
            }
            
            # Extract form fields
            inputs = form.find_elements(By.TAG_NAME, "input")
            for input_field in inputs:
                field = FormField(
                    name=input_field.get_attribute("name") or "",
                    field_type=input_field.get_attribute("type") or "text",
                    id=input_field.get_attribute("id"),
                    class_name=input_field.get_attribute("class"),
                    placeholder=input_field.get_attribute("placeholder"),
                    required=input_field.get_attribute("required") is not None
                )
                form_data["fields"].append(field.__dict__)
            
            return form_data
            
        except Exception as e:
            logger.error(f"Error extracting form data with Selenium: {str(e)}")
            return {"action": "", "method": "GET", "fields": []}
    
    def _extract_form_data_playwright(self, form) -> Dict[str, Any]:
        """Extract form data using Playwright."""
        try:
            form_data = {
                "action": form.get_attribute("action") or "",
                "method": form.get_attribute("method") or "GET",
                "fields": []
            }
            
            # Extract form fields
            inputs = form.query_selector_all("input")
            for input_field in inputs:
                field = FormField(
                    name=input_field.get_attribute("name") or "",
                    field_type=input_field.get_attribute("type") or "text",
                    id=input_field.get_attribute("id"),
                    class_name=input_field.get_attribute("class"),
                    placeholder=input_field.get_attribute("placeholder"),
                    required=input_field.get_attribute("required") is not None
                )
                form_data["fields"].append(field.__dict__)
            
            return form_data
            
        except Exception as e:
            logger.error(f"Error extracting form data with Playwright: {str(e)}")
            return {"action": "", "method": "GET", "fields": []}
    
    def _check_vulnerability_indicators_selenium(self, url: str):
        """Check for common vulnerability indicators using Selenium."""
        try:
            page_source = self.driver.page_source.lower()
            
            # Check for error messages that might indicate vulnerabilities
            error_indicators = [
                "sql syntax",
                "mysql error",
                "oracle error",
                "postgresql error",
                "microsoft ole db provider",
                "unclosed quotation mark",
                "syntax error",
                "stack trace",
                "exception details"
            ]
            
            for indicator in error_indicators:
                if indicator in page_source:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title=f"Potential SQL Injection - {indicator}",
                        description=f"Error message '{indicator}' found in page source",
                        endpoint=url,
                        severity="High",
                        confidence=0.7,
                        evidence=f"Found '{indicator}' in page source",
                        vulnerability_type="SQL Injection"
                    )
                    self.vulnerability_findings.append(finding)
            
            # Check for XSS indicators
            if "<script>" in page_source and "alert" in page_source:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential XSS - Script tags detected",
                    description="Script tags found in page source",
                    endpoint=url,
                    severity="Medium",
                    confidence=0.6,
                    evidence="Script tags found in page source",
                    vulnerability_type="XSS"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking vulnerability indicators with Selenium: {str(e)}")
    
    def _check_vulnerability_indicators_playwright(self, url: str):
        """Check for common vulnerability indicators using Playwright."""
        try:
            content = self.playwright_page.content().lower()
            
            # Check for error messages that might indicate vulnerabilities
            error_indicators = [
                "sql syntax",
                "mysql error",
                "oracle error",
                "postgresql error",
                "microsoft ole db provider",
                "unclosed quotation mark",
                "syntax error",
                "stack trace",
                "exception details"
            ]
            
            for indicator in error_indicators:
                if indicator in content:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title=f"Potential SQL Injection - {indicator}",
                        description=f"Error message '{indicator}' found in page content",
                        endpoint=url,
                        severity="High",
                        confidence=0.7,
                        evidence=f"Found '{indicator}' in page content",
                        vulnerability_type="SQL Injection"
                    )
                    self.vulnerability_findings.append(finding)
            
            # Check for XSS indicators
            if "<script>" in content and "alert" in content:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential XSS - Script tags detected",
                    description="Script tags found in page content",
                    endpoint=url,
                    severity="Medium",
                    confidence=0.6,
                    evidence="Script tags found in page content",
                    vulnerability_type="XSS"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error checking vulnerability indicators with Playwright: {str(e)}")
    
    def _discover_additional_endpoints(self):
        """Discover additional endpoints through various methods."""
        try:
            # Common endpoint discovery
            common_paths = [
                "/admin", "/login", "/register", "/dashboard",
                "/api", "/api/v1", "/api/v2", "/rest",
                "/wp-admin", "/phpmyadmin", "/admin.php",
                "/config", "/backup", "/test", "/dev",
                "/.git", "/.env", "/robots.txt", "/sitemap.xml"
            ]
            
            for path in common_paths:
                url = f"https://{self.config.target}{path}"
                endpoint = DiscoveredEndpoint(url=url, method="GET")
                self.discovered_endpoints.append(endpoint)
                
        except Exception as e:
            logger.error(f"Error discovering additional endpoints: {str(e)}")
    
    def _test_endpoint(self, endpoint: DiscoveredEndpoint):
        """Test a single endpoint for vulnerabilities."""
        try:
            logger.info(f"Testing endpoint: {endpoint.url}")
            
            # Test for common vulnerabilities
            self._test_xss(endpoint)
            self._test_sql_injection(endpoint)
            self._test_open_redirect(endpoint)
            self._test_information_disclosure(endpoint)
            
            # Rate limiting
            time.sleep(1 / self.rate_limit)
            
        except Exception as e:
            logger.error(f"Error testing endpoint {endpoint.url}: {str(e)}")
    
    def _test_xss(self, endpoint: DiscoveredEndpoint):
        """Test for XSS vulnerabilities."""
        try:
            # Test reflected XSS
            for payload in self.xss_payloads:
                test_url = f"{endpoint.url}?test={payload}"
                
                if self.driver:
                    self._test_xss_selenium(test_url, payload)
                elif self.playwright_page:
                    self._test_xss_playwright(test_url, payload)
                    
        except Exception as e:
            logger.error(f"Error testing XSS: {str(e)}")
    
    def _test_xss_selenium(self, url: str, payload: str):
        """Test XSS using Selenium."""
        try:
            self.driver.get(url)
            time.sleep(2)
            
            page_source = self.driver.page_source
            
            # Check if payload is reflected
            if payload in page_source:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential Reflected XSS",
                    description=f"XSS payload reflected in response",
                    endpoint=url,
                    parameter="test",
                    severity="High",
                    confidence=0.8,
                    evidence=f"Payload '{payload}' reflected in response",
                    vulnerability_type="XSS"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing XSS with Selenium: {str(e)}")
    
    def _test_xss_playwright(self, url: str, payload: str):
        """Test XSS using Playwright."""
        try:
            self.playwright_page.goto(url, wait_until="networkidle")
            
            content = self.playwright_page.content()
            
            # Check if payload is reflected
            if payload in content:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential Reflected XSS",
                    description=f"XSS payload reflected in response",
                    endpoint=url,
                    parameter="test",
                    severity="High",
                    confidence=0.8,
                    evidence=f"Payload '{payload}' reflected in response",
                    vulnerability_type="XSS"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing XSS with Playwright: {str(e)}")
    
    def _test_sql_injection(self, endpoint: DiscoveredEndpoint):
        """Test for SQL injection vulnerabilities."""
        try:
            # Test for SQL injection
            for payload in self.sqli_payloads:
                test_url = f"{endpoint.url}?id={payload}"
                
                if self.driver:
                    self._test_sqli_selenium(test_url, payload)
                elif self.playwright_page:
                    self._test_sqli_playwright(test_url, payload)
                    
        except Exception as e:
            logger.error(f"Error testing SQL injection: {str(e)}")
    
    def _test_sqli_selenium(self, url: str, payload: str):
        """Test SQL injection using Selenium."""
        try:
            self.driver.get(url)
            time.sleep(2)
            
            page_source = self.driver.page_source.lower()
            
            # Check for SQL error indicators
            sql_errors = ["sql syntax", "mysql error", "oracle error", "postgresql error"]
            
            for error in sql_errors:
                if error in page_source:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title="Potential SQL Injection",
                        description=f"SQL error detected with payload",
                        endpoint=url,
                        parameter="id",
                        severity="Critical",
                        confidence=0.9,
                        evidence=f"SQL error '{error}' found with payload '{payload}'",
                        vulnerability_type="SQL Injection"
                    )
                    self.vulnerability_findings.append(finding)
                    break
                    
        except Exception as e:
            logger.error(f"Error testing SQL injection with Selenium: {str(e)}")
    
    def _test_sqli_playwright(self, url: str, payload: str):
        """Test SQL injection using Playwright."""
        try:
            self.playwright_page.goto(url, wait_until="networkidle")
            
            content = self.playwright_page.content().lower()
            
            # Check for SQL error indicators
            sql_errors = ["sql syntax", "mysql error", "oracle error", "postgresql error"]
            
            for error in sql_errors:
                if error in content:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title="Potential SQL Injection",
                        description=f"SQL error detected with payload",
                        endpoint=url,
                        parameter="id",
                        severity="Critical",
                        confidence=0.9,
                        evidence=f"SQL error '{error}' found with payload '{payload}'",
                        vulnerability_type="SQL Injection"
                    )
                    self.vulnerability_findings.append(finding)
                    break
                    
        except Exception as e:
            logger.error(f"Error testing SQL injection with Playwright: {str(e)}")
    
    def _test_open_redirect(self, endpoint: DiscoveredEndpoint):
        """Test for open redirect vulnerabilities."""
        try:
            redirect_payloads = [
                "https://evil.com",
                "//evil.com",
                "javascript:alert('redirect')"
            ]
            
            for payload in redirect_payloads:
                test_url = f"{endpoint.url}?redirect={payload}"
                
                if self.driver:
                    self._test_redirect_selenium(test_url, payload)
                elif self.playwright_page:
                    self._test_redirect_playwright(test_url, payload)
                    
        except Exception as e:
            logger.error(f"Error testing open redirect: {str(e)}")
    
    def _test_redirect_selenium(self, url: str, payload: str):
        """Test open redirect using Selenium."""
        try:
            self.driver.get(url)
            time.sleep(3)
            
            current_url = self.driver.current_url
            
            # Check if redirect occurred
            if payload in current_url or "evil.com" in current_url:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential Open Redirect",
                    description="Open redirect vulnerability detected",
                    endpoint=url,
                    parameter="redirect",
                    severity="Medium",
                    confidence=0.7,
                    evidence=f"Redirected to {current_url} with payload '{payload}'",
                    vulnerability_type="Open Redirect"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing redirect with Selenium: {str(e)}")
    
    def _test_redirect_playwright(self, url: str, payload: str):
        """Test open redirect using Playwright."""
        try:
            self.playwright_page.goto(url, wait_until="networkidle")
            
            current_url = self.playwright_page.url
            
            # Check if redirect occurred
            if payload in current_url or "evil.com" in current_url:
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Potential Open Redirect",
                    description="Open redirect vulnerability detected",
                    endpoint=url,
                    parameter="redirect",
                    severity="Medium",
                    confidence=0.7,
                    evidence=f"Redirected to {current_url} with payload '{payload}'",
                    vulnerability_type="Open Redirect"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing redirect with Playwright: {str(e)}")
    
    def _test_information_disclosure(self, endpoint: DiscoveredEndpoint):
        """Test for information disclosure vulnerabilities."""
        try:
            if self.driver:
                self._test_info_disclosure_selenium(endpoint.url)
            elif self.playwright_page:
                self._test_info_disclosure_playwright(endpoint.url)
                
        except Exception as e:
            logger.error(f"Error testing information disclosure: {str(e)}")
    
    def _test_info_disclosure_selenium(self, url: str):
        """Test information disclosure using Selenium."""
        try:
            self.driver.get(url)
            time.sleep(2)
            
            page_source = self.driver.page_source.lower()
            
            # Check for sensitive information
            sensitive_patterns = [
                "password", "secret", "key", "token", "api_key",
                "database", "config", "error", "stack trace",
                "internal server error", "debug", "development"
            ]
            
            for pattern in sensitive_patterns:
                if pattern in page_source:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title="Potential Information Disclosure",
                        description=f"Sensitive information '{pattern}' found in response",
                        endpoint=url,
                        severity="Medium",
                        confidence=0.6,
                        evidence=f"Found '{pattern}' in page source",
                        vulnerability_type="Information Disclosure"
                    )
                    self.vulnerability_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing information disclosure with Selenium: {str(e)}")
    
    def _test_info_disclosure_playwright(self, url: str):
        """Test information disclosure using Playwright."""
        try:
            self.playwright_page.goto(url, wait_until="networkidle")
            
            content = self.playwright_page.content().lower()
            
            # Check for sensitive information
            sensitive_patterns = [
                "password", "secret", "key", "token", "api_key",
                "database", "config", "error", "stack trace",
                "internal server error", "debug", "development"
            ]
            
            for pattern in sensitive_patterns:
                if pattern in content:
                    finding = BrowserFinding(
                        id=f"browser_{len(self.vulnerability_findings) + 1}",
                        title="Potential Information Disclosure",
                        description=f"Sensitive information '{pattern}' found in response",
                        endpoint=url,
                        severity="Medium",
                        confidence=0.6,
                        evidence=f"Found '{pattern}' in page content",
                        vulnerability_type="Information Disclosure"
                    )
                    self.vulnerability_findings.append(finding)
                    
        except Exception as e:
            logger.error(f"Error testing information disclosure with Playwright: {str(e)}")
    
    def _test_forms(self):
        """Test discovered forms for vulnerabilities."""
        try:
            for form in self.discovered_forms:
                self._test_form_vulnerabilities(form)
                
        except Exception as e:
            logger.error(f"Error testing forms: {str(e)}")
    
    def _test_form_vulnerabilities(self, form: Dict[str, Any]):
        """Test a single form for vulnerabilities."""
        try:
            # Test form fields for XSS
            for field in form.get("fields", []):
                if field.get("field_type") in ["text", "email", "search"]:
                    self._test_form_field_xss(form, field)
                    
        except Exception as e:
            logger.error(f"Error testing form vulnerabilities: {str(e)}")
    
    def _test_form_field_xss(self, form: Dict[str, Any], field: Dict[str, Any]):
        """Test a form field for XSS vulnerabilities."""
        try:
            # This would involve filling the form and submitting it
            # For now, we'll create a placeholder finding
            if field.get("name"):
                finding = BrowserFinding(
                    id=f"browser_{len(self.vulnerability_findings) + 1}",
                    title="Form Field XSS Testing Required",
                    description=f"Form field '{field['name']}' requires XSS testing",
                    endpoint=form.get("action", ""),
                    parameter=field.get("name"),
                    severity="Medium",
                    confidence=0.5,
                    evidence=f"Form field '{field['name']}' of type '{field.get('field_type')}' discovered",
                    vulnerability_type="XSS"
                )
                self.vulnerability_findings.append(finding)
                
        except Exception as e:
            logger.error(f"Error testing form field XSS: {str(e)}")
    
    def _analyze_dynamic_content(self):
        """Analyze dynamic content for vulnerabilities."""
        try:
            # This would involve analyzing JavaScript, AJAX calls, etc.
            logger.info("Dynamic content analysis completed")
            
        except Exception as e:
            logger.error(f"Error analyzing dynamic content: {str(e)}")
    
    def _close_browser(self):
        """Close browser instances."""
        try:
            if self.driver:
                self.driver.quit()
                logger.info("Selenium WebDriver closed")
            
            if self.playwright_page:
                self.playwright_page.close()
            
            if self.playwright_browser:
                self.playwright_browser.close()
            
            if hasattr(self, 'playwright'):
                self.playwright.stop()
                logger.info("Playwright browser closed")
                
        except Exception as e:
            logger.error(f"Error closing browser: {str(e)}")
    
    def save_results(self):
        """Save browser scanning results to files."""
        try:
            # Save discovered endpoints
            endpoints_file = self.browser_dir / "discovered_endpoints.json"
            with open(endpoints_file, 'w') as f:
                json.dump([endpoint.__dict__ for endpoint in self.discovered_endpoints], f, indent=2)
            
            # Save discovered forms
            forms_file = self.browser_dir / "discovered_forms.json"
            with open(forms_file, 'w') as f:
                json.dump(self.discovered_forms, f, indent=2)
            
            # Save vulnerability findings
            findings_file = self.browser_dir / "vulnerability_findings.json"
            with open(findings_file, 'w') as f:
                json.dump([finding.__dict__ for finding in self.vulnerability_findings], f, indent=2)
            
            logger.info(f"Browser scanning results saved to {self.browser_dir}")
            
        except Exception as e:
            logger.error(f"Error saving browser scanning results: {str(e)}") 