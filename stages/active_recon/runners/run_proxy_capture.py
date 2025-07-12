#!/usr/bin/env python3
"""
Proxy Capture Runner for Active Reconnaissance

This module sets up a proxy server to capture HTTP/HTTPS traffic
and generate infrastructure maps from the captured data.
"""

import os
import json
import asyncio
import subprocess
import threading
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse
import logging
from mitmproxy import http, ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TrafficCapture:
    """Custom mitmproxy addon for capturing and storing traffic."""
    
    def __init__(self, output_dir: str, target_domain: str):
        self.output_dir = Path(output_dir)
        self.target_domain = target_domain
        self.requests = []
        self.responses = []
        self.infrastructure_map = {
            "target": target_domain,
            "domains": set(),
            "ips": set(),
            "ports": set(),
            "services": set(),
            "technologies": set(),
            "endpoints": set()
        }
        
        # Create output directories
        self.setup_directories()
    
    def setup_directories(self):
        """Create the required output directory structure."""
        dirs = [
            self.output_dir / "enumeration" / "infrastructure",
            self.output_dir / "enumeration" / "http-requests" / self.target_domain,
            self.output_dir / "enumeration" / "http-responses" / self.target_domain,
        ]
        
        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {dir_path}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Capture HTTP requests."""
        try:
            # Only capture traffic for our target domain
            if self.target_domain in flow.request.pretty_host:
                request_data = {
                    "timestamp": time.time(),
                    "method": flow.request.method,
                    "url": flow.request.pretty_url,
                    "host": flow.request.pretty_host,
                    "port": flow.request.port,
                    "path": flow.request.path,
                    "headers": dict(flow.request.headers),
                    "content": flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else ""
                }
                
                self.requests.append(request_data)
                
                # Update infrastructure map
                self.infrastructure_map["domains"].add(flow.request.pretty_host)
                self.infrastructure_map["ports"].add(str(flow.request.port))
                self.infrastructure_map["endpoints"].add(flow.request.path)
                
                logger.info(f"Captured request: {flow.request.method} {flow.request.pretty_url}")
        
        except Exception as e:
            logger.error(f"Error capturing request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Capture HTTP responses."""
        try:
            # Only capture traffic for our target domain
            if self.target_domain in flow.request.pretty_host:
                response_data = {
                    "timestamp": time.time(),
                    "request_url": flow.request.pretty_url,
                    "status_code": flow.response.status_code,
                    "headers": dict(flow.response.headers),
                    "content": flow.response.content.decode('utf-8', errors='ignore') if flow.response.content else "",
                    "content_type": flow.response.headers.get("content-type", "")
                }
                
                self.responses.append(response_data)
                
                # Extract technologies from headers
                server_header = flow.response.headers.get("server", "")
                if server_header:
                    self.infrastructure_map["technologies"].add(server_header)
                
                # Extract IP from response if available
                if hasattr(flow, 'server_conn') and flow.server_conn.ip_address:
                    self.infrastructure_map["ips"].add(str(flow.server_conn.ip_address[0]))
                
                logger.info(f"Captured response: {flow.response.status_code} for {flow.request.pretty_url}")
        
        except Exception as e:
            logger.error(f"Error capturing response: {e}")
    
    def save_captured_data(self):
        """Save all captured data to files."""
        try:
            # Save requests
            requests_file = self.output_dir / "enumeration" / "http-requests" / self.target_domain / "captured_requests.json"
            with open(requests_file, 'w') as f:
                json.dump(self.requests, f, indent=2)
            logger.info(f"Saved {len(self.requests)} requests to {requests_file}")
            
            # Save responses
            responses_file = self.output_dir / "enumeration" / "http-responses" / self.target_domain / "captured_responses.json"
            with open(responses_file, 'w') as f:
                json.dump(self.responses, f, indent=2)
            logger.info(f"Saved {len(self.responses)} responses to {responses_file}")
            
            # Save infrastructure map
            infrastructure_file = self.output_dir / "enumeration" / "infrastructure" / f"{self.target_domain}_infrastructure_map.json"
            
            # Convert sets to lists for JSON serialization
            infrastructure_data = {
                "target": self.infrastructure_map["target"],
                "domains": list(self.infrastructure_map["domains"]),
                "ips": list(self.infrastructure_map["ips"]),
                "ports": list(self.infrastructure_map["ports"]),
                "services": list(self.infrastructure_map["services"]),
                "technologies": list(self.infrastructure_map["technologies"]),
                "endpoints": list(self.infrastructure_map["endpoints"]),
                "summary": {
                    "total_requests": len(self.requests),
                    "total_responses": len(self.responses),
                    "unique_domains": len(self.infrastructure_map["domains"]),
                    "unique_ips": len(self.infrastructure_map["ips"]),
                    "unique_ports": len(self.infrastructure_map["ports"]),
                    "unique_endpoints": len(self.infrastructure_map["endpoints"])
                }
            }
            
            with open(infrastructure_file, 'w') as f:
                json.dump(infrastructure_data, f, indent=2)
            logger.info(f"Saved infrastructure map to {infrastructure_file}")
            
            return {
                "requests_file": str(requests_file),
                "responses_file": str(responses_file),
                "infrastructure_file": str(infrastructure_file),
                "summary": infrastructure_data["summary"]
            }
        
        except Exception as e:
            logger.error(f"Error saving captured data: {e}")
            return None

def start_proxy_server(port: int = 8080, host: str = "0.0.0.0") -> DumpMaster:
    """Start the mitmproxy server."""
    try:
        opts = Options(
            listen_host=host,
            listen_port=port,
            ssl_insecure=True,
            confdir="~/.mitmproxy"
        )
        
        master = DumpMaster(opts)
        
        logger.info(f"Starting proxy server on {host}:{port}")
        return master
    
    except Exception as e:
        logger.error(f"Error starting proxy server: {e}")
        raise

def run_proxy_capture(target_domain: str, output_dir: str, capture_duration: int = 300) -> Dict[str, Any]:
    """
    Run proxy capture for the specified target domain.
    
    Args:
        target_domain: The target domain to capture traffic for
        output_dir: Directory to save captured data
        capture_duration: Duration to capture traffic in seconds (default: 5 minutes)
    
    Returns:
        Dictionary containing capture results and file paths
    """
    try:
        logger.info(f"Starting proxy capture for {target_domain}")
        
        # Create traffic capture addon
        capture_addon = TrafficCapture(output_dir, target_domain)
        
        # Start proxy server
        master = start_proxy_server()
        master.addons.add(capture_addon)
        
        # Start proxy server in a separate thread
        def run_proxy():
            try:
                master.run()
            except KeyboardInterrupt:
                logger.info("Proxy server stopped by user")
            except Exception as e:
                logger.error(f"Proxy server error: {e}")
        
        proxy_thread = threading.Thread(target=run_proxy, daemon=True)
        proxy_thread.start()
        
        # Wait for proxy to start
        time.sleep(2)
        
        logger.info(f"Capturing traffic for {capture_duration} seconds...")
        logger.info(f"Proxy server running on http://localhost:8080")
        logger.info(f"Configure your tools to use this proxy for traffic capture")
        
        # Wait for capture duration
        time.sleep(capture_duration)
        
        # Stop proxy server
        master.shutdown()
        proxy_thread.join(timeout=5)
        
        # Save captured data
        results = capture_addon.save_captured_data()
        
        if results:
            logger.info("Proxy capture completed successfully")
            return {
                "success": True,
                "target": target_domain,
                "capture_duration": capture_duration,
                "files": results,
                "summary": results["summary"]
            }
        else:
            logger.error("Failed to save captured data")
            return {
                "success": False,
                "target": target_domain,
                "error": "Failed to save captured data"
            }
    
    except Exception as e:
        logger.error(f"Error in proxy capture: {e}")
        return {
            "success": False,
            "target": target_domain,
            "error": str(e)
        }

def main():
    """Main function for testing the proxy capture."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Proxy Capture Runner")
    parser.add_argument("--target", required=True, help="Target domain")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--duration", type=int, default=300, help="Capture duration in seconds")
    
    args = parser.parse_args()
    
    results = run_proxy_capture(args.target, args.output_dir, args.duration)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 