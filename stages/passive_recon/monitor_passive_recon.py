#!/usr/bin/env python3
"""
Continuous Passive Reconnaissance Monitor

This script provides continuous monitoring capabilities for passive reconnaissance,
including scheduled execution, new discovery alerts, and performance optimization.
"""

import argparse
import os
import json
import time
import schedule
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from dotenv import load_dotenv
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from run_passive_recon import main as run_passive_recon_main

class PassiveReconMonitor:
    """Monitor for continuous passive reconnaissance with alerting capabilities."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.targets = config.get('targets', [])
        self.schedule_interval = config.get('schedule_interval', 24)  # hours
        self.alert_threshold = config.get('alert_threshold', 5)  # new discoveries
        self.previous_results = {}
        self.monitoring = False
        self.lock = threading.Lock()
        
        # Load environment variables
        load_dotenv(dotenv_path=".env")
        self.api_url = os.environ.get("BACKEND_API_URL", "http://backend:8000/api/results/passive-recon")
        self.jwt_token = os.environ.get("BACKEND_JWT_TOKEN", "")
        
        # Email configuration
        self.email_config = config.get('email', {})
        self.enable_email_alerts = self.email_config.get('enabled', False)
        
        # Performance tracking
        self.performance_metrics = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'average_execution_time': 0,
            'total_discoveries': 0,
            'new_discoveries': 0
        }
    
    def get_primary_active_target(self) -> Optional[tuple[str, str]]:
        """
        Get the target ID and domain for the primary and active target from the database.
        
        This function queries the targets API to find a target that is both:
        - is_primary = True
        - status = ACTIVE
        
        Returns a tuple of (target_id, domain) if found, None otherwise.
        """
        try:
            if '/results/passive-recon' in self.api_url:
                base_url = self.api_url.split('/results/')[0]
            else:
                base_url = self.api_url.rstrip('/')
            targets_url = f"{base_url}/targets/"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.jwt_token}' if self.jwt_token else {}
            }
            
            # Query for targets with status=ACTIVE
            response = requests.get(f"{targets_url}?status=ACTIVE", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    # Get targets from response
                    targets = data['data'].get('items', [])
                    
                    # Find the primary target
                    for target in targets:
                        if target.get('is_primary', False):
                            target_id = target.get('id')
                            domain = target.get('domain') or target.get('target', '')
                            if target_id and domain:
                                print(f"[INFO] Found primary active target: {domain} (ID: {target_id})")
                                return target_id, domain
                    
                    # If no primary target found, check if there's only one active target
                    if len(targets) == 1:
                        target_id = targets[0].get('id')
                        domain = targets[0].get('domain') or targets[0].get('target', '')
                        if target_id and domain:
                            print(f"[INFO] Found single active target: {domain} (ID: {target_id})")
                            return target_id, domain
                    
                    # If multiple active targets but none are primary, show warning
                    if len(targets) > 1:
                        print(f"[WARNING] Found {len(targets)} active targets but none are marked as primary:")
                        for target in targets:
                            target_domain = target.get('domain') or target.get('target', 'Unknown')
                            print(f"  - {target_domain} (ID: {target.get('id')}, Primary: {target.get('is_primary', False)})")
                    elif len(targets) == 0:
                        print("[WARNING] No active targets found in database")
                    
            else:
                print(f"[ERROR] Failed to query targets API: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"[ERROR] Failed to get primary active target: {e}")
        
        return None

    def get_target_id(self, domain: str) -> Optional[str]:
        """Get target ID from backend API."""
        try:
            if '/results/passive-recon' in self.api_url:
                base_url = self.api_url.split('/results/')[0]
            else:
                base_url = self.api_url.rstrip('/')
            targets_url = f"{base_url}/targets/"
            headers = {'Content-Type': 'application/json'}
            
            response = requests.get(f"{targets_url}?value={domain}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    targets = data['data'].get('targets', []) or data['data'].get('items', [])
                    if targets and len(targets) > 0:
                        return targets[0].get('id')
            return None
        except Exception as e:
            print(f"[ERROR] Failed to get target ID for {domain}: {e}")
            return None
    
    def get_previous_results(self, target: str) -> Dict:
        """Get previous reconnaissance results for comparison."""
        try:
            target_id = self.get_target_id(target)
            if not target_id:
                return {}
            
            # Get latest passive recon results
            headers = {'Authorization': f'Bearer {self.jwt_token}'} if self.jwt_token else {}
            response = requests.get(f"{self.api_url}?target_id={target_id}", headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    results = data['data'].get('results', [])
                    if results:
                        return results[-1]  # Get latest result
            return {}
        except Exception as e:
            print(f"[ERROR] Failed to get previous results for {target}: {e}")
            return {}
    
    def compare_results(self, target: str, new_results: Dict, previous_results: Dict) -> Dict:
        """Compare new results with previous results to identify new discoveries."""
        comparison = {
            'new_subdomains': set(),
            'new_ips': set(),
            'new_technologies': set(),
            'new_vulnerabilities': set(),
            'new_secrets': set(),
            'total_new_discoveries': 0
        }
        
        # Extract current discoveries
        current_subdomains = set(new_results.get('correlation', {}).get('subdomains', []))
        current_ips = set(new_results.get('correlation', {}).get('ips', []))
        current_technologies = set(new_results.get('correlation', {}).get('technologies', []))
        current_vulnerabilities = set(new_results.get('correlation', {}).get('vulnerabilities', []))
        current_secrets = set(new_results.get('correlation', {}).get('secrets', []))
        
        # Extract previous discoveries
        previous_subdomains = set(previous_results.get('correlation', {}).get('subdomains', []))
        previous_ips = set(previous_results.get('correlation', {}).get('ips', []))
        previous_technologies = set(previous_results.get('correlation', {}).get('technologies', []))
        previous_vulnerabilities = set(previous_results.get('correlation', {}).get('vulnerabilities', []))
        previous_secrets = set(previous_results.get('correlation', {}).get('secrets', []))
        
        # Find new discoveries
        comparison['new_subdomains'] = current_subdomains - previous_subdomains
        comparison['new_ips'] = current_ips - previous_ips
        comparison['new_technologies'] = current_technologies - previous_technologies
        comparison['new_vulnerabilities'] = current_vulnerabilities - previous_vulnerabilities
        comparison['new_secrets'] = current_secrets - previous_secrets
        
        # Calculate total new discoveries
        comparison['total_new_discoveries'] = (
            len(comparison['new_subdomains']) +
            len(comparison['new_ips']) +
            len(comparison['new_technologies']) +
            len(comparison['new_vulnerabilities']) +
            len(comparison['new_secrets'])
        )
        
        # Convert sets to lists for JSON serialization
        for key in comparison:
            if isinstance(comparison[key], set):
                comparison[key] = list(comparison[key])
        
        return comparison
    
    def send_email_alert(self, target: str, comparison: Dict):
        """Send email alert for new discoveries."""
        if not self.enable_email_alerts:
            return
        
        try:
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = self.email_config['to_email']
            msg['Subject'] = f"Passive Recon Alert: New Discoveries for {target}"
            
            # Create email body
            body = f"""
            Passive Reconnaissance Alert
            
            Target: {target}
            Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            New Discoveries:
            - New Subdomains: {len(comparison['new_subdomains'])}
            - New IPs: {len(comparison['new_ips'])}
            - New Technologies: {len(comparison['new_technologies'])}
            - New Vulnerabilities: {len(comparison['new_vulnerabilities'])}
            - New Secrets: {len(comparison['new_secrets'])}
            
            Total New Discoveries: {comparison['total_new_discoveries']}
            
            Details:
            """
            
            if comparison['new_subdomains']:
                body += f"\nNew Subdomains:\n" + "\n".join(comparison['new_subdomains'])
            
            if comparison['new_ips']:
                body += f"\nNew IPs:\n" + "\n".join(comparison['new_ips'])
            
            if comparison['new_technologies']:
                body += f"\nNew Technologies:\n" + "\n".join(comparison['new_technologies'])
            
            if comparison['new_vulnerabilities']:
                body += f"\nNew Vulnerabilities:\n" + "\n".join(comparison['new_vulnerabilities'])
            
            if comparison['new_secrets']:
                body += f"\nNew Secrets:\n" + "\n".join(comparison['new_secrets'])
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['username'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"[ALERT] Email alert sent for {target}")
            
        except Exception as e:
            print(f"[ERROR] Failed to send email alert: {e}")
    
    def get_target_scan_config(self, target_id: str) -> Dict:
        """
        Get scan configuration from target profile in database.
        
        Returns configuration including rate limiting, in_scope targets, and other settings.
        """
        try:
            if '/results/passive-recon' in self.api_url:
                base_url = self.api_url.split('/results/')[0]
            else:
                base_url = self.api_url.rstrip('/')
            targets_url = f"{base_url}/targets/{target_id}"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {self.jwt_token}' if self.jwt_token else {}
            }
            
            response = requests.get(targets_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success') and data.get('data'):
                    target_data = data['data']
                    return {
                        'rate_limit_requests': target_data.get('rate_limit_requests', 10),
                        'rate_limit_seconds': target_data.get('rate_limit_seconds', 60),
                        'in_scope': target_data.get('in_scope', []),
                        'domain': target_data.get('domain', ''),
                        'target': target_data.get('target', ''),
                        'is_primary': target_data.get('is_primary', False),
                        'status': target_data.get('status', 'ACTIVE')
                    }
            
            print(f"[WARNING] Failed to get target scan config: {response.status_code}")
            return {
                'rate_limit_requests': 10,
                'rate_limit_seconds': 60,
                'in_scope': [],
                'domain': '',
                'target': '',
                'is_primary': False,
                'status': 'ACTIVE'
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to get target scan config: {e}")
            return {
                'rate_limit_requests': 10,
                'rate_limit_seconds': 60,
                'in_scope': [],
                'domain': '',
                'target': '',
                'is_primary': False,
                'status': 'ACTIVE'
            }

    def run_passive_recon_for_target(self, target: str) -> Dict:
        """Run passive reconnaissance for a specific target."""
        start_time = time.time()
        
        try:
            print(f"[INFO] Running passive recon for target: {target}")
            
            # Get target info and scan configuration
            target_info = self.get_primary_active_target()
            if not target_info:
                print("[ERROR] Could not get primary active target")
                return {'success': False, 'error': 'No primary active target found'}
            
            target_id, target_domain = target_info
            scan_config = self.get_target_scan_config(target_id)
            
            # Calculate rate limit from target configuration
            rate_limit = scan_config.get('rate_limit_requests', 10) / scan_config.get('rate_limit_seconds', 60)
            parallel_tools = max(1, min(5, int(rate_limit * 2)))
            
            print(f"[INFO] Using rate limit: {rate_limit:.2f} calls/second from target config")
            print(f"[INFO] Parallel tools: {parallel_tools}")
            
            # Set up command line arguments for the main runner
            import sys
            sys.argv = ['run_passive_recon.py', '--target', target, '--parallel', str(parallel_tools), '--rate-limit', str(rate_limit)]
            
            # Run the main passive recon script
            run_passive_recon_main()
            
            execution_time = time.time() - start_time
            
            # Update performance metrics
            with self.lock:
                self.performance_metrics['total_executions'] += 1
                self.performance_metrics['successful_executions'] += 1
                self.performance_metrics['average_execution_time'] = (
                    (self.performance_metrics['average_execution_time'] * 
                     (self.performance_metrics['total_executions'] - 1) + execution_time) /
                    self.performance_metrics['total_executions']
                )
            
            # Get results from output files
            output_dir = f"/outputs/{target}/parsed"
            summary_file = os.path.join(output_dir, "comprehensive_summary.json")
            
            if os.path.exists(summary_file):
                with open(summary_file, 'r') as f:
                    results = json.load(f)
                
                # Compare with previous results
                previous_results = self.get_previous_results(target)
                comparison = self.compare_results(target, results, previous_results)
                
                # Update performance metrics
                with self.lock:
                    self.performance_metrics['total_discoveries'] += comparison['total_new_discoveries']
                    self.performance_metrics['new_discoveries'] += comparison['total_new_discoveries']
                
                # Send alert if threshold exceeded
                if comparison['total_new_discoveries'] >= self.alert_threshold:
                    self.send_email_alert(target, comparison)
                    print(f"[ALERT] {comparison['total_new_discoveries']} new discoveries for {target}")
                
                # Store results for next comparison
                self.previous_results[target] = results
                
                return {
                    'success': True,
                    'execution_time': execution_time,
                    'comparison': comparison,
                    'results': results
                }
            
            return {'success': True, 'execution_time': execution_time}
            
        except Exception as e:
            execution_time = time.time() - start_time
            print(f"[ERROR] Passive recon failed for {target}: {e}")
            
            with self.lock:
                self.performance_metrics['total_executions'] += 1
                self.performance_metrics['failed_executions'] += 1
            
            return {'success': False, 'error': str(e), 'execution_time': execution_time}
    
    def run_scheduled_recon(self):
        """Run scheduled passive reconnaissance for the primary active target."""
        print(f"[SCHEDULE] Running scheduled passive recon at {datetime.now()}")
        
        # Get primary active target from database
        target_info = self.get_primary_active_target()
        if not target_info:
            print("[WARNING] No primary active target found in database. Skipping scheduled recon.")
            return
        
        target_id, target_domain = target_info
        print(f"[SCHEDULE] Running recon for primary active target: {target_domain} (ID: {target_id})")
        
        try:
            result = self.run_passive_recon_for_target(target_domain)
            if result['success']:
                print(f"[SCHEDULE] Successfully completed recon for {target_domain}")
            else:
                print(f"[SCHEDULE] Failed to complete recon for {target_domain}: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"[ERROR] Exception during scheduled recon for {target_domain}: {e}")
    
    def start_monitoring(self):
        """Start continuous monitoring."""
        self.monitoring = True
        
        # Schedule regular execution
        schedule.every(self.schedule_interval).hours.do(self.run_scheduled_recon)
        
        print(f"[MONITOR] Starting continuous monitoring")
        print(f"[MONITOR] Schedule: Every {self.schedule_interval} hours")
        print(f"[MONITOR] Alert threshold: {self.alert_threshold} new discoveries")
        print(f"[MONITOR] Target: Primary active target from database")
        
        # Run initial recon for primary active target
        print("[MONITOR] Running initial reconnaissance...")
        self.run_scheduled_recon()
        
        # Start monitoring loop
        while self.monitoring:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except KeyboardInterrupt:
                print("\n[MONITOR] Stopping monitoring...")
                self.monitoring = False
            except Exception as e:
                print(f"[ERROR] Monitoring error: {e}")
                time.sleep(60)
    
    def get_performance_report(self) -> Dict:
        """Get performance metrics report."""
        with self.lock:
            return self.performance_metrics.copy()
    
    def stop_monitoring(self):
        """Stop continuous monitoring."""
        self.monitoring = False

def main():
    parser = argparse.ArgumentParser(description="Passive Reconnaissance Monitor")
    parser.add_argument("--config", default="monitor_config.json", help="Configuration file")
    parser.add_argument("--interval", type=int, default=24, help="Schedule interval in hours")
    parser.add_argument("--threshold", type=int, default=5, help="Alert threshold for new discoveries")
    parser.add_argument("--run-once", action="store_true", help="Run once instead of continuous monitoring")
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Override config with command line arguments
    if args.interval:
        config['schedule_interval'] = args.interval
    if args.threshold:
        config['alert_threshold'] = args.threshold
    
    # Create monitor
    monitor = PassiveReconMonitor(config)
    
    if args.run_once:
        # Run once for primary active target
        print("[INFO] Running passive recon once for primary active target")
        target_info = monitor.get_primary_active_target()
        if target_info:
            target_id, target_domain = target_info
            result = monitor.run_passive_recon_for_target(target_domain)
            print(f"Result for {target_domain}: {result}")
        else:
            print("[WARNING] No primary active target found in database")
        
        # Print performance report
        performance = monitor.get_performance_report()
        print(f"\nPerformance Report:")
        print(f"Total Executions: {performance['total_executions']}")
        print(f"Successful: {performance['successful_executions']}")
        print(f"Failed: {performance['failed_executions']}")
        print(f"Average Execution Time: {performance['average_execution_time']:.2f} seconds")
        print(f"Total Discoveries: {performance['total_discoveries']}")
        print(f"New Discoveries: {performance['new_discoveries']}")
    else:
        # Start continuous monitoring
        monitor.start_monitoring()

if __name__ == "__main__":
    main()