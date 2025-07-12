#!/usr/bin/env python3
"""
EyeWitness Runner for Active Reconnaissance

This module runs EyeWitness to take screenshots of discovered web applications
and provides structured output for further analysis.
"""

import os
import json
import subprocess
import time
from typing import List, Dict, Any, Optional
from datetime import datetime


def run_eyewitness(targets: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Run EyeWitness to take screenshots of discovered web applications.
    
    Args:
        targets: List of target URLs/hostnames to screenshot
        output_dir: Directory to save outputs
        
    Returns:
        Dictionary containing EyeWitness results and metadata
    """
    try:
        print(f"[INFO] Starting EyeWitness screenshot capture for {len(targets)} targets")
        
        # Create EyeWitness output directory
        eyewitness_dir = os.path.join(output_dir, "enumeration", "eyewitness")
        os.makedirs(eyewitness_dir, exist_ok=True)
        
        # Create targets file for EyeWitness
        targets_file = os.path.join(eyewitness_dir, "targets.txt")
        with open(targets_file, 'w') as f:
            for target in targets:
                # Ensure targets have protocol
                if not target.startswith(('http://', 'https://')):
                    target = f"http://{target}"
                f.write(f"{target}\n")
        
        # EyeWitness command with minimal parameters for screenshot capture
        cmd = [
            "eyewitness",
            "--web",  # Web screenshot mode
            "--no-prompt",  # Non-interactive mode
            "--timeout", "10",  # 10 second timeout per target
            "--threads", "5",  # 5 concurrent threads
            "--max-retries", "2",  # 2 retries per target
            "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",  # Standard user agent
            "--no-dns",  # Skip DNS resolution (already done)
            "--no-http",  # Skip HTTP status check (already done)
            "--no-redirects", # Dont follow redirects
            "--screenshot-only",  # Only take screenshots, skip other checks
            "-f", targets_file,  # Input file
            "-d", eyewitness_dir  # Output directory
        ]
        
        print(f"[INFO] Running EyeWitness command: {' '.join(cmd)}")
        
        try:
            # Run EyeWitness
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for entire process
            )
            end_time = time.time()
            
            # Parse EyeWitness results
            eyewitness_results = {
                "success": result.returncode == 0,
                "command": " ".join(cmd),
                "execution_time": round(end_time - start_time, 2),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "files": {
                    "targets_file": targets_file,
                    "output_dir": eyewitness_dir,
                    "report_file": os.path.join(eyewitness_dir, "report.html")
                },
                "screenshots": [],
                "summary": {
                    "total_targets": len(targets),
                    "successful_screenshots": 0,
                    "failed_screenshots": 0,
                    "execution_time_seconds": round(end_time - start_time, 2)
                }
            }
            
            # Parse screenshot results
            if result.returncode == 0:
                # Look for screenshot files in the output directory
                screenshot_files = []
                for root, dirs, files in os.walk(eyewitness_dir):
                    for file in files:
                        if file.lower().endswith(('.png', '.jpg', '.jpeg')):
                            screenshot_files.append(os.path.join(root, file))
                
                eyewitness_results["screenshots"] = screenshot_files
                eyewitness_results["summary"]["successful_screenshots"] = len(screenshot_files)
                eyewitness_results["summary"]["failed_screenshots"] = len(targets) - len(screenshot_files)
                
                print(f"[INFO] EyeWitness completed successfully")
                print(f"  - Targets processed: {len(targets)}")
                print(f"  - Screenshots captured: {len(screenshot_files)}")
                print(f"  - Failed captures: {eyewitness_results['summary']['failed_screenshots']}")
                print(f"  - Execution time: {eyewitness_results['summary']['execution_time_seconds']}s")
            else:
                print(f"[ERROR] EyeWitness failed with return code {result.returncode}")
                print(f"  - STDOUT: {result.stdout}")
                print(f"  - STDERR: {result.stderr}")
                eyewitness_results["error"] = f"EyeWitness failed with return code {result.returncode}"
                eyewitness_results["summary"]["failed_screenshots"] = len(targets)
            
            return eyewitness_results
            
        except subprocess.TimeoutExpired:
            print(f"[ERROR] EyeWitness timed out after 5 minutes (timeout)")
            return {
                "success": False,
                "error": "EyeWitness execution timed out (timeout)",
                "command": " ".join(cmd),
                "execution_time": 300,
                "files": {
                    "targets_file": targets_file,
                    "output_dir": eyewitness_dir
                },
                "summary": {
                    "total_targets": len(targets),
                    "successful_screenshots": 0,
                    "failed_screenshots": len(targets),
                    "execution_time_seconds": 300
                }
            }
        except Exception as e:
            print(f"[ERROR] EyeWitness runner failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "command": " ".join(cmd),
                "files": {
                    "targets_file": targets_file,
                    "output_dir": eyewitness_dir
                },
                "summary": {
                    "total_targets": len(targets),
                    "successful_screenshots": 0,
                    "failed_screenshots": len(targets),
                    "execution_time_seconds": 0
                }
            }
    except OSError as e:
        print(f"[ERROR] Directory creation failed: {e}")
        return {
            "success": False,
            "error": f"Directory creation failed: {e}",
            "command": "",
            "files": {
                "targets_file": "",
                "output_dir": output_dir
            },
            "summary": {
                "total_targets": len(targets),
                "successful_screenshots": 0,
                "failed_screenshots": len(targets),
                "execution_time_seconds": 0
            }
        }
    except Exception as e:
        print(f"[ERROR] EyeWitness runner failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "command": "",
            "files": {
                "targets_file": "",
                "output_dir": output_dir
            },
            "summary": {
                "total_targets": len(targets),
                "successful_screenshots": 0,
                "failed_screenshots": len(targets),
                "execution_time_seconds": 0
            }
        }


def categorize_screenshots(screenshots: List[str]) -> Dict[str, List[str]]:
    """
    Categorize screenshots by target domain for better organization.
    
    Args:
        screenshots: List of screenshot file paths
        
    Returns:
        Dictionary mapping domains to their screenshot files
    """
    categorized = {}
    
    for screenshot in screenshots:
        filename = os.path.basename(screenshot)
        # Extract domain from filename (EyeWitness typically uses domain in filename)
        parts = filename.split('_')
        if len(parts) > 1:
            domain = parts[0]
            if domain not in categorized:
                categorized[domain] = []
            categorized[domain].append(screenshot)
    
    return categorized


def generate_screenshot_report(screenshots: List[str], output_dir: str) -> Dict[str, Any]:
    """
    Generate a structured report of screenshot results.
    
    Args:
        screenshots: List of screenshot file paths
        output_dir: Directory to save the report
        
    Returns:
        Dictionary containing screenshot report data
    """
    report = {
        "total_screenshots": len(screenshots),
        "screenshots_by_domain": categorize_screenshots(screenshots),
        "screenshot_details": [],
        "generated_at": datetime.now().isoformat()
    }
    
    # Add details for each screenshot
    for screenshot in screenshots:
        try:
            stat = os.stat(screenshot)
            report["screenshot_details"].append({
                "file_path": screenshot,
                "filename": os.path.basename(screenshot),
                "size_bytes": stat.st_size,
                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "modified_at": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        except Exception as e:
            print(f"[WARNING] Could not get details for screenshot {screenshot}: {e}")
    
    # Save report to file
    report_file = os.path.join(output_dir, "enumeration", "eyewitness", "screenshot_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report


if __name__ == "__main__":
    # Test the runner
    test_targets = ["example.com", "test.example.com"]
    test_output = "/tmp/test_eyewitness"
    
    results = run_eyewitness(test_targets, test_output)
    print(json.dumps(results, indent=2)) 