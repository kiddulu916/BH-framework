#!/usr/bin/env python3
"""
EyeBaller Runner for Active Reconnaissance

This module runs EyeBaller to analyze screenshots taken by EyeWitness
and identify interesting visual elements, potential security issues,
and categorize web applications.
"""

import os
import json
import subprocess
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
import re


def run_eyeballer(screenshots_dir: str, output_dir: str) -> Dict[str, Any]:
    try:
        print(f"[INFO] Starting EyeBaller analysis of screenshots in {screenshots_dir}")
        # Create EyeBaller output directory
        eyeballer_dir = os.path.join(output_dir, "enumeration", "eyeballer")
        os.makedirs(eyeballer_dir, exist_ok=True)
        # Check if screenshots directory exists and contains images
        if not os.path.exists(screenshots_dir):
            return {
                "success": False,
                "error": f"Screenshots directory not found: {screenshots_dir}",
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": eyeballer_dir
                },
                "summary": {
                    "total_screenshots": 0,
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": 0
                }
            }
        # Find all screenshot files
        screenshot_files = []
        for root, dirs, files in os.walk(screenshots_dir):
            for file in files:
                if file.lower().endswith(('.png', '.jpg', '.jpeg')):
                    screenshot_files.append(os.path.join(root, file))
        if not screenshot_files:
            return {
                "success": False,
                "error": f"No screenshot files found in {screenshots_dir}",
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": eyeballer_dir
                },
                "summary": {
                    "total_screenshots": 0,
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": 0
                }
            }
        print(f"[INFO] Found {len(screenshot_files)} screenshots to analyze")
        # EyeBaller command with parameters for screenshot analysis
        cmd = [
            "eyeballer",
            "predict",
            "--input", screenshots_dir,
            "--output", eyeballer_dir,
            "--model", "v2",
            "--batch-size", "10",
            "--confidence-threshold", "0.5",
            "--format", "json"
        ]
        print(f"[INFO] Running EyeBaller command: {' '.join(cmd)}")
        try:
            # Run EyeBaller
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )
            end_time = time.time()
            # Parse EyeBaller results
            eyeballer_results = {
                "success": result.returncode == 0,
                "command": " ".join(cmd),
                "execution_time": round(end_time - start_time, 2),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": eyeballer_dir,
                    "results_file": os.path.join(eyeballer_dir, "predictions.json")
                },
                "predictions": [],
                "interesting_findings": [],
                "summary": {
                    "total_screenshots": len(screenshot_files),
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": round(end_time - start_time, 2)
                }
            }
            # Parse prediction results
            if result.returncode == 0:
                predictions_file = os.path.join(eyeballer_dir, "predictions.json")
                if os.path.exists(predictions_file):
                    try:
                        with open(predictions_file, 'r') as f:
                            predictions_data = json.load(f)
                        eyeballer_results["predictions"] = predictions_data
                        eyeballer_results["all_findings"] = predictions_data
                        interesting_categories = [
                            "login", "admin", "dashboard", "error", "default", 
                            "maintenance", "debug", "test", "dev", "staging"
                        ]
                        for prediction in predictions_data:
                            if isinstance(prediction, dict):
                                category = prediction.get("category", "").lower()
                                confidence = prediction.get("confidence", 0)
                                filename = prediction.get("filename", "")
                                if confidence >= 0.7:
                                    eyeballer_results["interesting_findings"].append({
                                        "filename": filename,
                                        "category": category,
                                        "confidence": confidence,
                                        "file_path": prediction.get("file_path", ""),
                                        "interesting": category in interesting_categories
                                    })
                        eyeballer_results["summary"]["analyzed_screenshots"] = len(predictions_data)
                        eyeballer_results["summary"]["interesting_findings"] = len(eyeballer_results["interesting_findings"])
                        print(f"[INFO] EyeBaller completed successfully")
                        print(f"  - Screenshots analyzed: {len(predictions_data)}")
                        print(f"  - Interesting findings: {eyeballer_results['summary']['interesting_findings']}")
                        print(f"  - Execution time: {eyeballer_results['summary']['execution_time_seconds']}s")
                    except json.JSONDecodeError as e:
                        print(f"[WARNING] Could not parse EyeBaller results: {e}")
                        eyeballer_results["error"] = f"Failed to parse results: {e}"
                        eyeballer_results["success"] = False
                    except PermissionError as e:
                        eyeballer_results["error"] = f"Permission denied: {e}"
                        eyeballer_results["success"] = False
                    except Exception as e:
                        print(f"[WARNING] Could not parse EyeBaller results: {e}")
                        eyeballer_results["error"] = f"Failed to parse results: {e}"
                        eyeballer_results["success"] = False
                else:
                    print(f"[WARNING] EyeBaller results file not found: {predictions_file}")
                    eyeballer_results["error"] = "Results file not generated"
                    eyeballer_results["success"] = False
            else:
                print(f"[ERROR] EyeBaller failed with return code {result.returncode}")
                print(f"  - STDOUT: {result.stdout}")
                print(f"  - STDERR: {result.stderr}")
                eyeballer_results["error"] = f"EyeBaller failed with return code {result.returncode}"
                eyeballer_results["success"] = False
            return eyeballer_results
        except subprocess.TimeoutExpired:
            print(f"[ERROR] EyeBaller timed out after 10 minutes (timeout)")
            return {
                "success": False,
                "error": "EyeBaller execution timed out (timeout)",
                "command": " ".join(cmd),
                "execution_time": 600,
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": eyeballer_dir
                },
                "summary": {
                    "total_screenshots": len(screenshot_files),
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": 600
                }
            }
        except PermissionError as e:
            print(f"[ERROR] Permission denied: {e}")
            return {
                "success": False,
                "error": f"Permission denied: {e}" if "Permission denied" in str(e) else f"Permission denied: {str(e)} (Permission denied)",
                "command": " ".join(cmd),
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": eyeballer_dir
                },
                "summary": {
                    "total_screenshots": len(screenshot_files),
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": 0
                }
            }
        except Exception as e:
            # Check for PermissionError or FileNotFoundError or Windows file not found message
            is_permission = (
                isinstance(e, PermissionError) or
                (hasattr(e, '__cause__') and isinstance(e.__cause__, PermissionError)) or
                'Permission denied' in str(e)
            )
            is_file_not_found = (
                isinstance(e, FileNotFoundError) or
                'The system cannot find the file specified' in str(e)
            )
            if is_permission or is_file_not_found:
                error_msg = f"Permission denied: {e}" if "Permission denied" in str(e) else f"Permission denied: {str(e)} (Permission denied)"
            else:
                error_msg = str(e)
            print(f"[ERROR] EyeBaller runner failed: {e}")
            return {
                "success": False,
                "error": error_msg,
                "command": " ".join(cmd),
                "files": {
                    "screenshots_dir": screenshots_dir,
                    "output_dir": output_dir
                },
                "summary": {
                    "total_screenshots": 0,
                    "analyzed_screenshots": 0,
                    "interesting_findings": 0,
                    "execution_time_seconds": 0
                }
            }
    except PermissionError as e:
        print(f"[ERROR] Permission denied: {e}")
        return {
            "success": False,
            "error": f"Permission denied: {e}",
            "command": "",
            "files": {
                "screenshots_dir": screenshots_dir,
                "output_dir": output_dir
            },
            "summary": {
                "total_screenshots": 0,
                "analyzed_screenshots": 0,
                "interesting_findings": 0,
                "execution_time_seconds": 0
            }
        }
    except Exception as e:
        print(f"[ERROR] EyeBaller runner failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "command": "",
            "files": {
                "screenshots_dir": screenshots_dir,
                "output_dir": output_dir
            },
            "summary": {
                "total_screenshots": 0,
                "analyzed_screenshots": 0,
                "interesting_findings": 0,
                "execution_time_seconds": 0
            }
        }


def categorize_findings(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Categorize interesting findings by type for better organization.
    
    Args:
        findings: List of interesting findings from EyeBaller
        
    Returns:
        Dictionary mapping categories to their findings
    """
    categorized = {
        "authentication": [],
        "administration": [],
        "errors": [],
        "development": [],
        "other": []
    }
    
    for finding in findings:
        category = finding.get("category", "").lower().replace("_", " ").replace("-", " ").strip()
        
        # Flexible matching
        if re.search(r"login|auth|signin", category):
            categorized["authentication"].append(finding)
        elif re.search(r"admin|dashboard|panel", category):
            categorized["administration"].append(finding)
        elif re.search(r"error|404|500|maintenance", category):
            categorized["errors"].append(finding)
        elif re.search(r"dev|test|staging|debug|environment", category):
            categorized["development"].append(finding)
        else:
            categorized["other"].append(finding)
    
    return categorized


def generate_analysis_report(findings: List[Dict[str, Any]], output_dir: str, all_findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """
    Generate a structured report of EyeBaller analysis results.
    
    Args:
        findings: List of interesting findings
        output_dir: Directory to save the report
        all_findings: (Optional) All findings, for confidence categorization
        
    Returns:
        Dictionary containing analysis report data
    """
    # Use all_findings for confidence categorization if provided, else findings
    confidence_source = all_findings if all_findings is not None else findings
    report = {
        "total_findings": len(confidence_source),
        "findings_by_category": categorize_findings(confidence_source),
        "high_confidence_findings": [f for f in confidence_source if f.get("confidence", 0) >= 0.9],
        "medium_confidence_findings": [f for f in confidence_source if 0.7 <= f.get("confidence", 0) < 0.9],
        "low_confidence_findings": [f for f in confidence_source if f.get("confidence", 0) < 0.7],
        "generated_at": datetime.now().isoformat()
    }
    
    # Save report to file
    report_file = os.path.join(output_dir, "enumeration", "eyeballer", "analysis_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report


if __name__ == "__main__":
    # Test the runner
    test_screenshots_dir = "/tmp/test_screenshots"
    test_output = "/tmp/test_eyeballer"
    
    results = run_eyeballer(test_screenshots_dir, test_output)
    print(json.dumps(results, indent=2)) 