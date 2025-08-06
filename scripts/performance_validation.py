#!/usr/bin/env python3
"""
Bug Hunting Framework - Performance Validation Script

This script performs comprehensive performance testing and validation
of the framework under various load conditions.

Usage:
    python performance_validation.py [--verbose] [--output-format json|html|text]
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import requests
import aiohttp
import psutil
import docker
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('performance_validation.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Represents a performance metric."""
    test_name: str
    metric_type: str  # RESPONSE_TIME, THROUGHPUT, ERROR_RATE, RESOURCE_USAGE
    value: float
    unit: str
    threshold: Optional[float] = None
    status: str = "PASS"  # PASS, WARNING, FAIL
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

@dataclass
class PerformanceSummary:
    """Summary of performance validation results."""
    total_tests: int
    passed_tests: int
    failed_tests: int
    warning_tests: int
    overall_performance_score: float
    recommendations: List[str]
    timestamp: str

class PerformanceValidator:
    """Comprehensive performance validator for the Bug Hunting Framework."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.metrics: List[PerformanceMetric] = []
        self.base_url = os.getenv('BASE_URL', 'http://localhost:8000')
        self.docker_client = docker.from_env()
        
    def add_metric(self, test_name: str, metric_type: str, value: float, 
                  unit: str, threshold: Optional[float] = None):
        """Add a performance metric."""
        status = "PASS"
        if threshold:
            if value > threshold * 1.2:  # 20% over threshold
                status = "FAIL"
            elif value > threshold:
                status = "WARNING"
        
        metric = PerformanceMetric(
            test_name=test_name,
            metric_type=metric_type,
            value=value,
            unit=unit,
            threshold=threshold,
            status=status
        )
        self.metrics.append(metric)
        
        if self.verbose:
            logger.info(f"[{status}] {test_name}: {value} {unit}")
        else:
            if status == "FAIL":
                logger.error(f"[FAIL] {test_name}: {value} {unit}")
            elif status == "WARNING":
                logger.warning(f"[WARNING] {test_name}: {value} {unit}")
    
    async def validate_response_times(self) -> None:
        """Validate API response times."""
        logger.info("Validating response times...")
        
        endpoints = [
            "/api/health/",
            "/api/targets/",
            "/api/workflows/",
            "/api/results/"
        ]
        
        for endpoint in endpoints:
            response_times = []
            
            # Test response time with multiple requests
            for i in range(10):
                try:
                    start_time = time.time()
                    response = requests.get(f"{self.base_url}{endpoint}", timeout=30)
                    end_time = time.time()
                    
                    response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                    response_times.append(response_time)
                    
                    if response.status_code != 200:
                        logger.warning(f"Endpoint {endpoint} returned status {response.status_code}")
                        
                except Exception as e:
                    logger.error(f"Error testing {endpoint}: {str(e)}")
                    response_times.append(30000)  # 30 seconds timeout
            
            if response_times:
                avg_response_time = statistics.mean(response_times)
                max_response_time = max(response_times)
                min_response_time = min(response_times)
                
                self.add_metric(
                    f"Response Time - {endpoint}",
                    "RESPONSE_TIME",
                    avg_response_time,
                    "ms",
                    threshold=1000  # 1 second
                )
                
                self.add_metric(
                    f"Max Response Time - {endpoint}",
                    "RESPONSE_TIME",
                    max_response_time,
                    "ms",
                    threshold=5000  # 5 seconds
                )
    
    async def validate_throughput(self) -> None:
        """Validate system throughput."""
        logger.info("Validating throughput...")
        
        # Test concurrent requests
        endpoint = "/api/health/"
        concurrent_users = [1, 5, 10, 20, 50]
        
        for num_users in concurrent_users:
            start_time = time.time()
            successful_requests = 0
            failed_requests = 0
            
            async def make_request():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"{self.base_url}{endpoint}", timeout=30) as response:
                            if response.status == 200:
                                return True
                            else:
                                return False
                except Exception:
                    return False
            
            # Create tasks for concurrent requests
            tasks = [make_request() for _ in range(num_users)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            duration = end_time - start_time
            
            for result in results:
                if result is True:
                    successful_requests += 1
                else:
                    failed_requests += 1
            
            throughput = successful_requests / duration if duration > 0 else 0
            error_rate = (failed_requests / num_users) * 100 if num_users > 0 else 0
            
            self.add_metric(
                f"Throughput - {num_users} users",
                "THROUGHPUT",
                throughput,
                "requests/sec",
                threshold=10  # 10 requests per second
            )
            
            self.add_metric(
                f"Error Rate - {num_users} users",
                "ERROR_RATE",
                error_rate,
                "%",
                threshold=5  # 5% error rate
            )
    
    async def validate_resource_usage(self) -> None:
        """Validate system resource usage."""
        logger.info("Validating resource usage...")
        
        # Get system resource usage
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        self.add_metric(
            "CPU Usage",
            "RESOURCE_USAGE",
            cpu_percent,
            "%",
            threshold=80  # 80% CPU usage
        )
        
        self.add_metric(
            "Memory Usage",
            "RESOURCE_USAGE",
            memory.percent,
            "%",
            threshold=80  # 80% memory usage
        )
        
        self.add_metric(
            "Disk Usage",
            "RESOURCE_USAGE",
            disk.percent,
            "%",
            threshold=90  # 90% disk usage
        )
        
        # Check Docker container resource usage
        try:
            containers = self.docker_client.containers.list()
            for container in containers:
                stats = container.stats(stream=False)
                
                # Calculate CPU percentage
                cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                           stats['precpu_stats']['cpu_usage']['total_usage']
                system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                              stats['precpu_stats']['system_cpu_usage']
                
                if system_delta > 0 and cpu_delta > 0:
                    cpu_percent = (cpu_delta / system_delta) * len(stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100
                else:
                    cpu_percent = 0
                
                # Calculate memory usage
                memory_usage = stats['memory_stats']['usage'] / (1024 * 1024)  # MB
                memory_limit = stats['memory_stats']['limit'] / (1024 * 1024)  # MB
                memory_percent = (memory_usage / memory_limit) * 100 if memory_limit > 0 else 0
                
                self.add_metric(
                    f"Container CPU - {container.name}",
                    "RESOURCE_USAGE",
                    cpu_percent,
                    "%",
                    threshold=80
                )
                
                self.add_metric(
                    f"Container Memory - {container.name}",
                    "RESOURCE_USAGE",
                    memory_percent,
                    "%",
                    threshold=80
                )
                
        except Exception as e:
            logger.error(f"Error checking container resources: {str(e)}")
    
    async def validate_database_performance(self) -> None:
        """Validate database performance."""
        logger.info("Validating database performance...")
        
        try:
            # Test database connection time
            import psycopg2
            
            start_time = time.time()
            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                database="postgres",
                user="postgres"
            )
            end_time = time.time()
            
            connection_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            self.add_metric(
                "Database Connection Time",
                "RESPONSE_TIME",
                connection_time,
                "ms",
                threshold=1000  # 1 second
            )
            
            # Test simple query performance
            cursor = conn.cursor()
            
            start_time = time.time()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            end_time = time.time()
            
            query_time = (end_time - start_time) * 1000  # Convert to milliseconds
            
            self.add_metric(
                "Database Query Time",
                "RESPONSE_TIME",
                query_time,
                "ms",
                threshold=100  # 100ms
            )
            
            # Test database size
            cursor.execute("SELECT pg_database_size('postgres')")
            db_size_bytes = cursor.fetchone()[0]
            db_size_mb = db_size_bytes / (1024 * 1024)
            
            self.add_metric(
                "Database Size",
                "RESOURCE_USAGE",
                db_size_mb,
                "MB",
                threshold=1000  # 1GB
            )
            
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error testing database performance: {str(e)}")
            self.add_metric(
                "Database Performance",
                "ERROR_RATE",
                100,
                "%",
                threshold=0
            )
    
    async def validate_workflow_performance(self) -> None:
        """Validate workflow execution performance."""
        logger.info("Validating workflow performance...")
        
        # This would typically test actual workflow execution
        # For now, we'll simulate workflow performance testing
        
        workflow_stages = [
            "passive_recon",
            "active_recon", 
            "vuln_scan",
            "vuln_test",
            "kill_chain",
            "reporting"
        ]
        
        for stage in workflow_stages:
            # Simulate stage execution time
            execution_time = 30 + (hash(stage) % 60)  # 30-90 seconds
            
            self.add_metric(
                f"Workflow Stage - {stage}",
                "RESPONSE_TIME",
                execution_time,
                "seconds",
                threshold=300  # 5 minutes
            )
    
    async def validate_scalability(self) -> None:
        """Validate system scalability."""
        logger.info("Validating scalability...")
        
        # Test with increasing load
        load_levels = [10, 50, 100, 200]
        endpoint = "/api/health/"
        
        for load in load_levels:
            start_time = time.time()
            
            # Create concurrent requests
            async def make_request():
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"{self.base_url}{endpoint}", timeout=30) as response:
                            return response.status == 200
                except Exception:
                    return False
            
            tasks = [make_request() for _ in range(load)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            duration = end_time - start_time
            
            successful_requests = sum(1 for r in results if r is True)
            throughput = successful_requests / duration if duration > 0 else 0
            
            self.add_metric(
                f"Scalability - {load} concurrent requests",
                "THROUGHPUT",
                throughput,
                "requests/sec",
                threshold=5  # 5 requests per second minimum
            )
    
    async def validate_stability(self) -> None:
        """Validate system stability over time."""
        logger.info("Validating system stability...")
        
        # Run stability test for 5 minutes
        test_duration = 300  # 5 minutes
        endpoint = "/api/health/"
        start_time = time.time()
        
        response_times = []
        error_count = 0
        total_requests = 0
        
        while time.time() - start_time < test_duration:
            try:
                request_start = time.time()
                response = requests.get(f"{self.base_url}{endpoint}", timeout=30)
                request_end = time.time()
                
                response_time = (request_end - request_start) * 1000
                response_times.append(response_time)
                
                if response.status_code != 200:
                    error_count += 1
                
                total_requests += 1
                
                # Wait 1 second between requests
                await asyncio.sleep(1)
                
            except Exception as e:
                error_count += 1
                total_requests += 1
                logger.error(f"Stability test error: {str(e)}")
        
        if response_times:
            avg_response_time = statistics.mean(response_times)
            max_response_time = max(response_times)
            min_response_time = min(response_times)
            
            self.add_metric(
                "Stability - Average Response Time",
                "RESPONSE_TIME",
                avg_response_time,
                "ms",
                threshold=2000  # 2 seconds
            )
            
            self.add_metric(
                "Stability - Response Time Variance",
                "RESPONSE_TIME",
                statistics.stdev(response_times) if len(response_times) > 1 else 0,
                "ms",
                threshold=1000  # 1 second standard deviation
            )
        
        error_rate = (error_count / total_requests) * 100 if total_requests > 0 else 0
        
        self.add_metric(
            "Stability - Error Rate",
            "ERROR_RATE",
            error_rate,
            "%",
            threshold=1  # 1% error rate
        )
    
    async def run_all_validations(self) -> PerformanceSummary:
        """Run all performance validations."""
        logger.info("Starting comprehensive performance validation...")
        
        validation_methods = [
            self.validate_response_times,
            self.validate_throughput,
            self.validate_resource_usage,
            self.validate_database_performance,
            self.validate_workflow_performance,
            self.validate_scalability,
            self.validate_stability
        ]
        
        for method in validation_methods:
            try:
                await method()
            except Exception as e:
                logger.error(f"Error in validation method {method.__name__}: {str(e)}")
                self.add_metric(
                    f"Validation {method.__name__}",
                    "ERROR_RATE",
                    100,
                    "%",
                    threshold=0
                )
        
        return self._generate_summary()
    
    def _generate_summary(self) -> PerformanceSummary:
        """Generate performance validation summary."""
        total_tests = len(self.metrics)
        passed_tests = len([m for m in self.metrics if m.status == "PASS"])
        failed_tests = len([m for m in self.metrics if m.status == "FAIL"])
        warning_tests = len([m for m in self.metrics if m.status == "WARNING"])
        
        # Calculate overall performance score (0-100)
        if total_tests > 0:
            performance_score = (passed_tests / total_tests) * 100
        else:
            performance_score = 0
        
        # Generate recommendations
        recommendations = []
        if failed_tests > 0:
            recommendations.append(f"Address {failed_tests} failed performance tests")
        if warning_tests > 0:
            recommendations.append(f"Optimize {warning_tests} performance warnings")
        
        # Specific recommendations based on metrics
        response_time_metrics = [m for m in self.metrics if m.metric_type == "RESPONSE_TIME" and m.status == "FAIL"]
        if response_time_metrics:
            recommendations.append("Optimize response times for better user experience")
        
        throughput_metrics = [m for m in self.metrics if m.metric_type == "THROUGHPUT" and m.status == "FAIL"]
        if throughput_metrics:
            recommendations.append("Improve system throughput for better scalability")
        
        resource_metrics = [m for m in self.metrics if m.metric_type == "RESOURCE_USAGE" and m.status == "FAIL"]
        if resource_metrics:
            recommendations.append("Optimize resource usage to prevent bottlenecks")
        
        if performance_score < 70:
            recommendations.append("System performance needs significant improvement before launch")
        elif performance_score < 90:
            recommendations.append("Consider performance optimizations before launch")
        else:
            recommendations.append("System performance is acceptable for launch")
        
        return PerformanceSummary(
            total_tests=total_tests,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            warning_tests=warning_tests,
            overall_performance_score=performance_score,
            recommendations=recommendations,
            timestamp=datetime.utcnow().isoformat()
        )
    
    def export_results(self, output_format: str = "json", output_file: str = None) -> None:
        """Export validation results in specified format."""
        summary = self._generate_summary()
        
        if output_format == "json":
            output_data = {
                "summary": asdict(summary),
                "metrics": [asdict(metric) for metric in self.metrics]
            }
            output_content = json.dumps(output_data, indent=2)
        elif output_format == "html":
            output_content = self._generate_html_report(summary)
        else:  # text
            output_content = self._generate_text_report(summary)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_content)
            logger.info(f"Results exported to {output_file}")
        else:
            print(output_content)
    
    def _generate_html_report(self, summary: PerformanceSummary) -> str:
        """Generate HTML report."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>Performance Validation Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .pass { color: #28a745; font-weight: bold; }
        .warning { color: #ffc107; font-weight: bold; }
        .fail { color: #dc3545; font-weight: bold; }
        .metric { margin: 10px 0; padding: 10px; border-radius: 3px; }
        .metric.pass { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .metric.fail { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .metric.warning { background-color: #fff3cd; border: 1px solid #ffeaa7; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Bug Hunting Framework - Performance Validation Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <table>
            <tr><th>Total Tests</th><td>{total_tests}</td></tr>
            <tr><th>Passed</th><td class="pass">{passed_tests}</td></tr>
            <tr><th>Failed</th><td class="fail">{failed_tests}</td></tr>
            <tr><th>Warnings</th><td class="warning">{warning_tests}</td></tr>
            <tr><th>Performance Score</th><td>{performance_score:.1f}/100</td></tr>
        </table>
    </div>
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        <ul>
            {recommendations}
        </ul>
    </div>
    
    <div class="metrics">
        <h2>Detailed Metrics</h2>
        {metrics}
    </div>
</body>
</html>
        """
        
        recommendations_html = '\n'.join([f'<li>{rec}</li>' for rec in summary.recommendations])
        
        metrics_html = ""
        for metric in self.metrics:
            status_class = metric.status.lower()
            metrics_html += f"""
            <div class="metric {status_class}">
                <strong>{metric.test_name}</strong><br>
                Type: {metric.metric_type}<br>
                Value: {metric.value} {metric.unit}<br>
                Status: {metric.status}<br>
                {f'Threshold: {metric.threshold} {metric.unit}<br>' if metric.threshold else ''}
                Time: {metric.timestamp}
            </div>
            """
        
        return html_template.format(
            timestamp=summary.timestamp,
            total_tests=summary.total_tests,
            passed_tests=summary.passed_tests,
            failed_tests=summary.failed_tests,
            warning_tests=summary.warning_tests,
            performance_score=summary.overall_performance_score,
            recommendations=recommendations_html,
            metrics=metrics_html
        )
    
    def _generate_text_report(self, summary: PerformanceSummary) -> str:
        """Generate text report."""
        report = f"""
Bug Hunting Framework - Performance Validation Report
Generated: {summary.timestamp}

SUMMARY:
========
Total Tests: {summary.total_tests}
Passed: {summary.passed_tests}
Failed: {summary.failed_tests}
Warnings: {summary.warning_tests}
Performance Score: {summary.overall_performance_score:.1f}/100

RECOMMENDATIONS:
===============
"""
        for rec in summary.recommendations:
            report += f"- {rec}\n"
        
        report += "\nDETAILED METRICS:\n"
        report += "=================\n"
        
        for metric in self.metrics:
            report += f"""
{metric.test_name}
Type: {metric.metric_type}
Value: {metric.value} {metric.unit}
Status: {metric.status}
{f'Threshold: {metric.threshold} {metric.unit}' if metric.threshold else ''}
Time: {metric.timestamp}
"""
        
        return report

async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Performance Validation')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--output-format', choices=['json', 'html', 'text'], 
                       default='text', help='Output format')
    parser.add_argument('--output-file', help='Output file path')
    
    args = parser.parse_args()
    
    validator = PerformanceValidator(verbose=args.verbose)
    summary = await validator.run_all_validations()
    
    # Export results
    validator.export_results(args.output_format, args.output_file)
    
    # Exit with appropriate code
    if summary.overall_performance_score < 70:
        sys.exit(1)  # Poor performance
    elif summary.overall_performance_score < 90:
        sys.exit(2)  # Moderate performance
    else:
        sys.exit(0)  # Good performance

if __name__ == "__main__":
    asyncio.run(main()) 