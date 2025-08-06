"""
Performance and Scalability Testing Module

This module provides comprehensive testing for performance and scalability aspects including:
- System performance under various load conditions
- Resource usage and optimization opportunities
- Scalability and concurrent user handling
- Performance monitoring and alerting
- Load testing and stress testing
- Performance benchmarking and optimization

Author: AI Assistant
Date: 2025-01-27
"""

import asyncio
import json
import time
import psutil
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Callable
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import statistics
import requests
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport, TimeoutException
from api.asgi import application


@dataclass
class LoadTestConfig:
    """Configuration for a load test."""
    name: str
    description: str
    concurrent_users: int
    duration: int  # seconds
    ramp_up_time: int  # seconds
    target_rps: float  # requests per second
    timeout: float = 30.0


@dataclass
class PerformanceMetric:
    """Performance metric measurement."""
    name: str
    value: float
    unit: str
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceTestResult:
    """Result of a performance test."""
    test_name: str
    test_type: str
    status: str  # "PASS", "FAIL", "WARNING"
    duration: float
    metrics: List[PerformanceMetric]
    summary: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class PerformanceMonitor:
    """System performance monitoring and metrics collection."""
    
    def __init__(self):
        self.metrics: List[PerformanceMetric] = []
        self.monitoring_active = False
        self.monitor_thread = None
    
    def start_monitoring(self, interval: float = 1.0):
        """Start continuous performance monitoring."""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop performance monitoring."""
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join()
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop."""
        while self.monitoring_active:
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Collect network metrics
                network = psutil.net_io_counters()
                
                # Store metrics
                timestamp = datetime.now(timezone.utc)
                
                self.metrics.extend([
                    PerformanceMetric("cpu_usage", cpu_percent, "percent", timestamp),
                    PerformanceMetric("memory_usage", memory.percent, "percent", timestamp),
                    PerformanceMetric("memory_available", memory.available / (1024**3), "GB", timestamp),
                    PerformanceMetric("disk_usage", disk.percent, "percent", timestamp),
                    PerformanceMetric("disk_free", disk.free / (1024**3), "GB", timestamp),
                    PerformanceMetric("network_bytes_sent", network.bytes_sent, "bytes", timestamp),
                    PerformanceMetric("network_bytes_recv", network.bytes_recv, "bytes", timestamp)
                ])
                
                time.sleep(interval)
            
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(interval)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics."""
        if not self.metrics:
            return {}
        
        summary = {}
        metric_names = set(m.name for m in self.metrics)
        
        for metric_name in metric_names:
            metric_values = [m.value for m in self.metrics if m.name == metric_name]
            if metric_values:
                summary[metric_name] = {
                    "min": min(metric_values),
                    "max": max(metric_values),
                    "avg": statistics.mean(metric_values),
                    "median": statistics.median(metric_values),
                    "count": len(metric_values)
                }
        
        return summary


class PerformanceAndScalabilityTester:
    """Comprehensive performance and scalability testing framework."""
    
    def __init__(self, base_url: str = "http://localhost:3000", api_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.api_url = api_url
        self.test_results: List[PerformanceTestResult] = []
        self.monitor = PerformanceMonitor()
        
        # Define load test configurations
        self.load_tests = [
            LoadTestConfig(
                name="light_load",
                description="Light load testing with 5 concurrent users",
                concurrent_users=5,
                duration=60,
                ramp_up_time=10,
                target_rps=5.0
            ),
            LoadTestConfig(
                name="medium_load",
                description="Medium load testing with 20 concurrent users",
                concurrent_users=20,
                duration=120,
                ramp_up_time=20,
                target_rps=15.0
            ),
            LoadTestConfig(
                name="heavy_load",
                description="Heavy load testing with 50 concurrent users",
                concurrent_users=50,
                duration=180,
                ramp_up_time=30,
                target_rps=30.0
            ),
            LoadTestConfig(
                name="stress_test",
                description="Stress testing with 100 concurrent users",
                concurrent_users=100,
                duration=300,
                ramp_up_time=60,
                target_rps=50.0
            )
        ]
    
    async def test_api_performance(self, endpoint: str, method: str = "GET", 
                                 payload: Optional[Dict] = None, 
                                 iterations: int = 100) -> PerformanceTestResult:
        """Test API endpoint performance."""
        start_time = time.time()
        response_times = []
        errors = []
        
        try:
            async with AsyncClient() as client:
                for i in range(iterations):
                    try:
                        request_start = time.time()
                        
                        if method == "GET":
                            response = await client.get(f"{self.api_url}{endpoint}", timeout=30.0)
                        elif method == "POST":
                            response = await client.post(f"{self.api_url}{endpoint}", 
                                                       json=payload, timeout=30.0)
                        elif method == "PUT":
                            response = await client.put(f"{self.api_url}{endpoint}", 
                                                      json=payload, timeout=30.0)
                        elif method == "DELETE":
                            response = await client.delete(f"{self.api_url}{endpoint}", timeout=30.0)
                        
                        request_duration = time.time() - request_start
                        response_times.append(request_duration)
                        
                        if response.status_code >= 400:
                            errors.append(f"Request {i} failed with status {response.status_code}")
                    
                    except TimeoutException:
                        errors.append(f"Request {i} timed out")
                    except Exception as e:
                        errors.append(f"Request {i} failed: {str(e)}")
        
        except Exception as e:
            errors.append(f"API performance test failed: {str(e)}")
        
        duration = time.time() - start_time
        
        # Calculate metrics
        metrics = []
        if response_times:
            metrics.extend([
                PerformanceMetric("avg_response_time", statistics.mean(response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("min_response_time", min(response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("max_response_time", max(response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("median_response_time", statistics.median(response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("throughput", len(response_times) / duration, "requests/second", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("success_rate", (len(response_times) - len(errors)) / len(response_times) * 100, 
                                "percent", datetime.now(timezone.utc))
            ])
        
        # Determine status
        status = "PASS"
        if errors:
            error_rate = len(errors) / iterations
            if error_rate > 0.1:  # More than 10% errors
                status = "FAIL"
            elif error_rate > 0.05:  # More than 5% errors
                status = "WARNING"
        
        if response_times and statistics.mean(response_times) > 5.0:  # Average response time > 5s
            status = "FAIL"
        
        return PerformanceTestResult(
            test_name=f"api_performance_{endpoint.replace('/', '_')}",
            test_type="api_performance",
            status=status,
            duration=duration,
            metrics=metrics,
            summary={
                "endpoint": endpoint,
                "method": method,
                "iterations": iterations,
                "successful_requests": len(response_times),
                "failed_requests": len(errors),
                "error_rate": len(errors) / iterations if iterations > 0 else 0
            },
            errors=errors
        )
    
    async def test_concurrent_load(self, test_config: LoadTestConfig) -> PerformanceTestResult:
        """Test system performance under concurrent load."""
        start_time = time.time()
        
        # Start performance monitoring
        self.monitor.start_monitoring()
        
        # Create test data
        test_targets = [
            {"target": f"load-test-{i}.example.com", "domain": f"load-test-{i}.example.com"}
            for i in range(test_config.concurrent_users)
        ]
        
        results = []
        errors = []
        
        async def simulate_user_workload(user_id: int, target_data: Dict[str, str]):
            """Simulate a user performing a complete workflow."""
            user_start_time = time.time()
            user_results = []
            
            try:
                async with AsyncClient() as client:
                    # Simulate target creation
                    target_start = time.time()
                    target_response = await client.post(
                        f"{self.api_url}/api/targets/",
                        json=target_data,
                        timeout=test_config.timeout
                    )
                    target_duration = time.time() - target_start
                    
                    user_results.append({
                        "action": "target_creation",
                        "duration": target_duration,
                        "status": "PASS" if target_response.status_code == 200 else "FAIL",
                        "response_code": target_response.status_code
                    })
                    
                    if target_response.status_code == 200:
                        target_id = target_response.json().get("data", {}).get("id")
                        
                        # Simulate workflow operations
                        workflow_actions = [
                            ("workflow_creation", "POST", {"target_id": target_id, "stages": ["passive_recon"]}),
                            ("workflow_status", "GET", None),
                            ("target_details", "GET", None)
                        ]
                        
                        for action_name, action_method, action_payload in workflow_actions:
                            try:
                                action_start = time.time()
                                
                                if action_method == "GET":
                                    action_response = await client.get(
                                        f"{self.api_url}/api/{action_name.replace('_', '/')}/",
                                        timeout=test_config.timeout
                                    )
                                else:
                                    action_response = await client.post(
                                        f"{self.api_url}/api/{action_name.replace('_', '/')}/",
                                        json=action_payload,
                                        timeout=test_config.timeout
                                    )
                                
                                action_duration = time.time() - action_start
                                
                                user_results.append({
                                    "action": action_name,
                                    "duration": action_duration,
                                    "status": "PASS" if action_response.status_code == 200 else "FAIL",
                                    "response_code": action_response.status_code
                                })
                            
                            except Exception as e:
                                user_results.append({
                                    "action": action_name,
                                    "status": "FAIL",
                                    "error": str(e)
                                })
            
            except Exception as e:
                user_results.append({
                    "action": "user_simulation",
                    "status": "FAIL",
                    "error": str(e)
                })
            
            user_duration = time.time() - user_start_time
            return {
                "user_id": user_id,
                "duration": user_duration,
                "results": user_results
            }
        
        # Implement ramp-up strategy
        ramp_up_steps = max(1, test_config.concurrent_users // 10)
        users_per_step = test_config.concurrent_users // ramp_up_steps
        
        try:
            # Ramp up users gradually
            for step in range(ramp_up_steps):
                step_users = min(users_per_step, test_config.concurrent_users - step * users_per_step)
                step_start = step * (test_config.ramp_up_time // ramp_up_steps)
                
                # Start users for this step
                with ThreadPoolExecutor(max_workers=step_users) as executor:
                    loop = asyncio.get_event_loop()
                    tasks = [
                        loop.run_in_executor(executor, lambda: asyncio.run(simulate_user_workload(i, test_targets[i])))
                        for i in range(step * users_per_step, step * users_per_step + step_users)
                    ]
                    
                    step_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for i, result in enumerate(step_results):
                        if isinstance(result, Exception):
                            errors.append(f"User {step * users_per_step + i} simulation failed: {str(result)}")
                        else:
                            results.append(result)
                
                # Wait before next ramp-up step
                if step < ramp_up_steps - 1:
                    await asyncio.sleep(test_config.ramp_up_time // ramp_up_steps)
            
            # Maintain load for the specified duration
            await asyncio.sleep(test_config.duration)
        
        except Exception as e:
            errors.append(f"Concurrent load test failed: {str(e)}")
        
        finally:
            # Stop performance monitoring
            self.monitor.stop_monitoring()
        
        total_duration = time.time() - start_time
        
        # Calculate performance metrics
        successful_requests = sum(1 for r in results if any(ar.get("status") == "PASS" for ar in r.get("results", [])))
        all_response_times = [
            ar.get("duration", 0) for r in results 
            for ar in r.get("results", []) if ar.get("status") == "PASS" and ar.get("duration")
        ]
        
        metrics = []
        if all_response_times:
            metrics.extend([
                PerformanceMetric("avg_response_time", statistics.mean(all_response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("min_response_time", min(all_response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("max_response_time", max(all_response_times), "seconds", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("throughput", successful_requests / total_duration, "requests/second", 
                                datetime.now(timezone.utc)),
                PerformanceMetric("concurrent_users", test_config.concurrent_users, "users", 
                                datetime.now(timezone.utc))
            ])
        
        # Add system metrics
        system_metrics = self.monitor.get_metrics_summary()
        for metric_name, metric_data in system_metrics.items():
            metrics.append(PerformanceMetric(
                f"system_{metric_name}_avg", metric_data["avg"], 
                "percent" if "percent" in metric_name else "GB" if "GB" in metric_name else "bytes",
                datetime.now(timezone.utc)
            ))
        
        # Determine test status
        status = "PASS"
        if errors:
            error_rate = len(errors) / test_config.concurrent_users
            if error_rate > 0.2:  # More than 20% errors
                status = "FAIL"
            elif error_rate > 0.1:  # More than 10% errors
                status = "WARNING"
        
        if all_response_times and statistics.mean(all_response_times) > 10.0:  # Average response time > 10s
            status = "FAIL"
        
        throughput = successful_requests / total_duration if total_duration > 0 else 0
        if throughput < test_config.target_rps * 0.8:  # Less than 80% of target throughput
            status = "FAIL"
        
        return PerformanceTestResult(
            test_name=f"concurrent_load_{test_config.name}",
            test_type="load_testing",
            status=status,
            duration=total_duration,
            metrics=metrics,
            summary={
                "test_config": {
                    "concurrent_users": test_config.concurrent_users,
                    "duration": test_config.duration,
                    "ramp_up_time": test_config.ramp_up_time,
                    "target_rps": test_config.target_rps
                },
                "results": {
                    "total_users": len(results),
                    "successful_requests": successful_requests,
                    "failed_requests": len(errors),
                    "throughput": throughput,
                    "error_rate": len(errors) / test_config.concurrent_users if test_config.concurrent_users > 0 else 0
                },
                "system_metrics": system_metrics
            },
            errors=errors
        )
    
    async def test_resource_usage_optimization(self) -> PerformanceTestResult:
        """Test resource usage and identify optimization opportunities."""
        start_time = time.time()
        
        # Start monitoring
        self.monitor.start_monitoring(interval=0.5)
        
        # Perform various operations to measure resource usage
        operations = [
            ("target_creation", self._simulate_target_creation),
            ("workflow_execution", self._simulate_workflow_execution),
            ("data_retrieval", self._simulate_data_retrieval),
            ("report_generation", self._simulate_report_generation)
        ]
        
        operation_metrics = []
        errors = []
        
        for operation_name, operation_func in operations:
            try:
                # Measure resource usage before operation
                before_metrics = self._get_current_metrics()
                
                # Perform operation
                operation_start = time.time()
                await operation_func()
                operation_duration = time.time() - operation_start
                
                # Measure resource usage after operation
                after_metrics = self._get_current_metrics()
                
                # Calculate resource delta
                resource_delta = {}
                for metric_name in before_metrics:
                    if metric_name in after_metrics:
                        resource_delta[metric_name] = after_metrics[metric_name] - before_metrics[metric_name]
                
                operation_metrics.append({
                    "operation": operation_name,
                    "duration": operation_duration,
                    "resource_delta": resource_delta,
                    "status": "PASS"
                })
            
            except Exception as e:
                errors.append(f"Operation {operation_name} failed: {str(e)}")
                operation_metrics.append({
                    "operation": operation_name,
                    "status": "FAIL",
                    "error": str(e)
                })
        
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        duration = time.time() - start_time
        
        # Analyze resource usage patterns
        optimization_opportunities = self._analyze_optimization_opportunities(operation_metrics)
        
        # Generate metrics
        metrics = []
        system_metrics = self.monitor.get_metrics_summary()
        for metric_name, metric_data in system_metrics.items():
            metrics.append(PerformanceMetric(
                f"resource_{metric_name}_avg", metric_data["avg"], 
                "percent" if "percent" in metric_name else "GB" if "GB" in metric_name else "bytes",
                datetime.now(timezone.utc)
            ))
        
        # Determine status
        status = "PASS"
        if optimization_opportunities:
            status = "WARNING"
        
        if errors:
            status = "FAIL"
        
        return PerformanceTestResult(
            test_name="resource_usage_optimization",
            test_type="resource_analysis",
            status=status,
            duration=duration,
            metrics=metrics,
            summary={
                "operations": operation_metrics,
                "optimization_opportunities": optimization_opportunities,
                "system_metrics": system_metrics
            },
            errors=errors
        )
    
    async def _simulate_target_creation(self):
        """Simulate target creation operation."""
        async with AsyncClient() as client:
            await client.post(
                f"{self.api_url}/api/targets/",
                json={"target": "optimization-test.example.com", "domain": "optimization-test.example.com"},
                timeout=30.0
            )
    
    async def _simulate_workflow_execution(self):
        """Simulate workflow execution operation."""
        async with AsyncClient() as client:
            # Create target first
            target_response = await client.post(
                f"{self.api_url}/api/targets/",
                json={"target": "workflow-test.example.com", "domain": "workflow-test.example.com"},
                timeout=30.0
            )
            
            if target_response.status_code == 200:
                target_id = target_response.json().get("data", {}).get("id")
                
                # Create workflow
                await client.post(
                    f"{self.api_url}/api/workflows/",
                    json={"target_id": target_id, "stages": ["passive_recon"]},
                    timeout=30.0
                )
    
    async def _simulate_data_retrieval(self):
        """Simulate data retrieval operation."""
        async with AsyncClient() as client:
            await client.get(f"{self.api_url}/api/targets/", timeout=30.0)
            await client.get(f"{self.api_url}/api/workflows/", timeout=30.0)
    
    async def _simulate_report_generation(self):
        """Simulate report generation operation."""
        async with AsyncClient() as client:
            await client.post(
                f"{self.api_url}/api/reports/generate/",
                json={"target_id": "test-id", "report_type": "executive"},
                timeout=30.0
            )
    
    def _get_current_metrics(self) -> Dict[str, float]:
        """Get current system metrics."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "memory_available": memory.available / (1024**3),
                "disk_usage": disk.percent,
                "disk_free": disk.free / (1024**3)
            }
        except Exception:
            return {}
    
    def _analyze_optimization_opportunities(self, operation_metrics: List[Dict]) -> List[str]:
        """Analyze operation metrics for optimization opportunities."""
        opportunities = []
        
        for op_metric in operation_metrics:
            if op_metric.get("status") != "PASS":
                continue
            
            operation = op_metric["operation"]
            duration = op_metric.get("duration", 0)
            resource_delta = op_metric.get("resource_delta", {})
            
            # Check for slow operations
            if duration > 5.0:
                opportunities.append(f"Optimize {operation}: operation takes {duration:.2f}s")
            
            # Check for high memory usage
            memory_delta = resource_delta.get("memory_usage", 0)
            if memory_delta > 10.0:  # More than 10% memory increase
                opportunities.append(f"Optimize {operation}: high memory usage ({memory_delta:.1f}%)")
            
            # Check for high CPU usage
            cpu_delta = resource_delta.get("cpu_usage", 0)
            if cpu_delta > 50.0:  # More than 50% CPU increase
                opportunities.append(f"Optimize {operation}: high CPU usage ({cpu_delta:.1f}%)")
        
        return opportunities
    
    async def test_scalability_limits(self) -> PerformanceTestResult:
        """Test system scalability limits and breaking points."""
        start_time = time.time()
        
        # Test with increasing load until system breaks
        load_levels = [10, 25, 50, 100, 200, 500]
        breaking_point = None
        errors = []
        
        for load_level in load_levels:
            try:
                test_config = LoadTestConfig(
                    name=f"scalability_{load_level}",
                    description=f"Scalability test with {load_level} users",
                    concurrent_users=load_level,
                    duration=30,  # Shorter duration for scalability testing
                    ramp_up_time=10,
                    target_rps=load_level * 0.5
                )
                
                result = await self.test_concurrent_load(test_config)
                
                if result.status == "FAIL":
                    breaking_point = load_level
                    errors.append(f"System broke at {load_level} concurrent users")
                    break
                
                # Check if performance degrades significantly
                avg_response_time = next(
                    (m.value for m in result.metrics if m.name == "avg_response_time"), 0
                )
                
                if avg_response_time > 10.0:  # Response time > 10s
                    breaking_point = load_level
                    errors.append(f"Performance degraded at {load_level} concurrent users (avg response time: {avg_response_time:.2f}s)")
                    break
            
            except Exception as e:
                breaking_point = load_level
                errors.append(f"System failed at {load_level} concurrent users: {str(e)}")
                break
        
        duration = time.time() - start_time
        
        # Generate metrics
        metrics = [
            PerformanceMetric("max_concurrent_users", breaking_point or load_levels[-1], "users", 
                            datetime.now(timezone.utc)),
            PerformanceMetric("scalability_score", (breaking_point or load_levels[-1]) / 100, "ratio", 
                            datetime.now(timezone.utc))
        ]
        
        # Determine status
        status = "PASS"
        if breaking_point and breaking_point < 100:
            status = "FAIL"
        elif breaking_point and breaking_point < 200:
            status = "WARNING"
        
        return PerformanceTestResult(
            test_name="scalability_limits",
            test_type="scalability_testing",
            status=status,
            duration=duration,
            metrics=metrics,
            summary={
                "breaking_point": breaking_point,
                "max_tested": load_levels[-1],
                "scalability_score": (breaking_point or load_levels[-1]) / 100
            },
            errors=errors
        )
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate a comprehensive performance report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r.status == "PASS")
        failed_tests = sum(1 for r in self.test_results if r.status == "FAIL")
        warning_tests = sum(1 for r in self.test_results if r.status == "WARNING")
        
        total_duration = sum(r.duration for r in self.test_results)
        
        # Aggregate metrics across all tests
        all_metrics = {}
        for result in self.test_results:
            for metric in result.metrics:
                if metric.name not in all_metrics:
                    all_metrics[metric.name] = []
                all_metrics[metric.name].append(metric.value)
        
        # Calculate aggregated metrics
        aggregated_metrics = {}
        for metric_name, values in all_metrics.items():
            if values:
                aggregated_metrics[metric_name] = {
                    "min": min(values),
                    "max": max(values),
                    "avg": statistics.mean(values),
                    "median": statistics.median(values),
                    "count": len(values)
                }
        
        return {
            "summary": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "warning_tests": warning_tests,
                "success_rate": (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                "total_duration": total_duration
            },
            "aggregated_metrics": aggregated_metrics,
            "test_results": [
                {
                    "test_name": r.test_name,
                    "test_type": r.test_type,
                    "status": r.status,
                    "duration": r.duration,
                    "summary": r.summary,
                    "errors": r.errors,
                    "warnings": r.warnings
                }
                for r in self.test_results
            ],
            "recommendations": self._generate_performance_recommendations()
        }
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance recommendations based on test results."""
        recommendations = []
        
        failed_tests = [r for r in self.test_results if r.status == "FAIL"]
        warning_tests = [r for r in self.test_results if r.status == "WARNING"]
        
        if failed_tests:
            recommendations.append(f"Address {len(failed_tests)} failed performance tests")
        
        if warning_tests:
            recommendations.append(f"Review {len(warning_tests)} tests with performance warnings")
        
        # Analyze specific performance issues
        for result in self.test_results:
            if result.test_type == "load_testing" and result.status in ["FAIL", "WARNING"]:
                avg_response_time = next(
                    (m.value for m in result.metrics if m.name == "avg_response_time"), 0
                )
                if avg_response_time > 5.0:
                    recommendations.append(f"Optimize response times for {result.test_name} (avg: {avg_response_time:.2f}s)")
            
            elif result.test_type == "resource_analysis":
                optimization_opportunities = result.summary.get("optimization_opportunities", [])
                if optimization_opportunities:
                    recommendations.extend(optimization_opportunities[:3])  # Top 3 opportunities
        
        return recommendations


# Test functions for pytest integration
@pytest_asyncio.fixture
async def performance_tester():
    """Fixture for performance tester."""
    return PerformanceAndScalabilityTester()


@pytest.mark.asyncio
async def test_api_performance_targets(performance_tester):
    """Test API performance for targets endpoint."""
    result = await performance_tester.test_api_performance("/api/targets/", "GET")
    performance_tester.test_results.append(result)
    assert result.status == "PASS", f"API performance test failed: {result.errors}"


@pytest.mark.asyncio
async def test_api_performance_workflows(performance_tester):
    """Test API performance for workflows endpoint."""
    result = await performance_tester.test_api_performance("/api/workflows/", "GET")
    performance_tester.test_results.append(result)
    assert result.status == "PASS", f"API performance test failed: {result.errors}"


@pytest.mark.asyncio
async def test_light_load(performance_tester):
    """Test system performance under light load."""
    light_load_test = LoadTestConfig(
        name="light_load",
        description="Light load testing with 5 concurrent users",
        concurrent_users=5,
        duration=60,
        ramp_up_time=10,
        target_rps=5.0
    )
    result = await performance_tester.test_concurrent_load(light_load_test)
    performance_tester.test_results.append(result)
    assert result.status == "PASS", f"Light load test failed: {result.errors}"


@pytest.mark.asyncio
async def test_resource_usage_optimization(performance_tester):
    """Test resource usage and optimization opportunities."""
    result = await performance_tester.test_resource_usage_optimization()
    performance_tester.test_results.append(result)
    assert result.status in ["PASS", "WARNING"], f"Resource usage test failed: {result.errors}"


@pytest.mark.asyncio
async def test_scalability_limits(performance_tester):
    """Test system scalability limits."""
    result = await performance_tester.test_scalability_limits()
    performance_tester.test_results.append(result)
    assert result.status in ["PASS", "WARNING"], f"Scalability test failed: {result.errors}"


if __name__ == "__main__":
    # Run tests directly
    async def main():
        tester = PerformanceAndScalabilityTester()
        
        # Run all tests
        tests = [
            tester.test_api_performance("/api/targets/", "GET"),
            tester.test_api_performance("/api/workflows/", "GET"),
            tester.test_resource_usage_optimization(),
            tester.test_scalability_limits()
        ]
        
        # Add load tests
        for test_config in tester.load_tests:
            tests.append(tester.test_concurrent_load(test_config))
        
        # Execute all tests
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                print(f"Test failed with exception: {result}")
            else:
                tester.test_results.append(result)
        
        # Generate and print report
        report = tester.generate_performance_report()
        print(json.dumps(report, indent=2, default=str))
    
    asyncio.run(main()) 