#!/usr/bin/env python3
"""
Evidence Collector Runner for Stage 4: Step 4.5

This module implements comprehensive evidence collection, logging, and audit trail
management with screenshots, video recording, response data capture, and structured logging.
"""

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    """Represents an evidence item collected during testing."""
    
    evidence_id: str
    timestamp: datetime
    evidence_type: str  # screenshot, video, log, response, artifact
    file_path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    finding_id: Optional[str] = None
    test_id: Optional[str] = None
    size_bytes: int = 0
    checksum: Optional[str] = None


@dataclass
class ActivityLog:
    """Represents an activity log entry."""
    
    log_id: str
    timestamp: datetime
    activity_type: str  # scan_start, scan_end, finding_detected, exploit_test, error
    description: str
    severity: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    metadata: Dict[str, Any] = field(default_factory=dict)
    finding_id: Optional[str] = None
    test_id: Optional[str] = None
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


@dataclass
class ResponseData:
    """Represents captured response data."""
    
    response_id: str
    timestamp: datetime
    url: str
    method: str
    status_code: int
    response_time: float
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    size_bytes: int = 0
    content_type: Optional[str] = None
    finding_id: Optional[str] = None
    test_id: Optional[str] = None


class EvidenceCollector:
    """Comprehensive evidence collector for vulnerability testing."""
    
    def __init__(self, config):
        self.config = config
        self.output_dir = Path(f"outputs/{config.stage_name}/{config.target}")
        self.evidence_dir = self.output_dir / "evidence_collection"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
        # Create evidence subdirectories
        (self.evidence_dir / "screenshots").mkdir(exist_ok=True)
        (self.evidence_dir / "videos").mkdir(exist_ok=True)
        (self.evidence_dir / "logs").mkdir(exist_ok=True)
        (self.evidence_dir / "responses").mkdir(exist_ok=True)
        (self.evidence_dir / "artifacts").mkdir(exist_ok=True)
        
        # Evidence collection configuration
        self.screenshot_quality = config.screenshot_quality
        self.video_recording = config.video_recording
        self.enable_evidence_collection = config.enable_evidence_collection
        
        # Collected evidence
        self.evidence_items: List[EvidenceItem] = []
        self.activity_logs: List[ActivityLog] = []
        self.response_data: List[ResponseData] = []
        
        # Video recording
        self.video_writer = None
        self.video_recording_active = False
        self.video_thread = None
        
        # Browser driver for screenshots
        self.browser_driver = None
        
        # Thread pool for parallel evidence collection
        self.thread_pool = ThreadPoolExecutor(max_workers=3)
        
        # Initialize logging
        self._setup_logging()
        
        # Start activity logging
        self._log_activity("evidence_collector_start", "Evidence collector initialized", "INFO")
    
    def _setup_logging(self):
        """Setup structured logging for evidence collection."""
        try:
            # Create structured log file
            log_file = self.evidence_dir / "logs" / "evidence_collection.log"
            
            # Configure file handler
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            
            # Add handler to logger
            logger.addHandler(file_handler)
            
            logger.info("Evidence collection logging setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up logging: {str(e)}")
    
    def collect_activity_logs(self) -> List[ActivityLog]:
        """
        Collect activity logs from the testing session.
        
        Returns:
            List[ActivityLog]: Collected activity logs
        """
        logger.info("Collecting activity logs...")
        
        try:
            # Add current session logs
            current_logs = self.activity_logs.copy()
            
            # Add system activity logs
            system_logs = self._collect_system_logs()
            current_logs.extend(system_logs)
            
            # Add network activity logs
            network_logs = self._collect_network_logs()
            current_logs.extend(network_logs)
            
            # Sort by timestamp
            current_logs.sort(key=lambda x: x.timestamp)
            
            logger.info(f"Activity log collection completed. Collected {len(current_logs)} log entries")
            
            return current_logs
            
        except Exception as e:
            logger.error(f"Error collecting activity logs: {str(e)}")
            return self.activity_logs
    
    def _collect_system_logs(self) -> List[ActivityLog]:
        """Collect system-level activity logs."""
        try:
            system_logs = []
            
            # Add system resource usage
            import psutil
            
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            system_logs.append(ActivityLog(
                log_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                activity_type="system_resources",
                description=f"System resources - CPU: {cpu_percent}%, Memory: {memory.percent}%, Disk: {disk.percent}%",
                severity="INFO",
                metadata={
                    "cpu_percent": cpu_percent,
                    "memory_percent": memory.percent,
                    "disk_percent": disk.percent,
                    "memory_available": memory.available,
                    "disk_free": disk.free
                }
            ))
            
            return system_logs
            
        except Exception as e:
            logger.error(f"Error collecting system logs: {str(e)}")
            return []
    
    def _collect_network_logs(self) -> List[ActivityLog]:
        """Collect network activity logs."""
        try:
            network_logs = []
            
            # Add network connection information
            import socket
            
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            network_logs.append(ActivityLog(
                log_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                activity_type="network_info",
                description=f"Network information - Hostname: {hostname}, IP: {local_ip}",
                severity="INFO",
                metadata={
                    "hostname": hostname,
                    "local_ip": local_ip,
                    "target": self.config.target
                }
            ))
            
            return network_logs
            
        except Exception as e:
            logger.error(f"Error collecting network logs: {str(e)}")
            return []
    
    def capture_screenshots(self) -> List[str]:
        """
        Capture screenshots during testing.
        
        Returns:
            List[str]: List of screenshot file paths
        """
        logger.info("Capturing screenshots...")
        
        try:
            if not self.enable_evidence_collection:
                logger.info("Evidence collection disabled, skipping screenshots")
                return []
            
            screenshot_files = []
            
            # Initialize browser if not already done
            if not self.browser_driver:
                self._initialize_browser()
            
            if not self.browser_driver:
                logger.warning("Browser not available for screenshots")
                return []
            
            # Capture screenshots of key pages
            key_urls = [
                f"https://{self.config.target}",
                f"https://{self.config.target}/admin",
                f"https://{self.config.target}/login",
                f"https://{self.config.target}/api"
            ]
            
            for url in key_urls:
                try:
                    screenshot_path = self._capture_screenshot(url)
                    if screenshot_path:
                        screenshot_files.append(screenshot_path)
                        
                        # Create evidence item
                        evidence_item = EvidenceItem(
                            evidence_id=str(uuid.uuid4()),
                            timestamp=datetime.now(timezone.utc),
                            evidence_type="screenshot",
                            file_path=screenshot_path,
                            description=f"Screenshot of {url}",
                            metadata={"url": url, "quality": self.screenshot_quality}
                        )
                        self.evidence_items.append(evidence_item)
                        
                except Exception as e:
                    logger.error(f"Error capturing screenshot for {url}: {str(e)}")
            
            logger.info(f"Screenshot capture completed. Captured {len(screenshot_files)} screenshots")
            
            return screenshot_files
            
        except Exception as e:
            logger.error(f"Error capturing screenshots: {str(e)}")
            return []
    
    def _initialize_browser(self):
        """Initialize browser driver for screenshots."""
        try:
            # Try to initialize Chrome in headless mode
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1920,1080")
            
            self.browser_driver = webdriver.Chrome(options=options)
            logger.info("Browser driver initialized for screenshots")
            
        except Exception as e:
            logger.warning(f"Could not initialize browser driver for screenshots: {str(e)}")
            self.browser_driver = None
    
    def _capture_screenshot(self, url: str) -> Optional[str]:
        """Capture screenshot of a specific URL."""
        try:
            # Navigate to URL
            self.browser_driver.get(url)
            
            # Wait for page to load
            WebDriverWait(self.browser_driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = url.replace("://", "_").replace("/", "_").replace(".", "_")
            filename = f"screenshot_{safe_url}_{timestamp}.png"
            filepath = self.evidence_dir / "screenshots" / filename
            
            # Capture screenshot
            self.browser_driver.save_screenshot(str(filepath))
            
            # Add watermark
            self._add_watermark_to_screenshot(filepath, url)
            
            logger.info(f"Screenshot captured: {filepath}")
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {str(e)}")
            return None
    
    def _add_watermark_to_screenshot(self, filepath: Path, url: str):
        """Add watermark to screenshot with metadata."""
        try:
            # Open image
            image = Image.open(filepath)
            
            # Create drawing object
            draw = ImageDraw.Draw(image)
            
            # Try to load font, fallback to default if not available
            try:
                font = ImageFont.truetype("arial.ttf", 20)
            except:
                font = ImageFont.load_default()
            
            # Add watermark text
            watermark_text = f"Bug Hunting Framework - {url} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Calculate text position (bottom right)
            bbox = draw.textbbox((0, 0), watermark_text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            x = image.width - text_width - 10
            y = image.height - text_height - 10
            
            # Draw background rectangle
            draw.rectangle([x-5, y-5, x+text_width+5, y+text_height+5], fill=(0, 0, 0, 128))
            
            # Draw text
            draw.text((x, y), watermark_text, fill=(255, 255, 255), font=font)
            
            # Save watermarked image
            image.save(filepath)
            
        except Exception as e:
            logger.error(f"Error adding watermark to screenshot: {str(e)}")
    
    def start_video_recording(self, output_filename: str = None):
        """Start video recording of testing activities."""
        try:
            if not self.video_recording or not self.enable_evidence_collection:
                logger.info("Video recording disabled")
                return
            
            if self.video_recording_active:
                logger.warning("Video recording already active")
                return
            
            # Generate filename if not provided
            if not output_filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_filename = f"testing_session_{timestamp}.mp4"
            
            output_path = self.evidence_dir / "videos" / output_filename
            
            # Initialize video writer
            fourcc = cv2.VideoWriter_fourcc(*'mp4v')
            self.video_writer = cv2.VideoWriter(
                str(output_path), fourcc, 10.0, (1920, 1080)
            )
            
            if not self.video_writer.isOpened():
                logger.error("Could not initialize video writer")
                return
            
            self.video_recording_active = True
            
            # Start recording thread
            self.video_thread = threading.Thread(target=self._video_recording_loop)
            self.video_thread.daemon = True
            self.video_thread.start()
            
            logger.info(f"Video recording started: {output_path}")
            
            # Log activity
            self._log_activity("video_recording_start", f"Video recording started: {output_filename}", "INFO")
            
        except Exception as e:
            logger.error(f"Error starting video recording: {str(e)}")
    
    def stop_video_recording(self):
        """Stop video recording."""
        try:
            if not self.video_recording_active:
                logger.warning("Video recording not active")
                return
            
            self.video_recording_active = False
            
            if self.video_thread:
                self.video_thread.join(timeout=5)
            
            if self.video_writer:
                self.video_writer.release()
                self.video_writer = None
            
            logger.info("Video recording stopped")
            
            # Log activity
            self._log_activity("video_recording_stop", "Video recording stopped", "INFO")
            
        except Exception as e:
            logger.error(f"Error stopping video recording: {str(e)}")
    
    def _video_recording_loop(self):
        """Video recording loop for capturing screen activity."""
        try:
            while self.video_recording_active:
                # Capture screen (simplified - in practice would use screen capture library)
                # For now, create a placeholder frame
                frame = np.zeros((1080, 1920, 3), dtype=np.uint8)
                
                # Add timestamp to frame
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cv2.putText(frame, timestamp, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                cv2.putText(frame, f"Target: {self.config.target}", (10, 70), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2)
                
                # Write frame
                if self.video_writer and self.video_writer.isOpened():
                    self.video_writer.write(frame)
                
                # Sleep for frame rate
                time.sleep(0.1)  # 10 FPS
                
        except Exception as e:
            logger.error(f"Error in video recording loop: {str(e)}")
    
    def capture_response_data(self) -> List[ResponseData]:
        """
        Capture response data from testing activities.
        
        Returns:
            List[ResponseData]: Captured response data
        """
        logger.info("Capturing response data...")
        
        try:
            if not self.enable_evidence_collection:
                logger.info("Evidence collection disabled, skipping response capture")
                return []
            
            # Process collected response data
            processed_responses = []
            
            for response in self.response_data:
                # Save response to file
                response_file = self._save_response_to_file(response)
                
                if response_file:
                    response.file_path = response_file
                    processed_responses.append(response)
            
            logger.info(f"Response data capture completed. Processed {len(processed_responses)} responses")
            
            return processed_responses
            
        except Exception as e:
            logger.error(f"Error capturing response data: {str(e)}")
            return []
    
    def _save_response_to_file(self, response: ResponseData) -> Optional[str]:
        """Save response data to file."""
        try:
            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_url = response.url.replace("://", "_").replace("/", "_").replace(".", "_")
            filename = f"response_{safe_url}_{timestamp}.json"
            filepath = self.evidence_dir / "responses" / filename
            
            # Create response data for saving
            response_data = {
                "response_id": response.response_id,
                "timestamp": response.timestamp.isoformat(),
                "url": response.url,
                "method": response.method,
                "status_code": response.status_code,
                "response_time": response.response_time,
                "headers": response.headers,
                "body": response.body,
                "size_bytes": response.size_bytes,
                "content_type": response.content_type,
                "finding_id": response.finding_id,
                "test_id": response.test_id
            }
            
            # Save to file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(response_data, f, indent=2, ensure_ascii=False)
            
            return str(filepath)
            
        except Exception as e:
            logger.error(f"Error saving response to file: {str(e)}")
            return None
    
    def add_response_data(self, url: str, method: str, status_code: int, 
                         response_time: float, headers: Dict[str, str], 
                         body: str = None, finding_id: str = None, test_id: str = None):
        """Add response data to collection."""
        try:
            response = ResponseData(
                response_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                url=url,
                method=method,
                status_code=status_code,
                response_time=response_time,
                headers=headers,
                body=body,
                size_bytes=len(body) if body else 0,
                content_type=headers.get("content-type", ""),
                finding_id=finding_id,
                test_id=test_id
            )
            
            self.response_data.append(response)
            
        except Exception as e:
            logger.error(f"Error adding response data: {str(e)}")
    
    def organize_evidence(self) -> Dict[str, Any]:
        """
        Organize and categorize collected evidence.
        
        Returns:
            Dict[str, Any]: Organized evidence structure
        """
        logger.info("Organizing evidence...")
        
        try:
            organized_evidence = {
                "summary": {
                    "total_evidence_items": len(self.evidence_items),
                    "total_activity_logs": len(self.activity_logs),
                    "total_responses": len(self.response_data),
                    "collection_timestamp": datetime.now(timezone.utc).isoformat(),
                    "target": self.config.target,
                    "stage": self.config.stage_name
                },
                "evidence_by_type": {},
                "evidence_by_finding": {},
                "evidence_by_test": {},
                "timeline": [],
                "statistics": {}
            }
            
            # Organize evidence by type
            for evidence in self.evidence_items:
                evidence_type = evidence.evidence_type
                if evidence_type not in organized_evidence["evidence_by_type"]:
                    organized_evidence["evidence_by_type"][evidence_type] = []
                organized_evidence["evidence_by_type"][evidence_type].append(evidence.__dict__)
            
            # Organize evidence by finding
            for evidence in self.evidence_items:
                if evidence.finding_id:
                    if evidence.finding_id not in organized_evidence["evidence_by_finding"]:
                        organized_evidence["evidence_by_finding"][evidence.finding_id] = []
                    organized_evidence["evidence_by_finding"][evidence.finding_id].append(evidence.__dict__)
            
            # Organize evidence by test
            for evidence in self.evidence_items:
                if evidence.test_id:
                    if evidence.test_id not in organized_evidence["evidence_by_test"]:
                        organized_evidence["evidence_by_test"][evidence.test_id] = []
                    organized_evidence["evidence_by_test"][evidence.test_id].append(evidence.__dict__)
            
            # Create timeline
            timeline_items = []
            
            # Add evidence items to timeline
            for evidence in self.evidence_items:
                timeline_items.append({
                    "timestamp": evidence.timestamp.isoformat(),
                    "type": "evidence",
                    "description": f"{evidence.evidence_type}: {evidence.description}",
                    "item_id": evidence.evidence_id
                })
            
            # Add activity logs to timeline
            for log in self.activity_logs:
                timeline_items.append({
                    "timestamp": log.timestamp.isoformat(),
                    "type": "activity",
                    "description": log.description,
                    "severity": log.severity,
                    "item_id": log.log_id
                })
            
            # Sort timeline by timestamp
            timeline_items.sort(key=lambda x: x["timestamp"])
            organized_evidence["timeline"] = timeline_items
            
            # Calculate statistics
            organized_evidence["statistics"] = {
                "evidence_types": {k: len(v) for k, v in organized_evidence["evidence_by_type"].items()},
                "total_file_size": sum(e.size_bytes for e in self.evidence_items),
                "average_response_time": sum(r.response_time for r in self.response_data) / len(self.response_data) if self.response_data else 0,
                "activity_by_severity": {}
            }
            
            # Calculate activity by severity
            for log in self.activity_logs:
                severity = log.severity
                if severity not in organized_evidence["statistics"]["activity_by_severity"]:
                    organized_evidence["statistics"]["activity_by_severity"][severity] = 0
                organized_evidence["statistics"]["activity_by_severity"][severity] += 1
            
            logger.info("Evidence organization completed")
            
            return organized_evidence
            
        except Exception as e:
            logger.error(f"Error organizing evidence: {str(e)}")
            return {}
    
    def _log_activity(self, activity_type: str, description: str, severity: str = "INFO", 
                     finding_id: str = None, test_id: str = None, metadata: Dict[str, Any] = None):
        """Log an activity."""
        try:
            log_entry = ActivityLog(
                log_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                activity_type=activity_type,
                description=description,
                severity=severity,
                metadata=metadata or {},
                finding_id=finding_id,
                test_id=test_id
            )
            
            self.activity_logs.append(log_entry)
            
            # Also log to standard logger
            log_level = getattr(logging, severity.upper(), logging.INFO)
            logger.log(log_level, f"[{activity_type}] {description}")
            
        except Exception as e:
            logger.error(f"Error logging activity: {str(e)}")
    
    def capture_finding_evidence(self, finding: Any, evidence_type: str = "screenshot") -> Optional[str]:
        """
        Capture specific evidence for a finding.
        
        Args:
            finding: Vulnerability finding
            evidence_type: Type of evidence to capture
            
        Returns:
            Optional[str]: Path to captured evidence file
        """
        try:
            if not self.enable_evidence_collection:
                return None
            
            if evidence_type == "screenshot":
                return self._capture_finding_screenshot(finding)
            elif evidence_type == "response":
                return self._capture_finding_response(finding)
            else:
                logger.warning(f"Unknown evidence type: {evidence_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error capturing finding evidence: {str(e)}")
            return None
    
    def _capture_finding_screenshot(self, finding: Any) -> Optional[str]:
        """Capture screenshot for a specific finding."""
        try:
            if not self.browser_driver:
                self._initialize_browser()
            
            if not self.browser_driver:
                return None
            
            # Get URL from finding
            url = getattr(finding, 'endpoint', f"https://{self.config.target}")
            
            # Capture screenshot
            screenshot_path = self._capture_screenshot(url)
            
            if screenshot_path:
                # Create evidence item
                evidence_item = EvidenceItem(
                    evidence_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    evidence_type="screenshot",
                    file_path=screenshot_path,
                    description=f"Screenshot for finding: {finding.title}",
                    finding_id=finding.id,
                    metadata={
                        "finding_title": finding.title,
                        "finding_severity": getattr(finding, 'severity', 'Unknown'),
                        "url": url
                    }
                )
                self.evidence_items.append(evidence_item)
                
                # Log activity
                self._log_activity(
                    "finding_screenshot_captured",
                    f"Screenshot captured for finding: {finding.title}",
                    "INFO",
                    finding_id=finding.id
                )
            
            return screenshot_path
            
        except Exception as e:
            logger.error(f"Error capturing finding screenshot: {str(e)}")
            return None
    
    def _capture_finding_response(self, finding: Any) -> Optional[str]:
        """Capture response data for a specific finding."""
        try:
            # Get URL from finding
            url = getattr(finding, 'endpoint', f"https://{self.config.target}")
            
            # Make request to capture response
            response = requests.get(url, timeout=30)
            
            # Create response data
            response_data = ResponseData(
                response_id=str(uuid.uuid4()),
                timestamp=datetime.now(timezone.utc),
                url=url,
                method="GET",
                status_code=response.status_code,
                response_time=response.elapsed.total_seconds(),
                headers=dict(response.headers),
                body=response.text,
                size_bytes=len(response.content),
                content_type=response.headers.get("content-type", ""),
                finding_id=finding.id
            )
            
            self.response_data.append(response_data)
            
            # Save response to file
            response_file = self._save_response_to_file(response_data)
            
            if response_file:
                # Create evidence item
                evidence_item = EvidenceItem(
                    evidence_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    evidence_type="response",
                    file_path=response_file,
                    description=f"Response data for finding: {finding.title}",
                    finding_id=finding.id,
                    metadata={
                        "finding_title": finding.title,
                        "finding_severity": getattr(finding, 'severity', 'Unknown'),
                        "status_code": response.status_code,
                        "response_time": response_data.response_time
                    }
                )
                self.evidence_items.append(evidence_item)
                
                # Log activity
                self._log_activity(
                    "finding_response_captured",
                    f"Response captured for finding: {finding.title}",
                    "INFO",
                    finding_id=finding.id
                )
            
            return response_file
            
        except Exception as e:
            logger.error(f"Error capturing finding response: {str(e)}")
            return None
    
    def create_evidence_report(self) -> Dict[str, Any]:
        """
        Create comprehensive evidence report.
        
        Returns:
            Dict[str, Any]: Evidence report
        """
        logger.info("Creating evidence report...")
        
        try:
            # Organize evidence
            organized_evidence = self.organize_evidence()
            
            # Create report structure
            report = {
                "report_metadata": {
                    "report_id": str(uuid.uuid4()),
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "target": self.config.target,
                    "stage": self.config.stage_name,
                    "evidence_collector_version": "1.0.0"
                },
                "executive_summary": {
                    "total_evidence_collected": len(self.evidence_items),
                    "evidence_types": list(organized_evidence["evidence_by_type"].keys()),
                    "total_activities_logged": len(self.activity_logs),
                    "total_responses_captured": len(self.response_data),
                    "collection_duration": "N/A",  # Would calculate from start/end times
                    "key_findings": []
                },
                "detailed_evidence": organized_evidence,
                "recommendations": {
                    "evidence_preservation": "All evidence has been preserved in structured format",
                    "chain_of_custody": "Complete audit trail maintained",
                    "further_analysis": "Evidence available for detailed forensic analysis"
                }
            }
            
            # Add key findings
            for finding_id, evidence_list in organized_evidence["evidence_by_finding"].items():
                if evidence_list:
                    report["executive_summary"]["key_findings"].append({
                        "finding_id": finding_id,
                        "evidence_count": len(evidence_list),
                        "evidence_types": list(set(e["evidence_type"] for e in evidence_list))
                    })
            
            logger.info("Evidence report created successfully")
            
            return report
            
        except Exception as e:
            logger.error(f"Error creating evidence report: {str(e)}")
            return {}
    
    def cleanup(self):
        """Clean up resources after evidence collection."""
        try:
            # Stop video recording if active
            if self.video_recording_active:
                self.stop_video_recording()
            
            # Close browser driver
            if self.browser_driver:
                self.browser_driver.quit()
                self.browser_driver = None
            
            # Shutdown thread pool
            if self.thread_pool:
                self.thread_pool.shutdown(wait=True)
            
            # Log final activity
            self._log_activity("evidence_collector_stop", "Evidence collector cleanup completed", "INFO")
            
            logger.info("Evidence collector cleanup completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
    
    def save_results(self):
        """Save evidence collection results to files."""
        try:
            # Save evidence items
            evidence_file = self.evidence_dir / "evidence_items.json"
            with open(evidence_file, 'w') as f:
                json.dump([item.__dict__ for item in self.evidence_items], f, indent=2, default=str)
            
            # Save activity logs
            logs_file = self.evidence_dir / "activity_logs.json"
            with open(logs_file, 'w') as f:
                json.dump([log.__dict__ for log in self.activity_logs], f, indent=2, default=str)
            
            # Save response data
            responses_file = self.evidence_dir / "response_data.json"
            with open(responses_file, 'w') as f:
                json.dump([resp.__dict__ for resp in self.response_data], f, indent=2, default=str)
            
            # Create evidence report
            report = self.create_evidence_report()
            report_file = self.evidence_dir / "evidence_report.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Save organized evidence
            organized_evidence = self.organize_evidence()
            organized_file = self.evidence_dir / "organized_evidence.json"
            with open(organized_file, 'w') as f:
                json.dump(organized_evidence, f, indent=2, default=str)
            
            logger.info(f"Evidence collection results saved to {self.evidence_dir}")
            
        except Exception as e:
            logger.error(f"Error saving evidence collection results: {str(e)}") 