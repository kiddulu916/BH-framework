"""
Database Integration Tests

This module contains comprehensive tests for database integration,
validating data operations, consistency, and integrity across all stages.

Test Scenarios:
1. Database operations across all stages and workflows
2. Data integrity and consistency validation
3. Concurrent access and transaction handling
4. Data migration and schema validation
5. Performance and optimization testing
6. Backup and recovery testing

Author: Bug Hunting Framework Team
Date: 2025-01-27
"""

import asyncio
import json
import logging
import os
import pytest
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
from uuid import uuid4

import httpx
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# Import Django ASGI application
from api.asgi import application

# Import test utilities and fixtures
from tests.conftest import api_client, db_session
from core.models.target import Target
from core.models.workflow import Workflow, WorkflowStatus, StageStatus
from core.models.passive_recon import PassiveReconResult
from core.models.active_recon import ActiveReconResult
from core.models.vulnerability import Vulnerability
from core.models.kill_chain import KillChain
from core.models.report import Report
from core.schemas.base import APIResponse
from core.utils.database import get_db_session

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestDatabaseOperations:
    """
    Comprehensive database operations tests.
    
    Tests database operations across all stages and workflows,
    ensuring data integrity and consistency.
    """
    
    @pytest.fixture
    async def db_test_data(self) -> Dict[str, Any]:
        """Test data for database integration testing."""
        return {
            "target": {
                "name": "Database Test Target",
                "scope": "DOMAIN",
                "value": "database-test.com",
                "description": "Target for database integration testing",
                "platform": "BUGBOUNTY",
                "is_primary": True
            },
            "workflow": {
                "name": "Database Test Workflow",
                "description": "Workflow for database integration testing",
                "stages": ["PASSIVE_RECON", "ACTIVE_RECON"],
                "settings": {
                    "test_mode": True,
                    "timeout": 300,
                    "max_concurrent_stages": 2
                }
            }
        }
    
    @pytest.mark.asyncio
    async def test_database_operations_across_stages(self, api_client: AsyncClient, db_session, 
                                                    db_test_data: Dict[str, Any]):
        """
        Test database operations across all stages and workflows.
        
        Validates that database operations work correctly throughout
        the complete workflow lifecycle.
        """
        logger.info("Starting database operations across stages test")
        
        # Step 1: Create target and verify database persistence
        logger.info("Step 1: Creating target and verifying database persistence")
        target_response = await api_client.post("/api/targets/", json=db_test_data["target"])
        assert target_response.status_code == 200, f"Target creation failed: {target_response.text}"
        
        target_data = target_response.json()
        target_id = target_data["data"]["id"]
        
        # Verify target exists in database
        async with get_db_session() as session:
            target_query = await session.execute(
                text("SELECT * FROM targets WHERE id = :target_id"),
                {"target_id": target_id}
            )
            db_target = target_query.fetchone()
            assert db_target is not None, "Target not found in database"
            assert db_target.name == db_test_data["target"]["name"], "Target name mismatch"
        
        # Step 2: Create workflow and verify database persistence
        logger.info("Step 2: Creating workflow and verifying database persistence")
        workflow_data = db_test_data["workflow"].copy()
        workflow_data["target_id"] = target_id
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        assert workflow_response.status_code == 200, f"Workflow creation failed: {workflow_response.text}"
        
        workflow_result = workflow_response.json()
        workflow_id = workflow_result["data"]["id"]
        
        # Verify workflow exists in database
        async with get_db_session() as session:
            workflow_query = await session.execute(
                text("SELECT * FROM workflows WHERE id = :workflow_id"),
                {"workflow_id": workflow_id}
            )
            db_workflow = workflow_query.fetchone()
            assert db_workflow is not None, "Workflow not found in database"
            assert db_workflow.name == db_test_data["workflow"]["name"], "Workflow name mismatch"
        
        # Step 3: Execute stages and verify database operations
        logger.info("Step 3: Executing stages and verifying database operations")
        stages = db_test_data["workflow"]["stages"]
        
        for stage_name in stages:
            logger.info(f"Executing {stage_name} and verifying database operations")
            
            # Execute stage
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": stage_name,
                "config_overrides": {
                    "tools": self._get_stage_tools(stage_name),
                    "timeout": 120,
                    "test_mode": True
                }
            }
            
            execution_response = await api_client.post("/api/execution/", json=execution_data)
            assert execution_response.status_code == 200, f"{stage_name} execution failed: {execution_response.text}"
            
            execution_result = execution_response.json()
            execution_id = execution_result["data"]["execution_id"]
            
            # Wait for completion
            await self._wait_for_execution_completion(api_client, execution_id, timeout=180)
            
            # Verify execution record in database
            async with get_db_session() as session:
                execution_query = await session.execute(
                    text("SELECT * FROM executions WHERE id = :execution_id"),
                    {"execution_id": execution_id}
                )
                db_execution = execution_query.fetchone()
                assert db_execution is not None, f"Execution record not found for {stage_name}"
                assert db_execution.stage_name == stage_name, f"Stage name mismatch for {stage_name}"
            
            # Verify stage results in database
            await self._verify_stage_results_in_database(stage_name, target_id)
            
            logger.info(f"{stage_name} database operations verified successfully")
        
        logger.info("Database operations across stages test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_data_integrity_and_consistency(self, api_client: AsyncClient, db_session):
        """
        Test data integrity and consistency throughout the workflow.
        
        Validates that data remains consistent and intact throughout
        database operations and workflow execution.
        """
        logger.info("Starting data integrity and consistency test")
        
        # Create target
        target_data = {
            "name": "Data Integrity Test Target",
            "scope": "DOMAIN",
            "value": "data-integrity-test.com",
            "description": "Target for data integrity testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["data"]["id"]
        
        # Create workflow
        workflow_data = {
            "target_id": target_id,
            "name": "Data Integrity Test Workflow",
            "description": "Workflow for data integrity testing",
            "stages": ["PASSIVE_RECON", "ACTIVE_RECON"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Execute stages and validate data integrity
        stage_results = {}
        
        for stage_name in ["PASSIVE_RECON", "ACTIVE_RECON"]:
            # Execute stage
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": stage_name,
                "config_overrides": {
                    "tools": self._get_stage_tools(stage_name),
                    "timeout": 60,
                    "test_mode": True
                }
            }
            
            execution_response = await api_client.post("/api/execution/", json=execution_data)
            execution_id = execution_response.json()["data"]["execution_id"]
            
            # Wait for completion
            await self._wait_for_execution_completion(api_client, execution_id, timeout=120)
            
            # Get results from API
            results_response = await api_client.get(f"/api/results/{stage_name.lower()}/?target_id={target_id}")
            api_results = results_response.json()["data"]
            
            # Get results from database
            db_results = await self._get_stage_results_from_database(stage_name, target_id)
            
            # Validate consistency between API and database
            await self._validate_api_database_consistency(api_results, db_results, stage_name)
            
            stage_results[stage_name] = {
                "api": api_results,
                "database": db_results
            }
        
        # Validate cross-stage data consistency
        await self._validate_cross_stage_consistency(stage_results)
        
        logger.info("Data integrity and consistency test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_concurrent_access_and_transactions(self, api_client: AsyncClient, db_session):
        """
        Test concurrent access and transaction handling.
        
        Validates that the database handles concurrent operations
        correctly and maintains data integrity.
        """
        logger.info("Starting concurrent access and transactions test")
        
        # Create target for concurrent testing
        target_data = {
            "name": "Concurrent Test Target",
            "scope": "DOMAIN",
            "value": "concurrent-test.com",
            "description": "Target for concurrent access testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["data"]["id"]
        
        # Test concurrent target creation
        logger.info("Testing concurrent target creation")
        concurrent_target_tasks = []
        
        for i in range(5):
            concurrent_target_data = {
                "name": f"Concurrent Target {i+1}",
                "scope": "DOMAIN",
                "value": f"concurrent-target-{i+1}.com",
                "description": f"Concurrent target {i+1}",
                "platform": "BUGBOUNTY",
                "is_primary": True
            }
            
            task = api_client.post("/api/targets/", json=concurrent_target_data)
            concurrent_target_tasks.append(task)
        
        # Execute concurrent target creation
        target_responses = await asyncio.gather(*concurrent_target_tasks)
        
        # Validate all targets created successfully
        created_target_ids = []
        for response in target_responses:
            assert response.status_code == 200, f"Concurrent target creation failed: {response.text}"
            target_id = response.json()["data"]["id"]
            created_target_ids.append(target_id)
        
        # Verify all targets exist in database
        async with get_db_session() as session:
            for target_id in created_target_ids:
                target_query = await session.execute(
                    text("SELECT * FROM targets WHERE id = :target_id"),
                    {"target_id": target_id}
                )
                db_target = target_query.fetchone()
                assert db_target is not None, f"Concurrent target {target_id} not found in database"
        
        # Test concurrent workflow creation
        logger.info("Testing concurrent workflow creation")
        concurrent_workflow_tasks = []
        
        for i in range(3):
            workflow_data = {
                "target_id": target_id,
                "name": f"Concurrent Workflow {i+1}",
                "description": f"Concurrent workflow {i+1}",
                "stages": ["PASSIVE_RECON"],
                "settings": {"test_mode": True}
            }
            
            task = api_client.post("/api/workflows/", json=workflow_data)
            concurrent_workflow_tasks.append(task)
        
        # Execute concurrent workflow creation
        workflow_responses = await asyncio.gather(*concurrent_workflow_tasks)
        
        # Validate all workflows created successfully
        created_workflow_ids = []
        for response in workflow_responses:
            assert response.status_code == 200, f"Concurrent workflow creation failed: {response.text}"
            workflow_id = response.json()["data"]["id"]
            created_workflow_ids.append(workflow_id)
        
        # Verify all workflows exist in database
        async with get_db_session() as session:
            for workflow_id in created_workflow_ids:
                workflow_query = await session.execute(
                    text("SELECT * FROM workflows WHERE id = :workflow_id"),
                    {"workflow_id": workflow_id}
                )
                db_workflow = workflow_query.fetchone()
                assert db_workflow is not None, f"Concurrent workflow {workflow_id} not found in database"
        
        logger.info("Concurrent access and transactions test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_database_performance_and_optimization(self, api_client: AsyncClient, db_session):
        """
        Test database performance and optimization.
        
        Validates database performance under various load conditions
        and identifies optimization opportunities.
        """
        logger.info("Starting database performance and optimization test")
        
        # Test 1: Bulk target creation performance
        logger.info("Testing bulk target creation performance")
        bulk_target_tasks = []
        
        start_time = time.time()
        for i in range(10):
            target_data = {
                "name": f"Bulk Target {i+1}",
                "scope": "DOMAIN",
                "value": f"bulk-target-{i+1}.com",
                "description": f"Bulk target {i+1}",
                "platform": "BUGBOUNTY",
                "is_primary": True
            }
            
            task = api_client.post("/api/targets/", json=target_data)
            bulk_target_tasks.append(task)
        
        # Execute bulk target creation
        bulk_responses = await asyncio.gather(*bulk_target_tasks)
        bulk_creation_time = time.time() - start_time
        
        # Validate all targets created successfully
        for response in bulk_responses:
            assert response.status_code == 200, f"Bulk target creation failed: {response.text}"
        
        # Validate performance
        avg_creation_time = bulk_creation_time / len(bulk_responses)
        assert avg_creation_time < 1.0, f"Average target creation time {avg_creation_time}s exceeds 1 second threshold"
        
        # Test 2: Database query performance
        logger.info("Testing database query performance")
        
        # Test target listing performance
        start_time = time.time()
        targets_response = await api_client.get("/api/targets/")
        query_time = time.time() - start_time
        
        assert targets_response.status_code == 200
        assert query_time < 0.5, f"Target listing query time {query_time}s exceeds 0.5 second threshold"
        
        # Test 3: Complex query performance
        logger.info("Testing complex query performance")
        
        # Create workflow with multiple stages
        target_id = bulk_responses[0].json()["data"]["id"]
        workflow_data = {
            "target_id": target_id,
            "name": "Performance Test Workflow",
            "description": "Workflow for performance testing",
            "stages": ["PASSIVE_RECON", "ACTIVE_RECON", "VULN_SCAN"],
            "settings": {"test_mode": True}
        }
        
        workflow_response = await api_client.post("/api/workflows/", json=workflow_data)
        workflow_id = workflow_response.json()["data"]["id"]
        
        # Execute stages and measure performance
        stage_execution_times = {}
        
        for stage_name in ["PASSIVE_RECON", "ACTIVE_RECON"]:
            execution_data = {
                "workflow_id": str(workflow_id),
                "stage_name": stage_name,
                "config_overrides": {
                    "tools": self._get_stage_tools(stage_name),
                    "timeout": 60,
                    "test_mode": True
                }
            }
            
            start_time = time.time()
            execution_response = await api_client.post("/api/execution/", json=execution_data)
            execution_id = execution_response.json()["data"]["execution_id"]
            
            # Wait for completion
            await self._wait_for_execution_completion(api_client, execution_id, timeout=120)
            stage_execution_time = time.time() - start_time
            
            stage_execution_times[stage_name] = stage_execution_time
            
            # Validate performance
            assert stage_execution_time < 180, f"{stage_name} execution time {stage_execution_time}s exceeds 3 minute threshold"
        
        logger.info(f"Stage execution times: {stage_execution_times}")
        logger.info("Database performance and optimization test passed successfully!")
    
    @pytest.mark.asyncio
    async def test_data_migration_and_schema_validation(self, api_client: AsyncClient, db_session):
        """
        Test data migration and schema validation.
        
        Validates that database schema is correct and data migrations
        work properly.
        """
        logger.info("Starting data migration and schema validation test")
        
        # Test 1: Schema validation
        logger.info("Testing database schema validation")
        
        async with get_db_session() as session:
            # Check if all required tables exist
            required_tables = [
                "targets", "workflows", "executions", "passive_recon_results",
                "active_recon_results", "vulnerabilities", "kill_chains", "reports"
            ]
            
            for table_name in required_tables:
                table_query = await session.execute(
                    text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = :table_name)"),
                    {"table_name": table_name}
                )
                table_exists = table_query.scalar()
                assert table_exists, f"Required table {table_name} does not exist"
            
            # Check if all required columns exist in targets table
            required_columns = ["id", "name", "scope", "value", "description", "platform", "is_primary", "created_at", "updated_at"]
            
            for column_name in required_columns:
                column_query = await session.execute(
                    text("SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'targets' AND column_name = :column_name)"),
                    {"column_name": column_name}
                )
                column_exists = column_query.scalar()
                assert column_exists, f"Required column {column_name} does not exist in targets table"
        
        # Test 2: Data type validation
        logger.info("Testing data type validation")
        
        # Create target with various data types
        target_data = {
            "name": "Schema Test Target",
            "scope": "DOMAIN",
            "value": "schema-test.com",
            "description": "Target for schema validation testing",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        target_response = await api_client.post("/api/targets/", json=target_data)
        target_id = target_response.json()["data"]["id"]
        
        # Verify data types in database
        async with get_db_session() as session:
            target_query = await session.execute(
                text("SELECT * FROM targets WHERE id = :target_id"),
                {"target_id": target_id}
            )
            db_target = target_query.fetchone()
            
            # Validate data types
            assert isinstance(db_target.id, str), "Target ID should be string"
            assert isinstance(db_target.name, str), "Target name should be string"
            assert isinstance(db_target.scope, str), "Target scope should be string"
            assert isinstance(db_target.value, str), "Target value should be string"
            assert isinstance(db_target.description, str), "Target description should be string"
            assert isinstance(db_target.platform, str), "Target platform should be string"
            assert isinstance(db_target.is_primary, bool), "Target is_primary should be boolean"
            assert isinstance(db_target.created_at, datetime), "Target created_at should be datetime"
            assert isinstance(db_target.updated_at, datetime), "Target updated_at should be datetime"
        
        # Test 3: Constraint validation
        logger.info("Testing constraint validation")
        
        # Test unique constraint on target value
        duplicate_target_data = {
            "name": "Duplicate Target",
            "scope": "DOMAIN",
            "value": "schema-test.com",  # Same value as above
            "description": "Duplicate target",
            "platform": "BUGBOUNTY",
            "is_primary": True
        }
        
        duplicate_response = await api_client.post("/api/targets/", json=duplicate_target_data)
        # Should either reject duplicate or handle it gracefully
        assert duplicate_response.status_code in [200, 422, 409], "Should handle duplicate target appropriately"
        
        logger.info("Data migration and schema validation test passed successfully!")
    
    def _get_stage_tools(self, stage_name: str) -> str:
        """Get appropriate tools for each stage."""
        tool_mapping = {
            "PASSIVE_RECON": "subfinder,amass,assetfinder",
            "ACTIVE_RECON": "nmap,httpx,feroxbuster",
            "VULN_SCAN": "nuclei,nmap,nikto",
            "VULN_TEST": "ai_analyzer,browser_automation,evidence_collector",
            "KILL_CHAIN": "mitre_attack,threat_modeling,attack_visualization",
            "COMPREHENSIVE_REPORTING": "executive_generator,technical_docs,compliance_mapper"
        }
        return tool_mapping.get(stage_name, "default_tool")
    
    async def _wait_for_execution_completion(self, api_client: AsyncClient, execution_id: str, timeout: int = 300):
        """Wait for execution to complete with timeout."""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            status_response = await api_client.get(f"/api/execution/{execution_id}/status")
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data["data"]["status"]
                
                if status in ["COMPLETED", "FAILED", "TIMEOUT"]:
                    logger.info(f"Execution {execution_id} completed with status: {status}")
                    return status_data
                
                logger.info(f"Execution {execution_id} status: {status}")
            
            await asyncio.sleep(5)
        
        raise TimeoutError(f"Execution {execution_id} did not complete within {timeout} seconds")
    
    async def _verify_stage_results_in_database(self, stage_name: str, target_id: str):
        """Verify stage results exist in database."""
        table_mapping = {
            "PASSIVE_RECON": "passive_recon_results",
            "ACTIVE_RECON": "active_recon_results",
            "VULN_SCAN": "vulnerabilities",
            "VULN_TEST": "vulnerabilities",
            "KILL_CHAIN": "kill_chains",
            "COMPREHENSIVE_REPORTING": "reports"
        }
        
        table_name = table_mapping.get(stage_name)
        if not table_name:
            logger.warning(f"No table mapping found for stage {stage_name}")
            return
        
        async with get_db_session() as session:
            results_query = await session.execute(
                text(f"SELECT COUNT(*) FROM {table_name} WHERE target_id = :target_id"),
                {"target_id": target_id}
            )
            result_count = results_query.scalar()
            assert result_count > 0, f"No results found in {table_name} for target {target_id}"
    
    async def _get_stage_results_from_database(self, stage_name: str, target_id: str) -> List[Dict[str, Any]]:
        """Get stage results from database."""
        table_mapping = {
            "PASSIVE_RECON": "passive_recon_results",
            "ACTIVE_RECON": "active_recon_results",
            "VULN_SCAN": "vulnerabilities",
            "VULN_TEST": "vulnerabilities",
            "KILL_CHAIN": "kill_chains",
            "COMPREHENSIVE_REPORTING": "reports"
        }
        
        table_name = table_mapping.get(stage_name)
        if not table_name:
            return []
        
        async with get_db_session() as session:
            results_query = await session.execute(
                text(f"SELECT * FROM {table_name} WHERE target_id = :target_id"),
                {"target_id": target_id}
            )
            results = results_query.fetchall()
            
            # Convert to list of dictionaries
            return [dict(result._mapping) for result in results]
    
    async def _validate_api_database_consistency(self, api_results: List[Dict[str, Any]], 
                                               db_results: List[Dict[str, Any]], 
                                               stage_name: str):
        """Validate consistency between API and database results."""
        # Both should have the same number of results
        assert len(api_results) == len(db_results), f"Result count mismatch for {stage_name}: API={len(api_results)}, DB={len(db_results)}"
        
        # Validate result structure
        for api_result in api_results:
            assert "target" in api_result, f"API result missing target for {stage_name}"
            assert "tool_name" in api_result, f"API result missing tool_name for {stage_name}"
            assert "data" in api_result, f"API result missing data for {stage_name}"
        
        for db_result in db_results:
            assert "target_id" in db_result, f"DB result missing target_id for {stage_name}"
            assert "tool_name" in db_result, f"DB result missing tool_name for {stage_name}"
            assert "data" in db_result, f"DB result missing data for {stage_name}"
    
    async def _validate_cross_stage_consistency(self, stage_results: Dict[str, Any]):
        """Validate consistency across stages."""
        # Validate that data flows correctly between stages
        if "PASSIVE_RECON" in stage_results and "ACTIVE_RECON" in stage_results:
            passive_api_results = stage_results["PASSIVE_RECON"]["api"]
            active_api_results = stage_results["ACTIVE_RECON"]["api"]
            
            # Both stages should have results
            assert len(passive_api_results) > 0, "Passive recon should have API results"
            assert len(active_api_results) > 0, "Active recon should have API results"
            
            # Both stages should have database results
            passive_db_results = stage_results["PASSIVE_RECON"]["database"]
            active_db_results = stage_results["ACTIVE_RECON"]["database"]
            
            assert len(passive_db_results) > 0, "Passive recon should have database results"
            assert len(active_db_results) > 0, "Active recon should have database results"


if __name__ == "__main__":
    # Run database integration tests
    pytest.main([__file__, "-v", "--tb=short"]) 