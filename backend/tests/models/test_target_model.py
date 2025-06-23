"""
Tests for Target model.

This module contains comprehensive tests for the Target model,
including validation, relationships, and business logic.
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from core.models.target import Target, TargetScope, TargetStatus
from core.utils.exceptions import ValidationError


class TestTargetModel:
    """Test cases for Target model."""
    
    def test_target_creation(self):
        """Test basic target creation."""
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            scope=TargetScope.DOMAIN,
            status=TargetStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert target.name == "Test Target"
        assert target.value == "example.com"
        assert target.scope == TargetScope.DOMAIN
        assert target.status == TargetStatus.ACTIVE
        assert not target.is_primary
    
    def test_target_defaults(self):
        """Test target default values."""
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        assert target.scope == TargetScope.DOMAIN
        assert target.status == TargetStatus.ACTIVE
        assert not target.is_primary
        assert target.scope_config is None
    
    def test_target_domain_validation(self):
        """Test target value validation."""
        # Test valid values
        valid_values = [
            "example.com",
            "sub.example.com",
            "test-domain.com",
            "example.co.uk",
            "example.org"
        ]

        for value in valid_values:
            target = Target(
                id=uuid4(),
                name="Test Target",
                value=value,
                scope=TargetScope.DOMAIN,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            assert target.value == value

        # Test invalid values
        invalid_values = [
            "",  # Empty value
            "invalid",  # No TLD
            "example",  # No TLD
            "example..com",  # Double dots
            ".example.com",  # Starts with dot
            "example.com.",  # Ends with dot
        ]

        for value in invalid_values:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name="Test Target",
                    value=value,
                    scope=TargetScope.DOMAIN,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    @pytest.mark.asyncio
    async def test_target_domain_validation_database(self, db_session):
        """Test target value validation when saving to database."""
        # Test valid values
        valid_values = [
            "example.com",
            "sub.example.com",
            "test-domain.com",
            "example.co.uk",
            "example.org"
        ]

        for value in valid_values:
            target = Target(
                id=uuid4(),
                name="Test Target",
                value=value,
                scope=TargetScope.DOMAIN,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.value == value

        # Test invalid values
        invalid_values = [
            "",  # Empty value
            "invalid",  # No TLD
            "example",  # No TLD
            "example..com",  # Double dots
            ".example.com",  # Starts with dot
            "example.com.",  # Ends with dot
        ]

        for value in invalid_values:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name="Test Target",
                    value=value,
                    scope=TargetScope.DOMAIN,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    @pytest.mark.asyncio
    async def test_target_ip_range_validation(self, db_session):
        """Test IP range validation."""
        # Test valid IP ranges
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1"
        ]
        
        for ip in valid_ips:
            target = Target(
                id=uuid4(),
                name="Test IP Target",
                value=ip,
                scope=TargetScope.IP_RANGE,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.value == ip
            await db_session.delete(target)
            await db_session.commit()
        
        # Test invalid IP ranges
        invalid_ips = [
            "256.1.1.1",  # Invalid octet
            "1.1.1",  # Missing octet
            "1.1.1.1.1",  # Too many octets
            "abc.def.ghi.jkl"  # Non-numeric
        ]
        
        for ip in invalid_ips:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name="Test IP Target",
                    value=ip,
                    scope=TargetScope.IP_RANGE,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    @pytest.mark.asyncio
    async def test_target_subnet_validation(self, db_session):
        """Test subnet validation."""
        # Test valid subnets
        valid_subnets = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16"
        ]
        
        for subnet in valid_subnets:
            target = Target(
                id=uuid4(),
                name="Test Subnet Target",
                value=subnet,
                scope=TargetScope.SUBNET,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.value == subnet
            await db_session.delete(target)
            await db_session.commit()
        
        # Test invalid subnets
        invalid_subnets = [
            "192.168.1.0/33",  # Invalid CIDR (too large)
            "192.168.1.0/abc",  # Non-numeric CIDR
            "256.1.1.0/24",  # Invalid IP
            "192.168.1.0/",  # Missing CIDR number
        ]
        
        for subnet in invalid_subnets:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name="Test Subnet Target",
                    value=subnet,
                    scope=TargetScope.SUBNET,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    @pytest.mark.asyncio
    async def test_target_wildcard_validation(self, db_session):
        """Test wildcard validation."""
        # Test valid wildcards
        valid_wildcards = [
            "*.example.com",
            "*.sub.example.com"
        ]
        
        for wildcard in valid_wildcards:
            target = Target(
                id=uuid4(),
                name="Test Wildcard Target",
                value=wildcard,
                scope=TargetScope.WILDCARD,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.value == wildcard
            await db_session.delete(target)
            await db_session.commit()
        
        # Test invalid wildcards
        invalid_wildcards = [
            "example.com",  # No wildcard
            "*.com",  # No domain
            "example.*.com",  # Wildcard in middle
            "*.example"  # No TLD
        ]
        
        for wildcard in invalid_wildcards:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name="Test Wildcard Target",
                    value=wildcard,
                    scope=TargetScope.WILDCARD,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    def test_target_properties(self):
        """Test target properties."""
        # Test active target
        active_target = Target(
            id=uuid4(),
            name="Active Target",
            value="example.com",
            status=TargetStatus.ACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert active_target.is_active is True
        
        # Test inactive target
        inactive_target = Target(
            id=uuid4(),
            name="Inactive Target",
            value="example.com",
            status=TargetStatus.INACTIVE,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        assert inactive_target.is_active is False
    
    def test_target_display_name(self):
        """Test target display name property."""
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        expected_display = "Test Target (example.com)"
        assert target.display_name == expected_display
    
    def test_target_to_dict(self):
        """Test target to_dict method."""
        target_id = uuid4()
        user_id = uuid4()
        
        target = Target(
            id=target_id,
            name="Test Target",
            value="example.com",
            scope=TargetScope.DOMAIN,
            status=TargetStatus.ACTIVE,
            is_primary=True,
            scope_config={"key": "value"},
            user_id=user_id,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        target_dict = target.to_dict()
        
        assert target_dict["id"] == str(target_id)
        assert target_dict["name"] == "Test Target"
        assert target_dict["value"] == "example.com"
        assert target_dict["scope"] == "domain"
        assert target_dict["status"] == "active"
        assert target_dict["is_primary"] is True
        assert target_dict["scope_config"] == {"key": "value"}
        assert target_dict["user_id"] == str(user_id)
    
    def test_target_repr(self):
        """Test target string representation."""
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            scope=TargetScope.DOMAIN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        expected_repr = "<Target(name='Test Target', scope='domain', value='example.com')>"
        assert repr(target) == expected_repr

    @pytest.mark.asyncio
    async def test_target_creation_success(self, db_session):
        """Test successful target creation with all fields."""
        target_data = {
            "name": "Test Target",
            "value": "example.com",
            "scope": TargetScope.DOMAIN,
            "status": TargetStatus.ACTIVE,
            "is_primary": True,
            "scope_config": {"subdomains": ["*.example.com"]},
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        target = Target(**target_data)
        db_session.add(target)
        await db_session.commit()
        await db_session.refresh(target)
        
        assert target.id is not None
        assert target.name == "Test Target"
        assert target.value == "example.com"
        assert target.scope == TargetScope.DOMAIN
        assert target.status == TargetStatus.ACTIVE
        assert target.is_primary is True
        assert target.scope_config == {"subdomains": ["*.example.com"]}
    
    @pytest.mark.asyncio
    async def test_target_creation_minimal_data(self, db_session):
        """Test target creation with minimal required fields."""
        target_data = {
            "name": "Minimal Target",
            "value": "test.com",
            "scope": TargetScope.DOMAIN,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }
        
        target = Target(**target_data)
        db_session.add(target)
        await db_session.commit()
        await db_session.refresh(target)
        
        assert target.id is not None
        assert target.name == "Minimal Target"
        assert target.value == "test.com"
        assert target.scope == TargetScope.DOMAIN
        assert target.status == TargetStatus.ACTIVE  # Default value
        assert target.is_primary is False  # Default value
    
    def test_target_ip_addresses_validation(self):
        """Test target scope configuration validation."""
        # Test valid scope configs
        valid_configs = [
            {"subdomains": ["*.example.com"]},
            {"ips": ["192.168.1.1", "192.168.1.2"]},
            {"range": "192.168.1.0/24"},
            {},  # Empty config is valid
            None  # None is valid
        ]
        
        for config in valid_configs:
            target = Target(
                id=uuid4(),
                name="Test Target",
                value="example.com",
                scope=TargetScope.DOMAIN,
                scope_config=config,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            assert target.scope_config == config
    
    @pytest.mark.asyncio
    async def test_target_scope_validation(self, db_session):
        """Test target scope validation."""
        # Test valid scopes
        valid_scopes = [
            TargetScope.DOMAIN,
            TargetScope.IP_RANGE,
            TargetScope.SUBNET,
            TargetScope.WILDCARD
        ]
        
        scope_values = {
            TargetScope.DOMAIN: "example.com",
            TargetScope.IP_RANGE: "192.168.1.1",
            TargetScope.SUBNET: "192.168.1.0/24",
            TargetScope.WILDCARD: "*.example.com"
        }
        
        for scope in valid_scopes:
            target = Target(
                id=uuid4(),
                name="Test Target",
                value=scope_values[scope],
                scope=scope,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.scope == scope
            await db_session.delete(target)
            await db_session.commit()
        
        # Test invalid scopes - these should fail at the database level
        invalid_scopes = [
            "invalid-scope",
            "test",
            "random",
        ]
        
        for scope in invalid_scopes:
            target = Target(
                id=uuid4(),
                name="Test Target",
                value="example.com",
                scope=scope,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            with pytest.raises(Exception):  # SQLAlchemy will raise an exception for invalid enum values
                await db_session.commit()
            await db_session.rollback()
    
    @pytest.mark.asyncio
    async def test_target_description_validation(self, db_session):
        """Test target name validation."""
        # Test valid names
        valid_names = [
            "Test target",
            "A" * 255,  # Maximum length
            "Target 1",
            "My Target",
        ]
        
        for name in valid_names:
            target = Target(
                id=uuid4(),
                name=name,
                value="example.com",
                scope=TargetScope.DOMAIN,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )
            db_session.add(target)
            await db_session.commit()
            await db_session.refresh(target)
            assert target.name == name
            await db_session.delete(target)
            await db_session.commit()
        
        # Test invalid names
        invalid_names = [
            "",  # Empty name
            "A" * 256,  # Too long
        ]
        
        for name in invalid_names:
            with pytest.raises(ValueError):
                target = Target(
                    id=uuid4(),
                    name=name,
                    value="example.com",
                    scope=TargetScope.DOMAIN,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc)
                )
    
    def test_target_update(self):
        """Test target update method."""
        # Arrange
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            scope=TargetScope.DOMAIN,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        update_data = {
            "value": "updated.com",
            "name": "Updated Target",
            "scope_config": {"subdomains": ["*.updated.com"]}
        }
        
        # Act
        for key, value in update_data.items():
            setattr(target, key, value)
        target.updated_at = datetime.now(timezone.utc)
        
        # Assert
        assert target.value == "updated.com"
        assert target.name == "Updated Target"
        assert target.scope_config == {"subdomains": ["*.updated.com"]}
        assert target.updated_at > target.created_at
    
    @pytest.mark.asyncio
    async def test_target_validation_methods(self, db_session):
        """Test target validation methods."""
        # Arrange
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="example.com",
            scope=TargetScope.DOMAIN,
            scope_config={"ips": ["192.168.1.1"]},
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Act & Assert
        assert target._is_valid_domain("example.com") is True
        assert target.scope in TargetScope
        assert target.scope_config is not None
        
        # Test invalid cases
        assert target._is_valid_domain("invalid") is False
        
        # Test invalid scope (this would be caught by SQLAlchemy enum validation)
        target.scope = "invalid-scope"
        db_session.add(target)
        with pytest.raises(Exception):  # SQLAlchemy will raise an exception for invalid enum values
            await db_session.commit()
        await db_session.rollback()
    
    def test_target_scope_matching(self):
        """Test target scope matching functionality."""
        # Arrange
        target = Target(
            id=uuid4(),
            name="Test Target",
            value="*.example.com",
            scope=TargetScope.WILDCARD,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
        
        # Act & Assert - for wildcard scope, we check if the value matches the pattern
        assert target._is_valid_wildcard("*.example.com") is True
        assert target._is_valid_wildcard("*.other.com") is True  # Both are valid wildcard formats
        
        # Test wildcard pattern matching
        assert target._matches_wildcard_pattern("example.com", "*.example.com") is True
        assert target._matches_wildcard_pattern("sub.example.com", "*.example.com") is True
        assert target._matches_wildcard_pattern("other.com", "*.example.com") is False
        assert target._matches_wildcard_pattern("sub.other.com", "*.example.com") is False
        
        # Test with different scope patterns
        target.scope = TargetScope.DOMAIN
        target.value = "api.example.com"
        assert target._is_valid_domain("api.example.com") is True
        assert target._is_valid_domain("sub.api.example.com") is True  # This is a valid domain
