import pytest
from httpx import AsyncClient
from uuid import uuid4

@pytest.mark.asyncio
async def test_create_target_from_frontend_payload(api_client: AsyncClient):
    """
    Tests creating a target using a payload structure similar to the one
    sent by the new frontend profile builder.
    """
    unique_id = uuid4().hex[:8]
    domain = f"test-{unique_id}.com"
    
    frontend_payload = {
        "name": f"Test Target {unique_id}",
        "scope": "DOMAIN",
        "value": domain,
        "is_primary": True,
        "platform": "hackerone",
        "contact_email": f"researcher@{unique_id}.com",
        "approved_urls": [f"https://www.{domain}", f"https://api.{domain}"],
        "blacklisted_urls": [f"https://legacy.{domain}"],
        "scope_rules": ["Do not test during business hours"],
        "restrictions": ["Do not perform DDoS attacks"],
        "rate_limits": {
            "requests_per_minute": 100,
            "cooldown_period": 60,
        },
        "notes": "Do not perform DDoS attacks",
        "special_instructions": "Do not test during business hours",
    }

    # Act
    response = await api_client.post("/api/targets/", json=frontend_payload)

    # Assert
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["message"] == "Target created successfully"
    
    # Verify the created data
    created_target = data["data"]
    assert created_target["name"] == frontend_payload["name"]
    assert created_target["value"] == frontend_payload["value"]
    assert created_target["platform"] == "hackerone"
    assert created_target["approved_urls"] == frontend_payload["approved_urls"]
    assert created_target["rate_limits"]["requests_per_minute"] == 100 