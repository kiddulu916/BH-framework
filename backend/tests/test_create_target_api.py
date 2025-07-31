import httpx

url = "http://localhost:8000/api/targets/"
payload = {
    "target": "Example Target",
    "scope": "domain",
    "value": "example.com",
    "description": "Test target for bug bounty",
    "is_primary": True,
    "program_name": "Example Bug Bounty",
    "platform": "hackerone",
    "program_description": "This is a test bug bounty program.",
    "contact_email": "security@example.com",
    "contact_url": "https://hackerone.com/example",
    "approved_urls": ["https://example.com", "https://api.example.com"],
    "blacklisted_urls": ["https://admin.example.com"],
    "scope_rules": ["No testing on production", "Respect robots.txt"],
    "restrictions": ["No DDoS", "No social engineering"],
    "rate_limits": {
        "requests_per_minute": 60,
        "requests_per_hour": 1000,
        "requests_per_day": 10000,
        "burst_limit": 10,
        "cooldown_period": 60
    },
    "custom_headers": [
        {"name": "X-Test-Header", "value": "test"}
    ],
    "special_instructions": "Contact us before testing.",
    "notes": "This is a test run."
}

async def test_create_target():
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload)
            print(f"Status: {response.status_code}")
            print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_create_target()) 