import httpx
import json

async def test_running_backend():
    """Test the running backend to see what database it's using."""
    print("Testing running backend...")
    
    try:
        # Test health endpoint
        async with httpx.AsyncClient() as client:
            response = await client.get("http://localhost:8000/health/")
            print(f"Health endpoint status: {response.status_code}")
            if response.status_code == 200:
                health_data = response.json()
                print(f"Health data: {json.dumps(health_data, indent=2)}")
            
            # Test targets endpoint
            response = await client.get("http://localhost:8000/api/targets/")
            print(f"Targets endpoint status: {response.status_code}")
            if response.status_code == 200:
                targets_data = response.json()
                print(f"Targets data: {json.dumps(targets_data, indent=2)}")
                
    except Exception as e:
        print(f"Error testing backend: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_running_backend()) 