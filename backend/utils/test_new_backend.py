import httpx
import json

async def test_new_backend():
    """Test the new backend instance on port 8001."""
    print("Testing new backend on port 8001...")
    
    try:
        async with httpx.AsyncClient() as client:
            # Test health endpoint
            response = await client.get("http://localhost:8001/health/")
            print(f"Health endpoint status: {response.status_code}")
            if response.status_code == 200:
                health_data = response.json()
                print(f"Health data: {json.dumps(health_data, indent=2)}")
            
            # Test targets endpoint
            response = await client.get("http://localhost:8001/api/targets/")
            print(f"Targets endpoint status: {response.status_code}")
            if response.status_code == 200:
                targets_data = response.json()
                print(f"Targets data: {json.dumps(targets_data, indent=2)}")
                
    except Exception as e:
        print(f"Error testing new backend: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_new_backend()) 