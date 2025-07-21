import asyncio
from httpx import AsyncClient, ASGITransport
from api.asgi import application

async def debug_workflow_response():
    transport = ASGITransport(app=application)
    client = AsyncClient(transport=transport, base_url='http://testserver')
    
    try:
        response = await client.get('/api/workflows/18eb5957-5b25-4295-9818-161a7663cfac')
        print('Status:', response.status_code)
        print('Response:', response.json())
    finally:
        await client.aclose()

if __name__ == "__main__":
    asyncio.run(debug_workflow_response()) 