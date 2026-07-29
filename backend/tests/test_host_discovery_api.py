import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_hosts_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/hosts")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert isinstance(data["data"], list)


@pytest.mark.asyncio
async def test_hosts_summary_endpoint(client: AsyncClient):
    response = await client.get("/api/v1/hosts/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "total_hosts" in data["data"]
    assert "alive_hosts" in data["data"]


@pytest.mark.asyncio
async def test_create_discovery_assessment(client: AsyncClient):
    response = await client.post(
        "/api/v1/hosts/discover",
        json={
            "target": "192.168.56.0/24",
            "scan_type": "ping_sweep",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "assessment_id" in data["data"]


@pytest.mark.asyncio
async def test_get_nonexistent_host(client: AsyncClient):
    response = await client.get("/api/v1/hosts/nonexistent-id")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_delete_nonexistent_host(client: AsyncClient):
    response = await client.delete("/api/v1/hosts/nonexistent-id")
    assert response.status_code == 200
