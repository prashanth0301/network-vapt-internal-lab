import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_returns_200(client: AsyncClient):
    response = await client.get("/api/v1/health")
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_health_endpoint_structure(client: AsyncClient):
    response = await client.get("/api/v1/health")
    data = response.json()

    assert "status" in data
    assert "version" in data
    assert "app_name" in data
    assert "database" in data
    assert "uptime_seconds" in data
    assert "services" in data
    assert "timestamp" in data


@pytest.mark.asyncio
async def test_health_endpoint_valid_status(client: AsyncClient):
    response = await client.get("/api/v1/health")
    data = response.json()
    assert data["status"] in ("healthy", "degraded")


@pytest.mark.asyncio
async def test_health_endpoint_app_name(client: AsyncClient):
    response = await client.get("/api/v1/health")
    data = response.json()
    assert data["app_name"] == "Network VAPT Platform"


@pytest.mark.asyncio
async def test_health_endpoint_services(client: AsyncClient):
    response = await client.get("/api/v1/health")
    data = response.json()
    assert "api" in data["services"]
    assert "database" in data["services"]
    assert data["services"]["api"] == "running"
