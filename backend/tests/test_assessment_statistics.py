import pytest
from httpx import AsyncClient

from app.services.assessment import assessment_manager
from app.services.assessment.lifecycle import AssessmentStatus


@pytest.mark.asyncio
async def test_assessment_statistics_endpoint(client: AsyncClient, auth_headers: dict):
    response = await client.get("/api/v1/assessments/statistics", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "total" in data["data"]
    assert "by_status" in data["data"]
    assert "success_count" in data["data"]
    assert "failure_count" in data["data"]
    assert "active_count" in data["data"]


@pytest.mark.asyncio
async def test_assessment_statistics_reflects_status_counts(
    client: AsyncClient, auth_headers: dict
):
    record = assessment_manager.create_assessment(
        name="stats-check",
        scan_type="port_scan",
        target="10.0.0.1",
    )
    assessment_manager.update_assessment_status(record.id, AssessmentStatus.PENDING)
    assessment_manager.update_assessment_status(record.id, AssessmentStatus.RUNNING)

    response = await client.get("/api/v1/assessments/statistics", headers=auth_headers)
    assert response.status_code == 200
    stats = response.json()["data"]
    assert stats["total"] >= 1
    assert stats["by_status"].get("running", 0) >= 1
    assert stats["active_count"] >= 1

    assessment_manager.delete_assessment(record.id)


@pytest.mark.asyncio
async def test_assessment_statistics_requires_authentication(client: AsyncClient):
    response = await client.get("/api/v1/assessments/statistics")
    assert response.status_code == 401
