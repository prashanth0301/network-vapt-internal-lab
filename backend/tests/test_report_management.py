"""Tests for the Report Management module.

Covers search, filtering, rename, delete (with filesystem synchronization),
and error handling for missing files.
"""

import uuid
from pathlib import Path

import pytest_asyncio
from sqlalchemy import delete, select

from app.models.report import Report


async def _generate(client, headers, report_type="executive", output_format="json", assessment_id=None):
    params = f"report_type={report_type}&output_format={output_format}"
    if assessment_id:
        params += f"&assessment_id={assessment_id}"
    resp = await client.post(f"/api/v1/reports/generate?{params}", headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()["data"]


@pytest_asyncio.fixture(autouse=True)
async def cleanup_reports(db_session):
    """Remove any report rows and their files created during a test."""
    yield
    result = await db_session.execute(select(Report))
    for r in result.scalars().all():
        p = Path(r.filepath)
        if p.exists():
            p.unlink()
    await db_session.execute(delete(Report))
    await db_session.commit()


class TestListAndFilters:
    async def test_generate_creates_row_and_file(self, client, db_session, auth_headers):
        data = await _generate(client, auth_headers, "technical", "json")
        rid = uuid.UUID(data["id"])
        result = await db_session.execute(select(Report).where(Report.id == rid))
        report = result.scalar_one()
        assert report.title == "Technical Report - " + report.created_at.strftime("%Y-%m-%d")
        assert report.format == "json"
        assert report.file_size and report.file_size > 0
        assert Path(report.filepath).exists()

    async def test_list_returns_reports(self, client, auth_headers):
        await _generate(client, auth_headers, "executive", "json")
        await _generate(client, auth_headers, "technical", "html")
        resp = await client.get("/api/v1/reports", headers=auth_headers)
        assert resp.status_code == 200
        items = resp.json()["data"]
        assert len(items) == 2
        assert all("id" in i and "title" in i and "size" in i and "date" in i for i in items)

    async def test_search_by_title(self, client, auth_headers):
        await _generate(client, auth_headers, "executive", "json")
        await _generate(client, auth_headers, "technical", "json")
        resp = await client.get("/api/v1/reports?search=Technical", headers=auth_headers)
        items = resp.json()["data"]
        assert len(items) == 1
        assert "Technical" in items[0]["title"]

    async def test_filter_by_type(self, client, auth_headers):
        await _generate(client, auth_headers, "executive", "json")
        await _generate(client, auth_headers, "compliance", "json")
        resp = await client.get("/api/v1/reports?report_type=compliance", headers=auth_headers)
        items = resp.json()["data"]
        assert len(items) == 1
        assert items[0]["type"] == "Compliance"
        resp2 = await client.get("/api/v1/reports?report_type=technical", headers=auth_headers)
        assert resp2.json()["data"] == []

    async def test_filter_by_assessment(self, client, auth_headers):
        aid = str(uuid.uuid4())
        await _generate(client, auth_headers, "executive", "json", assessment_id=aid)
        await _generate(client, auth_headers, "technical", "json")
        resp = await client.get(f"/api/v1/reports?assessment_id={aid}", headers=auth_headers)
        items = resp.json()["data"]
        assert len(items) == 1
        assert items[0]["assessment_id"] == aid

    async def test_combined_search_and_filters(self, client, auth_headers):
        aid = str(uuid.uuid4())
        await _generate(client, auth_headers, "executive", "json", assessment_id=aid)
        await _generate(client, auth_headers, "technical", "json", assessment_id=aid)
        resp = await client.get(
            f"/api/v1/reports?assessment_id={aid}&search=Technical", headers=auth_headers
        )
        items = resp.json()["data"]
        assert len(items) == 1
        assert "Technical" in items[0]["title"]

    async def test_list_requires_authentication(self, client):
        resp = await client.get("/api/v1/reports")
        assert resp.status_code == 401


class TestRename:
    async def test_rename_report(self, client, db_session, auth_headers):
        data = await _generate(client, auth_headers, "technical", "json")
        rid = data["id"]
        resp = await client.patch(
            f"/api/v1/reports/{rid}?title=Renamed%20Technical%20Report",
            headers=auth_headers,
        )
        assert resp.status_code == 200
        body = resp.json()["data"]
        assert body["title"] == "Renamed Technical Report"
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        report = result.scalar_one()
        assert report.title == "Renamed Technical Report"
        assert Path(report.filepath).exists()

    async def test_rename_empty_title_rejected(self, client, auth_headers):
        data = await _generate(client, auth_headers, "executive", "json")
        resp = await client.patch(
            f"/api/v1/reports/{data['id']}?title=%20%20", headers=auth_headers
        )
        assert resp.status_code == 400

    async def test_rename_not_found(self, client, auth_headers):
        resp = await client.patch(
            f"/api/v1/reports/{uuid.uuid4()}?title=Anything", headers=auth_headers
        )
        assert resp.status_code == 404

    async def test_rename_invalid_id(self, client, auth_headers):
        resp = await client.patch("/api/v1/reports/not-a-uuid?title=X", headers=auth_headers)
        assert resp.status_code == 400


class TestDelete:
    async def test_delete_removes_row_and_file(self, client, db_session, auth_headers):
        data = await _generate(client, auth_headers, "executive", "json")
        rid = data["id"]
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        filepath = Path(result.scalar_one().filepath)
        assert filepath.exists()

        resp = await client.delete(f"/api/v1/reports/{rid}", headers=auth_headers)
        assert resp.status_code == 200
        assert "Report deleted" in resp.json()["message"]

        assert not filepath.exists()
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        assert result.scalar_one_or_none() is None

    async def test_delete_with_missing_file_still_syncs_db(self, client, db_session, auth_headers):
        data = await _generate(client, auth_headers, "technical", "json")
        rid = data["id"]
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        filepath = Path(result.scalar_one().filepath)
        filepath.unlink()

        resp = await client.delete(f"/api/v1/reports/{rid}", headers=auth_headers)
        assert resp.status_code == 200
        assert "already missing" in resp.json()["message"]
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        assert result.scalar_one_or_none() is None

    async def test_delete_not_found(self, client, auth_headers):
        resp = await client.delete(f"/api/v1/reports/{uuid.uuid4()}", headers=auth_headers)
        assert resp.status_code == 404

    async def test_delete_invalid_id(self, client, auth_headers):
        resp = await client.delete("/api/v1/reports/nope", headers=auth_headers)
        assert resp.status_code == 400


class TestDownload:
    async def test_download_ok(self, client, auth_headers):
        data = await _generate(client, auth_headers, "executive", "json")
        resp = await client.get(f"/api/v1/reports/download/{data['id']}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/json"
        assert b"report_type" in resp.content

    async def test_download_missing_file_returns_404(self, client, db_session, auth_headers):
        data = await _generate(client, auth_headers, "executive", "json")
        rid = data["id"]
        result = await db_session.execute(
            select(Report).where(Report.id == uuid.UUID(rid))
        )
        Path(result.scalar_one().filepath).unlink()
        resp = await client.get(f"/api/v1/reports/download/{rid}", headers=auth_headers)
        assert resp.status_code == 404

    async def test_download_not_found(self, client, auth_headers):
        resp = await client.get(
            f"/api/v1/reports/download/{uuid.uuid4()}", headers=auth_headers
        )
        assert resp.status_code == 404
