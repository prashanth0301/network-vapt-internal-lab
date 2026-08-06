"""Tests for GET /api/v1/captures search param and DELETE /api/v1/captures/{capture_id}."""

import uuid

import pytest
from sqlalchemy import delete

from app.models.packet_capture import PacketCapture

PCAP_BYTES = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16


async def _create_capture(db_session, filename="test.pcap", **kwargs) -> uuid.UUID:
    capture_id = uuid.uuid4()
    db_session.add(
        PacketCapture(
            id=capture_id,
            filename=filename,
            filepath=f"/tmp/{capture_id}.pcap",
            file_size=kwargs.get("file_size", 1024),
            packet_count=kwargs.get("packet_count", 50),
        )
    )
    await db_session.commit()
    return capture_id


async def _delete_capture(db_session, capture_id):
    await db_session.execute(
        delete(PacketCapture).where(PacketCapture.id == capture_id)
    )
    await db_session.commit()


# ---- Search Tests ----


@pytest.mark.asyncio
async def test_list_captures_returns_all_by_default(client, db_session, auth_headers):
    capture_id = await _create_capture(db_session, filename="default_search_test.pcap")
    resp = await client.get("/api/v1/captures", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data["data"], list)
    filenames = [c["filename"] for c in data["data"]]
    assert "default_search_test.pcap" in filenames
    await _delete_capture(db_session, capture_id)


@pytest.mark.asyncio
async def test_list_captures_search_by_filename(client, db_session, auth_headers):
    capture_id = await _create_capture(db_session, filename="unique_xyz_123.pcap")
    resp = await client.get("/api/v1/captures?search=unique_xyz_123", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    filenames = [c["filename"] for c in data["data"]]
    assert "unique_xyz_123.pcap" in filenames
    await _delete_capture(db_session, capture_id)


@pytest.mark.asyncio
async def test_list_captures_search_no_results(client, db_session, auth_headers):
    resp = await client.get("/api/v1/captures?search=zzz_nonexistent_zzz", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"] == []


@pytest.mark.asyncio
async def test_list_captures_search_case_insensitive(client, db_session, auth_headers):
    capture_id = await _create_capture(db_session, filename="CaseTest.pcap")
    resp = await client.get("/api/v1/captures?search=casetest", headers=auth_headers)
    assert resp.status_code == 200
    filenames = [c["filename"] for c in resp.json()["data"]]
    assert "CaseTest.pcap" in filenames
    await _delete_capture(db_session, capture_id)


# ---- Delete Tests ----


@pytest.mark.asyncio
async def test_delete_capture_success(client, db_session, auth_headers, tmp_path):
    pcap_file = tmp_path / "to_delete.pcap"
    pcap_file.write_bytes(PCAP_BYTES)
    capture_id = await _create_capture(db_session, filename="to_delete.pcap")
    # Update filepath to the real temp file
    await db_session.execute(
        PacketCapture.__table__.update()
        .where(PacketCapture.id == capture_id)
        .values(filepath=str(pcap_file))
    )
    await db_session.commit()

    resp = await client.delete(f"/api/v1/captures/{capture_id}", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["id"] == str(capture_id)

    # Verify row is gone
    from sqlalchemy import select
    result = await db_session.execute(select(PacketCapture).where(PacketCapture.id == capture_id))
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_delete_capture_unknown_returns_404(client, auth_headers):
    resp = await client.delete(f"/api/v1/captures/{uuid.uuid4()}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_capture_invalid_id_returns_400(client, auth_headers):
    resp = await client.delete("/api/v1/captures/not-a-uuid", headers=auth_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_delete_capture_requires_authentication(client, db_session):
    capture_id = await _create_capture(db_session, filename="no_auth.pcap")
    resp = await client.delete(f"/api/v1/captures/{capture_id}")
    assert resp.status_code == 401
    await _delete_capture(db_session, capture_id)


@pytest.mark.asyncio
async def test_delete_capture_removes_file(client, db_session, auth_headers, tmp_path):
    pcap_file = tmp_path / "file_delete.pcap"
    pcap_file.write_bytes(PCAP_BYTES)
    capture_id = await _create_capture(db_session, filename="file_delete.pcap")
    await db_session.execute(
        PacketCapture.__table__.update()
        .where(PacketCapture.id == capture_id)
        .values(filepath=str(pcap_file))
    )
    await db_session.commit()

    assert pcap_file.exists()
    resp = await client.delete(f"/api/v1/captures/{capture_id}", headers=auth_headers)
    assert resp.status_code == 200
    assert not pcap_file.exists()
