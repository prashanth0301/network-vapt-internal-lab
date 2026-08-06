"""Tests for GET /api/v1/captures/{capture_id}/download.

Verifies that a capture's stored PCAP is streamed with the correct content
type and Content-Disposition, that a 404 is returned when the capture or its
file is missing, and that the endpoint requires authentication (enforced by
the router-level dependency, shared with all capture endpoints).
"""

import uuid

import pytest
from sqlalchemy import delete

from app.models.packet_capture import PacketCapture

PCAP_BYTES = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16


async def _create_capture(db_session, filepath) -> uuid.UUID:
    capture_id = uuid.uuid4()
    db_session.add(
        PacketCapture(
            id=capture_id,
            filename=f"{capture_id}.pcap",
            filepath=str(filepath),
            file_size=1,
            packet_count=1,
        )
    )
    await db_session.commit()
    return capture_id


async def _delete_capture(db_session, capture_id):
    await db_session.execute(
        delete(PacketCapture).where(PacketCapture.id == capture_id)
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_download_streams_valid_pcap(client, db_session, auth_headers, tmp_path):
    pcap_file = tmp_path / "capture.pcap"
    pcap_file.write_bytes(PCAP_BYTES)
    capture_id = await _create_capture(db_session, pcap_file)

    resp = await client.get(
        f"/api/v1/captures/{capture_id}/download", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert "attachment" in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].split("filename=")[-1].strip('"') == f"{capture_id}.pcap"
    assert resp.content == PCAP_BYTES

    await _delete_capture(db_session, capture_id)


@pytest.mark.asyncio
async def test_download_missing_file_returns_404(client, db_session, auth_headers, tmp_path):
    missing = tmp_path / "does_not_exist.pcap"
    capture_id = await _create_capture(db_session, missing)

    resp = await client.get(
        f"/api/v1/captures/{capture_id}/download", headers=auth_headers
    )
    assert resp.status_code == 404

    await _delete_capture(db_session, capture_id)


@pytest.mark.asyncio
async def test_download_unknown_capture_returns_404(client, auth_headers):
    resp = await client.get(
        f"/api/v1/captures/{uuid.uuid4()}/download", headers=auth_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_download_requires_authentication(client, db_session, tmp_path):
    pcap_file = tmp_path / "auth.pcap"
    pcap_file.write_bytes(PCAP_BYTES)
    capture_id = await _create_capture(db_session, pcap_file)

    resp = await client.get(f"/api/v1/captures/{capture_id}/download")
    assert resp.status_code == 401

    await _delete_capture(db_session, capture_id)