"""Tests for the Assessment History feature:

- list filters (search / target / status / date range)
- list summary fields (severity counts, duration, progress)
- clone assessment
- assessment summary endpoint
- cascade delete (reports + files, artifacts + dirs, captures, findings, scan)

Assessments are created through the in-memory manager (as existing
assessment tests do) to avoid persisting into the real database; any
records that do reach the database are removed by the cascade delete.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.artifact import Artifact
from app.models.cve import CVE
from app.models.exploit import Exploit
from app.models.exploit_run import ExploitRun
from app.models.host import Host
from app.models.packet_capture import PacketCapture
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.vulnerability import Vulnerability
from app.services.artifact_manager import artifact_manager
from app.services.assessment import assessment_manager
from app.services.assessment.lifecycle import AssessmentStatus


def _create(name: str, target: str = "10.0.0.5", scan_type: str = "port_scan"):
    return assessment_manager.create_assessment(
        name=name, scan_type=scan_type, target=target
    )


async def _complete(record) -> None:
    assessment_manager.update_assessment_status(
        record.id, AssessmentStatus.PENDING
    )
    assessment_manager.update_assessment_status(
        record.id, AssessmentStatus.RUNNING
    )
    assessment_manager.update_assessment_status(
        record.id, AssessmentStatus.COMPLETED
    )
    record.started_at = datetime.now(timezone.utc) - timedelta(seconds=120)
    record.completed_at = datetime.now(timezone.utc)


async def _seed_findings(db: AsyncSession, scan_id: str) -> None:
    host = Host(scan_id=uuid.UUID(scan_id), ip_address="10.0.0.5", is_alive=True)
    db.add(host)
    await db.flush()
    port = Port(host_id=host.id, port=80, protocol="tcp", state="open")
    db.add(port)
    await db.flush()
    service = Service(
        port_id=port.id, name="http", product="nginx", version="1.24.0"
    )
    db.add(service)
    await db.flush()

    vuln = Vulnerability(
        host_id=host.id,
        scan_id=uuid.UUID(scan_id),
        name="Test Critical",
        severity="Critical",
    )
    db.add(vuln)
    await db.flush()
    db.add(CVE(vuln_id=vuln.id, cve_id="CVE-2026-0001", description="test"))
    exploit = Exploit(
        host_id=host.id,
        provider="test",
        module_name="exploit/linux/http/test",
        status="available",
    )
    db.add(exploit)
    await db.flush()
    db.add(ExploitRun(host_id=host.id, exploit_id=exploit.id, status="completed"))

    vuln_high = Vulnerability(
        host_id=host.id,
        scan_id=uuid.UUID(scan_id),
        name="Test High",
        severity="High",
    )
    db.add(vuln_high)
    await db.flush()

    db.add(
        Artifact(
            assessment_id=uuid.UUID(scan_id),
            stage_name="port_scan",
            artifact_path="/tmp/nonexistent-nowhere",
            status="completed",
        )
    )
    await db.commit()


@pytest.mark.asyncio
async def test_list_search_matches_name_and_target(client: AsyncClient, auth_headers: dict):
    a = _create(name="Alpha Web Scan", target="192.168.1.10")
    b = _create(name="Beta DB Audit", target="192.168.1.20")
    try:
        response = await client.get(
            "/api/v1/assessments", params={"search": "alpha"}, headers=auth_headers
        )
        assert response.status_code == 200
        names = [item["name"] for item in response.json()["data"]]
        assert a.name in names
        assert b.name not in names

        response = await client.get(
            "/api/v1/assessments",
            params={"search": "192.168.1.20"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        names = [item["name"] for item in response.json()["data"]]
        assert b.name in names
        assert a.name not in names
    finally:
        assessment_manager.delete_assessment(a.id)
        assessment_manager.delete_assessment(b.id)


@pytest.mark.asyncio
async def test_list_target_filter(client: AsyncClient, auth_headers: dict):
    a = _create(name="Target Filter A", target="10.1.1.1")
    b = _create(name="Target Filter B", target="10.2.2.2")
    try:
        response = await client.get(
            "/api/v1/assessments", params={"target": "10.1.1"}, headers=auth_headers
        )
        assert response.status_code == 200
        items = response.json()["data"]
        assert all(item["name"] == a.name for item in items if item["target"] == "10.1.1.1")
        names = [item["name"] for item in items]
        assert a.name in names
        assert b.name not in names
    finally:
        assessment_manager.delete_assessment(a.id)
        assessment_manager.delete_assessment(b.id)


@pytest.mark.asyncio
async def test_list_status_filter(client: AsyncClient, auth_headers: dict):
    a = _create(name="Status Running One")
    b = _create(name="Status Completed One")
    assessment_manager.update_assessment_status(a.id, AssessmentStatus.PENDING)
    assessment_manager.update_assessment_status(a.id, AssessmentStatus.RUNNING)
    await _complete(b)
    try:
        response = await client.get(
            "/api/v1/assessments", params={"status": "running"}, headers=auth_headers
        )
        items = response.json()["data"]
        assert any(item["id"] == a.id for item in items)
        assert not any(item["id"] == b.id for item in items)

        response = await client.get(
            "/api/v1/assessments", params={"status": "completed"}, headers=auth_headers
        )
        items = response.json()["data"]
        assert any(item["id"] == b.id for item in items)
        assert not any(item["id"] == a.id for item in items)
    finally:
        assessment_manager.delete_assessment(a.id)
        assessment_manager.delete_assessment(b.id)


@pytest.mark.asyncio
async def test_list_date_filters(client: AsyncClient, auth_headers: dict):
    a = _create(name="Date Filter Today")
    today = datetime.now(timezone.utc)
    yesterday = today - timedelta(days=1)
    try:
        response = await client.get(
            "/api/v1/assessments",
            params={
                "date_from": yesterday.strftime("%Y-%m-%d"),
                "date_to": today.strftime("%Y-%m-%d"),
            },
            headers=auth_headers,
        )
        assert any(item["id"] == a.id for item in response.json()["data"])

        response = await client.get(
            "/api/v1/assessments",
            params={
                "date_from": "2000-01-01",
                "date_to": yesterday.strftime("%Y-%m-%d"),
            },
            headers=auth_headers,
        )
        assert not any(item["id"] == a.id for item in response.json()["data"])
    finally:
        assessment_manager.delete_assessment(a.id)


@pytest.mark.asyncio
async def test_list_includes_severity_duration_and_progress(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
):
    a = _create(name="Summary Fields Check", target="10.9.9.9")
    await _complete(a)
    await _seed_findings(db_session, a.id)
    try:
        response = await client.get(
            "/api/v1/assessments",
            params={"search": "Summary Fields"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        items = response.json()["data"]
        item = next(i for i in items if i["id"] == a.id)
        assert item["severity_counts"]["Critical"] == 1
        assert item["severity_counts"]["High"] == 1
        assert item["duration_seconds"] == 120
        assert item["progress_percent"] == 100.0
    finally:
        response = await client.delete(
            f"/api/v1/assessments/{a.id}", headers=auth_headers
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_clone_assessment(client: AsyncClient, auth_headers: dict):
    a = _create(name="Clone Me", target="10.5.5.5", scan_type="vuln_scan")
    a.parameters = {"ports": "80,443"}
    clone_id = None
    try:
        response = await client.post(
            f"/api/v1/assessments/{a.id}/clone", headers=auth_headers
        )
        assert response.status_code == 201
        data = response.json()["data"]
        clone_id = data["id"]
        assert clone_id != a.id
        assert data["name"] == "Clone Me (clone)"
        assert data["scan_type"] == "vuln_scan"
        assert data["target"] == "10.5.5.5"
        assert data["status"] == "draft"
        assert data["parameters"] == {"ports": "80,443"}
    finally:
        assessment_manager.delete_assessment(a.id)
        if clone_id:
            assessment_manager.delete_assessment(clone_id)
            await assessment_manager.remove_persisted(clone_id)


@pytest.mark.asyncio
async def test_clone_missing_assessment_404(client: AsyncClient, auth_headers: dict):
    response = await client.post(
        f"/api/v1/assessments/{uuid.uuid4()}/clone", headers=auth_headers
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_assessment_summary_endpoint(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
):
    a = _create(name="Summary Endpoint", target="10.7.7.7", scan_type="full_assessment")
    await _complete(a)
    await _seed_findings(db_session, a.id)
    try:
        response = await client.get(
            f"/api/v1/assessments/{a.id}/summary", headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["id"] == a.id
        assert data["severity_counts"] == {"Critical": 1, "High": 1}
        assert data["total_vulnerabilities"] == 2
        assert data["hosts_count"] == 1
        assert data["ports_count"] == 1
        assert data["services_count"] == 1
        assert data["reports_count"] == 0
        assert data["exploits_count"] == 1
        assert data["captures_count"] == 0
        assert data["duration_seconds"] == 120
        assert data["progress_percent"] == 100.0
    finally:
        response = await client.delete(
            f"/api/v1/assessments/{a.id}", headers=auth_headers
        )
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_assessment_summary_missing_404(client: AsyncClient, auth_headers: dict):
    response = await client.get(
        f"/api/v1/assessments/{uuid.uuid4()}/summary", headers=auth_headers
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_assessment_cascade(
    client: AsyncClient, db_session: AsyncSession, tmp_path, auth_headers: dict
):
    a = _create(name="Cascade Delete", target="10.8.8.8")
    await _complete(a)

    report_file = tmp_path / "report.json"
    report_file.write_text("{}", encoding="utf-8")
    capture_file = tmp_path / "capture.pcap"
    capture_file.write_bytes(b"\xd4\xc3\xb2\xa1")

    scan_id = uuid.UUID(a.id)
    host = Host(scan_id=scan_id, ip_address="10.8.8.8", is_alive=True)
    db_session.add(host)
    await db_session.flush()
    port = Port(host_id=host.id, port=8080, protocol="tcp", state="open")
    db_session.add(port)
    await db_session.flush()
    service = Service(port_id=port.id, name="http")
    db_session.add(service)
    vuln = Vulnerability(host_id=host.id, scan_id=scan_id, name="V", severity="High")
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(CVE(vuln_id=vuln.id, cve_id="CVE-2026-9999", description="d"))
    exploit = Exploit(host_id=host.id, provider="test", module_name="m", status="available")
    db_session.add(exploit)
    await db_session.flush()
    db_session.add(ExploitRun(host_id=host.id, exploit_id=exploit.id, status="completed"))
    db_session.add(Report(scan_id=scan_id, title="Test Report", report_type="Technical", format="json", filepath=str(report_file), file_size=2))
    db_session.add(PacketCapture(scan_id=scan_id, filename="capture.pcap", filepath=str(capture_file)))
    db_session.add(Artifact(assessment_id=scan_id, stage_name="port_scan", artifact_path=str(tmp_path / "stage"), status="completed"))
    await db_session.commit()

    original_base_dir = artifact_manager._base_dir
    artifact_manager._base_dir = tmp_path
    try:
        stage_dir = tmp_path / ("assessment_" + a.id[:8])
        stage_dir.mkdir(parents=True, exist_ok=True)
        (stage_dir / "output.xml").write_text("<scan/>", encoding="utf-8")

        response = await client.delete(
            f"/api/v1/assessments/{a.id}", headers=auth_headers
        )
        assert response.status_code == 200
        deleted = response.json()["data"]["deleted"]
        assert deleted["reports"] == 1
        assert deleted["artifacts"] == 1
        assert deleted["vulnerabilities"] == 1
        assert deleted["hosts"] == 1
        assert deleted["exploit_runs"] == 1

        assert not report_file.exists()
        assert not capture_file.exists()
        assert not stage_dir.exists()

        for model in (Scan, Report, Artifact, Host, Port, Service, Vulnerability, CVE, Exploit, ExploitRun, PacketCapture):
            rows = (
                await db_session.execute(
                    model.__table__.select()
                )
            ).fetchall()
            assert not any(
                getattr(r, "scan_id", None) == scan_id
                or getattr(r, "host_id", None) == host.id
                or getattr(r, "vuln_id", None) == vuln.id
                or getattr(r, "assessment_id", None) == scan_id
                for r in rows
            ), f"leftover rows in {model.__tablename__}"

        from app.services.assessment.exceptions import AssessmentNotFoundError

        with pytest.raises(AssessmentNotFoundError):
            assessment_manager.get_assessment(a.id)

        response = await client.get(
            "/api/v1/assessments",
            params={"search": "Cascade Delete"},
            headers=auth_headers,
        )
        assert not any(item["id"] == a.id for item in response.json()["data"])
    finally:
        artifact_manager._base_dir = original_base_dir


@pytest.mark.asyncio
async def test_delete_assessment_missing_404(client: AsyncClient, auth_headers: dict):
    response = await client.delete(
        f"/api/v1/assessments/{uuid.uuid4()}", headers=auth_headers
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_assessment_invalid_uuid_404(client: AsyncClient, auth_headers: dict):
    response = await client.delete("/api/v1/assessments/not-a-uuid", headers=auth_headers)
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_history_cleanup_assessment_deletes_reports(
    client: AsyncClient, db_session: AsyncSession, tmp_path, auth_headers: dict
):
    a = _create(name="History Cleanup Cascade", target="10.11.11.11")
    report_file = tmp_path / "h.json"
    report_file.write_text("{}", encoding="utf-8")
    db_session.add(
        Report(
            scan_id=uuid.UUID(a.id),
            title="History Report",
            report_type="Technical",
            format="json",
            filepath=str(report_file),
            file_size=2,
        )
    )
    await db_session.commit()
    try:
        response = await client.delete(
            "/api/v1/history/cleanup",
            params={"preset": "all", "assessment_id": a.id},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert not report_file.exists()

        rows = (
            await db_session.execute(
                Report.__table__.select().where(
                    Report.scan_id == uuid.UUID(a.id)
                )
            )
        ).fetchall()
        assert len(rows) == 0
    finally:
        assessment_manager.delete_assessment(a.id)


@pytest.mark.asyncio
async def test_history_cleanup_custom_range_deletes_findings(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
):
    scan = Scan(
        id=uuid.uuid4(),
        name="Custom Range Cleanup",
        scan_type="port_scan",
        target="10.9.9.9",
        status="completed",
        created_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    db_session.add(scan)
    await db_session.flush()
    await _seed_findings(db_session, str(scan.id))

    from_date = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    to_date = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    try:
        response = await client.delete(
            "/api/v1/history/cleanup",
            params={"preset": "custom", "from_date": from_date, "to_date": to_date},
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["hosts_deleted"] == 1
        assert data["exploits_deleted"] == 1

        host_rows = (
            await db_session.execute(
                Host.__table__.select().where(Host.scan_id == scan.id)
            )
        ).fetchall()
        assert len(host_rows) == 0
    finally:
        assessment_manager.delete_assessment(str(scan.id))


@pytest.mark.asyncio
async def test_history_cleanup_last_7d_deletes_findings(
    client: AsyncClient, db_session: AsyncSession, auth_headers: dict
):
    scan = Scan(
        id=uuid.uuid4(),
        name="7d Cleanup",
        scan_type="port_scan",
        target="10.10.10.10",
        status="completed",
        created_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    db_session.add(scan)
    await db_session.flush()
    await _seed_findings(db_session, str(scan.id))
    try:
        response = await client.delete(
            "/api/v1/history/cleanup",
            params={"preset": "last_7d"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["data"]["hosts_deleted"] == 1
        host_rows = (
            await db_session.execute(
                Host.__table__.select().where(Host.scan_id == scan.id)
            )
        ).fetchall()
        assert len(host_rows) == 0
    finally:
        assessment_manager.delete_assessment(str(scan.id))


@pytest.mark.asyncio
async def test_history_cleanup_custom_requires_dates_400(
    client: AsyncClient, auth_headers: dict
):
    response = await client.delete(
        "/api/v1/history/cleanup",
        params={"preset": "custom"},
        headers=auth_headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_history_cleanup_unknown_preset_400(
    client: AsyncClient, auth_headers: dict
):
    response = await client.delete(
        "/api/v1/history/cleanup",
        params={"preset": "bogus_preset"},
        headers=auth_headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_history_cleanup_malformed_custom_date_400(
    client: AsyncClient, auth_headers: dict
):
    response = await client.delete(
        "/api/v1/history/cleanup",
        params={
            "preset": "custom",
            "from_date": "not-a-date",
            "to_date": "2026-08-04T00:00:00Z",
        },
        headers=auth_headers,
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_history_cleanup_missing_assessment_404(
    client: AsyncClient, auth_headers: dict
):
    response = await client.delete(
        "/api/v1/history/cleanup",
        params={"preset": "all", "assessment_id": str(uuid.uuid4())},
        headers=auth_headers,
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_persisted_assessment_is_listed(client: AsyncClient, auth_headers: dict):
    record = _create(name="Persisted List Check", target="10.12.12.12")
    await assessment_manager.persist_assessment(record.id)
    try:
        response = await client.get(
            "/api/v1/assessments",
            params={"search": "Persisted List Check"},
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert any(
            item["id"] == record.id for item in response.json()["data"]
        )
    finally:
        assessment_manager.delete_assessment(record.id)
        await assessment_manager.remove_persisted(record.id)
