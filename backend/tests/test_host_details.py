"""Tests for the Host Details page endpoint:

- consolidated payload shape (host, os info, ports, services, banners,
  vulnerabilities, cves, exploits, evidence, scan history, reports)
- summary counts
- 404 for missing / malformed host ids
- empty host (no data) returns empty lists
- scan history and reports span all assessments discovering the IP
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.exploit import Exploit
from app.models.host import Host
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.vulnerability import Vulnerability

NOW = datetime.now(timezone.utc)


async def _seed_host(
    db: AsyncSession,
    ip: str = "10.30.0.10",
    scan: Scan | None = None,
) -> Host:
    host = Host(
        scan_id=scan.id if scan else None,
        ip_address=ip,
        hostname="web-prod-01",
        mac_address="02:42:ac:11:00:02",
        vendor="VMware",
        os_name="Linux",
        os_version="5.15.0",
        os_accuracy=94,
        status="up",
        latency=1.2,
        is_alive=True,
    )
    db.add(host)
    await db.flush()
    return host


async def _seed_host_data(db: AsyncSession, host: Host, scan_id: uuid.UUID) -> dict:
    port_open = Port(host_id=host.id, port=80, protocol="tcp", state="open", reason="syn-ack")
    port_closed = Port(host_id=host.id, port=81, protocol="tcp", state="closed")
    db.add_all([port_open, port_closed])
    await db.flush()

    svc = Service(
        port_id=port_open.id,
        name="http",
        product="nginx",
        version="1.24.0",
        category="web",
        confidence=90,
        banner="nginx/1.24.0 (Ubuntu)",
    )
    db.add(svc)

    vuln = Vulnerability(
        host_id=host.id,
        scan_id=scan_id,
        name="Path Traversal",
        severity="High",
        risk_score=7.5,
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        status="open",
        confidence=85,
        cve_ids=["CVE-2021-41773"],
        cve_count=1,
        evidence="Observed ../../ traversal in GET /icons/%2e%2e/%2e%2e/etc/passwd",
        plugin_output="HTTP 200 with /etc/passwd content",
    )
    db.add(vuln)
    await db.flush()

    db.add(CVE(vuln_id=vuln.id, cve_id="CVE-2021-41773", description="Apache path traversal",
               cvss_v3=7.5, cvss_score=7.5, cvss_severity="High", exploit_available=True,
               metasploit_module="exploit/multi/http/apache_normalize_path", epss_score=0.9,
               kev_status=True, source="nvd"))
    db.add(Exploit(host_id=host.id, provider="exploitdb", module_name="exploit/multi/http/apache_normalize_path",
                   exploit_name="Apache 2.4.49 RCE", cve="CVE-2021-41773", rank="excellent",
                   remote_local="remote", verified=True, status="available", risk_level="critical"))
    await db.commit()
    return {"port_open_id": port_open.id, "svc_id": svc.id, "vuln_id": vuln.id}


async def _cleanup(db: AsyncSession, host: Host, scan_ids: list[uuid.UUID]) -> None:
    for sid in scan_ids:
        report_rows = (
            await db.execute(Report.__table__.select().where(Report.scan_id == sid))
        ).fetchall()
        for row in report_rows:
            await db.delete(await db.get(Report, row.id))
    for sid in scan_ids:
        scan = await db.get(Scan, sid)
        if scan:
            await db.delete(scan)
    if host is not None:
        await db.delete(host)
    await db.commit()


@pytest.mark.asyncio
async def test_host_details_endpoint_shape(
    client: AsyncClient, db_session: AsyncSession
):
    scan = Scan(name="Full Scan A", scan_type="full_assessment", target="10.30.0.0/24",
                status="completed",
                started_at=NOW - timedelta(minutes=5), completed_at=NOW)
    db_session.add(scan)
    await db_session.flush()
    host = await _seed_host(db_session, scan=scan)
    await _seed_host_data(db_session, host, scan.id)
    report = Report(scan_id=scan.id, title="Technical Report - 2026-08-03",
                    report_type="Technical", format="json",
                    filepath="/tmp/host-details-test.json", file_size=1024)
    db_session.add(report)
    await db_session.commit()

    try:
        response = await client.get(f"/api/v1/hosts/{host.id}/details")
        assert response.status_code == 200
        data = response.json()["data"]

        assert data["host"]["ip_address"] == "10.30.0.10"
        assert data["host"]["hostname"] == "web-prod-01"
        assert data["os_information"]["os_name"] == "Linux"
        assert data["os_information"]["os_version"] == "5.15.0"
        assert data["os_information"]["os_accuracy"] == 94
        assert data["os_information"]["vendor"] == "VMware"
        assert data["os_information"]["mac_address"] == "02:42:ac:11:00:02"
        assert data["os_information"]["is_alive"] is True

        assert len(data["open_ports"]) == 2
        open_states = {p["state"] for p in data["open_ports"]}
        assert open_states == {"open", "closed"}

        assert len(data["services"]) == 1
        svc = data["services"][0]
        assert svc["port"] == 80
        assert svc["name"] == "http"
        assert svc["product"] == "nginx"
        assert svc["version"] == "1.24.0"
        assert svc["banner"] == "nginx/1.24.0 (Ubuntu)"

        assert len(data["banners"]) == 1
        assert data["banners"][0]["banner"].startswith("nginx/")

        assert len(data["vulnerabilities"]) == 1
        vuln = data["vulnerabilities"][0]
        assert vuln["severity"] == "High"
        assert vuln["risk_score"] == 7.5
        assert vuln["cve_ids"] == ["CVE-2021-41773"]

        assert len(data["cves"]) == 1
        cve = data["cves"][0]
        assert cve["cve_id"] == "CVE-2021-41773"
        assert cve["exploit_available"] is True
        assert cve["kev_status"] is True
        assert cve["epss_score"] == 0.9

        assert len(data["exploits"]) == 1
        assert data["exploits"][0]["module_name"].endswith("apache_normalize_path")
        assert data["exploits"][0]["verified"] is True

        assert len(data["evidence"]) == 1
        ev = data["evidence"][0]
        assert "traversal" in ev["evidence"]
        assert "HTTP 200" in ev["plugin_output"]

        assert len(data["scan_history"]) == 1
        scan_entry = data["scan_history"][0]
        assert scan_entry["name"] == "Full Scan A"
        assert scan_entry["duration_seconds"] == 300

        assert len(data["reports"]) == 1
        assert data["reports"][0]["title"].startswith("Technical Report")

        assert data["summary"] == {
            "ports": 2, "open_ports": 1, "services": 1, "banners": 1,
            "vulnerabilities": 1, "cves": 1, "exploits": 1, "evidence": 1,
            "scans": 1, "reports": 1,
        }
    finally:
        await _cleanup(db_session, host, [scan.id])


@pytest.mark.asyncio
async def test_host_details_missing_host_404(client: AsyncClient):
    response = await client.get(f"/api/v1/hosts/{uuid.uuid4()}/details")
    assert response.status_code == 404
    response = await client.get("/api/v1/hosts/not-a-uuid/details")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_host_details_empty_data(client: AsyncClient, db_session: AsyncSession):
    host = await _seed_host(db_session, ip="10.30.0.99")
    await db_session.commit()
    try:
        response = await client.get(f"/api/v1/hosts/{host.id}/details")
        assert response.status_code == 200
        data = response.json()["data"]
        for key in ("open_ports", "services", "banners", "vulnerabilities",
                    "cves", "exploits", "evidence", "scan_history", "reports"):
            assert data[key] == []
        assert data["summary"]["ports"] == 0
        assert data["summary"]["scans"] == 0
        assert data["os_information"]["os_name"] == "Linux"
    finally:
        await _cleanup(db_session, host, [])


@pytest.mark.asyncio
async def test_scan_history_and_reports_span_assessments(
    client: AsyncClient, db_session: AsyncSession
):
    scan_a = Scan(name="Scan A", scan_type="host_discovery", target="10.30.0.0/24",
                  status="completed")
    scan_b = Scan(name="Scan B", scan_type="full_assessment", target="10.30.0.10/32",
                  status="completed")
    db_session.add_all([scan_a, scan_b])
    await db_session.flush()

    host_a = await _seed_host(db_session, ip="10.30.0.10", scan=scan_a)
    host_b = await _seed_host(db_session, ip="10.30.0.10", scan=scan_b)
    report_b = Report(scan_id=scan_b.id, title="Scan B Report", report_type="Technical",
                      format="json", filepath="/tmp/scan-b-report.json", file_size=512)
    db_session.add(report_b)
    await db_session.commit()

    try:
        response = await client.get(f"/api/v1/hosts/{host_a.id}/details")
        assert response.status_code == 200
        data = response.json()["data"]
        scan_names = {s["name"] for s in data["scan_history"]}
        assert scan_names == {"Scan A", "Scan B"}
        report_titles = [r["title"] for r in data["reports"]]
        assert "Scan B Report" in report_titles
        assert data["summary"]["scans"] == 2
        assert data["summary"]["reports"] == 1
    finally:
        await _cleanup(db_session, host_a, [scan_a.id, scan_b.id])
        await _cleanup(db_session, host_b, [])
