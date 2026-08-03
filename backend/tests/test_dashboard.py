"""Tests for the Dashboard summary endpoint.

Verifies role access, empty-state shape, and aggregation correctness for
severity distribution, trend, ports, services, hosts, risk score, counters,
scan durations and the activity timeline.
"""

import uuid
from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.models.audit_log import AuditLog
from app.models.cve import CVE
from app.models.host import Host
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.services.auth import auth_service
from tests.conftest import test_engine

CREATED_IDS: dict[str, list] = {}


@pytest_asyncio.fixture(scope="module")
async def module_session(setup_database) -> AsyncSession:
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as session:
        yield session


async def _ensure_user(module_session, username, email, role) -> str:
    result = await module_session.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        user = await auth_service.create_user(
            module_session,
            username=username,
            email=email,
            password="dashboardpass123",
            full_name=f"Dashboard {role}",
            role=role,
        )
        await module_session.commit()
    CREATED_IDS.setdefault("users", []).append(user.id)
    return auth_service.create_access_token(str(user.id), user.role)


@pytest_asyncio.fixture(scope="module")
async def admin_token(module_session) -> str:
    return await _ensure_user(module_session, "admin_dash", "admin_dash@example.com", "administrator")


@pytest_asyncio.fixture(scope="module")
async def analyst_token(module_session) -> str:
    return await _ensure_user(module_session, "analyst_dash", "analyst_dash@example.com", "security_analyst")


@pytest_asyncio.fixture(scope="module")
async def viewer_token(module_session) -> str:
    return await _ensure_user(module_session, "viewer_dash", "viewer_dash@example.com", "viewer")


@pytest_asyncio.fixture(scope="module", autouse=True)
async def _remove_test_users_and_data(module_session):
    yield
    for table, ids in CREATED_IDS.items():
        for rid in ids:
            try:
                await module_session.delete(
                    await module_session.get(
                        {"hosts": Host, "ports": Port, "services": Service,
                         "vulnerabilities": Vulnerability, "cves": CVE,
                         "scans": Scan, "reports": Report,
                         "audit_logs": AuditLog, "users": User}[table],
                        rid,
                    )
                )
            except Exception:
                pass
    await module_session.commit()


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(scope="module")
async def seeded_data(module_session):
    """Insert deterministic dashboard data; returns a dict of identifiers."""
    ids = {"users": [], "hosts": [], "ports": [], "services": [],
           "vulnerabilities": [], "cves": [], "scans": [], "reports": [],
           "audit_logs": []}
    for key, value in ids.items():
        CREATED_IDS.setdefault(key, []).extend(value)

    host_a = Host(ip_address="10.0.0.10", hostname="seed-host-a", is_alive=True)
    host_b = Host(ip_address="10.0.0.20", hostname="seed-host-b", is_alive=True)
    module_session.add_all([host_a, host_b])
    await module_session.flush()
    ids["hosts"].extend([host_a.id, host_b.id])

    port_80_a = Port(host_id=host_a.id, port=80, protocol="tcp", state="open")
    port_80_b = Port(host_id=host_b.id, port=80, protocol="tcp", state="open")
    port_443 = Port(host_id=host_a.id, port=443, protocol="tcp", state="open")
    port_22 = Port(host_id=host_b.id, port=22, protocol="tcp", state="closed")
    module_session.add_all([port_80_a, port_80_b, port_443, port_22])
    await module_session.flush()
    ids["ports"].extend([p.id for p in (port_80_a, port_80_b, port_443, port_22)])

    svc_ssh = Service(port_id=port_22.id, name="ssh", normalized_name="ssh")
    svc_http_a = Service(port_id=port_80_a.id, name="http", normalized_name="http")
    svc_http_b = Service(port_id=port_80_b.id, name="Apache", normalized_name="http")
    module_session.add_all([svc_ssh, svc_http_a, svc_http_b])
    await module_session.flush()
    ids["services"].extend([s.id for s in (svc_ssh, svc_http_a, svc_http_b)])

    def _vuln(host, severity):
        v = Vulnerability(
            host_id=host.id, name=f"seed-vuln-{uuid.uuid4().hex[:6]}", severity=severity
        )
        module_session.add(v)
        return v

    vulns = [
        _vuln(host_a, "Critical"),
        _vuln(host_a, "Critical"),
        _vuln(host_a, "High"),
        _vuln(host_a, "Medium"),
        _vuln(host_b, "Low"),
        _vuln(host_b, None),
    ]
    await module_session.flush()
    ids["vulnerabilities"].extend([v.id for v in vulns])

    cve_expl = CVE(
        vuln_id=vulns[0].id,
        cve_id="CVE-2026-DASH1",
        exploit_available=True,
        cvss_score=9.8,
    )
    cve_expl2 = CVE(
        vuln_id=vulns[1].id,
        cve_id="CVE-2026-DASH2",
        exploit_available=True,
        cvss_score=8.1,
    )
    cve_no = CVE(vuln_id=vulns[2].id, cve_id="CVE-2026-DASH3", exploit_available=False)
    module_session.add_all([cve_expl, cve_expl2, cve_no])
    await module_session.flush()
    ids["cves"].extend([c.id for c in (cve_expl, cve_expl2, cve_no)])

    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    scan_old = Scan(
        name="DashboardSeed Older Scan", scan_type="full", target="10.0.0.0/24",
        status="completed",
        started_at=now - timedelta(minutes=5), completed_at=now - timedelta(minutes=3),
        created_at=now - timedelta(hours=2),
    )
    scan_new = Scan(
        name="DashboardSeed Newer Scan", scan_type="full", target="10.0.0.0/24",
        status="running",
        started_at=now - timedelta(seconds=90), completed_at=now - timedelta(seconds=30),
        created_at=now - timedelta(hours=1),
    )
    module_session.add_all([scan_old, scan_new])
    await module_session.flush()
    ids["scans"].extend([scan_old.id, scan_new.id])

    report_old = Report(
        scan_id=scan_old.id, title="DashboardSeed Report One",
        report_type="technical", format="pdf", filepath="/tmp/dash1.pdf", file_size=1024,
        created_at=now - timedelta(hours=2),
    )
    report_new = Report(
        scan_id=scan_new.id, title="DashboardSeed Report Two",
        report_type="executive", format="json", filepath="/tmp/dash2.json", file_size=2048,
        created_at=now - timedelta(hours=1),
    )
    module_session.add_all([report_old, report_new])
    await module_session.flush()
    ids["reports"].extend([report_old.id, report_new.id])

    audit = AuditLog(action="dashboard_seed", resource_type="test", details={"seed": True})
    module_session.add(audit)
    await module_session.flush()
    ids["audit_logs"].append(audit.id)

    await module_session.commit()

    return {
        "host_a": host_a.id, "host_b": host_b.id,
        "vulns": [v.id for v in vulns],
    }


class TestAccess:
    async def test_unauthenticated_rejected(self, client):
        resp = await client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 401

    async def test_admin_can_read(self, client, admin_token):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        assert resp.status_code == 200

    async def test_analyst_can_read(self, client, analyst_token):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(analyst_token))
        assert resp.status_code == 200

    async def test_viewer_can_read(self, client, viewer_token):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(viewer_token))
        assert resp.status_code == 200


class TestEmptyState:
    async def test_empty_database_shape(self, client, admin_token):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert [s["count"] for s in data["severity_distribution"]] == [0, 0, 0, 0, 0]
        assert len(data["vulnerability_trend"]) == 14
        assert all(p["count"] == 0 for p in data["vulnerability_trend"])
        assert data["top_open_ports"] == []
        assert data["service_distribution"] == []
        assert data["recent_assessments"] == []
        assert data["recent_reports"] == []
        assert data["top_vulnerable_hosts"] == []
        assert data["risk_score"] == {"score": 0, "level": "None", "total": 0}
        assert data["critical_count"] == 0
        assert data["exploit_available_count"] == 0
        assert data["scan_duration_stats"]["count"] == 0
        assert data["totals"]["vulnerabilities"] == 0


class TestAggregations:
    async def test_severity_distribution(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        dist = {s["severity"]: s["count"] for s in resp.json()["data"]["severity_distribution"]}
        assert dist == {"Critical": 2, "High": 1, "Medium": 1, "Low": 1, "Info": 1}
        assert resp.json()["data"]["critical_count"] == 2

    async def test_vulnerability_trend_sums_to_total(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        data = resp.json()["data"]
        trend_sum = sum(p["count"] for p in data["vulnerability_trend"])
        assert trend_sum == data["totals"]["vulnerabilities"] == 6
        assert data["vulnerability_trend"][0]["date"] <= data["vulnerability_trend"][-1]["date"]

    async def test_top_open_ports(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        ports = {p["port"]: p for p in resp.json()["data"]["top_open_ports"]}
        assert ports[80]["count"] == 2
        assert ports[80]["label"] == "http"
        assert ports[443]["count"] == 1
        assert 22 not in ports

    async def test_service_distribution(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        services = {s["name"]: s["count"] for s in resp.json()["data"]["service_distribution"]}
        assert services.get("http") == 2
        assert services.get("ssh") == 1

    async def test_top_vulnerable_hosts(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        hosts = resp.json()["data"]["top_vulnerable_hosts"]
        assert hosts[0]["ip_address"] == "10.0.0.10"
        assert hosts[0]["count"] == 4
        assert hosts[1]["ip_address"] == "10.0.0.20"
        assert hosts[1]["count"] == 2

    async def test_risk_score(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        risk = resp.json()["data"]["risk_score"]
        assert risk["total"] == 6
        assert risk["score"] == 53
        assert risk["level"] == "High"

    async def test_exploit_available_count(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        assert resp.json()["data"]["exploit_available_count"] == 2

    async def test_scan_duration_stats(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        stats = resp.json()["data"]["scan_duration_stats"]
        assert stats["count"] == 2
        assert stats["average_seconds"] == 90.0
        assert stats["min_seconds"] == 60.0
        assert stats["max_seconds"] == 120.0

    async def test_recent_assessments_newest_first(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        items = resp.json()["data"]["recent_assessments"]
        assert items[0]["name"] == "DashboardSeed Newer Scan"
        assert items[0]["status"] == "running"
        assert items[1]["name"] == "DashboardSeed Older Scan"

    async def test_recent_reports(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        items = resp.json()["data"]["recent_reports"]
        assert items[0]["title"] == "DashboardSeed Report Two"
        assert items[0]["format"] == "json"
        assert items[1]["file_size"] == 1024

    async def test_activity_timeline(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        items = resp.json()["data"]["activity_timeline"]
        assert any(item["action"] == "dashboard_seed" for item in items)
        timestamps = [item["timestamp"] for item in items if item["timestamp"]]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_totals(self, client, admin_token, seeded_data):
        resp = await client.get("/api/v1/dashboard/summary", headers=_auth_headers(admin_token))
        totals = resp.json()["data"]["totals"]
        assert totals["vulnerabilities"] == 6
        assert totals["hosts"] == 2
        assert totals["open_ports"] == 3
        assert totals["services"] == 3
        assert totals["reports"] == 2
        assert totals["assessments"] == 2
