"""Tests for the Audit Log Viewer API.

Covers pagination, search, filters (user, action, date range, status),
sorting, CSV/JSON export and role-based access (administrator full access,
security analyst read-only, viewer no access). The audit recording
implementation itself is not modified by these tests.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.auth import auth_service
from tests.conftest import test_engine

NOW = datetime.now(timezone.utc)


@pytest_asyncio.fixture(scope="module")
async def module_session(setup_database) -> AsyncSession:
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="module")
async def admin_token(module_session, seed_audit_logs) -> str:
    return await _user_token(module_session, "audlog_admin", "administrator")


@pytest_asyncio.fixture(scope="module")
async def analyst_token(module_session, seed_audit_logs) -> str:
    return await _user_token(module_session, "audlog_analyst", "security_analyst")


@pytest_asyncio.fixture(scope="module")
async def viewer_token(module_session, seed_audit_logs) -> str:
    return await _user_token(module_session, "audlog_viewer", "viewer")


async def _user_token(session: AsyncSession, username: str, role: str) -> str:
    existing = await session.execute(select(User).where(User.username == username))
    user = existing.scalar_one_or_none()
    if not user:
        user = await auth_service.create_user(
            session,
            username=username,
            email=f"{username}@example.com",
            password="audpass123",
            full_name=username.replace("_", " ").title(),
            role=role,
        )
        await session.commit()
    return auth_service.create_access_token(str(user.id), user.role)


@pytest_asyncio.fixture(scope="module", autouse=True)
async def seed_audit_logs(module_session) -> dict:
    """Insert a deterministic set of users and audit records (committed once)."""
    result = await module_session.execute(
        select(AuditLog).where(AuditLog.action == "suite_seed_marker")
    )
    if result.scalar_one_or_none() is not None:
        return {}

    admin_id = await _ensure_user(module_session, "audlog_admin", "administrator")
    analyst_id = await _ensure_user(module_session, "audlog_analyst", "security_analyst")
    await _ensure_user(module_session, "audlog_viewer", "viewer")
    carol_id = "carol-0000-0000-0000-000000000001"

    rows = [
        # (user_id, action, resource_type, resource_id, details, ip, user_agent, age)
        (admin_id, "login", "auth", None, {"username": "audlog_admin"}, "10.0.0.1", None, timedelta(hours=48)),
        (admin_id, "user_created", "user", carol_id, {"username": "carol", "role": "viewer"}, "10.0.0.1", None, timedelta(hours=46)),
        (admin_id, "user_status_changed", "user", carol_id, {"username": "carol", "old_status": "active", "new_status": "inactive"}, "10.0.0.1", "AuditAgent/1.0", timedelta(hours=22)),
        (analyst_id, "login", "auth", None, {"username": "audlog_analyst"}, "10.0.0.2", None, timedelta(hours=30)),
        (analyst_id, "settings_updated", "settings", None, {"keys": ["general.theme"], "count": 1}, "10.0.0.2", None, timedelta(hours=6)),
        (admin_id, "user_role_changed", "user", carol_id, {"username": "carol", "status": "failure", "reason": "last admin"}, "10.0.0.3", None, timedelta(hours=3)),
        (analyst_id, "logout", "auth", None, {"username": "audlog_analyst"}, "10.0.0.2", "AuditAgent/1.0", timedelta(hours=1)),
    ]
    for user_id, action, rtype, rid, details, ip, ua, age in rows:
        log = await auth_service.log_audit(
            module_session,
            user_id=user_id,
            action=action,
            resource_type=rtype,
            resource_id=rid,
            details=details,
            ip_address=ip,
            user_agent=ua,
        )
        log.timestamp = NOW - age
    marker = await auth_service.log_audit(
        module_session,
        user_id=None,
        action="suite_seed_marker",
        resource_type="test",
        details={},
        ip_address="10.255.255.254",
    )
    marker.timestamp = NOW - timedelta(hours=24, minutes=5)
    await module_session.commit()
    return {}


@pytest_asyncio.fixture(scope="module", autouse=True)
async def cleanup_users(module_session):
    """Remove the seeded users after the module so other test modules (e.g.
    last-administrator protection in test_user_management) see a clean DB."""
    yield
    from sqlalchemy import delete

    await module_session.execute(
        delete(User).where(
            User.username.in_(["audlog_admin", "audlog_analyst", "audlog_viewer"])
        )
    )
    await module_session.commit()


async def _ensure_user(session: AsyncSession, username: str, role: str) -> str:
    existing = await session.execute(select(User).where(User.username == username))
    user = existing.scalar_one_or_none()
    if not user:
        user = await auth_service.create_user(
            session,
            username=username,
            email=f"{username}@example.com",
            password="audpass123",
            full_name=username.replace("_", " ").title(),
            role=role,
        )
        await session.commit()
    return str(user.id)


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


class TestList:
    async def test_returns_paginated_data_list(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_admin&per_page=2&page=1",
            headers=_auth_headers(admin_token),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body["data"], list)
        assert len(body["data"]) == 2
        assert body["pagination"]["per_page"] == 2
        assert body["pagination"]["total"] == 4
        assert body["pagination"]["total_pages"] == 2

    async def test_pagination_page_two(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_admin&per_page=3&page=2",
            headers=_auth_headers(admin_token),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["data"]) == 1
        assert body["pagination"]["page"] == 2

    async def test_items_include_username_user_agent_status(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_analyst&per_page=10",
            headers=_auth_headers(admin_token),
        )
        items = resp.json()["data"]
        assert items
        assert all(item["username"] == "audlog_analyst" for item in items)
        assert all(item["status"] == "success" for item in items)
        agents = {item["user_agent"] for item in items}
        assert "AuditAgent/1.0" in agents

    async def test_old_new_values_in_details(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?action=user_status_changed&user=audlog_admin&per_page=10",
            headers=_auth_headers(admin_token),
        )
        items = resp.json()["data"]
        assert len(items) == 1
        details = items[0]["details"]
        assert details["old_status"] == "active"
        assert details["new_status"] == "inactive"


class TestSearch:
    async def test_search_by_username(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_admin", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 4
        assert all(i["username"] == "audlog_admin" for i in body["data"])

    async def test_search_by_action(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=user_status&user=audlog_admin",
            headers=_auth_headers(admin_token),
        )
        body = resp.json()
        assert body["pagination"]["total"] == 1
        assert body["data"][0]["action"] == "user_status_changed"

    async def test_search_by_target(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=carol", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 3

    async def test_search_by_ip(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=10.0.0.2", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 3

    async def test_search_no_results(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=no_such_thing_xyz", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 0
        assert body["data"] == []


class TestFilters:
    async def test_filter_by_user(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?user=audlog_analyst", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 3
        assert all(i["username"] == "audlog_analyst" for i in body["data"])

    async def test_filter_by_action(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?action=login", headers=_auth_headers(admin_token)
        )
        body = resp.json()
        assert body["pagination"]["total"] == 2
        assert {i["username"] for i in body["data"]} == {"audlog_admin", "audlog_analyst"}

    async def test_filter_by_date_range(self, client, admin_token):
        base = await client.get(
            "/api/v1/audit-logs?search=audlog_analyst&per_page=100",
            headers=_auth_headers(admin_token),
        )
        logs = base.json()["data"]
        assert len(logs) == 3
        ts = [
            datetime.fromisoformat(i["timestamp"].replace("Z", "+00:00"))
            for i in logs
        ]
        oldest = min(ts)
        mid = (oldest + timedelta(hours=12)).date()
        expected_from = sum(1 for t in ts if t.date() >= mid)
        expected_to = sum(1 for t in ts if t.date() <= mid)
        resp = await client.get(
            f"/api/v1/audit-logs?search=audlog_analyst&date_from={mid.isoformat()}&per_page=100",
            headers=_auth_headers(admin_token),
        )
        assert resp.json()["pagination"]["total"] == expected_from
        resp = await client.get(
            f"/api/v1/audit-logs?search=audlog_analyst&date_to={mid.isoformat()}&per_page=100",
            headers=_auth_headers(admin_token),
        )
        assert resp.json()["pagination"]["total"] == expected_to
        assert expected_from >= 1
        assert expected_to >= 1

    async def test_filter_by_status_failure(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?status=failure&user=audlog_admin",
            headers=_auth_headers(admin_token),
        )
        body = resp.json()
        assert body["pagination"]["total"] == 1
        assert body["data"][0]["action"] == "user_role_changed"
        assert body["data"][0]["status"] == "failure"

    async def test_filter_by_status_success(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?status=success&search=audlog_admin&per_page=100",
            headers=_auth_headers(admin_token),
        )
        body = resp.json()
        assert body["pagination"]["total"] == 3
        assert all(i["status"] == "success" for i in body["data"])

    async def test_invalid_status_rejected(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?status=bogus", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 400

    async def test_invalid_date_range_rejected(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?date_from=2026-08-10&date_to=2026-08-01",
            headers=_auth_headers(admin_token),
        )
        assert resp.status_code == 400


class TestSort:
    async def test_sort_newest_first_default(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_analyst", headers=_auth_headers(admin_token)
        )
        items = resp.json()["data"]
        timestamps = [i["timestamp"] for i in items]
        assert timestamps == sorted(timestamps, reverse=True)

    async def test_sort_oldest_first(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog_analyst&sort_order=asc",
            headers=_auth_headers(admin_token),
        )
        items = resp.json()["data"]
        timestamps = [i["timestamp"] for i in items]
        assert timestamps == sorted(timestamps)

    async def test_sort_by_username(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?search=audlog&sort_by=username&sort_order=asc&per_page=100",
            headers=_auth_headers(admin_token),
        )
        items = resp.json()["data"]
        usernames = [i["username"] for i in items]
        assert usernames == sorted(usernames)
        assert len(items) == 7

    async def test_invalid_sort_field_rejected(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs?sort_by=bogus", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 400


class TestMeta:
    async def test_meta_returns_users_actions_statuses(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs/meta", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        usernames = set(data["users"])
        assert "audlog_admin" in usernames
        assert "audlog_analyst" in usernames
        actions = set(data["actions"])
        assert {"login", "logout", "user_created", "settings_updated"} <= actions
        assert set(data["statuses"]) == {"success", "failure"}


class TestExport:
    async def test_export_csv(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs/export?format=csv&search=audlog_analyst",
            headers=_auth_headers(admin_token),
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "attachment" in resp.headers["content-disposition"]
        content = resp.text.lstrip("\ufeff")
        rows = list(csv.reader(io.StringIO(content)))
        assert rows[0] == [
            "timestamp", "user", "action", "target_type", "target_id",
            "ip_address", "status", "user_agent", "details",
        ]
        data_rows = [r for r in rows[1:] if r]
        assert len(data_rows) == 3
        assert any(r[2] == "settings_updated" and r[5] == "10.0.0.2" for r in data_rows)
        settings_row = next(r for r in data_rows if r[2] == "settings_updated")
        details_json = json.loads(settings_row[8])
        assert details_json["count"] == 1
        assert details_json["keys"] == ["general.theme"]

    async def test_export_json(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs/export?format=json&search=audlog_admin",
            headers=_auth_headers(admin_token),
        )
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]
        items = json.loads(resp.text)
        assert isinstance(items, list)
        assert len(items) == 4
        assert all(i["username"] == "audlog_admin" for i in items)
        assert "status" in items[0]

    async def test_export_csv_filters_honored(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs/export?format=csv&action=login",
            headers=_auth_headers(admin_token),
        )
        content = resp.text.lstrip("\ufeff")
        rows = list(csv.reader(io.StringIO(content)))
        assert len([r for r in rows[1:] if r]) == 2

    async def test_export_invalid_format_rejected(self, client, admin_token):
        resp = await client.get(
            "/api/v1/audit-logs/export?format=xlsx", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 400


class TestPermissions:
    async def test_administrator_full_access(self, client, admin_token):
        resp = await client.get("/api/v1/audit-logs", headers=_auth_headers(admin_token))
        assert resp.status_code == 200

    async def test_security_analyst_read_only_access(self, client, analyst_token):
        resp = await client.get("/api/v1/audit-logs", headers=_auth_headers(analyst_token))
        assert resp.status_code == 200
        assert isinstance(resp.json()["data"], list)
        meta = await client.get(
            "/api/v1/audit-logs/meta", headers=_auth_headers(analyst_token)
        )
        assert meta.status_code == 200
        export = await client.get(
            "/api/v1/audit-logs/export?format=json", headers=_auth_headers(analyst_token)
        )
        assert export.status_code == 200

    async def test_viewer_no_access(self, client, viewer_token):
        for path in (
            "/api/v1/audit-logs",
            "/api/v1/audit-logs/meta",
            "/api/v1/audit-logs/export?format=csv",
        ):
            resp = await client.get(path, headers=_auth_headers(viewer_token))
            assert resp.status_code == 403, path

    async def test_unauthenticated_rejected(self, client):
        resp = await client.get("/api/v1/audit-logs")
        assert resp.status_code == 401
