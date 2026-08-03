"""Tests for the User Management module.

Covers CRUD, search, pagination, duplicate validation, last-administrator
protection, self-delete protection, status/role/password endpoints, audit
logging and role-based access.
"""

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.models.user import User
from app.services.auth import auth_service
from tests.conftest import test_engine


@pytest_asyncio.fixture(scope="module")
async def module_session(setup_database) -> AsyncSession:
    factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with factory() as session:
        yield session


@pytest_asyncio.fixture(scope="module")
async def admin_token(module_session) -> str:
    existing = await module_session.execute(
        select(User).where(User.username == "admin_umgmt")
    )
    admin = existing.scalar_one_or_none()
    if not admin:
        admin = await auth_service.create_user(
            module_session,
            username="admin_umgmt",
            email="admin_umgmt@example.com",
            password="adminpass123",
            full_name="UM Admin",
            role="administrator",
        )
        await module_session.commit()
    return auth_service.create_access_token(str(admin.id), admin.role)


@pytest_asyncio.fixture(scope="module")
async def admin_user_id(module_session) -> str:
    result = await module_session.execute(
        select(User.id).where(User.username == "admin_umgmt")
    )
    return str(result.scalar_one())


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _create_user(client, token, username, email, role="viewer", password="passw0rd!"):
    resp = await client.post(
        "/api/v1/users",
        headers=_auth_headers(token),
        json={
            "username": username,
            "email": email,
            "password": password,
            "full_name": f"Name {username}",
            "role": role,
        },
    )
    return resp


async def _create_user_token(client, admin_token, username, email, role):
    resp = await _create_user(client, admin_token, username, email, role)
    assert resp.status_code == 200, resp.text
    uid = resp.json()["data"]["id"]
    return auth_service.create_access_token(uid, role), uid


class TestPermissions:
    async def test_viewer_cannot_list_users(self, client, admin_token):
        viewer_tok, _ = await _create_user_token(
            client, admin_token, "permv1", "permv1@example.com", "viewer"
        )
        resp = await client.get("/api/v1/users", headers=_auth_headers(viewer_tok))
        assert resp.status_code == 403

    async def test_analyst_cannot_create_user(self, client, admin_token):
        analyst_tok, _ = await _create_user_token(
            client, admin_token, "perma1", "perma1@example.com", "security_analyst"
        )
        resp = await _create_user(client, analyst_tok, "nope_analyst", "nope_a@example.com")
        assert resp.status_code == 403

    async def test_viewer_can_view_own_profile(self, client, admin_token):
        viewer_tok, uid = await _create_user_token(
            client, admin_token, "ownview1", "ownview1@example.com", "viewer"
        )
        resp = await client.get(f"/api/v1/users/{uid}", headers=_auth_headers(viewer_tok))
        assert resp.status_code == 200
        assert resp.json()["data"]["username"] == "ownview1"

    async def test_viewer_cannot_view_other_user(self, client, admin_token):
        viewer_tok, _ = await _create_user_token(
            client, admin_token, "ownview2", "ownview2@example.com", "viewer"
        )
        other = await _create_user(client, admin_token, "ownview3", "ownview3@example.com", "viewer")
        other_uid = other.json()["data"]["id"]
        resp = await client.get(f"/api/v1/users/{other_uid}", headers=_auth_headers(viewer_tok))
        assert resp.status_code == 403

    async def test_admin_can_list_users(self, client, admin_token):
        resp = await client.get("/api/v1/users", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        body = resp.json()["data"]
        assert body["total"] >= 1
        assert isinstance(body["items"], list)


class TestCrud:
    async def test_create_user(self, client, admin_token):
        resp = await _create_user(client, admin_token, "crt1", "crt1@example.com")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["username"] == "crt1"
        assert data["role"] == "viewer"
        assert data["status"] == "active"
        assert data["is_active"] is True

    async def test_create_duplicate_username(self, client, admin_token):
        resp = await _create_user(client, admin_token, "dupuser1", "dupuser1@example.com")
        assert resp.status_code == 200
        resp2 = await _create_user(client, admin_token, "dupuser1", "other1@example.com")
        assert resp2.status_code == 409

    async def test_create_duplicate_email(self, client, admin_token):
        resp = await _create_user(client, admin_token, "dupemail1", "dupemail1@example.com")
        assert resp.status_code == 200
        resp2 = await _create_user(client, admin_token, "other2", "dupemail1@example.com")
        assert resp2.status_code == 409

    async def test_get_user(self, client, admin_token):
        created = await _create_user(client, admin_token, "getuser1", "getuser1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.get(f"/api/v1/users/{uid}", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        assert resp.json()["data"]["id"] == uid

    async def test_update_profile(self, client, admin_token):
        created = await _create_user(client, admin_token, "upduser1", "upduser1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}",
            headers=_auth_headers(admin_token),
            json={"email": "upduser1_new@example.com", "full_name": "Updated Name"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["email"] == "upduser1_new@example.com"
        assert data["full_name"] == "Updated Name"

    async def test_update_profile_duplicate_email(self, client, admin_token):
        await _create_user(client, admin_token, "upddup1", "upddup1@example.com")
        created = await _create_user(client, admin_token, "upddup2", "upddup2@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}",
            headers=_auth_headers(admin_token),
            json={"email": "upddup1@example.com"},
        )
        assert resp.status_code == 409

    async def test_delete_user(self, client, admin_token):
        created = await _create_user(client, admin_token, "deluser1", "deluser1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.delete(f"/api/v1/users/{uid}", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        get_resp = await client.get(f"/api/v1/users/{uid}", headers=_auth_headers(admin_token))
        assert get_resp.status_code == 404

    async def test_delete_self_blocked(self, client, admin_token, admin_user_id):
        resp = await client.delete(
            f"/api/v1/users/{admin_user_id}", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 400
        assert "own account" in resp.json()["detail"]


class TestLastAdminProtection:
    async def test_delete_last_admin_blocked_service(
        self, client, admin_token, admin_user_id, db_session
    ):
        """The last-active-admin guard is enforced at service level; through
        the API the self-delete check fires first when the only admin is
        targeted."""
        from app.services.user_management_service import (
            UserValidationError,
            delete_user,
        )

        admin = (
            await db_session.execute(
                select(User).where(User.id == uuid.UUID(admin_user_id))
            )
        ).scalar_one()
        with pytest.raises(UserValidationError):
            await delete_user(db_session, admin)

    async def test_delete_admin_allowed_when_other_admin_exists(self, client, admin_token):
        second = await _create_user(client, admin_token, "admin2_t", "admin2_t@example.com", "administrator")
        uid = second.json()["data"]["id"]
        resp = await client.delete(f"/api/v1/users/{uid}", headers=_auth_headers(admin_token))
        assert resp.status_code == 200

    async def test_deactivate_last_admin_blocked(self, client, admin_token, admin_user_id):
        resp = await client.put(
            f"/api/v1/users/{admin_user_id}/status",
            headers=_auth_headers(admin_token),
            json={"status": "inactive"},
        )
        assert resp.status_code == 400
        assert "last active administrator" in resp.json()["detail"]

    async def test_demote_last_admin_blocked(self, client, admin_token, admin_user_id):
        resp = await client.put(
            f"/api/v1/users/{admin_user_id}/role",
            headers=_auth_headers(admin_token),
            json={"role": "viewer"},
        )
        assert resp.status_code == 400
        assert "last active administrator" in resp.json()["detail"]


class TestStatusAndRole:
    async def test_status_change_syncs_is_active(self, client, admin_token):
        created = await _create_user(client, admin_token, "status1", "status1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/status",
            headers=_auth_headers(admin_token),
            json={"status": "inactive"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "inactive"
        assert data["is_active"] is False
        resp2 = await client.put(
            f"/api/v1/users/{uid}/status",
            headers=_auth_headers(admin_token),
            json={"status": "active"},
        )
        assert resp2.status_code == 200
        assert resp2.json()["data"]["is_active"] is True

    async def test_status_invalid_value(self, client, admin_token):
        created = await _create_user(client, admin_token, "status2", "status2@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/status",
            headers=_auth_headers(admin_token),
            json={"status": "banana"},
        )
        assert resp.status_code == 400

    async def test_role_change(self, client, admin_token):
        created = await _create_user(client, admin_token, "role1", "role1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/role",
            headers=_auth_headers(admin_token),
            json={"role": "security_analyst"},
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["role"] == "security_analyst"

    async def test_role_invalid_value(self, client, admin_token):
        created = await _create_user(client, admin_token, "role2", "role2@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/role",
            headers=_auth_headers(admin_token),
            json={"role": "superuser"},
        )
        assert resp.status_code == 400


class TestPassword:
    async def test_reset_password(self, client, admin_token, db_session):
        created = await _create_user(client, admin_token, "pw1", "pw1@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/password",
            headers=_auth_headers(admin_token),
            json={"password": "newpass123"},
        )
        assert resp.status_code == 200
        result = await db_session.execute(
            select(User).where(User.username == "pw1")
        )
        user = result.scalar_one()
        assert auth_service.verify_password("newpass123", user.password_hash) is True
        assert auth_service.verify_password("passw0rd!", user.password_hash) is False

    async def test_reset_password_too_short(self, client, admin_token):
        created = await _create_user(client, admin_token, "pw2", "pw2@example.com")
        uid = created.json()["data"]["id"]
        resp = await client.put(
            f"/api/v1/users/{uid}/password",
            headers=_auth_headers(admin_token),
            json={"password": "short"},
        )
        assert resp.status_code == 422


class TestSearchPagination:
    async def test_search_by_username(self, client, admin_token):
        await _create_user(client, admin_token, "sneaky_alpha", "alpha@example.com")
        await _create_user(client, admin_token, "beta_user", "beta@example.com")
        resp = await client.get(
            "/api/v1/users?search=alpha", headers=_auth_headers(admin_token)
        )
        body = resp.json()["data"]
        usernames = [u["username"] for u in body["items"]]
        assert "sneaky_alpha" in usernames
        assert "beta_user" not in usernames

    async def test_search_by_email(self, client, admin_token):
        await _create_user(client, admin_token, "gammauser", "gamma@example.com")
        resp = await client.get(
            "/api/v1/users?search=gamma@example", headers=_auth_headers(admin_token)
        )
        usernames = [u["username"] for u in resp.json()["data"]["items"]]
        assert "gammauser" in usernames

    async def test_filter_by_role_and_status(self, client, admin_token):
        await _create_user(client, admin_token, "filtr1", "filtr1@example.com")
        await _create_user(client, admin_token, "filtr2", "filtr2@example.com", "security_analyst")
        resp = await client.get(
            "/api/v1/users?role=security_analyst", headers=_auth_headers(admin_token)
        )
        items = resp.json()["data"]["items"]
        assert all(u["role"] == "security_analyst" for u in items)
        assert any(u["username"] == "filtr2" for u in items)

    async def test_pagination(self, client, admin_token):
        for i in range(12):
            await _create_user(client, admin_token, f"pager{i}", f"pager{i}@example.com")
        resp1 = await client.get(
            "/api/v1/users?per_page=10&page=1", headers=_auth_headers(admin_token)
        )
        body1 = resp1.json()["data"]
        assert len(body1["items"]) == 10
        assert body1["per_page"] == 10
        assert body1["page"] == 1
        assert body1["total_pages"] >= 2
        resp2 = await client.get(
            "/api/v1/users?per_page=10&page=2", headers=_auth_headers(admin_token)
        )
        body2 = resp2.json()["data"]
        assert len(body2["items"]) >= 2


class TestAudit:
    async def test_actions_recorded_in_audit_logs(self, client, admin_token):
        created = await _create_user(client, admin_token, "audit1", "audit1@example.com")
        uid = created.json()["data"]["id"]
        await client.put(
            f"/api/v1/users/{uid}/status",
            headers=_auth_headers(admin_token),
            json={"status": "inactive"},
        )
        await client.put(
            f"/api/v1/users/{uid}/role",
            headers=_auth_headers(admin_token),
            json={"role": "security_analyst"},
        )
        await client.put(
            f"/api/v1/users/{uid}/password",
            headers=_auth_headers(admin_token),
            json={"password": "anotherpass123"},
        )
        await client.delete(f"/api/v1/users/{uid}", headers=_auth_headers(admin_token))
        resp = await client.get("/api/v1/audit-logs", headers=_auth_headers(admin_token))
        actions = [log["action"] for log in resp.json()["data"]]
        assert "user_created" in actions
        assert "user_status_changed" in actions
        assert "user_role_changed" in actions
        assert "user_password_reset" in actions
        assert "user_deleted" in actions
