"""Tests for the Settings module.

Covers role-based access (read for all, write for administrators), default
values, typed validation, reset, logo upload/removal and system info.
"""

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

from app.core.config import settings as app_settings
from app.models.user import User
from app.services.auth import auth_service
from app.services.settings_service import LOGO_DIR, SETTING_DEFS, detect_nmap_path
from tests.conftest import test_engine

REGISTERED_KEY_COUNT = len(SETTING_DEFS)
SCANNER_KEY_COUNT = sum(1 for d in SETTING_DEFS if d["category"] == "scanner")


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
            password="settingspass123",
            full_name=f"Settings {role}",
            role=role,
        )
        await module_session.commit()
    return auth_service.create_access_token(str(user.id), user.role)


@pytest_asyncio.fixture(scope="module")
async def admin_token(module_session) -> str:
    return await _ensure_user(module_session, "admin_set", "admin_set@example.com", "administrator")


@pytest_asyncio.fixture(scope="module")
async def analyst_token(module_session) -> str:
    return await _ensure_user(module_session, "analyst_set", "analyst_set@example.com", "security_analyst")


@pytest_asyncio.fixture(scope="module")
async def viewer_token(module_session) -> str:
    return await _ensure_user(module_session, "viewer_set", "viewer_set@example.com", "viewer")


@pytest_asyncio.fixture(scope="module", autouse=True)
async def _remove_test_users(module_session):
    """Remove users created by this module.

    The user-management test module relies on there being a single active
    administrator in the shared test database; leaving admin_set behind
    would bypass its last-administrator protection tests.
    """
    yield
    for username in ("admin_set", "analyst_set", "viewer_set"):
        result = await module_session.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        if user:
            await module_session.delete(user)
    await module_session.commit()


def _auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest_asyncio.fixture(autouse=True)
async def _clean_state(client, admin_token):
    LOGO_DIR.mkdir(parents=True, exist_ok=True)
    for f in LOGO_DIR.iterdir():
        f.unlink(missing_ok=True)
    await client.post("/api/v1/settings/reset", headers=_auth_headers(admin_token))
    yield


async def _update(client, token, values):
    return await client.put(
        "/api/v1/settings", headers=_auth_headers(token), json={"values": values}
    )


class TestAccessControl:
    async def test_unauthenticated_read_rejected(self, client):
        resp = await client.get("/api/v1/settings")
        assert resp.status_code == 401

    async def test_viewer_can_read_settings(self, client, viewer_token):
        resp = await client.get("/api/v1/settings", headers=_auth_headers(viewer_token))
        assert resp.status_code == 200

    async def test_analyst_can_read_settings(self, client, analyst_token):
        resp = await client.get("/api/v1/settings", headers=_auth_headers(analyst_token))
        assert resp.status_code == 200

    async def test_viewer_cannot_update_settings(self, client, viewer_token):
        resp = await _update(client, viewer_token, {"general.theme": "dark"})
        assert resp.status_code == 403

    async def test_analyst_cannot_update_settings(self, client, analyst_token):
        resp = await _update(client, analyst_token, {"general.theme": "dark"})
        assert resp.status_code == 403

    async def test_viewer_cannot_reset_settings(self, client, viewer_token):
        resp = await client.post("/api/v1/settings/reset", headers=_auth_headers(viewer_token))
        assert resp.status_code == 403

    async def test_viewer_cannot_upload_logo(self, client, viewer_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(viewer_token),
            files={"file": ("logo.png", b"fake-png", "image/png")},
        )
        assert resp.status_code == 403

    async def test_viewer_cannot_remove_logo(self, client, viewer_token):
        resp = await client.delete("/api/v1/settings/logo", headers=_auth_headers(viewer_token))
        assert resp.status_code == 403

    async def test_viewer_can_read_system_info(self, client, viewer_token):
        resp = await client.get("/api/v1/settings/system", headers=_auth_headers(viewer_token))
        assert resp.status_code == 200


class TestList:
    async def test_defaults_returned_when_empty(self, client, admin_token):
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        items = resp.json()["data"]
        assert len(items) == REGISTERED_KEY_COUNT
        by_key = {i["key"]: i for i in items}
        assert by_key["general.organization_name"]["value"] == "Network VAPT Lab"
        assert by_key["general.organization_name"]["type"] == "string"
        assert by_key["scanner.enable_udp_scan"]["value"] == "false"
        assert by_key["scanner.enable_udp_scan"]["type"] == "boolean"
        assert by_key["security.session_timeout_minutes"]["value"] == "30"
        assert by_key["security.session_timeout_minutes"]["min"] == 5
        assert by_key["security.session_timeout_minutes"]["max"] == 1440
        assert by_key["general.theme"]["options"] == ["light", "dark", "system"]
        assert by_key["reporting.pdf_theme"]["options"] == ["modern", "classic", "minimal"]
        assert by_key["scanner.default_scan_speed"]["options"] is not None

    async def test_nmap_path_auto_detected_readonly(self, client, admin_token):
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["scanner.nmap_path"]["value"] == detect_nmap_path()
        assert items["scanner.nmap_path"]["readonly"] is True

    async def test_category_filter(self, client, admin_token):
        resp = await client.get(
            "/api/v1/settings?category=scanner", headers=_auth_headers(admin_token)
        )
        items = resp.json()["data"]
        assert len(items) == SCANNER_KEY_COUNT
        assert all(i["category"] == "scanner" for i in items)

    async def test_unknown_category_returns_empty(self, client, admin_token):
        resp = await client.get(
            "/api/v1/settings?category=nope", headers=_auth_headers(admin_token)
        )
        assert resp.status_code == 200
        assert resp.json()["data"] == []

    async def test_custom_path_unlocks_nmap_editing(self, client, admin_token):
        resp = await _update(client, admin_token, {"scanner.nmap_path": "/custom/nmap"})
        assert resp.status_code == 200
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["scanner.nmap_path"]["value"] == "/custom/nmap"
        assert items["scanner.nmap_path"]["readonly"] is False


class TestUpdate:
    async def test_save_and_persist_string(self, client, admin_token):
        resp = await _update(
            client, admin_token, {"general.organization_name": "Acme Security Inc"}
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["updated"] == 1
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["general.organization_name"]["value"] == "Acme Security Inc"

    async def test_save_booleans(self, client, admin_token):
        resp = await _update(
            client, admin_token, {"scanner.enable_udp_scan": "true"}
        )
        assert resp.status_code == 200
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["scanner.enable_udp_scan"]["value"] == "true"

    async def test_save_integers(self, client, admin_token):
        resp = await _update(
            client,
            admin_token,
            {"security.session_timeout_minutes": "45", "security.max_login_attempts": "10"},
        )
        assert resp.status_code == 200
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["security.session_timeout_minutes"]["value"] == "45"
        assert items["security.max_login_attempts"]["value"] == "10"

    async def test_empty_values_ok(self, client, admin_token):
        resp = await _update(client, admin_token, {})
        assert resp.status_code == 200
        assert resp.json()["data"]["updated"] == 0

    async def test_unknown_key_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"bogus.key": "x"})
        assert resp.status_code == 400
        errors = resp.json()["detail"]["errors"]
        assert errors["bogus.key"] == "unknown setting key"

    async def test_invalid_boolean_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"scanner.enable_udp_scan": "yes"})
        assert resp.status_code == 400
        assert resp.json()["detail"]["errors"]["scanner.enable_udp_scan"] == "must be 'true' or 'false'"

    async def test_invalid_integer_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"security.session_timeout_minutes": "abc"})
        assert resp.status_code == 400
        assert "whole number" in resp.json()["detail"]["errors"]["security.session_timeout_minutes"]

    async def test_integer_out_of_range_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"security.session_timeout_minutes": "1"})
        assert resp.status_code == 400
        assert "at least 5" in resp.json()["detail"]["errors"]["security.session_timeout_minutes"]

    async def test_invalid_enum_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"general.theme": "blue"})
        assert resp.status_code == 400
        assert "one of: light, dark, system" in resp.json()["detail"]["errors"]["general.theme"]

    async def test_invalid_port_range_rejected(self, client, admin_token):
        for bad in ("1-99999", "99999-1", "abc", "80,,443"):
            resp = await _update(client, admin_token, {"scanner.default_port_range": bad})
            assert resp.status_code == 400, bad
            assert "scanner.default_port_range" in resp.json()["detail"]["errors"]

    async def test_valid_port_range_accepted(self, client, admin_token):
        resp = await _update(
            client, admin_token, {"scanner.default_port_range": "1-1024, 80,443,3000-3010"}
        )
        assert resp.status_code == 200

    async def test_invalid_timezone_rejected(self, client, admin_token):
        resp = await _update(client, admin_token, {"general.timezone": "Mars/Olympus"})
        assert resp.status_code == 400
        assert "timezone" in resp.json()["detail"]["errors"]["general.timezone"]

    async def test_multiple_invalid_keys_reported(self, client, admin_token):
        resp = await _update(
            client,
            admin_token,
            {
                "general.theme": "blue",
                "security.max_login_attempts": "999",
                "good.key": "x",
            },
        )
        assert resp.status_code == 400
        errors = resp.json()["detail"]["errors"]
        assert set(errors.keys()) == {"general.theme", "security.max_login_attempts", "good.key"}

    async def test_string_length_limited(self, client, admin_token):
        resp = await _update(
            client, admin_token, {"general.organization_name": "X" * 200}
        )
        assert resp.status_code == 400
        assert "at most 100" in resp.json()["detail"]["errors"]["general.organization_name"]

    async def test_partial_save_rejected_atomically(self, client, admin_token):
        resp = await _update(
            client,
            admin_token,
            {"general.organization_name": "Valid Name", "general.theme": "purple"},
        )
        assert resp.status_code == 400
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["general.organization_name"]["value"] != "Valid Name"

    async def test_audit_logged(self, client, admin_token):
        await _update(client, admin_token, {"general.theme": "dark"})
        resp = await client.get("/api/v1/audit-logs", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        actions = [log["action"] for log in resp.json()["data"]]
        assert "settings_updated" in actions


class TestReset:
    async def test_reset_restores_defaults(self, client, admin_token):
        await _update(
            client,
            admin_token,
            {
                "general.organization_name": "Custom Name",
                "scanner.enable_udp_scan": "true",
                "security.session_timeout_minutes": "120",
            },
        )
        resp = await client.post("/api/v1/settings/reset", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["general.organization_name"]["value"] == "Network VAPT Lab"
        assert items["scanner.enable_udp_scan"]["value"] == "false"
        assert items["security.session_timeout_minutes"]["value"] == "30"


class TestSystem:
    async def test_system_info_shape(self, client, admin_token):
        resp = await client.get("/api/v1/settings/system", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert isinstance(data["docker"]["in_container"], bool)
        assert data["docker"]["mode"] in ("docker", "bare-metal")
        assert isinstance(data["database"]["connected"], bool)
        assert data["database"]["latency_ms"] is None or isinstance(data["database"]["latency_ms"], float)
        assert data["backend"]["version"] == app_settings.APP_VERSION
        assert data["frontend"]["version"] == "1.0.0"
        assert data["nmap"]["path"]
        assert data["disk"]["total_gb"] > 0
        assert data["health"]["status"] in ("healthy", "degraded")
        assert data["health"]["components"]["database"] in ("ok", "error")

    async def test_system_info_requires_auth(self, client):
        resp = await client.get("/api/v1/settings/system")
        assert resp.status_code == 401


class TestLogo:
    async def test_upload_logo(self, client, admin_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("logo.png", b"\x89PNG\r\n\x1a\nfakepng", "image/png")},
        )
        assert resp.status_code == 200
        filename = resp.json()["data"]["filename"]
        assert (LOGO_DIR / filename).is_file()

        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["general.company_logo"]["value"] == filename
        assert items["reporting.company_logo"]["value"] == filename

        resp = await client.get("/api/v1/settings/logo", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("image/png")

    async def test_viewer_can_download_logo(self, client, admin_token, viewer_token):
        await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("logo.png", b"fakepng", "image/png")},
        )
        resp = await client.get("/api/v1/settings/logo", headers=_auth_headers(viewer_token))
        assert resp.status_code == 200

    async def test_invalid_type_rejected(self, client, admin_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("evil.exe", b"MZ....", "application/x-msdownload")},
        )
        assert resp.status_code == 400
        assert "Unsupported file type" in resp.json()["detail"]

    async def test_oversize_logo_rejected(self, client, admin_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("big.png", b"x" * (2 * 1024 * 1024 + 1), "image/png")},
        )
        assert resp.status_code == 400
        assert "2 MB limit" in resp.json()["detail"]

    async def test_remove_logo(self, client, admin_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("logo.png", b"fakepng", "image/png")},
        )
        filename = resp.json()["data"]["filename"]

        resp = await client.delete("/api/v1/settings/logo", headers=_auth_headers(admin_token))
        assert resp.status_code == 200
        assert not (LOGO_DIR / filename).exists()

        resp = await client.get("/api/v1/settings", headers=_auth_headers(admin_token))
        items = {i["key"]: i for i in resp.json()["data"]}
        assert items["general.company_logo"]["value"] == ""
        assert items["reporting.company_logo"]["value"] == ""

        resp = await client.get("/api/v1/settings/logo", headers=_auth_headers(admin_token))
        assert resp.status_code == 404

    async def test_upload_replaces_previous_file(self, client, admin_token):
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("a.png", b"aaa", "image/png")},
        )
        first = resp.json()["data"]["filename"]
        resp = await client.post(
            "/api/v1/settings/logo",
            headers=_auth_headers(admin_token),
            files={"file": ("b.png", b"bbb", "image/png")},
        )
        second = resp.json()["data"]["filename"]
        assert first != second
        assert not (LOGO_DIR / first).exists()
        assert (LOGO_DIR / second).is_file()
