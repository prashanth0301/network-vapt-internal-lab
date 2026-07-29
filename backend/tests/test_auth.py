import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.auth.auth_service import AuthService
from app.services.auth.dependencies import (
    PERMISSIONS,
    get_current_user,
    has_permission,
    require_permissions,
    require_role,
)
from app.services.auth import auth_service


def _make_user(**kwargs) -> User:
    u = MagicMock(spec=User)
    u.id = uuid.uuid4()
    u.username = "testuser"
    u.email = "test@example.com"
    u.password_hash = auth_service.hash_password("password123")
    u.full_name = "Test User"
    u.role = "viewer"
    u.status = "active"
    u.last_login = None
    u.is_active = True
    u.created_at = datetime.now(timezone.utc)
    u.updated_at = datetime.now(timezone.utc)
    for k, val in kwargs.items():
        setattr(u, k, val)
    return u


class TestAuthService:
    def setup_method(self):
        self.service = AuthService()

    def test_hash_password(self):
        h = self.service.hash_password("test123")
        assert h != "test123"
        assert isinstance(h, str)
        assert len(h) > 20

    def test_verify_password_correct(self):
        h = self.service.hash_password("test123")
        assert self.service.verify_password("test123", h) is True

    def test_verify_password_incorrect(self):
        h = self.service.hash_password("test123")
        assert self.service.verify_password("wrong", h) is False

    def test_create_access_token(self):
        token = self.service.create_access_token("user-1", "administrator")
        assert isinstance(token, str)
        assert len(token) > 20

    def test_create_access_token_remember_me(self):
        token = self.service.create_access_token("user-1", "viewer", remember_me=True)
        assert isinstance(token, str)

    def test_create_refresh_token(self):
        token = self.service.create_refresh_token("user-1")
        assert isinstance(token, str)

    def test_decode_token_valid(self):
        token = self.service.create_access_token("user-1", "administrator")
        payload = self.service.decode_token(token)
        assert payload is not None
        assert payload["sub"] == "user-1"
        assert payload["role"] == "administrator"
        assert payload["type"] == "access"

    def test_decode_token_invalid(self):
        payload = self.service.decode_token("invalid.token.here")
        assert payload is None

    def test_decode_refresh_token(self):
        token = self.service.create_refresh_token("user-1")
        payload = self.service.decode_token(token)
        assert payload is not None
        assert payload["type"] == "refresh"

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        user = _make_user()
        user.password_hash = self.service.hash_password("correctpass")
        mock_result.scalar_one_or_none.return_value = user
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await self.service.authenticate(mock_session, "testuser", "correctpass")
        assert result is not None

    @pytest.mark.asyncio
    async def test_authenticate_wrong_password(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        user = _make_user()
        user.password_hash = self.service.hash_password("correctpass")
        mock_result.scalar_one_or_none.return_value = user
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await self.service.authenticate(mock_session, "testuser", "wrongpass")
        assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_inactive(self):
        mock_session = AsyncMock()
        mock_result = MagicMock()
        user = _make_user(status="inactive")
        user.password_hash = self.service.hash_password("correctpass")
        mock_result.scalar_one_or_none.return_value = user
        mock_session.execute = AsyncMock(return_value=mock_result)

        result = await self.service.authenticate(mock_session, "testuser", "correctpass")
        assert result is None

    @pytest.mark.asyncio
    async def test_create_user(self):
        mock_session = AsyncMock()
        user = await self.service.create_user(
            mock_session,
            username="newuser",
            email="new@example.com",
            password="testpass",
            full_name="New User",
            role="security_analyst",
        )
        assert user.username == "newuser"
        assert user.email == "new@example.com"
        assert user.role == "security_analyst"
        assert self.service.verify_password("testpass", user.password_hash)

    @pytest.mark.asyncio
    async def test_log_audit(self):
        mock_session = AsyncMock()
        log = await self.service.log_audit(
            mock_session,
            user_id=str(uuid.uuid4()),
            action="test_action",
            resource_type="test",
            resource_id="123",
            details={"key": "value"},
            ip_address="127.0.0.1",
        )
        assert log.action == "test_action"
        assert log.resource_type == "test"


class TestRBAC:
    def test_permissions_administrator(self):
        perms = PERMISSIONS["administrator"]
        assert "manage:users" in perms
        assert "create:assessment" in perms
        assert "delete:assessment" in perms
        assert "view:reports" in perms

    def test_permissions_security_analyst(self):
        perms = PERMISSIONS["security_analyst"]
        assert "create:assessment" in perms
        assert "run:scans" in perms
        assert "manage:users" not in perms

    def test_permissions_viewer(self):
        perms = PERMISSIONS["viewer"]
        assert "view:reports" in perms
        assert "create:assessment" not in perms

    def test_has_permission_true(self):
        assert has_permission("administrator", "manage:users") is True

    def test_has_permission_false(self):
        assert has_permission("viewer", "manage:users") is False

    def test_has_permission_unknown_role(self):
        assert has_permission("unknown", "view:reports") is False


class TestUserModel:
    def test_create_user(self):
        u = _make_user()
        assert u.username == "testuser"
        assert u.role == "viewer"
        assert u.status == "active"
        assert u.is_active is True

    def test_user_administrator(self):
        u = _make_user(role="administrator")
        assert u.role == "administrator"

    def test_user_inactive(self):
        u = _make_user(status="inactive")
        assert u.status == "inactive"
        assert u.is_active is True

    def test_user_last_login(self):
        now = datetime.now(timezone.utc)
        u = _make_user(last_login=now)
        assert u.last_login == now


class TestAuditLog:
    def test_create_audit_log(self):
        log = AuditLog(
            user_id=uuid.uuid4(),
            action="login",
            resource_type="auth",
            details={"ip": "127.0.0.1"},
        )
        assert log.action == "login"
        assert log.resource_type == "auth"


class TestAuthDependencies:
    @pytest.mark.asyncio
    async def test_require_permissions_admin(self):
        user = _make_user(role="administrator")
        dep = require_permissions(["manage:users"])
        result = await dep(current_user=user)
        assert result is not None

    @pytest.mark.asyncio
    async def test_require_permissions_viewer_denied(self):
        user = _make_user(role="viewer")
        dep = require_permissions(["manage:users"])
        with pytest.raises(Exception):
            await dep(current_user=user)

    @pytest.mark.asyncio
    async def test_require_role_admin(self):
        user = _make_user(role="administrator")
        dep = require_role("administrator")
        result = await dep(current_user=user)
        assert result is not None

    @pytest.mark.asyncio
    async def test_require_role_viewer_as_admin(self):
        user = _make_user(role="administrator")
        dep = require_role("security_analyst")
        result = await dep(current_user=user)
        assert result is not None

    @pytest.mark.asyncio
    async def test_require_role_denied(self):
        user = _make_user(role="viewer")
        dep = require_role("administrator")
        with pytest.raises(Exception):
            await dep(current_user=user)
