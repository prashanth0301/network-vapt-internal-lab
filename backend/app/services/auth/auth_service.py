from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import JWTError, jwt
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.audit_log import AuditLog
from app.models.user import User


class AuthService:
    def hash_password(self, password: str) -> str:
        return bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def verify_password(self, password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"), password_hash.encode("utf-8")
        )

    def create_access_token(
        self, user_id: str, role: str, remember_me: bool = False
    ) -> str:
        expiry = settings.JWT_REFRESH_EXPIRATION_DAYS if remember_me else settings.JWT_EXPIRATION_MINUTES
        expire = datetime.now(timezone.utc) + (
            timedelta(days=expiry) if remember_me else timedelta(minutes=expiry)
        )
        payload = {
            "sub": user_id,
            "role": role,
            "exp": expire,
            "type": "access",
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    def create_refresh_token(self, user_id: str) -> str:
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_EXPIRATION_DAYS
        )
        payload = {
            "sub": user_id,
            "exp": expire,
            "type": "refresh",
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    def decode_token(self, token: str) -> Optional[dict]:
        try:
            return jwt.decode(
                token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
            )
        except JWTError:
            return None

    async def authenticate(
        self, session: AsyncSession, username: str, password: str
    ) -> Optional[User]:
        result = await session.execute(
            select(User).where(
                (User.username == username) | (User.email == username)
            )
        )
        user = result.scalar_one_or_none()
        if not user or not self.verify_password(password, user.password_hash):
            return None
        if user.status != "active":
            return None
        return user

    async def create_user(
        self,
        session: AsyncSession,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        role: str = "viewer",
    ) -> User:
        user = User(
            username=username,
            email=email,
            password_hash=self.hash_password(password),
            full_name=full_name,
            role=role,
        )
        session.add(user)
        await session.flush()
        return user

    async def log_audit(
        self,
        session: AsyncSession,
        user_id: Optional[str],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> AuditLog:
        uid = None
        if user_id:
            try:
                import uuid
                uid = uuid.UUID(user_id)
            except ValueError:
                uid = None
        log = AuditLog(
            user_id=uid,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add(log)
        await session.flush()
        return log
