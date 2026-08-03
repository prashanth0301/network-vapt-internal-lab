"""Development-only admin bootstrap.

Creates the default administrator account on startup, but ONLY when the
users table is completely empty (i.e. the platform has never been
initialised). Disable with AUTO_CREATE_ADMIN=false.
"""
from typing import Optional

from loguru import logger
from sqlalchemy import select

from app.core.config import settings
from app.core.database import async_session_factory
from app.models.user import User
from app.services.auth.auth_service import AuthService

auth_service = AuthService()


async def ensure_admin_user() -> Optional[User]:
    """Create the default admin when no users exist. Returns the created user or None."""
    async with async_session_factory() as session:
        result = await session.execute(select(User.id).limit(1))
        if result.scalar_one_or_none() is not None:
            return None
        user = await auth_service.create_user(
            session,
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            password=settings.ADMIN_PASSWORD,
            full_name="System Administrator",
            role="administrator",
        )
        await session.commit()
        return user


async def bootstrap_default_admin() -> None:
    if not settings.AUTO_CREATE_ADMIN:
        logger.info("AUTO_CREATE_ADMIN is disabled - skipping default admin bootstrap")
        return
    try:
        user = await ensure_admin_user()
    except Exception as exc:
        logger.error(
            "Default admin bootstrap failed: {error}",
            error=f"{type(exc).__name__}: {exc}",
        )
        return
    if user is None:
        logger.info("Users already exist - default admin bootstrap skipped")
        return
    logger.warning(
        "Created default development admin '{username}' with password '{password}' "
        "- change it or disable AUTO_CREATE_ADMIN for production",
        username=user.username,
        password=settings.ADMIN_PASSWORD,
    )
