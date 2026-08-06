import asyncio
import sys
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.dependencies import get_db
from app.main import app
from app.models.base import Base

TEST_DATABASE_URL = "postgresql+asyncpg://vapt:vaptpassword@localhost:15432/vapt_test"

test_engine = create_async_engine(
    TEST_DATABASE_URL, echo=False, poolclass=NullPool
)

test_async_session_factory = None


@pytest.fixture(scope="session")
def event_loop_policy():
    if sys.platform == "win32":
        return asyncio.WindowsSelectorEventLoopPolicy()
    return asyncio.get_event_loop_policy()


@pytest_asyncio.fixture(scope="session")
async def setup_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest_asyncio.fixture
async def db_session(setup_database) -> AsyncGenerator[AsyncSession, None]:
    from sqlalchemy.ext.asyncio import async_sessionmaker

    session_factory = async_sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def auth_headers(db_session: AsyncSession) -> dict:
    """Bearer auth headers for an administrator user in the test database.

    The user is removed after the test so that other test modules (e.g. the
    last-administrator protection tests) see the same database state.
    """
    from sqlalchemy import delete

    from app.models.user import User
    from app.services.auth import auth_service

    result = await db_session.execute(
        select(User).where(User.username == "test_admin_user")
    )
    user = result.scalar_one_or_none()
    if not user:
        user = await auth_service.create_user(
            db_session,
            username="test_admin_user",
            email="test_admin_user@example.com",
            password="TestAdmin@123",
            full_name="Test Admin",
            role="administrator",
        )
        await db_session.commit()
    token = auth_service.create_access_token(str(user.id), user.role)
    yield {"Authorization": f"Bearer {token}"}
    await db_session.execute(delete(User).where(User.username == "test_admin_user"))
    await db_session.commit()
