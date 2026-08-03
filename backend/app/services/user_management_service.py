"""User management business logic.

Handles user CRUD, duplicate validation, last-administrator protection and
audit recording for the User Management module. No authentication or
permission logic is implemented here (that lives in app.services.auth).
"""

from typing import Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.services.auth import auth_service
from app.services.auth.dependencies import PERMISSIONS

VALID_ROLES = set(PERMISSIONS.keys())
VALID_STATUSES = {"active", "inactive", "disabled"}


class UserValidationError(Exception):
    """Raised when a user operation violates a business rule."""


async def list_users(
    session: AsyncSession,
    page: int = 1,
    per_page: int = 20,
    search: Optional[str] = None,
    status: Optional[str] = None,
    role: Optional[str] = None,
) -> Tuple[list[User], int]:
    """Search users by username/email/full_name with status/role filters."""
    query = select(User)

    if search:
        term = f"%{search.strip()}%"
        query = query.where(
            or_(
                User.username.ilike(term),
                User.email.ilike(term),
                User.full_name.ilike(term),
            )
        )
    if status:
        query = query.where(User.status == status)
    if role:
        query = query.where(User.role == role)

    total = (
        await session.execute(
            select(func.count()).select_from(query.subquery())
        )
    ).scalar_one()

    result = await session.execute(
        query.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    )
    return list(result.scalars().all()), total


async def find_duplicate(
    session: AsyncSession,
    username: Optional[str] = None,
    email: Optional[str] = None,
    exclude_user_id: Optional[str] = None,
) -> Optional[User]:
    """Return a user whose username/email collides with the given values,
    excluding the user being updated. Returns None when no conflict exists."""
    if not username and not email:
        return None
    conditions = []
    if username:
        conditions.append(User.username == username)
    if email:
        conditions.append(User.email == email)
    query = select(User).where(or_(*conditions))
    if exclude_user_id:
        query = query.where(User.id != exclude_user_id)
    result = await session.execute(query)
    return result.scalars().first()


async def count_active_admins(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count())
        .select_from(User)
        .where(User.role == "administrator", User.status == "active")
    )
    return result.scalar_one()


async def is_last_active_admin(session: AsyncSession, user: User) -> bool:
    if user.role != "administrator" or user.status != "active":
        return False
    return (await count_active_admins(session)) <= 1


async def create_user(
    session: AsyncSession,
    username: str,
    email: str,
    password: str,
    full_name: Optional[str] = None,
    role: str = "viewer",
) -> User:
    duplicate = await find_duplicate(session, username=username, email=email)
    if duplicate:
        raise UserValidationError("Username or email already exists")
    user = await auth_service.create_user(
        session,
        username=username,
        email=email,
        password=password,
        full_name=full_name,
        role=role,
    )
    await session.flush()
    return user


async def update_user_profile(
    session: AsyncSession,
    user: User,
    email: Optional[str] = None,
    full_name: Optional[str] = None,
) -> Tuple[User, list[str]]:
    changes = []
    if email is not None and email != user.email:
        duplicate = await find_duplicate(session, email=email, exclude_user_id=str(user.id))
        if duplicate:
            raise UserValidationError("Email already exists")
        user.email = email
        changes.append("email")
    if full_name is not None:
        user.full_name = full_name
        changes.append("full_name")
    await session.flush()
    return user, changes


async def change_user_status(session: AsyncSession, user: User, new_status: str) -> Tuple[User, list[str]]:
    if new_status not in VALID_STATUSES:
        raise UserValidationError(
            f"Invalid status '{new_status}'. Allowed: {', '.join(sorted(VALID_STATUSES))}"
        )
    if new_status == user.status:
        return user, []
    if new_status != "active" and await is_last_active_admin(session, user):
        raise UserValidationError(
            "Cannot deactivate the last active administrator"
        )
    old_status = user.status
    user.status = new_status
    user.is_active = new_status == "active"
    await session.flush()
    return user, [old_status, new_status]


async def change_user_role(session: AsyncSession, user: User, new_role: str) -> Tuple[User, list[str]]:
    if new_role not in VALID_ROLES:
        raise UserValidationError(
            f"Invalid role '{new_role}'. Allowed: {', '.join(sorted(VALID_ROLES))}"
        )
    if new_role == user.role:
        return user, []
    if user.role == "administrator" and new_role != "administrator":
        if await is_last_active_admin(session, user):
            raise UserValidationError(
                "Cannot demote the last active administrator"
            )
    old_role = user.role
    user.role = new_role
    await session.flush()
    return user, [old_role, new_role]


async def reset_user_password(
    session: AsyncSession, user: User, new_password: str
) -> User:
    if len(new_password) < 8:
        raise UserValidationError("Password must be at least 8 characters long")
    user.password_hash = auth_service.hash_password(new_password)
    await session.flush()
    return user


async def delete_user(session: AsyncSession, user: User) -> None:
    if user.role == "administrator" and user.status == "active":
        admins = await count_active_admins(session)
        if admins <= 1:
            raise UserValidationError(
                "Cannot delete the last active administrator"
            )
    await session.delete(user)
    await session.flush()
