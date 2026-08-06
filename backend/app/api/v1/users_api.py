import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.user import User
from app.schemas.auth import UserCreate, UserResponse, UserUpdate
from app.schemas.common import SuccessResponse
from app.schemas.user import (
    UserListResponse,
    UserPasswordReset,
    UserRoleUpdate,
    UserStatusUpdate,
)
from app.services.auth import auth_service, get_current_user, require_permissions
from app.services.user_management_service import (
    UserValidationError,
    change_user_role,
    change_user_status,
    create_user,
    delete_user,
    find_duplicate,
    is_last_active_admin,
    list_users,
    reset_user_password,
    update_user_profile,
)

router = APIRouter(prefix="/users", tags=["Users"])

USER_FIELDS = {
    "id": "id",
    "username": "username",
    "email": "email",
    "full_name": "full_name",
    "role": "role",
    "status": "status",
    "last_login": "last_login",
    "is_active": "is_active",
    "created_at": "created_at",
    "updated_at": "updated_at",
}


def _user_to_response(user: User) -> UserResponse:
    return UserResponse(**{key: getattr(user, attr) for key, attr in USER_FIELDS.items()})


@router.get(
    "",
    response_model=SuccessResponse[UserListResponse],
    summary="List and search users",
)
async def list_all_users(
    search: Optional[str] = Query(None, description="Search by username, email or full name"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    role: Optional[str] = Query(None, description="Filter by role"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    users, total = await list_users(
        session=db,
        page=page,
        per_page=per_page,
        search=search,
        status=status_filter,
        role=role,
    )
    items = [_user_to_response(u) for u in users]
    return SuccessResponse(
        data=UserListResponse(
            items=items,
            total=total,
            page=page,
            per_page=per_page,
            total_pages=max(1, -(-total // per_page)),
        ),
        message=f"Found {total} users",
    )


@router.get("/{user_id}", response_model=SuccessResponse[UserResponse])
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Admins may fetch any user; other roles may only fetch their own profile."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if current_user.role != "administrator" and str(current_user.id) != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You may only view your own profile",
        )

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return SuccessResponse(data=_user_to_response(user), message="User retrieved")


@router.post("", response_model=SuccessResponse[UserResponse])
async def create_new_user(
    request: UserCreate,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await create_user(
            db,
            username=request.username,
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            role=request.role or "viewer",
        )
    except UserValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="user_created",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username, "email": user.email, "role": user.role},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    await db.refresh(user)
    logger.info("User created: {username} (role={role}) by {actor}",
                username=user.username, role=user.role, actor=current_user.username)
    return SuccessResponse(data=_user_to_response(user), message="User created")


@router.put("/{user_id}", response_model=SuccessResponse[UserResponse])
async def update_user(
    user_id: str,
    request: UserUpdate,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        await update_user_profile(
            db, user, email=request.email, full_name=request.full_name
        )
    except UserValidationError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="user_updated",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    await db.refresh(user)
    return SuccessResponse(data=_user_to_response(user), message="User updated")


@router.delete("/{user_id}", response_model=SuccessResponse[dict])
async def delete_existing_user(
    user_id: str,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if str(user.id) == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account",
        )

    try:
        await delete_user(db, user)
    except UserValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="user_deleted",
        resource_type="user",
        resource_id=user_id,
        details={"username": user.username},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    return SuccessResponse(data={}, message="User deleted")


@router.put("/{user_id}/status", response_model=SuccessResponse[UserResponse])
async def set_user_status(
    user_id: str,
    request: UserStatusUpdate,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    """Activate or deactivate a user account."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        updated, [old_status, new_status] = await change_user_status(db, user, request.status)
    except UserValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if new_status != old_status:
        await auth_service.log_audit(
            db,
            user_id=str(current_user.id),
            action="user_status_changed",
            resource_type="user",
            resource_id=str(user.id),
            details={"username": user.username, "old_status": old_status, "new_status": new_status},
            ip_address=req.client.host if req.client else None,
        )
        await db.commit()
        await db.refresh(updated)
    return SuccessResponse(data=_user_to_response(updated), message="User status updated")


@router.put("/{user_id}/role", response_model=SuccessResponse[UserResponse])
async def set_user_role(
    user_id: str,
    request: UserRoleUpdate,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    """Change a user's role."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if (
        str(user.id) == str(current_user.id)
        and request.role != "administrator"
        and not await is_last_active_admin(db, user)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot change your own role to a lower privilege level",
        )

    try:
        updated, [old_role, new_role] = await change_user_role(db, user, request.role)
    except UserValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if new_role != old_role:
        await auth_service.log_audit(
            db,
            user_id=str(current_user.id),
            action="user_role_changed",
            resource_type="user",
            resource_id=str(user.id),
            details={"username": user.username, "old_role": old_role, "new_role": new_role},
            ip_address=req.client.host if req.client else None,
        )
        await db.commit()
        await db.refresh(updated)
    return SuccessResponse(data=_user_to_response(updated), message="User role updated")


@router.put("/{user_id}/password", response_model=SuccessResponse[dict])
async def reset_password(
    user_id: str,
    request: UserPasswordReset,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:users"])),
    db: AsyncSession = Depends(get_db),
):
    """Reset a user's password (admin only)."""
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        await reset_user_password(db, user, request.password)
    except UserValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="user_password_reset",
        resource_type="user",
        resource_id=str(user.id),
        details={"username": user.username},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    return SuccessResponse(data={}, message="Password reset successfully")
