from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.middleware.rate_limiter import login_limiter
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.auth import (
    AuditLogResponse,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserMeResponse,
)
from app.schemas.common import SuccessResponse
from app.services.auth import auth_service, get_current_user, require_permissions
from app.services.auth.dependencies import PERMISSIONS

router = APIRouter(tags=["Auth"])


@router.post("/auth/login", response_model=SuccessResponse[TokenResponse])
async def login(
    request: LoginRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = req.client.host if req.client else "unknown"
    if not login_limiter.check(f"login:{client_ip}"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait before trying again.",
        )
    user = await auth_service.authenticate(db, request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    user.last_login = datetime.now(timezone.utc)
    await db.flush()

    access_token = auth_service.create_access_token(
        str(user.id), user.role, remember_me=request.remember_me
    )
    refresh_token = auth_service.create_refresh_token(str(user.id))

    await auth_service.log_audit(
        db,
        user_id=str(user.id),
        action="login",
        resource_type="auth",
        details={"username": user.username},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()

    return SuccessResponse(
        data=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        ),
        message="Login successful",
    )


@router.post("/auth/logout", response_model=SuccessResponse[dict])
async def logout(
    req: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="logout",
        resource_type="auth",
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    return SuccessResponse(data={}, message="Logout successful")


@router.post("/auth/refresh", response_model=SuccessResponse[TokenResponse])
async def refresh_token(
    request: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    payload = auth_service.decode_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = payload.get("sub")
    try:
        import uuid
        uid = uuid.UUID(user_id)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    result = await db.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user or user.status != "active":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = auth_service.create_access_token(str(user.id), user.role)
    refresh_token = auth_service.create_refresh_token(str(user.id))

    return SuccessResponse(
        data=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
        ),
        message="Token refreshed",
    )


@router.get("/auth/me", response_model=SuccessResponse[UserMeResponse])
async def get_me(
    current_user: User = Depends(get_current_user),
):
    perms = PERMISSIONS.get(current_user.role, [])
    return SuccessResponse(
        data=UserMeResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            full_name=current_user.full_name,
            role=current_user.role,
            status=current_user.status,
            last_login=current_user.last_login,
            is_active=current_user.is_active,
            permissions=perms,
            created_at=current_user.created_at,
            updated_at=current_user.updated_at,
        ),
        message="User profile retrieved",
    )


@router.get("/roles", response_model=SuccessResponse[dict])
async def list_roles(
    current_user: User = Depends(require_permissions(["manage:users"])),
):
    return SuccessResponse(
        data={
            "roles": list(PERMISSIONS.keys()),
            "permissions": PERMISSIONS,
        },
        message="Roles retrieved",
    )


@router.get("/permissions", response_model=SuccessResponse[dict])
async def list_permissions(
    current_user: User = Depends(get_current_user),
):
    perms = PERMISSIONS.get(current_user.role, [])
    return SuccessResponse(
        data={
            "role": current_user.role,
            "permissions": perms,
            "all_permissions": PERMISSIONS,
        },
        message="Permissions retrieved",
    )


@router.get(
    "/audit-logs",
    response_model=SuccessResponse[list[AuditLogResponse]],
)
async def list_audit_logs(
    current_user: User = Depends(require_permissions(["view:audit"])),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100)
    )
    logs = list(result.scalars().all())
    items = [
        AuditLogResponse(
            id=log.id,
            user_id=log.user_id,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            details=log.details,
            ip_address=log.ip_address,
            timestamp=log.timestamp,
        )
        for log in logs
    ]
    return SuccessResponse(data=items, message=f"Found {len(items)} audit logs")
