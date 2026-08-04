import json
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.middleware.rate_limiter import login_limiter
from app.models.user import User
from app.schemas.auth import (
    AuditLogResponse,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserMeResponse,
)
from app.schemas.common import PaginatedResponse, SuccessResponse
from app.services.audit_log_service import (
    VALID_SORT_FIELDS,
    VALID_STATUSES,
    audit_log_to_dict,
    day_boundaries,
    fetch_all_matching,
    list_audit_actions,
    list_audit_users,
    query_audit_logs,
    render_csv,
)
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
    response_model=PaginatedResponse[AuditLogResponse],
)
async def list_audit_logs(
    current_user: User = Depends(require_permissions(["view:audit"])),
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = Query(
        None, description="Search across username, action, target and IP"
    ),
    user: Optional[str] = Query(None, description="Filter by username"),
    action: Optional[str] = Query(None, description="Filter by action name"),
    date_from: Optional[date] = Query(None, description="Inclusive start date"),
    date_to: Optional[date] = Query(None, description="Inclusive end date"),
    status: Optional[str] = Query(
        None, description="Filter by status: success or failure"
    ),
    sort_by: str = Query(
        "timestamp", description="Sort field: timestamp, action or username"
    ),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    if sort_by not in VALID_SORT_FIELDS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sort_by '{sort_by}'. Allowed: {', '.join(sorted(VALID_SORT_FIELDS))}",
        )
    if status and status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{status}'. Allowed: {', '.join(sorted(VALID_STATUSES))}",
        )
    if date_from and date_to and date_from > date_to:
        raise HTTPException(
            status_code=400, detail="date_from must be before or equal to date_to"
        )

    start, end = day_boundaries(date_from, date_to)
    logs, total = await query_audit_logs(
        db,
        search=search,
        user=user,
        action=action,
        date_from=start,
        date_to=end,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )
    items = [AuditLogResponse(**audit_log_to_dict(log)) for log in logs]
    total_pages = (total + per_page - 1) // per_page if total else 0
    return PaginatedResponse(
        data=items,
        pagination={
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
        },
        message=f"Found {total} audit logs",
    )


@router.get("/audit-logs/meta", response_model=SuccessResponse[dict])
async def audit_log_meta(
    current_user: User = Depends(require_permissions(["view:audit"])),
    db: AsyncSession = Depends(get_db),
):
    users, actions = await _audit_filter_options(db)
    return SuccessResponse(
        data={
            "users": users,
            "actions": actions,
            "statuses": list(VALID_STATUSES),
        },
        message="Audit log filter options retrieved",
    )


@router.get("/audit-logs/export")
async def export_audit_logs(
    current_user: User = Depends(require_permissions(["view:audit"])),
    db: AsyncSession = Depends(get_db),
    format: str = Query("csv", description="Export format: csv or json"),
    search: Optional[str] = Query(None),
    user: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    date_from: Optional[date] = Query(None),
    date_to: Optional[date] = Query(None),
    status: Optional[str] = Query(None),
    sort_by: str = Query("timestamp"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
):
    if format not in ("csv", "json"):
        raise HTTPException(
            status_code=400, detail="Invalid export format. Allowed: csv, json"
        )
    if sort_by not in VALID_SORT_FIELDS:
        raise HTTPException(status_code=400, detail="Invalid sort_by value")
    if status and status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status value")

    start, end = day_boundaries(date_from, date_to)
    logs = await fetch_all_matching(
        db,
        search=search,
        user=user,
        action=action,
        date_from=start,
        date_to=end,
        status=status,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    if format == "json":
        payload = json.dumps(
            [audit_log_to_dict(log) for log in logs],
            indent=2,
            default=str,
        )
        filename = f"audit_logs_{timestamp}.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )

    filename = f"audit_logs_{timestamp}.csv"
    return Response(
        content=render_csv(logs),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


async def _audit_filter_options(db: AsyncSession) -> tuple[list[dict], list[str]]:
    users = await list_audit_users(db)
    actions = await list_audit_actions(db)
    return users, actions
