"""Settings module API.

Read access for any authenticated user; modifications are restricted to
administrators (manage:settings permission). All mutations are audit-logged.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.user import User
from app.schemas.common import SuccessResponse
from app.schemas.setting import (
    ResetResponse,
    SettingItem,
    SettingsSaveResponse,
    SettingsUpdateRequest,
    SettingsUpdateResponse,
    SystemInfoResponse,
)
from app.services.auth import auth_service, get_current_user, require_permissions
from app.services.settings_service import (
    SettingsValidationError,
    get_settings,
    get_system_info,
    remove_logo,
    reset_settings,
    resolve_logo_path,
    save_settings,
    upload_logo,
)

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("", response_model=SuccessResponse[List[SettingItem]])
async def list_settings(
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    items = await get_settings(db, category)
    return SuccessResponse(data=items, message=f"Found {len(items)} settings")


@router.put("", response_model=SettingsSaveResponse)
async def update_settings(
    body: SettingsUpdateRequest,
    req: Request,
    current_user: User = Depends(require_permissions(["manage:settings"])),
    db: AsyncSession = Depends(get_db),
):
    try:
        updated = await save_settings(db, body.values)
    except SettingsValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "message": exc.message,
                "errors": exc.details,
            },
        ) from exc

    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="settings_updated",
        resource_type="settings",
        details={"keys": sorted(body.values.keys()), "count": updated},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    logger.info("Settings updated by {user}: {count} keys", user=current_user.username, count=updated)
    return SuccessResponse(
        data=SettingsUpdateResponse(updated=updated),
        message=f"Saved {updated} settings",
    )


@router.post("/reset", response_model=SuccessResponse[ResetResponse])
async def reset_settings_endpoint(
    req: Request,
    current_user: User = Depends(require_permissions(["manage:settings"])),
    db: AsyncSession = Depends(get_db),
):
    reset = await reset_settings(db)
    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="settings_reset",
        resource_type="settings",
        details={"count": reset},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    logger.info("Settings reset by {user}: {count} keys", user=current_user.username, count=reset)
    return SuccessResponse(data=ResetResponse(reset=True), message="Settings reset to defaults")


@router.get("/system", response_model=SuccessResponse[SystemInfoResponse])
async def system_info(
    current_user: User = Depends(get_current_user),
):
    info = await get_system_info()
    return SuccessResponse(data=info, message="System information collected")


@router.post("/logo", response_model=SuccessResponse[dict])
async def upload_logo_endpoint(
    req: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(require_permissions(["manage:settings"])),
    db: AsyncSession = Depends(get_db),
):
    content = await file.read()
    try:
        filename = await upload_logo(db, content, file.content_type or "", file.filename or "logo")
    except SettingsValidationError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc
    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="settings_logo_uploaded",
        resource_type="settings",
        details={"filename": filename},
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    return SuccessResponse(data={"filename": filename}, message="Company logo uploaded")


@router.get("/logo")
async def get_logo(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    items = await get_settings(db, "general")
    stored = next((s for s in items if s.key == "general.company_logo"), None)
    path = resolve_logo_path(stored.value) if stored and stored.value else None
    if path is None:
        raise HTTPException(status_code=404, detail="No company logo uploaded")
    return FileResponse(path)


@router.delete("/logo", response_model=SuccessResponse[dict])
async def remove_logo_endpoint(
    req: Request,
    current_user: User = Depends(require_permissions(["manage:settings"])),
    db: AsyncSession = Depends(get_db),
):
    await remove_logo(db)
    await auth_service.log_audit(
        db,
        user_id=str(current_user.id),
        action="settings_logo_removed",
        resource_type="settings",
        ip_address=req.client.host if req.client else None,
    )
    await db.commit()
    return SuccessResponse(data={"removed": True}, message="Company logo removed")
