"""Dashboard summary API.

Single read-only aggregation endpoint backing the enterprise dashboard.
Available to any authenticated user.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.user import User
from app.schemas.dashboard import DashboardSummaryResponse
from app.schemas.common import SuccessResponse
from app.services.auth import get_current_user
from app.services.dashboard_service import get_dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    summary = await get_dashboard_summary(db)
    return SuccessResponse(data=summary, message="Dashboard summary generated")
