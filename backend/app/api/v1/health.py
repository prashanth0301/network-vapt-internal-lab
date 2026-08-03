import time

from fastapi import APIRouter, Depends
from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.dependencies import get_db
from app.schemas.health import HealthResponse

router = APIRouter()

_start_time: float = time.time()


@router.get("", response_model=HealthResponse)
async def health_check(db: AsyncSession = Depends(get_db)) -> HealthResponse:
    db_status = "connected"
    services = {"api": "running"}

    try:
        await db.execute(text("SELECT 1"))
        services["database"] = "connected"
    except Exception as e:
        db_status = "disconnected"
        services["database"] = f"error: {str(e)}"
        logger.error("Health check: database connection failed: {error}", error=str(e))

    uptime = time.time() - _start_time

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=settings.APP_VERSION,
        app_name=settings.APP_NAME,
        database=db_status,
        uptime_seconds=round(uptime, 2),
        services=services,
        timestamp=__import__("datetime").datetime.utcnow().isoformat(),
    )
