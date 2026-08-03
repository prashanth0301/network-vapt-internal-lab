from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import shutil
from fastapi import APIRouter, Depends, Query
from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.schemas.common import SuccessResponse
from app.services.artifact_manager import artifact_manager

router = APIRouter(prefix="/history", tags=["History"])


def _delete_assessment_artifact_dir(assessment_id: Optional[str]) -> None:
    if not assessment_id:
        return
    sanitized = assessment_id.replace("/", "_").replace("\\", "_")
    assessment_dir = artifact_manager.base_dir / f"assessment_{sanitized[:8]}"
    if assessment_dir.exists():
        shutil.rmtree(assessment_dir, ignore_errors=True)
        logger.info(
            "Deleted artifact directory: {path}",
            path=str(assessment_dir),
        )


def _get_time_range(preset: str, from_date: Optional[str], to_date: Optional[str]) -> tuple[Optional[datetime], Optional[datetime]]:
    now = datetime.now(timezone.utc)
    if preset == "last_15m":
        return now - timedelta(minutes=15), now
    elif preset == "last_1h":
        return now - timedelta(hours=1), now
    elif preset == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0), now
    elif preset == "last_7d":
        return now - timedelta(days=7), now
    elif preset == "last_30d":
        return now - timedelta(days=30), now
    elif preset == "last_3m":
        return now - timedelta(days=90), now
    elif preset == "last_6m":
        return now - timedelta(days=180), now
    elif preset == "last_1y":
        return now - timedelta(days=365), now
    elif preset == "custom":
        if not from_date or not to_date:
            return None, None
        return datetime.fromisoformat(from_date), datetime.fromisoformat(to_date)
    elif preset == "all":
        return None, None
    return None, None


@router.delete("/cleanup", response_model=SuccessResponse[dict])
async def cleanup_history(
    preset: str = Query(..., description="Time range preset"),
    from_date: Optional[str] = Query(None, description="Custom range start (ISO)"),
    to_date: Optional[str] = Query(None, description="Custom range end (ISO)"),
    assessment_id: Optional[str] = Query(None, description="Delete specific assessment"),
    db: AsyncSession = Depends(get_db),
):
    if assessment_id:
        from app.services.assessment_cleanup import delete_assessment_cascade

        await delete_assessment_cascade(db, assessment_id)
        logger.info("Deleted artifacts for assessment {id}", id=assessment_id)
        return SuccessResponse(data={"deleted_assessment": assessment_id}, message="Assessment history deleted")

    if preset == "all":
        async with db.begin():
            await db.execute(text("DELETE FROM exploits"))
            await db.execute(text("DELETE FROM cves"))
            await db.execute(text("DELETE FROM vulnerabilities"))
            await db.execute(text("DELETE FROM services"))
            await db.execute(text("DELETE FROM ports"))
            await db.execute(text("DELETE FROM hosts"))
            await db.execute(text("DELETE FROM reports"))
            await db.execute(text("DELETE FROM packets"))
            await db.execute(text("DELETE FROM conversations"))
            await db.execute(text("DELETE FROM packet_captures"))
            await db.execute(text("DELETE FROM artifacts"))
            await db.execute(text("DELETE FROM scans"))
        for entry in artifact_manager.base_dir.iterdir():
            if entry.is_dir() and entry.name.startswith("assessment_"):
                shutil.rmtree(entry, ignore_errors=True)
                logger.info("Deleted artifact directory: {path}", path=str(entry))
        logger.info("Deleted all history data")
        return SuccessResponse(data={"deleted": "all"}, message="All history deleted")

    if not time_from or not time_to:
        return SuccessResponse(data={"deleted": 0}, message="Invalid time range")

    async with db.begin():
        artifact_assessments = await db.execute(
            text("SELECT DISTINCT assessment_id FROM artifacts WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        affected_assessment_ids = {
            str(row[0]) for row in artifact_assessments.fetchall() if row[0] is not None
        }
        result = await db.execute(
            text("DELETE FROM exploits WHERE host_id IN (SELECT id FROM hosts WHERE created_at BETWEEN :tf AND :tt)"),
            {"tf": time_from, "tt": time_to},
        )
        exploits_deleted = result.rowcount
        await db.execute(
            text("DELETE FROM cves WHERE vuln_id IN (SELECT id FROM vulnerabilities WHERE created_at BETWEEN :tf AND :tt)"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM vulnerabilities WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM services WHERE port_id IN (SELECT id FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE created_at BETWEEN :tf AND :tt))"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE created_at BETWEEN :tf AND :tt)"),
            {"tf": time_from, "tt": time_to},
        )
        host_result = await db.execute(
            text("DELETE FROM hosts WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        hosts_deleted = host_result.rowcount
        await db.execute(
            text("DELETE FROM reports WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM packets WHERE capture_id IN (SELECT id FROM packet_captures WHERE created_at BETWEEN :tf AND :tt)"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM conversations WHERE capture_id IN (SELECT id FROM packet_captures WHERE created_at BETWEEN :tf AND :tt)"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM packet_captures WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM artifacts WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
        await db.execute(
            text("DELETE FROM scans WHERE created_at BETWEEN :tf AND :tt"),
            {"tf": time_from, "tt": time_to},
        )
    for assessment_id in affected_assessment_ids:
        _delete_assessment_artifact_dir(assessment_id)

    logger.info("Deleted history: preset={preset}, hosts={hosts}, exploits={exploits}", preset=preset, hosts=hosts_deleted, exploits=exploits_deleted)
    return SuccessResponse(
        data={"preset": preset, "hosts_deleted": hosts_deleted, "exploits_deleted": exploits_deleted},
        message=f"Deleted {hosts_deleted} hosts and associated data",
    )
