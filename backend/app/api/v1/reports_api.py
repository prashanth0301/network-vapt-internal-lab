import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from loguru import logger
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.report import Report
from app.schemas.common import SuccessResponse
from app.services.report_service import (
    REPORT_TYPE_LABELS,
    collect_report_data,
    payload_to_json,
    render_html,
    render_pdf,
    _format_size,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


def _report_to_dict(r: Report) -> dict:
    return {
        "id": str(r.id),
        "title": r.title,
        "type": r.report_type,
        "format": r.format,
        "size": _format_size(r.file_size),
        "date": r.created_at.isoformat() if r.created_at else "",
        "status": "ready",
        "filepath": r.filepath,
        "assessment_id": str(r.scan_id) if r.scan_id else None,
    }


@router.get("", response_model=SuccessResponse[list[dict]])
async def list_reports(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    report_type: Optional[str] = Query(None, description="Filter by report type (executive, technical, compliance)"),
    search: Optional[str] = Query(None, description="Search report titles"),
    sort_by: str = Query("created_at"),
    sort_order: str = Query("desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(Report)
    if assessment_id:
        try:
            query = query.where(Report.scan_id == uuid.UUID(assessment_id))
        except ValueError:
            return SuccessResponse(data=[], message="Invalid assessment_id format")
    if report_type:
        query = query.where(Report.report_type == report_type.capitalize())
    if search:
        query = query.where(Report.title.ilike(f"%{search.strip()}%"))
    order_col = getattr(Report, sort_by, Report.created_at)
    if sort_order == "desc":
        order_col = order_col.desc()
    query = query.order_by(order_col).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    reports = result.scalars().all()
    items = [_report_to_dict(r) for r in reports]
    return SuccessResponse(data=items, message=f"Found {len(reports)} reports")


@router.patch("/{report_id}", response_model=SuccessResponse[dict])
async def rename_report(
    report_id: str,
    title: str = Query(..., min_length=1, max_length=255, description="New report title"),
    db: AsyncSession = Depends(get_db),
):
    """Rename a report (metadata only; the stored file keeps its name)."""
    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    new_title = title.strip()
    if not new_title:
        raise HTTPException(status_code=400, detail="Report title cannot be empty")

    old_title = report.title
    report.title = new_title
    await db.commit()
    await db.refresh(report)
    logger.info("Report renamed: {old} -> {new} ({id})", old=old_title, new=new_title, id=report_id)
    return SuccessResponse(
        data=_report_to_dict(report),
        message="Report renamed successfully",
    )


@router.delete("/{report_id}", response_model=SuccessResponse[dict])
async def delete_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Delete a report: removes the database row and its file from disk.

    If the file is already missing, the database row is still deleted so the
    two stay synchronized.
    """
    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    filepath = Path(report.filepath)
    file_was_missing = not filepath.exists()
    if not file_was_missing:
        try:
            filepath.unlink()
            logger.info("Report file removed from disk: {path}", path=filepath)
        except OSError as exc:
            logger.error("Failed to remove report file {path}: {err}", path=filepath, err=exc)
            raise HTTPException(
                status_code=500,
                detail=f"Failed to delete report file: {exc}",
            )

    await db.delete(report)
    await db.commit()
    message = "Report deleted"
    if file_was_missing:
        message = "Report deleted (file was already missing)"
    return SuccessResponse(data={"id": report_id}, message=message)


@router.post("/generate", response_model=SuccessResponse[dict])
async def generate_report(
    report_type: str = Query("executive", description="executive, technical, or compliance"),
    output_format: str = Query("json", description="json, html, or pdf"),
    assessment_id: Optional[str] = Query(None, description="Assessment UUID to scope the report"),
    db: AsyncSession = Depends(get_db),
):
    if report_type not in REPORT_TYPE_LABELS:
        return SuccessResponse(data={}, message=f"Unsupported report type '{report_type}'")
    if output_format not in ("json", "html", "pdf"):
        return SuccessResponse(data={}, message=f"Unsupported output format '{output_format}'")

    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            return SuccessResponse(data={}, message="Invalid assessment_id format")

    report_data = await collect_report_data(db, scan_uuid, report_type)

    label = REPORT_TYPE_LABELS.get(report_type, "Technical")
    report_title = f"{label} Report - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

    from app.core.config import settings
    reports_dir = settings.BASE_DIR / ".." / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_id = str(uuid.uuid4())
    fallback_note = None

    actual_format = output_format
    if output_format == "json":
        filepath = reports_dir / f"{report_id}.json"
        filepath.write_text(payload_to_json(report_data))
        file_size = filepath.stat().st_size
    elif output_format == "html":
        filepath = reports_dir / f"{report_id}.html"
        filepath.write_text(render_html(report_data))
        file_size = filepath.stat().st_size
    else:
        try:
            import reportlab  # type: ignore
        except ImportError:
            fallback_note = "PDF export unavailable on this server - HTML fallback generated"
            actual_format = "HTML"
            filepath = reports_dir / f"{report_id}.html"
            filepath.write_text(render_html(report_data))
            file_size = filepath.stat().st_size
        else:
            filepath = render_pdf(report_data, reports_dir / f"{report_id}.pdf")
            file_size = filepath.stat().st_size

    report = Report(
        id=uuid.UUID(report_id),
        scan_id=scan_uuid,
        title=report_title,
        report_type=report_type.capitalize(),
        format=actual_format,
        filepath=str(filepath),
        file_size=file_size,
        generated_by="system",
    )
    db.add(report)
    await db.commit()

    logger.info(
        "Report generated: {title} ({format}, {size} bytes)",
        title=report_title,
        format=actual_format,
        size=file_size,
    )
    message = "Report generated"
    if fallback_note:
        message = f"{message} ({fallback_note})"
    return SuccessResponse(
        data={
            "id": report_id,
            "title": report_title,
            "type": report_type,
            "format": actual_format,
            "size": _format_size(file_size),
            "fallback": fallback_note,
        },
        message=message,
    )


@router.get("/download/{report_id}")
async def download_report(report_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report ID format")

    result = await db.execute(select(Report).where(Report.id == uid))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    filepath = Path(report.filepath)
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    content = filepath.read_bytes()
    media_type = _media_type_for(filepath.name, report.format)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename=\"{filepath.name}\""},
    )


def _media_type_for(filename: str, report_format: str) -> str:
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        return "application/pdf"
    if ext == ".json":
        return "application/json"
    if ext == ".html":
        return "text/html"
    if ext == ".csv":
        return "text/csv"
    if report_format == "PDF":
        return "application/pdf"
    if report_format == "JSON":
        return "application/json"
    if report_format == "HTML":
        return "text/html"
    return "application/octet-stream"
