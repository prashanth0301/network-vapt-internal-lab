import asyncio
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Form, Query, UploadFile, File
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import get_db
from app.models.packet_capture import PacketCapture
from app.schemas.common import SuccessResponse
from app.services.pcap_parser import PcapParseError, parse_capture_file

router = APIRouter(prefix="/captures", tags=["Packet Captures"])

ACTIVE_CAPTURES: dict[str, "asyncio.subprocess.Process"] = {}

PCAP_EXTENSIONS = (".pcap", ".pcapng", ".cap")


def _live_capture_tool() -> Optional[str]:
    for tool in ("tcpdump", "dumpcap", "tshark"):
        path = shutil.which(tool)
        if path:
            return path
    return None


def _capture_to_dict(c) -> dict:
    return {
        "id": str(c.id),
        "filename": c.filename,
        "size": _format_size(c.file_size),
        "packets": c.packet_count or 0,
        "duration": f"{c.duration_seconds or 0}s",
        "date": c.created_at.isoformat() if c.created_at else "",
        "status": "completed" if c.capture_ended_at else ("capturing" if c.capture_started_at else "pending"),
        "protocol_stats": c.protocol_stats or {},
        "scan_id": str(c.scan_id) if c.scan_id else None,
    }


@router.get("", response_model=SuccessResponse[list[dict]])
async def list_captures(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(PacketCapture)
    if assessment_id:
        try:
            query = query.where(PacketCapture.scan_id == uuid.UUID(assessment_id))
        except ValueError:
            return SuccessResponse(data=[], message="Invalid assessment_id format")
    query = query.order_by(PacketCapture.created_at.desc()).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    captures = result.scalars().all()
    items = [_capture_to_dict(c) for c in captures]
    return SuccessResponse(data=items, message=f"Found {len(captures)} captures")


@router.get("/protocols", response_model=SuccessResponse[list[dict]])
async def get_protocol_stats(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
    db: AsyncSession = Depends(get_db),
):
    query = select(PacketCapture)
    if assessment_id:
        try:
            query = query.where(PacketCapture.scan_id == uuid.UUID(assessment_id))
        except ValueError:
            return SuccessResponse(data=[], message="Invalid assessment_id format")
    query = query.order_by(PacketCapture.created_at.desc()).limit(50)
    result = await db.execute(query)
    captures = result.scalars().all()

    from collections import Counter
    counter: Counter[str] = Counter()
    for c in captures:
        if c.protocol_stats:
            for proto, count in c.protocol_stats.items():
                if isinstance(count, (int, float)):
                    counter[proto] += int(count)

    total = sum(counter.values())
    if total <= 0:
        return SuccessResponse(data=[], message="No protocol data available")

    stats = [
        {"protocol": proto, "percentage": round((count / total) * 100, 1), "packets": count}
        for proto, count in counter.most_common()
    ]
    return SuccessResponse(data=stats, message="Protocol distribution")


@router.get("/{capture_id}", response_model=SuccessResponse[dict])
async def get_capture(capture_id: str, db: AsyncSession = Depends(get_db)):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={}, message="Invalid capture ID format")
    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        return SuccessResponse(data={}, message="Capture not found")
    return SuccessResponse(data=_capture_to_dict(capture), message="Capture retrieved")


@router.post("/upload", response_model=SuccessResponse[dict])
async def upload_capture(
    file: UploadFile = File(...),
    assessment_id: Optional[str] = Form(None, description="Assessment UUID to associate with this capture"),
    db: AsyncSession = Depends(get_db),
):
    from app.core.config import settings

    capture_id = str(uuid.uuid4())
    original_name = file.filename or f"capture_{capture_id}.pcap"
    filename = original_name
    if not filename.lower().endswith(PCAP_EXTENSIONS):
        filename = f"{filename}.pcap"

    dest_dir = settings.BASE_DIR / ".." / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"{capture_id}_{filename}"

    content = await file.read()
    if not content:
        return SuccessResponse(
            data={},
            message="Uploaded file is empty",
        )

    dest_path.write_bytes(content)

    try:
        parsed = parse_capture_file(content)
    except PcapParseError as e:
        dest_path.unlink(missing_ok=True)
        logger.warning("PCAP parse failed for {name}: {error}", name=original_name, error=str(e))
        return SuccessResponse(
            data={"id": capture_id, "filename": original_name, "error": str(e)},
            message=f"Capture uploaded but analysis failed: {e}",
        )

    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            scan_uuid = None

    capture = PacketCapture(
        id=uuid.UUID(capture_id),
        scan_id=scan_uuid,
        filename=original_name,
        filepath=str(dest_path),
        file_size=len(content),
        packet_count=parsed["packet_count"],
        duration_seconds=parsed["duration_seconds"],
        protocol_stats=parsed["protocol_stats"],
        capture_started_at=_parse_dt(parsed["capture_started_at"]),
        capture_ended_at=_parse_dt(parsed["capture_ended_at"]),
    )
    db.add(capture)
    await db.commit()

    logger.info(
        "Capture uploaded and analyzed: {name} ({packets} packets)",
        name=original_name,
        packets=parsed["packet_count"],
    )
    return SuccessResponse(
        data={
            "id": capture_id,
            "filename": original_name,
            "size": len(content),
            "packets": parsed["packet_count"],
            "protocol_stats": parsed["protocol_stats"],
            "duration_seconds": parsed["duration_seconds"],
        },
        message=f"Capture analyzed: {parsed['packet_count']} packets, {len(parsed['protocol_stats'])} protocols",
    )


@router.post("/start", response_model=SuccessResponse[dict])
async def start_capture(
    interface: str = Form("any", description="Network interface to capture on"),
    filter_expr: Optional[str] = Form(None, description="BPF filter expression"),
    assessment_id: Optional[str] = Form(None, description="Assessment UUID to associate"),
    db: AsyncSession = Depends(get_db),
):
    tool = _live_capture_tool()
    if tool is None:
        return SuccessResponse(
            data={},
            message="Live capture requires tcpdump, dumpcap, or tshark on the server PATH - upload a PCAP file instead",
        )

    from app.core.config import settings

    capture_id = str(uuid.uuid4())
    dest_dir = settings.BASE_DIR / ".." / "captures"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_path = dest_dir / f"live_{capture_id}.pcap"

    if shutil.basename(tool) == "tcpdump":
        args = ["-i", interface, "-w", str(dest_path)]
        if filter_expr:
            args.append(filter_expr)
    elif shutil.basename(tool) == "dumpcap":
        args = ["-i", interface, "-w", str(dest_path)]
    else:
        args = ["-i", interface, "-w", str(dest_path)]

    try:
        process = await asyncio.create_subprocess_exec(
            tool, *args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        logger.error("Failed to start capture process: {error}", error=str(e))
        return SuccessResponse(data={}, message=f"Failed to start live capture: {e}")

    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            scan_uuid = None

    capture = PacketCapture(
        id=uuid.UUID(capture_id),
        scan_id=scan_uuid,
        filename=f"live_{capture_id}.pcap",
        filepath=str(dest_path),
        file_size=0,
        packet_count=0,
        filter=filter_expr,
        capture_started_at=datetime.now(timezone.utc),
    )
    db.add(capture)
    await db.commit()

    ACTIVE_CAPTURES[capture_id] = process
    logger.info("Live capture started: {id} on interface {iface}", id=capture_id, iface=interface)
    return SuccessResponse(
        data={"id": capture_id, "interface": interface, "filename": capture.filename},
        message=f"Live capture started on interface '{interface}'",
    )


@router.post("/stop", response_model=SuccessResponse[dict])
async def stop_capture(
    capture_id: str = Form(..., description="Capture ID to stop"),
    db: AsyncSession = Depends(get_db),
):
    try:
        uid = uuid.UUID(capture_id)
    except ValueError:
        return SuccessResponse(data={}, message="Invalid capture ID format")

    result = await db.execute(select(PacketCapture).where(PacketCapture.id == uid))
    capture = result.scalar_one_or_none()
    if not capture:
        return SuccessResponse(data={}, message="Capture not found")

    process = ACTIVE_CAPTURES.pop(capture_id, None)
    if process is not None:
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=10)
        except Exception as e:
            logger.warning("Failed to stop capture process cleanly: {error}", error=str(e))

    from pathlib import Path
    filepath = Path(capture.filepath)
    parsed = None
    if filepath.exists() and filepath.stat().st_size > 0:
        try:
            parsed = parse_capture_file(filepath.read_bytes())
        except PcapParseError as e:
            logger.warning("Failed to parse stopped capture: {error}", error=str(e))

    now = datetime.now(timezone.utc)
    capture.capture_ended_at = now
    if parsed:
        capture.packet_count = parsed["packet_count"]
        capture.duration_seconds = parsed["duration_seconds"]
        capture.protocol_stats = parsed["protocol_stats"]
        if parsed["capture_ended_at"]:
            capture.capture_ended_at = _parse_dt(parsed["capture_ended_at"])
    capture.file_size = filepath.stat().st_size if filepath.exists() else 0
    await db.commit()

    logger.info("Live capture stopped: {id} ({packets} packets)", id=capture_id, packets=capture.packet_count or 0)
    return SuccessResponse(
        data={
            "id": capture_id,
            "packets": capture.packet_count or 0,
            "protocol_stats": capture.protocol_stats or {},
        },
        message=f"Capture stopped with {capture.packet_count or 0} packets captured",
    )


def _parse_dt(iso_str: Optional[str]) -> Optional[datetime]:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _format_size(size: Optional[int]) -> str:
    if size is None:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"
