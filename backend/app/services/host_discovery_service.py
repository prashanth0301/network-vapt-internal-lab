import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.models.host import Host
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.nmap_service import NmapHostResult, run_scan


async def host_discovery_handler(
    assessment_id: str,
    target: str,
    parameters: Optional[dict] = None,
    tracker: Optional[ProgressTracker] = None,
) -> dict:
    logger.info(
        "Host discovery handler invoked: assessment={id}, target={target}",
        id=assessment_id,
        target=target,
    )

    params = parameters or {}
    scan_type = params.get("scan_type", "ping_sweep")
    extra_args = params.get("extra_args")

    if tracker:
        tracker.update_stage_status("host_discovery", StageStatus.RUNNING)

    if tracker:
        tracker.update_stage_progress("host_discovery", 10.0)

    result = await run_scan(
        scan_type=scan_type,
        target=target,
        extra_args=extra_args,
    )

    if result.error:
        logger.error(
            "Host discovery scan failed: {error}",
            error=result.error,
        )
        return {"success": False, "error": result.error}

    if tracker:
        tracker.update_stage_progress("host_discovery", 60.0)

    hosts_stored = 0
    try:
        async with async_session_factory() as session:
            for nmap_host in result.hosts:
                await _upsert_host(
                    session=session,
                    nmap_host=nmap_host,
                    assessment_id=assessment_id,
                )
                hosts_stored += 1

            await session.commit()
    except Exception as e:
        logger.error(
            "Failed to store discovery results: {error}",
            error=str(e),
        )
        return {
            "success": False,
            "error": f"Database storage error: {str(e)}",
        }

    if tracker:
        tracker.update_stage_progress("host_discovery", 100.0)

    summary = {
        "total_hosts_found": len(result.hosts),
        "alive_hosts": sum(1 for h in result.hosts if h.status == "up"),
        "hosts_stored": hosts_stored,
        "scan_duration_seconds": result.duration_seconds,
        "scan_type": scan_type,
        "hosts": [
            {
                "ip": h.ip_address,
                "hostname": h.hostname,
                "os": h.os_name,
                "status": h.status,
            }
            for h in result.hosts
        ],
    }

    logger.info(
        "Host discovery completed: {alive}/{total} hosts alive",
        alive=summary["alive_hosts"],
        total=summary["total_hosts_found"],
    )

    return {"success": True, "summary": summary}


async def _upsert_host(
    session: AsyncSession,
    nmap_host: NmapHostResult,
    assessment_id: str,
) -> Host:
    result = await session.execute(
        select(Host).where(Host.ip_address == nmap_host.ip_address)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.hostname = nmap_host.hostname or existing.hostname
        existing.mac_address = nmap_host.mac_address or existing.mac_address
        existing.vendor = nmap_host.vendor or existing.vendor
        existing.os_name = nmap_host.os_name or existing.os_name
        existing.status = nmap_host.status
        existing.latency = nmap_host.latency or existing.latency
        existing.is_alive = nmap_host.status == "up"
        existing.last_seen = datetime.now(timezone.utc)
        if nmap_host.os_accuracy is not None:
            existing.os_accuracy = nmap_host.os_accuracy
        return existing
    else:
        new_host = Host(
            scan_id=uuid.UUID(assessment_id) if assessment_id else None,
            ip_address=nmap_host.ip_address,
            hostname=nmap_host.hostname,
            mac_address=nmap_host.mac_address,
            vendor=nmap_host.vendor,
            os_name=nmap_host.os_name,
            os_accuracy=nmap_host.os_accuracy,
            status=nmap_host.status,
            latency=nmap_host.latency,
            is_alive=nmap_host.status == "up",
        )
        session.add(new_host)
        return new_host


async def get_all_hosts(
    session: AsyncSession,
    page: int = 1,
    per_page: int = 20,
    status: Optional[str] = None,
    alive_only: bool = False,
) -> tuple[list[Host], int]:
    query = select(Host)

    if status:
        query = query.where(Host.status == status)
    if alive_only:
        query = query.where(Host.is_alive == True)

    count_query = select(Host.id).select_from(Host)
    if status:
        count_query = count_query.where(Host.status == status)
    if alive_only:
        count_query = count_query.where(Host.is_alive == True)

    total_result = await session.execute(count_query)
    total = len(total_result.fetchall())

    query = query.order_by(Host.last_seen.desc())
    query = query.offset((page - 1) * per_page).limit(per_page)

    result = await session.execute(query)
    hosts = list(result.scalars().all())

    return hosts, total


async def get_host_by_id(session: AsyncSession, host_id: str) -> Optional[Host]:
    try:
        uuid_id = uuid.UUID(host_id)
    except ValueError:
        return None
    result = await session.execute(select(Host).where(Host.id == uuid_id))
    return result.scalar_one_or_none()


async def delete_host(session: AsyncSession, host_id: str) -> bool:
    host = await get_host_by_id(session, host_id)
    if not host:
        return False
    await session.delete(host)
    return True


async def get_host_summary(session: AsyncSession) -> dict:
    total_result = await session.execute(select(Host.id))
    total = len(total_result.fetchall())

    alive_result = await session.execute(select(Host.id).where(Host.is_alive == True))
    alive = len(alive_result.fetchall())

    return {
        "total_hosts": total,
        "alive_hosts": alive,
    }
