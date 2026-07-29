import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.models.host import Host
from app.models.port import Port
from app.models.service import Service
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.nmap_service import NmapPortResult, run_scan


SCAN_PROFILES = {
    "top_ports": {"display_name": "Top 1000 Ports", "ports": None, "extra_args": ["--top-ports", "1000"]},
    "custom_range": {"display_name": "Custom Port Range", "ports": None, "extra_args": None},
    "all_ports": {"display_name": "All Ports (1-65535)", "ports": "1-65535", "extra_args": None},
}


async def port_scan_handler(
    assessment_id: str,
    target: str,
    parameters: Optional[dict] = None,
    tracker: Optional[ProgressTracker] = None,
) -> dict:
    logger.info(
        "Port scan handler invoked: assessment={id}, target={target}",
        id=assessment_id,
        target=target,
    )

    params = parameters or {}
    scan_type = params.get("scan_type", "tcp_syn")
    scan_profile = params.get("scan_profile", "top_ports")
    ports = params.get("ports")
    extra_args = params.get("extra_args")

    if tracker:
        tracker.update_stage_status("port_scan", StageStatus.RUNNING)

    if tracker:
        tracker.update_stage_progress("port_scan", 5.0)

    profile = SCAN_PROFILES.get(scan_profile, SCAN_PROFILES["top_ports"])
    resolved_ports = ports or profile.get("ports")
    resolved_extra_args = extra_args or profile.get("extra_args")

    if tracker:
        tracker.update_stage_progress("port_scan", 10.0)

    async with async_session_factory() as session:
        hosts_result = await session.execute(
            select(Host).where(Host.is_alive == True)
        )
        alive_hosts = list(hosts_result.scalars().all())

    if not alive_hosts:
        logger.warning("No alive hosts found to scan")
        if tracker:
            tracker.update_stage_progress("port_scan", 100.0)
        return {"success": True, "summary": {"total_hosts_scanned": 0, "total_ports_found": 0}}

    total_hosts = len(alive_hosts)
    total_ports_found = 0
    total_services_found = 0
    scan_details = []
    host_progress_per_host = 80.0 / total_hosts if total_hosts > 0 else 0

    for idx, host in enumerate(alive_hosts):
        host_target = host.ip_address
        host_progress_start = 15.0 + (idx * host_progress_per_host)

        if tracker:
            tracker.update_stage_progress("port_scan", host_progress_start)

        result = await run_scan(
            scan_type=scan_type,
            target=host_target,
            ports=resolved_ports,
            extra_args=resolved_extra_args,
        )

        if result.error:
            logger.error("Port scan failed for {ip}: {error}", ip=host_target, error=result.error)
            scan_details.append({"host": host_target, "error": result.error, "ports_found": 0})
            continue

        if not result.hosts:
            scan_details.append({"host": host_target, "ports_found": 0})
            continue

        scanned_host = result.hosts[0]
        ports_found_for_host = 0
        services_found_for_host = 0

        try:
            async with async_session_factory() as session:
                for nmap_port in scanned_host.open_ports:
                    upserted = await _upsert_port(session, host.id, nmap_port)
                    if nmap_port.service_name:
                        await _upsert_service(session, upserted.id, nmap_port)
                        services_found_for_host += 1
                    ports_found_for_host += 1

                await session.commit()
        except Exception as e:
            logger.error("Failed to store port results for {ip}: {error}", ip=host_target, error=str(e))
            continue

        total_ports_found += ports_found_for_host
        total_services_found += services_found_for_host

        scan_details.append({
            "host": host_target,
            "ports_found": ports_found_for_host,
            "services_found": services_found_for_host,
            "duration_seconds": result.duration_seconds,
        })

        if tracker:
            progress = host_progress_start + host_progress_per_host
            tracker.update_stage_progress("port_scan", min(progress, 95.0))

    if tracker:
        tracker.update_stage_progress("port_scan", 100.0)

    summary = {
        "scan_profile": scan_profile,
        "scan_type": scan_type,
        "ports": resolved_ports,
        "total_hosts_scanned": total_hosts,
        "total_ports_found": total_ports_found,
        "total_services_found": total_services_found,
        "scan_details": scan_details,
    }

    logger.info(
        "Port scan completed: {ports} ports on {hosts} hosts",
        ports=total_ports_found,
        hosts=total_hosts,
    )

    return {"success": True, "summary": summary}


async def _upsert_port(
    session: AsyncSession,
    host_id: uuid.UUID,
    nmap_port: NmapPortResult,
) -> Port:
    result = await session.execute(
        select(Port).where(
            Port.host_id == host_id,
            Port.port == nmap_port.port,
            Port.protocol == nmap_port.protocol,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.state = nmap_port.state
        existing.reason = nmap_port.reason or existing.reason
        return existing
    else:
        new_port = Port(
            host_id=host_id,
            port=nmap_port.port,
            protocol=nmap_port.protocol,
            state=nmap_port.state,
            reason=nmap_port.reason,
        )
        session.add(new_port)
        await session.flush()
        return new_port


async def _upsert_service(
    session: AsyncSession,
    port_id: uuid.UUID,
    nmap_port: NmapPortResult,
) -> Service:
    result = await session.execute(
        select(Service).where(Service.port_id == port_id)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.name = nmap_port.service_name or existing.name
        existing.product = nmap_port.product or existing.product
        existing.version = nmap_port.version or existing.version
        existing.extra_info = nmap_port.extra_info or existing.extra_info
        existing.tunnel = nmap_port.tunnel or existing.tunnel
        existing.banner = nmap_port.banner or existing.banner
        return existing
    else:
        new_service = Service(
            port_id=port_id,
            name=nmap_port.service_name,
            product=nmap_port.product,
            version=nmap_port.version,
            extra_info=nmap_port.extra_info,
            tunnel=nmap_port.tunnel,
            banner=nmap_port.banner,
        )
        session.add(new_service)
        await session.flush()
        return new_service


async def get_ports_by_host(
    session: AsyncSession,
    host_id: str,
) -> list[Port]:
    result = await session.execute(
        select(Port).where(Port.host_id == uuid.UUID(host_id)).order_by(Port.port)
    )
    return list(result.scalars().all())


async def get_ports_by_assessment(
    session: AsyncSession,
    assessment_id: str,
) -> list[Port]:
    result = await session.execute(
        select(Port)
        .join(Host, Port.host_id == Host.id)
        .where(Host.scan_id == uuid.UUID(assessment_id))
        .order_by(Host.ip_address, Port.port)
    )
    return list(result.scalars().all())


async def get_all_ports(
    session: AsyncSession,
    page: int = 1,
    per_page: int = 20,
    state: Optional[str] = None,
    protocol: Optional[str] = None,
) -> tuple[list[Port], int]:
    query = select(Port)

    if state:
        query = query.where(Port.state == state)
    if protocol:
        query = query.where(Port.protocol == protocol)

    count_query = select(Port).with_only_columns(Port.id).order_by(None)
    if state:
        count_query = count_query.where(Port.state == state)
    if protocol:
        count_query = count_query.where(Port.protocol == protocol)

    count_result = await session.execute(count_query)
    total = len(count_result.scalars().all())

    query = query.order_by(Port.port).offset((page - 1) * per_page).limit(per_page)
    result = await session.execute(query)
    return list(result.scalars().all()), total


async def get_port_by_id(
    session: AsyncSession,
    port_id: str,
) -> Optional[Port]:
    result = await session.execute(
        select(Port).where(Port.id == uuid.UUID(port_id))
    )
    return result.scalar_one_or_none()
