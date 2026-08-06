import asyncio
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import cast, exists, func, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory
from app.models.host import Host
from app.models.port import Port
from app.models.scan import Scan
from app.models.service import Service
from app.models.vulnerability import Vulnerability
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.artifact_manager import artifact_manager
from app.services.host_enrichment import enrich_hosts
from app.services.nmap_service import NmapHostResult, run_scan


def _is_invalid_discovery_address(ip: str, target: str) -> bool:
    """Broadcast, multicast, network and unspecified addresses are never hosts."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if (
        addr.is_multicast
        or addr.is_unspecified
        or addr.is_loopback
        or str(addr) == "255.255.255.255"
    ):
        return True
    try:
        if "/" in target:
            network = ipaddress.ip_network(target.strip(), strict=False)
            if addr == network.broadcast_address or addr == network.network_address:
                return True
    except ValueError:
        pass
    return False


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

    async with async_session_factory() as session:
        from sqlalchemy import text
        assessment_uuid = uuid.UUID(assessment_id) if assessment_id else None
        if assessment_uuid:
            await session.execute(text("DELETE FROM hosts WHERE scan_id = :aid"), {"aid": assessment_uuid})
            await session.execute(text("DELETE FROM vulnerabilities WHERE scan_id = :aid"), {"aid": assessment_uuid})
        else:
            await session.execute(text("DELETE FROM exploits"))
            await session.execute(text("DELETE FROM vulnerabilities"))
            await session.execute(text("DELETE FROM services"))
            await session.execute(text("DELETE FROM ports"))
            await session.execute(text("DELETE FROM hosts"))
        await session.commit()
        logger.info("Cleared previous scan data for assessment={id}", id=assessment_id)

    params = parameters or {}
    scan_type = params.get("scan_type", "ping_sweep")
    extra_args = params.get("extra_args")

    start_time = datetime.now(timezone.utc)
    artifact_dir = artifact_manager.create_stage_directory(
        assessment_id, "host_discovery"
    )

    from app.services.nmap_service import build_command

    cmd = build_command(
        scan_type=scan_type,
        target=target,
        extra_args=extra_args,
    )
    command_str = " ".join(cmd)
    artifact_manager.save_command(artifact_dir, command_str)

    metadata = {
        "assessment_id": assessment_id,
        "stage": "host_discovery",
        "scan_type": scan_type,
        "target": target,
        "parameters": params,
        "start_time": start_time.isoformat(),
    }
    artifact_manager.save_metadata(artifact_dir, metadata)

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
        artifact_manager.save_error(artifact_dir, result.error)
        end_time = datetime.now(timezone.utc)
        async with async_session_factory() as session:
            await artifact_manager.store_metadata(
                session=session,
                assessment_id=assessment_id,
                stage_name="host_discovery",
                artifact_dir=artifact_dir,
                status="failed",
                scanner_name="nmap",
                command=command_str,
                parameters=params,
                target=target,
                start_time=start_time,
                end_time=end_time,
                error_message=result.error,
                output_type="text",
            )
            await session.commit()
        return {"success": False, "error": result.error}

    if tracker:
        tracker.update_stage_progress("host_discovery", 60.0)

    result.hosts = [
        h
        for h in result.hosts
        if not _is_invalid_discovery_address(h.ip_address, target)
    ]

    if result.hosts:
        result.hosts = await asyncio.to_thread(enrich_hosts, result.hosts)

    if result.raw_output:
        artifact_manager.save_xml(artifact_dir, result.raw_output)

    hosts_data = [
        {
            "ip": h.ip_address,
            "hostname": h.hostname,
            "mac": h.mac_address,
            "vendor": h.vendor,
            "os": h.os_name,
            "status": h.status,
        }
        for h in result.hosts
    ]
    artifact_manager.save_json(artifact_dir, {
        "scan_type": scan_type,
        "target": target,
        "total_hosts": len(result.hosts),
        "hosts": hosts_data,
    })

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
        end_time = datetime.now(timezone.utc)
        async with async_session_factory() as session:
            await artifact_manager.store_metadata(
                session=session,
                assessment_id=assessment_id,
                stage_name="host_discovery",
                artifact_dir=artifact_dir,
                status="failed",
                scanner_name="nmap",
                command=command_str,
                parameters=params,
                target=target,
                start_time=start_time,
                end_time=end_time,
                error_message=f"Database storage error: {str(e)}",
                output_type="text",
            )
            await session.commit()
        return {
            "success": False,
            "error": f"Database storage error: {str(e)}",
        }

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()
    async with async_session_factory() as session:
        await artifact_manager.store_metadata(
            session=session,
            assessment_id=assessment_id,
            stage_name="host_discovery",
            artifact_dir=artifact_dir,
            status="completed",
            scanner_name="nmap",
            command=command_str,
            parameters=params,
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            output_type="xml",
        )
        await session.commit()

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
    scan_uuid = uuid.UUID(assessment_id) if assessment_id else None
    result = await session.execute(
        select(Host).where(
            Host.ip_address == nmap_host.ip_address,
            Host.scan_id == scan_uuid,
        )
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
    assessment_id: Optional[str] = None,
    search: Optional[str] = None,
) -> tuple[list[Host], int]:
    query = select(Host)
    count_query = select(Host.id).select_from(Host)

    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return [], 0
        query = query.where(Host.scan_id == aid)
        count_query = count_query.where(Host.scan_id == aid)

    if status:
        query = query.where(Host.status == status)
        count_query = count_query.where(Host.status == status)
    if alive_only:
        query = query.where(Host.is_alive == True)
        count_query = count_query.where(Host.is_alive == True)

    if search:
        term = f"%{search.strip()}%"
        open_ports_count = (
            select(func.count(Port.id))
            .where(Port.host_id == Host.id, Port.state == "open")
            .scalar_subquery()
        )
        services_count = (
            select(func.count(Service.id))
            .join(Port, Service.port_id == Port.id)
            .where(Port.host_id == Host.id)
            .scalar_subquery()
        )
        vulnerabilities_count = (
            select(func.count(Vulnerability.id))
            .where(Vulnerability.host_id == Host.id)
            .scalar_subquery()
        )
        service_match = (
            select(Service.id)
            .join(Port, Service.port_id == Port.id)
            .where(
                Port.host_id == Host.id,
                or_(
                    Service.name.ilike(term),
                    Service.product.ilike(term),
                    Service.version.ilike(term),
                    Service.normalized_name.ilike(term),
                    Service.normalized_product.ilike(term),
                    Service.normalized_version.ilike(term),
                ),
            )
            .exists()
        )
        search_filter = or_(
            cast(Host.ip_address, String).ilike(term),
            Host.hostname.ilike(term),
            Host.os_name.ilike(term),
            Host.os_version.ilike(term),
            Host.vendor.ilike(term),
            cast(Host.mac_address, String).ilike(term),
            Host.status.ilike(term),
            cast(Host.latency, String).ilike(term),
            cast(Host.os_accuracy, String).ilike(term),
            cast(Host.scan_id, String).ilike(term),
            exists().where(Scan.id == Host.scan_id, Scan.name.ilike(term)),
            service_match,
            cast(open_ports_count, String).ilike(term),
            cast(services_count, String).ilike(term),
            cast(vulnerabilities_count, String).ilike(term),
        )
        query = query.where(search_filter)
        count_query = count_query.where(search_filter)

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


async def get_host_summary(session: AsyncSession, assessment_id: Optional[str] = None) -> dict:
    total_query = select(Host.id)
    alive_query = select(Host.id).where(Host.is_alive == True)

    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return {"total_hosts": 0, "alive_hosts": 0}
        total_query = total_query.where(Host.scan_id == aid)
        alive_query = alive_query.where(Host.scan_id == aid)

    total_result = await session.execute(total_query)
    total = len(total_result.fetchall())

    alive_result = await session.execute(alive_query)
    alive = len(alive_result.fetchall())

    return {
        "total_hosts": total,
        "alive_hosts": alive,
    }
