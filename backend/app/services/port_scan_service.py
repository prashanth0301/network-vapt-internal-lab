import asyncio
import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import async_session_factory
from app.models.host import Host
from app.models.port import Port
from app.models.service import Service
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.artifact_manager import artifact_manager
from app.services.host_discovery_service import host_discovery_handler
from app.services.nmap_service import NmapPortResult, run_scan, build_command


PORT_SCAN_TYPES = {"tcp_syn", "tcp_connect", "udp_scan"}

SCAN_PROFILES = {
    "top_ports": {"display_name": "Top 1000 Ports", "ports": None, "extra_args": ["--top-ports", "1000"]},
    "custom_range": {"display_name": "Custom Port Range", "ports": None, "extra_args": None},
    "all_ports": {"display_name": "All Ports (1-65535)", "ports": "1-65535", "extra_args": None},
}


async def _save_port_scan_artifacts(
    artifact_dir, hosts_data, result, host_target
):
    if result.raw_output:
        artifact_manager.save_xml(artifact_dir, result.raw_output)

    if result.hosts and result.hosts[0].open_ports:
        ports_json = [
            {
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "service_name": p.service_name,
                "product": p.product,
                "version": p.version,
            }
            for p in result.hosts[0].open_ports
        ]
        host_safe = host_target.replace(".", "_")
        artifact_manager.save_json(
            artifact_dir,
            {"host": host_target, "ports": ports_json},
            filename=f"ports_{host_safe}.json",
        )


async def _get_alive_hosts(session: AsyncSession, assessment_id: str) -> list[Host]:
    try:
        aid = uuid.UUID(assessment_id)
    except ValueError:
        return []
    result = await session.execute(
        select(Host).where(Host.is_alive == True, Host.scan_id == aid)
    )
    return list(result.scalars().all())


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

    if scan_type not in PORT_SCAN_TYPES:
        logger.error("Invalid scan_type for port scan: {type}", type=scan_type)
        return {
            "success": False,
            "error": f"Invalid scan_type '{scan_type}'. Valid port scan types: {', '.join(sorted(PORT_SCAN_TYPES))}",
        }

    start_time = datetime.now(timezone.utc)
    artifact_dir = artifact_manager.create_stage_directory(
        assessment_id, "port_scan"
    )

    profile = SCAN_PROFILES.get(scan_profile, SCAN_PROFILES["top_ports"])
    resolved_ports = ports or profile.get("ports")
    resolved_extra_args = extra_args or profile.get("extra_args")

    command_list = build_command(scan_type, target, resolved_ports, resolved_extra_args)
    command_str = " ".join(command_list)
    artifact_manager.save_command(artifact_dir, command_str)

    metadata = {
        "assessment_id": assessment_id,
        "stage": "port_scan",
        "scan_profile": scan_profile,
        "scan_type": scan_type,
        "ports": resolved_ports,
        "target": target,
        "parameters": params,
        "start_time": start_time.isoformat(),
        "command": command_str,
        "scan_types_used": [scan_type],
    }
    artifact_manager.save_metadata(artifact_dir, metadata)

    if tracker:
        tracker.update_stage_status("port_scan", StageStatus.RUNNING)

    if tracker:
        tracker.update_stage_progress("port_scan", 5.0)

    if tracker:
        tracker.update_stage_progress("port_scan", 10.0)

    async with async_session_factory() as session:
        alive_hosts = await _get_alive_hosts(session, assessment_id)

    if not alive_hosts:
        logger.info(
            "No hosts for assessment {id}; bootstrapping via host discovery on {target}",
            id=assessment_id,
            target=target,
        )
        discovery = await host_discovery_handler(
            assessment_id=assessment_id,
            target=target,
            parameters={"scan_type": "ping_sweep"},
            tracker=tracker,
        )
        if not discovery.get("success"):
            logger.error(
                "Host discovery bootstrap failed for assessment {id}: {error}",
                id=assessment_id,
                error=discovery.get("error", "unknown"),
            )
            return {
                "success": False,
                "error": discovery.get("error", "Host discovery bootstrap failed"),
            }

        async with async_session_factory() as session:
            alive_hosts = await _get_alive_hosts(session, assessment_id)
        logger.info(
            "Host discovery bootstrap found {count} alive hosts for assessment {id}",
            count=len(alive_hosts),
            id=assessment_id,
        )

    if not alive_hosts:
        logger.warning("No alive hosts found to scan")
        end_time = datetime.now(timezone.utc)
        artifact_manager.save_json(artifact_dir, {
            "status": "no_hosts",
            "total_hosts_scanned": 0,
            "total_ports_found": 0,
        })
        async with async_session_factory() as session:
            await artifact_manager.store_metadata(
                session=session,
                assessment_id=assessment_id,
                stage_name="port_scan",
                artifact_dir=artifact_dir,
                status="completed",
                scanner_name="nmap",
                command=command_str,
                parameters=params,
                target=target,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                output_type="json",
            )
            await session.commit()
        if tracker:
            tracker.update_stage_progress("port_scan", 100.0)
        return {"success": True, "summary": {"total_hosts_scanned": 0, "total_ports_found": 0}}

    total_hosts = len(alive_hosts)
    host_progress_per_host = 80.0 / total_hosts if total_hosts > 0 else 0
    semaphore = asyncio.Semaphore(5)

    async def scan_host(host: Host, idx: int) -> dict:
        host_target = str(host.ip_address)
        host_command_list = build_command(scan_type, host_target, resolved_ports, resolved_extra_args)
        host_command_str = " ".join(host_command_list)
        artifact_manager.save_text(
            artifact_dir,
            f"command_{host_target.replace('.', '_')}.txt",
            host_command_str,
        )

        async with semaphore:
            result = await run_scan(
                scan_type=scan_type,
                target=host_target,
                ports=resolved_ports,
                extra_args=resolved_extra_args,
            )

        if result.error:
            logger.error("Port scan failed for {ip}: {error}", ip=host_target, error=result.error)
            return {"host": host_target, "error": result.error, "ports_found": 0, "command": host_command_str}

        if not result.hosts:
            return {"host": host_target, "ports_found": 0, "command": host_command_str}

        scanned_host = result.hosts[0]
        await _save_port_scan_artifacts(artifact_dir, {}, result, host_target)

        ports_found_for_host = 0
        services_found_for_host = 0
        store_error = None
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
            store_error = str(e)

        if tracker:
            progress = 15.0 + ((idx + 1) * host_progress_per_host)
            tracker.update_stage_progress("port_scan", min(progress, 95.0))

        if store_error:
            return {"host": host_target, "error": store_error, "ports_found": ports_found_for_host, "command": host_command_str}

        return {
            "host": host_target,
            "ports_found": ports_found_for_host,
            "services_found": services_found_for_host,
            "duration_seconds": result.duration_seconds,
            "command": host_command_str,
        }

    results = await asyncio.gather(*[scan_host(host, idx) for idx, host in enumerate(alive_hosts)])

    total_ports_found = 0
    total_services_found = 0
    scan_details = []
    scan_errors = []
    for r in results:
        if r.get("error"):
            scan_errors.append({"host": r["host"], "error": r["error"]})
        total_ports_found += r.get("ports_found", 0)
        total_services_found += r.get("services_found", 0)
        scan_details.append(r)

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    results_json = {
        "scan_profile": scan_profile,
        "scan_type": scan_type,
        "target": target,
        "command": command_str,
        "total_hosts_scanned": total_hosts,
        "total_ports_found": total_ports_found,
        "total_services_found": total_services_found,
        "scan_details": scan_details,
        "errors": scan_errors,
    }
    artifact_manager.save_json(artifact_dir, results_json)

    async with async_session_factory() as session:
        await artifact_manager.store_metadata(
            session=session,
            assessment_id=assessment_id,
            stage_name="port_scan",
            artifact_dir=artifact_dir,
            status="completed",
            scanner_name="nmap",
            command=command_str,
            parameters=params,
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            output_type="json",
        )
        await session.commit()

    if tracker:
        tracker.update_stage_progress("port_scan", 100.0)

    summary = {
        "scan_profile": scan_profile,
        "scan_type": scan_type,
        "ports": resolved_ports,
        "command": command_str,
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
        select(Port)
        .options(selectinload(Port.services))
        .where(Port.host_id == uuid.UUID(host_id))
        .order_by(Port.port)
    )
    return list(result.scalars().all())


async def get_ports_by_assessment(
    session: AsyncSession,
    assessment_id: str,
) -> list[Port]:
    result = await session.execute(
        select(Port)
        .options(selectinload(Port.services))
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
    assessment_id: Optional[str] = None,
) -> tuple[list[Port], int]:
    query = select(Port).options(selectinload(Port.services))
    count_query = select(Port).with_only_columns(Port.id).order_by(None)

    if assessment_id:
        try:
            aid = uuid.UUID(assessment_id)
        except ValueError:
            return [], 0
        query = query.join(Host, Port.host_id == Host.id).where(Host.scan_id == aid)
        count_query = count_query.join(Host, Port.host_id == Host.id).where(Host.scan_id == aid)

    if state:
        query = query.where(Port.state == state)
        count_query = count_query.where(Port.state == state)
    if protocol:
        query = query.where(Port.protocol == protocol)
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
        select(Port)
        .options(selectinload(Port.services))
        .where(Port.id == uuid.UUID(port_id))
    )
    return result.scalar_one_or_none()
