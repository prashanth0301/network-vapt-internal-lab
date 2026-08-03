"""Consolidated host details: everything the Host Details page shows.

All data is read from existing tables (hosts, ports, services,
vulnerabilities, cves, exploits, scans, reports) - no data is copied
or re-stored. The host row itself scopes ports, services, findings and
exploits; scan history and reports span every assessment that has
discovered the same IP address.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.cve import CVE
from app.models.exploit import Exploit
from app.models.host import Host
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.vulnerability import Vulnerability


async def get_host_details(
    session: AsyncSession, host_id: str
) -> Optional[dict]:
    """Return the full details payload for a host, or None if missing."""
    try:
        host_uuid = uuid.UUID(host_id)
    except ValueError:
        return None
    host = (
        await session.execute(select(Host).where(Host.id == host_uuid))
    ).scalar_one_or_none()
    if host is None:
        return None

    ports = (
        await session.execute(
            select(Port)
            .where(Port.host_id == host.id)
            .order_by(Port.port, Port.protocol)
        )
    ).scalars().all()
    port_ids = [p.id for p in ports]

    services = []
    if port_ids:
        service_rows = (
            await session.execute(
                select(Service, Port.port, Port.protocol)
                .join(Port, Port.id == Service.port_id)
                .where(Service.port_id.in_(port_ids))
                .order_by(Port.port, Service.name)
            )
        ).all()
        services = [
            {
                "id": svc.id,
                "port": port_number,
                "protocol": port_protocol,
                "name": svc.name,
                "product": svc.product,
                "version": svc.version,
                "extra_info": svc.extra_info,
                "tunnel": svc.tunnel,
                "category": svc.category,
                "confidence": svc.confidence,
                "normalized_name": svc.normalized_name,
                "banner": svc.banner,
            }
            for svc, port_number, port_protocol in service_rows
        ]

    vulnerabilities = (
        await session.execute(
            select(Vulnerability)
            .where(Vulnerability.host_id == host.id)
            .order_by(Vulnerability.created_at.desc())
        )
    ).scalars().all()
    vuln_ids = [v.id for v in vulnerabilities]

    cves = []
    if vuln_ids:
        cves = (
            await session.execute(
                select(CVE)
                .where(CVE.vuln_id.in_(vuln_ids))
                .order_by(CVE.cve_id)
            )
        ).scalars().all()

    exploits = (
        await session.execute(
            select(Exploit)
            .where(Exploit.host_id == host.id)
            .order_by(Exploit.rank, Exploit.module_name)
        )
    ).scalars().all()

    scan_rows = (
        await session.execute(
            select(Host.scan_id)
            .where(
                Host.ip_address == host.ip_address,
                Host.scan_id.is_not(None),
            )
        )
    ).scalars().all()
    scan_ids = {sid for sid in scan_rows}

    scans = []
    if scan_ids:
        scans = (
            await session.execute(
                select(Scan)
                .where(Scan.id.in_(scan_ids))
                .order_by(Scan.created_at.desc())
            )
        ).scalars().all()

    reports = []
    if scan_ids:
        reports = (
            await session.execute(
                select(Report)
                .where(Report.scan_id.in_(scan_ids))
                .order_by(Report.created_at.desc())
            )
        ).scalars().all()

    os_information = {
        "hostname": host.hostname,
        "os_name": host.os_name,
        "os_version": host.os_version,
        "os_accuracy": host.os_accuracy,
        "vendor": host.vendor,
        "mac_address": host.mac_address,
        "status": host.status,
        "is_alive": host.is_alive,
        "latency": host.latency,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
    }

    banners = [
        {
            "id": s["id"],
            "port": s["port"],
            "protocol": s["protocol"],
            "service_name": s["name"],
            "product": s["product"],
            "version": s["version"],
            "banner": s["banner"],
        }
        for s in services
        if s.get("banner")
    ]

    evidence = [
        {
            "id": v.id,
            "name": v.name,
            "severity": v.severity,
            "evidence": v.evidence,
            "plugin_output": v.plugin_output,
            "raw_scanner_output": v.raw_scanner_output,
            "references": v.references or [],
            "cve_ids": v.cve_ids or [],
            "created_at": v.created_at,
        }
        for v in vulnerabilities
        if v.evidence or v.plugin_output or v.raw_scanner_output or v.references
    ]

    summary = {
        "ports": len(ports),
        "open_ports": sum(1 for p in ports if p.state == "open"),
        "services": len(services),
        "banners": len(banners),
        "vulnerabilities": len(vulnerabilities),
        "cves": len(cves),
        "exploits": len(exploits),
        "evidence": len(evidence),
        "scans": len(scans),
        "reports": len(reports),
    }

    return {
        "host": host,
        "os_information": os_information,
        "open_ports": [
            {
                "id": p.id,
                "port": p.port,
                "protocol": p.protocol,
                "state": p.state,
                "reason": p.reason,
                "created_at": p.created_at,
            }
            for p in ports
        ],
        "services": services,
        "banners": banners,
        "vulnerabilities": [
            {
                "id": v.id,
                "name": v.name,
                "severity": v.severity,
                "risk_score": v.risk_score,
                "cvss_vector": v.cvss_vector,
                "status": v.status,
                "confidence": v.confidence,
                "cve_ids": v.cve_ids or [],
                "cve_count": v.cve_count,
                "created_at": v.created_at,
            }
            for v in vulnerabilities
        ],
        "cves": [
            {
                "id": c.id,
                "vulnerability_id": c.vuln_id,
                "cve_id": c.cve_id,
                "description": c.description,
                "cvss_v3": c.cvss_v3,
                "cvss_score": c.cvss_score,
                "cvss_severity": c.cvss_severity,
                "exploit_available": c.exploit_available,
                "metasploit_module": c.metasploit_module,
                "epss_score": c.epss_score,
                "kev_status": c.kev_status,
                "published_date": c.published_date,
                "source": c.source,
                "reference_urls": c.reference_urls or [],
            }
            for c in cves
        ],
        "exploits": [
            {
                "id": e.id,
                "module_name": e.module_name,
                "exploit_name": e.exploit_name,
                "cve": e.cve,
                "rank": e.rank,
                "remote_local": e.remote_local,
                "provider": e.provider,
                "verified": e.verified,
                "status": e.status,
                "risk_level": e.risk_level,
                "confidence": e.confidence,
                "session_created": e.session_created,
                "start_time": e.start_time,
                "end_time": e.end_time,
                "duration": e.duration,
            }
            for e in exploits
        ],
        "evidence": evidence,
        "scan_history": [
            {
                "id": s.id,
                "name": s.name,
                "scan_type": s.scan_type,
                "target": s.target,
                "status": s.status,
                "started_at": s.started_at,
                "completed_at": s.completed_at,
                "duration_seconds": (
                    int((s.completed_at - s.started_at).total_seconds())
                    if s.started_at and s.completed_at
                    else None
                ),
                "created_at": s.created_at,
            }
            for s in scans
        ],
        "reports": [
            {
                "id": r.id,
                "title": r.title,
                "report_type": r.report_type,
                "format": r.format,
                "file_size": r.file_size,
                "created_at": r.created_at,
            }
            for r in reports
        ],
        "summary": summary,
    }
