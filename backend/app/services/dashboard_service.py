"""Dashboard service.

Aggregates existing database records into a single summary payload for the
enterprise dashboard. Read-only: never mutates data and does not touch
assessment or scanner logic.
"""

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.cve import CVE
from app.models.host import Host
from app.models.port import Port
from app.models.report import Report
from app.models.scan import Scan
from app.models.service import Service
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.dashboard import (
    ActivityItem,
    AssessmentItem,
    DashboardSummary,
    DashboardTotals,
    HostVulnItem,
    PortSlice,
    ReportItem,
    RiskScore,
    ScanDurationStats,
    ServiceSlice,
    SeveritySlice,
    TrendPoint,
)

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}

WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "microsoft-ds", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}

TREND_DAYS = 14
RECENT_LIMIT = 5
ACTIVITY_LIMIT = 8


def _normalize_severity(raw: Optional[str]) -> str:
    if not raw:
        return "Info"
    value = raw.strip().lower()
    for sev in SEVERITIES:
        if sev.lower() == value:
            return sev
    return "Info"


async def _get_assessment_host_ids(session: AsyncSession, assessment_id: str) -> Optional[List[uuid.UUID]]:
    """Return list of host IDs belonging to the assessment, or None if no filter."""
    try:
        aid = uuid.UUID(assessment_id)
    except ValueError:
        return []
    result = await session.execute(select(Host.id).where(Host.scan_id == aid))
    ids = [row[0] for row in result.all()]
    return ids


async def _severity_distribution(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> List[SeveritySlice]:
    query = select(Vulnerability.severity, func.count(Vulnerability.id))
    if host_ids is not None:
        query = query.where(Vulnerability.host_id.in_(host_ids))
    result = await session.execute(query.group_by(Vulnerability.severity))
    counts = {_normalize_severity(sev): cnt for sev, cnt in result.all()}
    return [
        SeveritySlice(severity=sev, count=counts.get(sev, 0))
        for sev in SEVERITIES
    ]


async def _vulnerability_trend(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> List[TrendPoint]:
    day_expr = func.date(Vulnerability.created_at)
    query = select(day_expr.label("day"), func.count(Vulnerability.id)).where(Vulnerability.created_at.is_not(None))
    if host_ids is not None:
        query = query.where(Vulnerability.host_id.in_(host_ids))
    result = await session.execute(query.group_by(day_expr))
    by_day = {row[0]: row[1] for row in result.all()}

    today = date.today()
    points: List[TrendPoint] = []
    for offset in range(TREND_DAYS - 1, -1, -1):
        day = today - timedelta(days=offset)
        points.append(TrendPoint(date=day.isoformat(), count=by_day.get(day, 0)))
    return points


async def _top_open_ports(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> List[PortSlice]:
    query = select(Port.port, func.count(Port.id)).where(Port.state == "open")
    if host_ids is not None:
        query = query.where(Port.host_id.in_(host_ids))
    result = await session.execute(query.group_by(Port.port).order_by(func.count(Port.id).desc()).limit(10))
    return [
        PortSlice(port=port, count=cnt, label=WELL_KNOWN_PORTS.get(port))
        for port, cnt in result.all()
    ]


async def _service_distribution(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> List[ServiceSlice]:
    name_expr = func.coalesce(Service.normalized_name, Service.name)
    query = select(name_expr.label("name"), func.count(Service.id)).where(name_expr.is_not(None), name_expr != "")
    if host_ids is not None:
        from app.models.port import Port
        query = query.join(Port, Service.port_id == Port.id).where(Port.host_id.in_(host_ids))
    result = await session.execute(query.group_by(name_expr).order_by(func.count(Service.id).desc()).limit(10))
    return [ServiceSlice(name=name, count=cnt) for name, cnt in result.all()]


async def _recent_assessments(session: AsyncSession) -> List[AssessmentItem]:
    result = await session.execute(
        select(Scan).order_by(Scan.created_at.desc()).limit(RECENT_LIMIT)
    )
    return [
        AssessmentItem(
            id=scan.id,
            name=scan.name,
            scan_type=scan.scan_type,
            target=scan.target,
            status=scan.status,
            created_at=scan.created_at,
        )
        for scan in result.scalars().all()
    ]


async def _recent_reports(session: AsyncSession, scan_ids: Optional[List[uuid.UUID]] = None) -> List[ReportItem]:
    query = select(Report).order_by(Report.created_at.desc()).limit(RECENT_LIMIT)
    if scan_ids is not None:
        query = query.where(Report.scan_id.in_(scan_ids))
    result = await session.execute(query)
    return [
        ReportItem(
            id=report.id,
            title=report.title,
            report_type=report.report_type,
            format=report.format,
            file_size=report.file_size,
            created_at=report.created_at,
        )
        for report in result.scalars().all()
    ]


async def _top_vulnerable_hosts(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> List[HostVulnItem]:
    query = select(Host.ip_address, func.max(Host.hostname), func.count(Vulnerability.id)).join(
        Vulnerability, Vulnerability.host_id == Host.id
    )
    if host_ids is not None:
        query = query.where(Host.id.in_(host_ids))
    result = await session.execute(query.group_by(Host.ip_address).order_by(func.count(Vulnerability.id).desc()).limit(10))
    return [
        HostVulnItem(ip_address=str(ip), hostname=hostname, count=cnt)
        for ip, hostname, cnt in result.all()
    ]


def _risk_level(score: int) -> str:
    if score >= 70:
        return "Critical"
    if score >= 45:
        return "High"
    if score >= 20:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


async def _totals(session: AsyncSession, host_ids: Optional[List[uuid.UUID]] = None) -> DashboardTotals:
    if host_ids is not None:
        total_vulns = await session.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.host_id.in_(host_ids))
        )
        total_hosts = len(host_ids)
        open_ports = await session.scalar(
            select(func.count(Port.id)).where(Port.state == "open", Port.host_id.in_(host_ids))
        )
        from app.models.port import Port as _Port
        services = await session.scalar(
            select(func.count(Service.id))
            .join(_Port, Service.port_id == _Port.id)
            .where(_Port.host_id.in_(host_ids))
        )
    else:
        total_vulns = await session.scalar(select(func.count(Vulnerability.id)))
        total_hosts = await session.scalar(select(func.count(Host.id)))
        open_ports = await session.scalar(select(func.count(Port.id)).where(Port.state == "open"))
        services = await session.scalar(select(func.count(Service.id)))
    reports = await session.scalar(select(func.count(Report.id)))
    assessments = await session.scalar(select(func.count(Scan.id)))
    return DashboardTotals(
        vulnerabilities=total_vulns or 0,
        hosts=total_hosts or 0,
        open_ports=open_ports or 0,
        services=services or 0,
        reports=reports or 0,
        assessments=assessments or 0,
    )


async def _scan_duration_stats(session: AsyncSession, scan_ids: Optional[List[uuid.UUID]] = None) -> ScanDurationStats:
    duration_expr = func.extract(
        "epoch", Scan.completed_at - Scan.started_at
    )
    query = select(
        func.count(Scan.id),
        func.avg(duration_expr),
        func.min(duration_expr),
        func.max(duration_expr),
    ).where(
        Scan.started_at.is_not(None),
        Scan.completed_at.is_not(None),
        Scan.completed_at >= Scan.started_at,
    )
    if scan_ids is not None:
        query = query.where(Scan.id.in_(scan_ids))
    result = await session.execute(query)
    count, avg_d, min_d, max_d = result.one()
    return ScanDurationStats(
        count=count or 0,
        average_seconds=round(float(avg_d), 1) if avg_d is not None else None,
        min_seconds=round(float(min_d), 1) if min_d is not None else None,
        max_seconds=round(float(max_d), 1) if max_d is not None else None,
    )


async def _activity_timeline(session: AsyncSession) -> List[ActivityItem]:
    result = await session.execute(
        select(AuditLog.action, User.username, AuditLog.timestamp)
        .outerjoin(User, User.id == AuditLog.user_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(ACTIVITY_LIMIT)
    )
    items = []
    for action, username, timestamp in result.all():
        items.append(
            ActivityItem(
                action=action,
                user=username or "system",
                timestamp=timestamp,
            )
        )
    return items


async def get_dashboard_summary(session: AsyncSession, assessment_id: Optional[str] = None) -> DashboardSummary:
    host_ids = None
    scan_ids = None
    if assessment_id:
        host_ids = await _get_assessment_host_ids(session, assessment_id)
        if not host_ids:
            host_ids = []
        scan_ids = [uuid.UUID(assessment_id)] if assessment_id else None

    distribution = await _severity_distribution(session, host_ids)
    total_vulns = sum(s.count for s in distribution)

    critical_count = distribution[0].count
    weighted = sum(
        SEVERITY_WEIGHTS[sev.severity.lower()] * sev.count for sev in distribution
    )
    max_weighted = 10 * total_vulns if total_vulns else 1
    score = round(weighted / max_weighted * 100) if total_vulns else 0

    exploit_count_query = select(func.count(func.distinct(CVE.id))).where(
        CVE.exploit_available.is_(True)
    )
    if host_ids is not None:
        exploit_count_query = exploit_count_query.join(
            Vulnerability, CVE.vuln_id == Vulnerability.id
        ).where(Vulnerability.host_id.in_(host_ids))
    exploit_count = await session.scalar(exploit_count_query)

    totals = await _totals(session, host_ids)

    return DashboardSummary(
        severity_distribution=distribution,
        vulnerability_trend=await _vulnerability_trend(session, host_ids),
        top_open_ports=await _top_open_ports(session, host_ids),
        service_distribution=await _service_distribution(session, host_ids),
        recent_assessments=await _recent_assessments(session),
        recent_reports=await _recent_reports(session, scan_ids),
        top_vulnerable_hosts=await _top_vulnerable_hosts(session, host_ids),
        risk_score=RiskScore(score=score, level=_risk_level(score), total=total_vulns),
        critical_count=critical_count,
        exploit_available_count=exploit_count or 0,
        scan_duration_stats=await _scan_duration_stats(session, scan_ids),
        activity_timeline=await _activity_timeline(session),
        totals=totals,
    )
