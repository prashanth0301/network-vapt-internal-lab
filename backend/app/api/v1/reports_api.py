import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from app.core.dependencies import get_db
from app.models.report import Report
from app.models.host import Host
from app.models.vulnerability import Vulnerability
from app.schemas.common import SuccessResponse

router = APIRouter(prefix="/reports", tags=["Reports"])

REPORT_TYPE_LABELS = {
    "executive": "Executive",
    "technical": "Technical",
    "compliance": "Compliance",
}


@router.get("", response_model=SuccessResponse[list[dict]])
async def list_reports(
    assessment_id: Optional[str] = Query(None, description="Filter by assessment UUID"),
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
    order_col = getattr(Report, sort_by, Report.created_at)
    if sort_order == "desc":
        order_col = order_col.desc()
    query = query.order_by(order_col).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    reports = result.scalars().all()
    items = [
        {
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
        for r in reports
    ]
    return SuccessResponse(data=items, message=f"Found {len(reports)} reports")


@router.post("/generate", response_model=SuccessResponse[dict])
async def generate_report(
    report_type: str = Query("executive", description="executive, technical, or compliance"),
    output_format: str = Query("json", description="json, html, or pdf"),
    assessment_id: Optional[str] = Query(None, description="Assessment UUID to scope the report"),
    db: AsyncSession = Depends(get_db),
):
    scan_uuid = None
    if assessment_id:
        try:
            scan_uuid = uuid.UUID(assessment_id)
        except ValueError:
            return SuccessResponse(data={}, message="Invalid assessment_id format")

    hosts_query = select(Host)
    if scan_uuid:
        hosts_query = hosts_query.where(Host.scan_id == scan_uuid)
    hosts_result = await db.execute(hosts_query.order_by(Host.created_at.desc()).limit(1000))
    hosts = hosts_result.scalars().all()

    vulns_query = select(Vulnerability).options(
        joinedload(Vulnerability.host), joinedload(Vulnerability.port)
    )
    if scan_uuid:
        vulns_query = vulns_query.where(Vulnerability.scan_id == scan_uuid)
    vulns_result = await db.execute(vulns_query.order_by(Vulnerability.created_at.desc()).limit(1000))
    vulns = vulns_result.scalars().all()

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        sev = v.severity or "Info"
        if sev in severity_counts:
            severity_counts[sev] += 1

    report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": report_type,
        "assessment_id": assessment_id,
        "summary": {
            "total_hosts": len(hosts),
            "alive_hosts": sum(1 for h in hosts if h.is_alive),
            "total_vulnerabilities": len(vulns),
            "severity_counts": severity_counts,
        },
        "hosts": [
            {
                "ip": str(h.ip_address),
                "hostname": h.hostname,
                "os": h.os_name,
                "status": h.status,
                "is_alive": h.is_alive,
            }
            for h in hosts
        ],
        "findings": [
            {
                "name": v.name,
                "severity": v.severity,
                "risk_score": v.risk_score,
                "host_ip": str(v.host.ip_address) if v.host else None,
                "status": v.status,
                "cve_ids": v.cve_ids or [],
            }
            for v in vulns
            if v.host
        ],
    }

    label = REPORT_TYPE_LABELS.get(report_type, "Technical")
    report_title = f"{label} Report - {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"

    from app.core.config import settings
    reports_dir = settings.BASE_DIR / ".." / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_id = str(uuid.uuid4())
    fallback_note = None

    if output_format == "json":
        filepath = reports_dir / f"{report_id}.json"
        filepath.write_text(json.dumps(report_data, indent=2, default=str))
        file_size = filepath.stat().st_size
    elif output_format == "html":
        html = _render_html(report_data)
        filepath = reports_dir / f"{report_id}.html"
        filepath.write_text(html)
        file_size = filepath.stat().st_size
    elif output_format == "pdf":
        try:
            import reportlab  # type: ignore
        except ImportError:
            fallback_note = "PDF export unavailable on this server - HTML fallback generated"
            html = _render_html(report_data)
            filepath = reports_dir / f"{report_id}.html"
            filepath.write_text(html)
            file_size = filepath.stat().st_size
        else:
            filepath = _render_pdf(report_data, reports_dir / f"{report_id}.pdf")
            file_size = filepath.stat().st_size
    else:
        return SuccessResponse(data={}, message=f"Unsupported output format '{output_format}'")

    report = Report(
        id=uuid.UUID(report_id),
        scan_id=scan_uuid,
        title=report_title,
        report_type=report_type.capitalize(),
        format=output_format.upper(),
        filepath=str(filepath),
        file_size=file_size,
        generated_by="system",
    )
    db.add(report)
    await db.commit()

    logger.info(
        "Report generated: {title} ({format}, {size} bytes)",
        title=report_title,
        format=output_format,
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
            "format": output_format,
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


def _render_pdf(data: dict, filepath: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    doc = SimpleDocTemplate(str(filepath), pagesize=A4)
    styles = getSampleStyleSheet()
    story = [Paragraph("VAPT Assessment Report", styles["Title"]),
             Paragraph(f"Generated: {data.get('generated_at', '')}", styles["Normal"]),
             Spacer(1, 0.2 * inch)]

    summary = data.get("summary", {})
    story.append(Paragraph("Summary", styles["Heading2"]))
    sev = summary.get("severity_counts", {})
    summary_rows = [
        ["Total Hosts", str(summary.get("total_hosts", 0))],
        ["Alive Hosts", str(summary.get("alive_hosts", 0))],
        ["Vulnerabilities", str(summary.get("total_vulnerabilities", 0))],
        ["Critical", str(sev.get("Critical", 0))],
        ["High", str(sev.get("High", 0))],
        ["Medium", str(sev.get("Medium", 0))],
    ]
    summary_table = Table(summary_rows)
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.2 * inch))

    hosts = data.get("hosts", [])
    story.append(Paragraph(f"Hosts ({len(hosts)})", styles["Heading2"]))
    if hosts:
        host_rows = [[h.get("ip", ""), h.get("hostname", "-"), h.get("os", "-"),
                      "Alive" if h.get("is_alive") else "Down"] for h in hosts]
        host_table = Table([["IP", "Hostname", "OS", "Status"]] + host_rows)
        host_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        story.append(host_table)
        story.append(Spacer(1, 0.2 * inch))

    findings = data.get("findings", [])
    story.append(Paragraph(f"Findings ({len(findings)})", styles["Heading2"]))
    if findings:
        finding_rows = [[f.get("name", "")[:80], f.get("severity", "-"),
                         str(f.get("risk_score", "-")), f.get("host_ip", "-")] for f in findings]
        finding_table = Table([["Name", "Severity", "CVSS", "Host"]] + finding_rows, colWidths=[2.8 * inch, 1 * inch, 0.7 * inch, 1.5 * inch])
        finding_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ]))
        story.append(finding_table)

    doc.build(story)
    return filepath


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


def _render_html(data: dict) -> str:
    hosts = data.get("hosts", [])
    findings = data.get("findings", [])
    summary = data.get("summary", {})
    sev = summary.get("severity_counts", {})

    host_rows = "".join(f"<tr><td>{h['ip']}</td><td>{h.get('hostname','-')}</td><td>{h.get('os','-')}</td><td>{'Alive' if h['is_alive'] else 'Down'}</td></tr>" for h in hosts)
    finding_rows = "".join(f"<tr><td>{f['name'][:80]}</td><td>{f.get('severity','-')}</td><td>{f.get('risk_score','-')}</td><td>{f.get('host_ip','-')}</td></tr>" for f in findings)

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>VAPT Report</title>
<style>body{{font-family:Arial,sans-serif;margin:40px;color:#333}}h1{{color:#1a56db}}table{{width:100%;border-collapse:collapse;margin:16px 0}}th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background:#f5f5f5}}.severity{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}}.critical{{background:#dc2626;color:#fff}}.high{{background:#ea580c;color:#fff}}.medium{{background:#ca8a04;color:#fff}}.low{{background:#16a34a;color:#fff}}.summary{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:16px;margin:16px 0}}.stat-card{{border:1px solid #ddd;border-radius:8px;padding:16px;text-align:center}}.stat-value{{font-size:24px;font-weight:bold;color:#1a56db}}</style></head>
<body><h1>VAPT Assessment Report</h1><p>Generated: {data.get('generated_at','')}</p>
<h2>Summary</h2><div class="summary">
<div class="stat-card"><div class="stat-value">{summary.get('total_hosts',0)}</div><div>Total Hosts</div></div>
<div class="stat-card"><div class="stat-value">{summary.get('alive_hosts',0)}</div><div>Alive Hosts</div></div>
<div class="stat-card"><div class="stat-value">{summary.get('total_vulnerabilities',0)}</div><div>Vulnerabilities</div></div>
<div class="stat-card"><div class="stat-value {sev.get('Critical',0) > 0 and 'critical' or ''}">{sev.get('Critical',0)}</div><div>Critical</div></div>
<div class="stat-card"><div class="stat-value {sev.get('High',0) > 0 and 'high' or ''}">{sev.get('High',0)}</div><div>High</div></div>
<div class="stat-card"><div class="stat-value">{sev.get('Medium',0)}</div><div>Medium</div></div></div>
<h2>Hosts ({len(hosts)})</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Status</th></tr></thead><tbody>{host_rows}</tbody></table>
<h2>Findings ({len(findings)})</h2><table><thead><tr><th>Name</th><th>Severity</th><th>CVSS</th><th>Host</th></tr></thead><tbody>{finding_rows}</tbody></table>
</body></html>"""


def _format_size(size: Optional[int]) -> str:
    if size is None:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"
