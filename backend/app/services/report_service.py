"""Report generation service.

Collects assessment data from the database and renders type-specific reports:
- executive: high-level management summary (stats, scorecard, top findings,
  key recommendations) with no deep technical detail.
- technical: full technical details (hosts, ports, services, findings with
  evidence/remediation, CVE inventory, exploit inventory, artifacts).
- compliance: findings mapped to CIS Controls v8 / NIST SP 800-53 / OWASP WSTG
  where available.

This module is the only place that renders reports; scanner logic is untouched.
"""

import html as _html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from xml.sax.saxutils import escape as _xml_escape

from loguru import logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from app.models.artifact import Artifact
from app.models.cve import CVE
from app.models.exploit import Exploit
from app.models.host import Host
from app.models.port import Port
from app.models.vulnerability import Vulnerability
from app.services.report_compliance_map import compliance_map_for

REPORT_TYPE_LABELS = {
    "executive": "Executive",
    "technical": "Technical",
    "compliance": "Compliance",
}

MAX_LISTING = 1000
MAX_FINDING_LIMIT = 150


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
async def collect_report_data(
    db: AsyncSession, scan_uuid: Optional[Any], report_type: str
) -> dict:
    """Load assessment-scoped data (hosts, ports, services, findings, CVEs,
    exploits, artifacts) and build the type-specific report payload."""
    host_q = select(Host)
    if scan_uuid is not None:
        host_q = host_q.where(Host.scan_id == scan_uuid)
    hosts = (await db.execute(host_q.order_by(Host.created_at.desc()).limit(MAX_LISTING))).scalars().all()
    host_ids = [h.id for h in hosts]

    ports = []
    services_by_port = {}
    if host_ids:
        port_q = select(Port).options(selectinload(Port.services))
        port_q = port_q.where(Port.host_id.in_(host_ids)).order_by(Port.port)
        ports = (await db.execute(port_q)).scalars().all()
        for p in ports:
            services_by_port[p.id] = p.services

    vuln_q = select(Vulnerability).options(
        joinedload(Vulnerability.host),
        joinedload(Vulnerability.port),
        joinedload(Vulnerability.service),
    )
    if scan_uuid is not None:
        vuln_q = vuln_q.where(Vulnerability.scan_id == scan_uuid)
    vulns = (await db.execute(vuln_q.order_by(Vulnerability.created_at.desc()).limit(MAX_LISTING))).scalars().all()
    vuln_ids = [v.id for v in vulns]

    cves = []
    exploits = []
    if vuln_ids:
        cves = (await db.execute(
            select(CVE).where(CVE.vuln_id.in_(vuln_ids)).order_by(CVE.cve_id)
        )).scalars().all()
    if host_ids:
        exploits = (await db.execute(
            select(Exploit).where(Exploit.host_id.in_(host_ids)).order_by(Exploit.created_at.desc()).limit(MAX_LISTING)
        )).scalars().all()

    artifacts = []
    if scan_uuid is not None:
        artifacts = (await db.execute(
            select(Artifact).where(Artifact.assessment_id == scan_uuid)
            .order_by(Artifact.created_at.desc()).limit(500)
        )).scalars().all()

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in vulns:
        sev = (v.severity or "Info").capitalize()
        if sev not in severity_counts:
            sev = "Info"
        severity_counts[sev] += 1

    exploit_count_by_vuln: dict = {}
    for e in exploits:
        if e.vulnerability_id is not None:
            exploit_count_by_vuln[e.vulnerability_id] = (
                exploit_count_by_vuln.get(e.vulnerability_id, 0) + 1
            )

    exploitable_cves = [c for c in cves if c.exploit_available]
    kev_cves = [c for c in cves if c.kev_status]
    total_cves = len(cves)

    data: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "report_type": report_type,
        "report_label": REPORT_TYPE_LABELS.get(report_type, "Technical"),
        "assessment_id": str(scan_uuid) if scan_uuid is not None else None,
        "summary": {
            "total_hosts": len(hosts),
            "alive_hosts": sum(1 for h in hosts if h.is_alive),
            "total_vulnerabilities": len(vulns),
            "severity_counts": severity_counts,
            "total_cves": total_cves,
            "exploitable_cves": len(exploitable_cves),
            "kev_cves": len(kev_cves),
            "total_exploits": len(exploits),
        },
        "hosts": [],
        "ports": [],
        "services": [],
        "findings": [],
        "cves": [],
        "exploits": [],
        "artifacts": [],
    }

    for h in hosts:
        data["hosts"].append({
            "ip": str(h.ip_address),
            "hostname": h.hostname,
            "os": h.os_name or "-",
            "os_version": h.os_version or "-",
            "status": h.status,
            "is_alive": h.is_alive,
            "ports_open": sum(
                1 for p in ports if p.host_id == h.id and p.state == "open"
            ),
        })

    host_lookup = {h.id: h for h in hosts}

    def ip_for_host(hid: Any) -> str:
        h = host_lookup.get(hid)
        return str(h.ip_address) if h is not None else "-"

    for p in ports:
        for s in services_by_port.get(p.id, []) or [None]:
            data["ports"].append({
                "host_id": str(p.host_id),
                "ip": ip_for_host(p.host_id),
                "port": p.port,
                "protocol": p.protocol or "tcp",
                "state": p.state,
            })
            if s is not None:
                data["services"].append({
                    "host_id": str(p.host_id),
                    "ip": ip_for_host(p.host_id),
                    "port": p.port,
                    "protocol": p.protocol or "tcp",
                    "name": s.name or "-",
                    "product": s.product or "-",
                    "version": s.version or "-",
                    "banner": (s.banner or "")[:200] or "-",
                    "category": s.category or "-",
                })

    for v in vulns:
        cve_ids = v.cve_ids or []
        data["findings"].append({
            "id": str(v.id),
            "name": v.name,
            "severity": (v.severity or "Info").capitalize(),
            "risk_score": v.risk_score,
            "cvss_vector": v.cvss_vector or "-",
            "host_ip": str(v.host.ip_address) if v.host else None,
            "hostname": v.host.hostname if v.host else None,
            "port": v.port.port if v.port else None,
            "service": v.service.name if v.service else None,
            "product": v.affected_product or (v.service.product if v.service else None),
            "version": v.affected_version or (v.service.version if v.service else None),
            "status": v.status or "open",
            "cve_ids": cve_ids,
            "cwe": v.cwe or [],
            "description": v.description,
            "evidence": v.evidence or v.plugin_output or None,
            "solution": v.solution,
            "references": v.references or [],
            "scanner_name": v.scanner_name,
            "exploit_count": exploit_count_by_vuln.get(v.id, 0),
        })

    for c in cves:
        data["cves"].append({
            "cve_id": c.cve_id,
            "description": c.description,
            "cvss_v2": c.cvss_v2,
            "cvss_v3": c.cvss_v3,
            "cvss_severity": c.cvss_severity,
            "epss_score": c.epss_score,
            "kev_status": c.kev_status,
            "exploit_available": c.exploit_available,
            "metasploit_module": c.metasploit_module,
            "cwe_id": c.cwe_id,
            "reference_urls": c.reference_urls or [],
            "published_date": str(c.published_date) if c.published_date else None,
            "remediation_priority": c.remediation_priority,
            "source": c.source,
        })

    for e in exploits:
        data["exploits"].append({
            "module_name": e.module_name or e.exploit_name or "-",
            "exploit_name": e.exploit_name,
            "cve": e.cve or "-",
            "rank": e.rank or "-",
            "provider": e.provider,
            "status": e.status,
            "risk_level": e.risk_level or "-",
            "verified": e.verified,
            "host_ip": str(e.host.ip_address) if e.host else None,
        })

    for a in artifacts:
        data["artifacts"].append({
            "stage_name": a.stage_name,
            "output_type": a.output_type or "-",
            "status": a.status,
            "target": a.target or "-",
            "artifact_path": Path(a.artifact_path).name,
        })

    return _build_payload(data, report_type)


# ---------------------------------------------------------------------------
# Type-specific payloads
# ---------------------------------------------------------------------------
def _build_payload(data: dict, report_type: str) -> dict:
    if report_type == "executive":
        return _build_executive(data)
    if report_type == "compliance":
        return _build_compliance(data)
    return _build_technical(data)


def _build_executive(data: dict) -> dict:
    findings = sorted(
        (f for f in data["findings"] if f["host_ip"]),
        key=lambda f: f.get("risk_score") or 0,
        reverse=True,
    )
    top_findings = findings[:10]
    summary = data["summary"]

    recommendations = []
    seen = set()
    for f in findings:
        solution = (f.get("solution") or "").strip()
        if solution and solution.lower() not in seen:
            seen.add(solution.lower())
            recommendations.append(solution)
        if len(recommendations) >= 5:
            break

    exploit_ratio = 0
    if summary["total_cves"]:
        exploit_ratio = round(100 * summary["exploitable_cves"] / summary["total_cves"])

    risk_assessment = "Low"
    sev = summary["severity_counts"]
    if sev.get("Critical") or sev.get("High"):
        risk_assessment = "High" if sev.get("Critical") else "Elevated"
    elif sev.get("Medium"):
        risk_assessment = "Moderate"

    return {
        **data,
        "risk_assessment": risk_assessment,
        "exploit_ratio": exploit_ratio,
        "top_findings": top_findings,
        "recommendations": recommendations,
        "cves": [],
        "exploits": [],
        "findings": [],
        "ports": [],
        "services": [],
        "artifacts": [],
    }


def _build_technical(data: dict) -> dict:
    findings = sorted(
        data["findings"],
        key=lambda f: (f.get("risk_score") or 0),
        reverse=True,
    )
    payload = {**data, "findings": findings}
    payload["remediation_summary"] = _remediation_summary(findings)
    return payload


def _build_compliance(data: dict) -> dict:
    mapped = []
    unmapped = []
    for f in data["findings"]:
        entry = compliance_map_for(f.get("cwe") or [], f.get("name") or "")
        item = {
            "name": f["name"],
            "severity": f["severity"],
            "host_ip": f["host_ip"],
            "cwe": ", ".join(f.get("cwe") or []) or "-",
            "cve_ids": f.get("cve_ids") or [],
            "mapping": entry,
        }
        if entry:
            mapped.append(item)
        else:
            unmapped.append(item)

    controls = {"cis": set(), "nist": set(), "owasp": set()}
    for item in mapped:
        m = item["mapping"]
        for code in str(m["cis"]).split(";"):
            controls["cis"].add(code.strip())
        for code in str(m["nist"]).split(";"):
            controls["nist"].add(code.strip())
        controls["owasp"].add(m["owasp"])

    total = len(mapped) + len(unmapped)
    coverage = round(100 * len(mapped) / total) if total else 0
    return {
        **data,
        "findings": data["findings"],
        "compliance_findings": mapped,
        "unmapped_findings": unmapped,
        "controls": {k: sorted(v) for k, v in controls.items()},
        "coverage_pct": coverage,
        "mapped_count": len(mapped),
        "total_count": total,
        "cves": [],
        "exploits": [],
        "ports": [],
        "services": [],
        "artifacts": [],
    }


def _remediation_summary(findings: list[dict]) -> dict:
    groups = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}
    for f in findings:
        sev = f.get("severity") or "Info"
        groups.setdefault(sev, []).append(f)
    return {sev: len(items) for sev, items in groups.items() if items}


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------
def render_html(data: dict) -> str:
    report_type = data.get("report_type", "technical")
    if report_type == "executive":
        return _html_executive(data)
    if report_type == "compliance":
        return _html_compliance(data)
    return _html_technical(data)


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>{_html.escape(title)}</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;color:#333;font-size:13px}}
h1{{color:#1a56db}}h2{{color:#1e40af;border-bottom:2px solid #dbeafe;padding-bottom:6px;margin-top:32px}}
table{{width:100%;border-collapse:collapse;margin:14px 0}}
th,td{{border:1px solid #ddd;padding:7px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5}}tr:nth-child(even){{background:#fafafa}}
.summary{{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:14px;margin:16px 0}}
.stat-card{{border:1px solid #ddd;border-radius:8px;padding:14px;text-align:center;background:#fbfdff}}
.stat-value{{font-size:22px;font-weight:bold;color:#1a56db}}
.severity{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;color:#fff}}
.critical{{background:#dc2626}}.high{{background:#ea580c}}.medium{{background:#ca8a04}}.low{{background:#16a34a}}.info{{background:#64748b}}
.meta{{color:#666;font-size:12px}}.finding{{border:1px solid #e2e8f0;border-radius:8px;padding:14px;margin:14px 0;background:#fff}}
.finding h3{{margin:0 0 6px 0;color:#0f172a}}.label{{font-weight:bold;color:#334155}}
.mono{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}}
.footer{{margin-top:40px;padding-top:14px;border-top:1px solid #ddd;color:#777;font-size:11px}}
</style></head><body>
{body}
<div class="footer">Generated by the Network VAPT Platform. This report is intended for authorised security assessments only.</div>
</body></html>"""


def _stat_cards(items: list[tuple[str, str]]) -> str:
    return '<div class="summary">' + "".join(
        f'<div class="stat-card"><div class="stat-value">{_html.escape(v)}</div><div>{_html.escape(k)}</div></div>'
        for k, v in items
    ) + "</div>"


def _severity_badge(sev: str) -> str:
    cls = (sev or "Info").lower()
    if cls not in ("critical", "high", "medium", "low"):
        cls = "info"
    return f'<span class="severity {cls}">{_html.escape(sev or "Info")}</span>'


def _html_executive(data: dict) -> str:
    summary = data["summary"]
    sev = summary["severity_counts"]
    items = [
        ("Hosts", str(summary["total_hosts"])),
        ("Vulnerabilities", str(summary["total_vulnerabilities"])),
        ("Critical", str(sev.get("Critical", 0))),
        ("High", str(sev.get("High", 0))),
        ("Medium", str(sev.get("Medium", 0))),
        ("CVEs Identified", str(summary["total_cves"])),
        ("Exploitable CVEs", str(summary["exploitable_cves"])),
        ("Known Exploited (KEV)", str(summary["kev_cves"])),
    ]

    rows = "".join(
        f"<tr><td>{_severity_badge(f['severity'])}</td>"
        f"<td>{_html.escape(f['name'])}</td>"
        f"<td>{_html.escape(f['host_ip'] or '-')}</td>"
        f"<td>{f.get('risk_score') or '-'}</td></tr>"
        for f in data["top_findings"]
    )

    recs = "".join(f"<li>{_html.escape(r)}</li>" for r in data["recommendations"])
    if not recs:
        recs = "<li>No open findings require remediation at this time.</li>"

    body = f"""
<h1>Executive Summary - VAPT Assessment</h1>
<p class="meta">Generated: {_html.escape(data.get('generated_at', ''))} | Assessment: {_html.escape(str(data.get('assessment_id') or 'All'))}</p>
<h2>Assessment Overview</h2>
<p>This assessment identified <b>{summary['total_vulnerabilities']}</b> vulnerabilities across <b>{summary['total_hosts']}</b> host(s)
(<b>{summary['alive_hosts']}</b> alive). The overall risk posture is assessed as <b>{data['risk_assessment']}</b>,
driven primarily by {sev.get('Critical', 0)} critical and {sev.get('High', 0)} high severity findings.
Of {summary['total_cves']} CVEs identified, <b>{summary['exploitable_cves']}</b> ({data['exploit_ratio']}%) have publicly
available exploits and {summary['kev_cves']} are listed in CISA's Known Exploited Vulnerabilities catalogue.
These represent the highest immediate risk to the environment.</p>
{_stat_cards(items)}
<h2>Top Findings</h2>
<p class="meta">The ten highest-risk findings identified during the assessment.</p>
<table><thead><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Risk Score</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Key Recommendations</h2>
<ul>{recs}</ul>
<h2>Next Steps</h2>
<p>Immediately remediate all critical and high severity findings, prioritising those with known exploits or KEV status.
Verify the fixes through a follow-up verification scan, and review the Technical Report for detailed evidence and
the Compliance Report for alignment with CIS Controls, NIST SP 800-53 and OWASP guidance.</p>
"""
    return _page(f"Executive Summary Report - {data.get('generated_at', '')}", body)


def _html_technical(data: dict) -> str:
    summary = data["summary"]
    sev = summary["severity_counts"]

    host_rows = "".join(
        f"<tr><td>{_html.escape(h['ip'])}</td><td>{_html.escape(h['hostname'] or '-')}</td>"
        f"<td>{_html.escape(h['os'])}</td><td>{_html.escape(h['os_version'])}</td>"
        f"<td>{'Alive' if h['is_alive'] else 'Down'}</td><td>{h['ports_open']}</td></tr>"
        for h in data["hosts"]
    )
    host_block = f"""<h2>Host Inventory ({summary['total_hosts']})</h2>
<table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>OS Version</th><th>Status</th><th>Open Ports</th></tr></thead>
<tbody>{host_rows or '<tr><td colspan="6">No hosts recorded.</td></tr>'}</tbody></table>"""

    service_rows = "".join(
        f"<tr><td>{_html.escape(s['ip'])}</td><td>{s['port']}</td><td>{_html.escape(s['protocol'])}</td>"
        f"<td>{_html.escape(s['name'])}</td><td>{_html.escape(s['product'])}</td>"
        f"<td>{_html.escape(s['version'])}</td><td>{_html.escape(s['category'])}</td></tr>"
        for s in data["services"]
    )
    service_block = f"""<h2>Ports &amp; Services ({len(data['services'])})</h2>
<p class="meta">Open ports and identified services per host.</p>
<table><thead><tr><th>IP</th><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>Category</th></tr></thead>
<tbody>{service_rows or '<tr><td colspan="7">No services identified.</td></tr>'}</tbody></table>"""

    finding_blocks = []
    for f in data["findings"]:
        cves = ", ".join(_html.escape(c) for c in (f.get("cve_ids") or [])) or "None"
        cwes = ", ".join(_html.escape(c) for c in (f.get("cwe") or [])) or "-"
        refs = "".join(
            f"<div class='mono'>{_html.escape(r)}</div>" for r in (f.get("references") or [])[:10]
        )
        loc = f"{_html.escape(f['host_ip'] or '-')}"
        if f.get("port"):
            loc += f":{f['port']}"
        if f.get("service"):
            loc += f" ({_html.escape(f['service'])})"
        evidence = _html.escape(str(f.get("evidence") or "No evidence captured."))[:1500]
        solution = f.get("solution") or "No remediation guidance recorded."
        finding_blocks.append(f"""
<div class="finding">
<h3>{_severity_badge(f['severity'])} {_html.escape(f['name'])}</h3>
<p class="meta">Host: {loc} | Risk Score: {f.get('risk_score') or '-'} | Status: {_html.escape(f.get('status') or 'open')} | Scanner: {_html.escape(f.get('scanner_name') or '-')} | Exploits: {f.get('exploit_count', 0)}</p>
<p class="label">Description</p><p>{_html.escape(str(f.get('description') or 'No description.'))}</p>
<p class="label">Evidence</p><p class="mono">{evidence}</p>
<p class="label">Remediation</p><p>{_html.escape(solution)}</p>
<p class="label">CVEs</p><p class="mono">{cves}</p>
<p class="label">CWEs</p><p class="mono">{cwes}</p>
<p class="label">References</p>{refs or '<p>None</p>'}
</div>""")

    cve_rows = "".join(
        f"<tr><td class='mono'>{_html.escape(c['cve_id'])}</td><td>{c.get('cvss_v3') or c.get('cvss_v2') or '-'}</td>"
        f"<td>{_html.escape(c.get('cvss_severity') or '-')}</td><td>{c.get('epss_score') or '-'}</td>"
        f"<td>{'Yes' if c['kev_status'] else 'No'}</td><td>{'Yes' if c['exploit_available'] else 'No'}</td>"
        f"<td class='mono'>{_html.escape(c.get('metasploit_module') or '-')}</td></tr>"
        for c in data["cves"]
    )
    cve_block = f"""<h2>CVE Inventory ({len(data['cves'])})</h2>
<p class="meta">Enriched CVE details: CVSS, EPSS likelihood, KEV status and exploit availability.</p>
<table><thead><tr><th>CVE</th><th>CVSS</th><th>Severity</th><th>EPSS</th><th>KEV</th><th>Exploit</th><th>Metasploit Module</th></tr></thead>
<tbody>{cve_rows or '<tr><td colspan="7">No CVEs recorded.</td></tr>'}</tbody></table>"""

    exp_rows = "".join(
        f"<tr><td class='mono'>{_html.escape(e['module_name'])}</td><td>{_html.escape(e['cve'])}</td>"
        f"<td>{_html.escape(e['provider'])}</td><td>{_html.escape(e['rank'])}</td>"
        f"<td>{_html.escape(e['host_ip'] or '-')}</td><td>{_html.escape(e['status'])}</td></tr>"
        for e in data["exploits"]
    )
    exploit_block = f"""<h2>Exploit Inventory ({len(data['exploits'])})</h2>
<p class="meta">Identified exploit modules mapped to findings. Exploitation is not performed by the platform.</p>
<table><thead><tr><th>Module</th><th>CVE</th><th>Source</th><th>Rank</th><th>Host</th><th>Status</th></tr></thead>
<tbody>{exp_rows or '<tr><td colspan="6">No exploits identified.</td></tr>'}</tbody></table>"""

    art_rows = "".join(
        f"<tr><td>{_html.escape(a['stage_name'])}</td><td>{_html.escape(a['output_type'])}</td>"
        f"<td>{_html.escape(a['target'])}</td><td>{_html.escape(a['status'])}</td>"
        f"<td class='mono'>{_html.escape(a['artifact_path'])}</td></tr>"
        for a in data["artifacts"]
    )
    artifact_block = f"""<h2>Scan Artifacts ({len(data['artifacts'])})</h2>
<p class="meta">Raw scan outputs retained as supporting evidence.</p>
<table><thead><tr><th>Stage</th><th>Type</th><th>Target</th><th>Status</th><th>File</th></tr></thead>
<tbody>{art_rows or '<tr><td colspan="5">No artifacts recorded.</td></tr>'}</tbody></table>"""

    rem_summary = data.get("remediation_summary", {})
    rem_rows = "".join(
        f"<tr><td>{_html.escape(sev_name)}</td><td>{count}</td></tr>"
        for sev_name, count in rem_summary.items()
    )

    body = f"""
<h1>Technical Report - VAPT Assessment</h1>
<p class="meta">Generated: {_html.escape(data.get('generated_at', ''))} | Assessment: {_html.escape(str(data.get('assessment_id') or 'All'))}</p>
<h2>Summary</h2>
{_stat_cards([
    ("Hosts", str(summary["total_hosts"])),
    ("Vulnerabilities", str(summary["total_vulnerabilities"])),
    ("Critical", str(sev.get("Critical", 0))),
    ("High", str(sev.get("High", 0))),
    ("Medium", str(sev.get("Medium", 0))),
    ("CVEs", str(summary["total_cves"])),
    ("Exploits", str(summary["total_exploits"])),
])}
<h2>Methodology</h2>
<p>Discovery and identification were performed with non-destructive scanning tools including Nmap (host discovery,
port scan, version detection, vulnerability scripts), OpenVAS (where configured) and OSINT CVE/exploit enrichment
(ExploitDB, GitHub, PacketStorm, NVD, EPSS, CISA KEV). Findings are mapped to hosts, ports and services. Exploit
identification only confirms exploit availability; no exploit is executed against targets.</p>
{host_block}
{service_block}
<h2>Remediation Priority</h2>
<table><thead><tr><th>Severity</th><th>Open Findings</th></tr></thead>
<tbody>{rem_rows or '<tr><td colspan="2">No open findings.</td></tr>'}</tbody></table>
<h2>Findings ({len(data['findings'])})</h2>
<p class="meta">Full technical detail including evidence and remediation for every finding.</p>
{"".join(finding_blocks) or '<p>No findings recorded.</p>'}
{cve_block}
{exploit_block}
{artifact_block}
"""
    return _page("Technical Report", body)


def _html_compliance(data: dict) -> str:
    summary = data["summary"]
    sev = summary["severity_counts"]
    mapped = data.get("compliance_findings", [])
    unmapped = data.get("unmapped_findings", [])

    rows = "".join(
        f"<tr><td>{_severity_badge(f['severity'])} {_html.escape(f['name'])}</td>"
        f"<td>{_html.escape(f['host_ip'] or '-')}</td><td class='mono'>{_html.escape(f['cwe'])}</td>"
        f"<td>{_html.escape(f['mapping']['cis'])}</td><td>{_html.escape(f['mapping']['nist'])}</td>"
        f"<td>{_html.escape(f['mapping']['owasp'])}</td></tr>"
        for f in mapped
    )

    controls = data.get("controls", {})
    control_rows = (
        f"<tr><td>CIS Controls v8</td><td>{_html.escape(', '.join(controls.get('cis', [])) or '-')}</td></tr>"
        f"<tr><td>NIST SP 800-53 Rev5</td><td>{_html.escape(', '.join(controls.get('nist', [])) or '-')}</td></tr>"
        f"<tr><td>OWASP WSTG</td><td>{_html.escape(', '.join(controls.get('owasp', [])) or '-')}</td></tr>"
    )

    unmapped_rows = "".join(
        f"<tr><td>{_html.escape(f['name'])}</td><td>{_html.escape(f['severity'])}</td>"
        f"<td>{_html.escape(f['host_ip'] or '-')}</td></tr>"
        for f in unmapped
    )

    body = f"""
<h1>Compliance Report - VAPT Assessment</h1>
<p class="meta">Generated: {_html.escape(data.get('generated_at', ''))} | Assessment: {_html.escape(str(data.get('assessment_id') or 'All'))}</p>
<h2>Summary</h2>
<p>The assessment identified <b>{summary['total_vulnerabilities']}</b> vulnerabilities
({sev.get('Critical', 0)} critical, {sev.get('High', 0)} high, {sev.get('Medium', 0)} medium).
<b>{data['mapped_count']}</b> of {data['total_count']} findings ({data['coverage_pct']}%) were mapped to one or more
security frameworks where CWE/keyword information was available. Findings without a mapping require manual review
against organisational policy.</p>
{_stat_cards([
    ("Hosts", str(summary["total_hosts"])),
    ("Vulnerabilities", str(summary["total_vulnerabilities"])),
    ("Critical", str(sev.get("Critical", 0))),
    ("High", str(sev.get("High", 0))),
    ("Medium", str(sev.get("Medium", 0))),
    ("Findings Mapped", f"{data['mapped_count']}/{data['total_count']}"),
])}
<h2>Framework Coverage</h2>
<table><thead><tr><th>Framework</th><th>Controls Referenced</th></tr></thead><tbody>{control_rows}</tbody></table>
<h2>Findings to Framework Mapping ({len(mapped)})</h2>
<p class="meta">Each finding mapped to the closest CIS Control v8, NIST SP 800-53 Rev5 control and OWASP WSTG test
where available.</p>
<table><thead><tr><th>Finding</th><th>Host</th><th>CWE</th><th>CIS v8</th><th>NIST 800-53</th><th>OWASP WSTG</th></tr></thead>
<tbody>{rows or '<tr><td colspan="6">No mapped findings.</td></tr>'}</tbody></table>
<h2>Unmapped Findings ({len(unmapped)})</h2>
<p class="meta">Findings that could not be automatically mapped to a framework reference.</p>
<table><thead><tr><th>Finding</th><th>Severity</th><th>Host</th></tr></thead>
<tbody>{unmapped_rows or '<tr><td colspan="3">All findings were mapped.</td></tr>'}</tbody></table>
"""
    return _page("Compliance Report", body)


# ---------------------------------------------------------------------------
# PDF rendering (reportlab)
# ---------------------------------------------------------------------------
def render_pdf(data: dict, filepath: Path) -> Path:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )

    report_type = data.get("report_type", "technical")

    doc = SimpleDocTemplate(str(filepath), pagesize=A4,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            topMargin=0.7 * inch, bottomMargin=0.7 * inch)
    styles = getSampleStyleSheet()
    body = ParagraphStyle("Body", parent=styles["Normal"], fontSize=8.5, leading=11)
    small = ParagraphStyle("Small", parent=body, fontSize=7.5, leading=9.5)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    title = ParagraphStyle("Title2", parent=styles["Title"], fontSize=16, spaceAfter=4)

    story = [
        Paragraph(f"{data['report_label']} Report - VAPT Assessment", title),
        Paragraph(f"Generated: {_xml(data.get('generated_at', ''))} | Assessment: {_xml(str(data.get('assessment_id') or 'All'))}", small),
        Spacer(1, 0.1 * inch),
    ]

    def table(rows: list[list[str]], widths=None, header=True) -> Table:
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]
        if header and rows:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey))
            style.append(("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"))
        t.setStyle(TableStyle(style))
        return t

    summary = data.get("summary", {})
    sev = summary.get("severity_counts", {})

    if report_type == "executive":
        story.append(Paragraph("Assessment Overview", h2))
        story.append(Paragraph(
            f"This assessment identified {summary.get('total_vulnerabilities', 0)} vulnerabilities across "
            f"{summary.get('total_hosts', 0)} host(s). The overall risk posture is assessed as "
            f"{_xml(data.get('risk_assessment', 'Moderate'))}, driven primarily by {sev.get('Critical', 0)} critical "
            f"and {sev.get('High', 0)} high severity findings. Of {summary.get('total_cves', 0)} CVEs identified, "
            f"{summary.get('exploitable_cves', 0)} have publicly available exploits and "
            f"{summary.get('kev_cves', 0)} are listed in CISA's Known Exploited Vulnerabilities catalogue.", body))
        story.append(table([
            ["Total Hosts", str(summary.get("total_hosts", 0))],
            ["Vulnerabilities", str(summary.get("total_vulnerabilities", 0))],
            ["Critical", str(sev.get("Critical", 0))],
            ["High", str(sev.get("High", 0))],
            ["Medium", str(sev.get("Medium", 0))],
            ["CVEs Identified", str(summary.get("total_cves", 0))],
            ["Exploitable CVEs", str(summary.get("exploitable_cves", 0))],
        ], widths=[3 * inch, 3.4 * inch]))
        story.append(Paragraph(f"Top Findings ({len(data.get('top_findings', []))})", h2))
        if data.get("top_findings"):
            story.append(table(
                [["Severity", "Finding", "Host", "Risk"]] + [
                    [f.get("severity", "-"), _xml(str(f.get("name", "")))[:90], _xml(str(f.get("host_ip") or "-")), str(f.get("risk_score") or "-")]
                    for f in data["top_findings"]
                ],
                widths=[0.8 * inch, 3.4 * inch, 1.3 * inch, 0.6 * inch],
            ))
        story.append(Paragraph("Key Recommendations", h2))
        recs = data.get("recommendations", [])
        if recs:
            for r in recs:
                story.append(Paragraph(f"&#8226; {_xml(str(r))}", body))
        else:
            story.append(Paragraph("No open findings require remediation at this time.", body))

    elif report_type == "compliance":
        mapped = data.get("compliance_findings", [])
        unmapped = data.get("unmapped_findings", [])
        story.append(Paragraph("Compliance Summary", h2))
        story.append(Paragraph(
            f"The assessment identified {summary.get('total_vulnerabilities', 0)} vulnerabilities "
            f"({sev.get('Critical', 0)} critical, {sev.get('High', 0)} high, {sev.get('Medium', 0)} medium). "
            f"{data.get('mapped_count', 0)} of {data.get('total_count', 0)} findings "
            f"({data.get('coverage_pct', 0)}%) were mapped to CIS Controls v8, NIST SP 800-53 Rev5 and OWASP WSTG "
            f"references where CWE/keyword information was available.", body))
        controls = data.get("controls", {})
        story.append(Paragraph("Framework Coverage", h2))
        story.append(table([
            ["CIS Controls v8", ", ".join(controls.get("cis", [])) or "-"],
            ["NIST SP 800-53 Rev5", ", ".join(controls.get("nist", [])) or "-"],
            ["OWASP WSTG", ", ".join(controls.get("owasp", [])) or "-"],
        ], widths=[1.8 * inch, 4.6 * inch]))
        story.append(Paragraph(f"Findings to Framework Mapping ({len(mapped)})", h2))
        if mapped:
            rows = [["Finding", "Severity", "CIS v8", "NIST 800-53", "OWASP WSTG"]]
            for f in mapped[:120]:
                rows.append([
                    _xml(str(f["name"]))[:60],
                    str(f["severity"]),
                    f["mapping"]["cis"],
                    f["mapping"]["nist"],
                    f["mapping"]["owasp"],
                ])
            story.append(table(rows, widths=[2.1 * inch, 0.6 * inch, 1.0 * inch, 1.2 * inch, 1.5 * inch]))
        story.append(Paragraph(f"Unmapped Findings ({len(unmapped)})", h2))
        if unmapped:
            story.append(table(
                [["Finding", "Severity", "Host"]] + [
                    [_xml(str(f["name"]))[:70], str(f["severity"]), _xml(str(f["host_ip"] or "-"))]
                    for f in unmapped[:120]
                ],
                widths=[3.4 * inch, 0.8 * inch, 1.8 * inch],
            ))
        else:
            story.append(Paragraph("All findings were mapped.", body))

    else:  # technical
        story.append(Paragraph("Summary", h2))
        story.append(table([
            ["Total Hosts", str(summary.get("total_hosts", 0))],
            ["Vulnerabilities", str(summary.get("total_vulnerabilities", 0))],
            ["Critical", str(sev.get("Critical", 0))],
            ["High", str(sev.get("High", 0))],
            ["Medium", str(sev.get("Medium", 0))],
            ["CVEs", str(summary.get("total_cves", 0))],
            ["Exploits", str(summary.get("total_exploits", 0))],
        ], widths=[3 * inch, 3.4 * inch]))

        story.append(Paragraph(f"Host Inventory ({summary.get('total_hosts', 0)})", h2))
        hosts = data.get("hosts", [])
        if hosts:
            story.append(table(
                [["IP", "Hostname", "OS", "Status", "Open Ports"]] + [
                    [_xml(str(h.get("ip", ""))), _xml(str(h.get("hostname") or "-")),
                     _xml(str(h.get("os", "-"))), "Alive" if h.get("is_alive") else "Down",
                     str(h.get("ports_open", 0))]
                    for h in hosts
                ],
                widths=[1.3 * inch, 1.4 * inch, 2.0 * inch, 0.7 * inch, 0.9 * inch],
            ))

        story.append(Paragraph(f"Ports &amp; Services ({len(data.get('services', []))})", h2))
        services = data.get("services", [])
        if services:
            story.append(table(
                [["IP", "Port", "Service", "Product", "Version", "Category"]] + [
                    [_xml(str(s.get("ip", ""))), f"{s.get('port', '')}/{s.get('protocol', 'tcp')}",
                     _xml(str(s.get("name", "-"))), _xml(str(s.get("product", "-"))),
                     _xml(str(s.get("version", "-"))), _xml(str(s.get("category", "-")))]
                    for s in services[:400]
                ],
                widths=[1.2 * inch, 0.8 * inch, 1.1 * inch, 1.3 * inch, 1.1 * inch, 0.9 * inch],
            ))

        story.append(Paragraph(f"Findings ({len(data.get('findings', []))})", h2))
        for f in data.get("findings", []):
            loc = f"{f.get('host_ip') or '-'}"
            if f.get("port"):
                loc += f":{f['port']}"
            story.append(Paragraph(
                f"<b>[{f.get('severity', 'Info')}] {_xml(str(f.get('name', '')))}</b> "
                f"- Host: {_xml(loc)} - Risk Score: {f.get('risk_score') or '-'} - Exploits: {f.get('exploit_count', 0)}", body))
            desc = str(f.get("description") or "No description.")[:800]
            story.append(Paragraph(f"<b>Description:</b> {_xml(desc)}", small))
            evidence = str(f.get("evidence") or "No evidence captured.")[:600]
            story.append(Paragraph(f"<b>Evidence:</b> {_xml(evidence)}", small))
            solution = str(f.get("solution") or "No remediation guidance recorded.")[:600]
            story.append(Paragraph(f"<b>Remediation:</b> {_xml(solution)}", small))
            cves = ", ".join(f.get("cve_ids") or []) or "None"
            cwes = ", ".join(f.get("cwe") or []) or "-"
            story.append(Paragraph(f"<b>CVEs:</b> {_xml(cves)} | <b>CWEs:</b> {_xml(cwes)}", small))
            story.append(Spacer(1, 0.06 * inch))

        story.append(Paragraph(f"CVE Inventory ({len(data.get('cves', []))})", h2))
        cves = data.get("cves", [])
        if cves:
            story.append(table(
                [["CVE", "CVSS", "Severity", "EPSS", "KEV", "Exploit", "Metasploit Module"]] + [
                    [_xml(str(c.get("cve_id", ""))), str(c.get("cvss_v3") or c.get("cvss_v2") or "-"),
                     _xml(str(c.get("cvss_severity") or "-")), str(c.get("epss_score") or "-"),
                     "Y" if c.get("kev_status") else "N", "Y" if c.get("exploit_available") else "N",
                     _xml(str(c.get("metasploit_module") or "-"))[:40]]
                    for c in cves[:300]
                ],
                widths=[0.9 * inch, 0.6 * inch, 0.7 * inch, 0.6 * inch, 0.4 * inch, 0.5 * inch, 1.9 * inch],
            ))

        story.append(Paragraph(f"Exploit Inventory ({len(data.get('exploits', []))})", h2))
        exploits = data.get("exploits", [])
        if exploits:
            story.append(table(
                [["Module", "CVE", "Source", "Rank", "Host", "Status"]] + [
                    [_xml(str(e.get("module_name", "")))[:60], _xml(str(e.get("cve", "-"))),
                     _xml(str(e.get("provider", "-"))), _xml(str(e.get("rank", "-"))),
                     _xml(str(e.get("host_ip") or "-")), _xml(str(e.get("status", "-")))]
                    for e in exploits[:200]
                ],
                widths=[2.6 * inch, 0.9 * inch, 0.8 * inch, 0.6 * inch, 1.1 * inch, 0.6 * inch],
            ))

        story.append(Paragraph(f"Scan Artifacts ({len(data.get('artifacts', []))})", h2))
        artifacts = data.get("artifacts", [])
        if artifacts:
            story.append(table(
                [["Stage", "Type", "Target", "Status", "File"]] + [
                    [_xml(str(a.get("stage_name", ""))), _xml(str(a.get("output_type", "-"))),
                     _xml(str(a.get("target", "-"))), _xml(str(a.get("status", "-"))),
                     _xml(str(a.get("artifact_path", "-")))]
                    for a in artifacts[:200]
                ],
                widths=[1.4 * inch, 1.0 * inch, 1.4 * inch, 0.8 * inch, 1.8 * inch],
            ))

    doc.build(story)
    return filepath


def _xml(text: str) -> str:
    return _xml_escape(str(text))


def _format_size(size: Optional[int]) -> str:
    if size is None:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"


def payload_to_json(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)
