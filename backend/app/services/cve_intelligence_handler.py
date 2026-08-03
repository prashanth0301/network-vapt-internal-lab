import uuid
from datetime import datetime, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.core.database import async_session_factory
from app.models.cve import CVE
from app.models.vulnerability import Vulnerability
from app.services.artifact_manager import artifact_manager
from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.risk_engine import risk_engine
from app.services.threat_intelligence_service import (
    enrich_vulnerability_cves,
    get_cve_by_vuln_and_id,
)


async def cve_intelligence_handler(
    assessment_id: str,
    target: str,
    parameters: Optional[dict] = None,
    tracker: Optional[ProgressTracker] = None,
) -> dict:
    logger.info(
        "CVE intelligence handler invoked: assessment={id}, target={target}",
        id=assessment_id,
        target=target,
    )

    if tracker:
        tracker.update_stage_status("cve_intelligence", StageStatus.RUNNING)
        tracker.update_stage_progress("cve_intelligence", 5.0)

    async with async_session_factory() as session:
        vulns_query = (
            select(Vulnerability)
            .where(Vulnerability.cve_ids.isnot(None))
            .options(joinedload(Vulnerability.host))
        )
        if assessment_id:
            try:
                vulns_query = vulns_query.where(Vulnerability.scan_id == uuid.UUID(assessment_id))
            except ValueError:
                vulns_query = vulns_query.where(Vulnerability.scan_id.is_(None))
        vulns_result = await session.execute(vulns_query)
        vulns_with_cves = list(vulns_result.scalars().all())

    if not vulns_with_cves:
        logger.warning("No vulnerabilities with CVEs found for enrichment")
        if tracker:
            tracker.update_stage_progress("cve_intelligence", 100.0)
            tracker.update_stage_status(
                "cve_intelligence", StageStatus.COMPLETED
            )
        return {
            "success": True,
            "summary": {"total_vulnerabilities": 0, "total_cves_enriched": 0},
        }

    if tracker:
        tracker.update_stage_progress("cve_intelligence", 10.0)

    stage_dir = artifact_manager.create_stage_directory(
        assessment_id, "cve_intelligence"
    )
    artifact_manager.save_metadata(stage_dir, {
        "assessment_id": assessment_id,
        "target": target,
        "parameters": parameters or {},
        "vulnerabilities_with_cves": len(vulns_with_cves),
        "started_at": datetime.now(timezone.utc).isoformat(),
    })

    total_enriched = 0
    total_cves = 0
    enrichment_results = []
    provider_errors = []
    start_time = datetime.now(timezone.utc)

    progress_per_vuln = 80.0 / len(vulns_with_cves) if vulns_with_cves else 0

    for idx, vuln in enumerate(vulns_with_cves):
        progress = 15.0 + (idx * progress_per_vuln)
        if tracker:
            tracker.update_stage_progress("cve_intelligence", progress)

        async with async_session_factory() as session:
            enriched = await enrich_vulnerability_cves(session, vuln)
            if enriched > 0:
                await session.commit()
                total_enriched += 1
                total_cves += enriched

            cve_records = []
            if vuln.cve_ids:
                for cve_id in vuln.cve_ids:
                    cve_record = await get_cve_by_vuln_and_id(session, vuln.id, cve_id)
                    if cve_record:
                        rs = risk_engine.calculate_for_cve(cve_record)
                        cve_record.remediation_priority = rs.priority
                        cve_records.append({
                            "cve_id": cve_id,
                            "priority": rs.priority,
                            "priority_score": rs.priority_score,
                        })
                await session.commit()

        vuln_host = vuln.host.ip_address if vuln.host else "unknown"
        enrichment_results.append({
            "vulnerability_id": str(vuln.id),
            "vulnerability_name": vuln.name,
            "host": vuln_host,
            "cves": vuln.cve_ids or [],
            "enriched": enriched,
            "cve_details": cve_records,
        })

    end_time = datetime.now(timezone.utc)
    duration = (end_time - start_time).total_seconds()

    artifact_manager.save_json(stage_dir, {
        "total_vulnerabilities_processed": len(vulns_with_cves),
        "total_enriched": total_enriched,
        "total_cves": total_cves,
        "duration_seconds": duration,
        "enrichment_results": enrichment_results,
        "provider_errors": provider_errors,
    }, "results.json")

    provider_dir = artifact_manager.create_stage_directory(
        assessment_id, "cve_intelligence/provider_responses"
    )

    async with async_session_factory() as session:
        await artifact_manager.store_metadata(
            session=session,
            assessment_id=assessment_id,
            stage_name="cve_intelligence",
            artifact_dir=stage_dir,
            status="completed",
            parameters=parameters or {},
            target=target,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
        )

    if tracker:
        tracker.update_stage_progress("cve_intelligence", 100.0)
        tracker.update_stage_status(
            "cve_intelligence", StageStatus.COMPLETED
        )

    total_vuln_count = len(vulns_with_cves)
    summary = {
        "total_vulnerabilities": total_vuln_count,
        "total_cves_enriched": total_cves,
        "total_enriched_vulnerabilities": total_enriched,
        "provider_errors": len(provider_errors),
    }

    logger.info(
        "CVE intelligence completed: enriched {enriched} CVEs across {vulns} vulnerabilities",
        enriched=total_cves,
        vulns=total_enriched,
    )

    return {"success": True, "summary": summary}
