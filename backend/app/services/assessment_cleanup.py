"""Cascade deletion of an assessment and everything attached to it.

Deleting an assessment removes its reports (rows + files on disk),
artifacts (rows + stage directories), packet captures (rows + capture
files), hosts, ports, services, vulnerabilities, CVEs, exploit runs,
and the scan row itself. The in-memory assessment record is removed
through the assessment manager as well.
"""

import shutil
from pathlib import Path
from typing import Optional

from loguru import logger
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.artifact_manager import artifact_manager

_DELETE_ORDER = [
    (
        "DELETE FROM exploit_runs WHERE host_id IN "
        "(SELECT id FROM hosts WHERE scan_id = :aid)",
        "exploit_runs",
    ),
    (
        "DELETE FROM exploits WHERE host_id IN "
        "(SELECT id FROM hosts WHERE scan_id = :aid)",
        "exploits",
    ),
    (
        "DELETE FROM cves WHERE vuln_id IN "
        "(SELECT id FROM vulnerabilities WHERE scan_id = :aid)",
        "cves",
    ),
    ("DELETE FROM vulnerabilities WHERE scan_id = :aid", "vulnerabilities"),
    (
        "DELETE FROM services WHERE port_id IN "
        "(SELECT id FROM ports WHERE host_id IN "
        "(SELECT id FROM hosts WHERE scan_id = :aid))",
        "services",
    ),
    (
        "DELETE FROM ports WHERE host_id IN "
        "(SELECT id FROM hosts WHERE scan_id = :aid)",
        "ports",
    ),
    ("DELETE FROM hosts WHERE scan_id = :aid", "hosts"),
    (
        "DELETE FROM packets WHERE capture_id IN "
        "(SELECT id FROM packet_captures WHERE scan_id = :aid)",
        "packets",
    ),
    (
        "DELETE FROM conversations WHERE capture_id IN "
        "(SELECT id FROM packet_captures WHERE scan_id = :aid)",
        "conversations",
    ),
    ("DELETE FROM packet_captures WHERE scan_id = :aid", "packet_captures"),
    ("DELETE FROM artifacts WHERE assessment_id = :aid", "artifacts"),
    ("DELETE FROM reports WHERE scan_id = :aid", "reports"),
    ("DELETE FROM scans WHERE id = :aid", "scans"),
]


async def delete_assessment_cascade(
    db: AsyncSession,
    assessment_id: str,
    artifact_base_dir: Optional[Path] = None,
) -> dict:
    """Delete an assessment and all associated data.

    Returns a dict of deleted-row counts per table. Idempotent: if the
    assessment has no persisted data, all counts are zero and the call
    still succeeds.

    Files referenced by the deleted rows (report files, packet capture
    files) are removed from disk when present, and the artifact stage
    directory for the assessment is removed when it exists.
    """
    base_dir = artifact_base_dir or artifact_manager.base_dir

    report_files = [
        row[0]
        for row in (
            await db.execute(
                text("SELECT filepath FROM reports WHERE scan_id = :aid"),
                {"aid": assessment_id},
            )
        ).fetchall()
        if row[0]
    ]
    capture_files = [
        row[0]
        for row in (
            await db.execute(
                text(
                    "SELECT filepath FROM packet_captures "
                    "WHERE scan_id = :aid"
                ),
                {"aid": assessment_id},
            )
        ).fetchall()
        if row[0]
    ]

    counts: dict[str, int] = {}
    for statement, table_name in _DELETE_ORDER:
        result = await db.execute(text(statement), {"aid": assessment_id})
        counts[table_name] = result.rowcount
    await db.commit()

    for filepath in report_files + capture_files:
        try:
            Path(filepath).unlink(missing_ok=True)
        except OSError as exc:
            logger.warning(
                "Failed to delete file {path}: {error}",
                path=filepath,
                error=str(exc),
            )

    sanitized = assessment_id.replace("/", "_").replace("\\", "_")
    assessment_dir = base_dir / f"assessment_{sanitized[:8]}"
    if assessment_dir.exists():
        shutil.rmtree(assessment_dir, ignore_errors=True)
        logger.info(
            "Deleted artifact directory: {path}",
            path=str(assessment_dir),
        )

    from app.services.assessment import assessment_manager

    assessment_manager.delete_assessment(assessment_id)

    logger.info(
        "Cascade deleted assessment {id}: {counts}",
        id=assessment_id,
        counts=counts,
    )
    return counts
