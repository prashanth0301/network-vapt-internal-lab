import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from loguru import logger
from sqlalchemy import func, or_, select

from app.core.database import async_session_factory
from app.models.scan import Scan
from app.services.assessment.exceptions import (
    AssessmentAlreadyRunningError,
    AssessmentInvalidTransitionError,
    AssessmentNotFoundError,
)
from app.services.assessment.lifecycle import AssessmentStatus, StageStatus
from app.services.assessment.pipeline import AssessmentPipeline, PipelineStage
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.assessment.runner import AssessmentRunner
from app.services.assessment.stage_manager import StageManager

FULL_ASSESSMENT_STAGES = [
    PipelineStage(
        name="host_discovery",
        display_name="Host Discovery",
        description="Discover live hosts using Nmap ping sweep",
        weight=10.0,
        order=1,
        depends_on=[],
    ),
    PipelineStage(
        name="port_scan",
        display_name="Port Scanning",
        description="Scan discovered hosts for open TCP/UDP ports",
        weight=25.0,
        order=2,
        depends_on=["host_discovery"],
    ),
    PipelineStage(
        name="service_intelligence",
        display_name="Service Enumeration",
        description="Enumerate service versions and banners",
        weight=15.0,
        order=3,
        depends_on=["port_scan"],
    ),
    PipelineStage(
        name="vulnerability_assessment",
        display_name="Vulnerability Assessment",
        description="Scan for vulnerabilities using OpenVAS/Nessus",
        weight=30.0,
        order=4,
        depends_on=["service_intelligence"],
    ),
    PipelineStage(
        name="cve_intelligence",
        display_name="CVE Intelligence",
        description="Correlate findings with CVE database",
        weight=10.0,
        order=5,
        depends_on=["vulnerability_assessment"],
    ),
    PipelineStage(
        name="exploit_verification",
        display_name="Exploit Verification",
        description="Verify exploits against discovered vulnerabilities",
        weight=10.0,
        order=6,
        depends_on=["cve_intelligence"],
    ),
]

HOST_DISCOVERY_STAGES = [
    PipelineStage(
        name="host_discovery",
        display_name="Host Discovery",
        description="Discover live hosts using Nmap ping sweep",
        weight=100.0,
        order=1,
        depends_on=[],
    ),
]

PORT_SCAN_STAGES = [
    PipelineStage(
        name="port_scan",
        display_name="Port Scanning",
        description="Scan targets for open TCP/UDP ports",
        weight=100.0,
        order=1,
        depends_on=[],
    ),
]

SERVICE_ENUM_STAGES = [
    PipelineStage(
        name="service_intelligence",
        display_name="Service Enumeration",
        description="Enumerate service versions and banners",
        weight=100.0,
        order=1,
        depends_on=[],
    ),
]

VULN_SCAN_STAGES = [
    PipelineStage(
        name="vulnerability_assessment",
        display_name="Vulnerability Assessment",
        description="Scan for vulnerabilities using OpenVAS/Nessus",
        weight=100.0,
        order=1,
        depends_on=[],
    ),
]


class AssessmentRecord:
    def __init__(
        self,
        assessment_id: str,
        name: str,
        scan_type: str,
        target: str,
        parameters: Optional[dict] = None,
    ):
        self.id = assessment_id
        self.name = name
        self.scan_type = scan_type
        self.target = target
        self.parameters = parameters or {}
        self.status = AssessmentStatus.DRAFT
        self.created_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status.value,
            "parameters": self.parameters,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
        }


class AssessmentManager:
    def __init__(self):
        self._assessments: dict[str, AssessmentRecord] = {}
        self._trackers: dict[str, ProgressTracker] = {}
        self._pipeline_cache: dict[str, AssessmentPipeline] = {}
        self._runners: dict[str, AssessmentRunner] = {}
        self._stage_manager = StageManager()

    @property
    def stage_manager(self) -> StageManager:
        return self._stage_manager

    def _get_pipeline(self, scan_type: str) -> AssessmentPipeline:
        if scan_type == "full_assessment":
            return AssessmentPipeline(stages=FULL_ASSESSMENT_STAGES)
        elif scan_type == "host_discovery":
            return AssessmentPipeline(stages=HOST_DISCOVERY_STAGES)
        elif scan_type == "port_scan":
            return AssessmentPipeline(stages=PORT_SCAN_STAGES)
        elif scan_type == "service_enum":
            return AssessmentPipeline(stages=SERVICE_ENUM_STAGES)
        elif scan_type == "vuln_scan":
            return AssessmentPipeline(stages=VULN_SCAN_STAGES)
        else:
            return AssessmentPipeline(stages=FULL_ASSESSMENT_STAGES)

    def create_assessment(
        self,
        name: str,
        scan_type: str,
        target: str,
        parameters: Optional[dict] = None,
    ) -> AssessmentRecord:
        assessment_id = str(uuid.uuid4())
        record = AssessmentRecord(
            assessment_id=assessment_id,
            name=name,
            scan_type=scan_type,
            target=target,
            parameters=parameters,
        )
        self._assessments[assessment_id] = record

        pipeline = self._get_pipeline(scan_type)
        self._pipeline_cache[assessment_id] = pipeline
        tracker = ProgressTracker(pipeline)
        self._trackers[assessment_id] = tracker

        logger.info(
            "Created assessment: {id} - {name} ({type})",
            id=assessment_id,
            name=name,
            type=scan_type,
        )

        return record

    def get_assessment(self, assessment_id: str) -> AssessmentRecord:
        record = self._assessments.get(assessment_id)
        if not record:
            raise AssessmentNotFoundError(assessment_id)
        return record

    def list_assessments(
        self,
        status: Optional[str] = None,
        scan_type: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[AssessmentRecord], int]:
        results = list(self._assessments.values())

        if status:
            results = [a for a in results if a.status.value == status]
        if scan_type:
            results = [a for a in results if a.scan_type == scan_type]

        results.sort(key=lambda a: a.created_at, reverse=True)
        total = len(results)

        start = (page - 1) * per_page
        end = start + per_page
        page_items = results[start:end]

        return page_items, total

    async def get_status_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for record in self._assessments.values():
            counts[record.status.value] = counts.get(record.status.value, 0) + 1
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(Scan.status, func.count(Scan.id)).group_by(Scan.status)
                )
                for status, count in result:
                    counts[status] = counts.get(status, 0) + count
        except Exception as exc:
            logger.error(
                "Failed to load persisted assessment statistics: {error}",
                error=f"{type(exc).__name__}: {exc}",
            )
        return counts

    @staticmethod
    def _record_from_scan(scan: Scan) -> AssessmentRecord:
        record = AssessmentRecord(
            assessment_id=str(scan.id),
            name=scan.name,
            scan_type=scan.scan_type,
            target=scan.target,
            parameters=scan.parameters or {},
        )
        try:
            record.status = AssessmentStatus(scan.status)
        except ValueError:
            record.status = AssessmentStatus.FAILED
        record.created_at = scan.created_at or datetime.now(timezone.utc)
        record.updated_at = scan.updated_at or record.created_at
        record.started_at = scan.started_at
        record.completed_at = scan.completed_at
        record.error_message = scan.error_message
        return record

    async def persist_assessment(self, assessment_id: str) -> None:
        record = self._assessments.get(assessment_id)
        if record is None:
            return
        values = dict(
            name=record.name,
            scan_type=record.scan_type,
            target=record.target,
            status=record.status.value,
            started_at=record.started_at,
            completed_at=record.completed_at,
            parameters=record.parameters,
            error_message=record.error_message,
            updated_at=record.updated_at,
        )
        try:
            async with async_session_factory() as session:
                scan = await session.get(Scan, uuid.UUID(assessment_id))
                if scan is None:
                    session.add(
                        Scan(
                            id=uuid.UUID(assessment_id),
                            created_at=record.created_at,
                            **values,
                        )
                    )
                else:
                    for key, value in values.items():
                        setattr(scan, key, value)
                await session.commit()
        except Exception as exc:
            logger.error(
                "Failed to persist assessment {id}: {error}",
                id=assessment_id,
                error=f"{type(exc).__name__}: {exc}",
            )

    async def remove_persisted(self, assessment_id: str) -> None:
        try:
            async with async_session_factory() as session:
                scan = await session.get(Scan, uuid.UUID(assessment_id))
                if scan is not None:
                    await session.delete(scan)
                    await session.commit()
        except Exception as exc:
            logger.error(
                "Failed to remove persisted assessment {id}: {error}",
                id=assessment_id,
                error=f"{type(exc).__name__}: {exc}",
            )

    async def list_assessments_persisted(
        self,
        status: Optional[str] = None,
        scan_type: Optional[str] = None,
        search: Optional[str] = None,
        target: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[AssessmentRecord], int]:
        results = list(self._assessments.values())
        try:
            async with async_session_factory() as session:
                query = select(Scan).order_by(Scan.created_at.desc())
                if status:
                    query = query.where(Scan.status == status)
                if scan_type:
                    query = query.where(Scan.scan_type == scan_type)
                if search:
                    pattern = f"%{search.strip()}%"
                    query = query.where(
                        or_(Scan.name.ilike(pattern), Scan.target.ilike(pattern))
                    )
                if target:
                    query = query.where(
                        Scan.target.ilike(f"%{target.strip()}%")
                    )
                if date_from:
                    query = query.where(Scan.created_at >= date_from)
                if date_to:
                    query = query.where(
                        Scan.created_at < date_to + timedelta(days=1)
                    )
                result = await session.execute(query)
                results.extend(
                    self._record_from_scan(row)
                    for row in result.scalars()
                    if str(row.id) not in self._assessments
                )
        except Exception as exc:
            logger.error(
                "Failed to load persisted assessments: {error}",
                error=f"{type(exc).__name__}: {exc}",
            )

        if status:
            results = [a for a in results if a.status.value == status]
        if scan_type:
            results = [a for a in results if a.scan_type == scan_type]
        if search:
            term = search.strip().lower()
            results = [
                a
                for a in results
                if term in a.name.lower() or term in a.target.lower()
            ]
        if target:
            term = target.strip().lower()
            results = [a for a in results if term in a.target.lower()]
        if date_from:
            results = [
                a
                for a in results
                if (a.created_at or datetime.min.replace(tzinfo=timezone.utc))
                >= date_from
            ]
        if date_to:
            end = date_to + timedelta(days=1)
            results = [
                a
                for a in results
                if (a.created_at or datetime.min.replace(tzinfo=timezone.utc)) < end
            ]

        results.sort(key=lambda a: a.created_at, reverse=True)
        total = len(results)

        start = (page - 1) * per_page
        end = start + per_page
        page_items = results[start:end]

        return page_items, total

    async def get_assessment_status_persisted(
        self, assessment_id: str
    ) -> Optional[dict]:
        try:
            return self.get_assessment_status(assessment_id)
        except AssessmentNotFoundError:
            pass
        try:
            async with async_session_factory() as session:
                scan = await session.get(Scan, uuid.UUID(assessment_id))
        except Exception as exc:
            logger.error(
                "Failed to load persisted assessment {id}: {error}",
                id=assessment_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            scan = None
        if scan is None:
            raise AssessmentNotFoundError(assessment_id)
        return self._record_from_scan(scan).to_dict()

    def update_assessment_status(
        self, assessment_id: str, new_status: AssessmentStatus
    ) -> AssessmentRecord:
        record = self.get_assessment(assessment_id)
        if not record.status.can_transition_to(new_status):
            raise AssessmentInvalidTransitionError(
                record.status.value, new_status.value
            )
        record.status = new_status
        record.updated_at = datetime.now(timezone.utc)

        if new_status == AssessmentStatus.RUNNING:
            record.started_at = datetime.now(timezone.utc)
        elif new_status.is_terminal:
            record.completed_at = datetime.now(timezone.utc)

        logger.info(
            "Assessment {id} status: {current} → {new}",
            id=assessment_id,
            current=record.status.value,
            new=new_status.value,
        )

        return record

    async def start_assessment(
        self, assessment_id: str
    ) -> AssessmentRecord:
        record = self.get_assessment(assessment_id)

        if record.status == AssessmentStatus.RUNNING:
            raise AssessmentAlreadyRunningError(assessment_id)

        if record.status in (AssessmentStatus.DRAFT, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
            self.update_assessment_status(assessment_id, AssessmentStatus.PENDING)

        self.update_assessment_status(assessment_id, AssessmentStatus.RUNNING)

        tracker = self._trackers.get(assessment_id)
        pipeline = self._pipeline_cache.get(assessment_id)

        if not tracker or not pipeline:
            pipeline = self._get_pipeline(record.scan_type)
            self._pipeline_cache[assessment_id] = pipeline
            tracker = ProgressTracker(pipeline)
            self._trackers[assessment_id] = tracker

        runner = AssessmentRunner(
            pipeline=pipeline,
            stage_manager=self._stage_manager,
        )
        self._runners[assessment_id] = runner

        logger.info(
            "Starting assessment pipeline: {id} ({type}) - target: {target}",
            id=assessment_id,
            type=record.scan_type,
            target=record.target,
        )

        asyncio.create_task(
            runner.run_assessment(
                assessment_id=assessment_id,
                target=record.target,
                tracker=tracker,
                parameters=record.parameters,
                status_callback=self._on_status_change,
            )
        )

        return record

    async def _on_status_change(
        self, assessment_id: str, status: AssessmentStatus
    ) -> None:
        record = self._assessments.get(assessment_id)
        if record and record.status == status:
            return
        try:
            self.update_assessment_status(assessment_id, status)
        except AssessmentInvalidTransitionError:
            logger.warning(
                "Invalid status transition for {id}: {status}",
                id=assessment_id,
                status=status.value,
            )
            return
        if status.is_terminal:
            await self.persist_assessment(assessment_id)

    def cancel_assessment(self, assessment_id: str) -> AssessmentRecord:
        record = self.get_assessment(assessment_id)

        if record.status != AssessmentStatus.RUNNING:
            raise AssessmentInvalidTransitionError(
                record.status.value, AssessmentStatus.CANCELLED.value
            )

        runner = self._runners.get(assessment_id)
        if runner:
            runner.cancel_assessment(assessment_id)
        self.update_assessment_status(assessment_id, AssessmentStatus.CANCELLED)

        tracker = self._trackers.get(assessment_id)
        if tracker:
            tracker.fail(error_message="Assessment cancelled by user")

        logger.info("Assessment cancelled: {id}", id=assessment_id)

        return record

    def delete_assessment(self, assessment_id: str) -> bool:
        if assessment_id in self._assessments:
            record = self._assessments[assessment_id]
            if record.status == AssessmentStatus.RUNNING:
                runner = self._runners.get(assessment_id)
                if runner:
                    runner.cancel_assessment(assessment_id)
            del self._assessments[assessment_id]
            self._trackers.pop(assessment_id, None)
            self._pipeline_cache.pop(assessment_id, None)
            self._runners.pop(assessment_id, None)
            logger.info("Deleted assessment: {id}", id=assessment_id)
            return True
        return False

    def get_assessment_progress(
        self, assessment_id: str
    ) -> Optional[dict]:
        tracker = self._trackers.get(assessment_id)
        if not tracker:
            return None
        return tracker.to_dict()

    def get_assessment_status(self, assessment_id: str) -> Optional[dict]:
        record = self.get_assessment(assessment_id)
        data = record.to_dict()
        progress = self.get_assessment_progress(assessment_id)
        if progress:
            data["progress"] = progress
        pipeline = self._pipeline_cache.get(assessment_id)
        if pipeline:
            data["pipeline"] = pipeline.to_dict()
        return data

    def get_pipeline_stages(self, scan_type: str) -> list[dict]:
        pipeline = self._get_pipeline(scan_type)
        return pipeline.to_dict()
