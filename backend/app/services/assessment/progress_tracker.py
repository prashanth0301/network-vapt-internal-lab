from datetime import datetime, timezone
from typing import Optional

from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.pipeline import AssessmentPipeline, PipelineStage


class StageProgress:
    def __init__(self, stage: PipelineStage):
        self.stage_name = stage.name
        self.display_name = stage.display_name
        self.weight = stage.weight
        self.status = StageStatus.PENDING
        self.progress: float = 0.0
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.summary: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "stage_name": self.stage_name,
            "display_name": self.display_name,
            "weight": self.weight,
            "status": self.status.value,
            "progress": round(self.progress, 1),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message,
            "summary": self.summary,
        }


class ProgressTracker:
    def __init__(self, pipeline: AssessmentPipeline):
        self.pipeline = pipeline
        self._stage_progress: dict[str, StageProgress] = {
            s.name: StageProgress(s) for s in pipeline.stages
        }
        self._overall_progress: float = 0.0
        self._started_at: Optional[datetime] = None
        self._completed_at: Optional[datetime] = None

    @property
    def overall_progress(self) -> float:
        return round(self._overall_progress, 1)

    @property
    def total_weight(self) -> float:
        return self.pipeline.total_weight

    def start(self):
        self._started_at = datetime.now(timezone.utc)
        self._overall_progress = 0.0

    def complete(self):
        self._completed_at = datetime.now(timezone.utc)
        self._overall_progress = 100.0
        for sp in self._stage_progress.values():
            if sp.status == StageStatus.RUNNING:
                sp.status = StageStatus.COMPLETED
                sp.progress = 100.0
                sp.completed_at = datetime.now(timezone.utc)

    def fail(self, error_message: Optional[str] = None):
        self._completed_at = datetime.now(timezone.utc)
        for sp in self._stage_progress.values():
            if sp.status == StageStatus.RUNNING:
                sp.status = StageStatus.FAILED
                sp.error_message = error_message

    def update_stage_status(
        self, stage_name: str, status: StageStatus
    ) -> None:
        sp = self._stage_progress.get(stage_name)
        if not sp:
            return

        now = datetime.now(timezone.utc)
        sp.status = status

        if status == StageStatus.RUNNING:
            sp.started_at = now
            sp.progress = 0.0
        elif status == StageStatus.COMPLETED:
            sp.progress = 100.0
            sp.completed_at = now
        elif status == StageStatus.FAILED:
            sp.completed_at = now
        elif status == StageStatus.SKIPPED:
            sp.progress = 100.0
            sp.completed_at = now

        self._recalculate_progress()

    def update_stage_error(self, stage_name: str, error: str) -> None:
        sp = self._stage_progress.get(stage_name)
        if sp:
            sp.error_message = error

    def update_stage_progress(self, stage_name: str, progress: float) -> None:
        sp = self._stage_progress.get(stage_name)
        if sp:
            sp.progress = min(progress, 100.0)

    def update_stage_summary(self, stage_name: str, summary: dict) -> None:
        sp = self._stage_progress.get(stage_name)
        if sp:
            sp.summary = summary

    def _recalculate_progress(self):
        completed_weight = 0.0
        for sp in self._stage_progress.values():
            if sp.status in (StageStatus.COMPLETED, StageStatus.SKIPPED):
                completed_weight += sp.weight
        total = self.total_weight
        self._overall_progress = (completed_weight / total * 100) if total > 0 else 0.0

    def get_stage_progress(self, stage_name: str) -> Optional[dict]:
        sp = self._stage_progress.get(stage_name)
        return sp.to_dict() if sp else None

    def get_all_stages(self) -> list[dict]:
        return [sp.to_dict() for sp in self._stage_progress.values()]

    def to_dict(self) -> dict:
        return {
            "overall_progress": self.overall_progress,
            "total_weight": self.total_weight,
            "stages": self.get_all_stages(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "completed_at": self._completed_at.isoformat() if self._completed_at else None,
        }
