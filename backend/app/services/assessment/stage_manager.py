import asyncio
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

from loguru import logger

from app.services.assessment.lifecycle import StageStatus
from app.services.assessment.progress_tracker import ProgressTracker


StageHandler = Callable[..., Coroutine[Any, Any, dict]]


class StageManager:
    def __init__(self):
        self._handlers: dict[str, StageHandler] = {}

    def register_handler(self, stage_name: str, handler: StageHandler) -> None:
        self._handlers[stage_name] = handler
        logger.debug("Registered handler for stage: {stage}", stage=stage_name)

    def get_handler(self, stage_name: str) -> Optional[StageHandler]:
        return self._handlers.get(stage_name)

    def has_handler(self, stage_name: str) -> bool:
        return stage_name in self._handlers

    async def execute_stage(
        self,
        stage_name: str,
        tracker: ProgressTracker,
        assessment_id: str,
        target: str,
        parameters: Optional[dict] = None,
    ) -> bool:
        handler = self._handlers.get(stage_name)
        if not handler:
            logger.warning(
                "No handler registered for stage: {stage}. Skipping.",
                stage=stage_name,
            )
            tracker.update_stage_status(stage_name, StageStatus.SKIPPED)
            return True

        logger.info(
            "Executing stage: {stage} (assessment: {id})",
            stage=stage_name,
            id=assessment_id,
        )

        tracker.update_stage_status(stage_name, StageStatus.RUNNING)

        try:
            result = await handler(
                assessment_id=assessment_id,
                target=target,
                parameters=parameters or {},
                tracker=tracker,
            )

            success = result.get("success", False)

            if success:
                tracker.update_stage_status(stage_name, StageStatus.COMPLETED)
                tracker.update_stage_summary(stage_name, result.get("summary", {}))
                logger.info(
                    "Stage completed: {stage} (assessment: {id})",
                    stage=stage_name,
                    id=assessment_id,
                )
                return True
            else:
                error_msg = result.get("error", "Stage returned failure status")
                tracker.update_stage_status(stage_name, StageStatus.FAILED)
                tracker.update_stage_error(stage_name, error_msg)
                logger.error(
                    "Stage failed: {stage} (assessment: {id}) - {error}",
                    stage=stage_name,
                    id=assessment_id,
                    error=error_msg,
                )
                return False

        except asyncio.CancelledError:
            tracker.update_stage_status(stage_name, StageStatus.FAILED)
            tracker.update_stage_error(stage_name, "Stage execution was cancelled")
            logger.warning(
                "Stage cancelled: {stage} (assessment: {id})",
                stage=stage_name,
                id=assessment_id,
            )
            return False

        except Exception as e:
            error_msg = f"{type(e).__name__}: {str(e)}"
            tracker.update_stage_status(stage_name, StageStatus.FAILED)
            tracker.update_stage_error(stage_name, error_msg)
            logger.error(
                "Stage exception: {stage} (assessment: {id}) - {error}",
                stage=stage_name,
                id=assessment_id,
                error=error_msg,
            )
            return False
