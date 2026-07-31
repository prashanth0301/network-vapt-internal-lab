import asyncio
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from loguru import logger

from app.services.assessment.lifecycle import AssessmentStatus, StageStatus
from app.services.assessment.pipeline import AssessmentPipeline
from app.services.assessment.progress_tracker import ProgressTracker
from app.services.assessment.stage_manager import StageManager


class AssessmentRunner:
    def __init__(
        self,
        pipeline: AssessmentPipeline,
        stage_manager: StageManager,
    ):
        self._pipeline = pipeline
        self._stage_manager = stage_manager
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}

    async def run_assessment(
        self,
        assessment_id: str,
        target: str,
        tracker: ProgressTracker,
        parameters: Optional[dict] = None,
        status_callback=None,
    ) -> None:
        cancel_event = asyncio.Event()
        self._cancel_events[assessment_id] = cancel_event

        task = asyncio.create_task(
            self._execute_pipeline(
                assessment_id=assessment_id,
                target=target,
                tracker=tracker,
                parameters=parameters or {},
                cancel_event=cancel_event,
                status_callback=status_callback,
            )
        )
        self._active_tasks[assessment_id] = task

        try:
            await task
        except asyncio.CancelledError:
            logger.info(
                "Assessment runner cancelled: {id}",
                id=assessment_id,
            )
            if status_callback:
                await status_callback(assessment_id, AssessmentStatus.CANCELLED)
        except Exception as e:
            logger.error(
                "Assessment runner crashed: {id} - {error}",
                id=assessment_id,
                error=f"{type(e).__name__}: {e}",
            )
            if status_callback:
                await status_callback(assessment_id, AssessmentStatus.FAILED)
        finally:
            self._cleanup(assessment_id)

    async def _execute_pipeline(
        self,
        assessment_id: str,
        target: str,
        tracker: ProgressTracker,
        parameters: dict,
        cancel_event: asyncio.Event,
        status_callback=None,
    ) -> None:
        logger.info(
            "Assessment started: {id} (target: {target})",
            id=assessment_id,
            target=target,
        )

        tracker.start()
        execution_order = self._pipeline.get_execution_order()

        for stage in execution_order:
            if cancel_event.is_set():
                logger.warning(
                    "Assessment cancelled during stage: {stage} ({id})",
                    stage=stage.name,
                    id=assessment_id,
                )
                tracker.fail(error_message=f"Cancelled during stage '{stage.name}'")
                if status_callback:
                    await status_callback(assessment_id, AssessmentStatus.CANCELLED)
                return

            logger.info(
                "Assessment stage started: {stage} ({id})",
                stage=stage.display_name,
                id=assessment_id,
            )

            if not self._stage_manager.has_handler(stage.name):
                logger.info(
                    "No handler for stage '{stage}' - marking as completed",
                    stage=stage.name,
                )
                tracker.update_stage_status(stage.name, StageStatus.COMPLETED)
                logger.info(
                    "Assessment stage completed: {stage} ({id}) - no handler available",
                    stage=stage.display_name,
                    id=assessment_id,
                )
                continue

            success = await self._stage_manager.execute_stage(
                stage_name=stage.name,
                tracker=tracker,
                assessment_id=assessment_id,
                target=target,
                parameters=parameters.get(stage.name, parameters),
            )

            if success:
                logger.info(
                    "Assessment stage completed: {stage} ({id})",
                    stage=stage.display_name,
                    id=assessment_id,
                )
            elif stage.is_required:
                logger.error(
                    "Assessment stage failed: {stage} ({id}) - aborting pipeline",
                    stage=stage.display_name,
                    id=assessment_id,
                )
                tracker.fail(
                    error_message=f"Required stage '{stage.name}' failed"
                )
                if status_callback:
                    await status_callback(assessment_id, AssessmentStatus.FAILED)
                logger.info(
                    "Assessment failed: {id}",
                    id=assessment_id,
                )
                return
            else:
                logger.warning(
                    "Assessment stage failed (non-required): {stage} ({id}) - continuing",
                    stage=stage.display_name,
                    id=assessment_id,
                )

        tracker.complete()
        logger.info(
            "Assessment completed: {id}",
            id=assessment_id,
        )

        if status_callback:
            await status_callback(assessment_id, AssessmentStatus.COMPLETED)

    def cancel_assessment(self, assessment_id: str) -> bool:
        cancel_event = self._cancel_events.get(assessment_id)
        if cancel_event:
            cancel_event.set()
            logger.info(
                "Cancel event set for assessment: {id}",
                id=assessment_id,
            )

        task = self._active_tasks.get(assessment_id)
        if task and not task.done():
            task.cancel()
            logger.info(
                "Cancelled running task for assessment: {id}",
                id=assessment_id,
            )
            return True

        return False

    def is_running(self, assessment_id: str) -> bool:
        task = self._active_tasks.get(assessment_id)
        return task is not None and not task.done()

    def _cleanup(self, assessment_id: str) -> None:
        self._active_tasks.pop(assessment_id, None)
        self._cancel_events.pop(assessment_id, None)
