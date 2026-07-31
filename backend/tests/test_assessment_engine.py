import pytest

from app.services.assessment.lifecycle import AssessmentStatus, StageStatus
from app.services.assessment.manager import AssessmentManager
from app.services.assessment.pipeline import AssessmentPipeline, PipelineStage
from app.services.assessment.progress_tracker import ProgressTracker


class TestAssessmentLifecycle:
    def test_assessment_status_transitions(self):
        assert AssessmentStatus.DRAFT.can_transition_to(AssessmentStatus.PENDING)
        assert not AssessmentStatus.DRAFT.can_transition_to(AssessmentStatus.COMPLETED)
        assert not AssessmentStatus.COMPLETED.can_transition_to(AssessmentStatus.RUNNING)
        assert AssessmentStatus.FAILED.can_transition_to(AssessmentStatus.PENDING)
        assert AssessmentStatus.CANCELLED.can_transition_to(AssessmentStatus.PENDING)
        assert AssessmentStatus.RUNNING.can_transition_to(AssessmentStatus.COMPLETED)
        assert AssessmentStatus.RUNNING.can_transition_to(AssessmentStatus.FAILED)

    def test_stage_status_transitions(self):
        assert StageStatus.PENDING.can_transition_to(StageStatus.RUNNING)
        assert StageStatus.PENDING.can_transition_to(StageStatus.SKIPPED)
        assert StageStatus.RUNNING.can_transition_to(StageStatus.COMPLETED)
        assert StageStatus.RUNNING.can_transition_to(StageStatus.FAILED)
        assert StageStatus.FAILED.can_transition_to(StageStatus.PENDING)
        assert not StageStatus.COMPLETED.can_transition_to(StageStatus.RUNNING)
        assert not StageStatus.SKIPPED.can_transition_to(StageStatus.RUNNING)

    def test_terminal_status(self):
        assert AssessmentStatus.COMPLETED.is_terminal
        assert AssessmentStatus.FAILED.is_terminal
        assert AssessmentStatus.CANCELLED.is_terminal
        assert not AssessmentStatus.RUNNING.is_terminal
        assert not AssessmentStatus.PENDING.is_terminal

    def test_active_status(self):
        assert AssessmentStatus.RUNNING.is_active
        assert AssessmentStatus.PENDING.is_active
        assert not AssessmentStatus.COMPLETED.is_active


class TestAssessmentPipeline:
    def test_pipeline_creation(self):
        pipeline = AssessmentPipeline()
        assert len(pipeline.stages) == 6
        assert pipeline.stages[0].name == "host_discovery"
        assert pipeline.stages[-1].name == "exploit_verification"

    def test_pipeline_total_weight(self):
        pipeline = AssessmentPipeline()
        assert pipeline.total_weight == 100.0

    def test_pipeline_execution_order(self):
        pipeline = AssessmentPipeline()
        ordered = pipeline.get_execution_order()
        names = [s.name for s in ordered]
        assert names == [
            "host_discovery", "port_scan", "service_intelligence",
            "vulnerability_assessment", "cve_intelligence", "exploit_verification",
        ]

    def test_duplicate_stage_raises_error(self):
        with pytest.raises(ValueError, match="Duplicate"):
            AssessmentPipeline(stages=[
                PipelineStage(name="test", display_name="Test", description="", weight=10.0, order=1),
                PipelineStage(name="test", display_name="Test 2", description="", weight=10.0, order=2),
            ])

    def test_unknown_dependency_raises_error(self):
        with pytest.raises(ValueError, match="unknown"):
            AssessmentPipeline(stages=[
                PipelineStage(name="a", display_name="A", description="", weight=10.0, order=1, depends_on=["nonexistent"]),
            ])

    def test_negative_weight_raises_error(self):
        with pytest.raises(ValueError, match="weight must be positive"):
            PipelineStage(name="test", display_name="Test", description="", weight=-1.0, order=1)

    def test_get_next_pending_stage(self):
        pipeline = AssessmentPipeline()
        statuses = {s.name: StageStatus.PENDING for s in pipeline.stages}
        next_stage = pipeline.get_next_pending_stage(statuses)
        assert next_stage is not None
        assert next_stage.name == "host_discovery"

    def test_get_next_pending_stage_waits_for_deps(self):
        pipeline = AssessmentPipeline()
        statuses = {s.name: StageStatus.PENDING for s in pipeline.stages}
        statuses["host_discovery"] = StageStatus.COMPLETED
        next_stage = pipeline.get_next_pending_stage(statuses)
        assert next_stage is not None
        assert next_stage.name == "port_scan"

    def test_get_next_pending_stage_all_complete(self):
        pipeline = AssessmentPipeline()
        statuses = {s.name: StageStatus.COMPLETED for s in pipeline.stages}
        next_stage = pipeline.get_next_pending_stage(statuses)
        assert next_stage is None


class TestProgressTracker:
    def test_tracker_initial_state(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        assert tracker.overall_progress == 0.0
        assert len(tracker.get_all_stages()) == 6

    def test_tracker_progress_increases(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.start()
        tracker.update_stage_status("host_discovery", StageStatus.COMPLETED)
        assert tracker.overall_progress == 10.0

    def test_tracker_all_stages_complete(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.start()
        for stage in pipeline.stages:
            tracker.update_stage_status(stage.name, StageStatus.COMPLETED)
        assert tracker.overall_progress == 100.0

    def test_tracker_skipped_stage(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.start()
        tracker.update_stage_status("host_discovery", StageStatus.SKIPPED)
        assert tracker.overall_progress == 10.0

    def test_tracker_to_dict_structure(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.start()
        data = tracker.to_dict()
        assert "overall_progress" in data
        assert "total_weight" in data
        assert "stages" in data
        assert len(data["stages"]) == 6

    def test_tracker_stage_error(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.update_stage_error("host_discovery", "Connection refused")
        sp = tracker.get_stage_progress("host_discovery")
        assert sp["error_message"] == "Connection refused"

    def test_tracker_update_summary(self):
        pipeline = AssessmentPipeline()
        tracker = ProgressTracker(pipeline)
        tracker.update_stage_summary("host_discovery", {"hosts_found": 5})
        sp = tracker.get_stage_progress("host_discovery")
        assert sp["summary"] == {"hosts_found": 5}


class TestAssessmentManager:
    def test_create_assessment(self):
        manager = AssessmentManager()
        record = manager.create_assessment(
            name="Test Assessment",
            scan_type="full_assessment",
            target="192.168.56.0/24",
        )
        assert record.id is not None
        assert record.name == "Test Assessment"
        assert record.status == AssessmentStatus.DRAFT

    def test_get_assessment(self):
        manager = AssessmentManager()
        created = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        fetched = manager.get_assessment(created.id)
        assert fetched.id == created.id

    def test_get_nonexistent_assessment_raises(self):
        manager = AssessmentManager()
        with pytest.raises(Exception):
            manager.get_assessment("nonexistent-id")

    def test_list_assessments(self):
        manager = AssessmentManager()
        manager.create_assessment(name="A1", scan_type="full_assessment", target="192.168.56.0/24")
        manager.create_assessment(name="A2", scan_type="host_discovery", target="192.168.56.20")
        all_items, total = manager.list_assessments()
        assert total == 2

    def test_list_assessments_filter_by_type(self):
        manager = AssessmentManager()
        manager.create_assessment(name="A1", scan_type="full_assessment", target="192.168.56.0/24")
        manager.create_assessment(name="A2", scan_type="host_discovery", target="192.168.56.20")
        filtered, total = manager.list_assessments(scan_type="host_discovery")
        assert total == 1

    def test_update_assessment_status(self):
        manager = AssessmentManager()
        record = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        manager.update_assessment_status(record.id, AssessmentStatus.PENDING)
        assert manager.get_assessment(record.id).status == AssessmentStatus.PENDING

    def test_invalid_transition_raises(self):
        manager = AssessmentManager()
        record = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        with pytest.raises(Exception):
            manager.update_assessment_status(record.id, AssessmentStatus.COMPLETED)

    def test_delete_assessment(self):
        manager = AssessmentManager()
        record = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        assert manager.delete_assessment(record.id) == True
        with pytest.raises(Exception):
            manager.get_assessment(record.id)

    def test_delete_nonexistent(self):
        manager = AssessmentManager()
        assert manager.delete_assessment("nonexistent") == False

    def test_get_assessment_progress(self):
        manager = AssessmentManager()
        record = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        progress = manager.get_assessment_progress(record.id)
        assert progress is not None
        assert progress["overall_progress"] == 0.0

    def test_get_assessment_status(self):
        manager = AssessmentManager()
        record = manager.create_assessment(name="Test", scan_type="full_assessment", target="192.168.56.0/24")
        status = manager.get_assessment_status(record.id)
        assert status["id"] == record.id
        assert "progress" in status
        assert "pipeline" in status

    def test_get_pipeline_stages(self):
        manager = AssessmentManager()
        stages = manager.get_pipeline_stages("full_assessment")
        assert len(stages) == 6
        assert stages[0]["name"] == "host_discovery"

    def test_assessment_manager_singleton(self):
        from app.services.assessment import assessment_manager
        assert assessment_manager is not None
        assert isinstance(assessment_manager, AssessmentManager)
