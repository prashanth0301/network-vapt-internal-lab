from app.core.exceptions import VAPTException


class AssessmentException(VAPTException):
    status_code = 400
    error_code = "ASSESSMENT_ERROR"


class AssessmentNotFoundError(AssessmentException):
    status_code = 404
    error_code = "ASSESSMENT_NOT_FOUND"

    def __init__(self, assessment_id: str):
        super().__init__(
            message=f"Assessment '{assessment_id}' not found",
            error_code="ASSESSMENT_NOT_FOUND",
        )


class AssessmentInvalidTransitionError(AssessmentException):
    status_code = 400
    error_code = "ASSESSMENT_INVALID_TRANSITION"

    def __init__(self, current: str, target: str):
        super().__init__(
            message=f"Cannot transition assessment from '{current}' to '{target}'",
            error_code="ASSESSMENT_INVALID_TRANSITION",
            details={"current_status": current, "target_status": target},
        )


class AssessmentAlreadyRunningError(AssessmentException):
    status_code = 409
    error_code = "ASSESSMENT_ALREADY_RUNNING"

    def __init__(self, assessment_id: str):
        super().__init__(
            message=f"Assessment '{assessment_id}' is already running",
            error_code="ASSESSMENT_ALREADY_RUNNING",
        )


class AssessmentStageError(AssessmentException):
    status_code = 500
    error_code = "ASSESSMENT_STAGE_ERROR"

    def __init__(self, stage: str, message: str):
        super().__init__(
            message=f"Stage '{stage}' failed: {message}",
            error_code="ASSESSMENT_STAGE_ERROR",
            details={"stage": stage},
        )


class PipelineConfigurationError(AssessmentException):
    status_code = 500
    error_code = "PIPELINE_CONFIG_ERROR"

    def __init__(self, message: str):
        super().__init__(
            message=f"Pipeline configuration error: {message}",
            error_code="PIPELINE_CONFIG_ERROR",
        )
