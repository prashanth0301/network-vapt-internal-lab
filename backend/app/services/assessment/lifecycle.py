from enum import Enum


class AssessmentStatus(str, Enum):
    DRAFT = "draft"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @classmethod
    def valid_transitions(cls, current: "AssessmentStatus") -> set["AssessmentStatus"]:
        transitions = {
            cls.DRAFT: {cls.PENDING},
            cls.PENDING: {cls.RUNNING, cls.CANCELLED},
            cls.RUNNING: {cls.COMPLETED, cls.FAILED, cls.CANCELLED},
            cls.COMPLETED: set(),
            cls.FAILED: {cls.PENDING},
            cls.CANCELLED: {cls.PENDING},
        }
        return transitions.get(current, set())

    def can_transition_to(self, target: "AssessmentStatus") -> bool:
        return target in self.valid_transitions(self)

    @property
    def is_terminal(self) -> bool:
        return self in (self.COMPLETED, self.FAILED, self.CANCELLED)

    @property
    def is_active(self) -> bool:
        return self in (self.PENDING, self.RUNNING)

    @property
    def is_startable(self) -> bool:
        return self in (self.DRAFT, self.FAILED, self.CANCELLED)


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

    @classmethod
    def valid_transitions(cls, current: "StageStatus") -> set["StageStatus"]:
        transitions = {
            cls.PENDING: {cls.RUNNING, cls.SKIPPED},
            cls.RUNNING: {cls.COMPLETED, cls.FAILED},
            cls.COMPLETED: set(),
            cls.FAILED: {cls.PENDING},
            cls.SKIPPED: set(),
        }
        return transitions.get(current, set())

    def can_transition_to(self, target: "StageStatus") -> bool:
        return target in self.valid_transitions(self)

    @property
    def is_terminal(self) -> bool:
        return self in (self.COMPLETED, self.FAILED, self.SKIPPED)

    @property
    def is_active(self) -> bool:
        return self == self.RUNNING
