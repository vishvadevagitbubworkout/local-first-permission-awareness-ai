from typing import Any
from enum import Enum

from pydantic import BaseModel, Field


class PlannerIntent(str, Enum):
    LIST = "LIST"
    READ = "READ"
    MOVE = "MOVE"
    RENAME = "RENAME"
    CREATE = "CREATE"
    WRITE = "WRITE"
    DELETE = "DELETE"
    ASK_CLARIFICATION = "ASK_CLARIFICATION"


class CapabilityTemplate(str, Enum):
    FILE_LIST = "FILE_LIST"
    FILE_READ = "FILE_READ"
    FILE_MOVE = "FILE_MOVE"
    FILE_RENAME = "FILE_RENAME"
    FILE_CREATE = "FILE_CREATE"
    FILE_WRITE = "FILE_WRITE"
    FILE_DELETE = "FILE_DELETE"


class PlanStep(BaseModel):
    step_id: str
    agent: str
    operation: str
    resource: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    template: CapabilityTemplate | None = None
    intent: PlannerIntent | None = None
    opaque_file_refs: list[str] = Field(default_factory=list)
    description: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class TaskPlan(BaseModel):
    task_id: str
    original_request: str
    steps: list[PlanStep]
