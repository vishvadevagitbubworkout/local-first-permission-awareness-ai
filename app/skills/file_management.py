from __future__ import annotations

from app.core.task_plan import PlanStep, TaskPlan
from app.skills.file_executor import (
    FileSystemExecutor,
    PreparedFileAction,
)
from app.skills.registry import (
    PreparedSkillAction,
    SkillExecutionError,
    SkillExecutionContext,
    SkillResult,
)


class FileManagementSkill:
    """Expose the existing M6 file executor through the shared skill contract."""

    skill_id = "file_manager"

    def __init__(self, executor: FileSystemExecutor):
        self._executor = executor

    def prepare(self, task_plan: TaskPlan, step: PlanStep) -> PreparedSkillAction:
        action = self._executor.prepare(task_plan, step)
        return PreparedSkillAction(
            skill_id=self.skill_id,
            task_id=action.task_id,
            step_id=action.step_id,
            intent=action.intent,
            display_target=action.display_target,
            payload=action,
            audit_root=str(action.root),
            audit_target=str(action.target),
        )

    def execute(self, context: SkillExecutionContext) -> SkillResult:
        raise SkillExecutionError(
            "File actions must be dispatched by the mandatory execution gateway."
        )
