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
        action = context.prepared
        if (
            action.skill_id != self.skill_id
            or action.task_id != context.task_plan.task_id
            or action.step_id != context.step.step_id
            or not isinstance(action.payload, PreparedFileAction)
        ):
            raise SkillExecutionError(
                "The prepared action does not match the file-management skill."
            )
        result = self._executor.execute(
            context.authorization,
            context.capability,
            context.task_plan,
            context.step,
            context.intent_result,
            action.payload,
            after_capability_consumed=context.after_capability_consumed,
        )
        return SkillResult(summary=result.summary, output=result.output)
