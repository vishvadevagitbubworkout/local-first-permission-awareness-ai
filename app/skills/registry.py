"""Skill contracts and developer-controlled skill registration."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from typing import Callable, Protocol

from app.core.task_plan import PlanStep, PlannerIntent, TaskPlan
from app.validation.intent import ValidatedIntentResult
from app.security.permissions import AuthorizationResult
from app.security.verification import VerifiedCapability

class SkillPreparationError(RuntimeError):
    """Raised when a skill cannot safely prepare the requested action."""

class SkillExecutionError(RuntimeError):
    """Raised when a skill cannot complete an authorized action."""

@dataclass(frozen=True)
class PreparedSkillAction:
    skill_id: str
    task_id: str
    step_id: str
    intent: PlannerIntent
    display_target: str
    payload: object
    audit_root: str | None = None
    audit_target: str | None = None

@dataclass(frozen=True)
class SkillExecutionContext:
    authorization: AuthorizationResult
    capability: VerifiedCapability
    task_plan: TaskPlan
    step: PlanStep
    intent_result: ValidatedIntentResult
    prepared: PreparedSkillAction
    after_capability_consumed: Callable[[], None] | None = None

@dataclass(frozen=True)
class SkillResult:
    summary: str
    output: str = ""

class Skill(Protocol):
    skill_id: str

    def prepare(
        self,
        task_plan: TaskPlan,
        step: PlanStep,
    ) -> PreparedSkillAction: ...

    def execute(self, context: SkillExecutionContext) -> SkillResult: ...

class SkillRegistryError(ValueError):
    """Raised when a skill is missing or registered more than once."""

class SkillRegistry:
    """Registry for skills explicitly registered by application code."""

    def __init__(self, skills: Iterable[Skill] = ()):
        self._skills: dict[str, Skill] = {}
        for skill in skills:
            self.register(skill)

    def register(self, skill: Skill) -> None:
        skill_id = getattr(skill, "skill_id", None)
        if not isinstance(skill_id, str) or not skill_id.strip():
            raise TypeError("Registered skills must provide a non-empty skill_id.")
        if not callable(getattr(skill, "prepare", None)) or not callable(
            getattr(skill, "execute", None)
        ):
            raise TypeError("Registered skills must implement prepare and execute.")
        if skill_id in self._skills:
            raise SkillRegistryError(f"Skill '{skill_id}' is already registered.")
        self._skills[skill_id] = skill

    def get(self, skill_id: str) -> Skill:
        skill = self._skills.get(skill_id)
        if skill is None:
            raise SkillRegistryError(
                f"Skill '{skill_id}' is not registered by the application."
            )
        return skill

    def list(self) -> tuple[str, ...]:
        return tuple(self._skills)
