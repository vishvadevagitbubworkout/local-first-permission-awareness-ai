"""Developer-defined file capability templates and resolution."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.task_plan import CapabilityTemplate, PlanStep, PlannerIntent, TaskPlan

_CANONICAL_OPERATIONS = {
    "LIST": "LIST",
    "LIST_FILES": "LIST",
    "READ": "READ",
    "READ_FILE": "READ",
    "USER_REQUESTED_READ_DOCUMENTS": "READ",
    "CREATE": "CREATE",
    "CREATE_FILE": "CREATE",
    "WRITE": "WRITE",
    "WRITE_FILE": "WRITE",
    "MOVE": "MOVE",
    "MOVE_FILE": "MOVE",
    "RENAME": "RENAME",
    "RENAME_FILE": "RENAME",
    "DELETE": "DELETE",
    "DELETE_FILE": "DELETE",
}

def canonical_operation(operation: str) -> str | None:
    if not isinstance(operation, str):
        return None
    return _CANONICAL_OPERATIONS.get(operation.strip().upper())

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

class ResourceType(str, Enum):
    FILE = "file"
    DIRECTORY = "directory"

class CapabilityTemplateDefinition(BaseModel):
    """Developer-defined description of an approved capability.

    This model stores the metadata for a requestable capability but contains no
    execution logic. M3.1 is intentionally a registry/data-definition layer.
    """

    model_config = ConfigDict(extra="forbid")

    capability_id: str = Field(..., min_length=1)
    agent: str = Field(..., min_length=1)
    operation: str = Field(..., min_length=1)
    resource_type: ResourceType
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: RiskLevel
    description: str = Field(..., min_length=1)

FILE_READ = CapabilityTemplateDefinition(
    capability_id="file.read",
    agent="file_manager",
    operation="READ",
    resource_type=ResourceType.FILE,
    parameters={"mode": "read"},
    risk_level=RiskLevel.LOW,
    description="Read a file resource without executing it.",
)

FILE_LIST = CapabilityTemplateDefinition(
    capability_id="file.list", agent="file_manager", operation="LIST",
    resource_type=ResourceType.FILE, parameters={"mode": "list"},
    risk_level=RiskLevel.LOW, description="List a bounded file resource.",
)

FILE_MOVE = CapabilityTemplateDefinition(
    capability_id="file.move", agent="file_manager", operation="MOVE",
    resource_type=ResourceType.FILE, parameters={"mode": "move"},
    risk_level=RiskLevel.MEDIUM, description="Move a file within an approved scope.",
)

FILE_RENAME = CapabilityTemplateDefinition(
    capability_id="file.rename", agent="file_manager", operation="RENAME",
    resource_type=ResourceType.FILE, parameters={"mode": "rename"},
    risk_level=RiskLevel.MEDIUM, description="Rename a file within an approved scope.",
)

FILE_CREATE = CapabilityTemplateDefinition(
    capability_id="file.create",
    agent="file_manager",
    operation="CREATE",
    resource_type=ResourceType.FILE,
    parameters={"mode": "create"},
    risk_level=RiskLevel.MEDIUM,
    description="Create a new file resource without executing filesystem commands.",
)

FILE_WRITE = CapabilityTemplateDefinition(
    capability_id="file.write",
    agent="file_manager",
    operation="WRITE",
    resource_type=ResourceType.FILE,
    parameters={"mode": "write"},
    risk_level=RiskLevel.MEDIUM,
    description="Write content to an existing file resource without executing it.",
)

FILE_DELETE = CapabilityTemplateDefinition(
    capability_id="file.delete",
    agent="file_manager",
    operation="DELETE",
    resource_type=ResourceType.FILE,
    parameters={"mode": "delete"},
    risk_level=RiskLevel.HIGH,
    description="Delete a file resource without executing filesystem commands.",
)

APPROVED_CAPABILITY_TEMPLATES: list[CapabilityTemplateDefinition] = [
    FILE_LIST,
    FILE_READ,
    FILE_MOVE,
    FILE_RENAME,
    FILE_CREATE,
    FILE_WRITE,
    FILE_DELETE,
]

APPROVED_CAPABILITY_TEMPLATE_MAP: dict[str, CapabilityTemplateDefinition] = {
    template.capability_id: template for template in APPROVED_CAPABILITY_TEMPLATES
}

class CapabilityRegistryError(ValueError):
    """Controlled registry error for missing, duplicate, or ambiguous capabilities."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")

class CapabilityRegistry:
    """Deterministic registry for developer-defined capability templates."""

    def __init__(
        self,
        templates: list[CapabilityTemplateDefinition] | None = None,
    ):
        self._templates: dict[str, CapabilityTemplateDefinition] = {}
        source_templates = list(templates) if templates is not None else list(APPROVED_CAPABILITY_TEMPLATES)
        for template in source_templates:
            self.register(template)

    def register(self, template: CapabilityTemplateDefinition) -> CapabilityTemplateDefinition:
        if not isinstance(template, CapabilityTemplateDefinition):
            raise TypeError("CapabilityRegistry.register expects a CapabilityTemplateDefinition.")

        capability_id = template.capability_id
        normalized_capability = capability_id.lower()
        if "llm" in normalized_capability or "capability" in normalized_capability:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "Capability IDs cannot be created dynamically from LLM-style or capability factory inputs.",
            )

        if capability_id in self._templates:
            raise CapabilityRegistryError(
                "DUPLICATE_CAPABILITY",
                f"Capability '{capability_id}' is already registered.",
            )

        self._templates[capability_id] = template.model_copy(deep=True)
        return self._templates[capability_id].model_copy(deep=True)

    def get(self, capability_id: str) -> CapabilityTemplateDefinition:
        if not isinstance(capability_id, str) or not capability_id.strip():
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "A capability ID must be a non-empty string.",
            )

        template = self._templates.get(capability_id)
        if template is None:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                f"Capability '{capability_id}' does not exist in the approved registry.",
            )
        return template.model_copy(deep=True)

    def has(self, capability_id: str) -> bool:
        return capability_id in self._templates

    def list(self) -> list[CapabilityTemplateDefinition]:
        return [template.model_copy(deep=True) for template in self._templates.values()]

_TEMPLATE_TO_CAPABILITY = {
    CapabilityTemplate.FILE_LIST: ("LIST", "file.list"),
    CapabilityTemplate.FILE_READ: ("READ", "file.read"),
    CapabilityTemplate.FILE_MOVE: ("MOVE", "file.move"),
    CapabilityTemplate.FILE_RENAME: ("RENAME", "file.rename"),
    CapabilityTemplate.FILE_CREATE: ("CREATE", "file.create"),
    CapabilityTemplate.FILE_WRITE: ("WRITE", "file.write"),
    CapabilityTemplate.FILE_DELETE: ("DELETE", "file.delete"),
}

class CapabilitySecurityValidator:
    """Fail-closed validation for resolved, developer-defined capabilities."""

    def __init__(self, registry: CapabilityRegistry | None = None):
        self.registry = registry or CapabilityRegistry()

    def validate(
        self,
        capability: CapabilityTemplateDefinition,
        *,
        step: PlanStep | None = None,
    ) -> CapabilityTemplateDefinition:
        if not isinstance(capability, CapabilityTemplateDefinition):
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The resolved value is not a capability template.",
            )

        canonical = self.registry.get(capability.capability_id)
        if capability != canonical:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The capability does not exactly match its registered developer-defined template.",
            )

        if step is not None:
            self._validate_step(step, canonical)

        return canonical

    @staticmethod
    def _validate_step(step: PlanStep, capability: CapabilityTemplateDefinition) -> None:
        if not isinstance(step, PlanStep):
            raise TypeError("CapabilitySecurityValidator.validate expects a PlanStep.")
        if step.intent == PlannerIntent.ASK_CLARIFICATION:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "A clarification step cannot produce an approved capability.",
            )
        if step.template is not None:
            template_contract = _TEMPLATE_TO_CAPABILITY.get(step.template)
            if template_contract is None:
                raise CapabilityRegistryError(
                    "CAPABILITY_NOT_FOUND",
                    "The planner-declared template has no registered M3 capability.",
                )
            expected_operation, expected_capability_id = template_contract
            declared_operation = canonical_operation(step.operation) or step.operation.upper()
            if (
                declared_operation != expected_operation
                or capability.capability_id != expected_capability_id
            ):
                raise CapabilityRegistryError(
                    "CAPABILITY_NOT_FOUND",
                    "The capability does not match the planner-declared template.",
                )
        normalized_step_operation = canonical_operation(step.operation) or step.operation.upper()
        if step.agent != capability.agent or normalized_step_operation != capability.operation.upper():
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The capability does not match the validated step agent and operation.",
            )
        if step.resource is not None and capability.resource_type.value != "file":
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The capability does not match the validated step resource type.",
            )
        if step.parameters != capability.parameters:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The capability parameters do not exactly match the registered template.",
            )

class CapabilityResolver:
    """Resolve validated planner intents to approved capability templates."""

    def __init__(self, registry: CapabilityRegistry | None = None):
        self.registry = registry or CapabilityRegistry()
        self.security_validator = CapabilitySecurityValidator(self.registry)

    @staticmethod
    def _normalize_operation(operation: str) -> str:
        if not isinstance(operation, str) or not operation.strip():
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "A valid operation string is required to resolve a capability.",
            )
        normalized = canonical_operation(operation)
        if normalized is None:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                f"Planner operation '{operation}' has no approved canonical mapping.",
            )
        return normalized

    def resolve(self, operation: str, *, resource: str | None = None, agent: str | None = None) -> object:
        normalized_operation = self._normalize_operation(operation)
        if normalized_operation in {"CLARIFY", "ASK_CLARIFICATION"}:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "Clarification steps do not resolve to an approved capability.",
            )

        matches = [
            template
            for template in self.registry.list()
            if template.operation.upper() == normalized_operation
        ]

        if agent is not None:
            matches = [template for template in matches if template.agent == agent]

        if resource is not None:
            resource_value = str(resource).strip()
            if resource_value:
                if resource_value.lower() in {"directory", "browser", "email"}:
                    raise CapabilityRegistryError(
                        "CAPABILITY_NOT_FOUND",
                        f"Resource type '{resource_value}' is not supported by the matching file capability.",
                    )
                matches = [
                    template for template in matches if template.resource_type.value == "file"
                ]

        if not matches:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                f"No approved capability matches operation '{operation}'.",
            )
        if len(matches) > 1:
            ids = ", ".join(sorted(template.capability_id for template in matches))
            raise CapabilityRegistryError(
                "AMBIGUOUS_CAPABILITY",
                f"Operation '{operation}' matches multiple approved capabilities: {ids}.",
            )

        return matches[0]

    def resolve_step(self, step: PlanStep):
        if not isinstance(step, PlanStep):
            raise TypeError("CapabilityResolver.resolve_step expects a PlanStep.")

        if step.intent == PlannerIntent.ASK_CLARIFICATION:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The clarification step is not an approved capability.",
            )

        capability = self.resolve(
            step.operation,
            resource=step.resource,
            agent=step.agent,
        )
        return self.security_validator.validate(capability, step=step)

    def resolve_validated_plan(
        self,
        task_plan: TaskPlan,
        intent_result: IntentCheckResult,
    ) -> list:
        from app.validation.intent import IntentCheckResult

        if not isinstance(task_plan, TaskPlan):
            raise TypeError("CapabilityResolver.resolve_validated_plan expects a TaskPlan.")
        if not isinstance(intent_result, IntentCheckResult):
            raise TypeError(
                "CapabilityResolver.resolve_validated_plan expects an IntentCheckResult."
            )
        if intent_result.task_id != task_plan.task_id:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "The intent result does not belong to the supplied TaskPlan.",
            )
        if not intent_result.consistent or intent_result.mismatched_steps:
            raise CapabilityRegistryError(
                "CAPABILITY_NOT_FOUND",
                "An inconsistent task plan cannot produce approved capabilities.",
            )

        return [self.resolve_step(step) for step in task_plan.steps]

__all__ = [
    'canonical_operation',
    'APPROVED_CAPABILITY_TEMPLATE_MAP',
    'APPROVED_CAPABILITY_TEMPLATES',
    'CapabilityTemplateDefinition',
    'FILE_CREATE',
    'FILE_DELETE',
    'FILE_LIST',
    'FILE_MOVE',
    'FILE_RENAME',
    'FILE_READ',
    'FILE_WRITE',
    'ResourceType',
    'RiskLevel',
    'CapabilityRegistry',
    'CapabilityRegistryError',
    'CapabilitySecurityValidator',
    'CapabilityResolver',
]
