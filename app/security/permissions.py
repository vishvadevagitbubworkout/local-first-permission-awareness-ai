"""Permission scopes, developer policy, and authorization decisions."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    field_validator,
    model_validator,
)

from app.security.capabilities import (
    APPROVED_CAPABILITY_TEMPLATE_MAP,
    CapabilityRegistry,
    CapabilityRegistryError,
    CapabilityResolver,
    CapabilitySecurityValidator,
    CapabilityTemplateDefinition,
    ResourceType,
    RiskLevel,
)
from app.validation.intent import IntentCheckResult, ValidatedIntentResult
from app.core.task_plan import PlannerIntent, TaskPlan

class _ImmutableMetadata(dict):
    def _blocked(self, *args, **kwargs):
        raise TypeError("permission metadata is immutable")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = _blocked

    def __deepcopy__(self, memo):
        return self

class PermissionDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK_APPROVAL = "ASK_APPROVAL"
    ASK_CLARIFICATION = "ASK_CLARIFICATION"

class PermissionScopeKind(str, Enum):
    RESOURCE = "resource"
    TASK = "task"

class PermissionScope(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    resource_type: ResourceType
    kind: PermissionScopeKind
    selector: str = Field(..., min_length=1)
    resource_id: str | None = None

    @field_validator("selector")
    @classmethod
    def validate_selector(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("scope selector must not be empty")
        if "*" in normalized:
            raise ValueError("wildcard scopes are not allowed")
        if normalized.startswith(("/", "\\")) or (len(normalized) > 1 and normalized[1] == ":"):
            raise ValueError("absolute scope selectors are not allowed")
        return normalized

    @field_validator("resource_id")
    @classmethod
    def validate_resource_id(cls, value: str | None) -> str | None:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized or "*" in normalized:
            raise ValueError("resource_id must be a non-empty, non-wildcard value")
        if normalized.startswith(("/", "\\")) or (len(normalized) > 1 and normalized[1] == ":"):
            raise ValueError("absolute resource IDs are not allowed")
        return normalized

class PermissionPolicy(BaseModel):
    """Developer-defined permission metadata for one approved capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    permission_id: str = Field(..., min_length=1)
    capability_id: str = Field(..., min_length=1)
    resource_type: ResourceType
    operation: str = Field(..., min_length=1)
    scope: PermissionScope
    risk_level: RiskLevel
    decision: PermissionDecision
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @field_validator("metadata", mode="after")
    @classmethod
    def freeze_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return _ImmutableMetadata(value)

    @field_validator("permission_id")
    @classmethod
    def validate_permission_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or normalized != value:
            raise ValueError("permission_id must be a non-empty identifier without surrounding whitespace")
        if not normalized.startswith("permission."):
            raise ValueError("permission_id must use the permission.<name> format")
        return normalized

    @model_validator(mode="after")
    def validate_against_capability(self) -> "PermissionPolicy":
        template = APPROVED_CAPABILITY_TEMPLATE_MAP.get(self.capability_id)
        if template is None:
            raise ValueError(
                f"capability_id '{self.capability_id}' is not an approved capability"
            )
        if self.resource_type != template.resource_type:
            raise ValueError("resource_type does not match the referenced capability")
        if self.operation.upper() != template.operation.upper():
            raise ValueError("operation does not match the referenced capability")
        if self.risk_level != template.risk_level:
            raise ValueError("risk_level does not match the referenced capability")
        if self.scope.resource_type != template.resource_type:
            raise ValueError("scope resource_type does not match the referenced capability")
        return self

class PermissionPolicyRegistry:
    """Controlled collection of developer-defined permission policies."""

    def __init__(self, policies: list[PermissionPolicy] | None = None):
        self._policies: dict[str, PermissionPolicy] = {}
        source = list(policies) if policies is not None else list(APPROVED_PERMISSION_POLICIES)
        for policy in source:
            self.register(policy)

    def register(self, policy: PermissionPolicy) -> PermissionPolicy:
        if not isinstance(policy, PermissionPolicy):
            raise TypeError("PermissionPolicyRegistry.register expects a PermissionPolicy.")
        if policy.permission_id in self._policies:
            raise ValueError(
                f"DUPLICATE_PERMISSION: policy '{policy.permission_id}' is already registered"
            )
        self._policies[policy.permission_id] = policy.model_copy(deep=True)
        return policy.model_copy(deep=True)

    def get(self, permission_id: str) -> PermissionPolicy:
        policy = self._policies.get(permission_id)
        if policy is None:
            raise ValueError(f"PERMISSION_NOT_FOUND: policy '{permission_id}' is not registered")
        return policy.model_copy(deep=True)

    def list(self) -> list[PermissionPolicy]:
        return [policy.model_copy(deep=True) for policy in self._policies.values()]

APPROVED_PERMISSION_POLICIES: tuple[PermissionPolicy, ...] = (
    PermissionPolicy(permission_id="permission.file.list", capability_id="file.list", resource_type=ResourceType.FILE, operation="LIST", scope=PermissionScope(resource_type=ResourceType.FILE, kind=PermissionScopeKind.TASK, selector="current_task.resource"), risk_level=RiskLevel.LOW, decision=PermissionDecision.ALLOW, metadata={"source": "developer", "stage": "M4.2"}),
    PermissionPolicy(
        permission_id="permission.file.read",
        capability_id="file.read",
        resource_type=ResourceType.FILE,
        operation="READ",
        scope=PermissionScope(
            resource_type=ResourceType.FILE,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
        ),
        risk_level=RiskLevel.LOW,
        decision=PermissionDecision.ALLOW,
        metadata={"source": "developer", "stage": "M4.1"},
    ),
    PermissionPolicy(
        permission_id="permission.file.create",
        capability_id="file.create",
        resource_type=ResourceType.FILE,
        operation="CREATE",
        scope=PermissionScope(
            resource_type=ResourceType.FILE,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
        ),
        risk_level=RiskLevel.MEDIUM,
        decision=PermissionDecision.ASK_APPROVAL,
        metadata={"source": "developer", "stage": "M4.1"},
    ),
    PermissionPolicy(
        permission_id="permission.file.write",
        capability_id="file.write",
        resource_type=ResourceType.FILE,
        operation="WRITE",
        scope=PermissionScope(
            resource_type=ResourceType.FILE,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
        ),
        risk_level=RiskLevel.MEDIUM,
        decision=PermissionDecision.ASK_APPROVAL,
        metadata={"source": "developer", "stage": "M4.1"},
    ),
    PermissionPolicy(
        permission_id="permission.file.delete",
        capability_id="file.delete",
        resource_type=ResourceType.FILE,
        operation="DELETE",
        scope=PermissionScope(
            resource_type=ResourceType.FILE,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
        ),
        risk_level=RiskLevel.HIGH,
        decision=PermissionDecision.ASK_APPROVAL,
        metadata={"source": "developer", "stage": "M4.1"},
    ),
    PermissionPolicy(permission_id="permission.file.move", capability_id="file.move", resource_type=ResourceType.FILE, operation="MOVE", scope=PermissionScope(resource_type=ResourceType.FILE, kind=PermissionScopeKind.TASK, selector="current_task.resource"), risk_level=RiskLevel.MEDIUM, decision=PermissionDecision.ASK_APPROVAL, metadata={"source": "developer", "stage": "M4.2"}),
    PermissionPolicy(permission_id="permission.file.rename", capability_id="file.rename", resource_type=ResourceType.FILE, operation="RENAME", scope=PermissionScope(resource_type=ResourceType.FILE, kind=PermissionScopeKind.TASK, selector="current_task.resource"), risk_level=RiskLevel.MEDIUM, decision=PermissionDecision.ASK_APPROVAL, metadata={"source": "developer", "stage": "M4.2"}),
)

class PermissionEvaluator:
    """Deterministically evaluate an approved capability against policy."""

    def __init__(
        self,
        policy_registry: PermissionPolicyRegistry | None = None,
        capability_registry: CapabilityRegistry | None = None,
    ):
        self.policy_registry = policy_registry or PermissionPolicyRegistry()
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.capability_validator = CapabilitySecurityValidator(self.capability_registry)

    def evaluate(
        self,
        capability: CapabilityTemplateDefinition,
        *,
        agent: str,
        operation: str,
        resource_type,
        scope: PermissionScope | None,
        parameters: dict | None = None,
        resource: str | None = None,
    ) -> PermissionDecision:
        """Return ALLOW only when every authorization input matches policy."""
        try:
            canonical = self.capability_validator.validate(capability)
            matching_policies = [
                policy
                for policy in self.policy_registry.list()
                if policy.capability_id == canonical.capability_id
            ]
            if len(matching_policies) != 1:
                return PermissionDecision.DENY
            policy = matching_policies[0]
            requested_parameters = parameters if parameters is not None else {}

            if not isinstance(agent, str) or agent != canonical.agent:
                return PermissionDecision.DENY
            if not isinstance(operation, str) or operation.upper() != canonical.operation.upper():
                return PermissionDecision.DENY
            if resource_type != canonical.resource_type:
                return PermissionDecision.DENY
            if scope is None or not isinstance(scope, PermissionScope):
                return PermissionDecision.DENY
            if (
                scope.resource_type != policy.scope.resource_type
                or scope.kind != policy.scope.kind
                or scope.selector != policy.scope.selector
            ):
                return PermissionDecision.DENY
            if scope.resource_id is None or not isinstance(scope.resource_id, str):
                return PermissionDecision.DENY
            if resource is not None and scope.resource_id != resource:
                return PermissionDecision.DENY
            if (
                policy.scope.resource_id is not None
                and scope.resource_id != policy.scope.resource_id
            ):
                return PermissionDecision.DENY
            if requested_parameters != canonical.parameters:
                return PermissionDecision.DENY
            if policy.operation.upper() != canonical.operation.upper():
                return PermissionDecision.DENY
            if policy.resource_type != canonical.resource_type:
                return PermissionDecision.DENY
            if policy.risk_level != canonical.risk_level:
                return PermissionDecision.DENY

            return policy.decision
        except (TypeError, ValueError, AttributeError):
            return PermissionDecision.DENY

_M4_AUTHORIZATION_TOKEN = object()

_APPROVAL_REQUIRED_INTENTS = {
    PlannerIntent.CREATE,
    PlannerIntent.WRITE,
    PlannerIntent.MOVE,
    PlannerIntent.RENAME,
    PlannerIntent.DELETE,
}

class AuthorizationResult(BaseModel):
    """Immutable, task- and step-bound result produced by M4.3."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    task_id: str | None
    step_id: str | None
    capability_id: str | None
    decision: PermissionDecision
    scope: PermissionScope | None
    reason: str = Field(..., min_length=1)
    _integrity_token: object | None = PrivateAttr(default=None)

    def is_integrity_valid(self) -> bool:
        return getattr(self, "_integrity_token", None) is _M4_AUTHORIZATION_TOKEN

    def model_copy(self, *, update=None, deep=False):
        if update:
            raise TypeError("AuthorizationResult cannot be retagged after authorization.")
        return super().model_copy(update=None, deep=deep)

    def is_bound_to(self, task_id: str, step_id: str) -> bool:
        return self.task_id == task_id and self.step_id == step_id

class TaskAuthorizationManager:
    """Bind M3/M4 decisions to the validated task and step that requested them."""

    def __init__(
        self,
        resolver: CapabilityResolver | None = None,
        evaluator: PermissionEvaluator | None = None,
    ):
        self.resolver = resolver or CapabilityResolver()
        self.evaluator = evaluator or PermissionEvaluator(
            capability_registry=self.resolver.registry,
        )

    def authorize_step(
        self,
        task_plan: TaskPlan,
        intent_result: IntentCheckResult,
        step_id: str,
        *,
        scope: PermissionScope | None,
    ) -> AuthorizationResult:
        task_id = task_plan.task_id if isinstance(task_plan, TaskPlan) else None
        if not task_id or not isinstance(step_id, str) or not step_id.strip():
            return self._deny(task_id, step_id, scope, "Missing task or step identity.")
        step = next((candidate for candidate in task_plan.steps if candidate.step_id == step_id), None)
        if step is not None and step.intent == PlannerIntent.ASK_CLARIFICATION:
            reason = step.parameters.get(
                "reason",
                "The task needs a clearer target or action before authorization.",
            )
            return self._decision_result(
                task_id,
                step_id,
                None,
                PermissionDecision.ASK_CLARIFICATION,
                str(reason),
            )
        if not isinstance(intent_result, ValidatedIntentResult) or not intent_result.is_m2_validated():
            return self._deny(task_id, step_id, scope, "Missing validated M2 intent result.")
        if intent_result.task_id != task_id:
            return self._deny(task_id, step_id, scope, "The M2 task identity does not match the plan.")
        if not intent_result.is_bound_to_plan(task_plan):
            return self._deny(task_id, step_id, scope, "The M2 result does not match the validated task plan.")
        if not intent_result.consistent or step_id in intent_result.mismatched_steps:
            return self._deny(task_id, step_id, scope, "M2 did not validate this task step.")
        if scope is None or not isinstance(scope, PermissionScope):
            return self._deny(task_id, step_id, scope, "A valid authorization scope is required.")

        if step is None:
            return self._deny(task_id, step_id, scope, "The step is not part of the validated task.")
        if step.intent is None:
            return self._deny(task_id, step_id, scope, "The step has no validated planner intent.")
        if scope.resource_type.value != "file" or scope.resource_id != step.resource:
            return self._deny(task_id, step_id, scope, "The authorization scope does not match the task step resource.")

        try:
            capability = self.resolver.resolve_step(step)
            decision = self.evaluator.evaluate(
                capability,
                agent=step.agent,
                operation=capability.operation,
                resource_type=capability.resource_type,
                scope=scope,
                parameters=step.parameters,
                resource=step.resource,
            )
        except (CapabilityRegistryError, TypeError, ValueError, AttributeError) as error:
            return self._deny(
                task_id,
                step_id,
                scope,
                f"M3 resolution or M4 evaluation failed: {error}",
            )

        if (
            decision == PermissionDecision.ALLOW
            and step.intent in _APPROVAL_REQUIRED_INTENTS
        ):
            decision = PermissionDecision.ASK_APPROVAL
        if decision in {PermissionDecision.ALLOW, PermissionDecision.ASK_APPROVAL}:
            reason = (
                "The read-only capability is permitted by developer policy."
                if decision == PermissionDecision.ALLOW
                else "The capability is permitted only after explicit human approval."
            )
            return self._decision_result(
                task_id,
                step_id,
                capability.capability_id,
                decision,
                reason,
                scope,
            )
        return self._deny(task_id, step_id, scope, "The capability is not permitted by the developer policy.")

    def resolve_approval(
        self,
        authorization: AuthorizationResult,
        task_plan: TaskPlan,
        step_id: str,
        *,
        approved: bool,
    ) -> AuthorizationResult:
        if (
            not isinstance(authorization, AuthorizationResult)
            or not authorization.is_integrity_valid()
            or authorization.decision != PermissionDecision.ASK_APPROVAL
            or not isinstance(task_plan, TaskPlan)
            or authorization.task_id != task_plan.task_id
            or authorization.step_id != step_id
            or not isinstance(approved, bool)
        ):
            return self._deny(
                getattr(task_plan, "task_id", None),
                step_id,
                getattr(authorization, "scope", None),
                "A valid M4 approval request and explicit boolean decision are required.",
            )
        step = next(
            (candidate for candidate in task_plan.steps if candidate.step_id == step_id),
            None,
        )
        if (
            step is None
            or authorization.scope is None
            or authorization.scope.resource_id != step.resource
            or authorization.capability_id is None
        ):
            return self._deny(
                task_plan.task_id,
                step_id,
                authorization.scope,
                "The approval request no longer matches its authorized task step.",
            )
        if not approved:
            return self._deny(
                task_plan.task_id,
                step_id,
                authorization.scope,
                "The user declined the requested approval.",
            )
        return self._decision_result(
            task_plan.task_id,
            step_id,
            authorization.capability_id,
            PermissionDecision.ALLOW,
            "The exact prepared file action was explicitly approved by the user.",
            authorization.scope,
        )

    def authorize_plan(
        self,
        task_plan: TaskPlan,
        intent_result: IntentCheckResult,
        scopes: dict[str, PermissionScope | None],
    ) -> list[AuthorizationResult]:
        if not isinstance(task_plan, TaskPlan):
            return [self._deny(None, None, None, "Missing validated TaskPlan.")]
        return [
            self.authorize_step(
                task_plan,
                intent_result,
                step.step_id,
                scope=scopes.get(step.step_id),
            )
            for step in task_plan.steps
        ]

    @staticmethod
    def _deny(
        task_id: str | None,
        step_id: str | None,
        scope: PermissionScope | None,
        reason: str,
    ) -> AuthorizationResult:
        return TaskAuthorizationManager._decision_result(
            task_id,
            step_id if isinstance(step_id, str) else None,
            None,
            PermissionDecision.DENY,
            reason,
            scope,
        )

    @staticmethod
    def _decision_result(
        task_id: str | None,
        step_id: str | None,
        capability_id: str | None,
        decision: PermissionDecision,
        reason: str,
        scope: PermissionScope | None = None,
    ) -> AuthorizationResult:
        result = AuthorizationResult(
            task_id=task_id,
            step_id=step_id,
            capability_id=capability_id,
            decision=decision,
            scope=scope,
            reason=reason,
        )
        result._integrity_token = _M4_AUTHORIZATION_TOKEN
        return result

__all__ = [
    'APPROVED_PERMISSION_POLICIES',
    'PermissionDecision',
    'PermissionPolicy',
    'PermissionPolicyRegistry',
    'PermissionScope',
    'PermissionScopeKind',
    'PermissionEvaluator',
    'AuthorizationResult',
    'TaskAuthorizationManager',
]
