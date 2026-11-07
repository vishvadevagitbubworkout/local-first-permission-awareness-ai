from __future__ import annotations

from pathlib import Path

from app.core.task_plan import PlannerIntent, PlanStep, TaskPlan
from app.security.approval import (
    ActionBinding,
    ApprovalEvidence,
    ApprovalManager,
    build_action_binding,
)
from app.security.audit import AuditTrail
from app.security.capabilities import CapabilityResolver
from app.security.lifecycle import CapabilityLifecycleError, CapabilityLifecycleStore
from app.security.permissions import AuthorizationResult, PermissionDecision
from app.security.tokens import AuthenticatedCapability
from app.security.verification import (
    CapabilityVerificationError,
    CapabilityVerifier,
    VerifiedCapability,
)
from app.skills.file_executor import (
    FileActionResult,
    FileSystemExecutor,
    M6ExecutionError,
    PreparedFileAction,
    _GATEWAY_EXECUTION_TOKEN,
)
from app.skills.registry import PreparedSkillAction
from app.storage.local_store import LocalAutomationStore, LocalStoreError
from app.validation.intent import ValidatedIntentResult


class ExecutionGatewayError(M6ExecutionError):
    """Raised when an operation cannot pass mandatory gateway enforcement."""


class ExecutionGateway:
    """Enforce M2-M5 authorization before dispatching supported file reads."""

    def __init__(
        self,
        *,
        executor: FileSystemExecutor,
        verifier: CapabilityVerifier,
        lifecycle: CapabilityLifecycleStore,
        store: LocalAutomationStore,
        audit_trail: AuditTrail,
        approval_manager: ApprovalManager,
        resolver: CapabilityResolver | None = None,
    ):
        self._executor = executor
        self._verifier = verifier
        self._lifecycle = lifecycle
        self._store = store
        self._audit = audit_trail
        self._approvals = approval_manager
        self._resolver = resolver or CapabilityResolver()

    def execute(
        self,
        *,
        agent_id: str,
        task_id: str,
        subtask_id: str,
        authorization: AuthorizationResult,
        capability: AuthenticatedCapability | VerifiedCapability | dict,
        task_plan: TaskPlan,
        step: PlanStep,
        intent_result: ValidatedIntentResult,
        prepared: PreparedSkillAction,
        execution_id: str,
        principal_id: str | None = None,
        approval_evidence: ApprovalEvidence | dict | None = None,
    ) -> FileActionResult:
        scope = (
            self._audit.safe_scope(
                authorization.scope,
                intent=step.operation,
                root=prepared.audit_root,
                target=prepared.audit_target,
            )
            if isinstance(authorization, AuthorizationResult)
            else None
        )
        try:
            if step.intent in {
                PlannerIntent.CREATE,
                PlannerIntent.WRITE,
                PlannerIntent.MOVE,
                PlannerIntent.RENAME,
                PlannerIntent.DELETE,
            }:
                if principal_id is None:
                    raise ValueError("A trusted principal identity is required for approval.")
                binding = build_action_binding(
                    principal_id=principal_id,
                    capability_id=authorization.capability_id or "",
                    task_plan=task_plan,
                    step=step,
                    prepared=prepared,
                )
                self._approvals.verify(
                    approval_evidence,
                    expected_binding=binding,
                    principal_id=principal_id,
                )
            verified, file_action = self._authorize(
                agent_id=agent_id,
                task_id=task_id,
                subtask_id=subtask_id,
                authorization=authorization,
                capability=capability,
                task_plan=task_plan,
                step=step,
                intent_result=intent_result,
                prepared=prepared,
            )
        except (
            CapabilityVerificationError,
            TypeError,
            ValueError,
            AttributeError,
            LocalStoreError,
            OSError,
        ) as error:
            self._record(
                "EXECUTION_GATEWAY_DENIED",
                execution_id=execution_id,
                task_plan=task_plan,
                step=step,
                scope=scope,
                decision=PermissionDecision.DENY.value,
                execution_result="NOT_STARTED",
                failure_reason=type(error).__name__,
            )
            raise ExecutionGatewayError(
                f"Execution gateway denied the action: {error}"
            ) from error

        self._record(
            "EXECUTION_GATEWAY_ACCEPTED",
            execution_id=execution_id,
            task_plan=task_plan,
            step=step,
            scope=scope,
            capability_id=verified.claims.capability_id,
            decision=PermissionDecision.ALLOW.value,
            token_verification="VERIFIED",
            execution_result="PENDING",
        )
        self._store.start_gateway_execution(
            execution_id=execution_id,
            task_id=task_plan.task_id,
            step_id=step.step_id,
            capability_id=verified.claims.capability_id,
        )

        try:
            result = self._executor.execute(
                authorization,
                verified,
                task_plan,
                step,
                intent_result,
                file_action,
                _gateway_token=_GATEWAY_EXECUTION_TOKEN,
            )
        except (
            M6ExecutionError,
            CapabilityLifecycleError,
            LocalStoreError,
            OSError,
        ) as error:
            self._finish_if_pending(execution_id, "FAILED", type(error).__name__)
            self._record(
                "EXECUTION_GATEWAY_FAILED",
                execution_id=execution_id,
                task_plan=task_plan,
                step=step,
                scope=scope,
                capability_id=verified.claims.capability_id,
                decision="ERROR",
                token_verification="VERIFIED",
                execution_result="FAILED",
                failure_reason=type(error).__name__,
            )
            raise ExecutionGatewayError(
                f"Execution gateway adapter failed: {error}"
            ) from error

        self._store.finish_gateway_execution(
            execution_id=execution_id,
            status="SUCCEEDED",
        )
        self._record(
            "EXECUTION_GATEWAY_SUCCEEDED",
            execution_id=execution_id,
            task_plan=task_plan,
            step=step,
            scope=scope,
            capability_id=verified.claims.capability_id,
            decision=PermissionDecision.ALLOW.value,
            token_verification="VERIFIED",
            execution_result="SUCCEEDED",
        )
        return result

    def verify_approval(
        self,
        evidence: ApprovalEvidence | dict | None,
        *,
        principal_id: str,
        capability_id: str,
        task_plan: TaskPlan,
        step: PlanStep,
        prepared: PreparedSkillAction,
        consume: bool = False,
    ) -> ApprovalEvidence:
        binding = build_action_binding(
            principal_id=principal_id,
            capability_id=capability_id,
            task_plan=task_plan,
            step=step,
            prepared=prepared,
        )
        if consume:
            return self._approvals.consume(
                evidence,
                expected_binding=binding,
                principal_id=principal_id,
            )
        return self._approvals.verify(
            evidence,
            expected_binding=binding,
            principal_id=principal_id,
        )

    def _authorize(
        self,
        *,
        agent_id: str,
        task_id: str,
        subtask_id: str,
        authorization: AuthorizationResult,
        capability: AuthenticatedCapability | VerifiedCapability | dict,
        task_plan: TaskPlan,
        step: PlanStep,
        intent_result: ValidatedIntentResult,
        prepared: PreparedSkillAction,
    ) -> tuple[VerifiedCapability, PreparedFileAction]:
        if not isinstance(task_plan, TaskPlan) or not isinstance(step, PlanStep):
            raise TypeError("A task plan and action step are required.")
        if not task_plan.task_id or not step.step_id or not step.agent:
            raise ValueError("Task, subtask, and agent identities are required.")
        if (
            not isinstance(agent_id, str)
            or not agent_id.strip()
            or agent_id != step.agent
            or not isinstance(task_id, str)
            or not task_id.strip()
            or task_id != task_plan.task_id
            or not isinstance(subtask_id, str)
            or not subtask_id.strip()
            or subtask_id != step.step_id
        ):
            raise ValueError("Caller identities do not match the authorized action.")
        if not any(candidate is step for candidate in task_plan.steps):
            raise ValueError("The action step is not part of this task.")
        if step.intent != PlannerIntent.READ:
            raise ValueError("The gateway currently supports FILE_READ only.")
        if (
            step.agent != "file_manager"
            or step.operation != "READ"
            or step.resource is None
            or step.template is None
            or step.template.value != "FILE_READ"
            or step.parameters != {"mode": "read"}
        ):
            raise ValueError("The action does not match the fixed FILE_READ contract.")
        if (
            not isinstance(intent_result, ValidatedIntentResult)
            or not intent_result.is_bound_to_plan(task_plan)
            or not intent_result.consistent
            or step.step_id in intent_result.mismatched_steps
        ):
            raise ValueError("A consistent M2 result bound to this task is required.")
        if (
            not isinstance(authorization, AuthorizationResult)
            or not authorization.is_integrity_valid()
            or authorization.decision != PermissionDecision.ALLOW
            or not authorization.is_bound_to(task_plan.task_id, step.step_id)
            or authorization.capability_id != "file.read"
            or authorization.scope is None
            or authorization.scope.resource_id != step.resource
        ):
            raise ValueError("A matching integrity-checked M4 ALLOW is required.")
        canonical = self._resolver.resolve_step(step)
        if canonical.capability_id != authorization.capability_id:
            raise ValueError("The action does not resolve to the authorized M3 capability.")
        if (
            not isinstance(prepared, PreparedSkillAction)
            or prepared.skill_id != "file_manager"
            or prepared.task_id != task_plan.task_id
            or prepared.step_id != step.step_id
            or prepared.intent != PlannerIntent.READ
            or not isinstance(prepared.payload, PreparedFileAction)
        ):
            raise ValueError("The prepared action is not a supported file read.")
        file_action = self._executor.prepare(task_plan, step)
        if prepared.payload != file_action:
            raise ValueError("The prepared resource changed before gateway execution.")
        approved_root = (
            self._executor._working_directory or Path.cwd()
        ).resolve(strict=True)
        resolved_target = file_action.target.resolve(strict=True)
        try:
            relative_target = resolved_target.relative_to(approved_root)
        except ValueError as error:
            raise ValueError(
                "The resolved file is outside the configured workspace."
            ) from error
        if not relative_target.parts:
            raise ValueError("The gateway requires a file inside the configured workspace.")

        authenticated = (
            AuthenticatedCapability(
                claims=capability.claims,
                mac=capability.mac,
            )
            if isinstance(capability, VerifiedCapability)
            else capability
        )
        verified = self._verifier.verify(
            authenticated,
            expected_task_id=task_id,
            expected_step_id=subtask_id,
            expected_agent=agent_id,
            expected_operation=step.operation,
            expected_resource=step.resource,
            expected_scope=authorization.scope,
        )
        claims = verified.claims
        if (
            claims.capability_id != authorization.capability_id
            or dict(claims.constraints) != canonical.parameters
        ):
            raise ValueError("Capability constraints do not match the M3 action.")
        self._lifecycle.check_usable(verified)
        return verified, file_action

    def _record(
        self,
        event_type: str,
        *,
        execution_id: str,
        task_plan: TaskPlan,
        step: PlanStep,
        scope: dict | None,
        capability_id: str | None = None,
        decision: str,
        execution_result: str,
        token_verification: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        self._audit.record(
            event_type,
            execution_id=execution_id,
            task_id=task_plan.task_id,
            step_id=step.step_id,
            scope=scope,
            capability_id=capability_id,
            decision=decision,
            token_verification=token_verification,
            execution_result=execution_result,
            failure_reason=failure_reason,
        )

    def _finish_if_pending(
        self,
        execution_id: str,
        status: str,
        failure_reason: str,
    ) -> None:
        try:
            self._store.finish_gateway_execution(
                execution_id=execution_id,
                status=status,
                failure_reason=failure_reason,
            )
        except LocalStoreError:
            raise


__all__ = ["ExecutionGateway", "ExecutionGatewayError"]
