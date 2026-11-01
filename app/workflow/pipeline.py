"""Integrate planning, authorization, capability checks, and local M6 actions."""
from dataclasses import dataclass
from typing import Callable
import uuid

from app.core.config import AUTOMATION_STATE_DB, M6_WORKING_DIRECTORY
from app.security.capabilities import ResourceType
from app.validation.intent import IntentValidator
from app.validation.intent import ValidatedIntentResult
from app.security.permissions import TaskAuthorizationManager
from app.security.permissions import AuthorizationResult
from app.security.permissions import (
    PermissionDecision,
    PermissionScope,
    PermissionScopeKind,
)
from app.agents.planner import Planner
from app.core.task_plan import PlannerIntent
from app.security.lifecycle import CapabilityLifecycleStore
from app.security.lifecycle import CapabilityLifecycleError
from app.security.minting import CapabilityMinter, CapabilityMintingError
from app.security.verification import CapabilityVerificationError, CapabilityVerifier
from app.storage.local_store import LocalAutomationStore
from app.security.audit import AuditTrail
from app.skills.file_executor import (
    FileSystemExecutor,
    M6ExecutionError,
)
from app.skills.registry import (
    PreparedSkillAction,
    SkillExecutionContext,
    SkillExecutionError,
    SkillPreparationError,
)
from app.skills.file_management import FileManagementSkill
from app.skills.registry import SkillRegistry, SkillRegistryError
from app.core.task_plan import PlanStep


@dataclass(frozen=True)
class PipelineStepResult:
    step_id: str
    decision: str
    reason: str
    capability_id: str | None = None
    output: str = ""


ActionReviewCallback = Callable[
    [PlanStep, AuthorizationResult],
    None,
]


class M1M6Pipeline:
    """Run the real module chain and return an auditable, non-executing result."""

    def __init__(self, *, planner=None, validator=None, authorizer=None,
                 minter=None, verifier=None, lifecycle=None, executor=None,
                 skill_registry: SkillRegistry | None = None,
                 review_callback: ActionReviewCallback | None = None,
                 approval_callback: Callable[[PreparedSkillAction], bool] | None = None,
                 audit_trail: AuditTrail | None = None):
        self.planner = planner or Planner()
        self.validator = validator or IntentValidator()
        self.authorizer = authorizer or TaskAuthorizationManager()
        self.minter = minter or CapabilityMinter(resolver=self.authorizer.resolver)
        self.verifier = verifier or CapabilityVerifier(key_provider=self.minter._key_provider)
        self.state_store = (
            lifecycle.store
            if lifecycle is not None
            else LocalAutomationStore(AUTOMATION_STATE_DB)
        )
        self.lifecycle = lifecycle or CapabilityLifecycleStore(
            verifier=self.verifier,
            store=self.state_store,
        )
        self.audit_trail = audit_trail or AuditTrail(self.state_store)
        self.executor = executor or FileSystemExecutor(
            verifier=self.verifier,
            lifecycle=self.lifecycle,
            working_directory=M6_WORKING_DIRECTORY,
        )
        self.skills = skill_registry or SkillRegistry(
            [FileManagementSkill(self.executor)]
        )
        self.review_callback = review_callback
        self.approval_callback = approval_callback

    def run(
        self,
        user_request: str,
        *,
        dry_run: bool = False,
    ) -> tuple[object, ValidatedIntentResult, list[PipelineStepResult]]:
        self.audit_trail.record("REQUEST_RECEIVED", request=user_request)
        try:
            plan = self.planner.create_plan(user_request)
        except Exception as error:
            self.audit_trail.record(
                "PLANNING_FAILED",
                request=user_request,
                failure_reason=type(error).__name__,
            )
            raise
        self.audit_trail.record(
            "PLAN_CREATED",
            task_id=plan.task_id,
            request=user_request,
            execution_result="; ".join(
                f"{step.step_id}:{step.intent.value if step.intent else 'UNSPECIFIED'}"
                for step in plan.steps
            ),
        )
        try:
            intent = self.validator.validate(plan)
        except Exception as error:
            self.audit_trail.record(
                "INTENT_VALIDATION_FAILED",
                task_id=plan.task_id,
                request=user_request,
                failure_reason=type(error).__name__,
            )
            raise
        self.audit_trail.record(
            "INTENT_VALIDATED",
            task_id=plan.task_id,
            request=user_request,
            decision="ALLOW" if intent.consistent else "DENY",
            execution_result="CONSISTENT" if intent.consistent else "INCONSISTENT",
        )
        results = []
        for step in plan.steps:
            if step.intent == PlannerIntent.ASK_CLARIFICATION:
                clarification = self.authorizer.authorize_step(
                    plan,
                    intent,
                    step.step_id,
                    scope=None,
                )
                self.audit_trail.record(
                    "AUTHORIZATION_DECISION",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    decision=clarification.decision.value,
                    failure_reason="CLARIFICATION_REQUIRED",
                )
                results.append(
                    PipelineStepResult(
                        step.step_id,
                        clarification.decision.value,
                        clarification.reason,
                    )
                )
                continue
            scope = None if step.resource is None else PermissionScope(
                resource_type=ResourceType.FILE, kind=PermissionScopeKind.TASK,
                selector="current_task.resource", resource_id=step.resource,
            )
            authorization = self.authorizer.authorize_step(plan, intent, step.step_id, scope=scope)
            safe_scope = self.audit_trail.safe_scope(
                scope,
                intent=step.operation,
            )
            self.audit_trail.record(
                "AUTHORIZATION_DECISION",
                task_id=plan.task_id,
                step_id=step.step_id,
                request=user_request,
                scope=safe_scope,
                capability_id=authorization.capability_id,
                decision=authorization.decision.value,
                failure_reason=(
                    "AUTHORIZATION_DENIED"
                    if authorization.decision != PermissionDecision.ALLOW
                    else None
                ),
            )
            if authorization.decision not in {
                PermissionDecision.ALLOW,
                PermissionDecision.ASK_APPROVAL,
            }:
                if self.review_callback is not None:
                    self.review_callback(step, authorization)
                self.audit_trail.record(
                    "ACTION_REVIEWED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    capability_id=authorization.capability_id,
                    decision=authorization.decision.value,
                )
                results.append(PipelineStepResult(
                    step.step_id,
                    authorization.decision.value,
                    authorization.reason,
                ))
                continue

            try:
                skill = self.skills.get(step.agent)
                prepared = skill.prepare(plan, step)
            except (
                M6ExecutionError,
                SkillPreparationError,
                SkillRegistryError,
            ) as error:
                self.audit_trail.record(
                    "EXECUTION_PREFLIGHT_FAILED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    decision="DENY",
                    execution_result="NOT_STARTED",
                    failure_reason="PREFLIGHT_FAILED",
                )
                results.append(
                    PipelineStepResult(step.step_id, "ERROR", str(error))
                )
                continue

            safe_scope = self.audit_trail.safe_scope(
                scope,
                intent=step.operation,
                root=prepared.audit_root,
                target=prepared.audit_target,
            )
            if self.review_callback is not None:
                self.review_callback(step, authorization)
            self.audit_trail.record(
                "ACTION_REVIEWED",
                task_id=plan.task_id,
                step_id=step.step_id,
                request=user_request,
                scope=safe_scope,
                capability_id=authorization.capability_id,
                decision=authorization.decision.value,
            )
            if dry_run:
                self.audit_trail.record(
                    "DRY_RUN_PREVIEW",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    decision="DRY_RUN",
                    execution_result="NOT_STARTED",
                )
                results.append(
                    PipelineStepResult(
                        step.step_id,
                        "DRY_RUN",
                        (
                            f"Preview only; M4 would return "
                            f"{authorization.decision.value}. No capability was "
                            "minted and no file operation was performed."
                        ),
                        output=prepared.display_target,
                    )
                )
                continue
            if authorization.decision == PermissionDecision.ASK_APPROVAL:
                self.audit_trail.record(
                    "APPROVAL_REQUESTED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    capability_id=authorization.capability_id,
                    decision=PermissionDecision.ASK_APPROVAL.value,
                )
                try:
                    approved = bool(
                        self.approval_callback is not None
                        and self.approval_callback(prepared)
                    )
                except Exception:
                    self.audit_trail.record(
                        "APPROVAL_DECISION",
                        task_id=plan.task_id,
                        step_id=step.step_id,
                        request=user_request,
                        scope=safe_scope,
                        capability_id=authorization.capability_id,
                        decision=PermissionDecision.DENY.value,
                        approval="FAILED",
                        failure_reason="APPROVAL_FLOW_FAILED",
                    )
                    raise
                authorization = self.authorizer.resolve_approval(
                    authorization,
                    plan,
                    step.step_id,
                    approved=approved,
                )
                self.audit_trail.record(
                    "APPROVAL_DECISION",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    capability_id=authorization.capability_id,
                    decision=authorization.decision.value,
                    approval="APPROVED" if approved else "DENIED",
                    failure_reason=(
                        None if approved else "USER_DECLINED_APPROVAL"
                    ),
                )
                if authorization.decision != PermissionDecision.ALLOW:
                    results.append(
                        PipelineStepResult(
                            step.step_id,
                            authorization.decision.value,
                            authorization.reason,
                        )
                    )
                    continue

            try:
                capability = self.minter.mint(authorization, plan, step)
                self.audit_trail.record(
                    "CAPABILITY_ISSUED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    capability_id=capability.claims.capability_id,
                    decision=PermissionDecision.ALLOW.value,
                )
            except CapabilityMintingError as error:
                self.audit_trail.record(
                    "CAPABILITY_ISSUANCE_FAILED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    decision=PermissionDecision.DENY.value,
                    failure_reason="CAPABILITY_ISSUANCE_FAILED",
                )
                raise
            try:
                verified = self.verifier.verify(
                    capability,
                    expected_task_id=plan.task_id,
                    expected_step_id=step.step_id,
                    expected_agent=step.agent,
                    expected_operation=step.operation,
                    expected_resource=step.resource,
                    expected_scope=authorization.scope,
                )
            except CapabilityVerificationError as error:
                self.audit_trail.record(
                    "TOKEN_VERIFICATION_FAILED",
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    request=user_request,
                    scope=safe_scope,
                    decision=PermissionDecision.DENY.value,
                    token_verification="FAILED",
                    failure_reason="TOKEN_VERIFICATION_FAILED",
                )
                raise
            self.audit_trail.record(
                "TOKEN_VERIFIED",
                task_id=plan.task_id,
                step_id=step.step_id,
                request=user_request,
                scope=safe_scope,
                capability_id=capability.claims.capability_id,
                decision=PermissionDecision.ALLOW.value,
                token_verification="VERIFIED",
            )
            execution_id = uuid.uuid4().hex
            execution_started = False

            def record_consumed_capability() -> None:
                nonlocal execution_started
                self.state_store.start_execution(
                    execution_id=execution_id,
                    task_id=plan.task_id,
                    step_id=step.step_id,
                    capability_id=capability.claims.capability_id,
                    scope=safe_scope,
                )
                execution_started = True

            try:
                action_result = skill.execute(
                    SkillExecutionContext(
                        authorization=authorization,
                        capability=verified,
                        task_plan=plan,
                        step=step,
                        intent_result=intent,
                        prepared=prepared,
                        after_capability_consumed=record_consumed_capability,
                    )
                )
            except (
                M6ExecutionError,
                CapabilityLifecycleError,
                SkillExecutionError,
            ) as error:
                if execution_started:
                    self.state_store.finish_execution(
                        execution_id=execution_id,
                        task_id=plan.task_id,
                        step_id=step.step_id,
                        status="FAILED",
                        execution_result="FAILED",
                        failure_reason="EXECUTION_FAILED",
                    )
                elif isinstance(error, CapabilityLifecycleError):
                    self.audit_trail.record(
                        "TOKEN_LIFECYCLE_REJECTED",
                        task_id=plan.task_id,
                        step_id=step.step_id,
                        request=user_request,
                        scope=safe_scope,
                        capability_id=capability.claims.capability_id,
                        decision=PermissionDecision.DENY.value,
                        token_verification="REJECTED",
                        failure_reason="TOKEN_LIFECYCLE_REJECTED",
                    )
                else:
                    self.audit_trail.record(
                        "EXECUTION_REJECTED",
                        task_id=plan.task_id,
                        step_id=step.step_id,
                        request=user_request,
                        scope=safe_scope,
                        capability_id=capability.claims.capability_id,
                        decision="ERROR",
                        token_verification="VERIFIED",
                        execution_result="NOT_STARTED",
                        failure_reason="EXECUTION_REJECTED",
                    )
                results.append(PipelineStepResult(step.step_id, "ERROR", str(error)))
                continue
            self.state_store.finish_execution(
                execution_id=execution_id,
                task_id=plan.task_id,
                step_id=step.step_id,
                status="COMPLETED",
                execution_result="SUCCEEDED",
            )
            results.append(
                PipelineStepResult(
                    step.step_id,
                    "ALLOW",
                    action_result.summary,
                    capability.claims.capability_id,
                    action_result.output,
                )
            )
        return plan, intent, results


M1M5Pipeline = M1M6Pipeline
