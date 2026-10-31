from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.capabilities import CapabilityRegistryError
from app.security.capabilities import CapabilityResolver
from app.security.permissions import AuthorizationResult
from app.security.permissions import PermissionDecision
from app.core.task_plan import PlanStep, TaskPlan
from app.security.tokens import AuthenticatedCapability, CapabilityClaims, UsagePolicy
from app.security.tokens import compute_mac
from app.security.tokens import CapabilityKeyProvider

_MAX_LIFETIME = timedelta(hours=1)
_DEFAULT_LIFETIME = timedelta(minutes=5)


class CapabilityMintingError(ValueError):
    """Raised when an authorized capability cannot be minted safely."""


class CapabilityMintingPolicy(BaseModel):
    """Developer-controlled bounded lifetime and usage configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    lifetime: timedelta = Field(default=_DEFAULT_LIFETIME)
    usage_policy: UsagePolicy = UsagePolicy.ONE_TIME

    @field_validator("lifetime")
    @classmethod
    def validate_lifetime(cls, value: timedelta) -> timedelta:
        if value <= timedelta(0) or value > _MAX_LIFETIME:
            raise ValueError("capability lifetime must be greater than zero and at most one hour")
        return value

    @field_validator("usage_policy")
    @classmethod
    def validate_usage_policy(cls, value: UsagePolicy) -> UsagePolicy:
        if not isinstance(value, UsagePolicy):
            raise TypeError("usage_policy must be a UsagePolicy")
        return value


class CapabilityMinter:
    """Mint authenticated capability authority only from a trusted M4 ALLOW."""

    def __init__(
        self,
        *,
        key_provider: CapabilityKeyProvider | None = None,
        resolver: CapabilityResolver | None = None,
        policy: CapabilityMintingPolicy | None = None,
    ):
        self._key_provider = key_provider or CapabilityKeyProvider()
        self.resolver = resolver or CapabilityResolver()
        self.policy = policy or CapabilityMintingPolicy()

    def mint(
        self,
        authorization: AuthorizationResult,
        task_plan: TaskPlan,
        step: PlanStep,
    ) -> AuthenticatedCapability:
        self._validate_authorization(authorization, task_plan, step)

        try:
            canonical = self.resolver.resolve_step(step)
        except (CapabilityRegistryError, TypeError, ValueError, AttributeError) as error:
            raise CapabilityMintingError(f"M3 capability resolution failed: {error}") from error

        if authorization.capability_id != canonical.capability_id:
            raise CapabilityMintingError("authorization capability does not match M3 resolution")
        if authorization.scope is None or authorization.scope.resource_id != step.resource:
            raise CapabilityMintingError("authorization scope does not match the plan step resource")

        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + self.policy.lifetime
        claims = CapabilityClaims(
            capability_id=canonical.capability_id,
            task_id=task_plan.task_id,
            step_id=step.step_id,
            agent=canonical.agent,
            operation=canonical.operation,
            resource=step.resource,
            scope=authorization.scope,
            constraints=canonical.parameters,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=secrets.token_urlsafe(24),
            usage_policy=self.policy.usage_policy,
        )
        signing_key = self._key_provider.get_signing_key()
        return AuthenticatedCapability(
            claims=claims,
            mac=compute_mac(claims, signing_key),
        )

    @staticmethod
    def _validate_authorization(
        authorization: AuthorizationResult,
        task_plan: TaskPlan,
        step: PlanStep,
    ) -> None:
        if not isinstance(authorization, AuthorizationResult):
            raise CapabilityMintingError("authorization must be an AuthorizationResult")
        if not authorization.is_integrity_valid():
            raise CapabilityMintingError("authorization integrity is invalid")
        if authorization.decision != PermissionDecision.ALLOW:
            raise CapabilityMintingError("only an M4 ALLOW decision can mint a capability")
        if not isinstance(task_plan, TaskPlan) or not task_plan.task_id:
            raise CapabilityMintingError("a valid task plan is required")
        if not isinstance(step, PlanStep):
            raise CapabilityMintingError("a valid plan step is required")
        matching_step = next(
            (candidate for candidate in task_plan.steps if candidate.step_id == step.step_id),
            None,
        )
        if matching_step is None or matching_step != step:
            raise CapabilityMintingError("step is not the exact step in the task plan")
        if authorization.task_id != task_plan.task_id:
            raise CapabilityMintingError("authorization task does not match the task plan")
        if authorization.step_id != step.step_id:
            raise CapabilityMintingError("authorization step does not match the plan step")


__all__ = [
    "CapabilityMinter",
    "CapabilityMintingError",
    "CapabilityMintingPolicy",
]
