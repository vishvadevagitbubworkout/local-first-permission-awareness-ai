from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.security.tokens import CapabilityKeyProvider
from app.storage.local_store import LocalAutomationStore
from app.core.task_plan import PlanStep, TaskPlan
from app.skills.file_executor import PreparedFileAction
from app.skills.registry import PreparedSkillAction

_DEFAULT_APPROVAL_LIFETIME = timedelta(minutes=5)
_MAX_APPROVAL_LIFETIME = timedelta(minutes=15)
_APPROVAL_DOMAIN = b"permission-aware-automation:exact-action-approval:v1:"


class ApprovalError(ValueError):
    """Raised when approval evidence is absent, invalid, expired, or spent."""


class ActionBinding(BaseModel):
    """Canonical security-relevant identity of one prepared action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    principal_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    task_id: str = Field(..., min_length=1)
    step_id: str = Field(..., min_length=1)
    capability_id: str = Field(..., min_length=1)
    operation: str = Field(..., min_length=1)
    resource_id: str = Field(..., min_length=1)
    parameters: dict[str, Any] = Field(default_factory=dict)
    destination_id: str | None = None
    plan_digest: str = Field(..., min_length=64, max_length=64)

    def canonical_bytes(self) -> bytes:
        try:
            serialized = json.dumps(
                self.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ApprovalError("Action parameters are not canonical JSON.") from error
        return serialized.encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ApprovalEvidence(BaseModel):
    """Signed, time-bounded, single-use exact-action approval."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: str = Field(..., min_length=32)
    binding_digest: str = Field(..., min_length=64, max_length=64)
    principal_id: str = Field(..., min_length=1)
    issued_at: datetime
    expires_at: datetime
    nonce: str = Field(..., min_length=32)
    signature: str = Field(..., min_length=64, max_length=64)

    def signed_payload(self) -> bytes:
        payload = self.model_dump(mode="json", exclude={"signature"})
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return _APPROVAL_DOMAIN + serialized.encode("utf-8")


class ApprovalManager:
    """Issue, verify, consume, and revoke exact-action approval evidence."""

    def __init__(
        self,
        *,
        store: LocalAutomationStore,
        key_provider: CapabilityKeyProvider,
    ):
        self._store = store
        self._key_provider = key_provider

    def issue(
        self,
        binding: ActionBinding,
        *,
        now: datetime | None = None,
        lifetime: timedelta = _DEFAULT_APPROVAL_LIFETIME,
    ) -> ApprovalEvidence:
        if not isinstance(binding, ActionBinding):
            raise ApprovalError("Approval requires a canonical action binding.")
        if lifetime <= timedelta(0) or lifetime > _MAX_APPROVAL_LIFETIME:
            raise ApprovalError("Approval lifetime must be at most fifteen minutes.")
        issued_at = self._normalize_time(now or datetime.now(timezone.utc))
        expires_at = issued_at + lifetime
        unsigned = {
            "approval_id": uuid.uuid4().hex,
            "binding_digest": binding.digest(),
            "principal_id": binding.principal_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "nonce": secrets.token_urlsafe(24),
            "signature": "0" * 64,
        }
        provisional = ApprovalEvidence(**unsigned)
        signature = hmac.new(
            self._key_provider.get_signing_key(),
            provisional.signed_payload(),
            hashlib.sha256,
        ).hexdigest()
        evidence = provisional.model_copy(update={"signature": signature})
        self._store.create_approval(
            approval_id=evidence.approval_id,
            binding=binding.model_dump(mode="json"),
            binding_digest=evidence.binding_digest,
            principal_id=evidence.principal_id,
            issued_at=evidence.issued_at.astimezone(timezone.utc).isoformat(),
            expires_at=evidence.expires_at.astimezone(timezone.utc).isoformat(),
            nonce=evidence.nonce,
            signature=evidence.signature,
        )
        return evidence

    def verify(
        self,
        evidence: ApprovalEvidence | dict[str, Any] | None,
        *,
        expected_binding: ActionBinding,
        principal_id: str,
        now: datetime | None = None,
    ) -> ApprovalEvidence:
        if evidence is None:
            raise ApprovalError("Exact-action approval evidence is required.")
        try:
            record = (
                evidence
                if isinstance(evidence, ApprovalEvidence)
                else ApprovalEvidence.model_validate(evidence)
            )
        except (TypeError, ValueError) as error:
            raise ApprovalError("Approval evidence is malformed.") from error
        current = self._normalize_time(now or datetime.now(timezone.utc))
        issued = self._normalize_time(record.issued_at)
        expires = self._normalize_time(record.expires_at)
        if issued > current or expires <= issued:
            raise ApprovalError("Approval has invalid timestamps.")
        if expires - issued > _MAX_APPROVAL_LIFETIME:
            raise ApprovalError("Approval lifetime exceeds the configured maximum.")
        if record.principal_id != principal_id:
            raise ApprovalError("Approval principal does not match the caller.")
        if record.binding_digest != expected_binding.digest():
            raise ApprovalError("Approval does not bind to this exact action.")
        expected_signature = hmac.new(
            self._key_provider.get_signing_key(),
            record.signed_payload(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_signature, record.signature):
            raise ApprovalError("Approval signature verification failed.")
        state = self._store.get_approval_state(
            record.approval_id,
            now=current.isoformat(),
        )
        if state is None:
            raise ApprovalError("Approval lifecycle record is missing.")
        if state != "ACTIVE":
            raise ApprovalError(f"Approval is not active: {state}.")
        if expires <= current:
            raise ApprovalError("Approval is expired.")
        persisted = self._store.get_approval_record(record.approval_id)
        if persisted is None or (
            persisted["binding_digest"] != record.binding_digest
            or persisted["principal_id"] != record.principal_id
            or persisted["signature"] != record.signature
            or persisted["nonce"] != record.nonce
        ):
            raise ApprovalError("Approval differs from its persisted evidence.")
        return record

    def consume(
        self,
        evidence: ApprovalEvidence | dict[str, Any] | None,
        *,
        expected_binding: ActionBinding,
        principal_id: str,
        now: datetime | None = None,
    ) -> ApprovalEvidence:
        current = self._normalize_time(now or datetime.now(timezone.utc))
        record = self.verify(
            evidence,
            expected_binding=expected_binding,
            principal_id=principal_id,
            now=current,
        )
        state = self._store.consume_approval(
            approval_id=record.approval_id,
            binding_digest=expected_binding.digest(),
            now=current.astimezone(timezone.utc).isoformat(),
        )
        if state != "CONSUMED_NOW":
            raise ApprovalError(f"Approval could not be consumed: {state}.")
        return record

    def revoke(
        self,
        evidence: ApprovalEvidence | dict[str, Any],
        *,
        expected_binding: ActionBinding,
        principal_id: str,
        now: datetime | None = None,
    ) -> None:
        record = self.verify(
            evidence,
            expected_binding=expected_binding,
            principal_id=principal_id,
            now=now,
        )
        state = self._store.revoke_approval(record.approval_id)
        if state != "REVOKED":
            raise ApprovalError(f"Approval could not be revoked: {state}.")

    @staticmethod
    def _normalize_time(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ApprovalError("Approval timestamps must be timezone-aware.")
        return value.astimezone(timezone.utc)


def build_action_binding(
    *,
    principal_id: str,
    capability_id: str,
    task_plan: TaskPlan,
    step: PlanStep,
    prepared: PreparedSkillAction,
) -> ActionBinding:
    if (
        not isinstance(task_plan, TaskPlan)
        or not isinstance(step, PlanStep)
        or not isinstance(prepared, PreparedSkillAction)
        or not isinstance(prepared.payload, PreparedFileAction)
        or not any(candidate is step for candidate in task_plan.steps)
    ):
        raise ApprovalError("Approval requires the exact prepared task action.")
    if not principal_id.strip() or not capability_id:
        raise ApprovalError("Approval principal and capability identity are required.")

    action = prepared.payload
    try:
        resource_id = str(action.target.resolve(strict=False))
        destination_id = (
            str(action.destination.resolve(strict=False))
            if action.destination is not None
            else None
        )
        plan_bytes = json.dumps(
            task_plan.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        parameters = dict(step.parameters)
        if action.content is not None:
            parameters["content_sha256"] = hashlib.sha256(
                action.content.encode("utf-8")
            ).hexdigest()
        return ActionBinding(
            principal_id=principal_id,
            agent_id=step.agent,
            task_id=task_plan.task_id,
            step_id=step.step_id,
            capability_id=capability_id,
            operation=step.operation,
            resource_id=resource_id,
            parameters=parameters,
            destination_id=destination_id,
            plan_digest=hashlib.sha256(plan_bytes).hexdigest(),
        )
    except (OSError, TypeError, ValueError) as error:
        raise ApprovalError("The prepared action could not be canonicalized.") from error


__all__ = [
    "ActionBinding",
    "ApprovalError",
    "ApprovalEvidence",
    "ApprovalManager",
    "build_action_binding",
]
