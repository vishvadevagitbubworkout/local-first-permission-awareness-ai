from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, PrivateAttr, TypeAdapter

from app.security.permissions import PermissionScope
from app.security.tokens import AuthenticatedCapability, CapabilityClaims, UsagePolicy
from app.security.tokens import verify_mac
from app.security.tokens import CapabilityKeyProvider

_VERIFIED_TOKEN = object()


class CapabilityVerificationError(ValueError):
    """Raised when an untrusted capability cannot be verified."""


class VerifiedCapability(BaseModel):
    """Immutable capability whose MAC and contextual claims passed M5.4."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claims: CapabilityClaims
    mac: str
    _verified_token: object | None = PrivateAttr(default=None)

    @classmethod
    def _from_verifier(
        cls, capability: AuthenticatedCapability, *, issuer: object
    ) -> "VerifiedCapability":
        if issuer is not _VERIFIED_TOKEN:
            raise CapabilityVerificationError(
                "verified capability issuance is restricted to the verifier"
            )
        verified = cls(claims=capability.claims, mac=capability.mac)
        verified._verified_token = _VERIFIED_TOKEN
        return verified

    def is_verified(self) -> bool:
        return self._verified_token is _VERIFIED_TOKEN

    def model_copy(self, *, update=None, deep=False):
        if update:
            raise TypeError("VerifiedCapability cannot be retagged after verification")
        return super().model_copy(update=None, deep=deep)


class CapabilityVerifier:
    """Verify authenticated capability claims before downstream trust."""

    def __init__(self, *, key_provider: CapabilityKeyProvider | None = None):
        self._key_provider = key_provider or CapabilityKeyProvider()

    def verify(
        self,
        capability: AuthenticatedCapability | dict[str, Any] | str,
        *,
        now: datetime | None = None,
        expected_task_id: str | None = None,
        expected_step_id: str | None = None,
        expected_agent: str | None = None,
        expected_operation: str | None = None,
        expected_resource: str | None = None,
        expected_scope: PermissionScope | None = None,
    ) -> VerifiedCapability:
        raw_claims, mac = self._parse_raw(capability)
        structural_claims = self._structural_claims(raw_claims)
        signing_key = self._key_provider.get_signing_key()
        if not verify_mac(structural_claims, signing_key, mac):
            raise CapabilityVerificationError("capability MAC verification failed")

        try:
            authenticated = AuthenticatedCapability.model_validate(
                {"claims": raw_claims, "mac": mac}
            )
        except (TypeError, ValueError) as error:
            raise CapabilityVerificationError("capability claims are semantically invalid") from error

        current_time = now or datetime.now(timezone.utc)
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise CapabilityVerificationError("verification time must be timezone-aware")
        current_time = current_time.astimezone(timezone.utc)
        issued_at = authenticated.claims.issued_at.astimezone(timezone.utc)
        expires_at = authenticated.claims.expires_at.astimezone(timezone.utc)
        if expires_at <= issued_at or current_time >= expires_at:
            raise CapabilityVerificationError("capability is expired or has invalid lifetime")

        self._check_context(
            authenticated.claims,
            expected_task_id=expected_task_id,
            expected_step_id=expected_step_id,
            expected_agent=expected_agent,
            expected_operation=expected_operation,
            expected_resource=expected_resource,
            expected_scope=expected_scope,
        )
        return VerifiedCapability._from_verifier(
            authenticated, issuer=_VERIFIED_TOKEN
        )

    @staticmethod
    def _parse_raw(capability: AuthenticatedCapability | dict[str, Any] | str) -> tuple[dict[str, Any], str]:
        try:
            if isinstance(capability, AuthenticatedCapability):
                payload = capability.model_dump(mode="python")
            elif isinstance(capability, str):
                payload = json.loads(capability)
            elif isinstance(capability, dict):
                payload = capability
            else:
                raise TypeError
            if not isinstance(payload, dict) or not isinstance(payload.get("claims"), dict):
                raise TypeError
            mac = payload.get("mac")
            if not isinstance(mac, str):
                raise TypeError
            return dict(payload["claims"]), mac
        except (TypeError, ValueError) as error:
            raise CapabilityVerificationError("capability representation is malformed") from error

    @staticmethod
    def _structural_claims(raw_claims: dict[str, Any]) -> CapabilityClaims:
        try:
            required = {
                "capability_id",
                "task_id",
                "step_id",
                "agent",
                "operation",
                "resource",
                "scope",
                "constraints",
                "issued_at",
                "expires_at",
                "nonce",
                "usage_policy",
            }
            if set(raw_claims) != required or not isinstance(raw_claims["constraints"], dict):
                raise TypeError
            values = dict(raw_claims)
            values["scope"] = PermissionScope.model_validate(values["scope"])
            values["issued_at"] = TypeAdapter(datetime).validate_python(values["issued_at"])
            values["expires_at"] = TypeAdapter(datetime).validate_python(values["expires_at"])
            values["usage_policy"] = UsagePolicy(values["usage_policy"])
            return CapabilityClaims.model_construct(**values)
        except (TypeError, ValueError, KeyError) as error:
            raise CapabilityVerificationError("capability representation is malformed") from error

    @staticmethod
    def _check_context(
        claims: CapabilityClaims,
        *,
        expected_task_id: str | None,
        expected_step_id: str | None,
        expected_agent: str | None,
        expected_operation: str | None,
        expected_resource: str | None,
        expected_scope: PermissionScope | None,
    ) -> None:
        checks = (
            (expected_task_id, claims.task_id, "task"),
            (expected_step_id, claims.step_id, "step"),
            (expected_agent, claims.agent, "agent"),
            (expected_operation, claims.operation, "operation"),
            (expected_resource, claims.resource, "resource"),
        )
        for expected, actual, name in checks:
            if expected is not None and expected != actual:
                raise CapabilityVerificationError(f"capability {name} context mismatch")
        if expected_scope is not None and expected_scope != claims.scope:
            raise CapabilityVerificationError("capability scope context mismatch")


__all__ = [
    "CapabilityVerificationError",
    "CapabilityVerifier",
    "VerifiedCapability",
]
