from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from app.core.config import AUTOMATION_STATE_DB
from app.storage.local_store import LocalAutomationStore
from app.security.tokens import AuthenticatedCapability, UsagePolicy
from app.security.verification import CapabilityVerificationError, CapabilityVerifier, VerifiedCapability
from app.security.tokens import CapabilityKeyProvider


class CapabilityLifecycleState(str, Enum):
    ACTIVE = "ACTIVE"
    USED = "USED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class CapabilityLifecycleError(ValueError):
    """Base error for lifecycle and replay failures."""


class CapabilityReplayError(CapabilityLifecycleError):
    """Raised when a one-time capability is used again."""


class CapabilityExpiredError(CapabilityLifecycleError):
    """Raised when a capability is used after expiry."""


class CapabilityRevokedError(CapabilityLifecycleError):
    """Raised when a revoked capability is used."""


class CapabilityStateError(CapabilityLifecycleError):
    """Raised for invalid lifecycle transitions or untrusted inputs."""


class CapabilityLifecycleStore:
    """Persistent, cross-process lifecycle state for verified capabilities."""

    def __init__(
        self,
        *,
        verifier: CapabilityVerifier | None = None,
        store: LocalAutomationStore | None = None,
    ):
        self._verifier = verifier or CapabilityVerifier(
            key_provider=CapabilityKeyProvider()
        )
        self.store = store or LocalAutomationStore(AUTOMATION_STATE_DB)

    def _require_verified(
        self,
        capability: AuthenticatedCapability | VerifiedCapability,
        *,
        now: datetime | None = None,
    ) -> VerifiedCapability:
        if isinstance(capability, VerifiedCapability):
            capability = AuthenticatedCapability(
                claims=capability.claims,
                mac=capability.mac,
            )
        if not isinstance(capability, AuthenticatedCapability):
            raise CapabilityStateError("lifecycle requires an authenticated capability")
        try:
            return self._verifier.verify(capability, now=now)
        except CapabilityVerificationError as error:
            if "expired" in str(error).lower():
                try:
                    return self._verifier.verify(
                        capability,
                        now=capability.claims.issued_at,
                    )
                except CapabilityVerificationError:
                    pass
            raise CapabilityStateError(
                "lifecycle requires a capability with a valid MAC and expiry"
            ) from error

    @staticmethod
    def _store_claims(capability: VerifiedCapability) -> dict[str, str]:
        claims = capability.claims
        return {
            "capability_id": claims.capability_id,
            "nonce": claims.nonce,
            "expires_at": claims.expires_at.astimezone(timezone.utc).isoformat(),
            "usage_policy": claims.usage_policy.value,
        }

    @staticmethod
    def _now(now: datetime | None) -> datetime:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise CapabilityStateError("lifecycle time must be timezone-aware")
        return current.astimezone(timezone.utc)

    def state(self, capability: VerifiedCapability, *, now: datetime | None = None) -> CapabilityLifecycleState:
        capability = self._require_verified(capability, now=now)
        current = self._now(now)
        state = self.store.get_capability_state(
            **self._store_claims(capability),
            now=current,
        )
        return CapabilityLifecycleState(state)

    def check_usable(self, capability: VerifiedCapability, *, now: datetime | None = None) -> VerifiedCapability:
        current_state = self.state(capability, now=now)
        if current_state == CapabilityLifecycleState.EXPIRED:
            raise CapabilityExpiredError("capability is expired")
        if current_state == CapabilityLifecycleState.REVOKED:
            raise CapabilityRevokedError("capability is revoked")
        if current_state == CapabilityLifecycleState.USED:
            raise CapabilityReplayError("one-time capability has already been used")
        return capability

    def verify_and_consume(
        self,
        capability: VerifiedCapability,
        *,
        now: datetime | None = None,
    ) -> VerifiedCapability:
        """Atomically check and consume a one-time capability."""
        capability = self._require_verified(capability, now=now)
        current = self._now(now)
        state = self.store.consume_capability(
            **self._store_claims(capability),
            now=current,
        )
        if state == "CONSUMED":
            return capability
        if state == CapabilityLifecycleState.EXPIRED.value:
            raise CapabilityExpiredError("capability is expired")
        if state == CapabilityLifecycleState.REVOKED.value:
            raise CapabilityRevokedError("capability is revoked")
        if state == CapabilityLifecycleState.USED.value:
            raise CapabilityReplayError("one-time capability has already been used")
        return capability

    def revoke(self, capability: VerifiedCapability, *, now: datetime | None = None) -> None:
        capability = self._require_verified(capability, now=now)
        current = self._now(now)
        state = self.store.revoke_capability(
            **self._store_claims(capability),
            now=current,
        )
        if state == "REVOKED_NOW":
            return
        if state == CapabilityLifecycleState.USED.value:
            raise CapabilityStateError("used capability cannot be revoked")
        if state == CapabilityLifecycleState.EXPIRED.value:
            raise CapabilityStateError("expired capability cannot be revoked")
        if state == CapabilityLifecycleState.REVOKED.value:
            raise CapabilityStateError("capability is already revoked")


__all__ = [
    "CapabilityExpiredError",
    "CapabilityLifecycleError",
    "CapabilityLifecycleState",
    "CapabilityLifecycleStore",
    "CapabilityReplayError",
    "CapabilityRevokedError",
    "CapabilityStateError",
]
