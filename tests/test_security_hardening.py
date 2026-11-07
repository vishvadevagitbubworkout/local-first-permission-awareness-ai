import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.security.audit import redact_sensitive_text
from app.security.capabilities import ResourceType
from app.security.permissions import PermissionScope, PermissionScopeKind
from app.security.tokens import (
    AuthenticatedCapability,
    CapabilityClaims,
    CapabilityKeyProvider,
    UsagePolicy,
    compute_mac,
)
from app.security.verification import (
    CapabilityVerificationError,
    CapabilityVerifier,
)
from app.storage.local_store import LocalAutomationStore


class SecurityHardeningTests(unittest.TestCase):
    def test_redacts_unquoted_credential_assignments(self):
        redacted = redact_sensitive_text(
            "password=hunter2 api_key: abc123 token=eyJhbGci "
            "Authorization: Bearer abc.def"
        )

        self.assertNotIn("hunter2", redacted)
        self.assertNotIn("abc123", redacted)
        self.assertNotIn("eyJhbGci", redacted)
        self.assertNotIn("abc.def", redacted)
        self.assertEqual(redacted.count("[REDACTED_SECRET]"), 4)

    def _capability(self, issued_at, expires_at):
        claims = CapabilityClaims(
            capability_id="file.read",
            task_id="task-1",
            step_id="step-1",
            agent="file_manager",
            operation="READ",
            resource="sample.txt",
            scope=PermissionScope(
                resource_type=ResourceType.FILE,
                kind=PermissionScopeKind.RESOURCE,
                selector="sample.txt",
                resource_id="sample.txt",
            ),
            constraints={"mode": "read"},
            issued_at=issued_at,
            expires_at=expires_at,
            nonce="0123456789abcdef",
            usage_policy=UsagePolicy.ONE_TIME,
        )
        key = b"test-signing-key-that-is-at-least-32-bytes"
        return AuthenticatedCapability(claims=claims, mac=compute_mac(claims, key)), key

    def test_verifier_accepts_valid_capability_within_maximum_lifetime(self):
        now = datetime.now(timezone.utc)
        capability, key = self._capability(now, now + timedelta(minutes=5))

        verified = CapabilityVerifier(
            key_provider=CapabilityKeyProvider.for_testing(key)
        ).verify(capability, now=now)

        self.assertTrue(verified.is_verified())

    def test_verifier_rejects_future_issued_capability(self):
        now = datetime.now(timezone.utc)
        issued_at = now + timedelta(minutes=1)
        capability, key = self._capability(
            issued_at, issued_at + timedelta(minutes=5)
        )

        with self.assertRaises(CapabilityVerificationError):
            CapabilityVerifier(
                key_provider=CapabilityKeyProvider.for_testing(key)
            ).verify(capability, now=now)

    def test_verifier_rejects_capability_lifetime_over_one_hour(self):
        now = datetime.now(timezone.utc)
        capability, key = self._capability(
            now, now + timedelta(hours=1, microseconds=1)
        )

        with self.assertRaises(CapabilityVerificationError):
            CapabilityVerifier(
                key_provider=CapabilityKeyProvider.for_testing(key)
            ).verify(capability, now=now)

    def test_first_lifecycle_state_lookup_creates_active_record(self):
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=5)).isoformat()

        with tempfile.TemporaryDirectory() as temporary_directory:
            store = LocalAutomationStore(
                Path(temporary_directory) / "state.sqlite"
            )
            state = store.get_capability_state(
                capability_id="file.read",
                nonce="0123456789abcdef",
                expires_at=expires_at,
                usage_policy=UsagePolicy.ONE_TIME.value,
                now=now,
            )
            store.close_run()

        self.assertEqual(state, "ACTIVE")


if __name__ == "__main__":
    unittest.main()
