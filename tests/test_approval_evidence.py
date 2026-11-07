import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app.security.approval import (
    ActionBinding,
    ApprovalError,
    ApprovalManager,
)
from app.security.tokens import CapabilityKeyProvider
from app.storage.local_store import LocalAutomationStore, LocalStoreError


class ApprovalEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.store = LocalAutomationStore(
            Path(self.temporary_directory.name) / "approval.sqlite"
        )
        self.key_provider = CapabilityKeyProvider.for_testing(
            b"approval-evidence-tests-signing-key"
        )
        self.manager = ApprovalManager(
            store=self.store,
            key_provider=self.key_provider,
        )
        self.binding = ActionBinding(
            principal_id="local-test-principal",
            agent_id="file_manager",
            task_id="task-001",
            step_id="step-001",
            capability_id="file.write",
            operation="WRITE",
            resource_id="C:/temporary/workspace/draft.txt",
            parameters={"mode": "write", "content_sha256": "a" * 64},
            destination_id=None,
            plan_digest="b" * 64,
        )
        self.evidence = self.manager.issue(self.binding)

    def tearDown(self):
        self.store.close_run()
        self.temporary_directory.cleanup()

    def test_exact_action_binding_has_stable_digest(self):
        same = ActionBinding.model_validate(self.binding.model_dump())
        self.assertEqual(self.binding.digest(), same.digest())

    def test_changed_agent_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"agent_id": "other-agent"}).digest(),
        )

    def test_changed_task_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"task_id": "task-002"}).digest(),
        )

    def test_changed_step_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"step_id": "step-002"}).digest(),
        )

    def test_changed_capability_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"capability_id": "file.delete"}).digest(),
        )

    def test_changed_operation_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"operation": "DELETE"}).digest(),
        )

    def test_changed_resource_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"resource_id": "C:/other/file.txt"}).digest(),
        )

    def test_changed_parameters_change_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"parameters": {"mode": "write"}}).digest(),
        )

    def test_changed_destination_changes_digest(self):
        with_destination = self.binding.model_copy(
            update={"destination_id": "C:/other/destination.txt"}
        )
        self.assertNotEqual(self.binding.digest(), with_destination.digest())

    def test_changed_plan_version_changes_digest(self):
        self.assertNotEqual(
            self.binding.digest(),
            self.binding.model_copy(update={"plan_digest": "c" * 64}).digest(),
        )

    def test_valid_exact_action_approval_verifies(self):
        verified = self.manager.verify(
            self.evidence,
            expected_binding=self.binding,
            principal_id=self.binding.principal_id,
        )
        self.assertEqual(verified.approval_id, self.evidence.approval_id)

    def test_missing_approval_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                None,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_invalid_signature_is_rejected(self):
        tampered = self.evidence.model_copy(update={"signature": "0" * 64})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                tampered,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_expired_approval_is_rejected(self):
        now = datetime.now(timezone.utc)
        old = self.manager.issue(
            self.binding,
            now=now - timedelta(minutes=10),
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                old,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
                now=now,
            )

    def test_expired_approval_persists_expiration_transition(self):
        now = datetime.now(timezone.utc)
        old = self.manager.issue(
            self.binding,
            now=now - timedelta(minutes=10),
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                old,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
                now=now,
            )
        self.assertEqual(
            self.store.get_approval_state(old.approval_id),
            "EXPIRED",
        )

    def test_approval_longer_than_maximum_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.manager.issue(
                self.binding,
                lifetime=timedelta(minutes=16),
            )

    def test_future_issued_approval_is_rejected(self):
        future = datetime.now(timezone.utc) + timedelta(minutes=1)
        evidence = self.manager.issue(
            self.binding,
            now=future,
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                evidence,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_principal_is_rejected(self):
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=self.binding,
                principal_id="different-principal",
            )

    def test_wrong_agent_binding_is_rejected(self):
        other = self.binding.model_copy(update={"agent_id": "other-agent"})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_task_binding_is_rejected(self):
        other = self.binding.model_copy(update={"task_id": "other-task"})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_step_binding_is_rejected(self):
        other = self.binding.model_copy(update={"step_id": "other-step"})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_capability_binding_is_rejected(self):
        other = self.binding.model_copy(update={"capability_id": "file.delete"})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_operation_binding_is_rejected(self):
        other = self.binding.model_copy(update={"operation": "DELETE"})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_resource_binding_is_rejected(self):
        other = self.binding.model_copy(
            update={"resource_id": "C:/temporary/workspace/other.txt"}
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_wrong_destination_binding_is_rejected(self):
        other = self.binding.model_copy(
            update={"destination_id": "C:/temporary/workspace/other.txt"}
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_changed_parameters_binding_is_rejected(self):
        other = self.binding.model_copy(
            update={"parameters": {"mode": "write", "content_sha256": "d" * 64}}
        )
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_changed_plan_binding_is_rejected(self):
        other = self.binding.model_copy(update={"plan_digest": "e" * 64})
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=other,
                principal_id=self.binding.principal_id,
            )

    def test_single_use_approval_consumes_and_replay_is_rejected(self):
        self.manager.consume(
            self.evidence,
            expected_binding=self.binding,
            principal_id=self.binding.principal_id,
        )
        self.assertEqual(self.store.get_approval_state(self.evidence.approval_id), "CONSUMED")
        with self.assertRaises(ApprovalError):
            self.manager.consume(
                self.evidence,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_two_concurrent_consumers_allow_only_one(self):
        barrier = threading.Barrier(2)

        def consume():
            barrier.wait(timeout=5)
            try:
                self.manager.consume(
                    self.evidence,
                    expected_binding=self.binding,
                    principal_id=self.binding.principal_id,
                )
                return "CONSUMED"
            except ApprovalError:
                return "REJECTED"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: consume(), range(2)))
        self.assertEqual(results.count("CONSUMED"), 1)
        self.assertEqual(results.count("REJECTED"), 1)
        self.assertEqual(self.store.get_approval_state(self.evidence.approval_id), "CONSUMED")

    def test_missing_lifecycle_record_fails_closed(self):
        with closing(self.store._connect()) as connection:
            connection.execute(
                "DELETE FROM approval_lifecycle WHERE approval_id=?",
                (self.evidence.approval_id,),
            )
            connection.commit()
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_database_failure_fails_closed(self):
        with patch.object(
            self.store,
            "get_approval_state",
            side_effect=LocalStoreError("simulated database outage"),
        ):
            with self.assertRaises(LocalStoreError):
                self.manager.verify(
                    self.evidence,
                    expected_binding=self.binding,
                    principal_id=self.binding.principal_id,
                )

    def test_approval_verifier_exception_fails_closed(self):
        with patch(
            "app.security.approval.hmac.compare_digest",
            side_effect=RuntimeError("verification unavailable"),
        ):
            with self.assertRaises(RuntimeError):
                self.manager.verify(
                    self.evidence,
                    expected_binding=self.binding,
                    principal_id=self.binding.principal_id,
                )

    def test_revoked_approval_is_rejected(self):
        self.manager.revoke(
            self.evidence,
            expected_binding=self.binding,
            principal_id=self.binding.principal_id,
        )
        self.assertEqual(self.store.get_approval_state(self.evidence.approval_id), "REVOKED")
        with self.assertRaises(ApprovalError):
            self.manager.verify(
                self.evidence,
                expected_binding=self.binding,
                principal_id=self.binding.principal_id,
            )

    def test_approval_transition_audit_is_persisted(self):
        self.manager.consume(
            self.evidence,
            expected_binding=self.binding,
            principal_id=self.binding.principal_id,
        )
        with closing(self.store._connect()) as connection:
            events = connection.execute(
                "SELECT event_type, approval FROM audit_events WHERE event_type LIKE 'APPROVAL_%'"
            ).fetchall()
        self.assertEqual(
            [(row["event_type"], row["approval"]) for row in events],
            [
                ("APPROVAL_CREATED", "ACTIVE"),
                ("APPROVAL_STATE_CHANGED", "CONSUMED"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
