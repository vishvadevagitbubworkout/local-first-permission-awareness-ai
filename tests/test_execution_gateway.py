import sqlite3
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from app.agents.planner import Planner
from app.core.task_plan import PlannerIntent
from app.security.approval import ApprovalManager, build_action_binding
from app.security.audit import AuditTrail
from app.security.lifecycle import CapabilityLifecycleStore
from app.security.minting import CapabilityMinter
from app.security.permissions import (
    AuthorizationResult,
    PermissionDecision,
    PermissionScope,
    PermissionScopeKind,
    TaskAuthorizationManager,
)
from app.security.tokens import (
    AuthenticatedCapability,
    CapabilityClaims,
    CapabilityKeyProvider,
    UsagePolicy,
    compute_mac,
)
from app.security.verification import CapabilityVerifier
from app.skills.file_executor import FileSystemExecutor, M6ExecutionError
from app.skills.registry import SkillExecutionContext, SkillExecutionError
from app.storage.local_store import LocalAutomationStore, LocalStoreError
from app.validation.intent import IntentValidator
from app.workflow.pipeline import M1M6Pipeline


class ExecutionGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "sample.txt").write_text("approved test content", encoding="utf-8")
        self.database_path = self.root / "state.sqlite"
        self.store = LocalAutomationStore(self.database_path)
        self.key_provider = CapabilityKeyProvider.for_testing(
            b"execution-gateway-test-signing-key"
        )
        self.verifier = CapabilityVerifier(key_provider=self.key_provider)
        self.lifecycle = CapabilityLifecycleStore(
            verifier=self.verifier,
            store=self.store,
        )
        self.executor = FileSystemExecutor(
            verifier=self.verifier,
            lifecycle=self.lifecycle,
            working_directory=self.workspace,
        )
        self.authorizer = TaskAuthorizationManager()
        self.minter = CapabilityMinter(
            key_provider=self.key_provider,
            resolver=self.authorizer.resolver,
        )
        self.planner = Planner()
        self.validator = IntentValidator()
        self.pipeline = M1M6Pipeline(
            planner=self.planner,
            validator=self.validator,
            authorizer=self.authorizer,
            minter=self.minter,
            verifier=self.verifier,
            lifecycle=self.lifecycle,
            executor=self.executor,
            audit_trail=AuditTrail(self.store),
        )
        self.plan = self.planner.create_plan("Read sample.txt")
        self.step = self.plan.steps[0]
        self.intent_result = self.validator.validate(self.plan)
        self.scope = PermissionScope(
            resource_type=self.authorizer.resolver.resolve_step(self.step).resource_type,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
            resource_id=self.step.resource,
        )
        self.authorization = self.authorizer.authorize_step(
            self.plan,
            self.intent_result,
            self.step.step_id,
            scope=self.scope,
        )
        self.capability = self.minter.mint(
            self.authorization,
            self.plan,
            self.step,
        )
        self.verified = self.verifier.verify(
            self.capability,
            expected_task_id=self.plan.task_id,
            expected_step_id=self.step.step_id,
            expected_agent=self.step.agent,
            expected_operation=self.step.operation,
            expected_resource=self.step.resource,
            expected_scope=self.scope,
        )
        self.skill = self.pipeline.skills.get("file_manager")
        self.prepared = self.skill.prepare(self.plan, self.step)

    def tearDown(self):
        self.store.close_run()
        self.temporary_directory.cleanup()

    def _execute(self, **overrides):
        values = {
            "agent_id": self.step.agent,
            "task_id": self.plan.task_id,
            "subtask_id": self.step.step_id,
            "authorization": self.authorization,
            "capability": self.verified,
            "task_plan": self.plan,
            "step": self.step,
            "intent_result": self.intent_result,
            "prepared": self.prepared,
            "execution_id": uuid.uuid4().hex,
        }
        values.update(overrides)
        return self.pipeline.gateway.execute(**values)

    def _resign(self, *, issued_at=None, expires_at=None):
        claims_data = self.capability.claims.model_dump(mode="python")
        if issued_at is not None:
            claims_data["issued_at"] = issued_at
        if expires_at is not None:
            claims_data["expires_at"] = expires_at
        claims = CapabilityClaims.model_validate(claims_data)
        key = self.key_provider.get_signing_key()
        return AuthenticatedCapability(
            claims=claims,
            mac=compute_mac(claims, key),
        )

    def test_valid_file_read_succeeds_through_mandatory_pipeline_gateway(self):
        plan, intent, results = self.pipeline.run("Read sample.txt")

        self.assertTrue(intent.consistent)
        self.assertEqual(plan.steps[0].intent, PlannerIntent.READ)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].decision, "ALLOW")
        self.assertEqual(results[0].output, "approved test content")

    def test_invalid_hmac_is_rejected_before_adapter(self):
        tampered = self.capability.model_dump(mode="python")
        tampered["mac"] = "0" * 64
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(capability=tampered)
        adapter.assert_not_called()

    def test_expired_capability_is_rejected(self):
        now = datetime.now(timezone.utc)
        expired = self._resign(
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(capability=expired)
        adapter.assert_not_called()

    def test_future_issued_capability_is_rejected(self):
        issued_at = datetime.now(timezone.utc) + timedelta(minutes=1)
        future = self._resign(
            issued_at=issued_at,
            expires_at=issued_at + timedelta(minutes=5),
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(capability=future)
        adapter.assert_not_called()

    def test_excessive_capability_lifetime_is_rejected(self):
        issued_at = datetime.now(timezone.utc)
        excessive = self._resign(
            issued_at=issued_at,
            expires_at=issued_at + timedelta(hours=1, microseconds=1),
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(capability=excessive)
        adapter.assert_not_called()

    def test_wrong_agent_is_rejected(self):
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(agent_id="other-agent")
        adapter.assert_not_called()

    def test_wrong_task_is_rejected(self):
        other_plan = self.plan.model_copy(update={"task_id": "other-task"})
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(task_plan=other_plan)
        adapter.assert_not_called()

    def test_wrong_subtask_is_rejected(self):
        self.step.step_id = "other-step"
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_unauthorized_resource_substitution_is_rejected(self):
        substituted = replace(
            self.prepared,
            payload=replace(
                self.prepared.payload,
                target=self.workspace / "other.txt",
            ),
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(prepared=substituted)
        adapter.assert_not_called()

    def test_unauthorized_operation_is_rejected(self):
        self.step.intent = PlannerIntent.DELETE
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_changed_action_parameters_are_rejected(self):
        self.step.parameters = {"mode": "read", "limit": 1}
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_mutating_action_without_approval_is_rejected(self):
        create_plan = self.planner.create_plan("Create new.txt")
        create_step = create_plan.steps[0]
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(task_plan=create_plan, step=create_step)
        adapter.assert_not_called()

    def test_exact_write_approval_verifies_but_mutation_remains_disabled(self):
        plan = self.planner.create_plan("Write 'approved content' to result.txt")
        step = plan.steps[0]
        intent_result = self.validator.validate(plan)
        scope = PermissionScope(
            resource_type=self.authorizer.resolver.resolve_step(step).resource_type,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
            resource_id=step.resource,
        )
        authorization = self.authorizer.authorize_step(
            plan,
            intent_result,
            step.step_id,
            scope=scope,
        )
        self.assertEqual(authorization.decision, PermissionDecision.ASK_APPROVAL)
        authorization = self.authorizer.resolve_approval(
            authorization,
            plan,
            step.step_id,
            approved=True,
        )
        capability = self.minter.mint(authorization, plan, step)
        prepared = self.pipeline.skills.get("file_manager").prepare(plan, step)
        principal_id = "test-principal"
        approvals = ApprovalManager(
            store=self.store,
            key_provider=self.key_provider,
        )
        binding = build_action_binding(
            principal_id=principal_id,
            capability_id=authorization.capability_id,
            task_plan=plan,
            step=step,
            prepared=prepared,
        )
        evidence = approvals.issue(binding)

        self.assertEqual(
            self.pipeline.gateway.verify_approval(
                evidence,
                principal_id=principal_id,
                capability_id=authorization.capability_id,
                task_plan=plan,
                step=step,
                prepared=prepared,
            ),
            evidence,
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(
                    agent_id=step.agent,
                    task_id=plan.task_id,
                    subtask_id=step.step_id,
                    authorization=authorization,
                    capability=capability,
                    task_plan=plan,
                    step=step,
                    intent_result=intent_result,
                    prepared=prepared,
                    principal_id=principal_id,
                    approval_evidence=evidence,
                )
        adapter.assert_not_called()

    def test_write_approval_for_another_principal_is_rejected_before_adapter(self):
        plan = self.planner.create_plan("Write 'approved content' to result.txt")
        step = plan.steps[0]
        intent_result = self.validator.validate(plan)
        scope = PermissionScope(
            resource_type=self.authorizer.resolver.resolve_step(step).resource_type,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
            resource_id=step.resource,
        )
        authorization = self.authorizer.authorize_step(
            plan,
            intent_result,
            step.step_id,
            scope=scope,
        )
        authorization = self.authorizer.resolve_approval(
            authorization,
            plan,
            step.step_id,
            approved=True,
        )
        capability = self.minter.mint(authorization, plan, step)
        prepared = self.pipeline.skills.get("file_manager").prepare(plan, step)
        approvals = ApprovalManager(
            store=self.store,
            key_provider=self.key_provider,
        )
        binding = build_action_binding(
            principal_id="original-principal",
            capability_id=authorization.capability_id,
            task_plan=plan,
            step=step,
            prepared=prepared,
        )
        evidence = approvals.issue(binding)

        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(
                    agent_id=step.agent,
                    task_id=plan.task_id,
                    subtask_id=step.step_id,
                    authorization=authorization,
                    capability=capability,
                    task_plan=plan,
                    step=step,
                    intent_result=intent_result,
                    prepared=prepared,
                    principal_id="substituted-principal",
                    approval_evidence=evidence,
                )
        adapter.assert_not_called()

    def test_revoked_capability_is_rejected(self):
        self.lifecycle.revoke(self.verified)
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_consumed_single_use_capability_cannot_be_replayed(self):
        self._execute()
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_concurrent_consumption_allows_at_most_one_execution(self):
        barrier = __import__("threading").Barrier(2)

        def execute(index):
            barrier.wait(timeout=5)
            return self._execute(execution_id=f"parallel-{index}")

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(execute, index) for index in range(2)]
            outcomes = []
            for future in futures:
                try:
                    future.result()
                    outcomes.append("SUCCEEDED")
                except M6ExecutionError:
                    outcomes.append("REJECTED")

        self.assertEqual(outcomes.count("SUCCEEDED"), 1)
        self.assertEqual(outcomes.count("REJECTED"), 1)
        states = [
            self.store.get_gateway_execution_state("parallel-0"),
            self.store.get_gateway_execution_state("parallel-1"),
        ]
        self.assertEqual(states.count("SUCCEEDED"), 1)
        self.assertIn(
            next(state for state in states if state != "SUCCEEDED"),
            {None, "FAILED"},
        )

    def test_missing_lifecycle_record_is_created_and_consumed(self):
        query = """
            SELECT state FROM capability_lifecycle
            WHERE capability_id=? AND nonce=?
        """
        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                query,
                (
                    self.capability.claims.capability_id,
                    self.capability.claims.nonce,
                ),
            ).fetchone()
        self.assertIsNone(row)

        self._execute()
        with closing(sqlite3.connect(self.database_path)) as connection:
            row = connection.execute(
                query,
                (
                    self.capability.claims.capability_id,
                    self.capability.claims.nonce,
                ),
            ).fetchone()
        self.assertEqual(row[0], "USED")

    def test_sqlite_journal_failure_denies_before_adapter(self):
        with patch.object(
            self.store,
            "start_gateway_execution",
            side_effect=LocalStoreError("simulated storage outage"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(LocalStoreError):
                self._execute()
        adapter.assert_not_called()

    def test_lifecycle_storage_failure_denies_before_adapter(self):
        with patch.object(
            self.store,
            "consume_capability",
            side_effect=LocalStoreError("simulated lifecycle database outage"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_lifecycle_state_lookup_failure_denies_before_adapter(self):
        with patch.object(
            self.store,
            "get_capability_state",
            side_effect=LocalStoreError("simulated lifecycle lookup outage"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_verifier_exception_denies_before_adapter(self):
        with patch.object(
            self.verifier,
            "verify",
            side_effect=ValueError("verification unavailable"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_resource_resolver_exception_denies_before_adapter(self):
        with patch.object(
            self.executor,
            "prepare",
            side_effect=OSError("resource resolver unavailable"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_adapter_exception_is_journaled_as_failed(self):
        execution_id = uuid.uuid4().hex
        with patch.object(self.executor, "_perform", side_effect=OSError("read failed")):
            with self.assertRaises(M6ExecutionError):
                self._execute(execution_id=execution_id)

        self.assertEqual(
            self.store.get_gateway_execution_state(execution_id),
            "FAILED",
        )

    def test_post_adapter_journal_failure_becomes_unknown_on_recovery(self):
        execution_id = uuid.uuid4().hex
        with patch.object(
            self.store,
            "finish_gateway_execution",
            side_effect=LocalStoreError("simulated completion write failure"),
        ), patch.object(self.executor, "_perform", wraps=self.executor._perform) as adapter:
            with self.assertRaises(LocalStoreError):
                self._execute(execution_id=execution_id)

        adapter.assert_called_once()
        self.assertEqual(
            self.store.get_gateway_execution_state(execution_id),
            "PENDING",
        )
        self.store.close_run()
        self.assertEqual(
            self.store.get_gateway_execution_state(execution_id),
            "UNKNOWN",
        )

    def test_path_traversal_substitution_is_rejected(self):
        substituted = replace(
            self.prepared,
            payload=replace(
                self.prepared.payload,
                target=self.workspace.parent / "outside.txt",
            ),
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute(prepared=substituted)
        adapter.assert_not_called()

    def test_explicit_file_outside_configured_workspace_is_rejected(self):
        private_file = self.root / "private.txt"
        private_file.write_text("outside approved workspace", encoding="utf-8")
        plan = self.planner.create_plan(f'Read "{private_file}"')
        step = plan.steps[0]
        intent_result = self.validator.validate(plan)
        scope = PermissionScope(
            resource_type=self.authorizer.resolver.resolve_step(step).resource_type,
            kind=PermissionScopeKind.TASK,
            selector="current_task.resource",
            resource_id=step.resource,
        )
        authorization = self.authorizer.authorize_step(
            plan,
            intent_result,
            step.step_id,
            scope=scope,
        )
        capability = self.minter.mint(authorization, plan, step)
        prepared = self.skill.prepare(plan, step)

        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaisesRegex(M6ExecutionError, "outside the configured workspace"):
                self.pipeline.gateway.execute(
                    agent_id=step.agent,
                    task_id=plan.task_id,
                    subtask_id=step.step_id,
                    authorization=authorization,
                    capability=capability,
                    task_plan=plan,
                    step=step,
                    intent_result=intent_result,
                    prepared=prepared,
                    execution_id=uuid.uuid4().hex,
                )
        adapter.assert_not_called()

    def test_symlink_resource_is_rejected_when_supported(self):
        link = self.workspace / "linked.txt"
        try:
            link.symlink_to(self.workspace / "sample.txt")
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation is not permitted in this environment.")

        symlink_plan = self.planner.create_plan("Read linked.txt")
        with self.assertRaises(M6ExecutionError):
            self.executor.prepare(symlink_plan, symlink_plan.steps[0])

    def test_gateway_rejects_non_read_before_adapter_dispatch(self):
        self.step.intent = PlannerIntent.WRITE
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self._execute()
        adapter.assert_not_called()

    def test_execution_journal_marks_pending_outcome_unknown_after_recovery(self):
        execution_id = uuid.uuid4().hex
        self.store.start_gateway_execution(
            execution_id=execution_id,
            task_id=self.plan.task_id,
            step_id=self.step.step_id,
            capability_id=self.capability.claims.capability_id,
        )
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute(
                "UPDATE process_runs SET owner_pid=? WHERE run_id=?",
                (2147483647, self.store.run_id),
            )
            connection.commit()
        recovered = LocalAutomationStore(self.database_path)
        self.assertEqual(
            recovered.get_gateway_execution_state(execution_id),
            "UNKNOWN",
        )
        recovered.close_run()

    def test_audit_failure_denies_before_adapter(self):
        with patch.object(
            self.pipeline.gateway._audit,
            "record",
            side_effect=LocalStoreError("audit unavailable"),
        ), patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(LocalStoreError):
                self._execute()
        adapter.assert_not_called()

    def test_pipeline_denies_mutating_action_before_execution(self):
        with patch.object(self.executor, "_perform") as adapter:
            _, _, results = self.pipeline.run("Create new.txt")

        self.assertEqual(results[0].decision, "DENY")
        adapter.assert_not_called()

    def test_direct_executor_call_without_trusted_m4_result_is_denied(self):
        untrusted_authorization = AuthorizationResult(
            task_id=self.plan.task_id,
            step_id=self.step.step_id,
            capability_id=self.authorization.capability_id,
            decision=PermissionDecision.ALLOW,
            scope=self.scope,
            reason="caller-created authorization",
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaises(M6ExecutionError):
                self.executor.execute(
                    untrusted_authorization,
                    self.verified,
                    self.plan,
                    self.step,
                    self.intent_result,
                    self.prepared.payload,
                )
        adapter.assert_not_called()

    def test_direct_executor_call_without_gateway_dispatch_token_is_denied(self):
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaisesRegex(
                M6ExecutionError,
                "mandatory execution gateway",
            ):
                self.executor.execute(
                    self.authorization,
                    self.verified,
                    self.plan,
                    self.step,
                    self.intent_result,
                    self.prepared.payload,
                )
        adapter.assert_not_called()

    def test_file_skill_public_execute_route_is_disabled(self):
        context = SkillExecutionContext(
            authorization=self.authorization,
            capability=self.verified,
            task_plan=self.plan,
            step=self.step,
            intent_result=self.intent_result,
            prepared=self.prepared,
        )
        with patch.object(self.executor, "_perform") as adapter:
            with self.assertRaisesRegex(
                SkillExecutionError,
                "mandatory execution gateway",
            ):
                self.skill.execute(context)
        adapter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
