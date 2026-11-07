# Day 2 Execution Gateway Report

## Result

**Day 2 FILE_READ milestone: PASS.** The application pipeline now sends file reads through a mandatory gateway. A controlled read from a temporary workspace succeeds; the tested authorization failures are rejected before the adapter. Other file actions are deliberately denied in the application pipeline until they are integrated with the gateway.

This is an application-level control, not a process or OS security boundary. It is not a security certification.

## A. Architecture changes

- Added [`ExecutionGateway`](./app/gateway/execution_gateway.py#L32), which validates caller/task/step identity; M2 plan binding; integrity-checked M4 authorization; fixed M3 FILE_READ capability, resource, and constraints; the M5 MAC, lifetime, and expected context; current lifecycle state; and a newly prepared action before dispatch.
- The gateway limits supported operations to FILE_READ and confines resolved targets to the configured workspace. Other actions are denied rather than sent to the existing general-purpose executor.
- The gateway writes an execution-journal reservation and audit event before adapter dispatch. It records success/failure afterward. Pending outcomes are marked UNKNOWN during recovery or run closure; they are never automatically retried.
- The low-level executor now requires an internal dispatch token. The file skill’s public `execute()` route refuses direct dispatch. These mechanisms prevent ordinary application routes from bypassing the gateway; they are not isolation against hostile Python code in the same process.
- The existing capability, policy, verification, lifecycle, path-validation, and audit components were reused rather than replaced.

Key wiring: [`pipeline.py`](./app/workflow/pipeline.py#L87) constructs the gateway, rejects non-READ execution at line 275, and dispatches supported operations at line 407. The executor checks the dispatch token at [`file_executor.py`](./app/skills/file_executor.py#L159). The skill entry point rejects direct dispatch at [`file_management.py`](./app/skills/file_management.py#L37).

## B. Files created

- [`app/gateway/__init__.py`](./app/gateway/__init__.py)
- [`app/gateway/execution_gateway.py`](./app/gateway/execution_gateway.py)
- [`tests/test_execution_gateway.py`](./tests/test_execution_gateway.py)
- This report.

## C. Files modified for Day 2

- [`app/workflow/pipeline.py`](./app/workflow/pipeline.py)
- [`app/skills/file_executor.py`](./app/skills/file_executor.py)
- [`app/skills/file_management.py`](./app/skills/file_management.py)
- [`app/storage/local_store.py`](./app/storage/local_store.py)

The worktree already contained Day 1 changes when Day 2 began. Those existing changes in `app/security/audit.py`, `app/security/minting.py`, `app/security/tokens.py`, `app/security/verification.py`, `tests/test_security_hardening.py`, and `SECURITY-UPGRADE-REPORT.md` were preserved. Day 2 also extended the already-modified `local_store.py`.

## D. Existing modules reused

- **M3/M4:** capability resolver and permission manager.
- **M2:** validated-intent provenance and plan binding.
- **M5:** capability minter, HMAC verifier, and lifecycle store.
- **M6:** prepared file actions, existing path validation, and filesystem executor.
- **Persistence/audit:** existing SQLite store and audit trail.

## E. Modules replaced

**None.** The pipeline’s direct skill execution call was replaced with gateway dispatch. The existing skill’s public execution route was changed to reject calls outside the gateway.

## F. Gateway call flow

`CLI -> M1 planner -> M2 validator -> M3/M4 authorization -> M5 mint and verify -> prepare file action -> ExecutionGateway -> M4/M2/M3/M5/context/resource and lifecycle-state checks -> audit and PENDING journal -> atomic lifecycle consume in the executor -> FILE_READ adapter -> SUCCEEDED/FAILED journal and audit`.

The gateway re-resolves the prepared action and rejects a substituted target. The target must resolve beneath the configured workspace. M6 also retains its own validation. Existing `FileSystemExecutor` methods remain technically importable by in-process Python code; the dispatch token and disabled skill entry point are not an OS isolation mechanism.

## G. Security invariant coverage

| Invariant | Status | Evidence |
|---|---|---|
| S1 Gateway mediates supported application actions | **PASS, FILE_READ only** | Pipeline dispatch and non-READ denial tests. |
| S2 Invalid HMAC denied | **PASS** | Tampered-MAC test asserts adapter is not called. |
| S3 Expired capability denied | **PASS** | Expiry test. |
| S4 Future-issued capability denied | **PASS** | Future timestamp test. |
| S5–S7 Agent/task/subtask binding | **PASS** | Wrong-agent, wrong-task, wrong-subtask tests. |
| S8 Resource scope and workspace | **PASS for tested boundaries** | Resource substitution, traversal, and outside-workspace tests. |
| S9 Operation scope | **PASS** | Non-READ operation tests. |
| S10 Action parameter substitution | **PASS for current read contract** | Changed parameters and prepared-action substitution tests. |
| S11 Approval required for mutation | **PASS by default denial; approval workflow not supported** | Mutations are rejected before approval or adapter dispatch. Exact-action approval binding is **not implemented** for future mutating gateway actions. |
| S12 Revocation | **PASS** | Revoked capability test. |
| S13 One-time replay | **PASS** | Sequential replay test. |
| S14 Concurrent replay | **PASS** | Two simultaneous attempts produce one success and one rejection; journal states checked. |
| S15 Lifecycle storage failure | **PASS for simulated failure** | No adapter invocation on storage error. |
| S16 Token verification failure | **PASS for simulated failure** | No adapter invocation. |
| S17 Resource resolution failure | **PASS for simulated failure** | No adapter invocation. |
| S18 Adapter only after authorization | **PASS for tested denial paths** | Adapter spies remain uncalled. |
| S19 Audit failure | **PARTIAL** | Pre-dispatch audit failure denies before adapter; post-read audit-storage failure was not independently tested. |
| S20 Uncertain outcome handling | **PASS for tested recovery path** | Pending journal entry becomes UNKNOWN; no retry is attempted. |

Symlink/reparse-point rejection is implemented in existing path checks, but the symlink test was **skipped** because this Windows environment did not permit symlink creation.

## H. Worst-case scenario results

1. **Prompt injection requests a private file:** **PARTIAL.** A file outside the configured workspace is denied before adapter dispatch. There is no per-file sensitivity classification inside the workspace; files within that workspace remain readable under the existing READ policy. Prompt-injection behavior was not tested.
2. **Resource changes after review/approval:** **PARTIAL.** Current FILE_READ requests are bound to M2 plan/task/step, capability context, and re-resolved prepared resource; tested substitutions are denied. Mutating actions and exact-action approval evidence are not supported by this gateway yet.
3. **Capability reused for another task:** **PASS for tested cases.** Task/step context mismatch and sequential or concurrent reuse are rejected before a second adapter execution.

Invalid MAC, SQLite failure, pending-journal recovery, and direct skill/executor calls without the internal dispatch token were also tested. No attacker workflow or destructive real-data test was run.

## I. Test command

Run from the project directory:

```powershell
python -m unittest discover -s tests -v
```

## J. Actual test result

Final run: **41 tests, 40 passed, 0 failed, 1 skipped**, exit code 0. The runner reported `Ran 41 tests in 1.614s`; measured command elapsed time was **2.509 seconds**.

The single skipped test was `test_symlink_resource_is_rejected_when_supported`, skipped because symlink creation was not permitted.

### Gateway test names

`test_adapter_exception_is_journaled_as_failed`, `test_audit_failure_denies_before_adapter`, `test_changed_action_parameters_are_rejected`, `test_concurrent_consumption_allows_at_most_one_execution`, `test_consumed_single_use_capability_cannot_be_replayed`, `test_direct_executor_call_without_gateway_dispatch_token_is_denied`, `test_direct_executor_call_without_trusted_m4_result_is_denied`, `test_excessive_capability_lifetime_is_rejected`, `test_execution_journal_marks_pending_outcome_unknown_after_recovery`, `test_expired_capability_is_rejected`, `test_explicit_file_outside_configured_workspace_is_rejected`, `test_file_skill_public_execute_route_is_disabled`, `test_future_issued_capability_is_rejected`, `test_gateway_rejects_non_read_before_adapter_dispatch`, `test_invalid_hmac_is_rejected_before_adapter`, `test_lifecycle_state_lookup_failure_denies_before_adapter`, `test_lifecycle_storage_failure_denies_before_adapter`, `test_missing_lifecycle_record_is_created_and_consumed`, `test_mutating_action_without_approval_is_rejected`, `test_path_traversal_substitution_is_rejected`, `test_pipeline_denies_mutating_action_before_execution`, `test_resource_resolver_exception_denies_before_adapter`, `test_revoked_capability_is_rejected`, `test_sqlite_journal_failure_denies_before_adapter`, `test_symlink_resource_is_rejected_when_supported`, `test_unauthorized_operation_is_rejected`, `test_unauthorized_resource_substitution_is_rejected`, `test_valid_file_read_succeeds_through_mandatory_pipeline_gateway`, `test_verifier_exception_denies_before_adapter`, `test_wrong_agent_is_rejected`, `test_wrong_subtask_is_rejected`, and `test_wrong_task_is_rejected`.

The other nine tests are the four original request-analysis tests and five Day 1 regression tests. All test files are under [`tests/`](./tests/).

## K. Known vulnerabilities and residual risks

- No exact-action approval digest or mutation approval flow has been added. Mutating operations are currently blocked.
- Python private names and the internal dispatch object do not protect against malicious same-process code. Such code can import internals or invoke private methods; process separation or OS policy is required for that threat.
- Reads are workspace-bounded, but the entire configured workspace is not classified into public/private resources.
- Filesystem validation and file open are separate operations. A local actor able to change workspace entries concurrently may create a TOCTOU race.
- SQLite execution journaling and filesystem effects cannot form one atomic transaction. UNKNOWN prevents automatic retry but cannot determine whether a future non-read operation completed.
- The signing-key ACLs and SQLite file ACLs remain unverified. Local audit rows are not cryptographically tamper-evident.
- Audit redaction remains pattern-based and cannot guarantee discovery of every secret format.
- Concurrency was tested for two simultaneous attempts to consume one one-time capability. Prompt-injection, database-tampering, compromised-account, and crash-at-every-instruction-point tests were not performed.

## L. Windows-specific limitations

- Symlink creation was blocked by the current environment, so symlink behavior is **NOT TESTED** here. Existing checks also inspect Windows reparse-point attributes, but junction/reparse behavior was not dynamically tested.
- The workspace containment check uses resolved paths, but Windows file identity and reparse-point changes can still race after validation. No handle-relative/no-follow open implementation was added; do not treat canonicalization as race elimination.

## M. Execution journal and recovery semantics

- Gateway reserves `PENDING` before lifecycle consumption and adapter invocation.
- After successful read, the journal becomes `SUCCEEDED`; a handled adapter/lifecycle failure becomes `FAILED`.
- On process recovery or run closure, any remaining `PENDING` record becomes `UNKNOWN`. The application does not automatically retry it.
- If SQLite fails before the PENDING reservation, the adapter is not invoked. If persistence fails after a read occurred, the caller receives an explicit error; the durable record may remain PENDING until recovery marks it UNKNOWN.
- This is conservative recovery, not exactly-once execution. A read has no file mutation to undo; future mutations need a separate explicit reconciliation policy.

## N. Day 3 remaining work

1. Add exact-action approval evidence (principal, agent, task, step, operation, canonical resource, parameters/destination) before re-enabling any mutation; test digest substitution.
2. Decide whether LIST and each mutation should be supported, then route each through the gateway individually. Keep unsupported actions denied until that work and its tests are complete.
3. Add a per-resource allowlist or sensitivity policy within the workspace.
4. Evaluate Windows handle-based/reparse-safe file opening and document any remaining TOCTOU exposure.
5. Test storage failures after adapter completion and crash points around reservation, lifecycle consumption, adapter return, and outcome persistence.
6. Test symlink/junction behavior on a Windows environment where those test fixtures can be created safely.
7. Define key/database ACL requirements and whether audit tamper evidence is needed.
8. Add an OS/process isolation boundary if protection against hostile same-user code is in scope.

## O. GitHub and real-data confirmation

No GitHub push or Git history change was performed. Tests used temporary directories and temporary SQLite databases. No destructive operation against real user files was run, no dependencies were installed, and `.env` secrets were not inspected.

## Acceptance summary

- **PASS:** controlled FILE_READ succeeds through the mandatory pipeline gateway.
- **PASS:** implemented negative cases reject before adapter invocation.
- **PASS:** sequential and concurrent one-time replay tests allow at most one read.
- **PASS:** execution-journal recovery marks uncertain pending work UNKNOWN without retry.
- **NOT IMPLEMENTED:** mutation support and exact-action approval binding.
- **NOT TESTED:** symlink/reparse behavior in this environment, post-adapter audit/database outage behavior, and hostile same-process isolation.
