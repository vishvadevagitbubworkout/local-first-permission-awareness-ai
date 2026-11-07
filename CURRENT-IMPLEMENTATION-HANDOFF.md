# Current Implementation Handoff

## Purpose

This file summarizes the current state of the local-first, permission-aware desktop automation project for handing to another ChatGPT session or reviewer.

Project:

**Local-First, Permission-Aware Multi-Agent Desktop Automation with Task-Scoped Capabilities**

The implementation is a local Windows/Python application using SQLite persistence and local Ollama where the planner requires LLM reasoning.

## Current Pipeline

```text
User request
    -> M1 Local AI Planner
    -> M2 Task-Intent Consistency Validator
    -> M3 Capability Template / Resolver
    -> M4 Permission Manager
    -> M5 Capability Security and Lifecycle
    -> Execution Gateway
    -> M6 File Adapter / Executor
    -> SQLite journal and audit trail
```

The current execution gateway supports **FILE_READ only**. Mutation operations are deliberately denied before adapter dispatch.

## Work Completed

### M1: Local AI Planner

M1 converts a natural-language request into a structured proposal.

Implemented behavior includes:

- Local Ollama integration at `http://localhost:11434`.
- Configured local model in the current source: `rafw007/qwen35-claude-coder:4b`.
- Structured Pydantic-validated planner output.
- Planner intent whitelist:
  - `LIST`
  - `READ`
  - `MOVE`
  - `RENAME`
  - `BROWSER_OPEN`
  - `EMAIL_DRAFT`
  - `EMAIL_SEND`
  - `ASK_CLARIFICATION`
- Developer-defined template identifiers are represented as proposal data.
- Confidence values are validated from `0.0` to `1.0`.
- Confidence below `0.70` is routed to `ASK_CLARIFICATION`.
- Opaque file references use `file_...` identifiers rather than raw filesystem paths.
- Raw shell commands, absolute filesystem paths, HMAC instructions, permission instructions, and capability-creation instructions are rejected as planner output.
- M1 never executes the requested operation.

M1 remains a proposal generator. It does not authorize actions, mint capabilities, generate HMACs, or access the desktop.

### M2: Task-Intent Consistency

M2 checks whether the generated plan corresponds to the original user request.

Implemented behavior includes:

- Strict `IntentCheckResult` parsing.
- Whole-plan validation.
- Multi-step and multi-agent plans are allowed when they support the same goal.
- Unrelated browser, email, file, and second-step actions can be marked mismatched.
- Resource/entity comparison is included in the semantic prompt.
- Deterministic checks detect obvious resource-scope broadening.
- Deterministic checks detect obvious recipient changes.
- Empty plans return an inconsistent result.
- M2 does not authorize, grant permissions, mint capabilities, generate HMACs, or execute actions.

### Day 1 Security Hardening

The existing security layer was strengthened with:

- Audit-log redaction for common credential and bearer-token patterns.
- Capability future-issue rejection.
- Capability maximum lifetime enforcement.
- Capability lifecycle lookup repair.
- Regression tests for these controls.

The security layer uses HMAC-authenticated capabilities, context binding, expiry, revocation, and one-time lifecycle consumption. These are application controls, not OS-level isolation.

### Day 2 Execution Gateway

Implemented:

- `ExecutionGateway` as the mandatory application path for supported execution.
- FILE_READ operation support.
- Workspace containment checks.
- Caller, task, step, agent, capability, and M2 plan binding checks.
- M4 authorization-result integrity checks.
- M5 MAC, lifetime, context, lifecycle, replay, and revocation checks.
- Prepared-action re-resolution before dispatch.
- SQLite execution journal.
- Audit event before dispatch and outcome recording afterward.
- `PENDING`, `SUCCEEDED`, `FAILED`, and recovery-to-`UNKNOWN` handling.
- Internal dispatch token required by the low-level executor.
- Public file-skill execution route disabled outside the gateway.
- Unsupported operations denied before the general-purpose executor.

### Day 3 Exact-Action Approval Evidence

Implemented as a preparation for future mutation support:

- `ActionBinding` binds approval evidence to principal, agent, task, step, capability, operation, canonical resource, destination, parameters, and plan digest.
- `ApprovalEvidence` uses domain-separated HMAC-SHA-256.
- Five-minute default approval lifetime.
- Fifteen-minute maximum approval lifetime.
- Future-issued, expired, mismatched, invalid, revoked, and replayed evidence is rejected.
- Approval lifecycle records are persisted in SQLite.
- Concurrent approval consumption is tested.
- The gateway can verify or consume exact-action evidence.

Important: this is not yet a user-facing approval workflow. `principal_id` is currently caller-supplied and is not an authenticated identity. Mutation dispatch remains disabled.

## Current Files and Components

Important current components include:

- `app/gateway/execution_gateway.py`
- `app/workflow/pipeline.py`
- `app/skills/file_executor.py`
- `app/skills/file_management.py`
- `app/storage/local_store.py`
- `app/security/audit.py`
- `app/security/minting.py`
- `app/security/tokens.py`
- `app/security/verification.py`
- `app/security/approval.py`
- `tests/test_execution_gateway.py`
- `tests/test_approval_evidence.py`
- `tests/test_security_hardening.py`
- `DAY-2-EXECUTION-GATEWAY-REPORT.md`
- `DAY-3-EXACT-ACTION-APPROVAL-REPORT.md`
- `SECURITY-UPGRADE-REPORT.md`

## Test Status

Day 2 gateway report:

```text
41 tests, 40 passed, 0 failed, 1 skipped
```

The skipped test required Windows symlink creation, which was unavailable in that environment.

Day 3 approval report:

```text
78 tests, 77 passed, 0 failed, 1 skipped
```

The skipped test was again the Windows symlink test.

Additional verification reported:

```text
python -m compileall -q app tests       PASS
 git diff --check                       PASS
```

No destructive real-data tests were run. Tests used temporary directories and temporary SQLite databases.

## Independent Adversarial Validation

An independent Day 3 adversarial validation was executed without modifying
production security logic. The detailed evidence is in
[`DAY-3-ADVERSARIAL-VALIDATION-REPORT.md`](./DAY-3-ADVERSARIAL-VALIDATION-REPORT.md).

Required commands and results:

```text
python -m compileall -q app tests       exit 0
python -m pytest -q                     77 passed, 1 skipped
python -m unittest discover -s tests -v 78 tests, 77 passed, 1 skipped
git diff --check                        exit 0
```

Focused results:

```text
python -m pytest -q tests/test_execution_gateway.py    34 passed, 1 skipped
python -m pytest -q tests/test_approval_evidence.py    34 passed
python -m pytest -q tests/test_security_hardening.py    5 passed
```

The direct `pytest -q` executable had an import-path collection failure
(`ModuleNotFoundError: app`) in this environment. `python -m pytest` is the
reliable pytest invocation from the repository directory.

Adversarial scenario summary:

- 37 scenarios classified.
- 27 passed.
- 0 failed.
- 1 skipped because Windows symlink creation was unavailable.
- 9 not tested.

The final adversarial verdict was **INCONCLUSIVE**, not because an executed
security test failed, but because prompt injection, TOCTOU races, concurrent
gateway-request isolation, recovery idempotency, dedicated post-dispatch audit
failure, invalid dispatch-token variants, resource scope expansion, and full
information-leakage coverage were not independently established.

Additional synthetic checks passed:

- Credential-like values were redacted before audit persistence.
- SQLite append-only triggers blocked direct audit-row update and delete attempts.
- These triggers are not cryptographic tamper evidence; a privileged local
  process could still alter or replace the database outside the application.

## What the System Can Execute Now

Under the normal application pipeline, the only supported real-world operation is:

```text
FILE_READ
```

A successful read must pass the planner, intent validation, authorization, capability verification, lifecycle, workspace, prepared-action, audit, and gateway checks before the file adapter is called.

The supported read is confined to the configured workspace. The gateway rejects path traversal, outside-workspace targets, substituted resources, wrong task/step/agent context, invalid MACs, expired capabilities, revoked capabilities, replayed capabilities, and failed lifecycle or audit prerequisites.

The active runtime configuration should be checked in
[`app/core/config.py`](./app/core/config.py) before running a new handoff:

- Ollama host: `http://localhost:11434`
- Source default model: `rafw007/qwen35-claude-coder:4b`
- Working directory: configured by `M6_WORKING_DIRECTORY`, defaulting to the
  user's `OneDrive\\Desktop\\AI` path.

## Worst-Case Scenarios the Current System Could Still Execute

These are residual-risk scenarios, not claims that an attack was reproduced.

### 1. Authorized read of a sensitive file inside the workspace

If a file is inside the configured workspace and the application policy authorizes the read, the system can read it. There is currently no per-file sensitivity classification inside the workspace.

Impact:

- A private or sensitive file within the configured workspace could be read if policy and capability checks treat it as allowed.
- The system does not currently distinguish public and private files within the workspace.

Status: **Residual risk.** Workspace containment is implemented, but content sensitivity policy is not.

### 2. Prompt injection causes an unintended read proposal

A prompt injection or misleading request may cause M1 to propose an unwanted file read. M2 can detect some intent mismatches, and the gateway applies authorization and resource checks, but prompt-injection prevention is not implemented as a separate defense.

Impact:

- An unintended read may still occur if the generated proposal is semantically accepted and authorization permits the target.
- Files outside the workspace should be rejected, but sensitive files inside the workspace remain possible targets if authorized.

Status: **Partial protection.** Prompt-injection behavior was not independently tested.

### 3. Same-process Python code bypasses application conventions

The internal dispatch token and private Python methods prevent ordinary application routes from bypassing the gateway. They do not protect against hostile Python code already running in the same process.

Impact:

- Malicious same-process code could import internal classes or call lower-level methods directly.
- Python-level access controls are not an OS sandbox.

Status: **Known limitation.** Process isolation or OS policy is required for this threat.

### 4. Local signing key compromise

The capability and approval signing keys are stored locally. Their OS ACLs have not been independently verified.

Impact:

- A process that obtains the signing key may be able to forge capability or approval evidence.
- HMAC correctness does not help if the secret key is compromised.

Status: **Deployment-dependent risk.** Key ACL verification remains outstanding.

### 5. SQLite state or audit database tampering

Capability lifecycle, approval lifecycle, execution journals, and audit records rely on local SQLite storage.

Impact:

- A process able to modify the database may alter lifecycle or audit state.
- Audit rows are not cryptographically tamper-evident.

Status: **Known residual risk.** Database permissions and tamper evidence are not complete.

### 6. Filesystem TOCTOU race

Path validation and the later file open are separate operations.

Impact:

- A local actor changing filesystem entries between validation and open could create a time-of-check/time-of-use race.
- Canonical path resolution does not eliminate all Windows reparse-point or concurrent-change risks.

Status: **Not eliminated.** Handle-relative or no-follow file-opening strategies remain future work.

### 7. Uncertain outcome after crash or persistence failure

The SQLite journal and filesystem read cannot form one atomic transaction.

Impact:

- A capability may be consumed while the final execution result is uncertain.
- A journal may remain `PENDING` until recovery marks it `UNKNOWN`.
- The system does not automatically retry uncertain actions.

Status: **Conservative recovery implemented.** Exactly-once execution is not claimed.

### 8. Caller-supplied principal identity

The Day 3 approval model accepts a `principal_id`, but the current system does not establish that it came from an authenticated user or OS identity.

Impact:

- A caller that can choose the principal identifier may misrepresent identity at the application layer.
- Approval evidence proves binding to the supplied identifier, not that a human actually approved it.

Status: **Not authenticated.** An identity source and user-facing approval flow are required before mutations are enabled.

### 9. Audit failure after the adapter has run

Pre-dispatch audit failure denies execution. Post-adapter audit/database failure is not fully independently tested.

Impact:

- A read may complete while its final audit outcome is not durably recorded.
- Recovery may later classify the journal as `UNKNOWN`.

Status: **Partial coverage.** More post-dispatch failure tests are required.

### 10. Unsupported mutation attempt

The current pipeline rejects mutations such as file creation, deletion, move, or rename before adapter dispatch.

Impact:

- The system should not execute these through the application pipeline today.
- They are unavailable rather than safely supported.

Status: **Denied by default.** Mutation support is not implemented.

### 11. Validation gaps are not security passes

The following must remain labeled as unverified rather than treated as secure:

- Prompt-injection resistance.
- Filesystem TOCTOU/race resistance.
- Cross-request concurrency isolation.
- Repeated recovery idempotency.
- Dedicated post-dispatch audit failure behavior.
- Authenticated principal identity.
- Hostile same-process isolation.

## What the System Cannot Execute Through the Normal Pipeline

The normal pipeline currently denies:

- File creation
- File deletion
- File move
- File rename
- Browser opening
- Browser navigation
- Email drafting
- Email sending
- Shell commands
- Arbitrary desktop automation
- Automatic capability creation by M1 or M2

The application should not be described as a general desktop automation system yet. It is currently a guarded FILE_READ proof milestone with security and approval infrastructure prepared for later expansion.

## Remaining Work

### Day 3 follow-up

1. Authenticate the principal identity.
2. Add a real user-facing approval flow.
3. Consume approval evidence only after final action validation and immediately before dispatch.
4. Keep mutations disabled until mutation-specific path, race, recovery, and adapter tests exist.

### Gateway and filesystem safety

5. Add per-resource sensitivity or allowlist policy inside the workspace.
6. Evaluate Windows handle-relative and reparse-safe file opening.
7. Test symlinks and junctions in an environment that permits safe fixture creation.
8. Test post-adapter audit/database failures and crash points.
9. Define signing-key and SQLite ACL requirements.
10. Decide whether audit records require cryptographic tamper evidence.
11. Add OS/process isolation if hostile same-process code is in scope.

### Later module work

12. Integrate `LIST` through the gateway if required.
13. Integrate each mutation separately with exact-action approval and gateway tests.
14. Complete multi-agent orchestration.
15. Build the security/evaluation benchmark.
16. Run empirical prompt-injection, scope, replay, concurrency, and recovery experiments.
17. Conduct any planned user study.

## Important Non-Claims

This project does **not** currently claim:

- OS-level sandboxing
- protection against hostile same-process Python code
- perfect prompt-injection prevention
- complete private-file classification
- exactly-once execution
- cryptographically tamper-proof audit storage
- authenticated human approval
- mutation support
- browser automation
- email automation
- benchmark or user-study results
- security certification

## Recommended Next Step

Before enabling any mutation, complete identity/authentication, user-facing approval issuance, exact-action consumption immediately before dispatch, mutation-specific gateway integration, Windows race/reparse testing, post-adapter failure testing, and OS/process isolation decisions.

Do not begin broad desktop automation until those controls are implemented and tested per operation.
