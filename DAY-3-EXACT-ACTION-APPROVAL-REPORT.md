# Day 3 Exact-Action Approval Report

## Result

**Partial milestone complete.** The project now has a signed, time-bounded, replay-resistant exact-action approval evidence model and SQLite lifecycle storage. The existing pipeline remains FILE_READ-only: no file mutation is enabled, and this work does not provide an authenticated-user or interactive approval flow.

## Implemented

- Added [`ActionBinding`](./app/security/approval.py#L29) to bind approval evidence to the principal identifier, agent, task, step, capability, operation, canonical resource and destination, parameters, and a digest of the complete plan. File content is represented by a SHA-256 digest rather than stored in approval evidence.
- Added [`ApprovalEvidence`](./app/security/approval.py#L62) and [`ApprovalManager`](./app/security/approval.py#L87). Evidence uses HMAC-SHA-256 with a domain separate from capability signatures, a five-minute default lifetime, a fifteen-minute maximum, and checks for future issue times, expiry, binding mismatch, signature mismatch, revocation, and replay.
- Added persistent approval lifecycle records and transitions in [`local_store.py`](./app/storage/local_store.py#L668). Creation and state changes are written to the existing audit store. Expiration is persisted when checked; consumption uses a SQLite transaction.
- Wired the manager into the gateway in [`pipeline.py`](./app/workflow/pipeline.py#L94). The gateway verifies exact evidence for mutation intents before its existing authorization path; [`verify_approval`](./app/gateway/execution_gateway.py#L209) can verify or explicitly consume evidence.
- Fixed a single-use race discovered by tests: a previously consumed approval was being returned with the same result marker as a newly consumed one. Consumption now distinguishes a newly consumed record from an already-consumed record.
- Added tests for action substitution, plan and content binding, signatures, timestamp limits, expiration persistence, revocation, replay, concurrent consumption, gateway integration, and uncertain post-adapter journal outcomes.

## Current execution and approval flow

For regular application requests, the pipeline continues to plan, validate, authorize, prepare, and dispatch FILE_READ through the mandatory gateway. It rejects non-READ operations before any mutation can execute.

The new approval evidence is exercised directly in tests: a prepared write action can be bound and verified, but a subsequent gateway execution attempt is still rejected because the gateway supports FILE_READ only. Evidence for a different principal is rejected before adapter dispatch. No real file write was performed.

The following are **not implemented**: a user-facing approval prompt that issues `ApprovalEvidence`, an authenticated identity source for `principal_id`, or mutation dispatch through the gateway. The current caller supplies `principal_id`; it must not be treated as authenticated identity. Before enabling mutations, approval consumption must be made part of the final authorization-and-dispatch sequence, after action validation and before adapter invocation.

## Security behavior and remaining limits

### Verified controls

- Exact-action and plan substitutions change the digest and are rejected.
- Invalid signatures, missing lifecycle records, expired or future-issued evidence, revoked evidence, and replay are rejected.
- Concurrent consumption tests allow only one successful consumer. The approval concurrency test passed 20 repeated runs; the gateway capability replay test passed 10 repeated runs.
- The gateway test confirms valid write approval evidence does not enable writes; the executor adapter is not called.
- If an adapter has run but the completion journal write fails, the journal remains pending and recovery marks it `UNKNOWN`. The action is not automatically retried; exactly-once execution is not claimed.

### Not established

- A principal identifier is not backed by a login, OS identity check, or authenticated approval UI.
- The local signing-key protection and SQLite tamper resistance have not been independently verified. Domain separation prevents cross-protocol signature reuse; it does not protect a compromised key.
- No OS sandbox or same-process isolation is added. Filesystem symlink/junction behavior, TOCTOU resistance, and hostile-local-process scenarios remain unproven.
- Exact approval issuance is an application API, not proof that a human reviewed or approved an action.
- Mutating operations remain disabled and have not been executed against real or temporary files.

## Verification

Commands run from the project directory:

```powershell
python -m unittest tests.test_approval_evidence tests.test_execution_gateway -v
python -m unittest discover -s tests -v
python -m compileall -q app tests
git diff --check
```

Final full-suite result: **78 tests, 77 passed, 0 failed, 1 skipped**, exit code 0; the unittest runner reported **3.304 seconds**. The skipped symlink test requires symlink creation, which this Windows environment did not permit. Compilation succeeded and `git diff --check` was clean.

No dependencies were installed or changed. No secrets or `.env` contents were read. No destructive tests, commits, or pushes were performed.

## Before enabling mutation

1. Define and authenticate the principal; do not trust a caller-provided string as identity.
2. Connect an explicit approval UI/policy decision to exact evidence issuance.
3. Ensure approval is consumed once only after the gateway revalidates the action and immediately before dispatch.
4. Keep mutation adapters disabled until path/reparse-point validation, race resistance, and mutation-specific recovery tests are in place.
5. Test audit/database failure at each pre- and post-dispatch boundary, retaining `UNKNOWN` rather than retrying uncertain actions.
