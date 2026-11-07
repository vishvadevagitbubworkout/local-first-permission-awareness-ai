# Day 1 Security Upgrade Report

## What you asked for

You asked for a read-only, evidence-based Day 1 security architecture audit of the existing M1–M6 local-first automation project, including its repository inventory, authorization lifecycle, privileged entry points, baseline tests, security gaps, and a proposed mandatory execution gateway. You then authorized discretionary upgrades and asked for a clear report of what was requested and what was implemented.

## Changes implemented

1. **Audit redaction:** common unquoted credential assignments (`password`, `token`, `api_key`, `secret`, `authorization`, and related labels) and bearer tokens are redacted before audit text is persisted. This is targeted pattern redaction, not a guarantee of detecting every secret format.
2. **Capability time bounds:** verification now rejects future-issued capabilities and lifetimes longer than one hour. Minting and verification share one maximum-lifetime constant.
3. **Lifecycle lookup defect:** removed an undefined-variable reference from the first capability-state lookup path.
4. **Regression tests:** added focused tests for the above behavior, including a valid short-lived capability and an isolated temporary SQLite database.

## Current security architecture

The application is a local CLI that processes a request through a staged authorization path:

1. **M1 planning** turns user input into a proposed task plan. A local Ollama model may assist; model output is treated as a proposal.
2. **M2 intent validation** checks the plan and records a plan-bound validation result.
3. **M3 capability registry** restricts actions to developer-defined capability templates.
4. **M4 permission manager** evaluates policy and requests confirmation for mutating actions.
5. **M5 capability security** issues HMAC-authenticated, context-bound capabilities; the verifier checks the claims and time bounds, while lifecycle storage enforces expiry, revocation, and one-time use.
6. **M6 execution** checks authorization, validation, capability context, and the prepared action before calling the file operation.
7. **SQLite storage** records lifecycle state, execution status, and audit events.

The principal flow is `CLI -> pipeline -> planner -> intent validator -> authorization/approval -> capability mint and verify -> lifecycle consume -> file skill/executor -> audit/storage`. The CLI is the user-facing boundary; no remote API gateway or OS-level sandbox was identified in the audit. Detailed source locations are in the Day 1 audit conversation; this upgrade report summarizes the current design rather than reprinting the full audit.

## Security strength and limits

**Assessment: moderate baseline for a single-user local application; not independently certified or demonstrated safe against a hostile process running as the same user.** This is a qualitative assessment based on source review and nine focused unit tests, not a formal rating or penetration test.

**What is comparatively strong:** the design separates planning from authorization, uses a fixed capability allowlist, binds capability claims to task/step/action/resource context, verifies HMACs, limits capability lifetime, consumes one-time capabilities transactionally, requires approval for mutating actions in the CLI path, and rechecks the prepared action before execution.

**What limits confidence:** tests do not cover the full authorization/execution path, concurrent requests, filesystem races, or crash recovery. Python in-process APIs are not security boundaries against malicious code in the same process. Key-file ACLs and audit database access controls have not been verified. Filesystem validation and later operations may be vulnerable to a race if another local process can alter the workspace. Audit redaction is pattern-based and cannot guarantee detection of every secret.

## Three worst-case scenarios

These are threat scenarios, not claims that an attack was reproduced.

1. **Malicious or misleading request/model output leads to an unintended file mutation.** The current design routes proposed actions through intent checks, policy, approval, capability checks, and prepared-action validation. A normal CLI mutating action requires confirmation. However, end-to-end adversarial prompt tests have not been run, and the project has no isolated execution gateway or OS sandbox. **Impact if all application checks are bypassed or a user approves the wrong action:** files within the process user's permitted workspace could be changed or deleted. **Current status:** mitigations exist; bypass is unproven; least-privilege workspace permissions and end-to-end negative tests remain important.
2. **Signing key or local account is compromised.** The capability signing key is stored locally, and OS ACLs were not inspected. A party able to read the key and access or invoke the application may undermine capability authenticity; a party able to alter the SQLite database may also undermine local lifecycle/audit records. **Impact:** forged or replayed authority may become possible depending on access to the application and state store. **Current status:** key protections and database tamper resistance are deployment-dependent and unverified; the audit database is not cryptographically tamper-evident.
3. **A filesystem race or process crash occurs during an approved action.** Path checks happen before the later file operation, leaving a possible time-of-check/time-of-use window if another local process can change filesystem objects. Separately, capability consumption and execution journaling are not one atomic filesystem/database transaction. **Impact:** a race could redirect an operation under suitable local conditions; a crash could leave a capability consumed while the action result is incomplete or uncertain. **Current status:** neither scenario was dynamically tested; use race-resistant filesystem APIs and add crash/concurrency recovery tests before treating this as high assurance.

## Verification

Run from the project directory:

```powershell
python -m unittest discover -s tests -v
```

The complete suite contains four existing planner/request-analysis tests and five new focused security-hardening tests.

**Final result:** 9 passed, 0 failed; exit code 0; elapsed time 0.968 seconds. The tests cover planner/request parsing, audit-redaction patterns, capability time-bound verification, and initial lifecycle lookup. They do not test concurrency, TOCTOU, gateway enforcement, or crash recovery.

## Not changed in this pass

- No mandatory execution gateway was implemented; its interface remains a proposal.
- No key-file ACL changes, OS-specific filesystem/TOCTOU redesign, audit database tamper-proofing, or crash-atomic execution redesign.
- No dependencies or Git history changed.
- No real-user-data or destructive tests were run. The `.env` file and secrets were not inspected.

These remaining items require explicit platform/threat-model decisions and dedicated tests. The current changes narrow three concrete gaps; they are not a certification that all security risks are resolved.
