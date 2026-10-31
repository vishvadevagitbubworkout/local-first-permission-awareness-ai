from app.validation.intent import IntentParsingError
from app.providers.ollama import OllamaError
from app.agents.planner import PlanParsingError
from app.security.capabilities import CapabilityRegistryError
from app.security.lifecycle import CapabilityLifecycleError
from app.skills.file_executor import M6ExecutionError
from app.workflow.pipeline import M1M6Pipeline
from app.skills.registry import PreparedSkillAction
from app.skills.registry import SkillRegistryError
from app.security.permissions import AuthorizationResult
from app.core.task_plan import PlanStep


def review_action(
    step: PlanStep,
    authorization: AuthorizationResult,
) -> None:
    scope = authorization.scope
    scope_value = (
        scope.resource_id or scope.selector
        if scope is not None
        else "not specified"
    )
    print()
    print("Capability check")
    print(f"Action: {step.intent.value if step.intent else step.operation}")
    print(f"Capability: {authorization.capability_id or 'unresolved'}")
    print(f"Scope: {scope_value}")
    print(f"Status: {authorization.decision.value}")


def confirm_mutating_action(action: PreparedSkillAction) -> bool:
    print(f"Target: {action.display_target}")
    print("This operation changes or removes a file.")
    return input("Type YES to approve this action:\n> ").strip() == "YES"


def main(*, dry_run: bool = False) -> int:
    print("Describe the task you want to perform.")
    if dry_run:
        print("Preview only; no action will be performed.")
    user_request = input("> ").strip()
    if not user_request:
        print("Enter a task before continuing.")
        return 1

    try:
        _, _, results = M1M6Pipeline(
            review_callback=review_action,
            approval_callback=confirm_mutating_action,
        ).run(user_request, dry_run=dry_run)
    except (
        CapabilityLifecycleError,
        M6ExecutionError,
        SkillRegistryError,
    ) as error:
        print(f"Task failed: {error}")
        return 1
    except (
        OllamaError,
        PlanParsingError,
        IntentParsingError,
        CapabilityRegistryError,
        ValueError,
    ) as error:
        print(f"Could not validate the request: {error}")
        return 1

    failed = False
    for result in results:
        if result.decision == "ASK_CLARIFICATION":
            print(f"More information is needed: {result.reason}")
            continue
        if result.decision == "DENY":
            print(f"Not authorized: {result.reason}")
            failed = True
            continue
        if result.decision == "ASK_APPROVAL":
            print("Approval was not granted; no action was performed.")
            failed = True
            continue
        if result.decision == "ERROR":
            print(f"Action failed: {result.reason}")
            failed = True
            continue
        if result.decision == "DRY_RUN":
            print(f"Preview: {result.output}")
            continue

        print(f"Result: {result.reason}")
        if result.output:
            print(result.output)
    return 1 if failed else 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Local-first permission-aware file automation."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="check the requested capability and scope without executing",
    )
    raise SystemExit(main(dry_run=parser.parse_args().dry_run))
