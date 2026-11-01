from __future__ import annotations

import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable

from app.core.task_plan import PlannerIntent, PlanStep, TaskPlan
from app.validation.intent import ValidatedIntentResult
from app.security.permissions import AuthorizationResult
from app.security.permissions import PermissionDecision
from app.security.lifecycle import CapabilityLifecycleStore
from app.security.verification import (
    CapabilityVerificationError,
    CapabilityVerifier,
    VerifiedCapability,
)
from app.core.file_paths import (
    M6PathError,
    contains_absolute_path,
    resolve_user_path,
)

_FILE_NAME = re.compile(r"\b[\w.-]+\.(?:pdf|docx?|xlsx?|txt)\b", re.I)
_WRITE_CONTENT = re.compile(
    r"\b(?:write|overwrite|replace|put)\s+(['\"])(.*?)\1\s+(?:to|into|in)\s+"
    r"(?:the\s+)?(?:file\s+)?([\w.-]+\.(?:pdf|docx?|xlsx?|txt))\b",
    re.I | re.S,
)
_MAX_READ_BYTES = 256 * 1024
_MAX_WRITE_BYTES = 256 * 1024
_MAX_LIST_ENTRIES = 2000
_MAX_DIRECTORY_ENTRIES_SCANNED = 10000
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_MUTATING_INTENTS = {
    PlannerIntent.CREATE,
    PlannerIntent.WRITE,
    PlannerIntent.MOVE,
    PlannerIntent.RENAME,
    PlannerIntent.DELETE,
}
_OPERATION_CONTRACTS = {
    PlannerIntent.LIST: ("LIST", "FILE_LIST", "list"),
    PlannerIntent.READ: ("READ", "FILE_READ", "read"),
    PlannerIntent.CREATE: ("CREATE", "FILE_CREATE", "create"),
    PlannerIntent.WRITE: ("WRITE", "FILE_WRITE", "write"),
    PlannerIntent.MOVE: ("MOVE", "FILE_MOVE", "move"),
    PlannerIntent.RENAME: ("RENAME", "FILE_RENAME", "rename"),
    PlannerIntent.DELETE: ("DELETE", "FILE_DELETE", "delete"),
}


class M6ExecutionError(RuntimeError):
    """Raised when an authorized file action cannot be safely executed."""


@dataclass(frozen=True)
class PreparedFileAction:
    task_id: str
    step_id: str
    intent: PlannerIntent
    root: Path
    target: Path
    destination: Path | None = None
    content: str | None = None

    @property
    def requires_approval(self) -> bool:
        return self.intent in _MUTATING_INTENTS

    @property
    def display_target(self) -> str:
        if self.destination is not None:
            return f"{self.target} -> {self.destination}"
        return str(self.target)


@dataclass(frozen=True)
class FileActionResult:
    summary: str
    output: str = ""


class FileSystemExecutor:
    """Execute a narrow file action only after M5 verifies its task-scoped grant."""

    def __init__(
        self,
        *,
        verifier: CapabilityVerifier,
        lifecycle: CapabilityLifecycleStore,
        working_directory: Path | None = None,
    ):
        self._verifier = verifier
        self._lifecycle = lifecycle
        self._working_directory = working_directory

    def prepare(self, task_plan: TaskPlan, step: PlanStep) -> PreparedFileAction:
        prepared = self._resolve_action(task_plan, step)
        self._preflight(prepared)
        return prepared

    def _resolve_action(
        self,
        task_plan: TaskPlan,
        step: PlanStep,
    ) -> PreparedFileAction:
        if not isinstance(task_plan, TaskPlan) or not isinstance(step, PlanStep):
            raise M6ExecutionError("M6 requires a validated task plan and step.")
        if not any(candidate is step for candidate in task_plan.steps):
            raise M6ExecutionError("The step is not the exact object in the task plan.")
        if step.intent not in {
            PlannerIntent.LIST,
            PlannerIntent.READ,
            PlannerIntent.CREATE,
            PlannerIntent.WRITE,
            PlannerIntent.MOVE,
            PlannerIntent.RENAME,
            PlannerIntent.DELETE,
        }:
            raise M6ExecutionError("M6 does not support this operation.")

        try:
            explicit_path = resolve_user_path(task_plan.original_request)
            if explicit_path is not None:
                prepared = self._prepare_from_explicit_path(
                    task_plan,
                    step,
                    explicit_path,
                )
            else:
                if contains_absolute_path(task_plan.original_request):
                    raise M6ExecutionError(
                        "Quote exactly one absolute Windows directory or file path in the request."
                    )
                prepared = self._prepare_from_working_directory(task_plan, step)
            return prepared
        except M6PathError as error:
            raise M6ExecutionError(str(error)) from error
        except OSError as error:
            raise M6ExecutionError(f"Could not resolve the requested path: {error}") from error

    def execute(
        self,
        authorization: AuthorizationResult,
        capability: VerifiedCapability,
        task_plan: TaskPlan,
        step: PlanStep,
        intent_result: ValidatedIntentResult,
        prepared: PreparedFileAction,
        *,
        after_capability_consumed: Callable[[], None] | None = None,
    ) -> FileActionResult:
        if (
            not isinstance(authorization, AuthorizationResult)
            or not authorization.is_integrity_valid()
            or authorization.decision != PermissionDecision.ALLOW
            or not authorization.is_bound_to(task_plan.task_id, step.step_id)
            or authorization.capability_id is None
            or authorization.scope is None
        ):
            raise M6ExecutionError("M6 requires a bound, integrity-checked M4 ALLOW.")
        if (
            not isinstance(intent_result, ValidatedIntentResult)
            or not intent_result.is_bound_to_plan(task_plan)
            or not intent_result.consistent
            or step.step_id in intent_result.mismatched_steps
        ):
            raise M6ExecutionError("M6 requires an M2-validated task and step.")
        contract = _OPERATION_CONTRACTS.get(step.intent)
        if (
            contract is None
            or step.operation != contract[0]
            or step.template is None
            or step.template.value != contract[1]
            or step.parameters != {"mode": contract[2]}
        ):
            raise M6ExecutionError("The plan step does not match the fixed M6 action contract.")
        if not isinstance(capability, VerifiedCapability) or not capability.is_verified():
            raise M6ExecutionError("M6 requires a verifier-issued M5 capability.")
        if (
            authorization.capability_id != capability.claims.capability_id
            or authorization.scope != capability.claims.scope
            or authorization.scope.resource_id != step.resource
            or capability.claims.resource != step.resource
        ):
            raise M6ExecutionError("The M4 authorization does not match the M5 capability.")
        if (
            prepared.task_id != task_plan.task_id
            or prepared.step_id != step.step_id
            or prepared.intent != step.intent
            or prepared != self._resolve_action(task_plan, step)
        ):
            raise M6ExecutionError("The prepared file action no longer matches the task.")

        try:
            self._verifier.verify(
                capability.model_dump(mode="python"),
                expected_task_id=task_plan.task_id,
                expected_step_id=step.step_id,
                expected_agent=step.agent,
                expected_operation=step.operation,
                expected_resource=step.resource,
                expected_scope=authorization.scope,
            )
        except CapabilityVerificationError as error:
            raise M6ExecutionError(f"M5 capability verification failed: {error}") from error

        self._lifecycle.verify_and_consume(capability)
        if after_capability_consumed is not None:
            after_capability_consumed()
        try:
            return self._perform(prepared)
        except OSError as error:
            raise M6ExecutionError(f"{step.intent.value} failed for {prepared.display_target}: {error}") from error

    def _prepare_from_explicit_path(
        self,
        task_plan: TaskPlan,
        step: PlanStep,
        explicit_path: Path,
    ) -> PreparedFileAction:
        self._reject_reparse_components(explicit_path)
        exists = explicit_path.exists()
        if exists:
            resolved = explicit_path.resolve(strict=True)
            self._reject_reparse_components(resolved)
            if step.intent == PlannerIntent.LIST:
                if not resolved.is_dir():
                    raise M6ExecutionError("LIST requires the explicit path to be a directory.")
                return self._prepared(task_plan, step, resolved, resolved)
            if resolved.is_dir():
                root = resolved
                target = self._target_for_resource(root, step.resource)
            else:
                root = resolved.parent
                if step.resource != resolved.name:
                    raise M6ExecutionError(
                        "The planner target does not match the explicitly named file."
                    )
                target = resolved
        elif step.intent == PlannerIntent.LIST:
            raise M6ExecutionError(f"The requested directory does not exist: {explicit_path}")
        elif explicit_path.parent.is_dir() and explicit_path.name == step.resource:
            root = explicit_path.parent.resolve(strict=True)
            target = root / explicit_path.name
        else:
            root = explicit_path.resolve(strict=True)
            target = self._target_for_resource(root, step.resource)

        return self._prepared(task_plan, step, root, target)

    def _prepare_from_working_directory(
        self,
        task_plan: TaskPlan,
        step: PlanStep,
    ) -> PreparedFileAction:
        configured_root = self._working_directory or Path.cwd()
        self._reject_reparse_components(configured_root)
        root = configured_root.resolve(strict=True)
        self._reject_reparse_components(root)
        if step.intent == PlannerIntent.LIST:
            if step.resource == "user-selected directory":
                raise M6ExecutionError(
                    "The user-selected directory was not present in the original request."
                )
            if step.resource == "default workspace":
                return self._prepared(task_plan, step, root, root)
            if step.resource == "current folder":
                if not re.search(r"\bcurrent\s+(?:folder|directory)\b", task_plan.original_request, re.I):
                    raise M6ExecutionError(
                        "LIST may use the current folder only when the user explicitly requested it."
                    )
            else:
                root = self._target_for_resource(root, step.resource).resolve(strict=True)
                if not root.is_dir():
                    raise M6ExecutionError("LIST target must be a directory.")
            return self._prepared(task_plan, step, root, root)
        target = self._target_for_resource(root, step.resource)
        destination = self._destination_for(step, task_plan.original_request, root)
        content = self._content_for(step, task_plan.original_request)
        return PreparedFileAction(
            task_id=task_plan.task_id,
            step_id=step.step_id,
            intent=step.intent,
            root=root,
            target=target,
            destination=destination,
            content=content,
        )

    def _prepared(
        self,
        task_plan: TaskPlan,
        step: PlanStep,
        root: Path,
        target: Path,
    ) -> PreparedFileAction:
        destination = self._destination_for(step, task_plan.original_request, root)
        content = self._content_for(step, task_plan.original_request)
        return PreparedFileAction(
            task_id=task_plan.task_id,
            step_id=step.step_id,
            intent=step.intent,
            root=root,
            target=target,
            destination=destination,
            content=content,
        )

    @staticmethod
    def _target_for_resource(root: Path, resource: str | None) -> Path:
        if not isinstance(resource, str) or not resource.strip():
            raise M6ExecutionError("The plan does not identify a file target.")
        if resource in {".", ".."} or "/" in resource or "\\" in resource:
            raise M6ExecutionError("File targets must be a single name inside the selected directory.")
        if Path(resource).is_absolute():
            raise M6ExecutionError("M6 does not accept planner-generated absolute paths.")
        return root / resource

    @classmethod
    def _destination_for(
        cls,
        step: PlanStep,
        request: str,
        root: Path,
    ) -> Path | None:
        if step.intent not in {PlannerIntent.MOVE, PlannerIntent.RENAME}:
            return None
        names = list(dict.fromkeys(name for name in _FILE_NAME.findall(request)))
        destinations = [name for name in names if name.casefold() != (step.resource or "").casefold()]
        if len(destinations) != 1:
            raise M6ExecutionError(
                "MOVE and RENAME require exactly one source and one destination filename in the request."
            )
        return cls._target_for_resource(root, destinations[0])

    @staticmethod
    def _content_for(step: PlanStep, request: str) -> str | None:
        if step.intent != PlannerIntent.WRITE:
            return None
        match = _WRITE_CONTENT.search(request)
        if match is None:
            raise M6ExecutionError(
                "WRITE requires explicit quoted text, for example: write 'text' to note.txt."
            )
        if match.group(3).casefold() != (step.resource or "").casefold():
            raise M6ExecutionError(
                "The quoted WRITE target does not match the authorized file."
            )
        content = match.group(2)
        if len(content.encode("utf-8")) > _MAX_WRITE_BYTES:
            raise M6ExecutionError("WRITE content exceeds the 256 KiB safety limit.")
        return content

    def _perform(self, action: PreparedFileAction) -> FileActionResult:
        self._validate_root(action.root)
        if action.intent == PlannerIntent.LIST:
            return self._list_files(action.root)
        self._check_target_parent(action.root, action.target)
        if action.intent == PlannerIntent.READ:
            self._require_regular_file(action.target, must_exist=True)
            with action.target.open("rb") as source:
                content = source.read(_MAX_READ_BYTES + 1)
            if len(content) > _MAX_READ_BYTES:
                raise M6ExecutionError("READ output exceeds the 256 KiB safety limit.")
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError as error:
                raise M6ExecutionError("READ supports UTF-8 text files only.") from error
            return FileActionResult(f"Read {action.target.name}.", text)
        if action.intent == PlannerIntent.CREATE:
            with action.target.open("x", encoding="utf-8"):
                pass
            return FileActionResult(f"Created {action.target.name}.")
        if action.intent == PlannerIntent.WRITE:
            self._require_regular_file(action.target, must_exist=False)
            self._write_file(action)
            return FileActionResult(f"Wrote the requested text to {action.target.name}.")
        if action.intent in {PlannerIntent.MOVE, PlannerIntent.RENAME}:
            self._require_regular_file(action.target, must_exist=True)
            if action.destination is None:
                raise M6ExecutionError("The destination was not resolved.")
            self._check_target_parent(action.root, action.destination)
            self._require_absent(action.destination)
            action.target.rename(action.destination)
            return FileActionResult(
                f"Moved {action.target.name} to {action.destination.name}."
            )
        if action.intent == PlannerIntent.DELETE:
            self._require_regular_file(action.target, must_exist=True)
            action.target.unlink()
            return FileActionResult(f"Deleted {action.target.name}.")
        raise M6ExecutionError(f"Unsupported M6 action: {action.intent.value}")

    @classmethod
    def _preflight(cls, action: PreparedFileAction) -> None:
        cls._validate_root(action.root)
        if action.intent == PlannerIntent.LIST:
            if not action.root.is_dir():
                raise M6ExecutionError("LIST target must be an existing directory.")
            cls._reject_reparse_components(action.root)
            return

        cls._check_target_parent(action.root, action.target)
        if action.intent in {
            PlannerIntent.READ,
            PlannerIntent.MOVE,
            PlannerIntent.RENAME,
            PlannerIntent.DELETE,
        }:
            cls._require_regular_file(action.target, must_exist=True)
        elif action.intent == PlannerIntent.CREATE:
            cls._require_absent(action.target)
        elif action.intent == PlannerIntent.WRITE:
            cls._require_regular_file(action.target, must_exist=False)

        if action.destination is not None:
            cls._check_target_parent(action.root, action.destination)
            cls._require_absent(action.destination)

    @staticmethod
    def _validate_root(root: Path) -> None:
        try:
            FileSystemExecutor._reject_reparse_components(root)
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise M6ExecutionError(
                f"The authorized directory is unavailable: {error}"
            ) from error
        if resolved != root or not root.is_dir():
            raise M6ExecutionError(
                "The authorized directory changed or is no longer a real directory."
            )

    @staticmethod
    def _list_files(root: Path) -> FileActionResult:
        names: list[str] = []
        total = 0
        truncated = False
        scanned = 0
        with os.scandir(root) as entries:
            for entry in entries:
                scanned += 1
                if scanned > _MAX_DIRECTORY_ENTRIES_SCANNED:
                    truncated = True
                    break
                if entry.is_file(follow_symlinks=False):
                    total += 1
                    if len(names) == _MAX_LIST_ENTRIES:
                        truncated = True
                        break
                    names.append(entry.name)
        names.sort(key=str.casefold)
        summary = (
            f"Scan stopped at the configured limit after finding at least {total} "
            f"immediate file(s) in {root}."
            if truncated
            else f"Listed {total} immediate file(s) in {root}."
        )
        suffix = (
            f"\n... scan/output limit reached; showing {len(names)} file names."
            if truncated
            else ""
        )
        return FileActionResult(
            summary,
            "\n".join(names) + suffix,
        )

    @classmethod
    def _write_file(cls, action: PreparedFileAction) -> None:
        if action.content is None:
            raise M6ExecutionError("No explicit WRITE content was supplied.")
        if action.target.exists():
            cls._require_regular_file(action.target, must_exist=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=action.root,
                prefix=".m6-",
                delete=False,
            ) as temporary:
                temporary.write(action.content)
                temporary.flush()
                os.fsync(temporary.fileno())
                temporary_path = Path(temporary.name)
            os.replace(temporary_path, action.target)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

    @staticmethod
    def _require_regular_file(path: Path, *, must_exist: bool) -> None:
        try:
            file_stat = path.lstat()
        except FileNotFoundError:
            if must_exist:
                raise M6ExecutionError(f"The requested file does not exist: {path.name}")
            return
        if (
            path.is_symlink()
            or getattr(file_stat, "st_file_attributes", 0) & _REPARSE_POINT
            or not stat.S_ISREG(file_stat.st_mode)
        ):
            raise M6ExecutionError("M6 refuses symlink, reparse-point, and non-file targets.")

    @staticmethod
    def _require_absent(path: Path) -> None:
        try:
            path.lstat()
        except FileNotFoundError:
            return
        raise M6ExecutionError("The destination already exists; M6 will not overwrite it.")

    @staticmethod
    def _check_target_parent(root: Path, target: Path) -> None:
        if target.parent.resolve(strict=True) != root.resolve(strict=True):
            raise M6ExecutionError("The file target must remain directly inside the selected directory.")
        FileSystemExecutor._reject_reparse_components(target.parent)
        FileSystemExecutor._require_regular_file(target, must_exist=False)

    @staticmethod
    def _reject_reparse_components(path: Path) -> None:
        current = path
        while True:
            try:
                file_stat = current.lstat()
            except FileNotFoundError:
                pass
            else:
                if (
                    current.is_symlink()
                    or getattr(file_stat, "st_file_attributes", 0) & _REPARSE_POINT
                ):
                    raise M6ExecutionError("M6 refuses paths containing symlinks or reparse points.")
            if current.parent == current:
                break
            current = current.parent


__all__ = [
    "FileActionResult",
    "FileSystemExecutor",
    "M6ExecutionError",
    "PreparedFileAction",
]
