from __future__ import annotations

import hashlib
import re
from typing import Any

from app.storage.local_store import LocalAutomationStore
from app.security.permissions import PermissionScope


_QUOTED_TEXT = re.compile(r"""(['"`]).*?\1""", re.S)
_WINDOWS_PATH = re.compile(r"(?<![\w])[A-Za-z]:[\\/][^\r\n\"'`<>|?*]*")
_UNC_PATH = re.compile(r"(?<!\S)(?:\\\\|//)[^\s\"'`<>|?*]+")
_RELATIVE_TRAVERSAL = re.compile(
    r"(?<![\w.])(?:\.\.[\\/])+(?:[^\\/\s\"'`<>|?*]+"
    r"(?:[\\/][^\\/\s\"'`<>|?*]+)*)?",
    re.I,
)
_FILE_NAME = re.compile(r"\b[\w.-]+\.[A-Za-z0-9]{1,12}\b", re.I)


def redact_sensitive_text(value: str) -> str:
    value = _QUOTED_TEXT.sub("[REDACTED_TEXT]", value)
    value = _WINDOWS_PATH.sub("[REDACTED_PATH]", value)
    value = _UNC_PATH.sub("[REDACTED_PATH]", value)
    value = _RELATIVE_TRAVERSAL.sub("[REDACTED_PATH]", value)
    return _FILE_NAME.sub("[REDACTED_FILE]", value)


def _fingerprint(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class AuditTrail:
    """Append-only local audit events; request contents are redacted before storage."""

    def __init__(self, store: LocalAutomationStore):
        self.store = store

    @staticmethod
    def safe_scope(
        scope: PermissionScope | None,
        *,
        intent: str | None = None,
        root: str | None = None,
        target: str | None = None,
    ) -> dict[str, Any] | None:
        if scope is None and intent is None and root is None and target is None:
            return None
        value: dict[str, Any] = {}
        if scope is not None:
            value.update(
                resource_type=scope.resource_type.value,
                kind=scope.kind.value,
                selector=scope.selector,
                resource_fingerprint=_fingerprint(scope.resource_id),
            )
        if intent is not None:
            value["operation"] = intent
        if root is not None:
            value["directory_fingerprint"] = _fingerprint(root)
        if target is not None:
            value["target_fingerprint"] = _fingerprint(target)
        return value

    def record(
        self,
        event_type: str,
        *,
        task_id: str | None = None,
        step_id: str | None = None,
        request: str | None = None,
        scope: dict[str, Any] | None = None,
        capability_id: str | None = None,
        decision: str | None = None,
        approval: str | None = None,
        token_verification: str | None = None,
        execution_result: str | None = None,
        failure_reason: str | None = None,
        execution_id: str | None = None,
    ) -> None:
        self.store.append_audit_event(
            event_type,
            execution_id=execution_id,
            task_id=task_id,
            step_id=step_id,
            request_redacted=(
                redact_sensitive_text(request) if request is not None else None
            ),
            scope=scope,
            capability_id=capability_id,
            decision=decision,
            approval=approval,
            token_verification=token_verification,
            execution_result=(
                redact_sensitive_text(execution_result)
                if execution_result is not None
                else None
            ),
            failure_reason=(
                redact_sensitive_text(failure_reason)
                if failure_reason is not None
                else None
            ),
        )


__all__ = ["AuditTrail", "redact_sensitive_text"]
