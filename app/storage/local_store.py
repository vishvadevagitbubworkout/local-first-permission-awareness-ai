from __future__ import annotations

import ctypes
from datetime import datetime, timezone
import json
import os
import atexit
from pathlib import Path
import sqlite3
from contextlib import closing, contextmanager
from typing import Any
import uuid


class LocalStoreError(RuntimeError):
    """Raised when durable local state or audit data cannot be recorded."""


class LocalAutomationStore:
    """SQLite persistence for capability lifecycle and append-only audit events."""

    def __init__(self, path: Path | str):
        self.path = Path(path).expanduser()
        self.run_id = uuid.uuid4().hex
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS capability_lifecycle (
                        capability_id TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN ('ACTIVE', 'USED', 'EXPIRED', 'REVOKED')
                        ),
                        expires_at TEXT NOT NULL,
                        usage_policy TEXT NOT NULL CHECK (
                            usage_policy IN ('ONE_TIME', 'REPEATABLE')
                        ),
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (capability_id, nonce)
                    );

                    CREATE TABLE IF NOT EXISTS audit_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        execution_id TEXT,
                        run_id TEXT NOT NULL,
                        owner_pid INTEGER NOT NULL,
                        task_id TEXT,
                        step_id TEXT,
                        request_redacted TEXT,
                        scope_json TEXT,
                        capability_id TEXT,
                        decision TEXT,
                        approval TEXT,
                        token_verification TEXT,
                        execution_result TEXT,
                        failure_reason TEXT
                    );

                    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
                    BEFORE UPDATE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are append-only');
                    END;

                    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
                    BEFORE DELETE ON audit_events
                    BEGIN
                        SELECT RAISE(ABORT, 'audit events are append-only');
                    END;

                    CREATE TABLE IF NOT EXISTS process_runs (
                        run_id TEXT PRIMARY KEY,
                        owner_pid INTEGER NOT NULL,
                        status TEXT NOT NULL CHECK (status IN ('RUNNING', 'CLOSED')),
                        started_at TEXT NOT NULL,
                        ended_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS action_executions (
                        execution_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        step_id TEXT NOT NULL,
                        capability_id TEXT,
                        scope_json TEXT,
                        status TEXT NOT NULL CHECK (
                            status IN ('STARTED', 'COMPLETED', 'FAILED', 'INTERRUPTED')
                        ),
                        started_at TEXT NOT NULL,
                        ended_at TEXT
                    );

                    CREATE TABLE IF NOT EXISTS gateway_executions (
                        execution_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        step_id TEXT NOT NULL,
                        capability_id TEXT NOT NULL,
                        status TEXT NOT NULL CHECK (
                            status IN ('PENDING', 'SUCCEEDED', 'FAILED', 'UNKNOWN')
                        ),
                        started_at TEXT NOT NULL,
                        ended_at TEXT,
                        failure_reason TEXT
                    );

                    CREATE TABLE IF NOT EXISTS approval_lifecycle (
                        approval_id TEXT PRIMARY KEY,
                        run_id TEXT NOT NULL,
                        binding_json TEXT NOT NULL,
                        binding_digest TEXT NOT NULL,
                        principal_id TEXT NOT NULL,
                        issued_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        nonce TEXT NOT NULL,
                        signature TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN ('ACTIVE', 'CONSUMED', 'EXPIRED', 'REVOKED')
                        ),
                        updated_at TEXT NOT NULL
                    );
                    """
                )
                self._ensure_execution_columns(connection)
                with self._atomic(connection):
                    self._recover_interrupted(connection)
                    connection.execute(
                        """
                        INSERT INTO process_runs (run_id, owner_pid, status, started_at)
                        VALUES (?, ?, 'RUNNING', ?)
                        """,
                        (self.run_id, os.getpid(), self._now()),
                    )
            atexit.register(self._close_run_at_exit)
        except (OSError, sqlite3.Error) as error:
            raise LocalStoreError(f"Could not initialize local automation state: {error}") from error

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    @staticmethod
    @contextmanager
    def _atomic(connection: sqlite3.Connection):
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _ensure_execution_columns(connection: sqlite3.Connection) -> None:
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(action_executions)")
        }
        if "capability_id" not in columns:
            connection.execute(
                "ALTER TABLE action_executions ADD COLUMN capability_id TEXT"
            )
        if "scope_json" not in columns:
            connection.execute(
                "ALTER TABLE action_executions ADD COLUMN scope_json TEXT"
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _pid_is_running(pid: int) -> bool:
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [
                ctypes.c_uint32,
                ctypes.c_int,
                ctypes.c_uint32,
            ]
            kernel32.OpenProcess.restype = ctypes.c_void_p
            kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            kernel32.CloseHandle.restype = ctypes.c_int
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                kernel32.CloseHandle(ctypes.c_void_p(handle))
                return True
            return ctypes.get_last_error() != 87
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return True
        return True

    def _recover_interrupted(self, connection: sqlite3.Connection) -> None:
        runs = connection.execute(
            """
            SELECT run_id, owner_pid
            FROM process_runs
            WHERE status = 'RUNNING'
            """
        ).fetchall()
        for run in runs:
            if self._pid_is_running(run["owner_pid"]):
                continue
            connection.execute(
                """
                UPDATE gateway_executions
                SET status='UNKNOWN', ended_at=?,
                    failure_reason='Owning process ended before outcome was recorded.'
                WHERE run_id=? AND status='PENDING'
                """,
                (self._now(), run["run_id"]),
            )
            executions = connection.execute(
                """
                SELECT execution_id, task_id, step_id, capability_id, scope_json
                FROM action_executions
                WHERE run_id = ? AND status = 'STARTED'
                """,
                (run["run_id"],),
            ).fetchall()
            for execution in executions:
                now = self._now()
                cursor = connection.execute(
                    """
                    UPDATE action_executions
                    SET status = 'INTERRUPTED', ended_at = ?
                    WHERE execution_id = ? AND status = 'STARTED'
                    """,
                    (now, execution["execution_id"]),
                )
                if cursor.rowcount != 1:
                    continue
                self._append_on_connection(
                    connection,
                    event_type="EXECUTION_INTERRUPTED",
                    execution_id=execution["execution_id"],
                    run_id=run["run_id"],
                    owner_pid=run["owner_pid"],
                    task_id=execution["task_id"],
                    step_id=execution["step_id"],
                    capability_id=execution["capability_id"],
                    scope=(
                        json.loads(execution["scope_json"])
                        if execution["scope_json"] is not None
                        else None
                    ),
                    execution_result="INTERRUPTED",
                    failure_reason=(
                        "The owning process ended before recording an execution result. "
                        "The consumed one-time capability will not be retried."
                    ),
                )
            connection.execute(
                """
                UPDATE process_runs SET status='CLOSED', ended_at=?
                WHERE run_id=? AND status='RUNNING'
                """,
                (self._now(), run["run_id"]),
            )

    def consume_capability(
        self,
        *,
        capability_id: str,
        nonce: str,
        expires_at: str,
        usage_policy: str,
        now: datetime,
    ) -> str:
        current = now.astimezone(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, expires_at, usage_policy
                        FROM capability_lifecycle
                        WHERE capability_id = ? AND nonce = ?
                        """,
                        (capability_id, nonce),
                    ).fetchone()
                    if row is not None and (
                        row["expires_at"] != expires_at
                        or row["usage_policy"] != usage_policy
                    ):
                        raise LocalStoreError(
                            "Capability lifecycle claims differ from the persisted record."
                        )
                    state = row["state"] if row is not None else "ACTIVE"
                    if current >= expires_at and state != "REVOKED":
                        state = "EXPIRED"
                    if row is None:
                        stored_state = (
                            "USED"
                            if state == "ACTIVE" and usage_policy == "ONE_TIME"
                            else state
                        )
                        connection.execute(
                            """
                            INSERT INTO capability_lifecycle
                                (capability_id, nonce, state, expires_at, usage_policy, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                capability_id,
                                nonce,
                                stored_state,
                                expires_at,
                                usage_policy,
                                current,
                            ),
                        )
                        if stored_state == "USED":
                            state = "CONSUMED"
                    elif state == "EXPIRED":
                        connection.execute(
                            """
                            UPDATE capability_lifecycle
                            SET state = ?, updated_at = ?
                            WHERE capability_id = ? AND nonce = ?
                            """,
                            (state, current, capability_id, nonce),
                        )
                    elif state == "ACTIVE" and usage_policy == "ONE_TIME":
                        state = "USED"
                        connection.execute(
                            """
                            UPDATE capability_lifecycle
                            SET state = ?, updated_at = ?
                            WHERE capability_id = ? AND nonce = ?
                            """,
                            (state, current, capability_id, nonce),
                        )
                        state = "CONSUMED"
                return state
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(f"Could not consume capability state: {error}") from error

    def get_capability_state(
        self,
        *,
        capability_id: str,
        nonce: str,
        expires_at: str,
        usage_policy: str,
        now: datetime,
    ) -> str:
        current = now.astimezone(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, expires_at, usage_policy
                        FROM capability_lifecycle
                        WHERE capability_id=? AND nonce=?
                        """,
                        (capability_id, nonce),
                    ).fetchone()
                    existing = row["state"] if row is not None else "ACTIVE"
                    if row is not None and (
                        row["expires_at"] != expires_at
                        or row["usage_policy"] != usage_policy
                    ):
                        raise LocalStoreError(
                            "Capability lifecycle claims differ from the persisted record."
                        )
                    if current >= expires_at and existing != "REVOKED":
                        existing = "EXPIRED"
                    if row is None:
                        connection.execute(
                            """
                            INSERT INTO capability_lifecycle
                                (capability_id, nonce, state, expires_at, usage_policy, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (capability_id, nonce, existing, expires_at, usage_policy, current),
                        )
                    elif existing != row["state"]:
                        connection.execute(
                            """
                            UPDATE capability_lifecycle
                            SET state = ?, updated_at = ?
                            WHERE capability_id = ? AND nonce = ?
                            """,
                            (existing, current, capability_id, nonce),
                        )
                return existing
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(f"Could not read capability lifecycle state: {error}") from error

    def revoke_capability(
        self,
        *,
        capability_id: str,
        nonce: str,
        expires_at: str,
        usage_policy: str,
        now: datetime,
    ) -> str:
        current = now.astimezone(timezone.utc).isoformat()
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, expires_at, usage_policy
                        FROM capability_lifecycle
                        WHERE capability_id=? AND nonce=?
                        """,
                        (capability_id, nonce),
                    ).fetchone()
                    if row is not None and (
                        row["expires_at"] != expires_at
                        or row["usage_policy"] != usage_policy
                    ):
                        raise LocalStoreError(
                            "Capability lifecycle claims differ from the persisted record."
                        )
                    state = row["state"] if row is not None else "ACTIVE"
                    if current >= expires_at and state != "REVOKED":
                        state = "EXPIRED"
                    elif state == "ACTIVE":
                        state = "REVOKED"
                    if row is None:
                        newly_revoked = state == "REVOKED"
                        connection.execute(
                            """
                            INSERT INTO capability_lifecycle
                                (capability_id, nonce, state, expires_at, usage_policy, updated_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (capability_id, nonce, state, expires_at, usage_policy, current),
                        )
                    else:
                        newly_revoked = state == "REVOKED" and row["state"] != "REVOKED"
                        connection.execute(
                            """
                            UPDATE capability_lifecycle SET state=?, updated_at=?
                            WHERE capability_id=? AND nonce=?
                            """,
                            (state, current, capability_id, nonce),
                        )
                    if newly_revoked:
                        state = "REVOKED_NOW"
                return state
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(f"Could not revoke capability: {error}") from error

    @staticmethod
    def _append_on_connection(
        connection: sqlite3.Connection,
        *,
        event_type: str,
        run_id: str,
        owner_pid: int,
        execution_id: str | None = None,
        task_id: str | None = None,
        step_id: str | None = None,
        request_redacted: str | None = None,
        scope: Any = None,
        capability_id: str | None = None,
        decision: str | None = None,
        approval: str | None = None,
        token_verification: str | None = None,
        execution_result: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        scope_json = None if scope is None else json.dumps(
            scope, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        connection.execute(
            """
            INSERT INTO audit_events (
                timestamp, event_type, execution_id, run_id, owner_pid,
                task_id, step_id, request_redacted, scope_json, capability_id,
                decision, approval, token_verification, execution_result, failure_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                LocalAutomationStore._now(),
                event_type,
                execution_id,
                run_id,
                owner_pid,
                task_id,
                step_id,
                request_redacted,
                scope_json,
                capability_id,
                decision,
                approval,
                token_verification,
                execution_result,
                failure_reason,
            ),
        )

    def append_audit_event(self, event_type: str, **fields: Any) -> None:
        try:
            with closing(self._connect()) as connection:
                self._append_on_connection(
                    connection,
                    event_type=event_type,
                    run_id=self.run_id,
                    owner_pid=os.getpid(),
                    **fields,
                )
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not append audit event '{event_type}': {error}") from error

    def start_execution(
        self,
        *,
        execution_id: str,
        task_id: str,
        step_id: str,
        capability_id: str,
        scope: Any,
    ) -> None:
        now = self._now()
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    connection.execute(
                        """
                        INSERT INTO action_executions
                            (execution_id, run_id, task_id, step_id, capability_id,
                             scope_json, status, started_at)
                        VALUES (?, ?, ?, ?, ?, ?, 'STARTED', ?)
                        """,
                        (
                            execution_id,
                            self.run_id,
                            task_id,
                            step_id,
                            capability_id,
                            None if scope is None else json.dumps(
                                scope,
                                sort_keys=True,
                                separators=(",", ":"),
                                ensure_ascii=False,
                            ),
                            now,
                        ),
                    )
                    self._append_on_connection(
                        connection,
                        event_type="EXECUTION_STARTED",
                        execution_id=execution_id,
                        run_id=self.run_id,
                        owner_pid=os.getpid(),
                        task_id=task_id,
                        step_id=step_id,
                        scope=scope,
                        capability_id=capability_id,
                        token_verification="VERIFIED_AND_CONSUMED",
                    )
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not record execution start: {error}") from error

    def start_gateway_execution(
        self,
        *,
        execution_id: str,
        task_id: str,
        step_id: str,
        capability_id: str,
    ) -> None:
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    connection.execute(
                        """
                        INSERT INTO gateway_executions (
                            execution_id, run_id, task_id, step_id,
                            capability_id, status, started_at
                        ) VALUES (?, ?, ?, ?, ?, 'PENDING', ?)
                        """,
                        (
                            execution_id,
                            self.run_id,
                            task_id,
                            step_id,
                            capability_id,
                            self._now(),
                        ),
                    )
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(
                f"Could not reserve gateway execution: {error}"
            ) from error

    def finish_gateway_execution(
        self,
        *,
        execution_id: str,
        status: str,
        failure_reason: str | None = None,
    ) -> None:
        if status not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
            raise LocalStoreError("Invalid gateway execution terminal status.")
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    cursor = connection.execute(
                        """
                        UPDATE gateway_executions
                        SET status=?, ended_at=?, failure_reason=?
                        WHERE execution_id=? AND run_id=? AND status='PENDING'
                        """,
                        (
                            status,
                            self._now(),
                            failure_reason,
                            execution_id,
                            self.run_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise LocalStoreError(
                            "Gateway execution is missing or is no longer pending."
                        )
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(
                f"Could not finish gateway execution: {error}"
            ) from error

    def get_gateway_execution_state(self, execution_id: str) -> str | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT status FROM gateway_executions
                    WHERE execution_id=?
                    """,
                    (execution_id,),
                ).fetchone()
                return row["status"] if row is not None else None
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(
                f"Could not read gateway execution state: {error}"
            ) from error

    def create_approval(
        self,
        *,
        approval_id: str,
        binding: dict[str, Any],
        binding_digest: str,
        principal_id: str,
        issued_at: str,
        expires_at: str,
        nonce: str,
        signature: str,
    ) -> None:
        binding_json = json.dumps(
            binding,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    connection.execute(
                        """
                        INSERT INTO approval_lifecycle (
                            approval_id, run_id, binding_json, binding_digest,
                            principal_id, issued_at, expires_at, nonce,
                            signature, state, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
                        """,
                        (
                            approval_id,
                            self.run_id,
                            binding_json,
                            binding_digest,
                            principal_id,
                            issued_at,
                            expires_at,
                            nonce,
                            signature,
                            self._now(),
                        ),
                    )
                    self._append_on_connection(
                        connection,
                        event_type="APPROVAL_CREATED",
                        run_id=self.run_id,
                        owner_pid=os.getpid(),
                        task_id=binding.get("task_id"),
                        step_id=binding.get("step_id"),
                        capability_id=binding.get("capability_id"),
                        approval="ACTIVE",
                        execution_result=binding_digest,
                    )
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not persist approval: {error}") from error

    def get_approval_state(
        self,
        approval_id: str,
        *,
        now: str | None = None,
    ) -> str | None:
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, expires_at, binding_json, binding_digest
                        FROM approval_lifecycle WHERE approval_id=?
                        """,
                        (approval_id,),
                    ).fetchone()
                    if row is None:
                        return None
                    state = row["state"]
                    current = now or self._now()
                    if state == "ACTIVE" and current >= row["expires_at"]:
                        state = "EXPIRED"
                        binding = json.loads(row["binding_json"])
                        connection.execute(
                            """
                            UPDATE approval_lifecycle
                            SET state='EXPIRED', updated_at=?
                            WHERE approval_id=? AND state='ACTIVE'
                            """,
                            (current, approval_id),
                        )
                        self._append_on_connection(
                            connection,
                            event_type="APPROVAL_STATE_CHANGED",
                            run_id=self.run_id,
                            owner_pid=os.getpid(),
                            task_id=binding.get("task_id"),
                            step_id=binding.get("step_id"),
                            capability_id=binding.get("capability_id"),
                            approval="EXPIRED",
                            execution_result=row["binding_digest"],
                        )
                    return state
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not read approval state: {error}") from error

    def get_approval_record(self, approval_id: str) -> dict[str, Any] | None:
        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT binding_json, binding_digest, principal_id,
                           issued_at, expires_at, nonce, signature, state
                    FROM approval_lifecycle WHERE approval_id=?
                    """,
                    (approval_id,),
                ).fetchone()
                if row is None:
                    return None
                return {
                    "binding": json.loads(row["binding_json"]),
                    "binding_digest": row["binding_digest"],
                    "principal_id": row["principal_id"],
                    "issued_at": row["issued_at"],
                    "expires_at": row["expires_at"],
                    "nonce": row["nonce"],
                    "signature": row["signature"],
                    "state": row["state"],
                }
        except (sqlite3.Error, OSError, ValueError) as error:
            raise LocalStoreError(f"Could not read approval record: {error}") from error

    def consume_approval(
        self,
        *,
        approval_id: str,
        binding_digest: str,
        now: str,
    ) -> str:
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, expires_at, binding_digest, run_id,
                               binding_json
                        FROM approval_lifecycle
                        WHERE approval_id=?
                        """,
                        (approval_id,),
                    ).fetchone()
                    if row is None:
                        return "MISSING"
                    if row["binding_digest"] != binding_digest:
                        return "INVALID"
                    if row["state"] != "ACTIVE":
                        return row["state"]
                    if now >= row["expires_at"]:
                        state = "EXPIRED"
                    else:
                        state = "CONSUMED"
                    binding = json.loads(row["binding_json"])
                    connection.execute(
                        """
                        UPDATE approval_lifecycle
                        SET state=?, updated_at=?
                        WHERE approval_id=? AND state='ACTIVE'
                        """,
                        (state, now, approval_id),
                    )
                    self._append_on_connection(
                        connection,
                        event_type="APPROVAL_STATE_CHANGED",
                        run_id=self.run_id,
                        owner_pid=os.getpid(),
                        task_id=binding.get("task_id"),
                        step_id=binding.get("step_id"),
                        capability_id=binding.get("capability_id"),
                        approval=state,
                        execution_result=binding_digest,
                    )
                    return "CONSUMED_NOW" if state == "CONSUMED" else state
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not consume approval: {error}") from error

    def revoke_approval(self, approval_id: str) -> str:
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    row = connection.execute(
                        """
                        SELECT state, binding_json, binding_digest
                        FROM approval_lifecycle WHERE approval_id=?
                        """,
                        (approval_id,),
                    ).fetchone()
                    if row is None:
                        return "MISSING"
                    if row["state"] != "ACTIVE":
                        return row["state"]
                    binding = json.loads(row["binding_json"])
                    connection.execute(
                        """
                        UPDATE approval_lifecycle
                        SET state='REVOKED', updated_at=?
                        WHERE approval_id=? AND state='ACTIVE'
                        """,
                        (self._now(), approval_id),
                    )
                    self._append_on_connection(
                        connection,
                        event_type="APPROVAL_STATE_CHANGED",
                        run_id=self.run_id,
                        owner_pid=os.getpid(),
                        task_id=binding.get("task_id"),
                        step_id=binding.get("step_id"),
                        capability_id=binding.get("capability_id"),
                        approval="REVOKED",
                        execution_result=row["binding_digest"],
                    )
                    return "REVOKED"
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not revoke approval: {error}") from error

    def finish_execution(
        self,
        *,
        execution_id: str,
        task_id: str,
        step_id: str,
        status: str,
        execution_result: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        if status not in {"COMPLETED", "FAILED"}:
            raise ValueError("Execution status must be COMPLETED or FAILED.")
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    execution = connection.execute(
                        """
                        SELECT capability_id, scope_json
                        FROM action_executions
                        WHERE execution_id = ? AND run_id = ?
                        """,
                        (execution_id, self.run_id),
                    ).fetchone()
                    if execution is None:
                        raise LocalStoreError(
                            "The execution record is missing or no longer active."
                        )
                    cursor = connection.execute(
                        """
                        UPDATE action_executions
                        SET status = ?, ended_at = ?
                        WHERE execution_id = ? AND run_id = ?
                          AND task_id = ? AND step_id = ? AND status = 'STARTED'
                        """,
                        (
                            status,
                            self._now(),
                            execution_id,
                            self.run_id,
                            task_id,
                            step_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise LocalStoreError(
                            "The execution record is missing or no longer active."
                        )
                    self._append_on_connection(
                        connection,
                        event_type=f"EXECUTION_{status}",
                        execution_id=execution_id,
                        run_id=self.run_id,
                        owner_pid=os.getpid(),
                        task_id=task_id,
                        step_id=step_id,
                        capability_id=execution["capability_id"],
                        scope=(
                            json.loads(execution["scope_json"])
                            if execution is not None
                            and execution["scope_json"] is not None
                            else None
                        ),
                        execution_result=execution_result,
                        failure_reason=failure_reason,
                    )
        except (sqlite3.Error, OSError, TypeError, ValueError) as error:
            raise LocalStoreError(f"Could not record execution completion: {error}") from error

    def close_run(self) -> None:
        try:
            with closing(self._connect()) as connection:
                with self._atomic(connection):
                    rows = connection.execute(
                        """
                        SELECT execution_id, task_id, step_id, capability_id, scope_json
                        FROM action_executions
                        WHERE run_id = ? AND status = 'STARTED'
                        """,
                        (self.run_id,),
                    ).fetchall()
                    for row in rows:
                        now = self._now()
                        connection.execute(
                            """
                            UPDATE action_executions
                            SET status='INTERRUPTED', ended_at=?
                            WHERE execution_id=? AND status='STARTED'
                            """,
                            (now, row["execution_id"]),
                        )
                        self._append_on_connection(
                            connection,
                            event_type="EXECUTION_INTERRUPTED",
                            execution_id=row["execution_id"],
                            run_id=self.run_id,
                            owner_pid=os.getpid(),
                            task_id=row["task_id"],
                            step_id=row["step_id"],
                            capability_id=row["capability_id"],
                            scope=(
                                json.loads(row["scope_json"])
                                if row["scope_json"] is not None
                                else None
                            ),
                            execution_result="INTERRUPTED",
                            failure_reason=(
                                "The run ended before an execution result was recorded. "
                                "The consumed capability will not be retried."
                            ),
                        )
                    connection.execute(
                        """
                        UPDATE process_runs SET status='CLOSED', ended_at=?
                        WHERE run_id=? AND status='RUNNING'
                        """,
                        (self._now(), self.run_id),
                    )
                    connection.execute(
                        """
                        UPDATE gateway_executions
                        SET status='UNKNOWN', ended_at=?,
                            failure_reason='Run closed before outcome was recorded.'
                        WHERE run_id=? AND status='PENDING'
                        """,
                        (self._now(), self.run_id),
                    )
            atexit.unregister(self._close_run_at_exit)
        except (sqlite3.Error, OSError) as error:
            raise LocalStoreError(f"Could not close local automation run: {error}") from error

    def _close_run_at_exit(self) -> None:
        self.close_run()


__all__ = ["LocalAutomationStore", "LocalStoreError"]
