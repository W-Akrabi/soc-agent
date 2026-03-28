from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.postgres_support import connect_postgres, ensure_schema, qualified_name, validate_schema_name


class WorkerQueueError(Exception):
    pass


_TASK_COLUMNS = (
    "task_id",
    "run_id",
    "plan_task_id",
    "task_node_id",
    "agent_name",
    "alert_json",
    "db_path",
    "status",
    "created_at",
    "worker_id",
    "claimed_at",
    "completed_at",
    "result_json",
    "error",
    "lease_expires_at",
    "attempt_count",
)

_WORKER_COLUMNS = (
    "worker_id",
    "started_at",
    "last_heartbeat_at",
    "status",
    "current_task_id",
    "metadata_json",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _value_for(task: Any, key: str, default: Any = None) -> Any:
    if isinstance(task, dict):
        return task.get(key, default)
    return getattr(task, key, default)


def _payload_from_task(task: Any) -> dict[str, Any]:
    if is_dataclass(task):
        payload = asdict(task)
    elif isinstance(task, dict):
        payload = dict(task)
    else:
        payload = {column: _value_for(task, column) for column in _TASK_COLUMNS}

    payload.setdefault("task_id", str(uuid.uuid4()))
    payload.setdefault("status", "pending")
    payload.setdefault("created_at", _now())
    payload.setdefault("worker_id", None)
    payload.setdefault("claimed_at", None)
    payload.setdefault("completed_at", None)
    payload.setdefault("result_json", None)
    payload.setdefault("error", None)
    payload.setdefault("lease_expires_at", None)
    payload.setdefault("attempt_count", 0)

    if payload.get("alert_json") is not None and not isinstance(payload["alert_json"], str):
        payload["alert_json"] = json.dumps(payload["alert_json"])
    if payload.get("result_json") is not None and not isinstance(payload["result_json"], str):
        payload["result_json"] = json.dumps(payload["result_json"])
    if payload.get("db_path") is not None:
        payload["db_path"] = str(payload["db_path"])
    return {key: payload.get(key) for key in _TASK_COLUMNS}


def _row_to_task_record(row: Any) -> dict[str, Any]:
    record = dict(row)
    result_json = record.get("result_json")
    if result_json:
        try:
            record["result_json"] = json.loads(result_json)
        except json.JSONDecodeError:
            pass
    if record.get("attempt_count") is None:
        record["attempt_count"] = 0
    return record


def _row_to_worker_record(row: Any) -> dict[str, Any]:
    record = dict(row)
    metadata_json = record.pop("metadata_json", None)
    record["metadata"] = json.loads(metadata_json or "{}")
    return record


class WorkerQueue:
    """Task queue and worker registry for remote SOC workers."""

    def __init__(
        self,
        db_path: str = "./soc_workers.db",
        *,
        backend: str = "sqlite",
        postgres_dsn: str | None = None,
        postgres_schema: str = "soc_control",
        default_lease_seconds: float = 600.0,
    ):
        self.backend = (backend or "sqlite").strip().lower() or "sqlite"
        self.postgres_schema = validate_schema_name(postgres_schema) if self.backend == "postgres" else None
        self.dsn = postgres_dsn or db_path if self.backend == "postgres" else None
        self.db_path = self.dsn or db_path
        self.default_lease_seconds = float(default_lease_seconds)
        if self.backend == "sqlite":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        if self.backend == "postgres":
            return connect_postgres(self.dsn)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _tasks_table(self) -> str:
        if self.backend == "postgres":
            return qualified_name(self.postgres_schema, "worker_tasks")
        return "worker_tasks"

    def _workers_table(self) -> str:
        if self.backend == "postgres":
            return qualified_name(self.postgres_schema, "workers")
        return "workers"

    def _init_db(self) -> None:
        if self.backend == "postgres":
            with self._connect() as conn:
                ensure_schema(conn, self.postgres_schema)
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {self._tasks_table()} (
                            task_id TEXT PRIMARY KEY,
                            run_id TEXT NOT NULL,
                            plan_task_id TEXT NOT NULL,
                            task_node_id TEXT NOT NULL,
                            agent_name TEXT NOT NULL,
                            alert_json TEXT NOT NULL,
                            db_path TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            worker_id TEXT,
                            claimed_at TEXT,
                            completed_at TEXT,
                            result_json TEXT,
                            error TEXT,
                            lease_expires_at TEXT,
                            attempt_count INTEGER NOT NULL DEFAULT 0
                        )
                        """
                    )
                    cur.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {self._workers_table()} (
                            worker_id TEXT PRIMARY KEY,
                            started_at TEXT NOT NULL,
                            last_heartbeat_at TEXT NOT NULL,
                            status TEXT NOT NULL,
                            current_task_id TEXT,
                            metadata_json TEXT NOT NULL DEFAULT '{{}}'
                        )
                        """
                    )
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_worker_tasks_status ON {self._tasks_table()}(status)")
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_worker_tasks_run_id ON {self._tasks_table()}(run_id)")
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_worker_tasks_agent_name ON {self._tasks_table()}(agent_name)")
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_worker_tasks_lease ON {self._tasks_table()}(lease_expires_at)")
                    cur.execute(f"CREATE INDEX IF NOT EXISTS idx_workers_status ON {self._workers_table()}(status)")
            return

        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS worker_tasks (
                    task_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    plan_task_id TEXT NOT NULL,
                    task_node_id TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    alert_json TEXT NOT NULL,
                    db_path TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    worker_id TEXT,
                    claimed_at TEXT,
                    completed_at TEXT,
                    result_json TEXT,
                    error TEXT,
                    lease_expires_at TEXT,
                    attempt_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS workers (
                    worker_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    last_heartbeat_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_task_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_worker_tasks_status ON worker_tasks(status);
                CREATE INDEX IF NOT EXISTS idx_worker_tasks_run_id ON worker_tasks(run_id);
                CREATE INDEX IF NOT EXISTS idx_worker_tasks_agent_name ON worker_tasks(agent_name);
                CREATE INDEX IF NOT EXISTS idx_worker_tasks_lease ON worker_tasks(lease_expires_at);
                CREATE INDEX IF NOT EXISTS idx_workers_status ON workers(status);
                """
            )

    def enqueue(self, task: Any) -> dict[str, Any]:
        payload = _payload_from_task(task)
        try:
            with self._connect() as conn:
                if self.backend == "postgres":
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            INSERT INTO {self._tasks_table()} (
                                task_id, run_id, plan_task_id, task_node_id, agent_name,
                                alert_json, db_path, status, created_at, worker_id,
                                claimed_at, completed_at, result_json, error, lease_expires_at, attempt_count
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            tuple(payload[column] for column in _TASK_COLUMNS),
                        )
                else:
                    conn.execute(
                        """
                        INSERT INTO worker_tasks (
                            task_id, run_id, plan_task_id, task_node_id, agent_name,
                            alert_json, db_path, status, created_at, worker_id,
                            claimed_at, completed_at, result_json, error, lease_expires_at, attempt_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        tuple(payload[column] for column in _TASK_COLUMNS),
                    )
        except Exception as exc:
            raise WorkerQueueError(f"enqueue failed: {exc}") from exc
        return payload

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(f"SELECT * FROM {self._tasks_table()} WHERE task_id = %s", (task_id,))
                    row = cur.fetchone()
            else:
                row = conn.execute("SELECT * FROM worker_tasks WHERE task_id = ?", (task_id,)).fetchone()
        return _row_to_task_record(row) if row else None

    def list_tasks(self, status: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        query = f"SELECT * FROM {self._tasks_table()}" if self.backend == "postgres" else "SELECT * FROM worker_tasks"
        params: list[Any] = []
        if status:
            query += " WHERE status = %s" if self.backend == "postgres" else " WHERE status = ?"
            params.append(status)
        query += " ORDER BY created_at ASC, task_id ASC"
        if limit is not None:
            query += " LIMIT %s" if self.backend == "postgres" else " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(query, params)
                    rows = cur.fetchall()
            else:
                rows = conn.execute(query, params).fetchall()
        return [_row_to_task_record(row) for row in rows]

    def register_worker(
        self,
        worker_id: str,
        *,
        status: str = "idle",
        current_task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        started_at: str | None = None,
        last_heartbeat_at: str | None = None,
    ) -> dict[str, Any]:
        started_value = started_at or _now()
        heartbeat_value = last_heartbeat_at or started_value
        metadata_json = json.dumps(metadata or {}, sort_keys=True)
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        INSERT INTO {self._workers_table()} (
                            worker_id, started_at, last_heartbeat_at, status, current_task_id, metadata_json
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT(worker_id) DO UPDATE SET
                            last_heartbeat_at = excluded.last_heartbeat_at,
                            status = excluded.status,
                            current_task_id = excluded.current_task_id,
                            metadata_json = excluded.metadata_json
                        """,
                        (worker_id, started_value, heartbeat_value, status, current_task_id, metadata_json),
                    )
                    cur.execute(f"SELECT * FROM {self._workers_table()} WHERE worker_id = %s", (worker_id,))
                    row = cur.fetchone()
            else:
                conn.execute(
                    """
                    INSERT INTO workers (
                        worker_id, started_at, last_heartbeat_at, status, current_task_id, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(worker_id) DO UPDATE SET
                        last_heartbeat_at=excluded.last_heartbeat_at,
                        status=excluded.status,
                        current_task_id=excluded.current_task_id,
                        metadata_json=excluded.metadata_json
                    """,
                    (worker_id, started_value, heartbeat_value, status, current_task_id, metadata_json),
                )
                row = conn.execute("SELECT * FROM workers WHERE worker_id = ?", (worker_id,)).fetchone()
        return _row_to_worker_record(row)

    def heartbeat_worker(
        self,
        worker_id: str,
        *,
        status: str | None = None,
        current_task_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        last_heartbeat_at: str | None = None,
    ) -> dict[str, Any]:
        existing = self.get_worker(worker_id)
        if existing is None:
            return self.register_worker(
                worker_id,
                status=status or "idle",
                current_task_id=current_task_id,
                metadata=metadata,
                last_heartbeat_at=last_heartbeat_at,
            )

        heartbeat_value = last_heartbeat_at or _now()
        next_status = status or existing["status"]
        next_task = current_task_id if current_task_id is not None else existing.get("current_task_id")
        next_metadata = metadata if metadata is not None else existing.get("metadata", {})
        return self.register_worker(
            worker_id,
            status=next_status,
            current_task_id=next_task,
            metadata=next_metadata,
            started_at=existing["started_at"],
            last_heartbeat_at=heartbeat_value,
        )

    def get_worker(self, worker_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(f"SELECT * FROM {self._workers_table()} WHERE worker_id = %s", (worker_id,))
                    row = cur.fetchone()
            else:
                row = conn.execute("SELECT * FROM workers WHERE worker_id = ?", (worker_id,)).fetchone()
        return _row_to_worker_record(row) if row else None

    def list_workers(self, status: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        query = f"SELECT * FROM {self._workers_table()}" if self.backend == "postgres" else "SELECT * FROM workers"
        params: list[Any] = []
        if status:
            query += " WHERE status = %s" if self.backend == "postgres" else " WHERE status = ?"
            params.append(status)
        query += " ORDER BY last_heartbeat_at DESC, worker_id ASC"
        if limit is not None:
            query += " LIMIT %s" if self.backend == "postgres" else " LIMIT ?"
            params.append(limit)
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(query, params)
                    rows = cur.fetchall()
            else:
                rows = conn.execute(query, params).fetchall()
        return [_row_to_worker_record(row) for row in rows]

    def claim_next(self, worker_id: str, lease_seconds: float | None = None) -> dict[str, Any] | None:
        lease = self.default_lease_seconds if lease_seconds is None else float(lease_seconds)
        now_value = _now()
        lease_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=lease)).isoformat()
        try:
            with self._connect() as conn:
                if self.backend == "postgres":
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT * FROM {self._tasks_table()}
                            WHERE status = 'pending'
                               OR (status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at <= %s)
                            ORDER BY created_at ASC, task_id ASC
                            LIMIT 1
                            FOR UPDATE SKIP LOCKED
                            """,
                            (now_value,),
                        )
                        row = cur.fetchone()
                        if row is None:
                            return None
                        cur.execute(
                            f"""
                            UPDATE {self._tasks_table()}
                            SET status = 'claimed',
                                worker_id = %s,
                                claimed_at = %s,
                                completed_at = NULL,
                                lease_expires_at = %s,
                                attempt_count = COALESCE(attempt_count, 0) + 1
                            WHERE task_id = %s
                            """,
                            (worker_id, now_value, lease_expires_at, row["task_id"]),
                        )
                        cur.execute(f"SELECT * FROM {self._tasks_table()} WHERE task_id = %s", (row["task_id"],))
                        updated = cur.fetchone()
                else:
                    conn.execute("BEGIN IMMEDIATE")
                    row = conn.execute(
                        """
                        SELECT * FROM worker_tasks
                        WHERE status = 'pending'
                           OR (status IN ('claimed', 'running') AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
                        ORDER BY created_at ASC, task_id ASC
                        LIMIT 1
                        """,
                        (now_value,),
                    ).fetchone()
                    if row is None:
                        conn.rollback()
                        return None
                    conn.execute(
                        """
                        UPDATE worker_tasks
                        SET status = 'claimed',
                            worker_id = ?,
                            claimed_at = ?,
                            completed_at = NULL,
                            lease_expires_at = ?,
                            attempt_count = COALESCE(attempt_count, 0) + 1
                        WHERE task_id = ?
                        """,
                        (worker_id, now_value, lease_expires_at, row["task_id"]),
                    )
                    updated = conn.execute("SELECT * FROM worker_tasks WHERE task_id = ?", (row["task_id"],)).fetchone()
        except Exception as exc:
            raise WorkerQueueError(f"claim_next failed: {exc}") from exc

        claimed = _row_to_task_record(updated) if updated else None
        if claimed is not None:
            self.heartbeat_worker(worker_id, status="busy", current_task_id=claimed["task_id"])
        return claimed

    def update_task(
        self,
        task_id: str,
        *,
        status: str | None = None,
        worker_id: str | None = None,
        claimed_at: str | None = None,
        completed_at: str | None = None,
        result: Any | None = None,
        error: str | None = None,
        lease_expires_at: str | None = None,
        attempt_count: int | None = None,
    ) -> dict[str, Any]:
        updates: list[str] = []
        params: list[Any] = []
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if worker_id is not None or status == "pending":
            updates.append("worker_id = ?")
            params.append(worker_id)
        if claimed_at is not None or status == "pending":
            updates.append("claimed_at = ?")
            params.append(claimed_at)
        if completed_at is not None:
            updates.append("completed_at = ?")
            params.append(completed_at)
        if result is not None:
            updates.append("result_json = ?")
            params.append(json.dumps(result))
        if error is not None:
            updates.append("error = ?")
            params.append(error)
        if lease_expires_at is not None or status in {"pending", "completed", "failed"}:
            updates.append("lease_expires_at = ?")
            params.append(lease_expires_at)
        if attempt_count is not None:
            updates.append("attempt_count = ?")
            params.append(attempt_count)

        if not updates:
            record = self.get_task(task_id)
            if record is None:
                raise WorkerQueueError(f"task {task_id!r} not found")
            return record

        params.append(task_id)
        try:
            with self._connect() as conn:
                if self.backend == "postgres":
                    statement = f"UPDATE {self._tasks_table()} SET {', '.join(update.replace('?', '%s') for update in updates)} WHERE task_id = %s"
                    with conn.cursor() as cur:
                        cur.execute(statement, params)
                        if cur.rowcount == 0:
                            raise WorkerQueueError(f"task {task_id!r} not found")
                        cur.execute(f"SELECT * FROM {self._tasks_table()} WHERE task_id = %s", (task_id,))
                        row = cur.fetchone()
                else:
                    cursor = conn.execute(
                        f"UPDATE worker_tasks SET {', '.join(updates)} WHERE task_id = ?",
                        params,
                    )
                    if cursor.rowcount == 0:
                        raise WorkerQueueError(f"task {task_id!r} not found")
                    row = conn.execute("SELECT * FROM worker_tasks WHERE task_id = ?", (task_id,)).fetchone()
        except Exception as exc:
            if isinstance(exc, WorkerQueueError):
                raise
            raise WorkerQueueError(f"update_task failed: {exc}") from exc

        record = _row_to_task_record(row) if row else None
        if record is None:
            raise WorkerQueueError(f"task {task_id!r} not found")
        if record["status"] in {"completed", "failed", "pending"} and record.get("worker_id"):
            self.heartbeat_worker(record["worker_id"], status="idle", current_task_id=None)
        return record

    def complete_task(self, task_id: str, result: Any | None = None) -> dict[str, Any]:
        return self.update_task(
            task_id,
            status="completed",
            completed_at=_now(),
            result=result,
            error=None,
            lease_expires_at=None,
        )

    def fail_task(self, task_id: str, error: str) -> dict[str, Any]:
        return self.update_task(
            task_id,
            status="failed",
            completed_at=_now(),
            error=error,
            lease_expires_at=None,
        )

    def sweep_stale_tasks(self, *, now: str | None = None) -> list[dict[str, Any]]:
        threshold = now or _now()
        stale: list[dict[str, Any]] = []
        for task in self.list_tasks():
            if task["status"] not in {"claimed", "running"}:
                continue
            lease = _parse_time(task.get("lease_expires_at"))
            if lease is None or lease > _parse_time(threshold):
                continue
            stale.append(
                self.update_task(
                    task["task_id"],
                    status="pending",
                    worker_id=None,
                    claimed_at=None,
                    completed_at=None,
                    result=None,
                    error=task.get("error"),
                    lease_expires_at=None,
                )
            )
        return stale

    def sweep_stale_workers(self, *, timeout_seconds: float, now: str | None = None) -> list[dict[str, Any]]:
        if timeout_seconds <= 0:
            return []
        current_time = _parse_time(now or _now())
        stale_workers: list[dict[str, Any]] = []
        for worker in self.list_workers():
            last_seen = _parse_time(worker.get("last_heartbeat_at"))
            if last_seen is None:
                continue
            if (current_time - last_seen).total_seconds() < float(timeout_seconds):
                continue
            updated_worker = self.heartbeat_worker(
                worker["worker_id"],
                status="stale",
                current_task_id=None,
                metadata=worker.get("metadata"),
                last_heartbeat_at=worker["last_heartbeat_at"],
            )
            stale_workers.append(updated_worker)
            current_task_id = worker.get("current_task_id")
            if current_task_id and self.get_task(current_task_id):
                self.update_task(
                    current_task_id,
                    status="pending",
                    worker_id=None,
                    claimed_at=None,
                    completed_at=None,
                    result=None,
                    error=f"requeued after stale worker {worker['worker_id']}",
                    lease_expires_at=None,
                )
        return stale_workers
