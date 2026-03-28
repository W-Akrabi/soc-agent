from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
import uuid
from typing import Any

from core.postgres_support import connect_postgres, ensure_schema, qualified_name, validate_schema_name


class ApprovalQueueError(Exception):
    pass


class ApprovalQueue:
    def __init__(
        self,
        db_path: str = "./soc_approvals.db",
        *,
        backend: str = "sqlite",
        postgres_dsn: str | None = None,
        postgres_schema: str = "soc_control",
    ):
        self.backend = (backend or "sqlite").strip().lower() or "sqlite"
        self.postgres_schema = validate_schema_name(postgres_schema) if self.backend == "postgres" else None
        self.dsn = postgres_dsn or db_path if self.backend == "postgres" else None
        self.db_path = self.dsn or db_path
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

    def _table(self) -> str:
        if self.backend == "postgres":
            return qualified_name(self.postgres_schema, "approval_queue")
        return "approval_queue"

    def _init_db(self) -> None:
        if self.backend == "postgres":
            table = self._table()
            with self._connect() as conn:
                ensure_schema(conn, self.postgres_schema)
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {table} (
                            action_id TEXT PRIMARY KEY,
                            run_id TEXT,
                            alert_id TEXT,
                            action_type TEXT NOT NULL,
                            target TEXT NOT NULL,
                            reason TEXT NOT NULL,
                            urgency TEXT NOT NULL,
                            blast_radius TEXT NOT NULL,
                            status TEXT NOT NULL,
                            created_at TEXT NOT NULL,
                            reviewed_at TEXT,
                            reviewed_by TEXT,
                            rollback_supported INTEGER NOT NULL DEFAULT 0,
                            rollback_action_type TEXT,
                            rollback_data_json TEXT NOT NULL DEFAULT '{{}}',
                            execution_result_json TEXT,
                            payload_json TEXT NOT NULL
                        )
                        """
                    )
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_approval_queue_status ON {table}(status, created_at)"
                    )
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_approval_queue_action_type ON {table}(action_type)"
                    )
                    cur.execute(
                        f"""
                        CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_queue_pending_unique
                        ON {table}(run_id, action_type, target)
                        WHERE status = 'pending'
                        """
                    )
            return
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS approval_queue (
                    action_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    alert_id TEXT,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    urgency TEXT NOT NULL,
                    blast_radius TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    reviewed_by TEXT,
                    rollback_supported INTEGER NOT NULL DEFAULT 0,
                    rollback_action_type TEXT,
                    rollback_data_json TEXT NOT NULL DEFAULT '{}',
                    execution_result_json TEXT,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_approval_queue_status
                    ON approval_queue(status, created_at);
                CREATE INDEX IF NOT EXISTS idx_approval_queue_action_type
                    ON approval_queue(action_type);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_queue_pending_unique
                    ON approval_queue(run_id, action_type, target)
                    WHERE status = 'pending';
                """
            )

    def enqueue(self, item: Any) -> dict[str, Any]:
        record = self._coerce_record(item)
        action_id = str(record.get("action_id") or uuid.uuid4())
        created_at = str(record.get("created_at") or datetime.now(timezone.utc).isoformat())
        status = self._normalize_status(str(record.get("status") or "pending"))
        if status == "awaiting_approval":
            status = "pending"

        normalized = {
            "action_id": action_id,
            "run_id": str(record.get("run_id") or ""),
            "alert_id": str(record.get("alert_id") or ""),
            "action_type": str(record.get("action_type") or ""),
            "target": str(record.get("target") or ""),
            "reason": str(record.get("reason") or ""),
            "urgency": str(record.get("urgency") or ""),
            "blast_radius": str(record.get("blast_radius") or ""),
            "status": status,
            "created_at": created_at,
            "reviewed_at": record.get("reviewed_at"),
            "reviewed_by": record.get("reviewed_by"),
            "rollback_supported": bool(record.get("rollback_supported", False)),
            "rollback_action_type": record.get("rollback_action_type"),
            "rollback_data": self._jsonable(record.get("rollback_data") or {}),
            "execution_result": self._jsonable(record.get("execution_result")),
        }
        payload = self._jsonable({**record, **normalized})

        with self._connect() as conn:
            if self.backend == "postgres":
                table = self._table()
                with conn.cursor() as cur:
                    existing = None
                    if normalized["status"] == "pending":
                        cur.execute(
                            f"""
                            SELECT action_id
                            FROM {table}
                            WHERE run_id = %s AND action_type = %s AND target = %s AND status = 'pending'
                            LIMIT 1
                            """,
                            (
                                normalized["run_id"],
                                normalized["action_type"],
                                normalized["target"],
                            ),
                        )
                        existing = cur.fetchone()
                    if existing is not None:
                        return self.get(existing["action_id"]) or payload
                    try:
                        cur.execute(
                            f"""
                            INSERT INTO {table} (
                                action_id, run_id, alert_id, action_type, target, reason, urgency,
                                blast_radius, status, created_at, reviewed_at, reviewed_by,
                                rollback_supported, rollback_action_type, rollback_data_json,
                                execution_result_json, payload_json
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                action_id,
                                normalized["run_id"],
                                normalized["alert_id"],
                                normalized["action_type"],
                                normalized["target"],
                                normalized["reason"],
                                normalized["urgency"],
                                normalized["blast_radius"],
                                normalized["status"],
                                normalized["created_at"],
                                normalized["reviewed_at"],
                                normalized["reviewed_by"],
                                1 if normalized["rollback_supported"] else 0,
                                normalized["rollback_action_type"],
                                json.dumps(normalized["rollback_data"]),
                                json.dumps(normalized["execution_result"]),
                                json.dumps(payload),
                            ),
                        )
                    except Exception:
                        if normalized["status"] != "pending":
                            raise
                        cur.execute(
                            f"""
                            SELECT action_id
                            FROM {table}
                            WHERE run_id = %s AND action_type = %s AND target = %s AND status = 'pending'
                            LIMIT 1
                            """,
                            (
                                normalized["run_id"],
                                normalized["action_type"],
                                normalized["target"],
                            ),
                        )
                        existing = cur.fetchone()
                        if existing is not None:
                            return self.get(existing["action_id"]) or payload
                        raise
            else:
                existing = None
                if normalized["status"] == "pending":
                    existing = conn.execute(
                        """
                        SELECT action_id
                        FROM approval_queue
                        WHERE run_id = ? AND action_type = ? AND target = ? AND status = 'pending'
                        LIMIT 1
                        """,
                        (
                            normalized["run_id"],
                            normalized["action_type"],
                            normalized["target"],
                        ),
                    ).fetchone()
                if existing is not None:
                    return self.get(existing["action_id"]) or payload
                try:
                    conn.execute(
                        """
                        INSERT INTO approval_queue (
                            action_id, run_id, alert_id, action_type, target, reason, urgency,
                            blast_radius, status, created_at, reviewed_at, reviewed_by,
                            rollback_supported, rollback_action_type, rollback_data_json,
                            execution_result_json, payload_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            action_id,
                            normalized["run_id"],
                            normalized["alert_id"],
                            normalized["action_type"],
                            normalized["target"],
                            normalized["reason"],
                            normalized["urgency"],
                            normalized["blast_radius"],
                            normalized["status"],
                            normalized["created_at"],
                            normalized["reviewed_at"],
                            normalized["reviewed_by"],
                            1 if normalized["rollback_supported"] else 0,
                            normalized["rollback_action_type"],
                            json.dumps(normalized["rollback_data"]),
                            json.dumps(normalized["execution_result"]),
                            json.dumps(payload),
                        ),
                    )
                except sqlite3.IntegrityError:
                    if normalized["status"] != "pending":
                        raise
                    existing = conn.execute(
                        """
                        SELECT action_id
                        FROM approval_queue
                        WHERE run_id = ? AND action_type = ? AND target = ? AND status = 'pending'
                        LIMIT 1
                        """,
                        (
                            normalized["run_id"],
                            normalized["action_type"],
                            normalized["target"],
                        ),
                    ).fetchone()
                    if existing is not None:
                        return self.get(existing["action_id"]) or payload
                    raise
        return self.get(action_id) or payload

    def get(self, action_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT * FROM {self._table()} WHERE action_id = %s",
                        (action_id,),
                    )
                    row = cur.fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM approval_queue WHERE action_id = ?",
                    (action_id,),
                ).fetchone()
        return self._row_to_record(row) if row else None

    def list_actions(self, status: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        table = self._table()
        query = f"SELECT * FROM {table}" if self.backend == "postgres" else "SELECT * FROM approval_queue"
        params: list[Any] = []
        if status:
            query += " WHERE status = %s" if self.backend == "postgres" else " WHERE status = ?"
            params.append(self._normalize_status(status))
        query += " ORDER BY created_at ASC"
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
        return [self._row_to_record(row) for row in rows]

    def list_pending(self, limit: int | None = None) -> list[dict[str, Any]]:
        return self.list_actions(status="pending", limit=limit)

    def approve(
        self,
        action_id: str,
        *,
        reviewed_by: str | None = None,
        execution_result: dict[str, Any] | None = None,
        rollback_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        status = "approved"
        if execution_result is not None:
            status = "executed" if execution_result.get("executed") else "failed"
        return self._update_review(
            action_id,
            status=status,
            reviewed_by=reviewed_by,
            execution_result=execution_result,
            rollback_data=rollback_data,
        )

    def reject(
        self,
        action_id: str,
        *,
        reviewed_by: str | None = None,
    ) -> dict[str, Any]:
        return self._update_review(action_id, status="rejected", reviewed_by=reviewed_by)

    def rollback(
        self,
        action_id: str,
        *,
        reviewed_by: str | None = None,
        execution_result: dict[str, Any] | None = None,
        rollback_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        status = "rolled_back"
        if execution_result is not None and not execution_result.get("executed", True):
            status = "failed"
        return self._update_review(
            action_id,
            status=status,
            reviewed_by=reviewed_by,
            execution_result=execution_result,
            rollback_data=rollback_data,
        )

    def _update_review(
        self,
        action_id: str,
        *,
        status: str,
        reviewed_by: str | None = None,
        execution_result: dict[str, Any] | None = None,
        rollback_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        reviewed_at = datetime.now(timezone.utc).isoformat()
        updates = [
            "status = ?",
            "reviewed_at = ?",
            "reviewed_by = ?",
            "execution_result_json = ?",
        ]
        params: list[Any] = [
            self._normalize_status(status),
            reviewed_at,
            reviewed_by,
            json.dumps(self._jsonable(execution_result)),
        ]
        if rollback_data is not None:
            updates.append("rollback_data_json = ?")
            params.append(json.dumps(self._jsonable(rollback_data)))
        params.append(action_id)
        with self._connect() as conn:
            if self.backend == "postgres":
                statement = (
                    f"""
                    UPDATE {self._table()}
                    SET {', '.join(update.replace("?", "%s") for update in updates)}
                    WHERE action_id = %s
                    """
                )
                with conn.cursor() as cur:
                    cur.execute(statement, params)
            else:
                conn.execute(
                    f"""
                    UPDATE approval_queue
                    SET {', '.join(updates)}
                    WHERE action_id = ?
                    """,
                    params,
                )
        record = self.get(action_id)
        if record is None:
            raise ApprovalQueueError(f"Approval action {action_id!r} not found")
        return record

    def _row_to_record(self, row) -> dict[str, Any]:
        payload = {}
        if row["payload_json"]:
            payload = json.loads(row["payload_json"])
        record = dict(payload)
        record.update(
            {
                "action_id": row["action_id"],
                "run_id": row["run_id"],
                "alert_id": row["alert_id"],
                "action_type": row["action_type"],
                "target": row["target"],
                "reason": row["reason"],
                "urgency": row["urgency"],
                "blast_radius": row["blast_radius"],
                "status": row["status"],
                "created_at": row["created_at"],
                "reviewed_at": row["reviewed_at"],
                "reviewed_by": row["reviewed_by"],
                "rollback_supported": bool(row["rollback_supported"]),
                "rollback_action_type": row["rollback_action_type"],
                "rollback_data": json.loads(row["rollback_data_json"] or "{}"),
                "execution_result": json.loads(row["execution_result_json"])
                if row["execution_result_json"]
                else None,
            }
        )
        return record

    def _coerce_record(self, item: Any) -> dict[str, Any]:
        if item is None:
            raise ApprovalQueueError("approval queue item cannot be None")
        if is_dataclass(item):
            return asdict(item)
        if isinstance(item, dict):
            return dict(item)
        if hasattr(item, "__dict__"):
            return {
                key: value
                for key, value in vars(item).items()
                if not key.startswith("_")
            }
        raise ApprovalQueueError(f"Unsupported approval queue item type: {type(item).__name__}")

    def _jsonable(self, value: Any) -> Any:
        if value is None:
            return None
        return json.loads(json.dumps(value, default=str))

    def _normalize_status(self, status: str) -> str:
        normalized = (status or "").strip().lower()
        if normalized in {"awaiting_approval", "queued"}:
            return "pending"
        return normalized or "pending"
