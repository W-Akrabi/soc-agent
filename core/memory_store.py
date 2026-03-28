from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import asdict, is_dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.postgres_support import connect_postgres, ensure_schema, qualified_name, validate_schema_name
from core.schemas import AssetBaseline, IncidentMemory, PriorContext


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return dict(value.to_dict())
    return dict(vars(value))


def _normalize_list(values: Any) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        values = [values]
    result: list[str] = []
    for item in values:
        if item in (None, ""):
            continue
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _normalize_entities(entities: Any) -> dict[str, list[str]]:
    raw = _to_mapping(entities)
    normalized: dict[str, list[str]] = {}
    for key, values in raw.items():
        normalized[str(key)] = _normalize_list(values)
    return normalized


def _normalize_actions(actions: Any) -> list[dict[str, Any]]:
    if actions is None:
        return []
    if isinstance(actions, dict):
        return [dict(actions)]
    if not isinstance(actions, Iterable) or isinstance(actions, (str, bytes)):
        return [{"value": actions}]
    normalized: list[dict[str, Any]] = []
    for item in actions:
        if isinstance(item, dict):
            normalized.append(dict(item))
        elif is_dataclass(item):
            normalized.append(asdict(item))
        elif hasattr(item, "to_dict") and callable(item.to_dict):
            normalized.append(dict(item.to_dict()))
        else:
            normalized.append({"value": item})
    return normalized


def _row_to_incident(row: sqlite3.Row) -> IncidentMemory:
    entities = json.loads(row["entities_json"]) if row["entities_json"] else {}
    actions_taken = json.loads(row["actions_taken_json"]) if row["actions_taken_json"] else []
    return IncidentMemory(
        memory_id=row["memory_id"],
        incident_id=row["incident_id"],
        run_id=row["run_id"],
        alert_type=row["alert_type"],
        alert_json=row["alert_json"],
        entities=entities,
        actions_taken=actions_taken,
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        outcome=row["outcome"],
        analyst_notes=row["analyst_notes"],
        confidence_score=row["confidence_score"],
        created_at=row["created_at"],
    )


def _row_to_baseline(row: sqlite3.Row) -> AssetBaseline:
    tags = json.loads(row["tags_json"]) if row["tags_json"] else []
    return AssetBaseline(
        baseline_id=row["baseline_id"],
        entity_type=row["entity_type"],
        entity_value=row["entity_value"],
        baseline_type=row["baseline_type"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        incident_count=row["incident_count"],
        tags=tags,
    )


class MemoryStore:
    """SQLite-backed cross-incident memory for correlation and replay."""

    def __init__(
        self,
        db_path: str = "./soc_memory.db",
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

    def _table(self, name: str) -> str:
        if self.backend == "postgres":
            return qualified_name(self.postgres_schema, name)
        return name

    def _fetchone(
        self,
        sqlite_query: str,
        sqlite_params: tuple[Any, ...] | list[Any] = (),
        *,
        postgres_query: str | None = None,
        postgres_params: tuple[Any, ...] | list[Any] | None = None,
    ):
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(postgres_query or sqlite_query, postgres_params or sqlite_params)
                    return cur.fetchone()
            return conn.execute(sqlite_query, sqlite_params).fetchone()

    def _fetchall(
        self,
        sqlite_query: str,
        sqlite_params: tuple[Any, ...] | list[Any] = (),
        *,
        postgres_query: str | None = None,
        postgres_params: tuple[Any, ...] | list[Any] | None = None,
    ):
        with self._connect() as conn:
            if self.backend == "postgres":
                with conn.cursor() as cur:
                    cur.execute(postgres_query or sqlite_query, postgres_params or sqlite_params)
                    return cur.fetchall()
            return conn.execute(sqlite_query, sqlite_params).fetchall()

    def _init_db(self) -> None:
        if self.backend == "postgres":
            incident_table = self._table("incident_memory")
            baseline_table = self._table("asset_baseline")
            with self._connect() as conn:
                ensure_schema(conn, self.postgres_schema)
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {incident_table} (
                            memory_id TEXT PRIMARY KEY,
                            incident_id TEXT NOT NULL,
                            run_id TEXT NOT NULL UNIQUE,
                            alert_type TEXT NOT NULL,
                            alert_json TEXT NOT NULL,
                            entities_json TEXT NOT NULL,
                            actions_taken_json TEXT NOT NULL,
                            started_at TEXT NOT NULL,
                            completed_at TEXT,
                            outcome TEXT,
                            analyst_notes TEXT,
                            confidence_score REAL,
                            created_at TEXT NOT NULL
                        )
                        """
                    )
                    cur.execute(
                        f"""
                        CREATE TABLE IF NOT EXISTS {baseline_table} (
                            baseline_id TEXT PRIMARY KEY,
                            entity_type TEXT NOT NULL,
                            entity_value TEXT NOT NULL,
                            baseline_type TEXT NOT NULL,
                            first_seen TEXT NOT NULL,
                            last_seen TEXT NOT NULL,
                            incident_count INTEGER NOT NULL DEFAULT 1,
                            tags_json TEXT NOT NULL DEFAULT '[]',
                            UNIQUE(entity_type, entity_value, baseline_type)
                        )
                        """
                    )
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_incident_memory_run_id ON {incident_table}(run_id)"
                    )
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_incident_memory_incident_id ON {incident_table}(incident_id)"
                    )
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS idx_asset_baseline_entity ON {baseline_table}(entity_type, entity_value)"
                    )
            return
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS incident_memory (
                    memory_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    run_id TEXT NOT NULL UNIQUE,
                    alert_type TEXT NOT NULL,
                    alert_json TEXT NOT NULL,
                    entities_json TEXT NOT NULL,
                    actions_taken_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    outcome TEXT,
                    analyst_notes TEXT,
                    confidence_score REAL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS asset_baseline (
                    baseline_id TEXT PRIMARY KEY,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    baseline_type TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    incident_count INTEGER NOT NULL DEFAULT 1,
                    tags_json TEXT NOT NULL DEFAULT '[]',
                    UNIQUE(entity_type, entity_value, baseline_type)
                );
                CREATE INDEX IF NOT EXISTS idx_incident_memory_run_id ON incident_memory(run_id);
                CREATE INDEX IF NOT EXISTS idx_incident_memory_incident_id ON incident_memory(incident_id);
                CREATE INDEX IF NOT EXISTS idx_asset_baseline_entity ON asset_baseline(entity_type, entity_value);
                """
            )

    def write_memory(self, memory: Any, *, update_baselines: bool = True) -> IncidentMemory:
        record = self._coerce_incident(memory)
        payload = (
            record.memory_id,
            record.incident_id,
            record.run_id,
            record.alert_type,
            record.alert_json,
            json.dumps(record.entities, sort_keys=True),
            json.dumps(record.actions_taken, sort_keys=True, default=str),
            record.started_at,
            record.completed_at,
            record.outcome,
            record.analyst_notes,
            record.confidence_score,
            record.created_at or _now(),
        )

        with self._connect() as conn:
            if self.backend == "postgres":
                incident_table = self._table("incident_memory")
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT run_id FROM {incident_table} WHERE memory_id = %s",
                        (record.memory_id,),
                    )
                    existing = cur.fetchone()
                    if existing and existing["run_id"] != record.run_id:
                        record = replace(record, memory_id=str(uuid.uuid4()))
                        payload = (
                            record.memory_id,
                            record.incident_id,
                            record.run_id,
                            record.alert_type,
                            record.alert_json,
                            json.dumps(record.entities, sort_keys=True),
                            json.dumps(record.actions_taken, sort_keys=True, default=str),
                            record.started_at,
                            record.completed_at,
                            record.outcome,
                            record.analyst_notes,
                            record.confidence_score,
                            record.created_at or _now(),
                        )
                    cur.execute(
                        f"""
                        INSERT INTO {incident_table} (
                            memory_id, incident_id, run_id, alert_type, alert_json,
                            entities_json, actions_taken_json, started_at, completed_at,
                            outcome, analyst_notes, confidence_score, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT(run_id) DO UPDATE SET
                            memory_id=excluded.memory_id,
                            incident_id=excluded.incident_id,
                            alert_type=excluded.alert_type,
                            alert_json=excluded.alert_json,
                            entities_json=excluded.entities_json,
                            actions_taken_json=excluded.actions_taken_json,
                            started_at=excluded.started_at,
                            completed_at=excluded.completed_at,
                            outcome=excluded.outcome,
                            analyst_notes=excluded.analyst_notes,
                            confidence_score=excluded.confidence_score,
                            created_at=excluded.created_at
                        """,
                        payload,
                    )
            else:
                existing = conn.execute(
                    "SELECT run_id FROM incident_memory WHERE memory_id = ?",
                    (record.memory_id,),
                ).fetchone()
                if existing and existing["run_id"] != record.run_id:
                    record = replace(record, memory_id=str(uuid.uuid4()))
                    payload = (
                        record.memory_id,
                        record.incident_id,
                        record.run_id,
                        record.alert_type,
                        record.alert_json,
                        json.dumps(record.entities, sort_keys=True),
                        json.dumps(record.actions_taken, sort_keys=True, default=str),
                        record.started_at,
                        record.completed_at,
                        record.outcome,
                        record.analyst_notes,
                        record.confidence_score,
                        record.created_at or _now(),
                    )
                conn.execute(
                    """
                    INSERT INTO incident_memory (
                        memory_id, incident_id, run_id, alert_type, alert_json,
                        entities_json, actions_taken_json, started_at, completed_at,
                        outcome, analyst_notes, confidence_score, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id) DO UPDATE SET
                        memory_id=excluded.memory_id,
                        incident_id=excluded.incident_id,
                        alert_type=excluded.alert_type,
                        alert_json=excluded.alert_json,
                        entities_json=excluded.entities_json,
                        actions_taken_json=excluded.actions_taken_json,
                        started_at=excluded.started_at,
                        completed_at=excluded.completed_at,
                        outcome=excluded.outcome,
                        analyst_notes=excluded.analyst_notes,
                        confidence_score=excluded.confidence_score,
                        created_at=excluded.created_at
                    """,
                    payload,
                )

        stored = self.get_memory_by_run_id(record.run_id)
        if stored is None:
            raise RuntimeError(f"Failed to persist incident memory for run_id={record.run_id!r}")

        if update_baselines:
            self._update_baselines(stored)
        return stored

    def get_memory_by_run_id(self, run_id: str) -> IncidentMemory | None:
        row = self._fetchone(
            "SELECT * FROM incident_memory WHERE run_id=?",
            (run_id,),
            postgres_query=f"SELECT * FROM {self._table('incident_memory')} WHERE run_id=%s",
            postgres_params=(run_id,),
        )
        return _row_to_incident(row) if row else None

    def get_memory_by_incident_id(self, incident_id: str) -> IncidentMemory | None:
        row = self._fetchone(
            "SELECT * FROM incident_memory WHERE incident_id=? ORDER BY created_at DESC LIMIT 1",
            (incident_id,),
            postgres_query=f"SELECT * FROM {self._table('incident_memory')} WHERE incident_id=%s ORDER BY created_at DESC LIMIT 1",
            postgres_params=(incident_id,),
        )
        return _row_to_incident(row) if row else None

    def list_memories(self, *, limit: int | None = None) -> list[IncidentMemory]:
        query = "SELECT * FROM incident_memory ORDER BY created_at DESC"
        params: tuple[Any, ...] = ()
        postgres_query = f"SELECT * FROM {self._table('incident_memory')} ORDER BY created_at DESC"
        postgres_params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
            postgres_query += " LIMIT %s"
            postgres_params = (limit,)
        rows = self._fetchall(
            query,
            params,
            postgres_query=postgres_query,
            postgres_params=postgres_params,
        )
        return [_row_to_incident(row) for row in rows]

    def list_memories_for_entity(self, entity_type: str, entity_value: str, *, limit: int | None = None) -> list[IncidentMemory]:
        rows = self._fetchall(
            "SELECT * FROM incident_memory ORDER BY created_at DESC",
            (),
            postgres_query=f"SELECT * FROM {self._table('incident_memory')} ORDER BY created_at DESC",
            postgres_params=(),
        )
        matched: list[IncidentMemory] = []
        target_type = _canonical_entity_type(entity_type)
        for row in rows:
            memory = _row_to_incident(row)
            for key, values in memory.entities.items():
                if _canonical_entity_type(key) != target_type:
                    continue
                if entity_value in values:
                    matched.append(memory)
                    break
            if limit is not None and len(matched) >= limit:
                break
        return matched

    def list_baselines_for_entity(self, entity_type: str, entity_value: str, *, limit: int | None = None) -> list[AssetBaseline]:
        query = """
            SELECT *
            FROM asset_baseline
            WHERE entity_type = ? AND entity_value = ?
            ORDER BY incident_count DESC, last_seen DESC
        """
        params: list[Any] = [entity_type, entity_value]
        postgres_query = f"""
            SELECT *
            FROM {self._table('asset_baseline')}
            WHERE entity_type = %s AND entity_value = %s
            ORDER BY incident_count DESC, last_seen DESC
        """
        postgres_params: list[Any] = [entity_type, entity_value]
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)
            postgres_query += " LIMIT %s"
            postgres_params.append(limit)
        rows = self._fetchall(
            query,
            params,
            postgres_query=postgres_query,
            postgres_params=postgres_params,
        )
        return [_row_to_baseline(row) for row in rows]

    def list_baselines(self, *, limit: int | None = None) -> list[AssetBaseline]:
        query = "SELECT * FROM asset_baseline ORDER BY incident_count DESC, last_seen DESC"
        params: tuple[Any, ...] = ()
        postgres_query = f"SELECT * FROM {self._table('asset_baseline')} ORDER BY incident_count DESC, last_seen DESC"
        postgres_params: tuple[Any, ...] = ()
        if limit is not None:
            query += " LIMIT ?"
            params = (limit,)
            postgres_query += " LIMIT %s"
            postgres_params = (limit,)
        rows = self._fetchall(
            query,
            params,
            postgres_query=postgres_query,
            postgres_params=postgres_params,
        )
        return [_row_to_baseline(row) for row in rows]

    def upsert_baseline(
        self,
        entity_type: str,
        entity_value: str,
        *,
        baseline_type: str = "observed",
        first_seen: str | None = None,
        last_seen: str | None = None,
        tags: Iterable[str] | None = None,
        incident_count_increment: int = 1,
    ) -> AssetBaseline:
        first_seen_value = first_seen or _now()
        last_seen_value = last_seen or first_seen_value
        tag_list = [tag for tag in _normalize_list(tags)]

        with self._connect() as conn:
            if self.backend == "postgres":
                baseline_table = self._table("asset_baseline")
                with conn.cursor() as cur:
                    cur.execute(
                        f"""
                        SELECT * FROM {baseline_table}
                        WHERE entity_type = %s AND entity_value = %s AND baseline_type = %s
                        """,
                        (entity_type, entity_value, baseline_type),
                    )
                    existing = cur.fetchone()

                    if existing:
                        existing_tags = set(json.loads(existing["tags_json"]) or [])
                        existing_tags.update(tag_list)
                        cur.execute(
                            f"""
                            UPDATE {baseline_table}
                            SET last_seen = %s,
                                incident_count = incident_count + %s,
                                tags_json = %s
                            WHERE baseline_id = %s
                            """,
                            (
                                last_seen_value,
                                incident_count_increment,
                                json.dumps(sorted(existing_tags)),
                                existing["baseline_id"],
                            ),
                        )
                        cur.execute(
                            f"SELECT * FROM {baseline_table} WHERE baseline_id = %s",
                            (existing["baseline_id"],),
                        )
                        row = cur.fetchone()
                        return _row_to_baseline(row)

                    baseline = AssetBaseline(
                        baseline_id=str(uuid.uuid4()),
                        entity_type=entity_type,
                        entity_value=entity_value,
                        baseline_type=baseline_type,
                        first_seen=first_seen_value,
                        last_seen=last_seen_value,
                        incident_count=incident_count_increment,
                        tags=sorted(tag_list),
                    )
                    cur.execute(
                        f"""
                        INSERT INTO {baseline_table} (
                            baseline_id, entity_type, entity_value, baseline_type,
                            first_seen, last_seen, incident_count, tags_json
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            baseline.baseline_id,
                            baseline.entity_type,
                            baseline.entity_value,
                            baseline.baseline_type,
                            baseline.first_seen,
                            baseline.last_seen,
                            baseline.incident_count,
                            json.dumps(baseline.tags),
                        ),
                    )
                    return baseline

            existing = conn.execute(
                """
                SELECT * FROM asset_baseline
                WHERE entity_type = ? AND entity_value = ? AND baseline_type = ?
                """,
                (entity_type, entity_value, baseline_type),
            ).fetchone()

            if existing:
                existing_tags = set(json.loads(existing["tags_json"]) or [])
                existing_tags.update(tag_list)
                conn.execute(
                    """
                    UPDATE asset_baseline
                    SET last_seen = ?,
                        incident_count = incident_count + ?,
                        tags_json = ?
                    WHERE baseline_id = ?
                    """,
                    (
                        last_seen_value,
                        incident_count_increment,
                        json.dumps(sorted(existing_tags)),
                        existing["baseline_id"],
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM asset_baseline WHERE baseline_id = ?",
                    (existing["baseline_id"],),
                ).fetchone()
                return _row_to_baseline(row)

            baseline = AssetBaseline(
                baseline_id=str(uuid.uuid4()),
                entity_type=entity_type,
                entity_value=entity_value,
                baseline_type=baseline_type,
                first_seen=first_seen_value,
                last_seen=last_seen_value,
                incident_count=incident_count_increment,
                tags=sorted(tag_list),
            )
            conn.execute(
                """
                INSERT INTO asset_baseline (
                    baseline_id, entity_type, entity_value, baseline_type,
                    first_seen, last_seen, incident_count, tags_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    baseline.baseline_id,
                    baseline.entity_type,
                    baseline.entity_value,
                    baseline.baseline_type,
                    baseline.first_seen,
                    baseline.last_seen,
                    baseline.incident_count,
                    json.dumps(baseline.tags),
                ),
            )
            return baseline

    def _coerce_incident(self, memory: Any) -> IncidentMemory:
        if isinstance(memory, IncidentMemory):
            return memory
        payload = _to_mapping(memory)
        entities = _normalize_entities(payload.get("entities", {}))
        actions_taken = _normalize_actions(payload.get("actions_taken", []))
        return IncidentMemory(
            memory_id=str(payload.get("memory_id") or uuid.uuid4()),
            incident_id=str(payload["incident_id"]),
            run_id=str(payload["run_id"]),
            alert_type=str(payload["alert_type"]),
            alert_json=str(payload["alert_json"]),
            entities=entities,
            actions_taken=actions_taken,
            started_at=str(payload["started_at"]),
            completed_at=payload.get("completed_at"),
            outcome=payload.get("outcome"),
            analyst_notes=payload.get("analyst_notes"),
            confidence_score=payload.get("confidence_score"),
            created_at=payload.get("created_at"),
        )

    def _update_baselines(self, memory: IncidentMemory) -> None:
        first_seen = memory.completed_at or memory.started_at
        tag_values = [memory.alert_type]
        with self._connect() as conn:
            if self.backend == "postgres":
                baseline_table = self._table("asset_baseline")
                with conn.cursor() as cur:
                    for entity_type, values in memory.entities.items():
                        canonical = _canonical_entity_type(entity_type)
                        for entity_value in values:
                            cur.execute(
                                f"""
                                SELECT * FROM {baseline_table}
                                WHERE entity_type = %s AND entity_value = %s AND baseline_type = 'observed'
                                """,
                                (canonical, entity_value),
                            )
                            existing = cur.fetchone()
                            if existing:
                                existing_tags = set(json.loads(existing["tags_json"]) or [])
                                existing_tags.update(tag_values)
                                cur.execute(
                                    f"""
                                    UPDATE {baseline_table}
                                    SET last_seen = %s,
                                        incident_count = incident_count + 1,
                                        tags_json = %s
                                    WHERE baseline_id = %s
                                    """,
                                    (first_seen, json.dumps(sorted(existing_tags)), existing["baseline_id"]),
                                )
                            else:
                                cur.execute(
                                    f"""
                                    INSERT INTO {baseline_table} (
                                        baseline_id, entity_type, entity_value, baseline_type,
                                        first_seen, last_seen, incident_count, tags_json
                                    ) VALUES (%s, %s, %s, 'observed', %s, %s, 1, %s)
                                    """,
                                    (
                                        str(uuid.uuid4()),
                                        canonical,
                                        entity_value,
                                        first_seen,
                                        first_seen,
                                        json.dumps(tag_values),
                                    ),
                                )
                return

            for entity_type, values in memory.entities.items():
                canonical = _canonical_entity_type(entity_type)
                for entity_value in values:
                    existing = conn.execute(
                        """
                        SELECT * FROM asset_baseline
                        WHERE entity_type = ? AND entity_value = ? AND baseline_type = 'observed'
                        """,
                        (canonical, entity_value),
                    ).fetchone()
                    if existing:
                        existing_tags = set(json.loads(existing["tags_json"]) or [])
                        existing_tags.update(tag_values)
                        conn.execute(
                            """
                            UPDATE asset_baseline
                            SET last_seen = ?,
                                incident_count = incident_count + 1,
                                tags_json = ?
                            WHERE baseline_id = ?
                            """,
                            (first_seen, json.dumps(sorted(existing_tags)), existing["baseline_id"]),
                        )
                    else:
                        conn.execute(
                            """
                            INSERT INTO asset_baseline (
                                baseline_id, entity_type, entity_value, baseline_type,
                                first_seen, last_seen, incident_count, tags_json
                            ) VALUES (?, ?, ?, 'observed', ?, ?, 1, ?)
                            """,
                            (
                                str(uuid.uuid4()),
                                canonical,
                                entity_value,
                                first_seen,
                                first_seen,
                                json.dumps(tag_values),
                            ),
                        )


def _canonical_entity_type(entity_type: str) -> str:
    normalized = str(entity_type or "").strip().lower()
    aliases = {
        "hosts": "host",
        "host": "host",
        "users": "user",
        "user": "user",
        "ips": "ip",
        "ip": "ip",
        "domains": "domain",
        "domain": "domain",
        "hashes": "hash",
        "hash": "hash",
    }
    return aliases.get(normalized, normalized or "unknown")


__all__ = [
    "AssetBaseline",
    "IncidentMemory",
    "MemoryStore",
    "PriorContext",
]
