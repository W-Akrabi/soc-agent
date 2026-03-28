from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:  # pragma: no cover - exercised via test skips
    psycopg = None
    dict_row = None

from core.storage import StorageError
from core.storage_migrations import bootstrap_postgres_schema


class PostgresStorageBackend:
    def __init__(self, dsn: str, schema: str = "public", vector_dimensions: int = 1536):
        if psycopg is None:
            raise ImportError("psycopg is required for PostgresStorageBackend")
        self.db_path = dsn
        self.dsn = dsn
        self.schema = schema
        self.vector_dimensions = vector_dimensions
        self._init_db()

    def _connect(self):
        return psycopg.connect(self.dsn)

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                bootstrap_postgres_schema(
                    conn,
                    schema=self.schema,
                    vector_dimensions=self.vector_dimensions,
                )
        except Exception as e:
            raise StorageError(f"Postgres bootstrap failed: {e}") from e

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        data = d.get("data")
        if isinstance(data, str):
            d["data"] = json.loads(data)
        return d

    def write_node(
        self,
        type: str,
        label: str,
        data: dict,
        created_by: str,
        status: str = "active",
    ) -> str:
        node_id = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"INSERT INTO {self.schema}.nodes "
                        "(id, type, label, data, status, created_by, created_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (node_id, type, label, json.dumps(data), status, created_by, self._now()),
                    )
        except Exception as e:
            raise StorageError(f"write_node failed: {e}") from e
        return node_id

    def write_edge(
        self,
        src_id: str,
        dst_id: str,
        relation: str,
        created_by: str,
        data: dict | None = None,
    ) -> str:
        edge_id = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"INSERT INTO {self.schema}.edges "
                        "(id, src_id, dst_id, relation, data, created_by, created_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (
                            edge_id,
                            src_id,
                            dst_id,
                            relation,
                            json.dumps(data) if data is not None else None,
                            created_by,
                            self._now(),
                        ),
                    )
        except Exception as e:
            raise StorageError(f"write_edge failed: {e}") from e
        return edge_id

    def update_node_status(self, node_id: str, status: str) -> None:
        try:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"UPDATE {self.schema}.nodes SET status=%s WHERE id=%s",
                        (status, node_id),
                    )
        except Exception as e:
            raise StorageError(f"update_node_status failed: {e}") from e

    def get_node(self, node_id: str) -> dict | None:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(f"SELECT * FROM {self.schema}.nodes WHERE id=%s", (node_id,))
                row = cur.fetchone()
        return self._row_to_dict(row) if row else None

    def get_nodes_by_type(self, type: str) -> list[dict]:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(f"SELECT * FROM {self.schema}.nodes WHERE type=%s", (type,))
                rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_neighbors(self, node_id: str, relation: str | None = None) -> list[dict]:
        query = (
            f"SELECT n.* FROM {self.schema}.nodes n "
            f"JOIN {self.schema}.edges e ON e.dst_id = n.id "
            "WHERE e.src_id=%s"
        )
        params: list = [node_id]
        if relation:
            query += " AND e.relation=%s"
            params.append(relation)

        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_task_status(self, task_id: str) -> str:
        node = self.get_node(task_id)
        if not node:
            raise StorageError(f"Task node {task_id} not found")
        return node["status"]

    def get_full_graph(self) -> dict:
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(f"SELECT * FROM {self.schema}.nodes")
                nodes = [self._row_to_dict(r) for r in cur.fetchall()]
                cur.execute(f"SELECT * FROM {self.schema}.edges")
                edges = [dict(r) for r in cur.fetchall()]
        return {"nodes": nodes, "edges": edges}

    def search_nodes(
        self,
        type: str | None = None,
        label_contains: str | None = None,
        data_contains: dict | None = None,
    ) -> list[dict]:
        query = f"SELECT * FROM {self.schema}.nodes WHERE 1=1"
        params: list = []
        if type:
            query += " AND type=%s"
            params.append(type)
        if label_contains:
            query += " AND label LIKE %s"
            params.append(f"%{label_contains}%")
        if data_contains:
            for k, v in data_contains.items():
                query += f" AND (data::jsonb ->> %s) = %s"
                params.extend([k, str(v)])
        with self._connect() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(query, tuple(params))
                rows = cur.fetchall()
        return [self._row_to_dict(r) for r in rows]
