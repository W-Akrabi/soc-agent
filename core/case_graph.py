import json
import sqlite3
import uuid
from datetime import datetime, timezone


class CaseGraphError(Exception):
    pass


class CaseGraph:
    def __init__(self, db_path: str = "./soc_cases.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id         TEXT PRIMARY KEY,
                    type       TEXT NOT NULL,
                    label      TEXT NOT NULL,
                    data       TEXT NOT NULL,
                    status     TEXT NOT NULL DEFAULT 'active',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id         TEXT PRIMARY KEY,
                    src_id     TEXT NOT NULL REFERENCES nodes(id),
                    dst_id     TEXT NOT NULL REFERENCES nodes(id),
                    relation   TEXT NOT NULL,
                    data       TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_type   ON nodes(type);
                CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
                CREATE INDEX IF NOT EXISTS idx_edges_src    ON edges(src_id);
                CREATE INDEX IF NOT EXISTS idx_edges_dst    ON edges(dst_id);
            """)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d["data"])
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
                conn.execute(
                    "INSERT INTO nodes (id, type, label, data, status, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (node_id, type, label, json.dumps(data), status, created_by, self._now()),
                )
        except sqlite3.Error as e:
            raise CaseGraphError(f"write_node failed: {e}") from e
        return node_id

    def write_edge(self, src_id: str, dst_id: str, relation: str,
                   created_by: str, data: dict = None) -> str:
        edge_id = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO edges (id, src_id, dst_id, relation, data, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (edge_id, src_id, dst_id, relation,
                     json.dumps(data) if data else None, created_by, self._now()),
                )
        except sqlite3.Error as e:
            raise CaseGraphError(f"write_edge failed: {e}") from e
        return edge_id

    def update_node_status(self, node_id: str, status: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("UPDATE nodes SET status=? WHERE id=?", (status, node_id))
        except sqlite3.Error as e:
            raise CaseGraphError(f"update_node_status failed: {e}") from e

    def get_node(self, node_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def get_nodes_by_type(self, type: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM nodes WHERE type=?", (type,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_neighbors(self, node_id: str, relation: str = None) -> list[dict]:
        with self._connect() as conn:
            if relation:
                rows = conn.execute(
                    "SELECT n.* FROM nodes n "
                    "JOIN edges e ON e.dst_id = n.id "
                    "WHERE e.src_id=? AND e.relation=?",
                    (node_id, relation),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT n.* FROM nodes n "
                    "JOIN edges e ON e.dst_id = n.id "
                    "WHERE e.src_id=?",
                    (node_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_task_status(self, task_id: str) -> str:
        node = self.get_node(task_id)
        if not node:
            raise CaseGraphError(f"Task node {task_id} not found")
        return node["status"]

    def get_full_graph(self) -> dict:
        with self._connect() as conn:
            nodes = [self._row_to_dict(r) for r in conn.execute("SELECT * FROM nodes").fetchall()]
            rows = conn.execute("SELECT * FROM edges").fetchall()
            edges = [dict(r) for r in rows]
        return {"nodes": nodes, "edges": edges}

    def search_nodes(self, type: str = None, label_contains: str = None,
                     data_contains: dict = None) -> list[dict]:
        query = "SELECT * FROM nodes WHERE 1=1"
        params: list = []
        if type:
            query += " AND type=?"
            params.append(type)
        if label_contains:
            query += " AND label LIKE ?"
            params.append(f"%{label_contains}%")
        if data_contains:
            for k, v in data_contains.items():
                query += " AND json_extract(data, ?) = ?"
                params.extend([f"$.{k}", v])
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]
