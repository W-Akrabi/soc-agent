from __future__ import annotations

from psycopg import sql


def bootstrap_postgres_schema(conn, schema: str = "public", vector_dimensions: int = 1536) -> None:
    """Create the base schema and best-effort pgvector support."""
    schema_ident = sql.Identifier(schema)
    nodes_table = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {}.nodes (
            id         TEXT PRIMARY KEY,
            type       TEXT NOT NULL,
            label      TEXT NOT NULL,
            data       TEXT NOT NULL,
            status     TEXT NOT NULL DEFAULT 'active',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    ).format(schema_ident)
    edges_table = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {}.edges (
            id         TEXT PRIMARY KEY,
            src_id     TEXT NOT NULL,
            dst_id     TEXT NOT NULL,
            relation   TEXT NOT NULL,
            data       TEXT,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    ).format(schema_ident)
    embeddings_table = sql.SQL(
        """
        CREATE TABLE IF NOT EXISTS {}.embeddings (
            id         TEXT PRIMARY KEY,
            node_id    TEXT NOT NULL,
            embedding  vector({dim}),
            created_at TEXT NOT NULL
        )
        """
    ).format(schema_ident, dim=sql.SQL(str(int(vector_dimensions))))

    indices = [
        sql.SQL("CREATE INDEX IF NOT EXISTS idx_nodes_type ON {}.nodes(type)").format(schema_ident),
        sql.SQL("CREATE INDEX IF NOT EXISTS idx_nodes_status ON {}.nodes(status)").format(schema_ident),
        sql.SQL("CREATE INDEX IF NOT EXISTS idx_edges_src ON {}.edges(src_id)").format(schema_ident),
        sql.SQL("CREATE INDEX IF NOT EXISTS idx_edges_dst ON {}.edges(dst_id)").format(schema_ident),
    ]

    original_autocommit = conn.autocommit
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(schema_ident))
            cur.execute(nodes_table)
            cur.execute(edges_table)
            for statement in indices:
                cur.execute(statement)
            try:
                cur.execute("CREATE EXTENSION IF NOT EXISTS vector")
                cur.execute(embeddings_table)
            except Exception:
                conn.rollback()
    finally:
        conn.autocommit = original_autocommit
