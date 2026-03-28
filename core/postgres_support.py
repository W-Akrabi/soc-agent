from __future__ import annotations

import re

try:
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row
except Exception:  # pragma: no cover - exercised via skipped postgres tests
    psycopg = None
    sql = None
    dict_row = None


_SCHEMA_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def require_psycopg(component_name: str) -> None:
    if psycopg is None:
        raise ImportError(f"psycopg is required for {component_name}")


def validate_schema_name(schema: str) -> str:
    normalized = (schema or "").strip()
    if not normalized:
        raise ValueError("Postgres schema name cannot be empty")
    if not _SCHEMA_RE.fullmatch(normalized):
        raise ValueError(f"Invalid Postgres schema name: {schema!r}")
    return normalized


def connect_postgres(dsn: str):
    require_psycopg("postgres-backed control plane")
    return psycopg.connect(dsn, row_factory=dict_row)


def ensure_schema(conn, schema: str) -> None:
    require_psycopg("postgres-backed control plane")
    validated = validate_schema_name(schema)
    original_autocommit = conn.autocommit
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(validated)))
    finally:
        conn.autocommit = original_autocommit


def qualified_name(schema: str, table: str) -> str:
    validated_schema = validate_schema_name(schema)
    validated_table = validate_schema_name(table)
    return f"{validated_schema}.{validated_table}"
