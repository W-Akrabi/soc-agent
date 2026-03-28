from __future__ import annotations

from typing import Protocol, runtime_checkable


class StorageError(Exception):
    pass


@runtime_checkable
class StorageBackend(Protocol):
    db_path: str

    def write_node(
        self,
        type: str,
        label: str,
        data: dict,
        created_by: str,
        status: str = "active",
    ) -> str: ...

    def write_edge(
        self,
        src_id: str,
        dst_id: str,
        relation: str,
        created_by: str,
        data: dict | None = None,
    ) -> str: ...

    def update_node_status(self, node_id: str, status: str) -> None: ...
    def get_node(self, node_id: str) -> dict | None: ...
    def get_nodes_by_type(self, type: str) -> list[dict]: ...
    def get_neighbors(self, node_id: str, relation: str | None = None) -> list[dict]: ...
    def get_task_status(self, task_id: str) -> str: ...
    def get_full_graph(self) -> dict: ...
    def search_nodes(
        self,
        type: str | None = None,
        label_contains: str | None = None,
        data_contains: dict | None = None,
    ) -> list[dict]: ...


def build_storage(
    backend: str = "sqlite",
    *,
    db_path: str = "./soc_cases.db",
    postgres_dsn: str | None = None,
    postgres_schema: str = "public",
    vector_dimensions: int = 1536,
) -> StorageBackend:
    backend_name = backend.lower().strip()
    if backend_name == "sqlite":
        from core.storage_sqlite import SQLiteStorageBackend

        return SQLiteStorageBackend(db_path)

    if backend_name == "postgres":
        if not postgres_dsn:
            raise ValueError("postgres_dsn is required for postgres storage")
        from core.storage_postgres import PostgresStorageBackend

        return PostgresStorageBackend(
            postgres_dsn,
            schema=postgres_schema,
            vector_dimensions=vector_dimensions,
        )

    raise ValueError(f"Unsupported storage backend: {backend}")
