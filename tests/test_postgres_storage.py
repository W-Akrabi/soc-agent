import os

import pytest


psycopg = pytest.importorskip("psycopg")


def _skip_if_unavailable():
    dsn = os.getenv("SOC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SOC_TEST_POSTGRES_DSN not set")
    return dsn


def _make_backend():
    from core.storage_postgres import PostgresStorageBackend

    dsn = _skip_if_unavailable()
    try:
        return PostgresStorageBackend(dsn)
    except Exception as exc:
        pytest.skip(f"Postgres backend unavailable: {exc}")


def test_postgres_write_and_get_node():
    backend = _make_backend()
    node_id = backend.write_node("ip", "1.2.3.4", {"geo": "US"}, "recon", status="queued")
    node = backend.get_node(node_id)
    assert node is not None
    assert node["label"] == "1.2.3.4"
    assert node["data"]["geo"] == "US"


def test_postgres_write_edge_and_search():
    backend = _make_backend()
    src_id = backend.write_node("ip", "5.6.7.8", {"geo": "RU"}, "recon")
    dst_id = backend.write_node("cve", "CVE-2024-9999", {}, "intel")
    backend.write_edge(src_id, dst_id, "linked_to", "intel")

    neighbors = backend.get_neighbors(src_id)
    assert any(node["id"] == dst_id for node in neighbors)

    results = backend.search_nodes(type="ip", label_contains="5.6", data_contains={"geo": "RU"})
    assert len(results) == 1


def test_postgres_update_status_and_full_graph():
    backend = _make_backend()
    node_id = backend.write_node("task", "task-1", {}, "commander")
    backend.update_node_status(node_id, "running")
    assert backend.get_task_status(node_id) == "running"

    graph = backend.get_full_graph()
    assert any(node["id"] == node_id for node in graph["nodes"])
