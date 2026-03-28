from core.storage import build_storage
from core.storage_sqlite import SQLiteStorageBackend


def make_backend(tmp_path):
    return SQLiteStorageBackend(str(tmp_path / "storage.db"))


def test_factory_returns_sqlite_backend(tmp_path):
    backend = build_storage(backend="sqlite", db_path=str(tmp_path / "factory.db"))
    assert isinstance(backend, SQLiteStorageBackend)


def test_write_and_get_node(tmp_path):
    backend = make_backend(tmp_path)
    node_id = backend.write_node(
        type="ip",
        label="1.2.3.4",
        data={"geo": "RU"},
        created_by="recon",
        status="queued",
    )

    node = backend.get_node(node_id)
    assert node is not None
    assert node["type"] == "ip"
    assert node["label"] == "1.2.3.4"
    assert node["data"]["geo"] == "RU"
    assert node["status"] == "queued"


def test_write_edge_and_get_neighbors(tmp_path):
    backend = make_backend(tmp_path)
    src_id = backend.write_node("ip", "1.2.3.4", {}, "recon")
    dst_id = backend.write_node("cve", "CVE-2024-1337", {}, "intel")
    edge_id = backend.write_edge(src_id, dst_id, "linked_to", "intel")

    assert edge_id
    neighbors = backend.get_neighbors(src_id)
    assert any(node["id"] == dst_id for node in neighbors)


def test_update_node_status(tmp_path):
    backend = make_backend(tmp_path)
    node_id = backend.write_node("task", "recon-task", {}, "commander")

    backend.update_node_status(node_id, "running")
    assert backend.get_task_status(node_id) == "running"


def test_get_nodes_by_type_and_search(tmp_path):
    backend = make_backend(tmp_path)
    backend.write_node("ip", "192.168.1.1", {"geo": "US"}, "recon")
    backend.write_node("ip", "10.0.0.1", {"geo": "RU"}, "recon")
    backend.write_node("cve", "CVE-X", {"severity": "critical"}, "intel")

    ips = backend.get_nodes_by_type("ip")
    assert len(ips) == 2

    results = backend.search_nodes(type="ip", label_contains="192", data_contains={"geo": "US"})
    assert len(results) == 1
    assert results[0]["label"] == "192.168.1.1"


def test_get_full_graph(tmp_path):
    backend = make_backend(tmp_path)
    node_a = backend.write_node("alert", "alert-1", {}, "ingestion")
    node_b = backend.write_node("ip", "1.2.3.4", {}, "recon")
    backend.write_edge(node_a, node_b, "involves", "recon")

    graph = backend.get_full_graph()
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
