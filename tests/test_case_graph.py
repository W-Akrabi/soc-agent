import pytest
from core.case_graph import CaseGraph, CaseGraphError


@pytest.fixture
def graph(tmp_path):
    db = str(tmp_path / "test.db")
    return CaseGraph(db_path=db)


def test_write_and_get_node(graph):
    node_id = graph.write_node(type="ip", label="1.2.3.4", data={"geo": "RU"}, created_by="recon")
    node = graph.get_node(node_id)
    assert node["type"] == "ip"
    assert node["label"] == "1.2.3.4"
    assert node["data"]["geo"] == "RU"
    assert node["status"] == "active"
    assert node["created_by"] == "recon"


def test_write_edge(graph):
    ip_id = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    cve_id = graph.write_node(type="cve", label="CVE-2024-1337", data={}, created_by="intel")
    edge_id = graph.write_edge(src_id=ip_id, dst_id=cve_id, relation="linked_to", created_by="intel")
    assert edge_id is not None
    neighbors = graph.get_neighbors(ip_id)
    assert any(n["id"] == cve_id for n in neighbors)


def test_update_node_status(graph):
    node_id = graph.write_node(type="task", label="recon-task", data={}, created_by="commander")
    graph.update_node_status(node_id, "running")
    node = graph.get_node(node_id)
    assert node["status"] == "running"


def test_get_nodes_by_type(graph):
    graph.write_node(type="ip", label="1.1.1.1", data={}, created_by="recon")
    graph.write_node(type="ip", label="2.2.2.2", data={}, created_by="recon")
    graph.write_node(type="cve", label="CVE-X", data={}, created_by="intel")
    ips = graph.get_nodes_by_type("ip")
    assert len(ips) == 2
    assert all(n["type"] == "ip" for n in ips)


def test_get_task_status(graph):
    node_id = graph.write_node(type="task", label="task-1", data={}, created_by="commander")
    assert graph.get_task_status(node_id) == "active"
    graph.update_node_status(node_id, "completed")
    assert graph.get_task_status(node_id) == "completed"


def test_get_full_graph(graph):
    n1 = graph.write_node(type="alert", label="alert-1", data={}, created_by="ingestion")
    n2 = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    graph.write_edge(src_id=n1, dst_id=n2, relation="involves", created_by="recon")
    full = graph.get_full_graph()
    assert len(full["nodes"]) == 2
    assert len(full["edges"]) == 1


def test_search_nodes(graph):
    graph.write_node(type="ip", label="192.168.1.1", data={"geo": "US"}, created_by="recon")
    graph.write_node(type="ip", label="10.0.0.1", data={"geo": "RU"}, created_by="recon")
    results = graph.search_nodes(type="ip", label_contains="192")
    assert len(results) == 1
    assert results[0]["label"] == "192.168.1.1"


def test_missing_node_returns_none(graph):
    assert graph.get_node("nonexistent-id") is None


def test_get_neighbors_with_relation_filter(graph):
    ip_id = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    cve_id = graph.write_node(type="cve", label="CVE-X", data={}, created_by="intel")
    domain_id = graph.write_node(type="domain", label="evil.com", data={}, created_by="recon")
    graph.write_edge(ip_id, cve_id, "linked_to", "intel")
    graph.write_edge(ip_id, domain_id, "resolves_to", "recon")
    linked = graph.get_neighbors(ip_id, relation="linked_to")
    assert len(linked) == 1
    assert linked[0]["id"] == cve_id
