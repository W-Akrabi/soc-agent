from core.case_graph import CaseGraph
from core.entity_extractor import extract_entities_from_graph


def test_extract_entities_from_graph_collects_structured_values(tmp_path):
    graph = CaseGraph(str(tmp_path / "graph.db"))
    graph.write_node("alert", "alert-1", {"hostname": "web-01", "user_account": "alice"}, "ingestion")
    graph.write_node("host", "web-01", {"deviceName": "web-01", "ip_address": "10.0.0.1"}, "recon")
    graph.write_node("ip", "10.0.0.1", {"open_ports": [{"port": 443}], "host": "web-01"}, "recon")
    graph.write_node("evidence", "Suspicious sign-in", {"entity_type": "user", "entity_value": "alice@example.com"}, "forensics")
    graph.write_node("finding", "hash-evidence", {"summary": "observed hash deadbeefdeadbeefdeadbeefdeadbeef"}, "threat_intel")
    graph.write_node("domain", "corp.example.com", {"fqdn": "corp.example.com"}, "recon")

    entities = extract_entities_from_graph(graph)

    assert entities["hosts"] == ["web-01"]
    assert entities["users"] == ["alice", "alice@example.com"]
    assert "10.0.0.1" in entities["ips"]
    assert "corp.example.com" in entities["domains"]
    assert "deadbeefdeadbeefdeadbeefdeadbeef" in entities["hashes"]


def test_extract_entities_from_graph_deduplicates(tmp_path):
    graph = CaseGraph(str(tmp_path / "graph.db"))
    graph.write_node("ip", "10.0.0.1", {"ip_address": "10.0.0.1"}, "recon")
    graph.write_node("evidence", "IP evidence", {"entity_type": "ip", "entity_value": "10.0.0.1"}, "recon")

    entities = extract_entities_from_graph(graph)

    assert entities["ips"] == ["10.0.0.1"]

