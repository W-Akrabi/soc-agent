import json
from datetime import datetime, timezone
from types import SimpleNamespace

from core.correlation import CorrelationService
from core.memory_store import IncidentMemory, MemoryStore


def _memory(run_id: str, host: str, ip: str, user: str) -> IncidentMemory:
    alert_json = json.dumps(
        {
            "id": "a1",
            "type": "intrusion",
            "severity": "high",
            "timestamp": "2025-01-15T12:00:00+00:00",
            "raw_payload": {},
            "source_ip": ip,
            "dest_ip": None,
            "source_port": None,
            "dest_port": None,
            "hostname": host,
            "user_account": user,
            "process": None,
            "tags": [],
        }
    )
    return IncidentMemory(
        memory_id=f"m-{run_id}",
        incident_id=f"incident-{run_id}",
        run_id=run_id,
        alert_type="intrusion",
        alert_json=alert_json,
        entities={"hosts": [host], "users": [user], "ips": [ip], "hashes": []},
        actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
        outcome="contained",
    )


def test_get_prior_context_returns_matching_incidents_and_baselines(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    store.write_memory(_memory("run-1", "web-01", "10.0.0.1", "alice"))
    store.write_memory(_memory("run-2", "web-02", "10.0.0.2", "bob"))

    service = CorrelationService(store, limit=2)
    alert = SimpleNamespace(
        hostname="web-01",
        source_ip="10.0.0.1",
        dest_ip=None,
        user_account="alice",
        raw_payload={},
    )

    context = service.get_prior_context(alert)

    assert context.has_context is True
    assert len(context.prior_incidents) == 1
    assert context.prior_incidents[0].run_id == "run-1"
    assert len(context.entity_baselines) >= 1
    prompt = context.format_for_prompt(limit=1)
    assert "Prior Investigation Context" in prompt
    assert "web-01" in prompt


def test_get_prior_context_for_entities_handles_empty_input(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    service = CorrelationService(store)

    context = service.get_prior_context_for_entities({"hosts": [], "users": [], "ips": [], "domains": [], "hashes": []})

    assert context.has_context is False
    assert context.prior_incidents == []
    assert context.entity_baselines == []
