from datetime import datetime, timezone

from core.memory_store import AssetBaseline, IncidentMemory, MemoryStore, PriorContext


def _memory(**overrides) -> IncidentMemory:
    payload = {
        "memory_id": "m-1",
        "incident_id": "incident-1",
        "run_id": "run-1",
        "alert_type": "intrusion",
        "alert_json": '{"id":"a1","type":"intrusion","severity":"high","timestamp":"2025-01-15T12:00:00+00:00","raw_payload":{},"source_ip":"10.0.0.1","dest_ip":null,"source_port":null,"dest_port":null,"hostname":"web-01","user_account":"alice","process":null,"tags":[]}',
        "entities": {"hosts": ["web-01"], "users": ["alice"], "ips": ["10.0.0.1"], "hashes": []},
        "actions_taken": [{"action_type": "isolate_host", "target": "web-01", "status": "executed"}],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "outcome": "contained",
    }
    payload.update(overrides)
    return IncidentMemory(**payload)


def test_write_and_read_memory_roundtrip(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    stored = store.write_memory(_memory())

    fetched = store.get_memory_by_run_id("run-1")

    assert fetched is not None
    assert stored.run_id == fetched.run_id == "run-1"
    assert fetched.entities["hosts"] == ["web-01"]
    assert fetched.actions_taken[0]["action_type"] == "isolate_host"
    assert fetched.outcome == "contained"


def test_upsert_baseline_increments_incident_count(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    store.write_memory(_memory(run_id="run-1", incident_id="incident-1"))
    store.write_memory(_memory(run_id="run-2", incident_id="incident-2"))

    baselines = store.list_baselines_for_entity("host", "web-01")

    assert len(baselines) == 1
    assert baselines[0].incident_count == 2
    assert "intrusion" in baselines[0].tags


def test_prior_context_formatting_limits_blocks(tmp_path):
    memories = [
        _memory(run_id="run-1", incident_id="incident-1"),
        _memory(run_id="run-2", incident_id="incident-2", outcome="escalated"),
    ]
    context = PriorContext(prior_incidents=memories, entity_baselines=[])

    text = context.format_for_prompt(limit=1)

    assert text.startswith("[Prior Investigation Context]")
    assert text.count("run-") == 1

