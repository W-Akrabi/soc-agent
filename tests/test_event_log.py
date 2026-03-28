import json

from core.event_log import EventLog


def test_event_log_creates_file(tmp_path):
    log = EventLog(run_id="run-1", log_dir=str(tmp_path))
    log.append("agent_state", agent="recon", data={"status": "running"})

    log_file = tmp_path / "run-1.jsonl"
    assert log_file.exists()


def test_event_log_entries_are_valid_json(tmp_path):
    log = EventLog(run_id="run-2", log_dir=str(tmp_path))
    log.append("llm_call", agent="commander", data={"tokens": 100})
    log.append("tool_call", agent="recon", data={"tool": "ip_lookup"})

    entries = (tmp_path / "run-2.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(entries) == 2

    parsed = [json.loads(entry) for entry in entries]
    assert parsed[0]["event_type"] == "llm_call"
    assert parsed[1]["event_type"] == "tool_call"


def test_event_log_entry_has_timestamp_and_run_id(tmp_path):
    log = EventLog(run_id="run-3", log_dir=str(tmp_path))
    log.append("agent_state", agent="recon", data={})

    entry = json.loads((tmp_path / "run-3.jsonl").read_text(encoding="utf-8").strip())
    assert "timestamp" in entry
    assert "run_id" in entry
    assert entry["run_id"] == "run-3"


def test_event_log_is_append_only(tmp_path):
    log = EventLog(run_id="run-4", log_dir=str(tmp_path))
    for i in range(5):
        log.append("agent_state", agent="test", data={"i": i})

    entries = (tmp_path / "run-4.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(entries) == 5


def test_event_log_read_all(tmp_path):
    log = EventLog(run_id="run-5", log_dir=str(tmp_path))
    log.append("llm_call", agent="commander", data={"x": 1})
    log.append("llm_call", agent="recon", data={"x": 2})

    entries = log.read_all()
    assert len(entries) == 2
    assert entries[0]["agent"] == "commander"
    assert entries[1]["agent"] == "recon"


def test_event_log_noop_when_disabled(tmp_path):
    log = EventLog(run_id="run-6", log_dir=None)
    log.append("agent_state", agent="test", data={})

    assert list(tmp_path.iterdir()) == []
    assert log.read_all() == []
