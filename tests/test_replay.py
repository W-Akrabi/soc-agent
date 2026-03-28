from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from core.memory_store import IncidentMemory, MemoryStore
from core.replay import replay_investigation


def _memory() -> IncidentMemory:
    return IncidentMemory(
        memory_id="m-1",
        incident_id="incident-1",
        run_id="run-1",
        alert_type="intrusion",
        alert_json=(
            '{"id":"alert-1","type":"intrusion","severity":"high",'
            '"timestamp":"2025-01-15T12:00:00+00:00","raw_payload":{"logs":[]},'
            '"source_ip":"10.0.0.1","dest_ip":"10.0.0.2","source_port":null,"dest_port":443,'
            '"hostname":"web-01","user_account":"alice","process":null,"tags":[]}'
        ),
        entities={"hosts": ["web-01"], "ips": ["10.0.0.1"]},
        actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
        outcome="contained",
    )


@pytest.mark.asyncio
async def test_replay_investigation_reconstructs_alert_and_calls_runner(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    store.write_memory(_memory())
    config = SimpleNamespace(db_path=str(tmp_path / "cases.db"), reports_dir=str(tmp_path / "reports"))

    captured = {}

    async def fake_run_investigation(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(run_id="new-run", alert_id=kwargs["alert"].id)

    with patch("core.app.run_investigation", new=AsyncMock(side_effect=fake_run_investigation)):
        result = await replay_investigation("run-1", store, config, dry_run=True)

    assert result.alert_id == "alert-1"
    assert captured["dry_run"] is True
    assert captured["alert"].hostname == "web-01"
    assert captured["alert"].source_ip == "10.0.0.1"


@pytest.mark.asyncio
async def test_replay_investigation_rejects_missing_run_id(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "memory.db"))
    config = SimpleNamespace(db_path=str(tmp_path / "cases.db"), reports_dir=str(tmp_path / "reports"))

    with pytest.raises(ValueError, match="not found in memory store"):
        await replay_investigation("missing-run", store, config)

