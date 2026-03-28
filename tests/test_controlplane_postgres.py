import os
import uuid
from datetime import datetime, timezone

import pytest

from core.approval_queue import ApprovalQueue
from core.memory_store import IncidentMemory, MemoryStore
from core.worker_queue import WorkerQueue


pytest.importorskip("psycopg")


def _skip_if_unavailable() -> str:
    dsn = os.getenv("SOC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SOC_TEST_POSTGRES_DSN not set")
    return dsn


def _schema(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def test_postgres_memory_store_roundtrip():
    dsn = _skip_if_unavailable()
    store = MemoryStore(
        backend="postgres",
        postgres_dsn=dsn,
        postgres_schema=_schema("memory"),
    )
    memory = IncidentMemory(
        memory_id=str(uuid.uuid4()),
        incident_id="incident-1",
        run_id="run-1",
        alert_type="intrusion",
        alert_json='{"id":"a1"}',
        entities={"hosts": ["web-01"]},
        actions_taken=[{"action_type": "isolate_host", "target": "web-01"}],
        started_at=datetime.now(timezone.utc).isoformat(),
        outcome="contained",
    )

    store.write_memory(memory)
    fetched = store.get_memory_by_run_id("run-1")

    assert fetched is not None
    assert fetched.entities["hosts"] == ["web-01"]
    assert fetched.actions_taken[0]["action_type"] == "isolate_host"


def test_postgres_approval_queue_is_idempotent():
    dsn = _skip_if_unavailable()
    queue = ApprovalQueue(
        backend="postgres",
        postgres_dsn=dsn,
        postgres_schema=_schema("approval"),
    )
    action = {
        "action_id": "action-1",
        "run_id": "run-1",
        "alert_id": "alert-1",
        "action_type": "isolate_host",
        "target": "web-01",
        "reason": "containment required",
        "urgency": "immediate",
        "blast_radius": "Will isolate host 'web-01' from the network.",
        "status": "awaiting_approval",
    }

    first = queue.enqueue(action)
    second = queue.enqueue({**action, "action_id": "action-2"})

    assert first["action_id"] == "action-1"
    assert second["action_id"] == "action-1"
    assert len(queue.list_pending()) == 1


def test_postgres_worker_queue_claim_and_complete():
    dsn = _skip_if_unavailable()
    queue = WorkerQueue(
        backend="postgres",
        postgres_dsn=dsn,
        postgres_schema=_schema("worker"),
    )
    queue.enqueue(
        {
            "task_id": "task-1",
            "run_id": "run-1",
            "plan_task_id": "intrusion:recon",
            "task_node_id": "node-task-1",
            "agent_name": "recon",
            "alert_json": '{"id":"alert-1"}',
            "db_path": "postgresql://case-db",
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    claimed = queue.claim_next(worker_id="worker-1")
    completed = queue.complete_task("task-1", result={"ok": True})

    assert claimed is not None
    assert claimed["status"] == "claimed"
    assert completed["status"] == "completed"
    assert completed["result_json"] == {"ok": True}
