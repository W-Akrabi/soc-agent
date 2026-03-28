import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta

import pytest

from core.worker_queue import WorkerQueue


@dataclass
class TaskShape:
    task_id: str
    run_id: str
    plan_task_id: str
    task_node_id: str
    agent_name: str
    alert_json: str
    db_path: str
    status: str = "pending"
    created_at: str = "2026-03-27T00:00:00+00:00"
    worker_id: str | None = None
    claimed_at: str | None = None
    completed_at: str | None = None
    result_json: dict | None = None
    error: str | None = None


def _task(task_id: str = "task-1", agent_name: str = "recon") -> TaskShape:
    return TaskShape(
        task_id=task_id,
        run_id="run-1",
        plan_task_id=f"intrusion:{agent_name}",
        task_node_id=f"node-{task_id}",
        agent_name=agent_name,
        alert_json='{"id":"alert-1","type":"intrusion","severity":"high","timestamp":"2026-03-27T00:00:00+00:00","raw_payload":{}}',
        db_path="./case.db",
    )


def test_enqueue_and_claim(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task())

    claimed = queue.claim_next(worker_id="worker-1")

    assert claimed is not None
    assert claimed["task_id"] == "task-1"
    assert claimed["status"] == "claimed"
    assert claimed["worker_id"] == "worker-1"
    assert claimed["claimed_at"] is not None


def test_claim_next_returns_none_when_empty(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))

    assert queue.claim_next(worker_id="worker-1") is None


def test_claimed_task_is_not_returned_twice(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task())

    first = queue.claim_next(worker_id="worker-1")
    second = queue.claim_next(worker_id="worker-2")

    assert first is not None
    assert first["task_id"] == "task-1"
    assert second is None


def test_complete_and_fail_transitions(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task("task-2"))
    queue.enqueue(_task("task-3"))

    completed = queue.complete_task("task-2", result={"status": "ok"})
    failed = queue.fail_task("task-3", error="boom")

    assert completed["status"] == "completed"
    assert completed["result_json"] == {"status": "ok"}
    assert completed["completed_at"] is not None
    assert failed["status"] == "failed"
    assert failed["error"] == "boom"
    assert failed["completed_at"] is not None


def test_register_and_heartbeat_worker(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))

    worker = queue.register_worker("worker-1", metadata={"rack": "A"})
    heartbeat = queue.heartbeat_worker("worker-1", status="busy", current_task_id="task-9")

    assert worker["worker_id"] == "worker-1"
    assert worker["status"] == "idle"
    assert worker["metadata"] == {"rack": "A"}
    assert heartbeat["status"] == "busy"
    assert heartbeat["current_task_id"] == "task-9"
    assert heartbeat["last_heartbeat_at"] >= worker["last_heartbeat_at"]


def test_claim_sets_lease_and_stale_tasks_requeue(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task("task-10"))

    claimed = queue.claim_next(worker_id="worker-1", lease_seconds=0.0)
    assert claimed is not None
    assert claimed["status"] == "claimed"
    assert claimed["lease_expires_at"] is not None

    requeued = queue.sweep_stale_tasks()

    assert len(requeued) == 1
    assert requeued[0]["status"] == "pending"
    assert requeued[0]["worker_id"] is None
    assert queue.list_tasks(status="pending")[0]["task_id"] == "task-10"


def test_sweep_stale_workers_requeues_tasks(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task("task-11"))
    claimed = queue.claim_next(worker_id="worker-stale", lease_seconds=3600.0)
    assert claimed is not None

    old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    queue.heartbeat_worker(
        "worker-stale",
        status="busy",
        current_task_id="task-11",
        last_heartbeat_at=old,
    )

    stale_workers = queue.sweep_stale_workers(timeout_seconds=1.0)

    assert stale_workers[0]["worker_id"] == "worker-stale"
    assert stale_workers[0]["status"] == "stale"
    assert queue.get_task("task-11")["status"] == "pending"

def _postgres_dsn() -> str:
    dsn = os.getenv("SOC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SOC_TEST_POSTGRES_DSN not set")
    return dsn


def test_postgres_worker_queue_parity():
    pytest.importorskip("psycopg")
    queue = WorkerQueue(
        backend="postgres",
        postgres_dsn=_postgres_dsn(),
        postgres_schema=f"worker_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
    )
    queue.enqueue(_task("task-pg"))
    claimed = queue.claim_next(worker_id="worker-pg", lease_seconds=0.0)
    assert claimed is not None
    assert claimed["status"] == "claimed"
    queue.update_task("task-pg", lease_expires_at="2000-01-01T00:00:00+00:00")
    requeued = queue.sweep_stale_tasks()
    assert requeued and requeued[0]["status"] == "pending"
