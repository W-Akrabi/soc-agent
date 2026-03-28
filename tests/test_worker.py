from dataclasses import asdict, dataclass
from types import SimpleNamespace

import pytest
from unittest.mock import MagicMock

from core.worker import SOCWorker
from core import metrics
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


def _task(task_id: str = "task-1") -> TaskShape:
    return TaskShape(
        task_id=task_id,
        run_id="run-1",
        plan_task_id="intrusion:recon",
        task_node_id="node-1",
        agent_name="recon",
        alert_json='{"id":"alert-1","type":"intrusion","severity":"high","timestamp":"2026-03-27T00:00:00+00:00","raw_payload":{}}',
        db_path="./case.db",
    )


@pytest.mark.asyncio
async def test_run_once_completes_claimed_task(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task())

    storage_calls: list[str] = []
    agent_calls: list[tuple[str, str, str]] = []

    async def run(task_node_id, alert):
        agent_calls.append((task_node_id, alert.id, alert.type.value))
        return {"seen": task_node_id, "alert_id": alert.id}

    def agent_factory(task, alert, storage):
        assert task["agent_name"] == "recon"
        assert alert.id == "alert-1"
        storage_calls.append(storage["db_path"])
        return SimpleNamespace(run=run)

    worker = SOCWorker(
        queue,
        worker_id="worker-1",
        agent_factory=agent_factory,
        storage_factory=lambda db_path: {"db_path": db_path},
        alert_loader=lambda alert_json: SimpleNamespace(id="alert-1", type=SimpleNamespace(value="intrusion")),
        poll_interval=0.01,
    )

    did_work = await worker.run_once()
    record = queue.get_task("task-1")

    assert did_work is True
    assert storage_calls == ["./case.db"]
    assert agent_calls == [("node-1", "alert-1", "intrusion")]
    assert record is not None
    assert record["status"] == "completed"
    assert record["result_json"] == {"task_id": "task-1", "run_id": "run-1", "agent_name": "recon", "status": "completed", "result": {"seen": "node-1", "alert_id": "alert-1"}}


@pytest.mark.asyncio
async def test_run_once_emits_worker_heartbeats():
    metrics.reset_registry()
    queue = MagicMock()
    queue.default_lease_seconds = 30.0
    queue.register_worker = MagicMock(return_value={"worker_id": "worker-1"})
    queue.heartbeat_worker = MagicMock(return_value={"worker_id": "worker-1"})
    queue.update_task = MagicMock()
    queue.complete_task = MagicMock(return_value={"status": "completed"})
    queue.claim_next = MagicMock(return_value=asdict(_task()))

    worker = SOCWorker(
        queue,
        worker_id="worker-1",
        agent_factory=lambda task, alert, storage: SimpleNamespace(run=lambda *_: {"ok": True}),
        storage_factory=lambda db_path: {"db_path": db_path},
        alert_loader=lambda alert_json: SimpleNamespace(id="alert-1", type=SimpleNamespace(value="intrusion")),
        poll_interval=0.01,
    )

    await worker.run_once()

    assert queue.register_worker.call_count == 1
    assert queue.claim_next.call_args.kwargs["lease_seconds"] == 30.0
    heartbeat_statuses = [call.kwargs["status"] for call in queue.heartbeat_worker.call_args_list]
    assert heartbeat_statuses[0] == "idle"
    assert "busy" in heartbeat_statuses
    assert heartbeat_statuses[-1] == "idle"
    assert metrics.get_counter_value(
        "soc_worker_heartbeats_total",
        {"worker_id": "worker-1", "status": "idle"},
    ) == 3
    assert metrics.get_counter_value(
        "soc_worker_heartbeats_total",
        {"worker_id": "worker-1", "status": "busy"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_worker_claims_total",
        {"worker_id": "worker-1", "task_id": "task-1"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_worker_completions_total",
        {"worker_id": "worker-1", "task_id": "task-1"},
    ) == 1


@pytest.mark.asyncio
async def test_run_once_marks_task_failed_on_exception(tmp_path):
    metrics.reset_registry()
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_task())

    def agent_factory(task, alert, storage):
        class FailingAgent:
            async def run(self, task_node_id, alert):
                raise RuntimeError("boom")

        return FailingAgent()

    worker = SOCWorker(
        queue,
        worker_id="worker-1",
        agent_factory=agent_factory,
        storage_factory=lambda db_path: {"db_path": db_path},
        alert_loader=lambda alert_json: SimpleNamespace(id="alert-1", type=SimpleNamespace(value="intrusion")),
        poll_interval=0.01,
    )

    did_work = await worker.run_once()
    record = queue.get_task("task-1")

    assert did_work is True
    assert record is not None
    assert record["status"] == "failed"
    assert "boom" in record["error"]
    assert metrics.get_counter_value(
        "soc_worker_failures_total",
        {"worker_id": "worker-1", "task_id": "task-1"},
    ) == 1


@pytest.mark.asyncio
async def test_run_once_returns_false_when_queue_empty(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    worker = SOCWorker(
        queue,
        worker_id="worker-1",
        agent_factory=lambda task, alert, storage: SimpleNamespace(run=lambda *_: None),
        storage_factory=lambda db_path: {"db_path": db_path},
        alert_loader=lambda alert_json: SimpleNamespace(id="alert-1", type=SimpleNamespace(value="intrusion")),
        poll_interval=0.01,
    )

    assert await worker.run_once() is False
