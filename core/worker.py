from __future__ import annotations

import asyncio
import inspect
import uuid
from typing import Any, Callable

from rich.console import Console

from core.metrics import (
    record_worker_claim,
    record_worker_completion,
    record_worker_failure,
    record_worker_heartbeat,
)
from core.storage import build_storage
from core.worker_queue import WorkerQueue


def _task_value(task: Any, key: str, default: Any = None) -> Any:
    if isinstance(task, dict):
        return task.get(key, default)
    return getattr(task, key, default)


def _load_alert_reconstructor() -> Callable[[str], Any]:
    try:
        from core.models import reconstruct_alert_from_json
    except Exception as exc:  # pragma: no cover - exercised when shared helper is absent
        def _missing(_: str) -> Any:
            raise RuntimeError(
                "core.models.reconstruct_alert_from_json is not available yet"
            ) from exc

        return _missing
    return reconstruct_alert_from_json


class SOCWorker:
    """Polls the remote worker queue and runs claimed tasks."""

    def __init__(
        self,
        queue: WorkerQueue,
        *,
        worker_id: str | None = None,
        agent_factory: Callable[[Any, Any, Any], Any] | None = None,
        storage_factory: Callable[[str], Any] | None = None,
        alert_loader: Callable[[str], Any] | None = None,
        console: Console | None = None,
        poll_interval: float = 1.0,
        lease_seconds: float | None = None,
        heartbeat_interval: float | None = None,
        worker_metadata: dict[str, Any] | None = None,
    ):
        self.queue = queue
        self.worker_id = worker_id or f"worker-{uuid.uuid4().hex[:8]}"
        self.agent_factory = agent_factory
        self.storage_factory = storage_factory or (lambda db_path: build_storage(backend="sqlite", db_path=db_path))
        self.alert_loader = alert_loader or _load_alert_reconstructor()
        self.console = console or Console()
        self.poll_interval = poll_interval
        self.lease_seconds = getattr(queue, "default_lease_seconds", 30.0) if lease_seconds is None else lease_seconds
        self.heartbeat_interval = max(0.1, min(poll_interval, 5.0)) if heartbeat_interval is None else heartbeat_interval
        self.worker_metadata = worker_metadata or {}
        self.queue.register_worker(self.worker_id, status="idle", metadata=self.worker_metadata)
        record_worker_heartbeat(worker_id=self.worker_id, status="idle")

    def log(self, message: str, style: str = "cyan") -> None:
        self.console.print(f"[bold cyan][WORKER][/bold cyan] {message}", style=style)

    async def run_once(self) -> bool:
        self.queue.heartbeat_worker(self.worker_id, status="idle", current_task_id=None, metadata=self.worker_metadata)
        record_worker_heartbeat(worker_id=self.worker_id, status="idle")
        task = self.queue.claim_next(worker_id=self.worker_id, lease_seconds=self.lease_seconds)
        if task is None:
            self.queue.heartbeat_worker(self.worker_id, status="idle", current_task_id=None, metadata=self.worker_metadata)
            record_worker_heartbeat(worker_id=self.worker_id, status="idle")
            return False

        task_id = _task_value(task, "task_id")
        self.queue.heartbeat_worker(
            self.worker_id,
            status="busy",
            current_task_id=task_id,
            metadata=self.worker_metadata,
        )
        record_worker_heartbeat(worker_id=self.worker_id, status="busy", current_task_id=task_id)
        record_worker_claim(worker_id=self.worker_id, task_id=task_id)
        self.queue.update_task(task_id, status="running", worker_id=self.worker_id)
        try:
            result = await self._process_task(task)
        except Exception as exc:
            self.queue.fail_task(task_id, str(exc))
            self.queue.heartbeat_worker(
                self.worker_id,
                status="idle",
                current_task_id=None,
                metadata=self.worker_metadata,
            )
            record_worker_failure(worker_id=self.worker_id, task_id=task_id)
            record_worker_heartbeat(worker_id=self.worker_id, status="idle")
            self.log(f"task {task_id} failed: {exc}", style="red")
            return True

        self.queue.complete_task(task_id, result=result)
        self.queue.heartbeat_worker(
            self.worker_id,
            status="idle",
            current_task_id=None,
            metadata=self.worker_metadata,
        )
        record_worker_completion(worker_id=self.worker_id, task_id=task_id)
        record_worker_heartbeat(worker_id=self.worker_id, status="idle")
        self.log(f"task {task_id} completed", style="green")
        return True

    async def run_forever(self, stop_event: asyncio.Event | None = None) -> None:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            did_work = await self.run_once()
            if not did_work:
                self.queue.heartbeat_worker(
                    self.worker_id,
                    status="idle",
                    current_task_id=None,
                    metadata=self.worker_metadata,
                )
                record_worker_heartbeat(worker_id=self.worker_id, status="idle")
                await asyncio.sleep(min(self.poll_interval, self.heartbeat_interval))

    async def _process_task(self, task: Any) -> dict[str, Any]:
        alert_json = _task_value(task, "alert_json")
        db_path = _task_value(task, "db_path")
        agent_name = _task_value(task, "agent_name")
        task_node_id = _task_value(task, "task_node_id")

        if not alert_json:
            raise ValueError("worker task is missing alert_json")
        if not db_path:
            raise ValueError("worker task is missing db_path")
        if not agent_name:
            raise ValueError("worker task is missing agent_name")

        alert = self.alert_loader(alert_json)
        storage = self.storage_factory(db_path)
        agent = self._build_agent(task, alert, storage)

        outcome = agent.run(task_node_id, alert)
        if inspect.isawaitable(outcome):
            outcome = await outcome

        return {
            "task_id": _task_value(task, "task_id"),
            "run_id": _task_value(task, "run_id"),
            "agent_name": agent_name,
            "status": "completed",
            "result": outcome,
        }

    def _build_agent(self, task: Any, alert: Any, storage: Any) -> Any:
        if self.agent_factory is not None:
            return self.agent_factory(task, alert, storage)

        raise RuntimeError(
            "SOCWorker requires an agent_factory until the local Commander wiring is added"
        )


def build_default_worker_id() -> str:
    return f"worker-{uuid.uuid4().hex[:8]}"


def open_worker_queue(
    db_path: str = "./soc_workers.db",
    *,
    backend: str = "sqlite",
    postgres_dsn: str | None = None,
    postgres_schema: str = "soc_control",
) -> WorkerQueue:
    return WorkerQueue(
        db_path=db_path,
        backend=backend,
        postgres_dsn=postgres_dsn,
        postgres_schema=postgres_schema,
    )
