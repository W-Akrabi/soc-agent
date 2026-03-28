# Gate 6: Hybrid Execution — Remote Workers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a DB-backed worker task queue so individual agent tasks can be dispatched to out-of-process `SOCWorker` processes, enabling horizontal scaling, process isolation, and multi-machine distribution of investigation workloads.

**Architecture:** When `config.worker_mode = "remote"`, `Commander._build_task_runner()` switches from calling agents directly to enqueueing `WorkerTask` rows into a shared `WorkerQueue` SQLite file and polling until each task completes. A separate `SOCWorker` process claims tasks from the queue, reconstructs the alert, opens the case-graph DB, instantiates the correct agent, runs it, and marks the task complete. The local mode path (`worker_mode = "local"`) is unchanged. A `soc worker start` CLI command starts the worker loop.

**Tech Stack:** Python 3.11+, stdlib `sqlite3` and `asyncio`, existing `core.storage.build_storage`, existing `core.providers.build_provider`, existing `agents.*`. No new packages.

---

## Scope note

Gate 6 depends on Gates 1–3 (agents, schemas, integrations). Gate 5's `compose_integration_registry` rename (Task 5 Step 4) is referenced here — if Gate 5 has not been implemented, the equivalent private function `_compose_integration_registry` from `core/app.py` can be used as a fallback.

Remote workers in Gate 6 share the same machine (separate processes, shared filesystem). True multi-machine distribution requires a PostgreSQL-backed `WorkerQueue` — that is out of scope for Gate 6 but follows naturally by swapping the SQLite backend for the existing `StorageBackend` abstraction.

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/models.py` | **Modify** | Add `reconstruct_alert_from_json(alert_json)` function |
| `core/schemas.py` | **Modify** | Add `WorkerTask` dataclass |
| `core/worker_queue.py` | **Create** | SQLite-backed worker task queue — enqueue / claim / complete / fail |
| `core/worker.py` | **Create** | `SOCWorker` — polls queue, runs agents, marks complete |
| `core/config.py` | **Modify** | Add `worker_mode`, `worker_db_path`, `worker_poll_interval` fields |
| `core/app.py` | **Modify** | Create `WorkerQueue` and pass `run_id` + `db_path` to Commander when `worker_mode=remote` |
| `agents/commander.py` | **Modify** | Accept `worker_queue`, `worker_run_id`, `worker_db_path`; switch to remote runners when queue is set |
| `main.py` | **Modify** | Add `worker start` subcommand |
| `tests/test_schemas.py` | **Modify** | Add `WorkerTask` field tests |
| `tests/test_worker_queue.py` | **Create** | Unit tests for queue operations |
| `tests/test_worker.py` | **Create** | Unit tests for SOCWorker claim/run/complete loop |

---

## Task 1: Add WorkerTask schema and alert reconstruction helper

**Files:**
- Modify: `core/schemas.py`
- Modify: `core/models.py`
- Modify: `tests/test_schemas.py`

The `WorkerTask` carries all context the `SOCWorker` needs to run a task without the Commander's local state. `reconstruct_alert_from_json` is a shared helper used by both `SOCWorker` and `core/replay.py` (Gate 4).

- [ ] **Step 1: Write failing tests**

Add to `tests/test_schemas.py`:

```python
from core.schemas import WorkerTask
from dataclasses import fields

def test_worker_task_required_fields():
    required = {f.name for f in fields(WorkerTask)}
    assert "task_id" in required
    assert "run_id" in required
    assert "plan_task_id" in required
    assert "task_node_id" in required
    assert "agent_name" in required
    assert "alert_json" in required
    assert "db_path" in required
    assert "status" in required
    assert "created_at" in required

def test_worker_task_defaults():
    from datetime import datetime, timezone
    wt = WorkerTask(
        task_id="t1", run_id="r1", plan_task_id="intrusion:recon",
        task_node_id="node-1", agent_name="recon",
        alert_json='{"id":"a1"}', db_path="./case.db",
        status="pending", created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert wt.worker_id is None
    assert wt.claimed_at is None
    assert wt.completed_at is None
    assert wt.result_json is None
    assert wt.error is None
```

Add to `tests/test_models.py`:

```python
def test_reconstruct_alert_from_json_roundtrip():
    from datetime import datetime, timezone
    from core.models import Alert, AlertType, Severity, reconstruct_alert_from_json
    import json

    original = Alert(
        id="a1", type=AlertType.INTRUSION, severity=Severity.HIGH,
        timestamp=datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc),
        raw_payload={"key": "value"},
        source_ip="10.0.0.1", hostname="web-01",
        dest_port=443,
    )
    alert_json = json.dumps({
        "id": original.id, "type": original.type.value,
        "severity": original.severity.value,
        "timestamp": original.timestamp.isoformat(),
        "source_ip": original.source_ip, "dest_ip": None,
        "source_port": None, "dest_port": original.dest_port,
        "hostname": original.hostname, "user_account": None,
        "process": None, "tags": [], "raw_payload": original.raw_payload,
    })
    reconstructed = reconstruct_alert_from_json(alert_json)
    assert reconstructed.id == "a1"
    assert reconstructed.type == AlertType.INTRUSION
    assert reconstructed.severity == Severity.HIGH
    assert reconstructed.source_ip == "10.0.0.1"
    assert reconstructed.hostname == "web-01"
    assert reconstructed.dest_port == 443
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /Users/waleedakrabi/Desktop/Github-forks/soc-agent
pytest tests/test_schemas.py::test_worker_task_required_fields tests/test_schemas.py::test_worker_task_defaults tests/test_models.py::test_reconstruct_alert_from_json_roundtrip -v
```

Expected: `ImportError: cannot import name 'WorkerTask'` and `ImportError: cannot import name 'reconstruct_alert_from_json'`

- [ ] **Step 3: Add `WorkerTask` to `core/schemas.py`**

Append after `validate_action_proposals` (or after `PendingAction` if Gate 5 is implemented):

```python
@dataclass
class WorkerTask:
    task_id: str           # unique ID for this queue entry
    run_id: str            # InvestigationRun.run_id
    plan_task_id: str      # PlannedTask.task_id (e.g. "intrusion:recon")
    task_node_id: str      # graph node ID written by Commander before enqueueing
    agent_name: str        # which agent to run
    alert_json: str        # JSON-serialized Alert for reconstruction in worker
    db_path: str           # path to the per-run case graph database
    status: str            # pending | claimed | running | completed | failed
    created_at: str        # ISO timestamp
    worker_id: str | None = None
    claimed_at: str | None = None
    completed_at: str | None = None
    result_json: str | None = None  # dict from agent run
    error: str | None = None
```

- [ ] **Step 4: Add `reconstruct_alert_from_json` to `core/models.py`**

Append at the bottom of `core/models.py`:

```python
def reconstruct_alert_from_json(alert_json: str) -> "Alert":
    """Deserialize a stored alert JSON string back to an Alert dataclass.

    Used by SOCWorker and replay_investigation to reconstruct alerts from
    persisted storage without access to the original in-memory object.
    """
    import json
    from datetime import datetime

    data = json.loads(alert_json)
    return Alert(
        id=data["id"],
        type=AlertType(data["type"]),
        severity=Severity(data["severity"]),
        timestamp=datetime.fromisoformat(data["timestamp"]),
        raw_payload=data.get("raw_payload", {}),
        source_ip=data.get("source_ip"),
        dest_ip=data.get("dest_ip"),
        source_port=data.get("source_port"),
        dest_port=data.get("dest_port"),
        hostname=data.get("hostname"),
        user_account=data.get("user_account"),
        process=data.get("process"),
        tags=data.get("tags", []),
    )
```

> **Note:** If Gate 4 has been implemented, `core/replay.py` has a local `_reconstruct_alert()`. Update that function to call `reconstruct_alert_from_json` from `core/models` to eliminate the duplication.

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_schemas.py -v
pytest tests/test_models.py::test_reconstruct_alert_from_json_roundtrip -v
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add core/schemas.py core/models.py tests/test_schemas.py tests/test_models.py
git commit -m "feat(gate6): add WorkerTask schema and reconstruct_alert_from_json helper"
```

---

## Task 2: Create WorkerQueue

**Files:**
- Create: `core/worker_queue.py`
- Create: `tests/test_worker_queue.py`

The `WorkerQueue` is a shared SQLite file (default `soc_workers.db`). The `claim_next()` method uses a SQLite `UPDATE ... WHERE status='pending' ... RETURNING` pattern to atomically claim one task (preventing two workers from claiming the same task).

- [ ] **Step 1: Write failing tests**

Create `tests/test_worker_queue.py`:

```python
import pytest
from datetime import datetime, timezone
from core.worker_queue import WorkerQueue
from core.schemas import WorkerTask


def _wt(task_id="t1", run_id="r1", agent_name="recon") -> WorkerTask:
    return WorkerTask(
        task_id=task_id, run_id=run_id,
        plan_task_id=f"intrusion:{agent_name}",
        task_node_id=f"node-{task_id}",
        agent_name=agent_name,
        alert_json=(
            '{"id":"a1","type":"intrusion","severity":"high",'
            '"timestamp":"2025-01-15T12:00:00+00:00","raw_payload":{},'
            '"source_ip":null,"dest_ip":null,"source_port":null,"dest_port":null,'
            '"hostname":null,"user_account":null,"process":null,"tags":[]}'
        ),
        db_path="./case.db",
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def test_enqueue_and_claim(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1"))
    task = queue.claim_next(worker_id="worker-1")
    assert task is not None
    assert task.task_id == "t1"
    assert task.status == "claimed"
    assert task.worker_id == "worker-1"


def test_claim_next_returns_none_when_empty(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    assert queue.claim_next(worker_id="worker-1") is None


def test_claim_next_does_not_return_same_task_twice(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1"))
    first = queue.claim_next(worker_id="worker-1")
    second = queue.claim_next(worker_id="worker-2")
    assert first is not None
    assert second is None  # already claimed


def test_complete_updates_status(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1"))
    queue.claim_next(worker_id="worker-1")
    queue.complete("t1", result={"status": "completed", "confidence": 1.0})
    task = queue.get("t1")
    assert task.status == "completed"
    assert task.completed_at is not None


def test_fail_updates_status(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1"))
    queue.claim_next(worker_id="worker-1")
    queue.fail("t1", error="Agent timed out")
    task = queue.get("t1")
    assert task.status == "failed"
    assert task.error == "Agent timed out"


def test_get_returns_none_for_missing(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    assert queue.get("nonexistent") is None


def test_list_pending(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1", agent_name="recon"))
    queue.enqueue(_wt("t2", agent_name="threat_intel"))
    queue.claim_next(worker_id="worker-1")  # claims t1
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].task_id == "t2"


def test_list_by_run_id(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_wt("t1", run_id="run-A"))
    queue.enqueue(_wt("t2", run_id="run-B"))
    tasks = queue.list_by_run_id("run-A")
    assert len(tasks) == 1
    assert tasks[0].task_id == "t1"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_worker_queue.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.worker_queue'`

- [ ] **Step 3: Create `core/worker_queue.py`**

```python
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import WorkerTask


class WorkerQueue:
    """Shared SQLite queue for dispatching agent tasks to SOCWorker processes.

    `claim_next()` is atomic: only one worker claims a given task even when
    multiple workers poll concurrently, because SQLite serialises writes.
    """

    def __init__(self, db_path: str = "./soc_workers.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")  # wait up to 5s on lock
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS worker_tasks (
                    task_id         TEXT PRIMARY KEY,
                    run_id          TEXT NOT NULL,
                    plan_task_id    TEXT NOT NULL,
                    task_node_id    TEXT NOT NULL,
                    agent_name      TEXT NOT NULL,
                    alert_json      TEXT NOT NULL,
                    db_path         TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    created_at      TEXT NOT NULL,
                    worker_id       TEXT,
                    claimed_at      TEXT,
                    completed_at    TEXT,
                    result_json     TEXT,
                    error           TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_wt_status ON worker_tasks(status);
                CREATE INDEX IF NOT EXISTS idx_wt_run ON worker_tasks(run_id);
            """)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def enqueue(self, task: WorkerTask) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO worker_tasks
                   (task_id, run_id, plan_task_id, task_node_id, agent_name,
                    alert_json, db_path, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    task.task_id, task.run_id, task.plan_task_id,
                    task.task_node_id, task.agent_name,
                    task.alert_json, task.db_path, "pending", task.created_at,
                ),
            )

    def claim_next(self, worker_id: str) -> WorkerTask | None:
        """Atomically claim the oldest pending task. Returns None if queue is empty.

        Concurrency strategy:
        - `BEGIN IMMEDIATE` acquires a write lock before the SELECT, so no other
          connection can begin a competing write between our SELECT and UPDATE.
        - SQLite serialises all writes — even without IMMEDIATE, the UPDATE's
          `WHERE status='pending'` guard means only one worker wins. The IMMEDIATE
          transaction just prevents the wasted round-trip of losing the race.
        - The final re-fetch with `WHERE worker_id=?` returns None if another
          connection somehow won despite the guard, providing a safe fallback.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT task_id FROM worker_tasks WHERE status='pending' "
                "ORDER BY created_at ASC LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            task_id = row["task_id"]
            now = self._now()
            conn.execute(
                "UPDATE worker_tasks SET status='claimed', worker_id=?, claimed_at=? "
                "WHERE task_id=? AND status='pending'",
                (worker_id, now, task_id),
            )
            conn.execute("COMMIT")
            row = conn.execute(
                "SELECT * FROM worker_tasks WHERE task_id=? AND worker_id=?",
                (task_id, worker_id),
            ).fetchone()
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return self._row_to_task(row) if row else None

    def get(self, task_id: str) -> WorkerTask | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM worker_tasks WHERE task_id=?", (task_id,)
            ).fetchone()
        return self._row_to_task(row) if row else None

    def list_pending(self) -> list[WorkerTask]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM worker_tasks WHERE status='pending' ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def list_by_run_id(self, run_id: str) -> list[WorkerTask]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM worker_tasks WHERE run_id=? ORDER BY created_at ASC",
                (run_id,),
            ).fetchall()
        return [self._row_to_task(r) for r in rows]

    def complete(self, task_id: str, *, result: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE worker_tasks SET status='completed', completed_at=?, result_json=? "
                "WHERE task_id=?",
                (self._now(), json.dumps(result), task_id),
            )

    def fail(self, task_id: str, *, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE worker_tasks SET status='failed', completed_at=?, error=? "
                "WHERE task_id=?",
                (self._now(), error, task_id),
            )

    @staticmethod
    def _row_to_task(row) -> WorkerTask:
        d = dict(row)
        return WorkerTask(
            task_id=d["task_id"],
            run_id=d["run_id"],
            plan_task_id=d["plan_task_id"],
            task_node_id=d["task_node_id"],
            agent_name=d["agent_name"],
            alert_json=d["alert_json"],
            db_path=d["db_path"],
            status=d["status"],
            created_at=d["created_at"],
            worker_id=d.get("worker_id"),
            claimed_at=d.get("claimed_at"),
            completed_at=d.get("completed_at"),
            result_json=d.get("result_json"),
            error=d.get("error"),
        )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_worker_queue.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/worker_queue.py tests/test_worker_queue.py
git commit -m "feat(gate6): add WorkerQueue with atomic claim and status transitions"
```

---

## Task 3: Create SOCWorker

**Files:**
- Create: `core/worker.py`
- Create: `tests/test_worker.py`

`SOCWorker` is a long-running process component. It polls `WorkerQueue`, claims tasks, builds agent dependencies from `Config`, runs the agent, and marks the task complete or failed. `run_loop()` accepts a `max_iterations` param for testing (omit or set to `None` for production).

- [ ] **Step 1: Write failing tests**

Create `tests/test_worker.py`:

```python
import pytest
import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from core.worker_queue import WorkerQueue
from core.worker import SOCWorker
from core.schemas import WorkerTask


def _make_alert_json() -> str:
    return json.dumps({
        "id": "a1", "type": "brute_force", "severity": "medium",
        "timestamp": "2025-01-15T12:00:00+00:00",
        "source_ip": "10.0.0.1", "dest_ip": None,
        "source_port": None, "dest_port": None,
        "hostname": "bastion-01", "user_account": None,
        "process": None, "tags": [], "raw_payload": {},
    })


def _make_task(tmp_path, agent_name="recon") -> WorkerTask:
    return WorkerTask(
        task_id="t1", run_id="r1",
        plan_task_id=f"brute_force:{agent_name}",
        task_node_id="node-1",
        agent_name=agent_name,
        alert_json=_make_alert_json(),
        db_path=str(tmp_path / "case.db"),
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
    )


@pytest.mark.asyncio
async def test_worker_claims_and_completes_task(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_make_task(tmp_path))

    # Build a minimal Config
    from core.config import Config
    config = Config(
        anthropic_api_key="", model="mock",
        db_path=str(tmp_path / "case.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30, agent_timeout=10,
        auto_remediate=False, log_level="WARNING",
    )

    # Mock the agent so it doesn't actually call the LLM
    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=None)


    worker = SOCWorker(
        worker_id="test-worker",
        worker_queue=queue,
        config=config,
        poll_interval=0.01,
    )
    # Inject agent factory override for testing
    worker._agent_factory = lambda agent_name, **kwargs: mock_agent

    await worker.run_loop(max_iterations=2)

    task = queue.get("t1")
    assert task.status == "completed"
    assert task.worker_id == "test-worker"
    mock_agent.run.assert_called_once()
    call_args = mock_agent.run.call_args[0]
    assert call_args[0] == "node-1"      # task_node_id
    assert call_args[1].id == "a1"       # reconstructed Alert.id


@pytest.mark.asyncio
async def test_worker_marks_task_failed_on_agent_exception(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))
    queue.enqueue(_make_task(tmp_path))

    from core.config import Config
    config = Config(
        anthropic_api_key="", model="mock",
        db_path=str(tmp_path / "case.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30, agent_timeout=10,
        auto_remediate=False, log_level="WARNING",
    )

    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(side_effect=RuntimeError("LLM call failed"))


    worker = SOCWorker(
        worker_id="test-worker",
        worker_queue=queue,
        config=config,
        poll_interval=0.01,
    )
    worker._agent_factory = lambda agent_name, **kwargs: mock_agent

    await worker.run_loop(max_iterations=2)

    task = queue.get("t1")
    assert task.status == "failed"
    assert "LLM call failed" in task.error


@pytest.mark.asyncio
async def test_worker_does_nothing_when_queue_empty(tmp_path):
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))

    from core.config import Config
    config = Config(
        anthropic_api_key="", model="mock",
        db_path=str(tmp_path / "case.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30, agent_timeout=10,
        auto_remediate=False, log_level="WARNING",
    )
    worker = SOCWorker(
        worker_id="test-worker",
        worker_queue=queue,
        config=config,
        poll_interval=0.01,
    )
    # Should complete immediately (no tasks, max_iterations reached)
    await worker.run_loop(max_iterations=3)
    # No exception = pass
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_worker.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.worker'`

- [ ] **Step 3: Create `core/worker.py`**

```python
"""SOCWorker: polls WorkerQueue, runs agent tasks, marks complete/failed."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

from rich.console import Console

from core.models import reconstruct_alert_from_json
from core.worker_queue import WorkerQueue
from core.schemas import WorkerTask


class SOCWorker:
    """Out-of-process agent task executor.

    Polls WorkerQueue, claims tasks, runs the appropriate agent using
    dependencies built from Config, and writes results back to the queue.
    """

    def __init__(
        self,
        worker_id: str,
        worker_queue: WorkerQueue,
        config: Any,  # core.config.Config — lazy import to avoid circular deps
        poll_interval: float = 2.0,
        console: Console | None = None,
    ):
        self.worker_id = worker_id
        self._queue = worker_queue
        self._config = config
        self.poll_interval = poll_interval
        self._console = console or Console()
        # Override in tests to inject mock agents without real LLM/storage setup
        self._agent_factory: Callable[..., Any] | None = None

    def log(self, message: str) -> None:
        self._console.print(f"[bold cyan][WORKER {self.worker_id}][/bold cyan] {message}")

    async def run_loop(self, max_iterations: int | None = None) -> None:
        """Poll and process tasks until stopped or max_iterations reached.

        Pass `max_iterations` in tests to prevent infinite loops.
        In production, omit it and cancel the coroutine with Ctrl+C.
        """
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            iteration += 1
            task = self._queue.claim_next(self.worker_id)
            if task is not None:
                self.log(f"Claimed task {task.task_id} ({task.agent_name})")
                await self._execute_task(task)
            else:
                await asyncio.sleep(self.poll_interval)

    async def _execute_task(self, task: WorkerTask) -> None:
        try:
            alert = reconstruct_alert_from_json(task.alert_json)
            agent = self._build_agent(task.agent_name, db_path=task.db_path, alert=alert)
            await agent.run(task.task_node_id, alert)
            self._queue.complete(task.task_id, result={"status": "completed", "agent": task.agent_name})
            self.log(f"Completed task {task.task_id}")
        except Exception as exc:
            self._queue.fail(task.task_id, error=str(exc))
            self.log(f"Failed task {task.task_id}: {exc}")

    def _build_agent(self, agent_name: str, db_path: str, alert: Any = None) -> Any:
        """Build the requested agent with fresh dependencies from Config.

        In tests, override `self._agent_factory` to inject mocks.

        `alert` is passed so that MockLLMClient can receive `set_alert_context()`
        when running in dry-run / test mode — without it, MockLLMClient defaults
        to intrusion-type responses regardless of actual alert type.

        Known limitation (Gate 6 scope): agents are built without an
        IntegrationRegistry, so live integrations (threat_intel adapter,
        Entra, Defender) will not be used by remote workers. Full integration
        support is a follow-up for a later gate.
        """
        if self._agent_factory is not None:
            return self._agent_factory(
                agent_name=agent_name, db_path=db_path, config=self._config
            )

        # Lazy imports to avoid circular dependencies at module load time
        from core.storage import build_storage
        from core.providers import build_provider
        from agents.recon import ReconAgent
        from agents.threat_intel import ThreatIntelAgent
        from agents.forensics import ForensicsAgent
        from agents.remediation import RemediationAgent
        from agents.reporter import ReporterAgent

        storage = build_storage(
            backend=self._config.storage_backend,
            db_path=db_path,
        )
        # build_provider does not support provider="mock"; use MockLLMClient directly
        # when running in dry-run / test mode so workers don't need an API key.
        if getattr(self._config, "provider", None) == "mock":
            from core.mock_llm import MockLLMClient
            llm = MockLLMClient()
            if alert is not None:
                llm.set_alert_context(alert)
        else:
            llm = build_provider(self._config)

        kwargs = dict(
            case_graph=storage,
            llm=llm,
            console=self._console,
            agent_timeout=self._config.agent_timeout,
        )

        agents_map = {
            "recon": ReconAgent(**kwargs),
            "threat_intel": ThreatIntelAgent(**kwargs),
            "forensics": ForensicsAgent(**kwargs),
            "remediation": RemediationAgent(**kwargs, auto_remediate=self._config.auto_remediate),
            "reporter": ReporterAgent(**kwargs, reports_dir=self._config.reports_dir),
        }
        agent = agents_map.get(agent_name)
        if agent is None:
            raise ValueError(f"Unknown agent_name {agent_name!r}")
        return agent
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_worker.py -v
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/worker.py tests/test_worker.py
git commit -m "feat(gate6): add SOCWorker with poll loop and injectable agent factory"
```

---

## Task 4: Wire Config and app.py

**Files:**
- Modify: `core/config.py`
- Modify: `core/app.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Add worker config fields**

In `core/config.py`, add three optional fields to `Config` (after `allowed_actions` or after the Gate 5 fields if present):

```python
worker_mode: str = "local"         # "local" | "remote"
worker_db_path: str = "./soc_workers.db"
worker_poll_interval: float = 2.0
```

Add to `_from_env()` return dict:

```python
worker_mode=os.getenv("SOC_WORKER_MODE", "local").strip().lower() or "local",
worker_db_path=os.getenv("SOC_WORKER_DB_PATH", "./soc_workers.db"),
worker_poll_interval=float(os.getenv("SOC_WORKER_POLL_INTERVAL", "2.0")),
```

- [ ] **Step 2: Write failing tests**

Add to `tests/test_config.py`:

```python
def test_config_worker_fields_have_defaults():
    from core.config import Config
    config = Config.for_dry_run()
    assert config.worker_mode == "local"
    assert config.worker_db_path == "./soc_workers.db"
    assert config.worker_poll_interval == 2.0

def test_config_worker_mode_from_env(monkeypatch):
    # Do NOT use importlib.reload — module reloads break isinstance checks in
    # parallel test runs. Config._from_env() calls os.getenv() at instance
    # creation time, so monkeypatching env vars before calling for_dry_run() works.
    monkeypatch.setenv("SOC_WORKER_MODE", "remote")
    monkeypatch.setenv("SOC_WORKER_DB_PATH", "/tmp/workers.db")
    monkeypatch.setenv("SOC_WORKER_POLL_INTERVAL", "0.5")
    from core.config import Config
    config = Config.for_dry_run()
    assert config.worker_mode == "remote"
    assert config.worker_db_path == "/tmp/workers.db"
    assert config.worker_poll_interval == 0.5
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/test_config.py::test_config_worker_fields_have_defaults tests/test_config.py::test_config_worker_mode_from_env -v
```

Expected: `AttributeError: 'Config' object has no attribute 'worker_mode'`

- [ ] **Step 4: Apply config changes and wire `core/app.py`**

After adding Config fields, update `core/app.py`:

Add imports at the **top of `core/app.py`** (not inside any function):

```python
from core.worker_queue import WorkerQueue
```

In `run_investigation()`, after creating `storage` and before creating `commander`, add:

```python
    worker_queue: WorkerQueue | None = None
    if config.worker_mode == "remote":
        worker_queue = WorkerQueue(db_path=config.worker_db_path)
```

Pass additional context to `Commander(...)`:

```python
commander = Commander(
    ...,
    worker_queue=worker_queue,
    worker_run_id=run_id,          # use run_id str — run object is created AFTER Commander
    worker_db_path=resolved_db_path,
    worker_poll_interval=config.worker_poll_interval,
)
```

> **Note:** `run_id` (the plain `str` on line ~60 of `app.py`) is already available before `Commander` is constructed. Do NOT use `run.run_id` — the `InvestigationRun` object is not created until after `Commander` is initialized.

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_config.py -v
```

Expected: all config tests pass including the two new ones.

- [ ] **Step 6: Commit**

```bash
git add core/config.py core/app.py tests/test_config.py
git commit -m "feat(gate6): add worker_mode/worker_db_path/worker_poll_interval config; wire WorkerQueue into app.py"
```

---

## Task 5: Wire Commander with remote runner mode

**Files:**
- Modify: `agents/commander.py`
- Modify: `tests/test_commander.py`

When `worker_queue` is set, `Commander._build_task_runner()` returns a remote runner: instead of calling `agent.run()` directly, it enqueues a `WorkerTask` and polls the `WorkerQueue` until the task is completed or failed.

- [ ] **Step 1: Write failing tests**

Add to `tests/test_commander.py`:

```python
@pytest.mark.asyncio
async def test_commander_remote_mode_enqueues_tasks(tmp_path):
    """When worker_queue is set, Commander should enqueue tasks instead of running them locally."""
    import asyncio, json
    from unittest.mock import MagicMock
    from agents.commander import Commander
    from core.worker_queue import WorkerQueue
    from core.models import Alert, AlertType, Severity
    from datetime import datetime, timezone
    from rich.console import Console

    # Queue that captures enqueued tasks
    queue = WorkerQueue(db_path=str(tmp_path / "workers.db"))

    graph = MagicMock()
    graph.write_node.return_value = "node-1"
    graph.get_nodes_by_type.return_value = []
    graph.get_task_status.return_value = "completed"

    llm = MagicMock()
    async def fake_call(system, messages, **kwargs):
        return '{"objective": "test", "priority_agents": ["recon"]}'
    llm.call = fake_call
    llm.attach_event_log = MagicMock()

    alert = Alert(
        id="a1", type=AlertType.INTRUSION, severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc), raw_payload={},
        source_ip="10.0.0.1",
    )

    # Background task to complete all enqueued worker tasks.
    # Uses claim_next() to atomically claim each task before completing it —
    # avoids TOCTOU race between list_pending() snapshot and claim/complete calls.
    async def auto_complete_tasks():
        for _ in range(50):   # up to 50 polls × 0.05s = 2.5s budget
            await asyncio.sleep(0.05)
            task = queue.claim_next(worker_id="fake-worker")
            if task:
                queue.complete(task.task_id, result={"status": "completed"})

    auto_complete = asyncio.create_task(auto_complete_tasks())
    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=Console(quiet=True),
        commander_timeout=10,
        worker_queue=queue,
        worker_run_id="r1",
        worker_db_path=str(tmp_path / "case.db"),
        worker_poll_interval=0.05,
    )
    try:
        await asyncio.wait_for(commander.investigate(alert), timeout=8)
    except Exception:
        pass
    finally:
        auto_complete.cancel()

    # At least one task should have been enqueued (recon is mandatory)
    all_tasks = queue.list_by_run_id("r1")
    assert len(all_tasks) >= 1
    assert any(t.agent_name == "recon" for t in all_tasks)
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_commander.py::test_commander_remote_mode_enqueues_tasks -v
```

Expected: `TypeError` — `Commander` does not accept `worker_queue`.

- [ ] **Step 3: Update `agents/commander.py`**

Add imports at module top:

```python
import uuid
from datetime import datetime, timezone
import json as _json
from core.worker_queue import WorkerQueue
from core.schemas import WorkerTask
```

Add params to `Commander.__init__()`:

```python
def __init__(
    self, ...,
    worker_queue: WorkerQueue | None = None,
    worker_run_id: str = "",
    worker_db_path: str = "",
    worker_poll_interval: float = 2.0,
):
    ...
    self.worker_queue = worker_queue
    self._worker_run_id = worker_run_id
    self._worker_db_path = worker_db_path
    self._worker_poll_interval = worker_poll_interval
```

Replace `_build_task_runner()` to switch between local and remote modes:

```python
def _build_task_runner(self, agent, alert: Alert):
    if self.worker_queue is not None:
        return self._build_remote_task_runner(alert)
    return self._build_local_task_runner(agent, alert)

def _build_local_task_runner(self, agent, alert: Alert):
    """Original in-process runner (existing logic, just renamed)."""
    async def runner(planned_task):
        task_node_id = self.graph.write_node(
            "task", planned_task.task_id,
            {
                "agent": planned_task.agent_name,
                "objective": planned_task.objective,
                "dependencies": planned_task.dependencies,
                "optional": planned_task.optional,
            },
            self.name,
            status=TaskStatus.QUEUED.value,
        )
        await agent.run(task_node_id, alert)
        status = self.graph.get_task_status(task_node_id)
        if status != TaskStatus.COMPLETED.value:
            raise RuntimeError(f"Agent {planned_task.agent_name} finished with status {status}")
        return {"task_node_id": task_node_id, "confidence": 1.0}
    return runner

def _build_remote_task_runner(self, alert: Alert):
    """Remote runner: writes task node, enqueues to WorkerQueue, polls for completion."""
    alert_json = _json.dumps({
        "id": alert.id, "type": alert.type.value, "severity": alert.severity.value,
        "timestamp": alert.timestamp.isoformat(),
        "source_ip": alert.source_ip, "dest_ip": alert.dest_ip,
        "source_port": alert.source_port, "dest_port": alert.dest_port,
        "hostname": alert.hostname, "user_account": alert.user_account,
        "process": alert.process, "tags": alert.tags,
        "raw_payload": alert.raw_payload,
    })

    async def runner(planned_task):
        task_node_id = self.graph.write_node(
            "task", planned_task.task_id,
            {
                "agent": planned_task.agent_name,
                "objective": planned_task.objective,
                "dependencies": planned_task.dependencies,
                "optional": planned_task.optional,
            },
            self.name,
            status=TaskStatus.QUEUED.value,
        )
        worker_task = WorkerTask(
            task_id=str(uuid.uuid4()),
            run_id=self._worker_run_id,
            plan_task_id=planned_task.task_id,
            task_node_id=task_node_id,
            agent_name=planned_task.agent_name,
            alert_json=alert_json,
            db_path=self._worker_db_path,
            status="pending",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.worker_queue.enqueue(worker_task)
        self.log(f"Dispatched {planned_task.agent_name} to worker queue ({worker_task.task_id[:8]})")

        # Poll until the worker marks this task complete or failed
        while True:
            queued = self.worker_queue.get(worker_task.task_id)
            if queued is not None and queued.status == "completed":
                return {"task_node_id": task_node_id, "confidence": 1.0}
            if queued is not None and queued.status == "failed":
                raise RuntimeError(
                    f"Remote agent {planned_task.agent_name} failed: {queued.error}"
                )
            await asyncio.sleep(self._worker_poll_interval)

    return runner
```

Update `_run_plan()` to use the updated `_build_task_runner()` (which now only takes `agent` and `alert` — no change needed since the local runner already matched this, but verify the call site still passes both):

```python
task_runners = {
    task.agent_name: self._build_task_runner(agents_map[task.agent_name], alert)
    for task in plan.tasks
    if task.agent_name in agents_map
}
```

- [ ] **Step 4: Run full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add agents/commander.py tests/test_commander.py
git commit -m "feat(gate6): add remote runner mode to Commander — enqueue WorkerTask, poll for completion"
```

---

## Task 6: Add `soc worker start` CLI

**Files:**
- Modify: `main.py`

The `worker start` command starts a long-running `SOCWorker` loop. Press Ctrl+C to stop. When `--dry-run` is passed, uses `MockLLMClient` so no API key is required.

- [ ] **Step 0: Verify subparser prerequisite**

Gate 6's `worker start` command requires `main.py` to use subparsers (not the flat `add_mutually_exclusive_group` in the current `main.py`). Gate 4 Task 8 adds subparsers. Verify the migration has happened:

```bash
grep -n "add_subparsers\|subparsers" /Users/waleedakrabi/Desktop/Github-forks/soc-agent/main.py
```

Expected output: at least one line containing `add_subparsers`.

If the grep returns nothing, Gate 4 Task 8 has not been implemented. **Stop and implement Gate 4 Task 8 first**, then return here.

- [ ] **Step 1: Add `worker` subcommand and handler**

Add to the subparsers block in `main()`:

```python
    # ── worker ───────────────────────────────────────────────────────────────
    worker_parser = subparsers.add_parser("worker", help="Start a SOC worker process")
    worker_sub = worker_parser.add_subparsers(dest="worker_command")
    worker_start_parser = worker_sub.add_parser("start", help="Start the worker loop")
    worker_start_parser.add_argument(
        "--worker-id", default="",
        help="Unique worker identifier (default: auto-generated)",
    )
    worker_start_parser.add_argument(
        "--poll-interval", type=float, default=None,
        help="Queue poll interval in seconds (overrides config)",
    )
    worker_start_parser.add_argument(
        "--dry-run", action="store_true", default=False,
        help="Use mock LLM — no API key required",
    )
```

Add dispatch in the `command` switch block:

```python
    elif command == "worker":
        asyncio.run(_cmd_worker(args, config))
```

Add the handler function:

```python
async def _cmd_worker(args, config) -> None:
    import uuid as _uuid
    from rich.console import Console
    from core.worker_queue import WorkerQueue
    from core.worker import SOCWorker

    console = Console()
    worker_command = getattr(args, "worker_command", None)
    if worker_command != "start":
        console.print("[yellow]Usage: soc worker start[/yellow]")
        return

    worker_id = getattr(args, "worker_id", "") or f"worker-{str(_uuid.uuid4())[:8]}"
    poll_interval = getattr(args, "poll_interval", None) or config.worker_poll_interval
    dry_run = getattr(args, "dry_run", False)

    if dry_run:
        # Set provider="mock" so SOCWorker._build_agent() detects it and substitutes
        # MockLLMClient instead of calling build_provider() (which doesn't support "mock").
        import dataclasses
        config = dataclasses.replace(config, provider="mock", model="mock")

    queue = WorkerQueue(db_path=config.worker_db_path)
    worker = SOCWorker(
        worker_id=worker_id,
        worker_queue=queue,
        config=config,
        poll_interval=poll_interval,
        console=console,
    )

    console.print(f"[bold cyan]SOC Worker[/bold cyan] {worker_id} started — "
                  f"polling {config.worker_db_path} every {poll_interval}s")
    console.print("[dim]Press Ctrl+C to stop.[/dim]")
    try:
        await worker.run_loop()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        console.print(f"\n[dim]Worker {worker_id} stopped.[/dim]")
```

- [ ] **Step 2: Run full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 3: Smoke test worker help**

```bash
python main.py worker start --help
```

Expected: help text showing `--worker-id`, `--poll-interval`, `--dry-run` options.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(gate6): add 'soc worker start' CLI command"
```

---

## Task 7: End-to-end remote mode smoke test

**Files:**
- Modify: `tests/test_dry_run_smoke.py`

Verify that an investigation with `worker_mode=remote` correctly enqueues all tasks and completes when a `SOCWorker` is running in a background coroutine.

- [ ] **Step 1: Write the test**

Add to `tests/test_dry_run_smoke.py`:

```python
@pytest.mark.asyncio
@pytest.mark.slow
async def test_remote_worker_mode_investigation_completes(tmp_path):
    """Full investigation with worker_mode=remote — worker runs in background task."""
    import asyncio
    import dataclasses
    from core.app import run_investigation
    from core.worker_queue import WorkerQueue
    from core.worker import SOCWorker
    from core.models import Alert, AlertType, Severity
    from datetime import datetime, timezone
    from rich.console import Console

    # Build config in dry-run + remote worker mode
    from core.config import Config
    config = Config.for_dry_run()
    config = dataclasses.replace(
        config,
        worker_mode="remote",
        worker_db_path=str(tmp_path / "workers.db"),
        worker_poll_interval=0.05,
        db_path=str(tmp_path / "case"),
        reports_dir=str(tmp_path / "reports"),
    )

    queue = WorkerQueue(db_path=config.worker_db_path)
    # Worker config: local mode + provider="mock" so _build_agent() uses MockLLMClient
    # (build_provider does not handle provider="mock"; the mock branch was added in Task 3)
    worker_config = dataclasses.replace(config, worker_mode="local", provider="mock", model="mock")
    worker = SOCWorker(
        worker_id="smoke-worker",
        worker_queue=queue,
        config=worker_config,
        poll_interval=0.05,
        console=Console(quiet=True),
    )

    # Start worker in background
    worker_task = asyncio.create_task(worker.run_loop())

    try:
        alert = Alert(
            id="smoke-remote-1", type=AlertType.BRUTE_FORCE, severity=Severity.MEDIUM,
            timestamp=datetime.now(timezone.utc), raw_payload={},
            source_ip="10.0.0.1", hostname="bastion-01",
        )
        run = await asyncio.wait_for(
            run_investigation(
                config=config, alert=alert, dry_run=True,
                console=Console(quiet=True),
            ),
            timeout=120,
        )
        assert run.completed_at is not None
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
```

- [ ] **Step 2: Run the smoke test**

```bash
pytest tests/test_dry_run_smoke.py::test_remote_worker_mode_investigation_completes -v -m slow
```

Expected: PASS (investigation completes with all tasks handled by the background worker).

- [ ] **Step 3: Run fast suite to verify no regressions**

```bash
pytest tests/ --ignore=tests/test_integration.py -m "not slow" -v
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_dry_run_smoke.py
git commit -m "test(gate6): add remote worker mode smoke test"
```
