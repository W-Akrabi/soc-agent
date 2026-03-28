# Gate 5: Controlled Execution — Approval Queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist AWAITING_APPROVAL actions to a shared SQLite approval queue so analysts can review, approve, reject, and roll back remediation actions from the terminal without re-running an investigation.

**Architecture:** When `ExecutionPolicy.decide()` returns AWAITING_APPROVAL, `ActionExecutorTool` writes a `PendingAction` row (with blast-radius estimate and rollback metadata) to a shared `ApprovalQueue` SQLite file (`soc_approvals.db`). The CLI gains four commands: `approve list`, `approve action <id>` (executes via adapter), `reject <id>`, and `rollback <id>` (executes inverse action via adapter). Rollback is modelled as an inverse action type (`unisolate_host`, `enable_account`) dispatched through the same adapter `execute()` path.

**Tech Stack:** Python 3.11+, stdlib `sqlite3`, existing `core.execution_policy.ExecutionPolicy`, existing `tools.action_executor.ActionExecutorTool`, existing `integrations.defender.DefenderAdapter`, existing `integrations.entra.EntraAdapter`. No new packages.

---

## Scope note

Gate 5 depends on Gates 1–3 (schemas, execution policy, adapters). It does NOT depend on Gate 4 (MemoryStore). The `ApprovalQueue` pattern is intentionally parallel to `MemoryStore` — separate file, separate responsibility.

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/schemas.py` | **Modify** | Add `PendingAction` dataclass |
| `core/blast_radius.py` | **Create** | Rule-based blast-radius estimator + rollback action map |
| `core/approval_queue.py` | **Create** | SQLite approval queue — enqueue / list / approve / reject / rollback status |
| `core/config.py` | **Modify** | Add `approval_db_path`, `enable_approval_queue` fields |
| `tools/action_executor.py` | **Modify** | On AWAITING_APPROVAL: enqueue to `ApprovalQueue` |
| `integrations/defender.py` | **Modify** | Add `unisolate_host` support in `execute()` for rollback |
| `agents/commander.py` | **Modify** | Accept `approval_queue` param, pass through `_build_agents()` |
| `agents/remediation.py` | **Modify** | Pass `approval_queue` to `ActionExecutorTool` constructor |
| `core/app.py` | **Modify** | Create `ApprovalQueue` and pass to `Commander` |
| `main.py` | **Modify** | Add `approve`, `reject`, `rollback` subcommands |
| `tests/test_schemas.py` | **Modify** | Add `PendingAction` field tests |
| `tests/test_blast_radius.py` | **Create** | Unit tests for blast-radius strings and rollback map |
| `tests/test_approval_queue.py` | **Create** | Unit tests for queue write / read / state transitions |
| `tests/test_action_executor.py` | **Create** | Test queue write on AWAITING_APPROVAL |

---

## Task 1: Add PendingAction schema

**Files:**
- Modify: `core/schemas.py`
- Modify: `tests/test_schemas.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_schemas.py`:

```python
from core.schemas import PendingAction
from dataclasses import fields

def test_pending_action_required_fields():
    required = {f.name for f in fields(PendingAction)}
    assert "action_id" in required
    assert "run_id" in required
    assert "alert_id" in required
    assert "action_type" in required
    assert "target" in required
    assert "reason" in required
    assert "urgency" in required
    assert "blast_radius" in required
    assert "status" in required
    assert "created_at" in required

def test_pending_action_defaults():
    from datetime import datetime, timezone
    pa = PendingAction(
        action_id="a1", run_id="r1", alert_id="al1",
        action_type="block_ip", target="10.0.0.1",
        reason="C2 traffic", urgency="immediate",
        blast_radius="Blocks all traffic from 10.0.0.1",
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert pa.reviewed_at is None
    assert pa.reviewed_by is None
    assert pa.rollback_supported is False
    assert pa.rollback_action_type is None
    assert pa.execution_result is None
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /Users/waleedakrabi/Desktop/Github-forks/soc-agent
pytest tests/test_schemas.py::test_pending_action_required_fields tests/test_schemas.py::test_pending_action_defaults -v
```

Expected: `ImportError: cannot import name 'PendingAction'`

- [ ] **Step 3: Add `PendingAction` to `core/schemas.py`**

Append after `validate_action_proposals`:

```python
@dataclass
class PendingAction:
    action_id: str
    run_id: str
    alert_id: str
    action_type: str
    target: str
    reason: str
    urgency: str
    blast_radius: str           # human-readable impact estimate
    status: str                 # pending | approved | rejected | executed | rolled_back | failed
    created_at: str             # ISO timestamp
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    rollback_supported: bool = False
    rollback_action_type: str | None = None   # e.g. "unisolate_host"
    rollback_data: dict = field(default_factory=dict)   # adapter-specific rollback payload
    execution_result: dict | None = None      # captured from ActionExecutionResult on approve
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_schemas.py -v
```

Expected: all schema tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/schemas.py tests/test_schemas.py
git commit -m "feat(gate5): add PendingAction schema"
```

---

## Task 2: Create BlastRadiusEstimator

**Files:**
- Create: `core/blast_radius.py`
- Create: `tests/test_blast_radius.py`

The `estimate_blast_radius` function returns a short, analyst-readable impact string. The `ROLLBACK_MAP` defines which actions are reversible and what the inverse action type is.

- [ ] **Step 1: Write failing tests**

Create `tests/test_blast_radius.py`:

```python
from core.blast_radius import estimate_blast_radius, ROLLBACK_MAP

def test_block_ip_description():
    result = estimate_blast_radius("block_ip", "10.0.0.1")
    assert "10.0.0.1" in result
    assert "block" in result.lower() or "traffic" in result.lower()

def test_disable_account_description():
    result = estimate_blast_radius("disable_account", "jdoe")
    assert "jdoe" in result
    assert "access" in result.lower() or "account" in result.lower()

def test_isolate_host_description():
    result = estimate_blast_radius("isolate_host", "web-prod-01")
    assert "web-prod-01" in result
    assert "isolat" in result.lower() or "network" in result.lower()

def test_patch_recommendation_is_advisory():
    result = estimate_blast_radius("patch_recommendation", "CVE-2024-1234")
    assert "advisory" in result.lower() or "no automated" in result.lower()

def test_unknown_action_returns_generic():
    result = estimate_blast_radius("unknown_action_xyz", "some-target")
    assert len(result) > 0  # must return something, never raise

def test_rollback_map_isolate_host():
    entry = ROLLBACK_MAP.get("isolate_host")
    assert entry is not None
    rollback_action, rollback_supported = entry
    assert rollback_supported is True
    assert rollback_action == "unisolate_host"

def test_rollback_map_disable_account():
    entry = ROLLBACK_MAP.get("disable_account")
    assert entry is not None
    _, rollback_supported = entry
    assert rollback_supported is True

def test_rollback_map_block_ip_not_supported():
    entry = ROLLBACK_MAP.get("block_ip")
    assert entry is not None
    _, rollback_supported = entry
    assert rollback_supported is False
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_blast_radius.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.blast_radius'`

- [ ] **Step 3: Create `core/blast_radius.py`**

```python
"""Rule-based blast-radius estimator and rollback action map for remediation actions."""
from __future__ import annotations

# (action_type) -> (inverse_action_type, rollback_supported)
ROLLBACK_MAP: dict[str, tuple[str, bool]] = {
    "block_ip": ("unblock_ip", False),           # no standard unblock API in current adapters
    "disable_account": ("enable_account", True),  # EntraAdapter supports re-enable
    "isolate_host": ("unisolate_host", True),      # DefenderAdapter supports unisolate
    "revoke_sessions": ("", False),               # sessions cannot be restored
    "patch_recommendation": ("", False),          # advisory; no automated action
}

_DESCRIPTIONS: dict[str, str] = {
    "block_ip": (
        "Will block all inbound and outbound traffic for IP '{target}' at the network "
        "perimeter. Any legitimate traffic from this IP will be dropped until unblocked."
    ),
    "disable_account": (
        "Will lock user account '{target}'. The user will lose access to all systems "
        "immediately and must be re-enabled manually or via 'soc rollback'."
    ),
    "isolate_host": (
        "Will disconnect host '{target}' from all network segments via Defender isolation. "
        "Connected services and users relying on this host will lose access until unisolated."
    ),
    "revoke_sessions": (
        "Will terminate all active sessions for '{target}'. "
        "Existing work may be lost; the user will need to re-authenticate."
    ),
    "patch_recommendation": (
        "Advisory only — no automated action is taken. "
        "Analyst should apply patch for '{target}' at next maintenance window."
    ),
}


def estimate_blast_radius(action_type: str, target: str) -> str:
    """Return a short, analyst-readable blast-radius description.

    Never raises — unknown action types get a generic message.
    """
    normalized = (action_type or "").strip().lower()
    template = _DESCRIPTIONS.get(normalized)
    if template:
        return template.format(target=target)
    return (
        f"Action '{action_type}' on target '{target}': no pre-defined impact estimate. "
        "Review manually before approving."
    )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_blast_radius.py -v
```

Expected: all 8 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/blast_radius.py tests/test_blast_radius.py
git commit -m "feat(gate5): add blast-radius estimator and rollback action map"
```

---

## Task 3: Create ApprovalQueue

**Files:**
- Create: `core/approval_queue.py`
- Create: `tests/test_approval_queue.py`

The `ApprovalQueue` owns a shared SQLite file (default `soc_approvals.db`). Multiple investigation runs and the CLI all read from and write to this same file.

Idempotency rule: if `(run_id, action_type, target)` already exists with a non-rejected status, `enqueue()` returns the existing `PendingAction` without inserting a duplicate.

- [ ] **Step 1: Write failing tests**

Create `tests/test_approval_queue.py`:

```python
import pytest
from datetime import datetime, timezone
from core.approval_queue import ApprovalQueue
from core.schemas import PendingAction


def _pa(action_id="a1", run_id="r1", alert_id="al1",
        action_type="block_ip", target="10.0.0.1") -> PendingAction:
    return PendingAction(
        action_id=action_id,
        run_id=run_id,
        alert_id=alert_id,
        action_type=action_type,
        target=target,
        reason="C2 traffic",
        urgency="immediate",
        blast_radius="Blocks all traffic from 10.0.0.1",
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
        rollback_supported=True,
        rollback_action_type="unisolate_host",
    )


def test_enqueue_and_list_pending(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].action_id == "a1"


def test_get_by_action_id(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    result = queue.get("a1")
    assert result is not None
    assert result.action_type == "block_ip"


def test_get_returns_none_for_missing(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    assert queue.get("nonexistent") is None


def test_reject_updates_status(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    queue.reject("a1", reviewed_by="analyst@corp.com")
    result = queue.get("a1")
    assert result.status == "rejected"
    assert result.reviewed_by == "analyst@corp.com"
    assert result.reviewed_at is not None


def test_mark_executed_updates_status(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    queue.mark_executed("a1", execution_result={"status": "executed", "message": "ok"})
    result = queue.get("a1")
    assert result.status == "executed"
    assert result.execution_result == {"status": "executed", "message": "ok"}


def test_mark_rolled_back_updates_status(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    queue.mark_executed("a1", execution_result={"status": "executed"})
    queue.mark_rolled_back("a1")
    result = queue.get("a1")
    assert result.status == "rolled_back"


def test_idempotent_enqueue_returns_existing(tmp_path):
    """Enqueueing same (run_id, action_type, target) twice returns the first entry."""
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    queue.enqueue(_pa("a2"))  # different action_id, same run+type+target
    pending = queue.list_pending()
    # Only the first should be present; the second is a duplicate
    assert len(pending) == 1
    assert pending[0].action_id == "a1"


def test_list_pending_excludes_rejected(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1"))
    queue.reject("a1", reviewed_by="analyst")
    assert queue.list_pending() == []


def test_list_all_includes_all_statuses(tmp_path):
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    queue.enqueue(_pa("a1", run_id="r1", action_type="block_ip", target="1.1.1.1"))
    queue.enqueue(_pa("a2", run_id="r2", action_type="disable_account", target="jdoe"))
    queue.reject("a1", reviewed_by="analyst")
    all_actions = queue.list_all()
    assert len(all_actions) == 2
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_approval_queue.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.approval_queue'`

- [ ] **Step 3: Create `core/approval_queue.py`**

```python
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import PendingAction


class ApprovalQueue:
    """Shared cross-run SQLite approval queue for AWAITING_APPROVAL actions.

    Multiple investigation runs and CLI commands read/write this same file.
    Idempotency: (run_id, action_type, target) is a unique key for non-rejected rows.
    """

    def __init__(self, db_path: str = "./soc_approvals.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS pending_actions (
                    action_id           TEXT PRIMARY KEY,
                    run_id              TEXT NOT NULL,
                    alert_id            TEXT NOT NULL,
                    action_type         TEXT NOT NULL,
                    target              TEXT NOT NULL,
                    reason              TEXT NOT NULL,
                    urgency             TEXT NOT NULL,
                    blast_radius        TEXT NOT NULL,
                    status              TEXT NOT NULL DEFAULT 'pending',
                    created_at          TEXT NOT NULL,
                    reviewed_at         TEXT,
                    reviewed_by         TEXT,
                    rollback_supported  INTEGER NOT NULL DEFAULT 0,
                    rollback_action_type TEXT,
                    rollback_data_json  TEXT NOT NULL DEFAULT '{}',
                    execution_result_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_pa_status ON pending_actions(status);
                CREATE INDEX IF NOT EXISTS idx_pa_run ON pending_actions(run_id);
                -- Only one non-executed pending row per (run_id, action_type, target).
                -- Using status = 'pending' means completed/rejected/executed rows do not
                -- block re-queueing from a subsequent investigation run.
                CREATE UNIQUE INDEX IF NOT EXISTS idx_pa_idempotent
                    ON pending_actions(run_id, action_type, target)
                    WHERE status = 'pending';
            """)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def enqueue(self, action: PendingAction) -> PendingAction:
        """Insert the action into the queue.

        If an identical (run_id, action_type, target) row already exists with a
        non-rejected status, returns the existing row without inserting a duplicate.
        """
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM pending_actions "
                "WHERE run_id=? AND action_type=? AND target=? AND status = 'pending'",
                (action.run_id, action.action_type, action.target),
            ).fetchone()
            if existing:
                return self._row_to_action(existing)

            conn.execute(
                """INSERT INTO pending_actions
                   (action_id, run_id, alert_id, action_type, target, reason, urgency,
                    blast_radius, status, created_at, rollback_supported,
                    rollback_action_type, rollback_data_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    action.action_id, action.run_id, action.alert_id,
                    action.action_type, action.target, action.reason, action.urgency,
                    action.blast_radius, action.status, action.created_at,
                    int(action.rollback_supported),
                    action.rollback_action_type,
                    json.dumps(action.rollback_data or {}),
                ),
            )
        return action

    def get(self, action_id: str) -> PendingAction | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM pending_actions WHERE action_id=?", (action_id,)
            ).fetchone()
        return self._row_to_action(row) if row else None

    def list_pending(self) -> list[PendingAction]:
        """Return all actions with status='pending'."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_actions WHERE status='pending' "
                "ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_action(r) for r in rows]

    def list_all(self) -> list[PendingAction]:
        """Return all actions regardless of status."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM pending_actions ORDER BY created_at ASC"
            ).fetchall()
        return [self._row_to_action(r) for r in rows]

    def reject(self, action_id: str, *, reviewed_by: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_actions SET status='rejected', reviewed_at=?, reviewed_by=? "
                "WHERE action_id=?",
                (self._now(), reviewed_by or None, action_id),
            )

    def mark_executed(self, action_id: str, *, execution_result: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_actions SET status='executed', reviewed_at=?, "
                "execution_result_json=? WHERE action_id=?",
                (self._now(), json.dumps(execution_result), action_id),
            )

    def mark_failed(self, action_id: str, *, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_actions SET status='failed', reviewed_at=?, "
                "execution_result_json=? WHERE action_id=?",
                (self._now(), json.dumps({"error": error}), action_id),
            )

    def mark_rolled_back(self, action_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE pending_actions SET status='rolled_back', reviewed_at=? "
                "WHERE action_id=?",
                (self._now(), action_id),
            )

    @staticmethod
    def _row_to_action(row) -> PendingAction:
        d = dict(row)
        exec_json = d.get("execution_result_json")
        return PendingAction(
            action_id=d["action_id"],
            run_id=d["run_id"],
            alert_id=d["alert_id"],
            action_type=d["action_type"],
            target=d["target"],
            reason=d["reason"],
            urgency=d["urgency"],
            blast_radius=d["blast_radius"],
            status=d["status"],
            created_at=d["created_at"],
            reviewed_at=d.get("reviewed_at"),
            reviewed_by=d.get("reviewed_by"),
            rollback_supported=bool(d.get("rollback_supported", 0)),
            rollback_action_type=d.get("rollback_action_type"),
            rollback_data=json.loads(d.get("rollback_data_json") or "{}"),
            execution_result=json.loads(exec_json) if exec_json else None,
        )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_approval_queue.py -v
```

Expected: all 9 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/approval_queue.py tests/test_approval_queue.py
git commit -m "feat(gate5): add ApprovalQueue with idempotent enqueue and state transitions"
```

---

## Task 4: Wire ApprovalQueue into ActionExecutorTool

**Files:**
- Modify: `tools/action_executor.py`
- Create: `tests/test_action_executor.py`

When `ExecutionPolicy.decide()` returns AWAITING_APPROVAL (i.e., `decision.status == ActionStatus.AWAITING_APPROVAL`), `ActionExecutorTool.run()` enqueues a `PendingAction` before returning. The blast-radius string and rollback metadata are computed from `ROLLBACK_MAP` and `estimate_blast_radius`.

- [ ] **Step 1: Write failing tests**

Create `tests/test_action_executor.py`:

```python
import pytest
import asyncio
from unittest.mock import MagicMock
from core.approval_queue import ApprovalQueue
from core.execution_policy import ExecutionPolicy
from tools.action_executor import ActionExecutorTool


def _make_executor(tmp_path, *, enabled=True, allowed=("block_ip",)):
    policy = ExecutionPolicy(enabled=enabled, allowed_actions=allowed)
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    return ActionExecutorTool(
        auto_remediate=False,   # allow_execution=False → AWAITING_APPROVAL
        policy=policy,
        approval_queue=queue,
        defender_adapter=MagicMock(supports_write=True),
    ), queue


@pytest.mark.asyncio
async def test_awaiting_approval_enqueues_to_queue(tmp_path):
    executor, queue = _make_executor(tmp_path)
    result = await executor.run({
        "action_type": "block_ip",
        "target": "10.0.0.1",
        "reason": "C2 traffic",
        "urgency": "immediate",
        "metadata": {"alert_id": "a1", "run_id": "r1"},
    })
    assert result["status"] == "awaiting_approval"
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].action_type == "block_ip"
    assert pending[0].target == "10.0.0.1"
    assert len(pending[0].blast_radius) > 0


@pytest.mark.asyncio
async def test_proposed_does_not_enqueue(tmp_path):
    """PROPOSED (policy disabled) must NOT write to queue."""
    policy = ExecutionPolicy(enabled=False)
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    executor = ActionExecutorTool(auto_remediate=False, policy=policy, approval_queue=queue)
    await executor.run({
        "action_type": "block_ip",
        "target": "10.0.0.1",
        "reason": "test",
        "urgency": "scheduled",
        "metadata": {},
    })
    assert queue.list_pending() == []


@pytest.mark.asyncio
async def test_no_queue_does_not_raise_on_awaiting_approval(tmp_path):
    """If no approval_queue is wired, AWAITING_APPROVAL still returns correct status."""
    policy = ExecutionPolicy(enabled=True, allowed_actions=("block_ip",))
    executor = ActionExecutorTool(auto_remediate=False, policy=policy, approval_queue=None)
    result = await executor.run({
        "action_type": "block_ip",
        "target": "10.0.0.1",
        "reason": "test",
        "urgency": "immediate",
        "metadata": {},
    })
    assert result["status"] == "awaiting_approval"


@pytest.mark.asyncio
async def test_rollback_metadata_stored_for_isolate_host(tmp_path):
    policy = ExecutionPolicy(enabled=True, allowed_actions=("isolate_host",))
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))
    executor = ActionExecutorTool(
        auto_remediate=False, policy=policy, approval_queue=queue,
        defender_adapter=MagicMock(supports_write=True),
    )
    await executor.run({
        "action_type": "isolate_host",
        "target": "web-prod-01",
        "reason": "malware",
        "urgency": "immediate",
        "metadata": {"alert_id": "a1", "run_id": "r1"},
    })
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].rollback_supported is True
    assert pending[0].rollback_action_type == "unisolate_host"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_action_executor.py -v
```

Expected: `TypeError` — `ActionExecutorTool.__init__` does not accept `approval_queue`.

- [ ] **Step 3: Update `tools/action_executor.py`**

Add imports at the **top of `tools/action_executor.py`** (not inside any function):

```python
import uuid
from datetime import datetime, timezone
from core.approval_queue import ApprovalQueue
from core.blast_radius import ROLLBACK_MAP, estimate_blast_radius
from core.schemas import PendingAction
```

Add `approval_queue` param to `__init__`:

```python
def __init__(
    self,
    auto_remediate: bool = False,
    *,
    policy: ExecutionPolicy | None = None,
    defender_adapter: Any | None = None,
    entra_adapter: Any | None = None,
    approval_queue: ApprovalQueue | None = None,  # add this
):
    ...
    self.approval_queue = approval_queue
```

In `run()`, after the `if not decision.should_execute:` block where `decision.status == ActionStatus.AWAITING_APPROVAL`, add queue write. Replace that return block:

```python
        if not decision.should_execute:
            response = {
                "status": decision.status.value,
                "executed": False,
                "action_type": action_type,
                "target": target,
                "message": decision.reason,
                "policy": {
                    "action_type": decision.action_type,
                    "status": decision.status.value,
                    "allowed": decision.allowed,
                    "should_execute": decision.should_execute,
                    "reason": decision.reason,
                    "metadata": decision.metadata,
                },
            }
            # Enqueue when policy allows but execution mode is not yet enabled
            if decision.allowed and self.approval_queue is not None:
                rollback_action, rollback_ok = ROLLBACK_MAP.get(
                    action_type, ("", False)
                )
                pending = PendingAction(
                    action_id=str(uuid.uuid4()),
                    run_id=metadata.get("run_id", ""),
                    alert_id=metadata.get("alert_id", ""),
                    action_type=action_type,
                    target=target,
                    reason=reason,
                    urgency=urgency,
                    blast_radius=estimate_blast_radius(action_type, target),
                    status="pending",
                    created_at=datetime.now(timezone.utc).isoformat(),
                    rollback_supported=rollback_ok,
                    rollback_action_type=rollback_action or None,
                )
                enqueued = self.approval_queue.enqueue(pending)
                response["approval_queue_id"] = enqueued.action_id
            return response
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_action_executor.py -v
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add tools/action_executor.py tests/test_action_executor.py core/blast_radius.py
git commit -m "feat(gate5): wire ApprovalQueue into ActionExecutorTool on AWAITING_APPROVAL"
```

---

## Task 5: Wire Config and app.py

**Files:**
- Modify: `core/config.py`
- Modify: `core/app.py`
- Modify: `tests/test_config.py`

- [ ] **Step 1: Add approval config fields**

In `core/config.py`, add two optional fields to `Config` (after `allowed_actions`):

```python
approval_db_path: str = "./soc_approvals.db"
enable_approval_queue: bool = True
```

Add to `_from_env()` return dict:

```python
approval_db_path=os.getenv("SOC_APPROVAL_DB_PATH", "./soc_approvals.db"),
enable_approval_queue=parse_bool_flag(os.getenv("SOC_ENABLE_APPROVAL_QUEUE"), default=True),
```

- [ ] **Step 2: Write failing test**

Add to `tests/test_config.py`:

```python
def test_config_approval_fields_have_defaults():
    from core.config import Config
    # Config.for_dry_run() reads all env vars and falls back to defaults.
    import os
    os.environ.setdefault("ANTHROPIC_API_KEY", "test")
    config = Config.for_dry_run()
    assert config.approval_db_path == "./soc_approvals.db"
    assert config.enable_approval_queue is True

def test_config_approval_db_path_from_env(monkeypatch):
    monkeypatch.setenv("SOC_APPROVAL_DB_PATH", "/tmp/my_approvals.db")
    monkeypatch.setenv("SOC_ENABLE_APPROVAL_QUEUE", "false")
    from importlib import reload
    import core.config as cfg_module
    reload(cfg_module)
    config = cfg_module.Config.for_dry_run()
    assert config.approval_db_path == "/tmp/my_approvals.db"
    assert config.enable_approval_queue is False
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/test_config.py::test_config_approval_fields_have_defaults tests/test_config.py::test_config_approval_db_path_from_env -v
```

Expected: `AttributeError: 'Config' object has no attribute 'approval_db_path'`

- [ ] **Step 4: Apply config changes and wire `core/app.py`**

After adding Config fields, update `core/app.py`:

**a) Rename `_compose_integration_registry` to public.** Rename the existing private function `_compose_integration_registry` to `compose_integration_registry` (drop the leading underscore) everywhere it is defined and called in `core/app.py`. This makes it safely importable by CLI handlers without coupling them to an internal name.

```python
# Before (existing)
def _compose_integration_registry(config: Config, *, dry_run: bool) -> IntegrationRegistry:
    ...

# After
def compose_integration_registry(config: Config, *, dry_run: bool) -> IntegrationRegistry:
    ...
```

Update the call site in `run_investigation()` to use the new name.

**b) Add ApprovalQueue import** at the **top of `core/app.py`** (not inside any function):

```python
from core.approval_queue import ApprovalQueue
```

**c) Wire in `run_investigation()`** — after creating `storage` and before creating `commander`:

```python
    approval_queue: ApprovalQueue | None = None
    if config.enable_approval_queue:
        approval_queue = ApprovalQueue(db_path=config.approval_db_path)
```

Pass to `Commander(...)`:

```python
commander = Commander(
    ...,
    approval_queue=approval_queue,
)
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_config.py -v
```

Expected: all config tests pass including the two new ones.

- [ ] **Step 6: Commit**

```bash
git add core/config.py core/app.py tests/test_config.py
git commit -m "feat(gate5): add approval_db_path/enable_approval_queue config; wire ApprovalQueue into app.py"
```

---

## Task 6: Wire through Commander and RemediationAgent

**Files:**
- Modify: `agents/commander.py`
- Modify: `agents/remediation.py`
- Modify: `tests/test_agents.py`

- [ ] **Step 1: Write failing test**

Add to `tests/test_agents.py`:

```python
@pytest.mark.asyncio
async def test_remediation_agent_enqueues_awaiting_approval(tmp_path):
    """When policy is enabled but allow_execution=False, action goes to ApprovalQueue."""
    from unittest.mock import AsyncMock, MagicMock
    from agents.remediation import RemediationAgent
    from core.execution_policy import ExecutionPolicy
    from core.approval_queue import ApprovalQueue
    from core.models import Alert, AlertType, Severity
    from datetime import datetime, timezone
    import json

    # Graph that returns one finding, zero CVEs, zero timeline events
    graph = MagicMock()
    graph.get_nodes_by_type.side_effect = lambda t: (
        [{"data": {"description": "C2 traffic", "source_ip": "10.0.0.1"}}]
        if t == "finding" else []
    )
    graph.write_node.return_value = "node-1"
    graph.update_node_status = MagicMock()

    llm = MagicMock()
    llm.call = AsyncMock(return_value=json.dumps([{
        "action_type": "block_ip",
        "target": "10.0.0.1",
        "reason": "C2 traffic",
        "urgency": "immediate",
    }]))
    llm.attach_event_log = MagicMock()

    from rich.console import Console
    policy = ExecutionPolicy(enabled=True, allowed_actions=("block_ip",))
    queue = ApprovalQueue(db_path=str(tmp_path / "approvals.db"))

    agent = RemediationAgent(
        case_graph=graph,
        llm=llm,
        console=Console(quiet=True),
        execution_policy=policy,
        approval_queue=queue,
    )
    alert = Alert(
        id="a1", type=AlertType.INTRUSION, severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc), raw_payload={},
        source_ip="10.0.0.1",
    )
    await agent.run("task-node-1", alert)
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].action_type == "block_ip"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_agents.py::test_remediation_agent_enqueues_awaiting_approval -v
```

Expected: `TypeError` — `RemediationAgent` does not accept `approval_queue`.

- [ ] **Step 3: Update `agents/remediation.py`**

Add import at top:

```python
from core.approval_queue import ApprovalQueue
```

Add `approval_queue` to `__init__` signature:

```python
def __init__(
    self,
    *args,
    auto_remediate: bool = False,
    execution_policy: ExecutionPolicy | None = None,
    defender_adapter=None,
    entra_adapter=None,
    allowed_actions: tuple[str, ...] = (),
    approval_queue: ApprovalQueue | None = None,  # add this
    **kwargs,
):
    super().__init__(*args, **kwargs)
    policy = execution_policy or ExecutionPolicy(
        enabled=auto_remediate,
        allowed_actions=allowed_actions,
    )
    self.executor = ActionExecutorTool(
        auto_remediate=auto_remediate,
        policy=policy,
        defender_adapter=defender_adapter,
        entra_adapter=entra_adapter,
        approval_queue=approval_queue,   # pass through
    )
```

- [ ] **Step 4: Update `agents/commander.py`**

Add import at top:

```python
from core.approval_queue import ApprovalQueue
```

Add to `Commander.__init__` signature:

```python
def __init__(self, ..., approval_queue: ApprovalQueue | None = None):
    ...
    self.approval_queue = approval_queue
```

In `_build_agents()`, pass it to `RemediationAgent`:

```python
"remediation": RemediationAgent(
    **kwargs,
    auto_remediate=self.auto_remediate,
    execution_policy=self.execution_policy,
    defender_adapter=defender_adapter,
    entra_adapter=entra_adapter,
    approval_queue=self.approval_queue,   # add this line
),
```

- [ ] **Step 5: Run full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add agents/commander.py agents/remediation.py tests/test_agents.py
git commit -m "feat(gate5): wire approval_queue through Commander → RemediationAgent → ActionExecutorTool"
```

---

## Task 7: Add unisolate_host to DefenderAdapter

**Files:**
- Modify: `integrations/defender.py`
- Modify: `tests/test_defender_integration.py`

Rollback of `isolate_host` is `unisolate_host`. The Defender API endpoint is `POST /api/machines/{id}/unisolate`.

- [ ] **Step 1: Write failing test**

Add to `tests/test_defender_integration.py`:

```python
@pytest.mark.asyncio
async def test_unisolate_host_calls_correct_endpoint(respx_mock):
    """unisolate_host should POST to /api/machines/{id}/unisolate."""
    import respx, httpx
    from integrations.defender import DefenderAdapter
    from core.schemas import ActionExecutionRequest

    machine_id = "abc123"
    respx_mock.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/unisolate"
    ).mock(return_value=httpx.Response(200, json={"id": "action-456"}))

    # Stub auth so the test doesn't need real credentials
    from integrations.base import MicrosoftAuthHelper
    auth = MagicMock()
    auth.authorization_headers = AsyncMock(return_value={"Authorization": "Bearer test"})

    adapter = DefenderAdapter(bearer_token="test")
    adapter._auth = auth

    request = ActionExecutionRequest(
        action_type="unisolate_host",
        target=machine_id,
        reason="Rollback of isolate_host",
        urgency="immediate",
        requested_by="analyst",
        allow_execution=True,
        metadata={"machine_id": machine_id},
    )
    result = await adapter.execute(request)
    assert result.executed is True
    assert result.status == "executed"
    assert result.action_type == "unisolate_host"
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_defender_integration.py::test_unisolate_host_calls_correct_endpoint -v
```

Expected: `AssertionError: assert False is True` (adapter returns `unsupported` for unknown action types)

- [ ] **Step 3: Update `DefenderAdapter.execute()` in `integrations/defender.py`**

In `execute()`, add a branch for `unisolate_host` before the unsupported return:

```python
async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
    action_type = (request.action_type or "").strip().lower()
    if action_type == "isolate_host":
        return await self._execute_isolate(request)
    if action_type == "unisolate_host":
        return await self._execute_unisolate(request)
    return ActionExecutionResult(
        adapter_name=self.name,
        action_type=request.action_type,
        target=request.target,
        status="unsupported",
        executed=False,
        message=f"Defender adapter does not support action_type {request.action_type!r}",
        metadata={"requested_by": request.requested_by},
    )
```

Extract the existing isolate logic into `_execute_isolate(self, request)` (no behaviour change — just rename the implementation). Then add:

```python
async def _execute_unisolate(self, request: ActionExecutionRequest) -> ActionExecutionResult:
    try:
        headers = await self._auth.authorization_headers()
        machine_id, resolution = await self._resolve_machine_id(request, headers=headers)
        payload = {"Comment": request.reason}
        async with self._client_factory() as client:
            response = await client.post(
                f"{self.base_url}/api/machines/{machine_id}/unisolate",
                headers={**headers, "Content-Type": "application/json", "Accept": "application/json"},
                json=payload,
            )
            response.raise_for_status()
            response_payload = response.json() if hasattr(response, "json") else {}
        external_id = None
        if isinstance(response_payload, dict):
            external_id = str(
                response_payload.get("id")
                or response_payload.get("machineActionId")
                or ""
            ) or None
        return ActionExecutionResult(
            adapter_name=self.name,
            action_type=request.action_type,
            target=request.target,
            status="executed",
            executed=True,
            external_id=external_id,
            rollback_supported=False,   # unisolate cannot itself be rolled back
            message="Machine unisolate request submitted successfully",
            metadata={
                "requested_by": request.requested_by,
                "machine_id": machine_id,
                "resolution": resolution,
                "response": response_payload,
            },
        )
    except Exception as exc:
        return ActionExecutionResult(
            adapter_name=self.name,
            action_type=request.action_type,
            target=request.target,
            status="failed",
            executed=False,
            message=str(exc),
            metadata={"requested_by": request.requested_by},
        )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_defender_integration.py -v
```

Expected: all defender tests pass including the new unisolate test.

- [ ] **Step 5: Commit**

```bash
git add integrations/defender.py tests/test_defender_integration.py
git commit -m "feat(gate5): add unisolate_host to DefenderAdapter for rollback support"
```

---

## Task 8: Add approve/reject/rollback CLI subcommands

**Files:**
- Modify: `main.py`

The existing `main.py` uses a flat argparse structure (`--alert` / `--watch`). Gate 4 converts this to subparsers (as part of its Task 8). Gate 5's CLI additions build on top of that same subparser structure. If Gate 4 has not been implemented yet, apply the subparser conversion from Gate 4's plan first, then add these subcommands.

The three new subcommands are:
- `python main.py approve list` — print pending actions as a rich table
- `python main.py approve action <action_id>` — execute the action via the right adapter, mark as executed
- `python main.py reject <action_id>` — mark as rejected, prompt for reviewer name
- `python main.py rollback <action_id>` — execute inverse action via adapter, mark as rolled_back

- [ ] **Step 1: Add `approve` and `reject` and `rollback` subcommands**

> **NOTE:** If Gate 4's subparser structure is already in place, add these parsers to the existing subparsers block. If not, convert from flat to subparser first (copy the structure from Gate 4 Task 8 Step 1), then add these.

```python
    # ── approve ──────────────────────────────────────────────────────────────
    approve_parser = subparsers.add_parser("approve", help="Approve or list pending actions")
    approve_sub = approve_parser.add_subparsers(dest="approve_command")
    approve_sub.add_parser("list", help="List pending actions")
    approve_action_parser = approve_sub.add_parser("action", help="Approve a specific action")
    approve_action_parser.add_argument("action_id", help="Action ID from 'approve list'")
    approve_action_parser.add_argument("--reviewed-by", default="", help="Analyst identifier")
    approve_action_parser.add_argument("--dry-run", action="store_true", default=False,
                                        help="Show what would happen without executing")

    # ── reject ───────────────────────────────────────────────────────────────
    reject_parser = subparsers.add_parser("reject", help="Reject a pending action")
    reject_parser.add_argument("action_id")
    reject_parser.add_argument("--reviewed-by", default="", help="Analyst identifier")

    # ── rollback ─────────────────────────────────────────────────────────────
    rollback_parser = subparsers.add_parser("rollback", help="Roll back an executed action")
    rollback_parser.add_argument("action_id")
    rollback_parser.add_argument("--dry-run", action="store_true", default=False)
```

Add dispatch in the `command` switch block:

```python
    elif command == "approve":
        _cmd_approve(args, config)
    elif command == "reject":
        _cmd_reject(args, config)
    elif command == "rollback":
        asyncio.run(_cmd_rollback(args, config))
```

- [ ] **Step 2: Add command handler functions**

```python
def _cmd_approve(args, config) -> None:
    from rich.console import Console
    from rich.table import Table
    from core.approval_queue import ApprovalQueue

    console = Console()
    queue = ApprovalQueue(db_path=config.approval_db_path)
    approve_command = getattr(args, "approve_command", None)

    if approve_command == "list" or approve_command is None:
        pending = queue.list_pending()
        if not pending:
            console.print("[dim]No pending actions.[/dim]")
            return
        table = Table(title="Pending Actions", show_lines=True)
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Type", style="bold")
        table.add_column("Target")
        table.add_column("Urgency")
        table.add_column("Blast Radius")
        table.add_column("Run ID", style="dim")
        for pa in pending:
            table.add_row(
                pa.action_id[:8], pa.action_type, pa.target,
                pa.urgency, pa.blast_radius, pa.run_id[:8],
            )
        console.print(table)
        return

    if approve_command == "action":
        action_id = args.action_id
        pa = queue.get(action_id)
        if pa is None:
            console.print(f"[red]Action {action_id!r} not found.[/red]")
            return
        if pa.status != "pending":
            console.print(f"[yellow]Action is already in status '{pa.status}'; cannot approve.[/yellow]")
            return

        console.print(f"[bold]Approving:[/bold] {pa.action_type} → {pa.target}")
        console.print(f"[dim]Blast radius:[/dim] {pa.blast_radius}")

        dry_run = getattr(args, "dry_run", False)
        if dry_run:
            console.print("[yellow](dry-run) Approval recorded but action not executed.[/yellow]")
            return

        # Execute via adapter
        asyncio.run(_execute_approved_action(pa, config, queue, console))


async def _execute_approved_action(pa, config, queue, console) -> None:
    # NOTE: _compose_integration_registry is promoted to a public name
    # (compose_integration_registry) in core/app.py as part of Task 5 Step 4,
    # so it can be safely imported by CLI handlers without coupling to an internal name.
    from core.app import compose_integration_registry
    from core.schemas import ActionExecutionRequest

    registry = compose_integration_registry(config, dry_run=False)
    adapter_map = {
        "isolate_host": "defender",
        "unisolate_host": "defender",
        "disable_account": "entra",
        "enable_account": "entra",
        "revoke_sessions": "entra",
    }
    adapter_name = adapter_map.get(pa.action_type)
    adapter = registry.adapters.get(adapter_name) if adapter_name else None

    if adapter is None:
        console.print(f"[yellow]No adapter for action_type {pa.action_type!r}; marking as proposed.[/yellow]")
        queue.mark_failed(pa.action_id, error=f"No adapter available for {pa.action_type!r}")
        return

    request = ActionExecutionRequest(
        action_type=pa.action_type,
        target=pa.target,
        reason=pa.reason,
        urgency=pa.urgency,
        requested_by=getattr(pa, "reviewed_by", None) or "cli-approve",
        allow_execution=True,
        metadata=pa.rollback_data or {},
    )
    try:
        result = await adapter.execute(request)
        if result.executed:
            queue.mark_executed(pa.action_id, execution_result={
                "status": result.status,
                "external_id": result.external_id,
                "message": result.message,
                "adapter": result.adapter_name,
            })
            console.print(f"[green]✓ Executed:[/green] {pa.action_type} → {pa.target}")
        else:
            queue.mark_failed(pa.action_id, error=result.message or "adapter returned not-executed")
            console.print(f"[red]✗ Execution failed:[/red] {result.message}")
    except Exception as exc:
        queue.mark_failed(pa.action_id, error=str(exc))
        console.print(f"[red]✗ Execution error:[/red] {exc}")


def _cmd_reject(args, config) -> None:
    from rich.console import Console
    from core.approval_queue import ApprovalQueue

    console = Console()
    queue = ApprovalQueue(db_path=config.approval_db_path)
    pa = queue.get(args.action_id)
    if pa is None:
        console.print(f"[red]Action {args.action_id!r} not found.[/red]")
        return
    reviewed_by = getattr(args, "reviewed_by", "") or ""
    queue.reject(args.action_id, reviewed_by=reviewed_by)
    console.print(f"[yellow]Rejected:[/yellow] {pa.action_type} → {pa.target}")


async def _cmd_rollback(args, config) -> None:
    from rich.console import Console
    from core.approval_queue import ApprovalQueue

    console = Console()
    queue = ApprovalQueue(db_path=config.approval_db_path)
    pa = queue.get(args.action_id)
    if pa is None:
        console.print(f"[red]Action {args.action_id!r} not found.[/red]")
        return
    if pa.status != "executed":
        console.print(f"[yellow]Action status is '{pa.status}'; can only rollback 'executed' actions.[/yellow]")
        return
    if not pa.rollback_supported or not pa.rollback_action_type:
        console.print(f"[yellow]Action {pa.action_type!r} does not support rollback.[/yellow]")
        return

    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        console.print(f"[yellow](dry-run) Would execute {pa.rollback_action_type} → {pa.target}[/yellow]")
        return

    console.print(f"[bold]Rolling back:[/bold] {pa.action_type} → {pa.target} "
                  f"(via {pa.rollback_action_type})")
    from core.app import compose_integration_registry
    from core.schemas import ActionExecutionRequest

    registry = compose_integration_registry(config, dry_run=False)
    # Use the same explicit adapter_map as _execute_approved_action — no string-sniffing
    _rollback_adapter_map = {
        "unisolate_host": "defender",
        "enable_account": "entra",
    }
    adapter_name = _rollback_adapter_map.get(pa.rollback_action_type or "")
    adapter = registry.adapters.get(adapter_name) if adapter_name else None
    if adapter is None:
        console.print(f"[red]No adapter available for rollback action {pa.rollback_action_type!r}[/red]")
        return

    request = ActionExecutionRequest(
        action_type=pa.rollback_action_type,
        target=pa.target,
        reason=f"Rollback of {pa.action_type} on {pa.target}",
        urgency="immediate",
        requested_by="cli-rollback",
        allow_execution=True,
        metadata=pa.rollback_data or {},
    )
    try:
        result = await adapter.execute(request)
        if result.executed:
            queue.mark_rolled_back(pa.action_id)
            console.print(f"[green]✓ Rolled back:[/green] {pa.action_type} → {pa.target}")
        else:
            console.print(f"[red]✗ Rollback failed:[/red] {result.message}")
    except Exception as exc:
        console.print(f"[red]✗ Rollback error:[/red] {exc}")
```

- [ ] **Step 3: Run full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 4: Smoke test CLI commands (dry-run)**

```bash
python main.py approve list --dry-run 2>/dev/null || python main.py approve list
```

Expected: "No pending actions." or a table (if any approvals exist in the default db).

- [ ] **Step 5: Commit**

```bash
git add main.py
git commit -m "feat(gate5): add approve/reject/rollback CLI subcommands"
```
