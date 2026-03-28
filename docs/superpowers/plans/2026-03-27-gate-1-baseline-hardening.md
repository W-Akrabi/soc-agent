# Gate 1: Baseline Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix dry-run/live config parity, make mock LLM responses derive from alert context, add typed status enums and internal schemas, add an append-only JSONL event log, and extract a `core/app.py` internal layer so `main.py` becomes a thin CLI compatibility wrapper.

**Architecture:** All changes are additive or in-place refactors — no new external dependencies required. `core/schemas.py` adds typed contracts used by the app layer. `core/event_log.py` adds a per-run append-only JSONL audit trail. `core/app.py` extracts investigation orchestration from `main.py`. Config parity is fixed by `Config.for_dry_run()` which reads all non-auth env vars so dry-run honors the same paths and timeouts as live mode.

**Tech Stack:** Python 3.11+ dataclasses, `enum.Enum`, stdlib `json` (JSONL), existing `pytest` + `pytest-asyncio`. No new packages.

---

## Scope note

This plan covers Gate 1 only. Gates 2–6 (provider abstraction, Postgres, real integrations, correlation, approval queue, remote workers) are separate plans to be written after this gate is merged and green.

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/models.py` | **Modify** | Add `TaskStatus` and `ActionStatus` enums |
| `core/config.py` | **Modify** | Add `Config.for_dry_run()` and `event_log_dir` field; `SOC_EVENT_LOG_DIR` env var support |
| `core/mock_llm.py` | **Modify** | Accept alert context via `set_alert_context()`; return alert-type-specific responses |
| `core/schemas.py` | **Create** | Typed contracts: `InvestigationRun`, `InvestigationTask`, `EvidenceRecord`, `ActionProposal` |
| `core/event_log.py` | **Create** | `EventLog` class — append-only JSONL, one file per run |
| `core/app.py` | **Create** | `run_investigation(config, alert, dry_run, overrides)` and `run_watch(config, watch_dir, dry_run, overrides)` |
| `main.py` | **Modify** | Thin CLI wrapper; all investigation logic moves to `core/app.py` |
| `agents/base.py` | **Modify** | Use `TaskStatus` enum values; emit `agent_state` events to `EventLog` |
| `agents/commander.py` | **Modify** | Use `TaskStatus.QUEUED` when creating task nodes; pass `EventLog` to agents |
| `agents/remediation.py` | **Modify** | Use `ActionStatus` enum values from tool result instead of raw strings |
| `core/llm_client.py` | **Modify** | Emit `llm_call` events to `EventLog` when log is attached |
| `tests/test_models.py` | **Modify** | Add enum tests; update status-string assertions to new values |
| `tests/test_agents.py` | **Modify** | Update `"in_progress"` / `"complete"` / `"failed"` assertions to new enum values |
| `tests/test_config.py` | **Create** | Tests for `Config.for_dry_run()` env parity |
| `tests/test_schemas.py` | **Create** | Tests for schema dataclasses and field validation |
| `tests/test_event_log.py` | **Create** | Tests for append, read-back, and JSONL format |
| `tests/test_mock_llm.py` | **Create** | Tests for alert-type-aware mock responses |
| `tests/test_app.py` | **Create** | Tests for `run_investigation()` via `core/app.py` |
| `tests/test_dry_run_smoke.py` | **Create** | CLI subprocess smoke test: dry-run writes to `SOC_DB_PATH` and `SOC_REPORTS_DIR` |

---

## Task 1: Add `TaskStatus` and `ActionStatus` enums

**Files:**
- Modify: `core/models.py`
- Modify: `tests/test_models.py`

The current code scatters status strings (`"in_progress"`, `"complete"`, `"failed"`, `"suggested"`, `"executed"`) across agents. Centralizing them as enums prevents typos, makes grep-ability trivial, and is the foundation for later policy-engine work.

Mapping from old strings to new enum values:
- `"in_progress"` → `TaskStatus.RUNNING = "running"`
- `"complete"` → `TaskStatus.COMPLETED = "completed"`
- `"failed"` → `TaskStatus.FAILED = "failed"`
- `"pending"` / default `"active"` for task nodes → `TaskStatus.QUEUED = "queued"`
- `"suggested"` → `ActionStatus.PROPOSED = "proposed"`
- `"executed"` → `ActionStatus.EXECUTED = "executed"`

Non-task node statuses (`"active"`, `"rolled_back"`) are not changed in this gate — they aren't used in control flow.

- [ ] **Step 1: Write failing tests for new enums**

Add to `tests/test_models.py`:

```python
from core.models import TaskStatus, ActionStatus

def test_task_status_values():
    assert TaskStatus.QUEUED.value == "queued"
    assert TaskStatus.RUNNING.value == "running"
    assert TaskStatus.BLOCKED.value == "blocked"
    assert TaskStatus.COMPLETED.value == "completed"
    assert TaskStatus.FAILED.value == "failed"
    assert TaskStatus.CANCELLED.value == "cancelled"

def test_action_status_values():
    assert ActionStatus.PROPOSED.value == "proposed"
    assert ActionStatus.AWAITING_APPROVAL.value == "awaiting_approval"
    assert ActionStatus.APPROVED.value == "approved"
    assert ActionStatus.EXECUTING.value == "executing"
    assert ActionStatus.EXECUTED.value == "executed"
    assert ActionStatus.ROLLED_BACK.value == "rolled_back"
    assert ActionStatus.REJECTED.value == "rejected"
    assert ActionStatus.FAILED.value == "failed"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /Users/waleedakrabi/Desktop/Github-forks/soc-agent
pytest tests/test_models.py::test_task_status_values tests/test_models.py::test_action_status_values -v
```

Expected: `ImportError: cannot import name 'TaskStatus'`

- [ ] **Step 3: Add enums to `core/models.py`**

After the `Severity` enum, add:

```python
class TaskStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"
    FAILED = "failed"
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_models.py -v
```

Expected: all tests in `test_models.py` pass.

- [ ] **Step 5: Commit**

```bash
git add core/models.py tests/test_models.py
git commit -m "feat: add TaskStatus and ActionStatus enums to core/models"
```

---

## Task 2: Use `TaskStatus` and `ActionStatus` in agents

**Files:**
- Modify: `agents/base.py`
- Modify: `agents/commander.py`
- Modify: `agents/remediation.py`
- Modify: `tests/test_agents.py`

This converts the raw string calls to typed enum values. The Case Graph stores `.value` strings — the DB schema is unchanged.

- [ ] **Step 1: Update `agents/base.py`**

Replace the three `update_node_status` calls with enum values:

```python
# agents/base.py — top of file, add import
from core.models import Alert, TaskStatus

# In run():
self.graph.update_node_status(task_node_id, TaskStatus.RUNNING.value)
# ...
self.graph.update_node_status(task_node_id, TaskStatus.COMPLETED.value)
# ...on TimeoutError:
self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
# ...on Exception:
self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
```

- [ ] **Step 2: Update `agents/commander.py`**

Task nodes are created with the DB default status (`"active"`). Change the `write_node` calls to explicitly set `data` with an initial status, or pass initial status via a new `status` kwarg if you add it. Since `write_node` doesn't yet accept `status` as a param and the DB column has a `DEFAULT 'active'`, the simplest fix is adding `"status": TaskStatus.QUEUED.value` into the `data` dict of each task node write, so the status intent is readable from data even if the DB column stays `active` until `run()` transitions it.

Alternatively — preferred — add an optional `status` param to `CaseGraph.write_node()` so the initial row is written with `status = TaskStatus.QUEUED.value`. This is done here because it's small and tests it immediately.

In `core/case_graph.py`, update `write_node` signature:

```python
def write_node(self, type: str, label: str, data: dict, created_by: str,
               status: str = "active") -> str:
    node_id = str(uuid.uuid4())
    try:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nodes (id, type, label, data, status, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (node_id, type, label, json.dumps(data), status, created_by, self._now())
            )
        return node_id
    except sqlite3.Error as e:
        raise CaseGraphError(f"write_node failed: {e}") from e
```

In `agents/commander.py`, add import and pass initial status:

```python
from core.models import Alert, TaskStatus

# Each task node write becomes:
recon_task_id = self.graph.write_node(
    "task", "recon-task", {"agent": "recon"},
    self.name, status=TaskStatus.QUEUED.value
)
intel_task_id = self.graph.write_node(
    "task", "intel-task", {"agent": "threat_intel"},
    self.name, status=TaskStatus.QUEUED.value
)
forensics_task_id = self.graph.write_node(
    "task", "forensics-task", {"agent": "forensics"},
    self.name, status=TaskStatus.QUEUED.value
)
remediation_task_id = self.graph.write_node(
    "task", "remediation-task", {"agent": "remediation"},
    self.name, status=TaskStatus.QUEUED.value
)
reporter_task_id = self.graph.write_node(
    "task", "reporter-task", {"agent": "reporter"},
    self.name, status=TaskStatus.QUEUED.value
)
# Also the timeout-path reporter task in investigate():
reporter_task_id = self.graph.write_node(
    "task", "reporter-task", {"agent": "reporter"},
    self.name, status=TaskStatus.QUEUED.value
)
```

- [ ] **Step 3: Update `agents/remediation.py`**

Replace raw status strings with `ActionStatus` values. The `ActionExecutorTool` returns `{"status": "suggested"|"executed", ...}`. Map those at the call site:

```python
from core.models import Alert, ActionStatus

# After result = await self.executor.run(action):
raw_status = result["status"]
action_status = (
    ActionStatus.EXECUTED.value if raw_status == "executed"
    else ActionStatus.PROPOSED.value
)
# ... write node ...
self.graph.update_node_status(action_nodes[-1]["id"], action_status)
self.log(f"[{action_status.upper()}] ...")
```

> **Note — deferred states:** `AWAITING_APPROVAL`, `APPROVED`, `EXECUTING`, `ROLLED_BACK`, `REJECTED` are defined in the enum here but are not wired in Gate 1 because the approval queue is a Gate 5 concern. Only `PROPOSED` and `EXECUTED` are active in this gate.

- [ ] **Step 4: Run tests to find broken assertions**

```bash
pytest tests/test_agents.py tests/test_case_graph.py -v
```

Expected: some tests fail because they assert `"in_progress"`, `"complete"`, `"failed"`, `"suggested"`, `"executed"` — update those assertions to the new values (`"running"`, `"completed"`, `"failed"`, `"proposed"`, `"executed"`).

- [ ] **Step 5: Fix all assertion strings in `tests/test_agents.py`**

Search for and replace all occurrences:
- `assert.*"in_progress"` → `"running"`
- `assert.*"complete"` (task status) → `"completed"`
- `assert.*"suggested"` → `"proposed"`

Do not rename `"failed"` — the value is unchanged.

- [ ] **Step 5b: Add `write_node` status param test to `tests/test_case_graph.py`**

Find the existing test that calls `write_node` and add a variant that verifies the `status` param is persisted:

```python
def test_write_node_with_explicit_status(graph):
    node_id = graph.write_node("task", "test-task", {}, "test", status="queued")
    node = graph.get_node(node_id)
    assert node["status"] == "queued"
```

- [ ] **Step 6: Run full non-integration suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py
```

Expected: all non-integration tests pass (37 original + new test from Step 5b).

- [ ] **Step 7: Commit**

```bash
git add core/case_graph.py agents/base.py agents/commander.py agents/remediation.py tests/test_agents.py tests/test_case_graph.py
git commit -m "feat: use TaskStatus/ActionStatus enums in agents; add status param to write_node"
```

---

## Task 3: Fix dry-run config parity

**Files:**
- Modify: `core/config.py`
- Modify: `main.py`
- Create: `tests/test_config.py`

**The bug:** In `main.py` lines 50–54, dry-run hardcodes `reports_dir = "./reports"`, `agent_timeout = 30`, `commander_timeout = 120`, `base_db = "./soc_dry_run"` — completely ignoring any env vars the operator has set. If `SOC_REPORTS_DIR=/tmp/alerts/reports` is set, dry-run still writes to `./reports`.

**The fix:** Add `Config.for_dry_run()` that loads all env vars (same as `from_env()`) but does not require `ANTHROPIC_API_KEY`. Dry-run path in `main.py` calls this instead.

- [ ] **Step 1: Write failing tests**

Create `tests/test_config.py`:

```python
import os
import pytest
from unittest.mock import patch
from core.config import Config


def test_for_dry_run_uses_env_db_path():
    with patch.dict(os.environ, {"SOC_DB_PATH": "/tmp/mydb.db"}, clear=False):
        config = Config.for_dry_run()
    assert config.db_path == "/tmp/mydb.db"


def test_for_dry_run_uses_env_reports_dir():
    with patch.dict(os.environ, {"SOC_REPORTS_DIR": "/tmp/myreports"}, clear=False):
        config = Config.for_dry_run()
    assert config.reports_dir == "/tmp/myreports"


def test_for_dry_run_uses_env_timeouts():
    with patch.dict(os.environ,
                    {"SOC_COMMANDER_TIMEOUT": "600", "SOC_AGENT_TIMEOUT": "60"},
                    clear=False):
        config = Config.for_dry_run()
    assert config.commander_timeout == 600
    assert config.agent_timeout == 60


def test_for_dry_run_does_not_require_api_key():
    # Must not raise even when ANTHROPIC_API_KEY is absent
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.anthropic_api_key == ""


def test_for_dry_run_defaults_match_from_env_defaults():
    # When no env vars set, db_path default is ./soc_cases.db
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("SOC_") and k != "ANTHROPIC_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        config = Config.for_dry_run()
    assert config.db_path == "./soc_cases.db"
    assert config.reports_dir == "./reports"
    assert config.event_log_dir is None


def test_for_dry_run_uses_soc_event_log_dir():
    with patch.dict(os.environ, {"SOC_EVENT_LOG_DIR": "/tmp/logs"}, clear=False):
        config = Config.for_dry_run()
    assert config.event_log_dir == "/tmp/logs"


def test_from_env_uses_soc_event_log_dir():
    """Verify from_env() also picks up SOC_EVENT_LOG_DIR, not just for_dry_run()."""
    with patch.dict(os.environ,
                    {"ANTHROPIC_API_KEY": "sk-fake", "SOC_EVENT_LOG_DIR": "/tmp/prodlogs"},
                    clear=False):
        config = Config.from_env()
    assert config.event_log_dir == "/tmp/prodlogs"
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_config.py -v
```

Expected: `AttributeError: type object 'Config' has no attribute 'for_dry_run'`

- [ ] **Step 3: Add `event_log_dir` field and `Config.for_dry_run()` to `core/config.py`**

Add `event_log_dir: str | None = None` as an optional field on the `Config` dataclass, then add the classmethod:

```python
# Add to Config dataclass:
event_log_dir: str | None = None

@classmethod
def for_dry_run(cls) -> "Config":
    """Load all non-auth config from env. ANTHROPIC_API_KEY is not required."""
    return cls(
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        model=os.getenv("SOC_MODEL", "claude-sonnet-4-6"),
        db_path=os.getenv("SOC_DB_PATH", "./soc_cases.db"),
        reports_dir=os.getenv("SOC_REPORTS_DIR", "./reports"),
        commander_timeout=int(os.getenv("SOC_COMMANDER_TIMEOUT", "300")),
        agent_timeout=int(os.getenv("SOC_AGENT_TIMEOUT", "120")),
        auto_remediate=os.getenv("SOC_AUTO_REMEDIATE", "false").lower() == "true",
        log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
        event_log_dir=os.getenv("SOC_EVENT_LOG_DIR") or None,
    )

# Also update from_env() to load event_log_dir:
# In Config.from_env(), add to the return:
event_log_dir=os.getenv("SOC_EVENT_LOG_DIR") or None,
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
pytest tests/test_config.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 5: Fix the dry-run branch in `main.py`**

> **Note:** Task 7 will fully replace `main.py` with a cleaner version. This step applies the minimal fix to unblock the smoke test (Task 8) and the full refactor follows in Task 7.

Replace lines 47–54 (the dry-run branch):

```python
# BEFORE:
if args.dry_run:
    from core.mock_llm import MockLLMClient
    llm = MockLLMClient()
    reports_dir = "./reports"
    agent_timeout = 30
    commander_timeout = args.timeout or 120
    auto_remediate = args.auto_remediate
    base_db = "./soc_dry_run"

# AFTER:
if args.dry_run:
    from core.mock_llm import MockLLMClient
    from core.config import Config
    config = Config.for_dry_run()
    llm = MockLLMClient()
    reports_dir = config.reports_dir
    agent_timeout = config.agent_timeout
    commander_timeout = args.timeout or config.commander_timeout
    auto_remediate = args.auto_remediate or config.auto_remediate
    base_db = config.db_path.replace(".db", "") + "_dry"
```

- [ ] **Step 6: Run full non-integration suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py
```

Expected: all tests pass.

- [ ] **Step 7: Commit**

```bash
git add core/config.py main.py tests/test_config.py
git commit -m "fix: dry-run config parity — honor SOC_* env vars in dry-run mode"
```

---

## Task 4: Make `MockLLMClient` alert-context-aware

**Files:**
- Modify: `core/mock_llm.py`
- Create: `tests/test_mock_llm.py`

Currently all mock responses are hardcoded to an intrusion/Tor-exit-node scenario regardless of what alert is being investigated. This makes brute-force dry-runs produce reports about CVE-2024-1337 and port 8080, which is confusing and breaks any future eval harness.

The fix: `MockLLMClient.set_alert_context(alert)` caches key alert fields; `call()` selects from a per-alert-type response set.

- [ ] **Step 1: Write failing tests**

Create `tests/test_mock_llm.py`:

```python
import pytest
from unittest.mock import MagicMock
from core.mock_llm import MockLLMClient
from core.models import Alert, AlertType, Severity
from datetime import datetime, timezone


def _make_alert(alert_type: AlertType, source_ip="1.2.3.4", hostname="host-01",
                user_account=None) -> Alert:
    return Alert(
        id="test-id",
        type=alert_type,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip=source_ip,
        hostname=hostname,
        user_account=user_account,
    )


@pytest.mark.asyncio
async def test_mock_brute_force_response_mentions_brute_force():
    llm = MockLLMClient()
    llm.set_alert_context(_make_alert(AlertType.BRUTE_FORCE, source_ip="10.0.0.5"))
    response = await llm.call(
        system="You are a reconnaissance specialist.",
        messages=[{"role": "user", "content": "investigate"}]
    )
    lower = response.lower()
    assert "brute" in lower or "ssh" in lower or "10.0.0.5" in lower


@pytest.mark.asyncio
async def test_mock_malware_response_mentions_malware():
    llm = MockLLMClient()
    llm.set_alert_context(_make_alert(AlertType.MALWARE, hostname="workstation-99"))
    response = await llm.call(
        system="You are a reconnaissance specialist.",
        messages=[{"role": "user", "content": "investigate"}]
    )
    lower = response.lower()
    assert "malware" in lower or "beacon" in lower or "workstation-99" in lower


@pytest.mark.asyncio
async def test_mock_intrusion_response_unchanged():
    llm = MockLLMClient()
    llm.set_alert_context(_make_alert(AlertType.INTRUSION))
    response = await llm.call(
        system="You are a reconnaissance specialist.",
        messages=[{"role": "user", "content": "investigate"}]
    )
    # intrusion still returns a non-empty investigation summary
    assert len(response) > 10


@pytest.mark.asyncio
async def test_mock_without_context_still_works():
    llm = MockLLMClient()
    response = await llm.call(
        system="You are the Commander of a Security Operations Center investigation.",
        messages=[{"role": "user", "content": "{}"}]
    )
    assert "objective" in response


@pytest.mark.asyncio
async def test_same_alert_type_gives_consistent_response():
    """Same alert type → same response every call (determinism)."""
    llm = MockLLMClient()
    alert = _make_alert(AlertType.BRUTE_FORCE)
    llm.set_alert_context(alert)
    r1 = await llm.call("You are a recon specialist.", [{"role": "user", "content": "x"}])
    r2 = await llm.call("You are a recon specialist.", [{"role": "user", "content": "x"}])
    assert r1 == r2


@pytest.mark.asyncio
async def test_mock_reporter_with_context_does_not_raise():
    """Reporter branch with alert context set must not raise AttributeError.

    Regression guard for: _ctx['alert_type'] is a str, not an enum — calling .value on it raises.
    """
    llm = MockLLMClient()
    llm.set_alert_context(_make_alert(AlertType.MALWARE, hostname="ws-01"))
    response = await llm.call(
        system="You are a SOC incident reporter.",
        messages=[{"role": "user", "content": "Investigation data:\n{}"}]
    )
    assert "Incident Report" in response
    assert "malware" in response.lower()  # alert_type rendered as string, not enum repr
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_mock_llm.py -v
```

Expected: `AttributeError: 'MockLLMClient' object has no attribute 'set_alert_context'`

- [ ] **Step 3: Refactor `core/mock_llm.py`**

Replace the entire file with the following structure. Keep all existing response content for INTRUSION. Add MALWARE, BRUTE_FORCE, DATA_EXFILTRATION, and ANOMALY sets. Context-select in `call()`.

```python
from core.models import AlertType

# --- Per-alert-type response sets ---

_RESPONSES_INTRUSION = {
    "commander": '{"objective": "Investigate suspicious external IP exploiting web service on port 8080", "priority_agents": ["recon", "threat_intel", "forensics"]}',
    "recon": (
        "Reconnaissance complete. Source IP 185.220.101.45 is a known Tor exit node (ASN AS60117, RU) "
        "with ports 22, 80, and 8080 open. Destination host 10.0.1.50 is an internal web server. "
        "The connection pattern is consistent with an automated exploit attempt."
    ),
    "threat_intel": (
        "CVE-2024-1337 (CVSS 9.8) matches the HTTP service on port 8080 — a critical RCE vulnerability "
        "in popular web frameworks. The source IP 185.220.101.45 appears in threat feeds with 95% "
        "confidence as a Tor exit node used for scanning and exploitation."
    ),
    "forensics": (
        "Attack timeline reconstructed from 5 log events:\n"
        "1. 03:12:01 — Initial connection from 185.220.101.45 to port 8080\n"
        "2. 03:12:03 — Exploit payload sent targeting CVE-2024-1337\n"
        "3. 03:12:05 — Shell spawned under nginx (initial access confirmed)\n"
        "4. 03:14:10 — Privilege escalation to root\n"
        "5. 03:19:22 — Data staged at /tmp/.exfil (52 KB)\n"
    ),
    "remediation": (
        '[{"action_type": "block_ip", "target": "185.220.101.45", "reason": "Known Tor exit node, confirmed exploit source", "urgency": "immediate"}, '
        '{"action_type": "isolate_host", "target": "web-prod-01", "reason": "Host compromised, root shell confirmed", "urgency": "immediate"}, '
        '{"action_type": "patch_recommendation", "target": "CVE-2024-1337", "reason": "Exploited in this incident", "urgency": "within_24h"}]'
    ),
}

_RESPONSES_MALWARE = {
    "commander": '{"objective": "Investigate malware beacon activity to external C2 server", "priority_agents": ["recon", "threat_intel", "forensics"]}',
    "recon": (
        "Recon complete. Source host {hostname} is an internal Windows workstation. "
        "Outbound connection to {source_ip} on port 443 — external IP resolves to a known bulletproof hosting AS. "
        "Port 443 open with self-signed TLS certificate, no legitimate business registration."
    ),
    "threat_intel": (
        "Source IP {source_ip} flagged in multiple threat feeds as Cobalt Strike C2 infrastructure (confidence 89%). "
        "File hash matches known AgentTesla stealer variant. CVE-2023-0950 may be relevant to the initial dropper. "
        "Campaign attributed to financially motivated threat actor TA505."
    ),
    "forensics": (
        "Malware timeline from beacon logs:\n"
        "1. T+0 — Malicious document opened on {hostname}\n"
        "2. T+2m — PowerShell spawned via WMI (LOLBin execution)\n"
        "3. T+4m — Beacon installed in %APPDATA%, persistence via Run key\n"
        "4. T+6m — First C2 checkin to {source_ip}:443\n"
        "5. T+12m — Credential dumping activity detected (LSASS access)\n"
    ),
    "remediation": (
        '[{{"action_type": "isolate_host", "target": "{hostname}", "reason": "Active malware beacon, credential access detected", "urgency": "immediate"}}, '
        '{{"action_type": "block_ip", "target": "{source_ip}", "reason": "Confirmed C2 server", "urgency": "immediate"}}, '
        '{{"action_type": "disable_account", "target": "{user_account}", "reason": "Credentials likely compromised via beacon", "urgency": "within_24h"}}]'
    ),
}

_RESPONSES_BRUTE_FORCE = {
    "commander": '{"objective": "Investigate SSH brute-force attack from external IP targeting bastion host", "priority_agents": ["recon", "threat_intel", "forensics"]}',
    "recon": (
        "Recon complete. Source IP {source_ip} is a residential broadband address with no business registration. "
        "Target host {hostname} has port 22 (SSH) exposed publicly. "
        "247 failed authentication attempts detected from source in the last 10 minutes — automated brute force confirmed."
    ),
    "threat_intel": (
        "Source IP {source_ip} has low abuse confidence score (23%) but appears in SSH scanner lists. "
        "No CVEs directly applicable. The attack pattern matches credential-stuffing tooling (Hydra/Medusa signature). "
        "No known threat actor attribution — likely opportunistic scanner."
    ),
    "forensics": (
        "Brute-force timeline:\n"
        "1. T+0 — First SSH authentication attempt to {hostname}\n"
        "2. T+1m — 50 failed attempts across multiple usernames (admin, root, ubuntu)\n"
        "3. T+4m — 200+ attempts, rate increasing — automated tool confirmed\n"
        "4. T+9m — Attempt targeting account '{user_account}' (valid username)\n"
        "5. T+10m — No successful authentication; host lockout policy triggered\n"
    ),
    "remediation": (
        '[{{"action_type": "block_ip", "target": "{source_ip}", "reason": "Active SSH brute force source", "urgency": "immediate"}}, '
        '{{"action_type": "patch_recommendation", "target": "{hostname}", "reason": "Restrict SSH to VPN/allowlist; enforce MFA", "urgency": "within_24h"}}]'
    ),
}

_RESPONSES_DATA_EXFILTRATION = {
    "commander": '{"objective": "Investigate large outbound data transfer consistent with exfiltration", "priority_agents": ["recon", "threat_intel", "forensics"]}',
    "recon": (
        "Recon complete. Source host {hostname} ({source_ip}) initiated 2.4 GB outbound transfer to external IP over port 443. "
        "Destination is a cloud storage endpoint (AS registered to file-sharing service). "
        "Transfer volume is 40x the host's normal daily egress baseline."
    ),
    "threat_intel": (
        "Destination IP {source_ip} associated with legitimate cloud provider but used in known data-staging campaigns. "
        "No direct CVE match. DLP telemetry indicates transfer contained file types matching source code and credentials. "
        "Consistent with insider threat or compromised account exfiltration TTP."
    ),
    "forensics": (
        "Exfiltration timeline:\n"
        "1. T-30m — Account '{user_account}' logged in from unusual geolocation\n"
        "2. T-20m — Bulk file access across sensitive shares (5,000 files in 10 min)\n"
        "3. T-10m — Archive created in %TEMP%\n"
        "4. T+0 — Upload initiated to external endpoint\n"
        "5. T+12m — 2.4 GB transfer complete; session terminated\n"
    ),
    "remediation": (
        '[{{"action_type": "disable_account", "target": "{user_account}", "reason": "Account performed anomalous bulk data access and exfiltration", "urgency": "immediate"}}, '
        '{{"action_type": "isolate_host", "target": "{hostname}", "reason": "Source of exfiltration; may have active session", "urgency": "immediate"}}, '
        '{{"action_type": "block_ip", "target": "{source_ip}", "reason": "Exfiltration destination", "urgency": "within_24h"}}]'
    ),
}

_RESPONSES_ANOMALY = {
    "commander": '{"objective": "Investigate anomalous process and network behavior on internal host", "priority_agents": ["recon", "threat_intel", "forensics"]}',
    "recon": (
        "Recon complete. Host {hostname} shows process spawning behavior significantly outside its baseline. "
        "Outbound connections to {source_ip} on non-standard ports (4444, 8443). "
        "Host is a database server — outbound internet access is not expected."
    ),
    "threat_intel": (
        "IP {source_ip} has moderate reputation score; associated with penetration testing tools in some feeds. "
        "Process spawn pattern (cmd.exe spawned from java.exe) matches post-exploitation frameworks. "
        "Cannot confirm threat actor attribution without additional artifacts."
    ),
    "forensics": (
        "Anomaly timeline:\n"
        "1. T-2h — Baseline deviation alert triggered on {hostname}\n"
        "2. T-1h30m — New scheduled task created (persistence indicator)\n"
        "3. T-30m — java.exe spawned cmd.exe and powershell.exe (abnormal)\n"
        "4. T-10m — Outbound connection to {source_ip}:4444 established\n"
        "5. T+0 — Alert escalated by EDR on command execution pattern\n"
    ),
    "remediation": (
        '[{{"action_type": "isolate_host", "target": "{hostname}", "reason": "Post-exploitation indicators; unexpected outbound C2 traffic", "urgency": "immediate"}}, '
        '{{"action_type": "block_ip", "target": "{source_ip}", "reason": "Suspected C2 endpoint", "urgency": "immediate"}}]'
    ),
}

_RESPONSES_BY_TYPE = {
    AlertType.INTRUSION: _RESPONSES_INTRUSION,
    AlertType.MALWARE: _RESPONSES_MALWARE,
    AlertType.BRUTE_FORCE: _RESPONSES_BRUTE_FORCE,
    AlertType.DATA_EXFILTRATION: _RESPONSES_DATA_EXFILTRATION,
    AlertType.ANOMALY: _RESPONSES_ANOMALY,
}

_REPORTER_TEMPLATE = """\
# Incident Report

**Severity:** {severity_upper}
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Alert Type:** {alert_type}
**Investigation Status:** Complete (Dry Run)

---

## Executive Summary

A {alert_type} alert was detected involving host {hostname} and external IP {source_ip}. \
Specialist agents completed investigation phases: recon, threat intel, forensics, and remediation. \
This report was generated in dry-run mode using synthetic responses.

---

## Recommended Next Steps

1. Review the evidence nodes in the case graph for this investigation
2. Action any PROPOSED remediation items with appropriate approvals
3. Follow up with affected asset owners

"""


class MockLLMClient:
    """Alert-context-aware mock LLM. No API key required. Responses derive from alert type."""

    def __init__(self):
        self.model = "mock"
        self._ctx: dict = {}
        self._alert_type = AlertType.INTRUSION  # default; overridden by set_alert_context()

    def set_alert_context(self, alert) -> None:
        """Call this before running investigation so responses match the alert type."""
        self._alert_type = alert.type  # kept as enum for _responses() lookup
        self._ctx = {
            "alert_type": alert.type.value,  # string for template substitution
            "source_ip": alert.source_ip or "unknown",
            "hostname": alert.hostname or "unknown-host",
            "user_account": alert.user_account or "unknown-user",
            "severity": alert.severity.value,
            "alert_id": alert.id[:8],
        }

    def _responses(self) -> dict:
        alert_type = getattr(self, "_alert_type", AlertType.INTRUSION)
        return _RESPONSES_BY_TYPE.get(alert_type, _RESPONSES_INTRUSION)

    def _fill(self, template: str) -> str:
        """Substitute context fields into template strings."""
        try:
            return template.format(**self._ctx)
        except (KeyError, ValueError):
            return template

    async def call(self, system: str, messages: list[dict],
                   tools: list[dict] = None, max_tokens: int = 4096) -> str:
        system_lower = system.lower()
        responses = self._responses()

        if "you are the commander" in system_lower:
            return self._fill(responses["commander"])
        elif "you are a reconnaissance" in system_lower:
            return self._fill(responses["recon"])
        elif "you are a threat intelligence" in system_lower:
            return self._fill(responses["threat_intel"])
        elif "you are a digital forensics" in system_lower:
            return self._fill(responses["forensics"])
        elif "you are a soc remediation" in system_lower:
            return self._fill(responses["remediation"])
        elif "you are a soc incident reporter" in system_lower:
            import json
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            alert_id = self._ctx.get("alert_id", "dry-run")
            try:
                content = messages[-1]["content"]
                data = json.loads(content.split("Investigation data:\n", 1)[-1])
                alert_id = data.get("alert_id", alert_id)[:8]
            except Exception:
                pass
            return _REPORTER_TEMPLATE.format(
                alert_id=alert_id,
                timestamp=ts,
                alert_type=self._ctx.get("alert_type", "unknown"),  # already a str (stored as .value)
                severity_upper=self._ctx.get("severity", "unknown").upper(),
                hostname=self._ctx.get("hostname", "unknown"),
                source_ip=self._ctx.get("source_ip", "unknown"),
            )
        return "No findings."
```

- [ ] **Step 4: Run mock LLM tests**

```bash
pytest tests/test_mock_llm.py -v
```

Expected: all 6 tests pass.

- [ ] **Step 5: Run full non-integration suite to check for regressions**

```bash
pytest tests/ -v --ignore=tests/test_integration.py
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add core/mock_llm.py tests/test_mock_llm.py
git commit -m "feat: alert-context-aware MockLLMClient with per-type response sets"
```

---

## Task 5: Add typed internal schemas

**Files:**
- Create: `core/schemas.py`
- Create: `tests/test_schemas.py`

These typed dataclasses are the foundation for Gate 2's planner and Gate 5's approval queue. In Gate 1 we define and test them; integration into agents happens in Task 7.

- [ ] **Step 1: Write failing tests**

Create `tests/test_schemas.py`:

```python
from dataclasses import fields
from core.schemas import InvestigationRun, InvestigationTask, EvidenceRecord, ActionProposal
from core.models import TaskStatus, ActionStatus


def test_investigation_run_has_required_fields():
    required = {f.name for f in fields(InvestigationRun)}
    assert "run_id" in required
    assert "alert_id" in required
    assert "started_at" in required
    assert "db_path" in required
    assert "reports_dir" in required
    assert "dry_run" in required


def test_investigation_task_has_required_fields():
    required = {f.name for f in fields(InvestigationTask)}
    assert "task_id" in required
    assert "agent_name" in required
    assert "node_id" in required
    assert "status" in required


def test_evidence_record_has_required_fields():
    required = {f.name for f in fields(EvidenceRecord)}
    assert "evidence_id" in required
    assert "source_agent" in required
    assert "data" in required


def test_action_proposal_has_required_fields():
    required = {f.name for f in fields(ActionProposal)}
    assert "action_id" in required
    assert "action_type" in required
    assert "target" in required
    assert "urgency" in required
    assert "status" in required


def test_investigation_run_instantiation():
    from datetime import datetime, timezone
    run = InvestigationRun(
        run_id="r1",
        alert_id="a1",
        started_at=datetime.now(timezone.utc),
        db_path="/tmp/test.db",
        reports_dir="/tmp/reports",
        dry_run=True,
    )
    assert run.dry_run is True


def test_action_proposal_default_status():
    prop = ActionProposal(
        action_id="x1",
        action_type="block_ip",
        target="1.2.3.4",
        reason="test",
        urgency="immediate",
    )
    assert prop.status == ActionStatus.PROPOSED
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_schemas.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.schemas'`

- [ ] **Step 3: Create `core/schemas.py`**

```python
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.models import TaskStatus, ActionStatus


@dataclass
class InvestigationRun:
    run_id: str
    alert_id: str
    started_at: datetime
    db_path: str
    reports_dir: str
    dry_run: bool
    completed_at: datetime | None = None
    report_path: str | None = None


@dataclass
class InvestigationTask:
    task_id: str
    agent_name: str
    node_id: str
    status: TaskStatus = TaskStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


@dataclass
class EvidenceRecord:
    evidence_id: str
    source_agent: str
    data: dict[str, Any]
    node_id: str | None = None
    confidence: float | None = None


@dataclass
class ActionProposal:
    action_id: str
    action_type: str
    target: str
    reason: str
    urgency: str
    status: ActionStatus = ActionStatus.PROPOSED
    node_id: str | None = None
    blast_radius: str | None = None


def validate_action_proposals(raw_json: str) -> list["ActionProposal"]:
    """Parse and validate LLM-returned action JSON before any action is executed.

    Raises ValueError if the input is not a JSON array or if any item is missing
    required fields (action_type, target, reason, urgency).
    This is the schema-validation gate for LLM control-flow artifacts.
    """
    import json as _json
    import uuid
    try:
        items = _json.loads(raw_json)
    except _json.JSONDecodeError as e:
        raise ValueError(f"Action proposals JSON is invalid: {e}") from e
    if not isinstance(items, list):
        raise ValueError(f"Expected a JSON array, got {type(items).__name__}")
    proposals = []
    for i, item in enumerate(items):
        for field in ("action_type", "target", "reason", "urgency"):
            if field not in item:
                raise ValueError(f"Action proposal[{i}] missing required field '{field}'")
        proposals.append(ActionProposal(
            action_id=str(uuid.uuid4()),
            action_type=item["action_type"],
            target=item["target"],
            reason=item["reason"],
            urgency=item["urgency"],
        ))
    return proposals
```

- [ ] **Step 4: Add validation tests to `tests/test_schemas.py`**

Add these tests to the existing file:

```python
from core.schemas import validate_action_proposals


def test_validate_action_proposals_happy_path():
    raw = '[{"action_type": "block_ip", "target": "1.2.3.4", "reason": "scanner", "urgency": "immediate"}]'
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].action_type == "block_ip"
    assert proposals[0].target == "1.2.3.4"


def test_validate_action_proposals_rejects_non_array():
    import pytest
    with pytest.raises(ValueError, match="JSON array"):
        validate_action_proposals('{"action_type": "block_ip"}')


def test_validate_action_proposals_rejects_missing_field():
    import pytest
    raw = '[{"action_type": "block_ip", "target": "1.2.3.4", "urgency": "immediate"}]'
    with pytest.raises(ValueError, match="reason"):
        validate_action_proposals(raw)


def test_validate_action_proposals_rejects_invalid_json():
    import pytest
    with pytest.raises(ValueError, match="invalid"):
        validate_action_proposals("not json at all")
```

- [ ] **Step 5: Wire `validate_action_proposals` into `agents/remediation.py`**

Replace the raw `json.loads(raw)` + `isinstance` check with the validated path:

```python
from core.schemas import validate_action_proposals

# In _run(), replace:
try:
    actions = json.loads(raw)
    if not isinstance(actions, list):
        actions = []
except json.JSONDecodeError:
    self.log("Could not parse actions from LLM response", style="yellow")
    actions = []

# With:
try:
    proposals = validate_action_proposals(raw)
except ValueError as e:
    self.log(f"Action validation failed: {e}", style="yellow")
    proposals = []

# Then iterate proposals instead of actions:
for proposal in proposals:
    action = {
        "action_type": proposal.action_type,
        "target": proposal.target,
        "reason": proposal.reason,
        "urgency": proposal.urgency,
    }
    result = await self.executor.run(action)
    ...
```

- [ ] **Step 6: Run tests**

```bash
pytest tests/test_schemas.py -v
```

Expected: all 10 tests pass (6 original + 4 new validation tests).

- [ ] **Step 7: Commit**

```bash
git add core/schemas.py tests/test_schemas.py agents/remediation.py
git commit -m "feat: add typed internal schemas (InvestigationRun, InvestigationTask, EvidenceRecord, ActionProposal); add validate_action_proposals with schema enforcement"
```

---

## Task 6: Add append-only event log

**Files:**
- Create: `core/event_log.py`
- Create: `tests/test_event_log.py`

Every LLM call, tool call, and agent state transition is appended as a JSONL entry to a per-run file. This is the audit trail required for replay in Gate 4.

- [ ] **Step 1: Write failing tests**

Create `tests/test_event_log.py`:

```python
import json
import pytest
from pathlib import Path
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
    entries = (tmp_path / "run-2.jsonl").read_text().strip().splitlines()
    assert len(entries) == 2
    parsed = [json.loads(e) for e in entries]
    assert parsed[0]["event_type"] == "llm_call"
    assert parsed[1]["event_type"] == "tool_call"


def test_event_log_entry_has_timestamp(tmp_path):
    log = EventLog(run_id="run-3", log_dir=str(tmp_path))
    log.append("agent_state", agent="recon", data={})
    entry = json.loads((tmp_path / "run-3.jsonl").read_text().strip())
    assert "timestamp" in entry
    assert "run_id" in entry
    assert entry["run_id"] == "run-3"


def test_event_log_is_append_only(tmp_path):
    log = EventLog(run_id="run-4", log_dir=str(tmp_path))
    for i in range(5):
        log.append("agent_state", agent="test", data={"i": i})
    entries = (tmp_path / "run-4.jsonl").read_text().strip().splitlines()
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
    """EventLog with log_dir=None must not raise and must not create files."""
    log = EventLog(run_id="run-6", log_dir=None)
    log.append("agent_state", agent="test", data={})
    assert not any(tmp_path.iterdir())
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_event_log.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.event_log'`

- [ ] **Step 3: Create `core/event_log.py`**

```python
import json
from datetime import datetime, timezone
from pathlib import Path


class EventLog:
    """Append-only JSONL event log for one investigation run.

    Each entry: {"timestamp": ISO, "run_id": str, "event_type": str, "agent": str, "data": dict}

    Pass log_dir=None to create a no-op log (useful when logging is not configured).
    """

    def __init__(self, run_id: str, log_dir: str | None):
        self.run_id = run_id
        self._path: Path | None = None
        if log_dir is not None:
            self._path = Path(log_dir) / f"{run_id}.jsonl"
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, agent: str, data: dict) -> None:
        if self._path is None:
            return
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event_type": event_type,
            "agent": agent,
            "data": data,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def read_all(self) -> list[dict]:
        if self._path is None or not self._path.exists():
            return []
        return [json.loads(line) for line in self._path.read_text().splitlines() if line.strip()]
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_event_log.py -v
```

Expected: all 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/event_log.py tests/test_event_log.py
git commit -m "feat: add append-only JSONL EventLog for per-run audit trail"
```

---

## Task 7: Extract `core/app.py` and wire event log into agents

**Files:**
- Create: `core/app.py`
- Modify: `core/llm_client.py`
- Modify: `agents/base.py`
- Modify: `agents/commander.py`
- Modify: `main.py`
- Create: `tests/test_app.py`

`core/app.py` becomes the single place that assembles config + LLM + graph + event log into a Commander and runs it. `main.py` becomes a thin CLI wrapper. The event log is wired to `AgentBase` and `LLMClient` so every state transition and LLM call is recorded.

- [ ] **Step 1: Write failing test for `core/app.py`**

Create `tests/test_app.py`:

```python
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.app import run_investigation
from core.models import Alert, AlertType, Severity
from datetime import datetime, timezone


def _make_alert():
    return Alert(
        id="test-app-id",
        type=AlertType.BRUTE_FORCE,
        severity=Severity.MEDIUM,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="10.1.2.3",
        hostname="bastion-01",
    )


@pytest.mark.asyncio
async def test_run_investigation_returns_investigation_run(tmp_path):
    from core.config import Config
    config = Config.for_dry_run()
    config = Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
    )
    alert = _make_alert()
    result = await run_investigation(config=config, alert=alert, dry_run=True)
    from core.schemas import InvestigationRun
    assert isinstance(result, InvestigationRun)
    assert result.alert_id == alert.id
    assert result.dry_run is True


@pytest.mark.asyncio
async def test_run_investigation_creates_report_file(tmp_path):
    from core.config import Config
    config = Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
    )
    alert = _make_alert()
    result = await run_investigation(config=config, alert=alert, dry_run=True)
    import pathlib
    reports = list(pathlib.Path(config.reports_dir).glob("*.md"))
    assert len(reports) >= 1


@pytest.mark.asyncio
async def test_run_investigation_creates_event_log(tmp_path):
    from core.config import Config
    config = Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
    )
    alert = _make_alert()
    result = await run_investigation(config=config, alert=alert, dry_run=True,
                                     event_log_dir=str(tmp_path / "logs"))
    import pathlib
    logs = list(pathlib.Path(tmp_path / "logs").glob("*.jsonl"))
    assert len(logs) == 1
    from core.event_log import EventLog
    log = EventLog(run_id=result.run_id, log_dir=str(tmp_path / "logs"))
    entries = log.read_all()
    assert len(entries) > 0
    event_types = {e["event_type"] for e in entries}
    assert "agent_state" in event_types
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
pytest tests/test_app.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.app'`

- [ ] **Step 3: Add `EventLog` attachment to `LLMClient`**

In `core/llm_client.py`, add an optional event log attachment:

```python
# Add to LLMClient.__init__:
self._event_log = None

def attach_event_log(self, event_log) -> None:
    self._event_log = event_log

# In call(), before returning result:
if self._event_log is not None:
    self._event_log.append("llm_call", agent="llm", data={
        "system_snippet": system[:120],
        "response_snippet": result[:120],
    })
```

- [ ] **Step 4: Add `EventLog` emission to `AgentBase`**

In `agents/base.py`, add an optional event log:

```python
# Add to AgentBase.__init__:
self._event_log = None

def attach_event_log(self, event_log) -> None:
    self._event_log = event_log

# In run(), after status updates:
# After RUNNING:
if self._event_log:
    self._event_log.append("agent_state", agent=self.name,
                           data={"status": TaskStatus.RUNNING.value, "task_node_id": task_node_id})
# After COMPLETED:
if self._event_log:
    self._event_log.append("agent_state", agent=self.name,
                           data={"status": TaskStatus.COMPLETED.value})
# After FAILED (both branches):
if self._event_log:
    self._event_log.append("agent_state", agent=self.name,
                           data={"status": TaskStatus.FAILED.value, "error": str(e) if 'e' in dir() else "timeout"})
```

- [ ] **Step 5: Create `core/app.py`**

```python
import uuid
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from core.config import Config
from core.case_graph import CaseGraph
from core.event_log import EventLog
from core.models import Alert
from core.schemas import InvestigationRun
from agents.commander import Commander


async def run_investigation(
    config: Config,
    alert: Alert,
    dry_run: bool = False,
    event_log_dir: str | None = None,
    commander_timeout_override: int | None = None,
    console: Console | None = None,
) -> InvestigationRun:
    """Run a single alert investigation. Returns InvestigationRun with result metadata."""
    if console is None:
        console = Console()

    if dry_run:
        from core.mock_llm import MockLLMClient
        llm = MockLLMClient()
        llm.set_alert_context(alert)
    else:
        from core.llm_client import LLMClient
        llm = LLMClient(api_key=config.anthropic_api_key, model=config.model)

    run_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = "_dry" if dry_run else ""
    db_path = config.db_path.replace(".db", "") + suffix + f"-{ts}-{alert.id[:8]}.db"
    Path(config.reports_dir).mkdir(parents=True, exist_ok=True)

    event_log = EventLog(run_id=run_id, log_dir=event_log_dir)
    llm.attach_event_log(event_log)

    graph = CaseGraph(db_path=db_path)
    commander_timeout = commander_timeout_override or config.commander_timeout

    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        agent_timeout=config.agent_timeout,
        commander_timeout=commander_timeout,
        auto_remediate=config.auto_remediate,
        reports_dir=config.reports_dir,
        event_log=event_log,
    )

    started_at = datetime.now(timezone.utc)
    run = InvestigationRun(
        run_id=run_id,
        alert_id=alert.id,
        started_at=started_at,
        db_path=db_path,
        reports_dir=config.reports_dir,
        dry_run=dry_run,
    )

    await commander.investigate(alert)
    run.completed_at = datetime.now(timezone.utc)
    return run
```

- [ ] **Step 6: Update `agents/commander.py` to accept and propagate `event_log`**

Add `event_log` parameter to `Commander.__init__()`:

```python
def __init__(self, case_graph, llm, console, agent_timeout=120, commander_timeout=300,
             auto_remediate=False, reports_dir="./reports", event_log=None):
    ...
    self.event_log = event_log

# In _run_phases(), after creating each agent, attach the event log:
agents_map = {
    "recon": ReconAgent(**kwargs),
    ...
}
for agent in agents_map.values():
    agent.attach_event_log(self.event_log)
```

- [ ] **Step 6b: Verify existing Commander tests still pass**

The new `event_log=None` parameter is optional — existing tests that instantiate `Commander` directly must not break.

```bash
pytest tests/test_agents.py -v
```

Expected: all agent tests pass with no `TypeError` about unexpected keyword arguments.

- [ ] **Step 7: Refactor `main.py` to use `core/app.py`**

Replace the body of `main()` with calls to `core/app.py`. All investigation logic moves out. `main.py` becomes:

```python
#!/usr/bin/env python3
import argparse
import asyncio
import sys
from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        description="SOC Agent — autonomous multi-agent security incident investigation"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--alert", help="Run once: 'simulated', or path to a JSON alert file")
    mode.add_argument("--watch", nargs="?", const="alerts/incoming", metavar="DIR",
                      help="Watch a folder for incoming alert files (default: alerts/incoming/)")
    parser.add_argument("--auto-remediate", action="store_true", default=False)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args()

    from core.config import Config
    if args.dry_run:
        config = Config.for_dry_run()
    else:
        try:
            config = Config.from_env()
        except ValueError as e:
            print(f"Configuration error: {e}", file=sys.stderr)
            sys.exit(1)

    if args.auto_remediate:
        from dataclasses import replace
        config = replace(config, auto_remediate=True)

    if args.alert:
        asyncio.run(_run_once(args.alert, config, args))
    else:
        try:
            asyncio.run(_run_watch(args.watch, config, args))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass


async def _run_once(source: str, config, args) -> None:
    from rich.console import Console
    from ingestion.loader import load_alert
    from core.app import run_investigation
    console = Console()
    try:
        alert = load_alert(source)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading alert:[/red] {e}")
        return
    await run_investigation(
        config=config,
        alert=alert,
        dry_run=args.dry_run,
        commander_timeout_override=args.timeout,
        event_log_dir=config.event_log_dir,
        console=console,
    )


async def _run_watch(watch_dir: str, config, args) -> None:
    from rich.console import Console
    from ingestion.adapters.folder_watcher import FolderWatcher
    from core.app import run_investigation
    from ui import WatchUI
    console = Console()
    watcher = FolderWatcher(watch_dir)
    model_name = "mock" if args.dry_run else config.model
    watch_ui = WatchUI(console=console, model=model_name,
                       watch_dir=watch_dir, dry_run=args.dry_run)
    watch_ui.show_banner()
    watch_ui.start_watching()
    try:
        async for alert, path in watcher.watch():
            watch_ui.alert_received(alert.type.value, alert.severity.value, path.name)
            try:
                await run_investigation(
                    config=config,
                    alert=alert,
                    dry_run=args.dry_run,
                    commander_timeout_override=args.timeout,
                    event_log_dir=config.event_log_dir,
                    console=console,
                )
                watcher.mark_processed(path)
                watch_ui.investigation_done(alert.id)
            except (KeyboardInterrupt, asyncio.CancelledError):
                watcher.mark_failed(path)
                raise
            except Exception as e:
                console.print(f"[red]Investigation failed:[/red] {e}")
                watcher.mark_failed(path)
                watch_ui.investigation_done(alert.id)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        watch_ui.stop_watching()
        console.print("\n[dim]Watcher stopped.[/dim]")


if __name__ == "__main__":
    main()
```

- [ ] **Step 8: Run tests**

```bash
pytest tests/test_app.py tests/test_event_log.py -v
```

Expected: all pass.

- [ ] **Step 9: Run full non-integration suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py
```

Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add core/app.py core/llm_client.py agents/base.py agents/commander.py main.py tests/test_app.py
git commit -m "feat: extract core/app.py; wire EventLog into agents and LLM client; main.py is now a thin wrapper"
```

---

## Task 8: Dry-run config parity smoke test

**Files:**
- Create: `tests/test_dry_run_smoke.py`

This is the regression guard the roadmap explicitly requires: "Add one CLI smoke test for dry-run using temp outputs specifically to prevent the current config-parity bug from recurring."

This test runs `python main.py --alert simulated --dry-run` as a subprocess with custom `SOC_DB_PATH` and `SOC_REPORTS_DIR` env vars set to temp dirs, then asserts files land there — not in the repo root.

> **Test classification:** These are slow subprocess tests. They are marked `@pytest.mark.slow` and are NOT counted in the 37-test non-integration baseline. Run them separately with `pytest -m slow` or include them in a dedicated CI job. The 37-test suite remains fast and API-key-free. To keep the subprocess timeout safe, the smoke test env sets `SOC_AGENT_TIMEOUT=5` and `SOC_COMMANDER_TIMEOUT=45`.

- [ ] **Step 1: Write the smoke test**

Create `tests/test_dry_run_smoke.py`:

```python
"""
Smoke test: dry-run must write DB and report to env-configured paths,
not hardcoded repo-root defaults.

Regression guard for: https://github.com/<org>/soc-agent/issues/N
  dry-run was ignoring SOC_DB_PATH / SOC_REPORTS_DIR env vars.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


@pytest.mark.slow
def test_dry_run_honors_soc_db_path(tmp_path):
    db_dir = tmp_path / "db"
    reports_dir = tmp_path / "reports"
    db_dir.mkdir()
    reports_dir.mkdir()

    env = {
        **os.environ,
        "SOC_DB_PATH": str(db_dir / "mytest.db"),
        "SOC_REPORTS_DIR": str(reports_dir),
        # Remove real API key to prove dry-run doesn't need it
        "ANTHROPIC_API_KEY": "",
        # Keep timeouts tight so the subprocess finishes quickly
        "SOC_AGENT_TIMEOUT": "5",
        "SOC_COMMANDER_TIMEOUT": "45",
    }

    result = subprocess.run(
        [sys.executable, "main.py", "--alert", "simulated", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        cwd=Path(__file__).parent.parent,  # repo root
        timeout=90,
    )

    assert result.returncode == 0, (
        f"dry-run exited non-zero.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    # DB must be written under SOC_DB_PATH prefix, not in repo root
    db_files = list(db_dir.glob("*.db"))
    assert len(db_files) >= 1, (
        f"No .db files found under {db_dir}. "
        f"Dry-run likely wrote to repo root instead.\n"
        f"STDOUT:\n{result.stdout}"
    )

    # Report must be written under SOC_REPORTS_DIR, not ./reports
    report_files = list(reports_dir.glob("*.md"))
    assert len(report_files) >= 1, (
        f"No .md files found under {reports_dir}. "
        f"Dry-run likely wrote reports to ./reports instead.\n"
        f"STDOUT:\n{result.stdout}"
    )


@pytest.mark.slow
def test_dry_run_does_not_write_to_repo_root(tmp_path):
    """Confirm no .db files land in the repo root during dry-run with custom paths."""
    db_dir = tmp_path / "db"
    reports_dir = tmp_path / "reports"
    db_dir.mkdir()
    reports_dir.mkdir()

    repo_root = Path(__file__).parent.parent
    db_files_before = set(repo_root.glob("*.db"))

    env = {
        **os.environ,
        "SOC_DB_PATH": str(db_dir / "mytest.db"),
        "SOC_REPORTS_DIR": str(reports_dir),
        "ANTHROPIC_API_KEY": "",
        "SOC_AGENT_TIMEOUT": "5",
        "SOC_COMMANDER_TIMEOUT": "45",
    }

    subprocess.run(
        [sys.executable, "main.py", "--alert", "simulated", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo_root,
        timeout=90,
    )

    db_files_after = set(repo_root.glob("*.db"))
    new_db_files = db_files_after - db_files_before
    assert len(new_db_files) == 0, (
        f"Dry-run wrote unexpected .db files to repo root: {new_db_files}"
    )
```

- [ ] **Step 2: Register the `slow` marker in `pytest.ini`**

Add to `pytest.ini`:

```ini
[pytest]
asyncio_mode = auto
markers =
    slow: subprocess / integration tests that launch the full CLI (run with -m slow)
```

- [ ] **Step 3: Run the smoke test**

```bash
pytest tests/test_dry_run_smoke.py -v -s -m slow
```

Expected: both tests pass. (If config parity fix from Task 3 is in place, they should pass immediately.)

- [ ] **Step 4: Run the fast non-integration suite (smoke tests excluded)**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all fast tests pass. This count must be ≥ 37 (original baseline) + new unit tests added in this gate.

- [ ] **Step 5: Commit**

```bash
git add tests/test_dry_run_smoke.py pytest.ini
git commit -m "test: add CLI smoke test for dry-run config parity (regression guard); register slow marker"
```

---

## Gate 1 Complete — Verification Checklist

Before declaring Gate 1 done:

- [ ] All non-integration tests pass: `pytest tests/ --ignore=tests/test_integration.py`
- [ ] No `.db` or `.md` files leak to repo root during dry-run smoke test
- [ ] `python main.py --alert simulated --dry-run` completes without error when `ANTHROPIC_API_KEY` is unset
- [ ] `python main.py --alert simulated --dry-run` with `SOC_REPORTS_DIR=/tmp/x` creates reports in `/tmp/x`
- [ ] `python main.py --alert alerts/sample_intrusion.json --dry-run` completes
- [ ] `core/event_log.py` exists and `EventLog.read_all()` returns entries after a dry-run investigation

---

## Next: Gate 2

After this gate is merged and green, write `docs/superpowers/plans/2026-03-27-gate-2-platform-core.md` covering:
- Multi-provider model adapter (Anthropic, OpenAI, Ollama)
- Storage abstraction (SQLite backend + Postgres backend interface)
- Postgres + pgvector migration
- Task-graph planner replacing fixed phase runner
- Per-alert-type task DAGs
- Scheduler with concurrency, retries, and early-stop on confidence threshold
