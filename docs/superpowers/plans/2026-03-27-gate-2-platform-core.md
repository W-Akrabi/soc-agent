# Gate 2: Platform Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the remaining MVP-era single-provider, single-backend, fixed-phase architecture with a platform core that supports multiple model providers, pluggable storage backends, PostgreSQL + `pgvector`, and dynamic task planning/scheduling per alert type.

**Architecture:** Gate 1 created the seams needed for this work: `core/app.py` now owns orchestration, `core/schemas.py` defines typed internal contracts, and `core/event_log.py` provides an audit trail. Gate 2 builds on those seams rather than bypassing them. The guiding rule is additive replacement: keep the current CLI behavior working while moving internals behind abstractions.

**Tech Stack:** Python 3.11+, stdlib dataclasses/protocol-style interfaces, existing `pytest` + `pytest-asyncio`, `httpx`, and the current Anthropic client. New dependencies are allowed only where they are required for Postgres and vector support in this gate.

---

## Scope note

This plan covers Gate 2 only:
- Multi-provider model adapter (Anthropic, OpenAI, Ollama)
- Storage abstraction (SQLite backend + Postgres backend interface)
- Postgres + `pgvector` migration
- Task-graph planner replacing fixed phase runner
- Per-alert-type task DAGs
- Scheduler with concurrency, retries, and early-stop on confidence threshold

It does **not** cover real external integrations, approval queues, correlation memory, or remote workers. Those remain later gates.

---

## Design decisions locked for this gate

- `core/app.py` remains the public internal composition root.
- `main.py` remains a thin CLI compatibility wrapper.
- SQLite stays supported for local dev and tests.
- Postgres becomes the production backend, but not the only backend.
- The planner produces typed task definitions; it does not directly execute agents.
- The scheduler owns concurrency, retries, timeout policy, and early-stop policy.
- The existing specialist agents remain in place for this gate. The planner decides **when** to run them, not what they fundamentally are.
- Confidence-based early stop is advisory and scoped:
  - if a plan reaches a configured confidence threshold and no unresolved mandatory tasks remain, the scheduler may skip optional downstream tasks and proceed to reporting
  - mandatory tasks for the alert type must still run unless explicitly marked skippable by the planner

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/config.py` | **Modify** | Add provider/backend config and planner/scheduler settings |
| `core/app.py` | **Modify** | Compose provider adapter, storage backend, planner, scheduler |
| `core/schemas.py` | **Modify** | Add planner/scheduler/storage contracts |
| `core/models.py` | **Modify** | Add planner-related enums if needed |
| `core/llm_client.py` | **Refactor** | Become Anthropic adapter under provider abstraction |
| `core/providers.py` | **Create** | Provider interfaces and provider factory |
| `core/providers/anthropic_provider.py` | **Create** | Anthropic adapter |
| `core/providers/openai_provider.py` | **Create** | OpenAI-compatible adapter |
| `core/providers/ollama_provider.py` | **Create** | Ollama adapter |
| `core/storage.py` | **Create** | Storage backend interface and backend factory |
| `core/storage_sqlite.py` | **Create** | SQLite backend implementation using existing graph schema concepts |
| `core/storage_postgres.py` | **Create** | Postgres backend implementation |
| `core/storage_migrations.py` | **Create** | Postgres schema/bootstrap helpers including `pgvector` |
| `core/planner.py` | **Create** | Task-graph planner and alert-type plan templates |
| `core/scheduler.py` | **Create** | DAG scheduler, retry policy, timeout handling, early-stop logic |
| `agents/commander.py` | **Refactor** | Stop owning fixed phase sequencing; delegate to planner/scheduler |
| `tests/test_config.py` | **Modify** | Provider/backend config coverage |
| `tests/test_app.py` | **Modify** | App wiring via provider/storage/planner/scheduler |
| `tests/test_llm_client.py` | **Refactor** | Move Anthropic-specific tests under provider tests |
| `tests/test_providers.py` | **Create** | Provider contract tests |
| `tests/test_storage.py` | **Create** | Storage backend parity tests |
| `tests/test_postgres_storage.py` | **Create** | Postgres backend tests, guarded by environment or docker availability |
| `tests/test_planner.py` | **Create** | Alert-type DAG generation tests |
| `tests/test_scheduler.py` | **Create** | Concurrency/retry/early-stop tests |
| `tests/test_commander.py` | **Create** | Commander-to-scheduler delegation tests |

---

## Contracts introduced in Gate 2

The implementer must add these typed contracts to `core/schemas.py` or adjacent modules.

### Provider contract

```python
class ModelProvider(Protocol):
    name: str
    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> str: ...
    def attach_event_log(self, event_log) -> None: ...
```

### Storage contract

```python
class StorageBackend(Protocol):
    def write_node(self, type: str, label: str, data: dict, created_by: str, status: str = "active") -> str: ...
    def write_edge(self, src_id: str, dst_id: str, relation: str, created_by: str, data: dict | None = None) -> str: ...
    def update_node_status(self, node_id: str, status: str) -> None: ...
    def get_node(self, node_id: str) -> dict | None: ...
    def get_nodes_by_type(self, type: str) -> list[dict]: ...
    def get_neighbors(self, node_id: str, relation: str | None = None) -> list[dict]: ...
    def get_full_graph(self) -> dict: ...
    def search_nodes(self, type: str | None = None, label_contains: str | None = None, data_contains: dict | None = None) -> list[dict]: ...
```

### Planner contract

```python
@dataclass
class PlannedTask:
    task_id: str
    agent_name: str
    objective: str
    depends_on: list[str]
    optional: bool = False
    max_retries: int = 0
    timeout_override: int | None = None

@dataclass
class InvestigationPlan:
    plan_id: str
    alert_type: str
    objective: str
    tasks: list[PlannedTask]
    early_stop_threshold: float | None = None
```

### Scheduler contract

```python
@dataclass
class TaskExecutionResult:
    task_id: str
    status: str
    attempts: int
    skipped: bool = False
    error: str | None = None

@dataclass
class ScheduleResult:
    plan_id: str
    task_results: list[TaskExecutionResult]
    early_stopped: bool
```

These exact names may vary, but the split of responsibility must remain.

---

## Task 1: Introduce provider abstraction

**Files:**
- Create: `core/providers.py`
- Create: `core/providers/anthropic_provider.py`
- Create: `core/providers/openai_provider.py`
- Create: `core/providers/ollama_provider.py`
- Modify: `core/llm_client.py`
- Create: `tests/test_providers.py`

Gate 1 still binds orchestration directly to `LLMClient` or `MockLLMClient`. Gate 2 must replace that with a provider interface and a provider factory. Anthropic behavior should be preserved by moving current `LLMClient` logic into the Anthropic adapter. OpenAI and Ollama adapters must be real implementations, not placeholders, even if their tests use mocks.

- [ ] **Step 1: Write provider contract tests**

Create `tests/test_providers.py` to assert:
- Anthropic adapter returns text and supports event log attachment
- OpenAI adapter returns text from an OpenAI-compatible mocked client
- Ollama adapter returns text from an HTTP mocked response
- provider factory chooses the correct adapter from config
- unsupported provider names raise clear `ValueError`

- [ ] **Step 2: Add provider config to `core/config.py`**

Add fields:
- `provider: str`
- `provider_model: str`
- `openai_api_key: str | None = None`
- `openai_base_url: str | None = None`
- `ollama_base_url: str | None = None`

Env mapping defaults:
- `SOC_PROVIDER=anthropic`
- `SOC_MODEL` remains the model name used by the chosen provider
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`
- `OLLAMA_BASE_URL` default `http://localhost:11434`

Dry-run path continues to use `MockLLMClient`; it is not part of the provider factory.

- [ ] **Step 3: Move Anthropic logic out of `core/llm_client.py`**

Refactor:
- keep `LLMError` in a shared module or keep it in `core/llm_client.py` and import it from the Anthropic provider
- reduce `core/llm_client.py` to either a compatibility shim or shared error/helpers module
- put the actual `messages.create()` logic into `AnthropicProvider`

- [ ] **Step 4: Implement OpenAI-compatible provider**

Requirements:
- support `api_key`, `base_url`, `model`
- call chat-completions or responses API through one consistent abstraction
- use mocked tests only in this gate if live access is unavailable
- emit `llm_call` event log entries consistent with Anthropic and Mock providers

- [ ] **Step 5: Implement Ollama provider**

Requirements:
- use HTTP against Ollama’s local API
- support model selection
- emit `llm_call` event log entries
- fail clearly on connection errors

- [ ] **Step 6: Add provider factory**

Create a `build_provider(config, dry_run)` helper used by `core/app.py`.

- [ ] **Step 7: Run tests**

```bash
pytest tests/test_providers.py tests/test_config.py -v
```

Expected: provider selection and adapter tests pass.

---

## Task 2: Add storage abstraction and SQLite backend

**Files:**
- Create: `core/storage.py`
- Create: `core/storage_sqlite.py`
- Modify: `core/app.py`
- Modify: `agents/base.py`
- Modify: `agents/commander.py`
- Create: `tests/test_storage.py`

Right now everything is coupled directly to `CaseGraph`. Gate 2 must preserve that behavior behind a storage interface so Postgres can be added without rewriting all agent call sites later.

- [ ] **Step 1: Write storage parity tests**

Create `tests/test_storage.py` to assert a SQLite storage backend supports:
- write/get node
- write/get edge
- status updates
- type-based lookup
- search
- full graph retrieval

The tests should mirror the current `CaseGraph` contract closely.

- [ ] **Step 2: Create storage backend interface**

Define the `StorageBackend` contract and a `build_storage(config, db_path)` factory.

- [ ] **Step 3: Implement SQLite backend**

Requirements:
- either wrap `CaseGraph` or move its logic into `SQLiteStorageBackend`
- keep the same observable semantics as current `CaseGraph`
- keep WAL and foreign key behavior

- [ ] **Step 4: Route app composition through storage**

`core/app.py` must instantiate a storage backend instead of directly instantiating `CaseGraph`.

- [ ] **Step 5: Decouple agents/commander type hints**

Replace direct `CaseGraph` typing where needed with the storage interface or a compatible abstract type. The runtime behavior should remain unchanged.

- [ ] **Step 6: Run tests**

```bash
pytest tests/test_storage.py tests/test_agents.py tests/test_app.py -v
```

Expected: SQLite-backed behavior remains green.

---

## Task 3: Add Postgres backend and `pgvector` bootstrap

**Files:**
- Create: `core/storage_postgres.py`
- Create: `core/storage_migrations.py`
- Modify: `core/config.py`
- Create: `tests/test_postgres_storage.py`

This task adds the production backend without removing SQLite. The implementation must support running local tests without Postgres being available.

- [ ] **Step 1: Add backend config**

Add fields:
- `storage_backend: str` with default `sqlite`
- `postgres_dsn: str | None = None`
- `postgres_schema: str = "public"`
- `vector_dimensions: int = 1536`

Env mapping:
- `SOC_STORAGE_BACKEND=sqlite|postgres`
- `SOC_POSTGRES_DSN`
- `SOC_POSTGRES_SCHEMA`
- `SOC_VECTOR_DIMENSIONS`

- [ ] **Step 2: Define Postgres schema bootstrap**

Create migration/bootstrap logic that ensures:
- required tables exist
- indexes exist
- `pgvector` extension is enabled if possible
- vector column(s) are added for future embedding use

Minimum tables:
- `nodes`
- `edges`
- optional `embeddings` table or vector column on `nodes`

The implementer must keep the observable storage contract compatible with SQLite even if the physical schema differs.

- [ ] **Step 3: Implement Postgres storage backend**

Requirements:
- same public storage methods as SQLite backend
- parameterized SQL only
- clear transaction boundaries
- row-to-dict behavior equivalent to SQLite backend

- [ ] **Step 4: Add guarded Postgres tests**

`tests/test_postgres_storage.py` must:
- skip unless `SOC_TEST_POSTGRES_DSN` is set
- verify backend bootstrap
- verify contract parity for writes/reads/status/search

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_storage.py -v
pytest tests/test_postgres_storage.py -v
```

Expected:
- SQLite tests always pass
- Postgres tests pass when DSN is provided, otherwise skip cleanly

---

## Task 4: Add planner and alert-type task DAGs

**Files:**
- Create: `core/planner.py`
- Modify: `core/schemas.py`
- Create: `tests/test_planner.py`

This is the key architectural shift of Gate 2. The planner replaces the fixed four-phase sequencing in `Commander` with a typed investigation plan per alert type.

- [ ] **Step 1: Write planner tests first**

Create `tests/test_planner.py` covering:
- `intrusion` generates recon + threat_intel + forensics + remediation + reporter with correct dependencies
- `malware` generates endpoint-focused sequencing, but still maps to current available agents in this gate
- `brute_force` can skip remediation until after recon/forensics confidence is sufficient
- `anomaly` can mark remediation optional
- unknown alert type falls back to a safe default plan

- [ ] **Step 2: Implement typed `InvestigationPlan` and `PlannedTask`**

Add them to `core/schemas.py` or a closely related planning module.

- [ ] **Step 3: Implement plan builder**

Planner requirements:
- input: normalized `Alert`
- output: `InvestigationPlan`
- each task has:
  - stable `task_id`
  - `agent_name`
  - `objective`
  - dependency list
  - optional flag
  - retry budget
  - timeout override
- per-alert defaults:
  - `intrusion`: keep current full path
  - `malware`: keep full path but mark forensics mandatory
  - `brute_force`: remediation optional unless severity is high/critical
  - `anomaly`: remediation optional and early-stop threshold lower
  - `data_exfiltration`: forensics and reporter mandatory, remediation mandatory if severity high+

- [ ] **Step 4: Preserve current LLM planning use only as advisory**

The current `Commander` LLM objective generation may stay, but task graph generation in Gate 2 must be deterministic and schema-driven. Do not let free-form LLM output define task dependencies in this gate.

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_planner.py -v
```

Expected: all alert types produce valid DAGs.

---

## Task 5: Add scheduler with concurrency, retries, and early stop

**Files:**
- Create: `core/scheduler.py`
- Create: `tests/test_scheduler.py`

The scheduler consumes the planner output and executes tasks according to dependencies. This removes the hardcoded sequencing from `Commander`.

- [ ] **Step 1: Write scheduler tests**

Create `tests/test_scheduler.py` covering:
- dependency ordering
- concurrent execution of independent tasks
- retry on failure up to `max_retries`
- timeout override application
- skip optional tasks after early stop
- no early stop when mandatory tasks remain unresolved

- [ ] **Step 2: Implement scheduler**

Requirements:
- accept `InvestigationPlan`
- accept an agent registry such as `{agent_name: agent_instance}`
- execute ready tasks concurrently
- wait for dependencies before launching dependent tasks
- record task execution result with attempts and final state
- stop retrying after the configured limit

- [ ] **Step 3: Implement early-stop policy**

For this gate, confidence is computed from existing graph evidence and task outcomes, not from external integration signals.

Minimum policy:
- if planner sets `early_stop_threshold`
- and all completed mandatory tasks succeeded
- and computed confidence meets threshold
- scheduler may skip optional remaining tasks and continue to reporting

The confidence computation may be simple in this gate, but it must be explicit and testable.

- [ ] **Step 4: Emit scheduler events to event log**

New event types:
- `plan_created`
- `task_scheduled`
- `task_retry`
- `early_stop_triggered`
- `schedule_complete`

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_scheduler.py -v
```

Expected: scheduler behavior is deterministic and green under mocked agents.

---

## Task 6: Refactor Commander and app composition to use provider/storage/planner/scheduler

**Files:**
- Modify: `agents/commander.py`
- Modify: `core/app.py`
- Create: `tests/test_commander.py`
- Modify: `tests/test_app.py`

This task removes fixed phase orchestration from `Commander` without breaking the CLI or current agent implementations.

- [ ] **Step 1: Write commander delegation tests**

Create `tests/test_commander.py` to assert:
- `Commander` asks the planner for a plan
- `Commander` passes the plan to the scheduler
- `Commander` still writes the initial alert node
- timeout path still results in reporting with available data

- [ ] **Step 2: Refactor Commander to delegate**

Requirements:
- `Commander` still owns:
  - alert node creation
  - objective logging
  - error/timeout handling
  - final reporting fallback
- `Commander` no longer owns:
  - hardcoded recon/intel/forensics/remediation sequencing

- [ ] **Step 3: Refactor `core/app.py` composition**

`run_investigation()` must:
- build provider via provider factory unless dry-run
- build storage backend based on config
- build planner
- build scheduler
- inject those into `Commander`

`run_watch()` continues to call `run_investigation()` and must not duplicate composition logic.

- [ ] **Step 4: Keep current CLI behavior intact**

The following commands must still work:
- `python main.py --alert simulated --dry-run`
- `python main.py --alert alerts/sample_intrusion.json --dry-run`
- `python main.py --watch alerts/incoming --dry-run`

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_commander.py tests/test_app.py tests/test_agents.py -v
```

Expected: orchestration works via planner/scheduler and user-facing behavior is unchanged.

---

## Validation and Merge Gates

- **After Task 1:** run
  - `pytest tests/test_providers.py tests/test_config.py -v`

- **After Task 2:** run
  - `pytest tests/test_storage.py tests/test_agents.py tests/test_app.py -v`

- **After Task 3:** run
  - `pytest tests/test_storage.py -v`
  - `pytest tests/test_postgres_storage.py -v`

- **After Task 4:** run
  - `pytest tests/test_planner.py -v`

- **After Task 5:** run
  - `pytest tests/test_scheduler.py -v`

- **After Task 6:** run full non-integration suite
  - `pytest tests/ -v --ignore=tests/test_integration.py`

If a Postgres DSN is available, also run:

```bash
SOC_TEST_POSTGRES_DSN=... pytest tests/test_postgres_storage.py -v
```

---

## Important implementation details

- Keep `MockLLMClient` outside the provider factory for now. Dry-run mode stays special-cased.
- Do not remove `CaseGraph` in this gate; either wrap it or progressively delegate through the storage abstraction.
- Keep SQLite as the default backend so local runs remain simple.
- Postgres support must be opt-in by config until later gates harden deployment.
- Provider adapters must all support `attach_event_log()` and emit the same `llm_call` event shape.
- The scheduler must use the existing agent instances; do not split or redesign agent responsibilities in Gate 2.
- The planner must be deterministic. LLM output may annotate or summarize, but must not be the source of DAG truth in this gate.
- The early-stop policy must be conservative. Incorrect early stop is worse than extra work in this gate.

---

## Acceptance criteria

- App composition supports Anthropic, OpenAI-compatible, and Ollama providers.
- Storage can run on SQLite or Postgres behind one interface.
- Postgres bootstrap supports `pgvector`.
- `Commander` no longer hardcodes the four-phase flow.
- Planner produces valid per-alert-type DAGs.
- Scheduler runs independent tasks concurrently, retries failures, and supports conservative early stop.
- `python main.py --alert simulated --dry-run` still works.
- `pytest tests/ -v --ignore=tests/test_integration.py` passes after the refactor.
- Postgres backend tests pass when `SOC_TEST_POSTGRES_DSN` is supplied.

---

## Next: Gate 3

After this gate is merged and green, write `docs/superpowers/plans/2026-03-27-gate-3-real-integrations.md` covering:
- first-wave SOC integrations (Sentinel, Defender, Entra, threat intel feeds)
- adapter contract for read/write integrations
- real remediation action execution
- evidence normalization from external systems
- integration fixture recording for offline tests
