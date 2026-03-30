# Agent Dispatch Tool — Design Spec

**Date:** 2026-03-28
**Status:** Approved
**Scope:** Add dynamic inter-agent dispatch to soc-agent (Option A1: DAG + dispatch)

---

## Problem

The current investigation pipeline follows a fixed DAG planned before any agent runs.
Agents communicate only through shared state (the case graph) — they never directly
request work from each other. If Recon discovers a file hash mid-run, it cannot ask
Forensics to analyse it until the pre-planned Forensics task runs later, by which point
the opportunity for targeted analysis is gone.

This limits investigative depth and makes the system feel more like a pipeline than a
reasoning system.

---

## Goal

Allow agents to dynamically request specialist analysis from other agents mid-task,
based on what they discover during their own reasoning — without removing the DAG or
its compliance and auditability guarantees.

---

## Approach: A1 — DAG + Agent Dispatch Tool

The base DAG runs exactly as today (required steps per alert type, parallel where
dependencies allow). Each agent gains access to a `dispatch_agent` tool alongside its
existing tools (ip_lookup, whois, port_scan, etc.). When the agent's LLM reasoning
decides it needs specialist input, it calls the tool. The Commander handles the call
synchronously and returns the result before the agent finishes.

**Why not full ReACT (no DAG)?**
Cybersecurity is a regulated, high-consequence domain. SOC playbooks mandate specific
checks per alert type regardless of LLM confidence. The DAG represents the runbook —
non-negotiable, certifiable, auditable. Dynamic dispatch is the analyst intuition layer
on top. Removing the DAG trades compliance guarantees for flexibility in a domain where
missing a step has legal and operational consequences.

---

## Architecture

```
Base DAG (unchanged):
  recon ──┬──> threat_intel ──┬──> remediation ──> reporter
          └──> forensics ─────┘

Dynamic layer (new):
  recon is running...
    └─ LLM: "found hash abc123, need forensic analysis"
    └─ calls dispatch_agent("forensics", "analyse hash abc123", context={...})
         └─ Commander spins up ForensicsAgent sub-task (local, never via worker queue)
         └─ ForensicsAgent runs, writes findings to case graph with "dispatched:" prefix
         └─ result returned into recon's tool results
    └─ recon continues reasoning with forensic findings included
    └─ recon completes normally

  threat_intel is also running (in parallel, unaffected)
```

---

## Components

### 1. `core/dispatch.py` (new)

**DispatchCounter** — a shared mutable counter, passed by reference to all branches of
a single investigation. Using a wrapper object avoids read-modify-write races in the
asyncio event loop when two DAG agents dispatch concurrently:

```python
@dataclass
class DispatchCounter:
    value: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def increment(self) -> int:
        async with self.lock:
            self.value += 1
            return self.value
```

**DispatchContext** — per-branch context, holds an immutable chain view plus a
reference to the shared counter:

```python
@dataclass
class DispatchContext:
    depth: int = 0
    max_depth: int = 2
    max_sub_tasks: int = 5
    dispatched_agents: frozenset[str] = frozenset()
    _counter: DispatchCounter = field(default_factory=DispatchCounter)

    def can_dispatch(self, agent_name: str) -> bool:
        """Check limits. reporter and commander are always denied."""
        if agent_name in ("reporter", "commander"):
            return False
        return (
            self.depth < self.max_depth
            and self._counter.value < self.max_sub_tasks
            and agent_name not in self.dispatched_agents
        )

    def child(self, agent_name: str) -> "DispatchContext":
        """Return a new context for the sub-task, sharing the same counter."""
        return DispatchContext(
            depth=self.depth + 1,
            max_depth=self.max_depth,
            max_sub_tasks=self.max_sub_tasks,
            dispatched_agents=self.dispatched_agents | {agent_name},
            _counter=self._counter,  # shared reference
        )
```

**DispatchTool** — calls back to Commander via an injected async callable:

```python
class DispatchTool:
    def __init__(
        self,
        dispatch_fn: Callable[[str, str, dict, DispatchContext], Awaitable[str]],
        dispatch_context: DispatchContext,
        caller_name: str,
        sub_task_timeout: float,
    ):
        self._dispatch_fn = dispatch_fn
        self._context = dispatch_context
        self._caller = caller_name
        self._timeout = sub_task_timeout

    async def run(self, agent: str, objective: str, context: dict) -> str:
        if agent == self._caller:
            return f"Cannot dispatch to self ({self._caller})."
        if not self._context.can_dispatch(agent):
            return (
                f"Dispatch limit reached (depth={self._context.depth}, "
                f"sub_tasks={self._context._counter.value}). "
                "Proceeding with available findings."
            )
        try:
            return await asyncio.wait_for(
                self._dispatch_fn(agent, objective, context, self._context),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return f"Specialist agent '{agent}' timed out. Proceeding without those findings."
        except Exception as e:
            return f"Specialist agent '{agent}' failed: {e}. Proceeding without those findings."
```

Tool definition exposed to the LLM:
```json
{
  "name": "dispatch_agent",
  "description": "Request specialist analysis from another agent. Use when you discover a specific IOC or finding that requires deeper investigation beyond your own capability.",
  "parameters": {
    "agent": "one of: recon, threat_intel, forensics, remediation",
    "objective": "specific question or task for the specialist",
    "context": "relevant data to pass — IPs, hashes, hostnames, etc."
  }
}
```

---

### 2. `agents/base.py` (updated)

`AgentBase.__init__` gains two new optional parameters:

```python
def __init__(
    self,
    case_graph,
    llm,
    console,
    agent_timeout: int = 120,
    dispatch_context: DispatchContext | None = None,
    dispatch_fn: Callable | None = None,
):
    ...
    self.dispatch_context = dispatch_context
    self._dispatch_fn = dispatch_fn
```

When both are present, a `DispatchTool` is constructed and available to the agent's
tool-use loop. When absent, dispatch is simply not available — base DAG agents that
are not given a context cannot dispatch.

**Tool-use loop:** All agent `_run()` methods currently make a single `llm.call()` and
return the text. For dispatch to work, each agent's `_run()` must be extended into a
multi-turn ReACT loop:

```
1. Send message + tools list to LLM
2. If response contains tool_use blocks → execute each tool, collect results
3. Send tool_results back to LLM as a new message
4. Repeat until response is text-only (no tool_use blocks) or max_iterations reached
5. Use final text response as the agent's summary/finding
```

`max_iterations` defaults to 5 to prevent runaway loops. `LLMClient.call()` must be
updated to return both text and tool_use blocks (currently it discards tool_use blocks
entirely — see `core/llm_client.py`). A `LLMResponse` dataclass is introduced:

```python
@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict]  # [{name, input}]
```

`LLMClient.call()` returns `LLMResponse` instead of `str`. All existing callers
(single-call agents) access `.text` and ignore `.tool_calls` — backwards compatible.

---

### 3. `agents/commander.py` (updated)

Commander stores the current alert at investigation start and exposes `run_sub_task()`:

```python
async def investigate(self, alert: Alert) -> None:
    self._current_alert = alert  # stored for sub-task access
    ...
```

```python
async def run_sub_task(
    self,
    agent_name: str,
    objective: str,
    context: dict,
    dispatch_context: DispatchContext,
) -> str:
    await dispatch_context._counter.increment()

    self.event_log.append("agent_dispatch", agent=agent_name, data={
        "objective": objective,
        "context": context,
        "depth": dispatch_context.depth,
        "sub_task_count": dispatch_context._counter.value,
    })

    task_node_id = self.graph.write_node(
        type="task",
        label=f"dispatch:{agent_name}:{dispatch_context.depth}",
        data={"agent": agent_name, "objective": objective, "dispatched": True},
        created_by="dispatch",
    )

    child_ctx = dispatch_context.child(agent_name)
    sub_timeout = self._agent_timeout_for(agent_name)  # already halved with floor
    agent = self._build_single_agent(agent_name, child_ctx, sub_timeout)
    await agent.run(task_node_id, self._current_alert)

    return self._read_latest_findings(agent_name, task_node_id)
```

**`_build_single_agent(agent_name, dispatch_context, timeout)`** — reuses the adapter
wiring from `_build_agents()` but constructs only the named agent. It must pass the
same real adapters (threat_adapter, entra_adapter, defender_adapter, approval_queue,
execution_policy) that the base DAG agent receives. The dispatch_fn passed to the
agent is `self.run_sub_task`:

```python
def _build_single_agent(self, agent_name: str, ctx: DispatchContext, timeout: int):
    registry = self.integration_registry or IntegrationRegistry()
    has_registry = self.integration_registry is not None
    base_kwargs = dict(
        case_graph=self.graph,
        llm=self.llm,
        console=self.console,
        agent_timeout=timeout,
        dispatch_context=ctx,
        dispatch_fn=self.run_sub_task,
    )
    # Mirror the adapter wiring from _build_agents()
    if agent_name == "recon":
        return ReconAgent(**base_kwargs, integration_registry=registry if has_registry else None)
    if agent_name == "threat_intel":
        return ThreatIntelAgent(**base_kwargs,
            threat_adapter=registry.adapters.get("threat_intel") if has_registry else None,
            use_env_adapter=not has_registry)
    if agent_name == "forensics":
        return ForensicsAgent(**base_kwargs,
            entra_adapter=registry.adapters.get("entra") if has_registry else None,
            use_env_adapter=not has_registry)
    if agent_name == "remediation":
        return RemediationAgent(**base_kwargs,
            auto_remediate=self.auto_remediate,
            execution_policy=self.execution_policy,
            defender_adapter=registry.adapters.get("defender") if has_registry else None,
            entra_adapter=registry.adapters.get("entra") if has_registry else None,
            approval_queue=self.approval_queue)
    raise ValueError(f"Unknown dispatchable agent: {agent_name}")
```

**`_agent_timeout_for(agent_name)`** — returns half of `self.agent_timeout` for all
agents, with a 10-second floor:

```python
def _agent_timeout_for(self, agent_name: str) -> int:
    return max(10, self.agent_timeout // 2)
```

**`_read_latest_findings(agent_name, task_node_id)`** — reads the dispatch summary
node written by the sub-agent after it completes. Each agent's `_run()` is extended to
write a standardized `finding` node at the end when running as a dispatched sub-task
(see agent changes below). The label is always `dispatch-summary:{agent_name}:{task_node_id}`.

```python
def _read_latest_findings(self, agent_name: str, task_node_id: str) -> str:
    label = f"dispatch-summary:{agent_name}:{task_node_id}"
    nodes = self.graph.get_nodes_by_type("finding")
    match = next((n for n in nodes if n.get("label") == label), None)
    if match is None:
        return f"No findings returned by dispatched {agent_name} agent."
    return match.get("data", {}).get("summary", "No summary available.")
```

**Dispatch summary node — agent contract:** Every agent's `_run()` is extended with a
final write when `self.dispatch_context is not None` (i.e., the agent is running as a
dispatched sub-task). This write happens after the agent's normal node writes and
always produces a `finding` node of type `finding` with a `summary` key:

```python
# Added at the end of each agent's _run() — example for ForensicsAgent:
if self.dispatch_context is not None:
    self.graph.write_node(
        type="finding",
        label=f"dispatch-summary:forensics:{task_node_id}",
        data={"summary": analysis},  # reuse the LLM analysis already computed
        created_by=self.name,
    )
```

For each agent, `summary` maps to the LLM-generated text it already computes:
- **ReconAgent**: the `summary` string from `llm.call()` (already stored in the finding node)
- **ThreatIntelAgent**: the `assessment` text from `llm.call()`
- **ForensicsAgent**: the `analysis` text from `llm.call()` (currently written as a `timeline_event` node — the dispatch summary node is additional, not a replacement)
- **RemediationAgent**: a JSON-serialised list of proposed actions

This approach requires no `label_prefix` parameter and no changes to agents' normal
node-writing logic. The dispatch summary node is a simple addendum.

**Worker queue:** `run_sub_task()` always executes locally regardless of whether the
investigation was started in worker mode. This is intentional — sub-tasks are
synchronous enrichment steps within a running agent, not independent work items. A
remote worker round-trip (enqueue → poll → complete) would add unacceptable latency
and complexity to an already time-bounded agent execution.

**Root DispatchContext creation:** Commander creates one `DispatchContext` per
investigation (with a fresh `DispatchCounter`) and passes it to all base DAG agents
inside `_build_agents()`. This means all base DAG agents share the same counter,
ensuring the per-investigation sub-task budget is enforced globally.

---

### 4. `agents/*.py` — System prompt additions (updated)

Each agent's `SYSTEM_PROMPT` gains a specific dispatch guidance clause. The "only
dispatch when" constraint prevents reflexive dispatch on every run and preserves
sub-task budget for cases that genuinely need it. Most investigations (brute force,
anomaly) complete without any dispatches.

**Recon:**
> If you discover a file hash, malware sample, or forensic artifact, dispatch forensics
> with the specific artifact as context. If you find a suspicious IP with no clear
> attribution, dispatch threat_intel. Only dispatch when you have a specific concrete
> IOC — not as a general enrichment step.

**Threat Intel:**
> If threat feeds confirm an active campaign and you need endpoint evidence to
> corroborate it, dispatch forensics with the campaign IOCs as context. Only dispatch
> when intelligence findings require validation against host evidence.

**Forensics:**
> If timeline reconstruction reveals an unknown external IP or domain not already in
> the case graph, dispatch recon or threat_intel with that specific indicator. Only
> dispatch when the timeline surfaces a new IOC.

**Remediation:**
> If a proposed action depends on live host state you don't have (e.g. confirming a
> process is still running), dispatch recon with the specific query. Only dispatch when
> an action depends on data you're missing.

---

### 5. `core/llm_client.py` (updated)

`LLMClient.call()` currently discards `tool_use` blocks. It must be updated to return
a `LLMResponse(text, tool_calls)` dataclass. The Anthropic provider extracts both
`text` blocks and `tool_use` blocks from the response. The Ollama and OpenAI providers
do the same for their respective response formats. `MockLLMClient` returns
`LLMResponse(text=<existing canned response>, tool_calls=[])` for all existing calls,
maintaining backwards compatibility.

---

### 6. `core/mock_llm.py` (updated)

For dry-run dispatch, `MockLLMClient` simulates a two-turn tool-use exchange:

- **Turn 1**: If the system prompt indicates an agent that has dispatch enabled, and if
  the alert type warrants it (intrusion, malware, data_exfiltration), `MockLLMClient`
  returns a `LLMResponse` with one synthetic `dispatch_agent` tool call in `tool_calls`.
- **Turn 2**: After the tool result is fed back, `MockLLMClient` returns the normal
  canned text summary for that agent.

A `_should_mock_dispatch(system, alert_type)` helper determines whether to inject the
synthetic tool call. It is only injected once per agent per dry-run (tracked by a
`_dispatched` set on the client instance) to prevent loops.

---

## Guardrails summary

| Guardrail | Mechanism |
|---|---|
| Max dispatch depth (2) | `DispatchContext.depth` check in `can_dispatch()` |
| Max sub-tasks per investigation (5) | Shared `DispatchCounter` checked in `can_dispatch()` |
| No self-dispatch | `agent == self._caller` check in `DispatchTool.run()` |
| No reporter/commander dispatch | Denylist in `can_dispatch()` |
| No circular dispatch | `dispatched_agents` frozenset on child context |
| Sub-task timeout | `asyncio.wait_for` in `DispatchTool.run()` at `agent_timeout // 2` |
| Sub-agent failure isolation | `try/except` in `DispatchTool.run()` returns graceful string |
| Worker queue bypass | `run_sub_task()` always runs locally, documented explicitly |
| Full auditability | `agent_dispatch` and `agent_dispatch_blocked` event log entries |

---

## Event log entries

All dispatch events use `agent_dispatch`:
```json
{
  "event": "agent_dispatch",
  "agent": "forensics",
  "data": {
    "objective": "analyse hash abc123",
    "context": {"hash": "abc123"},
    "depth": 1,
    "sub_task_count": 1
  }
}
```

Limit hits, failures, and circular blocks log as `agent_dispatch_blocked`:
```json
{
  "event": "agent_dispatch_blocked",
  "agent": "recon",
  "data": {
    "reason": "circular_dispatch",
    "depth": 1
  }
}
```

All dispatch events are captured by the existing replay system.

---

## Files changed

| File | Change |
|---|---|
| `core/dispatch.py` | New — DispatchCounter, DispatchContext, DispatchTool |
| `core/providers.py` | Update `ModelProvider.call()` Protocol return type from `str` to `LLMResponse` |
| `core/llm_client.py` | Return LLMResponse instead of str; extract tool_use blocks |
| `core/providers/anthropic_provider.py` | Return LLMResponse |
| `core/providers/openai_provider.py` | Return LLMResponse |
| `core/providers/ollama_provider.py` | Return LLMResponse |
| `core/mock_llm.py` | Return LLMResponse; two-turn dispatch simulation |
| `agents/base.py` | Accept dispatch_context + dispatch_fn; implement tool-use loop |
| `agents/recon.py` | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/threat_intel.py` | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/forensics.py` | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/remediation.py` | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/commander.py` | Store _current_alert; add run_sub_task(), _build_single_agent(), _agent_timeout_for(), _read_latest_findings(); pass root DispatchContext to _build_agents() |

**Unchanged:** Planner, Scheduler, StorageBackend, approval queue, execution policy,
existing tests, API server, worker queue, replay logic, reporter agent.

---

## Testing

- Unit: `DispatchContext` — limit enforcement, child context creation, circular
  detection, shared counter across branches
- Unit: `DispatchTool` — limit-reached path, failure path, timeout path, self-dispatch
  rejection, reporter/commander rejection
- Unit: `LLMResponse` — all providers return correct structure for text-only and
  tool_use responses
- Unit: tool-use loop in `AgentBase` — verify multi-turn exchange terminates correctly
  at max_iterations
- Integration: dry-run dispatch — `MockLLMClient` triggers a synthetic dispatch, verify
  sub-task node appears in case graph with `dispatch:` label prefix
- Integration: base DAG smoke test — existing `--dry-run` investigations complete
  unchanged with no regressions
