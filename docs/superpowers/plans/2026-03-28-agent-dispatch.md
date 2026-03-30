# Agent Dispatch Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow SOC agents to dynamically request specialist analysis from each other mid-task via a `dispatch_agent` tool, while preserving the base DAG and all governance guarantees.

**Architecture:** A `DispatchTool` is registered on each agent alongside existing tools. When the agent's LLM calls `dispatch_agent`, `AgentBase` executes a tool-use loop: send tools to LLM → execute any tool calls → inject results back → continue until text-only response. The `Commander` handles sub-task execution via `run_sub_task()`, writing findings to the shared case graph. A `DispatchContext` threaded through every agent enforces depth (max 2) and budget (max 5 sub-tasks) limits per investigation.

**Tech Stack:** Python 3.11+, asyncio, existing `StorageBackend` (SQLite), `LLMClient` (Anthropic/OpenAI/Ollama), pytest

**Spec:** `docs/superpowers/specs/2026-03-28-agent-dispatch-design.md`

---

## File Map

| File | Status | Responsibility |
|---|---|---|
| `core/llm_response.py` | **Create** | `LLMResponse` dataclass — text + tool_calls |
| `core/dispatch.py` | **Create** | `DispatchCounter`, `DispatchContext`, `DispatchTool` |
| `core/providers.py` | **Modify** | Update `ModelProvider.call()` Protocol return type |
| `core/llm_client.py` | **Modify** | Return `LLMResponse`; extract tool_use blocks |
| `core/providers/openai_provider.py` | **Modify** | Return `LLMResponse`; extract tool_calls |
| `core/providers/ollama_provider.py` | **Modify** | Return `LLMResponse`; extract tool_calls |
| `core/mock_llm.py` | **Modify** | Return `LLMResponse`; two-turn dispatch simulation |
| `agents/base.py` | **Modify** | `dispatch_context`, `dispatch_fn`, tool-use loop helper |
| `agents/recon.py` | **Modify** | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/threat_intel.py` | **Modify** | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/forensics.py` | **Modify** | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/remediation.py` | **Modify** | Updated SYSTEM_PROMPT; dispatch summary node write |
| `agents/commander.py` | **Modify** | `_current_alert`, `run_sub_task()`, `_build_single_agent()`, `_agent_timeout_for()`, `_read_latest_findings()`, root `DispatchContext` wiring |
| `tests/test_dispatch.py` | **Create** | Unit tests for `DispatchContext` and `DispatchTool` |
| `tests/test_llm_response.py` | **Create** | Unit tests for provider `LLMResponse` output |
| `tests/test_agent_dispatch_integration.py` | **Create** | Integration test: dry-run dispatch smoke test |
| `tests/test_mock_llm.py` | **Modify** | Update assertions to use `.text` after Task 4 |
| `tests/test_agents.py` | **Modify** | Update `AsyncMock(return_value=<str>)` to `LLMResponse` after Task 3 |
| `tests/test_commander.py` | **Modify** | Update `AsyncMock(return_value=<str>)` to `LLMResponse` after Task 3 |

---

## Task 1: `LLMResponse` dataclass

**Files:**
- Create: `core/llm_response.py`
- Create: `tests/test_llm_response.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_llm_response.py
from core.llm_response import LLMResponse


def test_llm_response_text_only():
    r = LLMResponse(text="hello", tool_calls=[])
    assert r.text == "hello"
    assert r.tool_calls == []
    assert not r.has_tool_calls


def test_llm_response_with_tool_calls():
    calls = [{"name": "dispatch_agent", "input": {"agent": "forensics"}, "id": "tc1"}]
    r = LLMResponse(text="", tool_calls=calls)
    assert r.has_tool_calls
    assert r.tool_calls[0]["name"] == "dispatch_agent"


def test_llm_response_first_tool_call():
    calls = [{"name": "dispatch_agent", "input": {"agent": "forensics"}, "id": "tc1"}]
    r = LLMResponse(text="", tool_calls=calls)
    assert r.first_tool_call["name"] == "dispatch_agent"


def test_llm_response_first_tool_call_empty():
    r = LLMResponse(text="ok", tool_calls=[])
    assert r.first_tool_call is None
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /Users/waleedakrabi/Desktop/Github-forks/soc-agent
pytest tests/test_llm_response.py -v
```
Expected: `ModuleNotFoundError: No module named 'core.llm_response'`

- [ ] **Step 3: Implement `core/llm_response.py`**

```python
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)

    @property
    def first_tool_call(self) -> dict | None:
        return self.tool_calls[0] if self.tool_calls else None
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_llm_response.py -v
```
Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add core/llm_response.py tests/test_llm_response.py
git commit -m "feat: add LLMResponse dataclass"
```

---

## Task 2: `DispatchContext` and `DispatchCounter`

**Files:**
- Create: `core/dispatch.py` (DispatchCounter + DispatchContext only — no DispatchTool yet)
- Create: `tests/test_dispatch.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_dispatch.py
import asyncio
import pytest
from core.dispatch import DispatchContext, DispatchCounter


def test_can_dispatch_within_limits():
    ctx = DispatchContext()
    assert ctx.can_dispatch("forensics") is True


def test_cannot_dispatch_reporter():
    ctx = DispatchContext()
    assert ctx.can_dispatch("reporter") is False


def test_cannot_dispatch_commander():
    ctx = DispatchContext()
    assert ctx.can_dispatch("commander") is False


def test_cannot_dispatch_at_max_depth():
    ctx = DispatchContext(depth=2, max_depth=2)
    assert ctx.can_dispatch("forensics") is False


def test_cannot_dispatch_when_budget_exhausted():
    counter = DispatchCounter()
    counter.value = 5
    ctx = DispatchContext(max_sub_tasks=5, _counter=counter)
    assert ctx.can_dispatch("forensics") is False


def test_cannot_dispatch_same_agent_in_chain():
    ctx = DispatchContext(dispatched_agents=frozenset({"recon"}))
    assert ctx.can_dispatch("recon") is False


def test_child_increments_depth():
    ctx = DispatchContext(depth=0)
    child = ctx.child("forensics")
    assert child.depth == 1


def test_child_adds_agent_to_dispatched_set():
    ctx = DispatchContext()
    child = ctx.child("forensics")
    assert "forensics" in child.dispatched_agents


def test_child_shares_counter():
    ctx = DispatchContext()
    child = ctx.child("forensics")
    assert child._counter is ctx._counter


@pytest.mark.asyncio
async def test_counter_increment():
    counter = DispatchCounter()
    val = await counter.increment()
    assert val == 1
    val2 = await counter.increment()
    assert val2 == 2
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_dispatch.py -v
```
Expected: `ModuleNotFoundError: No module named 'core.dispatch'`

- [ ] **Step 3: Implement `DispatchCounter` and `DispatchContext` in `core/dispatch.py`**

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class DispatchCounter:
    value: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def increment(self) -> int:
        async with self._lock:
            self.value += 1
            return self.value


@dataclass
class DispatchContext:
    depth: int = 0
    max_depth: int = 2
    max_sub_tasks: int = 5
    dispatched_agents: frozenset[str] = field(default_factory=frozenset)
    _counter: DispatchCounter = field(default_factory=DispatchCounter)

    _DENIED: frozenset[str] = field(
        default_factory=lambda: frozenset({"reporter", "commander"}),
        init=False,
        repr=False,
        compare=False,
    )

    def can_dispatch(self, agent_name: str) -> bool:
        if agent_name in self._DENIED:
            return False
        return (
            self.depth < self.max_depth
            and self._counter.value < self.max_sub_tasks
            and agent_name not in self.dispatched_agents
        )

    def child(self, agent_name: str) -> DispatchContext:
        return DispatchContext(
            depth=self.depth + 1,
            max_depth=self.max_depth,
            max_sub_tasks=self.max_sub_tasks,
            dispatched_agents=self.dispatched_agents | {agent_name},
            _counter=self._counter,
        )
```

- [ ] **Step 4: Run tests to confirm pass**

```bash
pytest tests/test_dispatch.py -v
```
Expected: all passed

- [ ] **Step 5: Commit**

```bash
git add core/dispatch.py tests/test_dispatch.py
git commit -m "feat: add DispatchContext and DispatchCounter"
```

---

## Task 3: Update providers to return `LLMResponse`

The goal here is to make all providers return `LLMResponse` instead of `str`. `AnthropicProvider` inherits from `LLMClient` so only `LLMClient` needs updating for Anthropic. `OpenAIProvider` and `OllamaProvider` have their own `call()` implementations.

**Files:**
- Modify: `core/providers.py`
- Modify: `core/llm_client.py`
- Modify: `core/providers/openai_provider.py`
- Modify: `core/providers/ollama_provider.py`
- Modify: `tests/test_llm_response.py` (add provider contract test)
- Modify: `tests/test_agents.py` (update mocks)
- Modify: `tests/test_commander.py` (update mocks)

- [ ] **Step 0: Write a failing contract test before touching any implementation**

Add this test to `tests/test_llm_response.py`:

```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.llm_client import LLMClient
from core.llm_response import LLMResponse


@pytest.mark.asyncio
async def test_llm_client_returns_llm_response():
    """LLMClient.call() must return LLMResponse, not a plain str."""
    mock_block = MagicMock()
    mock_block.text = "hello world"
    # No tool_use attribute — simulates a text-only block
    del mock_block.type

    mock_response = MagicMock()
    mock_response.content = [mock_block]

    with patch("anthropic.AsyncAnthropic") as mock_anthropic:
        mock_client = AsyncMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client

        llm = LLMClient(api_key="test", model="claude-test")
        result = await llm.call(system="sys", messages=[{"role": "user", "content": "hi"}])

    assert isinstance(result, LLMResponse), f"Expected LLMResponse, got {type(result)}"
    assert result.text == "hello world"
    assert result.tool_calls == []
```

- [ ] **Step 0b: Run to confirm failure**

```bash
pytest tests/test_llm_response.py::test_llm_client_returns_llm_response -v
```
Expected: FAIL — `AssertionError: Expected LLMResponse, got <class 'str'>`

- [ ] **Step 1: Update `core/providers.py` — change Protocol return type**

Open `core/providers.py`. Change the `call()` return type annotation from `-> str` to `-> LLMResponse`. Add the import.

The full updated file:

```python
from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from core.config import Config
from core.llm_response import LLMResponse

__path__ = [str(Path(__file__).with_name("providers"))]


@runtime_checkable
class ModelProvider(Protocol):
    name: str

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    def attach_event_log(self, event_log) -> None: ...


def build_provider(config: Config) -> ModelProvider:
    provider = (config.provider or "anthropic").strip().lower()

    if provider == "anthropic":
        from core.providers.anthropic_provider import AnthropicProvider
        return AnthropicProvider(api_key=config.anthropic_api_key, model=config.model)
    if provider == "openai":
        from core.providers.openai_provider import OpenAIProvider
        base_url = config.openai_base_url or "https://api.openai.com/v1"
        return OpenAIProvider(api_key=config.openai_api_key, model=config.model, base_url=base_url)
    if provider == "ollama":
        from core.providers.ollama_provider import OllamaProvider
        return OllamaProvider(model=config.model, base_url=config.ollama_base_url or "http://localhost:11434")

    raise ValueError(f"Unsupported model provider: {config.provider!r}")
```

- [ ] **Step 2: Update `core/llm_client.py` — return `LLMResponse`, extract tool_use blocks**

The full updated file:

```python
import asyncio
import anthropic

from core.llm_response import LLMResponse


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.model = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = await self._client.messages.create(**kwargs)

                text = ""
                tool_calls = []
                for block in response.content:
                    if hasattr(block, "text"):
                        text = block.text
                    elif block.type == "tool_use":
                        tool_calls.append({
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })

                if self._event_log is not None:
                    self._event_log.append(
                        "llm_call",
                        agent="llm",
                        data={
                            "system_snippet": system[:120],
                            "response_snippet": text[:120],
                        },
                    )
                return LLMResponse(text=text, tool_calls=tool_calls)

            except Exception as e:
                last_error = e
                if attempt == 0:
                    await asyncio.sleep(2)

        raise LLMError(f"LLM call failed after retry: {last_error}") from last_error
```

- [ ] **Step 3: Update `core/providers/openai_provider.py` — return `LLMResponse`**

```python
from __future__ import annotations

import httpx

from core.llm_response import LLMResponse


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    def _emit_call_event(self, system: str, response: str) -> None:
        if self._event_log is not None:
            self._event_log.append(
                "llm_call",
                agent="llm",
                data={"system_snippet": system[:120], "response_snippet": response[:120]},
            )

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload_messages = [{"role": "system", "content": system}, *messages]
        payload = {"model": self.model, "messages": payload_messages, "max_tokens": max_tokens}
        if tools:
            payload["tools"] = tools

        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{self.base_url}/chat/completions", headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        content = ""
        tool_calls = []
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "") or ""
            for tc in message.get("tool_calls", []):
                import json
                tool_calls.append({
                    "id": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "input": json.loads(tc.get("function", {}).get("arguments", "{}")),
                })

        self._emit_call_event(system, content)
        return LLMResponse(text=content, tool_calls=tool_calls)
```

- [ ] **Step 4: Update `core/providers/ollama_provider.py` — return `LLMResponse`**

```python
from __future__ import annotations

import httpx

from core.llm_response import LLMResponse


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    def _emit_call_event(self, system: str, response: str) -> None:
        if self._event_log is not None:
            self._event_log.append(
                "llm_call",
                agent="llm",
                data={"system_snippet": system[:120], "response_snippet": response[:120]},
            )

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(f"{self.base_url}/api/chat", json=payload)
            response.raise_for_status()
            data = response.json()

        content = ""
        tool_calls = []
        if isinstance(data, dict):
            message = data.get("message") or {}
            content = message.get("content") or data.get("response") or ""
            for tc in message.get("tool_calls", []):
                tool_calls.append({
                    "id": tc.get("id", ""),
                    "name": tc.get("function", {}).get("name", ""),
                    "input": tc.get("function", {}).get("arguments", {}),
                })

        self._emit_call_event(system, content)
        return LLMResponse(text=content, tool_calls=tool_calls)
```

- [ ] **Step 5: Fix all callers that treat `llm.call()` return value as `str`**

Every agent currently does `summary = await self.llm.call(...)` and uses `summary` directly as a string. Now `call()` returns `LLMResponse`. Before touching `AgentBase` (Task 5), update each agent's `_run()` to use `.text`:

In `agents/recon.py` line ~130:
```python
# Before:
summary = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user_msg}])
# After:
response = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user_msg}])
summary = response.text
```

In `agents/threat_intel.py` line ~93:
```python
# Before:
assessment = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
response = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
assessment = response.text
```

In `agents/forensics.py` line ~79:
```python
# Before:
analysis = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
response = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
analysis = response.text
```

In `agents/remediation.py` line ~63:
```python
# Before:
raw = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
response = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
raw = response.text
```

In `agents/reporter.py` — find `llm.call()` calls and apply `.text` the same way.

In `agents/commander.py` line ~99:
```python
# Before:
raw = await self.llm.call(system=prompt, messages=[{"role": "user", "content": alert_summary}])
# After:
response = await self.llm.call(system=prompt, messages=[{"role": "user", "content": alert_summary}])
raw = response.text
```

- [ ] **Step 6: Update test mocks in `tests/test_agents.py` and `tests/test_commander.py`**

All `AsyncMock(return_value=<str>)` patterns for `llm.call` must now return `LLMResponse`. Add this import at the top of each test file:
```python
from core.llm_response import LLMResponse
```

In `tests/test_agents.py`, replace every occurrence of:
```python
mock_llm.call = AsyncMock(return_value="<some string>")
```
with:
```python
mock_llm.call = AsyncMock(return_value=LLMResponse(text="<some string>", tool_calls=[]))
```

The affected lines are approximately: 41, 47, 61, 100, 113, 135–143, 197, 213, 286.

For line 135 (multi-line string), wrap the whole string:
```python
mock_llm.call = AsyncMock(return_value=LLMResponse(text='[{"action_type": ...}]', tool_calls=[]))
```

In `tests/test_commander.py`, replace:
```python
llm.call = AsyncMock(return_value='{"objective":"Investigate","priority_agents":["recon"]}')
```
with:
```python
llm.call = AsyncMock(return_value=LLMResponse(text='{"objective":"Investigate","priority_agents":["recon"]}', tool_calls=[]))
```
(applies to lines ~42 and ~78)

- [ ] **Step 7: Run the existing test suite to confirm no regressions**

```bash
pytest tests/ -q --ignore=tests/test_dry_run_smoke.py --ignore=tests/test_integration.py
```
Expected: all pass

- [ ] **Step 8: Commit**

```bash
git add core/providers.py core/llm_client.py core/providers/openai_provider.py core/providers/ollama_provider.py agents/recon.py agents/threat_intel.py agents/forensics.py agents/remediation.py agents/reporter.py agents/commander.py tests/test_agents.py tests/test_commander.py tests/test_llm_response.py
git commit -m "feat: update all providers and agents to use LLMResponse"
```

---

## Task 4: Update `MockLLMClient` to return `LLMResponse`

`MockLLMClient` is used by `--dry-run`. It needs to return `LLMResponse` and simulate a two-turn dispatch exchange for qualifying alert types.

**Files:**
- Modify: `core/mock_llm.py`

- [ ] **Step 1: Update `MockLLMClient.call()` return type**

At the top of `core/mock_llm.py`, add:
```python
from core.llm_response import LLMResponse
```

Update the `call()` method signature:
```python
async def call(self, system: str, messages: list[dict], tools: list[dict] = None, max_tokens: int = 4096) -> LLMResponse:
```

All existing return statements `return rendered` and `return report` must become `return LLMResponse(text=rendered, tool_calls=[])` and `return LLMResponse(text=report, tool_calls=[])`.

- [ ] **Step 2: Add two-turn dispatch simulation**

Add a `_dispatched: set[str]` instance variable in `__init__`:
```python
self._dispatched: set[str] = set()
```

Add a `_should_mock_dispatch(role, alert_type)` helper:
```python
def _should_mock_dispatch(self, role: str, alert_type: str) -> bool:
    """Return True once per role for high-severity alert types to simulate dispatch."""
    key = f"{role}:{alert_type}"
    if key in self._dispatched:
        return False
    high_severity_types = {"intrusion", "malware", "data_exfiltration"}
    dispatch_roles = {"recon", "threat_intel"}
    if role in dispatch_roles and alert_type in high_severity_types:
        self._dispatched.add(key)
        return True
    return False
```

In `call()`, after determining `role` and `alert_type`, before looking up the bucket response, add:
```python
# Check if this is a tool_result follow-up (second turn)
last_message = messages[-1] if messages else {}
is_tool_result = (
    isinstance(last_message.get("content"), list)
    and any(isinstance(c, dict) and c.get("type") == "tool_result" for c in last_message["content"])
)

# On first turn for qualifying cases, inject a synthetic dispatch_agent call
if not is_tool_result and tools and self._should_mock_dispatch(role, alert_type):
    return LLMResponse(
        text="",
        tool_calls=[{
            "id": f"mock-dispatch-{role}",
            "name": "dispatch_agent",
            "input": {
                "agent": "forensics" if role == "recon" else "recon",
                "objective": f"Investigate IOC discovered during {role} analysis",
                "context": {"source": role, "alert_type": alert_type},
            },
        }],
    )
```

- [ ] **Step 3: Update `tests/test_mock_llm.py` assertions to use `.text`**

Add import at top of the file:
```python
from core.llm_response import LLMResponse
```

Replace every bare `response` assertion with `response.text`:
```python
# Line 35-37: was assert response / assert "Tor exit node" in response / assert "8080" in response
assert response.text
assert "Tor exit node" in response.text
assert "8080" in response.text

# Line 50-53: was lower = response.lower() / assert response / assert "brute" in lower ...
lower = response.text.lower()
assert response.text
assert "brute" in lower or "credential" in lower or "ssh" in lower
assert "203.0.113.99" in response.text or "bastion-01" in response.text

# Line 66-68: was assert response / assert "Incident Report" in response / assert "malware" in response.lower()
assert response.text
assert "Incident Report" in response.text
assert "malware" in response.text.lower()

# Line 85: was assert first == second
assert first.text == second.text

# Line 96-97: was assert response / assert "objective" in response.lower()
assert response.text
assert "objective" in response.text.lower()

# Line 111-112: was assert "Incident Report" in response / assert "malware" in response.lower()
assert "Incident Report" in response.text
assert "malware" in response.text.lower()
```

- [ ] **Step 4: Run the existing test suite**

```bash
pytest tests/ -q --ignore=tests/test_dry_run_smoke.py --ignore=tests/test_integration.py
```
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add core/mock_llm.py tests/test_mock_llm.py
git commit -m "feat: update MockLLMClient to return LLMResponse with dispatch simulation"
```

---

## Task 5: `DispatchTool` + `AgentBase` tool-use loop

**Files:**
- Modify: `core/dispatch.py` (add `DispatchTool` and `DISPATCH_TOOL_SCHEMA`)
- Modify: `agents/base.py`

- [ ] **Step 1: Add `DispatchTool` and `DISPATCH_TOOL_SCHEMA` to `core/dispatch.py`**

Append to `core/dispatch.py`:

```python
import asyncio
from collections.abc import Awaitable, Callable

# Tool schema definition exposed to the LLM
DISPATCH_TOOL_SCHEMA = {
    "name": "dispatch_agent",
    "description": (
        "Request specialist analysis from another agent. Use when you discover a specific "
        "IOC or finding that requires deeper investigation beyond your own capability. "
        "Only dispatch when you have a concrete indicator — not as a general enrichment step."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "agent": {
                "type": "string",
                "enum": ["recon", "threat_intel", "forensics", "remediation"],
                "description": "The specialist agent to dispatch",
            },
            "objective": {
                "type": "string",
                "description": "Specific question or task for the specialist",
            },
            "context": {
                "type": "object",
                "description": "Relevant data to pass — IPs, hashes, hostnames, etc.",
            },
        },
        "required": ["agent", "objective", "context"],
    },
}


class DispatchTool:
    def __init__(
        self,
        dispatch_fn: Callable[..., Awaitable[str]],
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

- [ ] **Step 2: Write failing tests for `DispatchTool`**

Add to `tests/test_dispatch.py`:

```python
import pytest
from unittest.mock import AsyncMock
from core.dispatch import DispatchContext, DispatchTool


@pytest.mark.asyncio
async def test_dispatch_tool_calls_dispatch_fn():
    mock_fn = AsyncMock(return_value="forensics findings")
    ctx = DispatchContext()
    tool = DispatchTool(dispatch_fn=mock_fn, dispatch_context=ctx, caller_name="recon", sub_task_timeout=30.0)
    result = await tool.run(agent="forensics", objective="analyse hash", context={"hash": "abc"})
    assert result == "forensics findings"
    mock_fn.assert_called_once()


@pytest.mark.asyncio
async def test_dispatch_tool_blocks_self_dispatch():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext()
    tool = DispatchTool(dispatch_fn=mock_fn, dispatch_context=ctx, caller_name="recon", sub_task_timeout=30.0)
    result = await tool.run(agent="recon", objective="more recon", context={})
    assert "Cannot dispatch to self" in result
    mock_fn.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tool_respects_limit():
    mock_fn = AsyncMock(return_value="findings")
    ctx = DispatchContext(depth=2, max_depth=2)
    tool = DispatchTool(dispatch_fn=mock_fn, dispatch_context=ctx, caller_name="recon", sub_task_timeout=30.0)
    result = await tool.run(agent="forensics", objective="analyse", context={})
    assert "Dispatch limit reached" in result
    mock_fn.assert_not_called()


@pytest.mark.asyncio
async def test_dispatch_tool_handles_timeout():
    async def slow_fn(*args, **kwargs):
        await asyncio.sleep(100)
        return "never"
    ctx = DispatchContext()
    tool = DispatchTool(dispatch_fn=slow_fn, dispatch_context=ctx, caller_name="recon", sub_task_timeout=0.01)
    result = await tool.run(agent="forensics", objective="analyse", context={})
    assert "timed out" in result


@pytest.mark.asyncio
async def test_dispatch_tool_handles_exception():
    async def failing_fn(*args, **kwargs):
        raise RuntimeError("agent exploded")
    ctx = DispatchContext()
    tool = DispatchTool(dispatch_fn=failing_fn, dispatch_context=ctx, caller_name="recon", sub_task_timeout=30.0)
    result = await tool.run(agent="forensics", objective="analyse", context={})
    assert "failed" in result
    assert "agent exploded" in result
```

- [ ] **Step 3: Run to confirm tests pass**

```bash
pytest tests/test_dispatch.py -v
```
Expected: all passed

- [ ] **Step 4: Update `agents/base.py` — add `dispatch_context`, `dispatch_fn`, and tool-use loop helper**

The updated `agents/base.py`:

```python
import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from rich.console import Console

from core.dispatch import DispatchContext, DispatchTool, DISPATCH_TOOL_SCHEMA
from core.models import Alert, TaskStatus
from core.providers import ModelProvider
from core.storage import StorageBackend

MAX_TOOL_ITERATIONS = 5


class AgentBase(ABC):
    name: str = "base"

    def __init__(
        self,
        case_graph: StorageBackend,
        llm: ModelProvider,
        console: Console,
        agent_timeout: int = 120,
        dispatch_context: DispatchContext | None = None,
        dispatch_fn: Callable[..., Awaitable[str]] | None = None,
    ):
        self.graph = case_graph
        self.llm = llm
        self.console = console
        self.agent_timeout = agent_timeout
        self._event_log = None
        self.dispatch_context = dispatch_context
        self._dispatch_tool: DispatchTool | None = None

        if dispatch_context is not None and dispatch_fn is not None:
            self._dispatch_tool = DispatchTool(
                dispatch_fn=dispatch_fn,
                dispatch_context=dispatch_context,
                caller_name=self.name,
                sub_task_timeout=max(10, agent_timeout // 2),
            )

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    def log(self, message: str, style: str = "white") -> None:
        self.console.print(f"[bold cyan]\\[{self.name.upper()}][/bold cyan] {message}", style=style)

    async def run(self, task_node_id: str, alert: Alert) -> None:
        """Run the agent with a timeout. Marks task complete or failed."""
        self.graph.update_node_status(task_node_id, TaskStatus.RUNNING.value)
        if self._event_log:
            self._event_log.append(
                "agent_state",
                agent=self.name,
                data={"status": TaskStatus.RUNNING.value, "task_node_id": task_node_id},
            )
        try:
            await asyncio.wait_for(self._run(task_node_id, alert), timeout=self.agent_timeout)
            self.graph.update_node_status(task_node_id, TaskStatus.COMPLETED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={"status": TaskStatus.COMPLETED.value, "task_node_id": task_node_id},
                )
            self.log("✓ complete", style="green")
        except asyncio.TimeoutError:
            self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={"status": TaskStatus.FAILED.value, "task_node_id": task_node_id, "error": "timeout"},
                )
            self.log(f"✗ timed out after {self.agent_timeout}s", style="red")
        except Exception as e:
            self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={"status": TaskStatus.FAILED.value, "task_node_id": task_node_id, "error": str(e)},
                )
            self.log(f"✗ failed: {e}", style="red")

    async def _llm_call_with_dispatch(
        self,
        system: str,
        messages: list[dict],
    ) -> str:
        """
        LLM call with dispatch_agent tool support.

        If dispatch is available, sends the tool schema with the first call.
        If the LLM returns a tool_call for dispatch_agent, executes it and
        injects the result back into the conversation as context before the
        second call. Falls back to single-call behavior if no dispatch context.

        Returns the final text response.
        """
        tools = [DISPATCH_TOOL_SCHEMA] if self._dispatch_tool is not None else None
        current_messages = list(messages)

        for iteration in range(MAX_TOOL_ITERATIONS):
            response = await self.llm.call(
                system=system,
                messages=current_messages,
                tools=tools,
            )

            if not response.has_tool_calls:
                return response.text

            # Execute each tool call and collect results as context
            result_parts = []
            for tool_call in response.tool_calls:
                if tool_call["name"] == "dispatch_agent" and self._dispatch_tool is not None:
                    inp = tool_call["input"]
                    specialist_result = await self._dispatch_tool.run(
                        agent=inp.get("agent", ""),
                        objective=inp.get("objective", ""),
                        context=inp.get("context", {}),
                    )
                    if self._event_log:
                        self._event_log.append(
                            "agent_dispatch",
                            agent=self.name,
                            data={
                                "dispatched_to": inp.get("agent"),
                                "objective": inp.get("objective"),
                                "depth": self.dispatch_context.depth if self.dispatch_context else 0,
                            },
                        )
                    result_parts.append(
                        f"[Specialist findings from {inp.get('agent')}]\n{specialist_result}"
                    )

            if not result_parts:
                # Tool calls we don't handle — stop looping
                return response.text

            # Inject results as additional user context for next turn
            enriched_content = current_messages[-1]["content"] if current_messages else ""
            enriched_content += "\n\n" + "\n\n".join(result_parts)
            current_messages = [{"role": "user", "content": enriched_content}]
            # Don't send tools on follow-up — just want the final summary
            tools = None

        return response.text

    @abstractmethod
    async def _run(self, task_node_id: str, alert: Alert) -> None:
        """Subclasses implement their investigation logic here."""
        ...
```

- [ ] **Step 5: Run the test suite**

```bash
pytest tests/ -q --ignore=tests/test_dry_run_smoke.py --ignore=tests/test_integration.py
```
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add core/dispatch.py agents/base.py tests/test_dispatch.py
git commit -m "feat: add DispatchTool and AgentBase tool-use loop"
```

---

## Task 6: Update individual agents — SYSTEM_PROMPT and dispatch summary node

Each agent needs:
1. Updated `SYSTEM_PROMPT` with dispatch guidance
2. `_llm_call_with_dispatch()` used instead of direct `self.llm.call()`
3. Dispatch summary node written at end of `_run()` when running as a sub-task

**Files:**
- Modify: `agents/recon.py`
- Modify: `agents/threat_intel.py`
- Modify: `agents/forensics.py`
- Modify: `agents/remediation.py`

- [ ] **Step 1: Update `agents/recon.py`**

Replace the `SYSTEM_PROMPT` constant:
```python
SYSTEM_PROMPT = """You are a Reconnaissance Specialist in a SOC investigation.
You have access to IP lookup, WHOIS, and port scan tools.
Given an alert, gather all available information about the involved IPs, domains, hostnames.
Think step by step. Use tools in order: IP lookup → WHOIS → port scan.
Summarize what you found in 2-3 sentences.

If you discover a file hash, malware sample, or forensic artifact, use dispatch_agent to
request forensics analysis with the specific artifact as context. If you find a suspicious
IP with no clear attribution, use dispatch_agent to request threat_intel analysis.
Only dispatch when you have a specific concrete IOC — not as a general enrichment step."""
```

In `ReconAgent._run()`, replace the `llm.call()` line:
```python
# Before:
summary = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user_msg}])
# After:
summary = await self._llm_call_with_dispatch(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user_msg}])
```

After the existing `write_node` call for `recon-summary-{alert.id}`, add:
```python
# Write dispatch summary node when running as a dispatched sub-task
if self.dispatch_context is not None:
    self.graph.write_node(
        type="finding",
        label=f"dispatch-summary:recon:{task_node_id}",
        data={"summary": summary},
        created_by=self.name,
    )
```

- [ ] **Step 2: Update `agents/threat_intel.py`**

Replace `SYSTEM_PROMPT`:
```python
SYSTEM_PROMPT = """You are a Threat Intelligence Analyst in a SOC investigation.
Given the Case Graph findings (IPs, ports, domains), look up CVEs and threat feeds.
Identify what threat actor or campaign this may be associated with.
Respond with a 2-3 sentence threat assessment.

If threat feeds confirm an active campaign and you need endpoint evidence to corroborate it,
use dispatch_agent to request forensics analysis with the campaign IOCs as context.
Only dispatch when intelligence findings require validation against host evidence."""
```

Replace `llm.call()`:
```python
# Before:
assessment = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
assessment = await self._llm_call_with_dispatch(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
```

After `write_node` for `intel-assessment-{alert.id}`, add:
```python
if self.dispatch_context is not None:
    self.graph.write_node(
        type="finding",
        label=f"dispatch-summary:threat_intel:{task_node_id}",
        data={"summary": assessment},
        created_by=self.name,
    )
```

- [ ] **Step 3: Update `agents/forensics.py`**

Replace `SYSTEM_PROMPT`:
```python
SYSTEM_PROMPT = """You are a Digital Forensics Investigator in a SOC investigation.
Given the alert payload and parsed logs, reconstruct the attack timeline.
Identify: initial access vector, lateral movement, persistence, data touched.
List the timeline events in chronological order. Be specific about timestamps.

If timeline reconstruction reveals an unknown external IP or domain not already in the
case graph, use dispatch_agent to request recon or threat_intel analysis with that
specific indicator. Only dispatch when the timeline surfaces a new IOC."""
```

Replace `llm.call()` (line ~79):
```python
# Before:
analysis = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
analysis = await self._llm_call_with_dispatch(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
```

After the existing `write_node` for `attack-chain-{alert.id}`, add:
```python
if self.dispatch_context is not None:
    self.graph.write_node(
        type="finding",
        label=f"dispatch-summary:forensics:{task_node_id}",
        data={"summary": analysis},
        created_by=self.name,
    )
```

- [ ] **Step 4: Update `agents/remediation.py`**

Replace `SYSTEM_PROMPT` (add dispatch guidance at the end):
```python
SYSTEM_PROMPT = """You are a SOC Remediation Specialist.
Given the Case Graph findings (CVEs, timeline, threat intel), propose containment actions.
For each action return a JSON array. Each item must have:
  action_type: block_ip | disable_account | isolate_host | revoke_sessions | patch_recommendation
  target: the specific IP, account, host, or CVE to act on
  reason: why this action is needed
  urgency: immediate | within_24h | scheduled

Respond ONLY with a valid JSON array. No other text.

If a proposed action depends on live host state you don't have (e.g. confirming a process
is still running), use dispatch_agent to request recon with the specific query before
proposing the action. Only dispatch when an action depends on data you are missing."""
```

Replace `llm.call()`:
```python
# Before:
raw = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
# After:
raw = await self._llm_call_with_dispatch(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])
```

After the for-loop that processes proposals, add:
```python
if self.dispatch_context is not None:
    self.graph.write_node(
        type="finding",
        label=f"dispatch-summary:remediation:{task_node_id}",
        data={"summary": raw},
        created_by=self.name,
    )
```

- [ ] **Step 5: Run the full test suite**

```bash
pytest tests/ -q --ignore=tests/test_dry_run_smoke.py --ignore=tests/test_integration.py
```
Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add agents/recon.py agents/threat_intel.py agents/forensics.py agents/remediation.py
git commit -m "feat: add dispatch guidance and summary nodes to specialist agents"
```

---

## Task 7: Update `Commander` — `run_sub_task` and root `DispatchContext` wiring

**Files:**
- Modify: `agents/commander.py`

- [ ] **Step 1: Add `_current_alert` storage and root `DispatchContext` creation**

Add the import at the top of `commander.py`:
```python
from core.dispatch import DispatchContext
```

At the very top of `investigate()`, add the two assignments. The existing `raw = await self.llm.call(...)` line must use `.text` (fixed in Task 3) — preserve that fix:
```python
async def investigate(self, alert: Alert) -> None:
    self._current_alert = alert          # store for sub-task access
    self._root_dispatch_ctx = DispatchContext()   # one context per investigation

    # ... existing code ...
    # IMPORTANT: the llm.call() line in this method must remain:
    #   response = await self.llm.call(system=prompt, messages=[...])
    #   raw = response.text
    # Do NOT revert to the old `raw = await self.llm.call(...)` pattern.
```

- [ ] **Step 2: Pass `DispatchContext` to base DAG agents via `_build_agents()`**

In `_build_agents()`, update `kwargs`:
```python
def _build_agents(self):
    registry = self.integration_registry if self.integration_registry is not None else IntegrationRegistry()
    has_registry = self.integration_registry is not None

    ctx = getattr(self, "_root_dispatch_ctx", None)
    dispatch_fn = self.run_sub_task if ctx is not None else None

    kwargs = dict(
        case_graph=self.graph,
        llm=self.llm,
        console=self.console,
        agent_timeout=self.agent_timeout,
        dispatch_context=ctx,
        dispatch_fn=dispatch_fn,
    )
    # ... rest of method unchanged
```

- [ ] **Step 3: Add `_agent_timeout_for()`, `_build_single_agent()`, `_read_latest_findings()`, and `run_sub_task()`**

Add these methods to `Commander`:

```python
def _agent_timeout_for(self, agent_name: str) -> int:
    """Return the sub-task timeout: half of agent_timeout with a 10s floor."""
    return max(10, self.agent_timeout // 2)

def _build_single_agent(self, agent_name: str, ctx: DispatchContext, timeout: int):
    """Build a single named agent with full adapter wiring and dispatch context."""
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
    if agent_name == "recon":
        return ReconAgent(**base_kwargs, integration_registry=registry if has_registry else None)
    if agent_name == "threat_intel":
        return ThreatIntelAgent(
            **base_kwargs,
            threat_adapter=registry.adapters.get("threat_intel") if has_registry else None,
            use_env_adapter=not has_registry,
        )
    if agent_name == "forensics":
        return ForensicsAgent(
            **base_kwargs,
            entra_adapter=registry.adapters.get("entra") if has_registry else None,
            use_env_adapter=not has_registry,
        )
    if agent_name == "remediation":
        return RemediationAgent(
            **base_kwargs,
            auto_remediate=self.auto_remediate,
            execution_policy=self.execution_policy,
            defender_adapter=registry.adapters.get("defender") if has_registry else None,
            entra_adapter=registry.adapters.get("entra") if has_registry else None,
            approval_queue=self.approval_queue,
        )
    raise ValueError(f"Unknown dispatchable agent: {agent_name}")

def _read_latest_findings(self, agent_name: str, task_node_id: str) -> str:
    """Read the dispatch summary node written by a completed sub-task."""
    label = f"dispatch-summary:{agent_name}:{task_node_id}"
    nodes = self.graph.get_nodes_by_type("finding")
    match = next((n for n in nodes if n.get("label") == label), None)
    if match is None:
        return f"No findings returned by dispatched {agent_name} agent."
    return match.get("data", {}).get("summary", "No summary available.")

async def run_sub_task(
    self,
    agent_name: str,
    objective: str,
    context: dict,
    dispatch_context: DispatchContext,
) -> str:
    """Execute a named agent as a sub-task and return its findings as a string."""
    await dispatch_context._counter.increment()

    if self.event_log:
        self.event_log.append(
            "agent_dispatch",
            agent=agent_name,
            data={
                "objective": objective,
                "context": context,
                "depth": dispatch_context.depth,
                "sub_task_count": dispatch_context._counter.value,
            },
        )

    task_node_id = self.graph.write_node(
        type="task",
        label=f"dispatch:{agent_name}:{dispatch_context.depth}",
        data={"agent": agent_name, "objective": objective, "dispatched": True},
        created_by="dispatch",
    )

    child_ctx = dispatch_context.child(agent_name)
    sub_timeout = self._agent_timeout_for(agent_name)
    agent = self._build_single_agent(agent_name, child_ctx, sub_timeout)
    agent.attach_event_log(self.event_log)
    await agent.run(task_node_id, self._current_alert)

    return self._read_latest_findings(agent_name, task_node_id)
```

- [ ] **Step 4: Run the full test suite**

```bash
pytest tests/ -q --ignore=tests/test_dry_run_smoke.py --ignore=tests/test_integration.py
```
Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add agents/commander.py
git commit -m "feat: add run_sub_task and DispatchContext wiring to Commander"
```

---

## Task 8: Integration test — dry-run dispatch smoke test

Verify that a dry-run investigation with `MockLLMClient` produces a dispatch sub-task node in the case graph, confirming the full pipeline works end-to-end.

**Files:**
- Create: `tests/test_agent_dispatch_integration.py`

- [ ] **Step 1: Write the integration test**

```python
# tests/test_agent_dispatch_integration.py
"""
Integration smoke test: verifies that a dry-run investigation with MockLLMClient
produces at least one dispatch task node in the case graph when the alert type
triggers the mock dispatch logic (intrusion, malware, data_exfiltration).
"""
import asyncio
import pytest
from unittest.mock import MagicMock
from rich.console import Console

from core.mock_llm import MockLLMClient
from core.storage_sqlite import SQLiteStorageBackend
from core.models import Alert, AlertType, Severity
from core.event_log import EventLog
from agents.commander import Commander


@pytest.fixture
def tmp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    backend = SQLiteStorageBackend(db_path)
    return backend


@pytest.fixture
def mock_llm():
    client = MockLLMClient()
    return client


@pytest.fixture
def intrusion_alert():
    import uuid
    from datetime import datetime, timezone
    return Alert(
        id=str(uuid.uuid4()),
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        source_ip="185.220.101.45",
        dest_ip="10.0.1.50",
        dest_port=8080,
        hostname="web-prod-01",
        user_account="www-data",
        raw_payload={},
    )


@pytest.mark.asyncio
async def test_dry_run_produces_dispatch_task_node(tmp_db, mock_llm, intrusion_alert, tmp_path):
    """A dry-run intrusion investigation should produce at least one dispatch task node."""
    console = Console(quiet=True)
    event_log = EventLog(run_id="test-run", log_dir=str(tmp_path))
    mock_llm.set_alert_context(intrusion_alert)
    mock_llm.attach_event_log(event_log)

    commander = Commander(
        case_graph=tmp_db,
        llm=mock_llm,
        console=console,
        agent_timeout=30,
        commander_timeout=120,
        event_log=event_log,
        reports_dir=str(tmp_path),
    )

    await commander.investigate(intrusion_alert)

    # Check for at least one dispatch task node in the case graph
    all_tasks = tmp_db.get_nodes_by_type("task")
    dispatch_tasks = [t for t in all_tasks if t.get("label", "").startswith("dispatch:")]
    assert len(dispatch_tasks) >= 1, (
        f"Expected at least one dispatch task node. Found tasks: {[t['label'] for t in all_tasks]}"
    )


@pytest.mark.asyncio
async def test_dry_run_brute_force_no_dispatch(tmp_db, mock_llm, tmp_path):
    """A brute_force dry-run should NOT dispatch (not in high-severity dispatch types)."""
    import uuid
    from datetime import datetime, timezone

    alert = Alert(
        id=str(uuid.uuid4()),
        type=AlertType.BRUTE_FORCE,
        severity=Severity.MEDIUM,
        timestamp=datetime.now(timezone.utc),
        source_ip="203.0.113.99",
        dest_ip="10.0.0.10",
        dest_port=22,
        hostname="bastion-01",
        user_account="admin",
        raw_payload={},
    )

    console = Console(quiet=True)
    event_log = EventLog(run_id="test-run-bf", log_dir=str(tmp_path))
    mock_llm.set_alert_context(alert)
    mock_llm.attach_event_log(event_log)

    commander = Commander(
        case_graph=tmp_db,
        llm=mock_llm,
        console=console,
        agent_timeout=30,
        commander_timeout=120,
        event_log=event_log,
        reports_dir=str(tmp_path),
    )

    await commander.investigate(alert)

    all_tasks = tmp_db.get_nodes_by_type("task")
    dispatch_tasks = [t for t in all_tasks if t.get("label", "").startswith("dispatch:")]
    assert len(dispatch_tasks) == 0, (
        f"Expected no dispatch tasks for brute_force alert. Found: {[t['label'] for t in dispatch_tasks]}"
    )
```

- [ ] **Step 2: Run the integration test**

```bash
pytest tests/test_agent_dispatch_integration.py -v
```
Expected: both tests pass

- [ ] **Step 3: Run the full test suite including dry-run smoke test**

```bash
pytest tests/ -q
```
Expected: all pass (including `test_dry_run_smoke.py` — the existing dry-run must still work)

- [ ] **Step 4: Final commit**

```bash
git add tests/test_agent_dispatch_integration.py
git commit -m "test: add dispatch integration smoke tests"
```

---

## Verification Checklist

Before declaring implementation complete:

- [ ] `pytest tests/ -q` passes with no failures
- [ ] `python3 main.py investigate simulated --dry-run` completes successfully
- [ ] `SOC_PROVIDER=ollama SOC_MODEL=llama3:latest python3 main.py investigate simulated` runs end-to-end (dispatch may or may not fire depending on model)
- [ ] Event log contains `agent_dispatch` entries when dispatch is triggered
- [ ] No `dispatch:` task nodes appear in brute_force or anomaly dry-run investigations
