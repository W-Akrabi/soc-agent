from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field


DISPATCH_TOOL_SCHEMA = {
    "name": "dispatch_agent",
    "description": (
        "Request specialist analysis from another agent. Use when you discover a specific "
        "IOC or finding that requires deeper investigation beyond your own capability. "
        "Only dispatch when you have a concrete indicator, not as a general enrichment step."
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
                "description": "Relevant data to pass, including IPs, hashes, hostnames, or findings",
            },
        },
        "required": ["agent", "objective", "context"],
    },
}


@dataclass
class DispatchCounter:
    value: int = 0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False, compare=False)

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
    _counter: DispatchCounter = field(default_factory=DispatchCounter, repr=False, compare=False)

    _DENIED: frozenset[str] = frozenset({"reporter", "commander"})

    def can_dispatch(self, agent_name: str) -> bool:
        if agent_name in self._DENIED:
            return False
        return (
            self.depth < self.max_depth
            and self._counter.value < self.max_sub_tasks
            and agent_name not in self.dispatched_agents
        )

    def child(self, agent_name: str) -> "DispatchContext":
        return DispatchContext(
            depth=self.depth + 1,
            max_depth=self.max_depth,
            max_sub_tasks=self.max_sub_tasks,
            dispatched_agents=self.dispatched_agents | {agent_name},
            _counter=self._counter,
        )


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
        if not isinstance(agent, str) or not agent.strip():
            return "Invalid dispatch request: agent must be a non-empty string."
        if not isinstance(objective, str) or not objective.strip():
            return "Invalid dispatch request: objective must be a non-empty string."
        if context is None:
            context = {}
        elif not isinstance(context, dict):
            context = {"raw": context}

        agent_name = agent.strip()
        objective_text = objective.strip()

        if agent_name == self._caller:
            return f"Cannot dispatch to self ({self._caller})."
        if not self._context.can_dispatch(agent_name):
            return (
                f"Dispatch limit reached (depth={self._context.depth}, "
                f"sub_tasks={self._context._counter.value}). "
                "Proceeding with available findings."
            )
        try:
            return await asyncio.wait_for(
                self._dispatch_fn(agent_name, objective_text, context, self._context),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return f"Specialist agent '{agent_name}' timed out. Proceeding without those findings."
        except Exception as exc:
            return f"Specialist agent '{agent_name}' failed: {exc}. Proceeding without those findings."
