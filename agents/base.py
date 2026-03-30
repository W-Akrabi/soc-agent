import asyncio
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from rich.console import Console

from core.dispatch import DISPATCH_TOOL_SCHEMA, DispatchContext, DispatchTool
from core.llm_response import LLMResponse
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
        dispatch_fn: Callable[[str, str, dict, DispatchContext], Awaitable[str]] | None = None,
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

    def _normalize_llm_response(self, response) -> LLMResponse:
        if isinstance(response, LLMResponse):
            return response
        if isinstance(response, str):
            return LLMResponse(text=response, tool_calls=[])
        return LLMResponse(text=str(response), tool_calls=[])

    def _format_exception(self, exc: Exception) -> str:
        message = str(exc).strip()
        if message:
            return message
        return f"{type(exc).__name__}()"

    async def _llm_call_with_dispatch(self, system: str, messages: list[dict]) -> str:
        tools = [DISPATCH_TOOL_SCHEMA] if self._dispatch_tool is not None else None
        current_messages = list(messages)
        response = LLMResponse(text="", tool_calls=[])

        for _ in range(MAX_TOOL_ITERATIONS):
            raw_response = await self.llm.call(
                system=system,
                messages=current_messages,
                tools=tools,
            )
            response = self._normalize_llm_response(raw_response)
            if not response.has_tool_calls:
                return response.text

            tool_results: list[str] = []
            for tool_call in response.tool_calls:
                if tool_call.get("name") != "dispatch_agent" or self._dispatch_tool is None:
                    continue
                tool_input = tool_call.get("input") or {}
                specialist_result = await self._dispatch_tool.run(
                    agent=tool_input.get("agent", ""),
                    objective=tool_input.get("objective", ""),
                    context=tool_input.get("context", {}),
                )
                if self._event_log is not None:
                    self._event_log.append(
                        "agent_dispatch",
                        agent=self.name,
                        data={
                            "dispatched_to": tool_input.get("agent"),
                            "objective": tool_input.get("objective"),
                            "depth": self.dispatch_context.depth if self.dispatch_context else 0,
                        },
                    )
                tool_results.append(
                    f"[Specialist findings from {tool_input.get('agent', 'unknown')}]\n{specialist_result}"
                )

            if not tool_results:
                return response.text

            if response.text:
                current_messages.append({"role": "assistant", "content": response.text})
            current_messages.append({"role": "user", "content": "\n\n".join(tool_results)})
            tools = None

        return response.text

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
            self.log(f"✓ complete", style="green")
        except asyncio.TimeoutError:
            self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={
                        "status": TaskStatus.FAILED.value,
                        "task_node_id": task_node_id,
                        "error": "timeout",
                    },
                )
            self.log(f"✗ timed out after {self.agent_timeout}s", style="red")
        except asyncio.CancelledError:
            self.graph.update_node_status(task_node_id, TaskStatus.CANCELLED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={
                        "status": TaskStatus.CANCELLED.value,
                        "task_node_id": task_node_id,
                        "error": "cancelled",
                    },
                )
            self.log("✗ cancelled", style="red")
            raise
        except Exception as e:
            self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
            error_text = self._format_exception(e)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={
                        "status": TaskStatus.FAILED.value,
                        "task_node_id": task_node_id,
                        "error": error_text,
                    },
                )
            self.log(f"✗ failed: {error_text}", style="red")

    @abstractmethod
    async def _run(self, task_node_id: str, alert: Alert) -> None:
        """Subclasses implement their investigation logic here."""
        ...
