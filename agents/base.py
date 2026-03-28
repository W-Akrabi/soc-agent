import asyncio
from abc import ABC, abstractmethod
from rich.console import Console
from core.models import Alert, TaskStatus
from core.providers import ModelProvider
from core.storage import StorageBackend


class AgentBase(ABC):
    name: str = "base"

    def __init__(self, case_graph: StorageBackend, llm: ModelProvider, console: Console,
                 agent_timeout: int = 120):
        self.graph = case_graph
        self.llm = llm
        self.console = console
        self.agent_timeout = agent_timeout
        self._event_log = None

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
        except Exception as e:
            self.graph.update_node_status(task_node_id, TaskStatus.FAILED.value)
            if self._event_log:
                self._event_log.append(
                    "agent_state",
                    agent=self.name,
                    data={
                        "status": TaskStatus.FAILED.value,
                        "task_node_id": task_node_id,
                        "error": str(e),
                    },
                )
            self.log(f"✗ failed: {e}", style="red")

    @abstractmethod
    async def _run(self, task_node_id: str, alert: Alert) -> None:
        """Subclasses implement their investigation logic here."""
        ...
