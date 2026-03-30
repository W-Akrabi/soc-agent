import asyncio
import json
from datetime import datetime, timezone
from rich.console import Console
from core.correlation import CorrelationService
from core.dispatch import DispatchContext
from core.execution_policy import ExecutionPolicy
from core.models import Alert, TaskStatus
from core.planner import Planner
from core.providers import ModelProvider
from core.scheduler import Scheduler
from core.schemas import WorkerTask
from core.storage import StorageBackend
from core.worker_queue import WorkerQueue
from integrations.registry import IntegrationRegistry
from agents.recon import ReconAgent
from agents.threat_intel import ThreatIntelAgent
from agents.forensics import ForensicsAgent
from agents.remediation import RemediationAgent
from agents.reporter import ReporterAgent

SYSTEM_PROMPT = """You are the Commander of a Security Operations Center investigation.
You receive a normalized security alert. Respond ONLY with valid JSON:
{"objective": "one sentence describing what happened", "priority_agents": ["recon", "threat_intel", "forensics"]}
Always include recon. Include threat_intel and forensics for all alerts. Include remediation only if severity is high or critical."""


class Commander:
    name = "commander"

    def __init__(self, case_graph: StorageBackend, llm: ModelProvider, console: Console,
                 agent_timeout: int = 120, commander_timeout: int = 300,
                 auto_remediate: bool = False, reports_dir: str = "./reports",
                 event_log=None, planner: Planner | None = None,
                 scheduler: Scheduler | None = None,
                 integration_registry: IntegrationRegistry | None = None,
                 execution_policy: ExecutionPolicy | None = None,
                 run_id: str | None = None,
                 correlation_service: CorrelationService | None = None,
                 memory_context_limit: int = 3,
                 approval_queue=None,
                 worker_queue: WorkerQueue | None = None,
                 worker_poll_interval: float = 1.0):
        self.graph = case_graph
        self.llm = llm
        self.console = console
        self.agent_timeout = agent_timeout
        self.commander_timeout = commander_timeout
        self.auto_remediate = auto_remediate
        self.reports_dir = reports_dir
        self.event_log = event_log
        self.planner = planner or Planner()
        self.scheduler = scheduler or Scheduler(default_timeout=float(agent_timeout))
        self.scheduler.attach_event_log(event_log)
        self.integration_registry = integration_registry
        self.execution_policy = execution_policy
        self.run_id = run_id
        self.correlation_service = correlation_service
        self.memory_context_limit = memory_context_limit
        self.approval_queue = approval_queue
        self.worker_queue = worker_queue
        self.worker_poll_interval = worker_poll_interval

    def log(self, message: str, style: str = "bold magenta") -> None:
        self.console.print(f"[bold magenta][COMMANDER][/bold magenta] {message}")

    async def investigate(self, alert: Alert) -> None:
        """Run the full investigation pipeline."""
        self._current_alert = alert
        self._root_dispatch_ctx = DispatchContext()
        start = datetime.now(timezone.utc)

        severity_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(alert.severity.value, "white")
        self.console.rule(
            f"[bold]SOC AGENT[/bold]  │  Alert: [bold]{alert.type.value.upper()}[/bold]  │  [{severity_color}]{alert.severity.value.upper()}[/{severity_color}]"
        )

        alert_node_id = self.graph.write_node(
            type="alert", label=alert.id,
            data={"type": alert.type.value, "severity": alert.severity.value,
                  "source_ip": alert.source_ip, "dest_ip": alert.dest_ip,
                  "hostname": alert.hostname, "user_account": alert.user_account},
            created_by=self.name
        )

        alert_summary = json.dumps({
            "type": alert.type.value, "severity": alert.severity.value,
            "source_ip": alert.source_ip, "dest_ip": alert.dest_ip,
            "dest_port": alert.dest_port, "hostname": alert.hostname,
            "user_account": alert.user_account,
        })
        prompt = SYSTEM_PROMPT
        if self.correlation_service is not None:
            try:
                prior_context = self.correlation_service.get_prior_context(alert)
            except Exception:
                prior_context = None
            if prior_context is not None and prior_context.has_context:
                prompt = f"{SYSTEM_PROMPT}\n\n{prior_context.format_for_prompt(limit=self.memory_context_limit)}"

        try:
            response = await self.llm.call(system=prompt, messages=[{"role": "user", "content": alert_summary}])
            raw = response.text if hasattr(response, "text") else str(response)
            plan = json.loads(raw)
        except Exception:
            plan = {"objective": f"Investigate {alert.type.value} alert", "priority_agents": ["recon", "threat_intel", "forensics"]}

        self.log(f"Alert received. Objective: {plan.get('objective', 'Investigate')}")

        agents_map = self._build_agents()

        try:
            await asyncio.wait_for(
                self._run_plan(alert, agents_map),
                timeout=self.commander_timeout
            )
        except asyncio.TimeoutError:
            self.log(f"Overall investigation timeout ({self.commander_timeout}s). Running reporter with available data.", style="red")
            await self._run_fallback_reporter(agents_map, alert)
        else:
            if not self._reporter_completed():
                self.log("Planned reporter did not complete. Running reporter with available data.", style="yellow")
                await self._run_fallback_reporter(agents_map, alert)

        elapsed = (datetime.now(timezone.utc) - start).seconds
        self.log(f"Investigation complete in {elapsed}s")

    async def _run_plan(self, alert: Alert, agents_map: dict) -> None:
        plan = self.planner.build_plan(alert)
        self.log(f"Plan created with {len(plan.tasks)} tasks")

        task_runners = {
            task.agent_name: self._build_task_runner(agents_map[task.agent_name], alert)
            for task in plan.tasks
            if task.agent_name in agents_map
        }
        await self.scheduler.run(plan, task_runners)

    def _build_task_runner(self, agent, alert: Alert):
        if self.worker_queue is not None and self.run_id:
            return self._build_remote_task_runner(alert)

        async def runner(planned_task):
            task_node_id = self.graph.write_node(
                "task",
                planned_task.task_id,
                {
                    "agent": planned_task.agent_name,
                    "objective": planned_task.objective,
                    "dependencies": planned_task.dependencies,
                    "soft_dependencies": planned_task.soft_dependencies,
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
        async def runner(planned_task):
            queue_task_id = f"{self.run_id}:{planned_task.task_id}"
            task_node_id = self.graph.write_node(
                "task",
                planned_task.task_id,
                {
                    "agent": planned_task.agent_name,
                    "objective": planned_task.objective,
                    "dependencies": planned_task.dependencies,
                    "soft_dependencies": planned_task.soft_dependencies,
                    "optional": planned_task.optional,
                },
                self.name,
                status=TaskStatus.QUEUED.value,
            )
            queue_record = self.worker_queue.enqueue(
                WorkerTask(
                    task_id=queue_task_id,
                    run_id=self.run_id,
                    plan_task_id=planned_task.task_id,
                    task_node_id=task_node_id,
                    agent_name=planned_task.agent_name,
                    alert_json=self._serialize_alert(alert),
                    db_path=self.graph.db_path,
                    status="pending",
                    created_at=datetime.now(timezone.utc).isoformat(),
                )
            )

            while True:
                queued_task = self.worker_queue.get_task(queue_record["task_id"])
                if queued_task is None:
                    raise RuntimeError(f"Remote task {queue_record['task_id']} disappeared from worker queue")
                status = queued_task["status"]
                if status == "completed":
                    graph_status = self.graph.get_task_status(task_node_id)
                    if graph_status != TaskStatus.COMPLETED.value:
                        raise RuntimeError(
                            f"Remote agent {planned_task.agent_name} finished with status {graph_status}"
                        )
                    result = queued_task.get("result_json") or {}
                    return {
                        "task_node_id": task_node_id,
                        "confidence": 1.0,
                        "worker_result": result,
                    }
                if status == "failed":
                    raise RuntimeError(
                        queued_task.get("error")
                        or f"Remote agent {planned_task.agent_name} failed"
                    )
                await asyncio.sleep(self.worker_poll_interval)

        return runner

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
        threat_adapter = registry.adapters.get("threat_intel") if has_registry else None
        entra_adapter = registry.adapters.get("entra") if has_registry else None
        defender_adapter = registry.adapters.get("defender") if has_registry else None

        agents_map = {
            "recon": ReconAgent(**kwargs, integration_registry=registry if has_registry else None),
            "threat_intel": ThreatIntelAgent(
                **kwargs,
                threat_adapter=threat_adapter,
                use_env_adapter=not has_registry,
            ),
            "forensics": ForensicsAgent(
                **kwargs,
                entra_adapter=entra_adapter,
                use_env_adapter=not has_registry,
            ),
            "remediation": RemediationAgent(
                **kwargs,
                auto_remediate=self.auto_remediate,
                execution_policy=self.execution_policy,
                defender_adapter=defender_adapter,
                entra_adapter=entra_adapter,
                approval_queue=self.approval_queue,
            ),
            "reporter": ReporterAgent(**kwargs, reports_dir=self.reports_dir),
        }
        for agent in agents_map.values():
            agent.attach_event_log(self.event_log)
        return agents_map

    def _reporter_completed(self) -> bool:
        for node in self.graph.get_nodes_by_type("task"):
            data = node.get("data") or {}
            if data.get("agent") == "reporter" and node.get("status") == TaskStatus.COMPLETED.value:
                return True
        return False

    async def _run_fallback_reporter(self, agents_map: dict, alert: Alert) -> None:
        reporter_task_id = self.graph.write_node(
            "task",
            "reporter-task",
            {"agent": "reporter"},
            self.name,
            status=TaskStatus.QUEUED.value,
        )
        await agents_map["reporter"].run(reporter_task_id, alert)

    def _agent_timeout_for(self, agent_name: str) -> int:
        return max(10, self.agent_timeout // 2)

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
        label = f"dispatch-summary:{agent_name}:{task_node_id}"
        nodes = self.graph.get_nodes_by_type("finding")
        match = next((node for node in nodes if node.get("label") == label), None)
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
        await dispatch_context._counter.increment()

        if self.event_log is not None:
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

    def _serialize_alert(self, alert: Alert) -> str:
        return json.dumps(
            {
                "id": alert.id,
                "type": alert.type.value,
                "severity": alert.severity.value,
                "timestamp": alert.timestamp.isoformat(),
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "source_port": alert.source_port,
                "dest_port": alert.dest_port,
                "hostname": alert.hostname,
                "user_account": alert.user_account,
                "process": alert.process,
                "tags": list(alert.tags),
                "raw_payload": alert.raw_payload,
            }
        )
