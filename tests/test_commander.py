import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rich.console import Console

from agents.commander import Commander
from core.case_graph import CaseGraph
from core.models import Alert, AlertType, Severity, TaskStatus
from core.schemas import InvestigationPlan, PlannedTask


def _make_alert():
    return Alert(
        id="cmd-alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={"logs": []},
        source_ip="185.220.101.45",
        dest_ip="10.0.1.50",
        dest_port=8080,
        hostname="web-prod-01",
    )


@pytest.fixture
def console():
    return Console(quiet=True)


@pytest.fixture
def graph(tmp_path):
    return CaseGraph(str(tmp_path / "commander.db"))


@pytest.mark.asyncio
async def test_commander_delegates_to_planner_and_scheduler(graph, console):
    alert = _make_alert()
    llm = MagicMock()
    llm.call = AsyncMock(return_value='{"objective":"Investigate","priority_agents":["recon"]}')

    plan = InvestigationPlan(
        plan_id="plan-1",
        alert_id=alert.id,
        alert_type=alert.type.value,
        objective="Investigate",
        tasks=[PlannedTask(task_id="intrusion:reporter", agent_name="reporter", objective="Summarize")],
    )
    planner = MagicMock()
    planner.build_plan.return_value = plan
    scheduler = MagicMock()
    scheduler.attach_event_log = MagicMock()
    scheduler.run = AsyncMock()

    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        planner=planner,
        scheduler=scheduler,
    )

    await commander.investigate(alert)

    planner.build_plan.assert_called_once_with(alert)
    scheduler.run.assert_called_once()
    nodes = graph.get_nodes_by_type("alert")
    assert len(nodes) == 1
    assert nodes[0]["label"] == alert.id


@pytest.mark.asyncio
async def test_commander_timeout_runs_reporter_with_available_data(graph, console, tmp_path):
    alert = _make_alert()
    llm = MagicMock()
    llm.call = AsyncMock(return_value='{"objective":"Investigate","priority_agents":["recon"]}')

    plan = InvestigationPlan(
        plan_id="plan-timeout",
        alert_id=alert.id,
        alert_type=alert.type.value,
        objective="Investigate",
        tasks=[PlannedTask(task_id="intrusion:recon", agent_name="recon", objective="Gather")],
    )
    planner = MagicMock()
    planner.build_plan.return_value = plan
    scheduler = MagicMock()
    scheduler.attach_event_log = MagicMock()
    scheduler.run = AsyncMock(side_effect=asyncio.TimeoutError())

    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        planner=planner,
        scheduler=scheduler,
        commander_timeout=0.01,
        reports_dir=str(tmp_path),
    )

    with patch("agents.commander.ReporterAgent.run", new=AsyncMock()) as reporter_run:
        await commander.investigate(alert)

    reporter_run.assert_awaited()
    task_nodes = graph.get_nodes_by_type("task")
    assert any(node["label"] == "reporter-task" and node["status"] == TaskStatus.QUEUED.value for node in task_nodes)


@pytest.mark.asyncio
async def test_commander_runs_fallback_reporter_when_planned_reporter_does_not_complete(graph, console, tmp_path):
    alert = _make_alert()
    llm = MagicMock()
    llm.call = AsyncMock(return_value='{"objective":"Investigate","priority_agents":["recon"]}')

    plan = InvestigationPlan(
        plan_id="plan-no-report",
        alert_id=alert.id,
        alert_type=alert.type.value,
        objective="Investigate",
        tasks=[
            PlannedTask(task_id="intrusion:recon", agent_name="recon", objective="Gather"),
            PlannedTask(
                task_id="intrusion:reporter",
                agent_name="reporter",
                objective="Summarize",
                dependencies=["intrusion:recon"],
            ),
        ],
    )
    planner = MagicMock()
    planner.build_plan.return_value = plan
    scheduler = MagicMock()
    scheduler.attach_event_log = MagicMock()
    scheduler.run = AsyncMock(return_value=None)

    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        planner=planner,
        scheduler=scheduler,
        reports_dir=str(tmp_path),
    )

    with patch("agents.commander.ReporterAgent.run", new=AsyncMock()) as reporter_run:
        await commander.investigate(alert)

    reporter_run.assert_awaited()
    task_nodes = graph.get_nodes_by_type("task")
    assert any(node["label"] == "reporter-task" for node in task_nodes)


@pytest.mark.asyncio
async def test_remote_task_runner_uses_scoped_queue_task_id(console):
    alert = _make_alert()
    graph = MagicMock()
    graph.db_path = "./case.db"
    graph.write_node.return_value = "task-node-1"
    graph.get_task_status.return_value = TaskStatus.COMPLETED.value

    worker_queue = MagicMock()
    worker_queue.enqueue.return_value = {"task_id": "run-123:intrusion:recon"}
    worker_queue.get_task.return_value = {"status": "completed", "result_json": {"ok": True}}

    commander = Commander(
        case_graph=graph,
        llm=MagicMock(),
        console=console,
        worker_queue=worker_queue,
        run_id="run-123",
    )

    runner = commander._build_remote_task_runner(alert)
    result = await runner(PlannedTask(task_id="intrusion:recon", agent_name="recon", objective="Gather"))

    enqueued_task = worker_queue.enqueue.call_args.args[0]
    assert enqueued_task.task_id == "run-123:intrusion:recon"
    assert enqueued_task.plan_task_id == "intrusion:recon"
    assert result["worker_result"] == {"ok": True}
