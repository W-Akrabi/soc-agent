import asyncio
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from core.models import Alert, AlertType, Severity
from core.planner import Planner
from core.scheduler import Scheduler
from core.schemas import InvestigationPlan, PlannedTask


def make_alert(alert_type=AlertType.INTRUSION, severity=Severity.HIGH):
    return Alert(
        id="alert-1",
        type=alert_type,
        severity=severity,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        dest_port=443,
        hostname="host-01",
        user_account="jsmith",
        process="proc",
    )


class EventCollector:
    def __init__(self):
        self.entries = []

    def append(self, event_type, agent, data):
        self.entries.append({"event_type": event_type, "agent": agent, "data": data})


def plan_with_tasks(*tasks, plan_id="plan-1", alert_type="intrusion", objective="test", threshold=None):
    return InvestigationPlan(
        plan_id=plan_id,
        alert_id="alert-1",
        alert_type=alert_type,
        objective=objective,
        tasks=list(tasks),
        early_stop_threshold=threshold,
    )


@pytest.mark.asyncio
async def test_scheduler_runs_ready_tasks_concurrently():
    recon = PlannedTask(task_id="recon", agent_name="recon", objective="recon")
    intel = PlannedTask(task_id="intel", agent_name="threat_intel", objective="intel", dependencies=["recon"])
    forensics = PlannedTask(task_id="forensics", agent_name="forensics", objective="forensics", dependencies=["recon"])
    plan = plan_with_tasks(recon, intel, forensics, threshold=None)

    scheduler = Scheduler(default_timeout=1.0)

    started = []
    active = 0
    max_active = 0
    both_started = asyncio.Event()

    async def recon_runner(task):
        return {"confidence": 0.99, "task_id": task.task_id}

    async def parallel_runner(task):
        nonlocal active, max_active
        started.append(task.agent_name)
        active += 1
        max_active = max(max_active, active)
        if len(started) == 2:
            both_started.set()
        await both_started.wait()
        active -= 1
        return {"confidence": 0.98, "task_id": task.task_id}

    result = await asyncio.wait_for(
        scheduler.run(
            plan,
            {
                "recon": recon_runner,
                "threat_intel": parallel_runner,
                "forensics": parallel_runner,
            },
        ),
        timeout=2.0,
    )

    assert max_active == 2
    assert [task.status for task in result.task_results] == ["completed", "completed", "completed"]


@pytest.mark.asyncio
async def test_scheduler_retries_failures_and_emits_retry_event():
    task = PlannedTask(task_id="recon", agent_name="recon", objective="recon", max_retries=1)
    plan = plan_with_tasks(task, threshold=None)
    scheduler = Scheduler(default_timeout=1.0)
    events = EventCollector()
    scheduler.attach_event_log(events)

    attempts = {"count": 0}

    async def runner(_task):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("transient")
        return {"confidence": 0.9}

    result = await scheduler.run(plan, {"recon": runner})

    assert result.task_results[0].status == "completed"
    assert result.task_results[0].attempts == 2
    assert any(entry["event_type"] == "task_retry" for entry in events.entries)
    assert any(entry["event_type"] == "schedule_complete" for entry in events.entries)


@pytest.mark.asyncio
async def test_scheduler_applies_timeout_override_and_fails_closed():
    task = PlannedTask(
        task_id="recon",
        agent_name="recon",
        objective="recon",
        max_retries=1,
        timeout_override=0.01,
    )
    plan = plan_with_tasks(task, threshold=None)
    scheduler = Scheduler(default_timeout=1.0)

    async def runner(_task):
        await asyncio.sleep(0.05)
        return {"confidence": 0.5}

    result = await scheduler.run(plan, {"recon": runner})

    assert result.task_results[0].status == "failed"
    assert result.task_results[0].attempts == 2
    assert "timed out" in result.task_results[0].error


@pytest.mark.asyncio
async def test_scheduler_early_stop_skips_optional_tasks_only_after_mandatory_complete():
    recon = PlannedTask(task_id="recon", agent_name="recon", objective="recon")
    intel = PlannedTask(task_id="intel", agent_name="threat_intel", objective="intel", dependencies=["recon"])
    forensics = PlannedTask(task_id="forensics", agent_name="forensics", objective="forensics", dependencies=["recon"])
    remediation = PlannedTask(
        task_id="remediation",
        agent_name="remediation",
        objective="remediation",
        dependencies=["intel", "forensics"],
        optional=True,
    )
    reporter = PlannedTask(
        task_id="reporter",
        agent_name="reporter",
        objective="reporter",
        dependencies=["recon", "intel", "forensics", "remediation"],
    )
    plan = plan_with_tasks(recon, intel, forensics, remediation, reporter, threshold=0.9)
    scheduler = Scheduler(default_timeout=1.0)
    events = EventCollector()
    scheduler.attach_event_log(events)

    called = []

    async def runner(task):
        called.append(task.agent_name)
        if task.agent_name == "reporter":
            return {"confidence": 1.0}
        return {"confidence": 0.99}

    result = await scheduler.run(
        plan,
        {
            "recon": runner,
            "threat_intel": runner,
            "forensics": runner,
            "remediation": runner,
            "reporter": runner,
        },
    )

    statuses = {task.task_id: task.status for task in result.task_results}
    assert statuses["remediation"] == "skipped"
    assert statuses["reporter"] == "completed"
    assert result.early_stopped is True
    assert "remediation" not in called
    assert any(entry["event_type"] == "early_stop_triggered" for entry in events.entries)
