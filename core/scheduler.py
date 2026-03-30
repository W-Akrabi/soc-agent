from __future__ import annotations

import asyncio
import inspect
from collections.abc import Mapping
from typing import Any

from core.schemas import InvestigationPlan, PlannedTask, ScheduleResult, TaskExecutionResult


class Scheduler:
    """Execute a planned DAG with concurrency, retries, and early stop."""

    def __init__(self, default_timeout: float = 30.0, confidence_threshold: float | None = None):
        self.default_timeout = default_timeout
        self.confidence_threshold = confidence_threshold
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    async def run(
        self,
        plan: InvestigationPlan,
        task_runners: Mapping[str, Any],
    ) -> ScheduleResult:
        self._append_event(
            "plan_created",
            agent="scheduler",
            data={
                "plan_id": plan.plan_id,
                "alert_id": plan.alert_id,
                "alert_type": plan.alert_type,
                "task_count": len(plan.tasks),
                "threshold": self._threshold_for(plan),
            },
        )

        task_map = {task.task_id: task for task in plan.tasks}
        remaining = dict(task_map)
        task_results: dict[str, TaskExecutionResult] = {}
        completed: set[str] = set()
        failed: set[str] = set()
        blocked: set[str] = set()
        skipped: set[str] = set()
        early_stopped = False

        while remaining:
            self._block_unreachable_tasks(remaining, failed, blocked, task_results)

            if not remaining:
                break

            if self._should_early_stop(plan, task_results, remaining, completed, skipped, failed, blocked):
                skipped_now = [task for task in remaining.values() if task.optional]
                if skipped_now:
                    for task in skipped_now:
                        result = TaskExecutionResult(
                            task_id=task.task_id,
                            agent_name=task.agent_name,
                            status="skipped",
                            attempts=0,
                            skipped=True,
                        )
                        task_results[task.task_id] = result
                        skipped.add(task.task_id)
                    self._append_event(
                        "early_stop_triggered",
                        agent="scheduler",
                        data={
                            "plan_id": plan.plan_id,
                            "threshold": self._threshold_for(plan),
                            "confidence": self._mandatory_confidence(plan, task_results),
                            "skipped_task_ids": [task.task_id for task in skipped_now],
                        },
                    )
                    early_stopped = True
                    for task in skipped_now:
                        remaining.pop(task.task_id, None)
                    continue

            ready = [
                task
                for task in remaining.values()
                if self._deps_satisfied(task, completed, skipped, failed, blocked)
            ]
            if not ready:
                raise ValueError("Plan contains unsatisfiable or cyclic dependencies")

            batch_results = await asyncio.gather(
                *(self._run_task(task, task_runners) for task in ready)
            )
            for result in batch_results:
                task_results[result.task_id] = result
                remaining.pop(result.task_id, None)
                if result.status == "completed":
                    completed.add(result.task_id)
                elif result.status == "failed":
                    failed.add(result.task_id)
                elif result.status == "blocked":
                    blocked.add(result.task_id)
                elif result.status == "skipped":
                    skipped.add(result.task_id)

        ordered_results = [task_results[task.task_id] for task in plan.tasks if task.task_id in task_results]
        confidence = self._mandatory_confidence(plan, task_results)
        self._append_event(
            "schedule_complete",
            agent="scheduler",
            data={
                "plan_id": plan.plan_id,
                "task_count": len(plan.tasks),
                "completed": sum(1 for result in ordered_results if result.status == "completed"),
                "failed": sum(1 for result in ordered_results if result.status == "failed"),
                "blocked": sum(1 for result in ordered_results if result.status == "blocked"),
                "skipped": sum(1 for result in ordered_results if result.status == "skipped"),
                "early_stopped": early_stopped,
                "confidence": confidence,
            },
        )

        return ScheduleResult(
            plan_id=plan.plan_id,
            task_results=ordered_results,
            early_stopped=early_stopped,
            confidence=confidence,
            skipped_task_ids=[result.task_id for result in ordered_results if result.skipped],
        )

    async def _run_task(self, task: PlannedTask, task_runners: Mapping[str, Any]) -> TaskExecutionResult:
        runner = task_runners.get(task.agent_name)
        if runner is None:
            return TaskExecutionResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                status="failed",
                attempts=0,
                error=f"No runner registered for agent '{task.agent_name}'",
            )

        attempts = 0
        last_error: str | None = None
        timeout = max(task.timeout_override or 0, self.default_timeout) + 5.0

        while True:
            attempts += 1
            self._append_event(
                "task_scheduled",
                agent=task.agent_name,
                data={
                    "plan_task_id": task.task_id,
                    "attempt": attempts,
                    "timeout": timeout,
                    "optional": task.optional,
                },
            )
            try:
                output = await asyncio.wait_for(self._invoke_runner(runner, task), timeout=timeout)
                confidence = self._extract_confidence(output)
                return TaskExecutionResult(
                    task_id=task.task_id,
                    agent_name=task.agent_name,
                    status="completed",
                    attempts=attempts,
                    output=output,
                    confidence=confidence,
                )
            except asyncio.TimeoutError:
                last_error = f"timed out after {timeout}s"
            except Exception as e:
                last_error = self._format_exception(e)

            if attempts > task.max_retries:
                return TaskExecutionResult(
                    task_id=task.task_id,
                    agent_name=task.agent_name,
                    status="failed",
                    attempts=attempts,
                    error=last_error,
                )

            self._append_event(
                "task_retry",
                agent=task.agent_name,
                data={
                    "plan_task_id": task.task_id,
                    "attempt": attempts,
                    "error": last_error,
                },
            )

    def _format_exception(self, exc: Exception) -> str:
        message = str(exc).strip()
        if message:
            return message
        return f"{type(exc).__name__}()"

    async def _invoke_runner(self, runner: Any, task: PlannedTask) -> Any:
        candidate = None
        if callable(runner):
            candidate = runner(task)
        elif hasattr(runner, "run"):
            candidate = runner.run(task)
        else:
            raise TypeError(f"Runner for {task.agent_name} is not callable")

        if inspect.isawaitable(candidate):
            return await candidate
        return candidate

    def _deps_satisfied(
        self,
        task: PlannedTask,
        completed: set[str],
        skipped: set[str],
        failed: set[str] | None = None,
        blocked: set[str] | None = None,
    ) -> bool:
        failed = failed or set()
        blocked = blocked or set()
        hard_ready = all(dep in completed or dep in skipped for dep in task.dependencies)
        soft_ready = all(
            dep in completed or dep in skipped or dep in failed or dep in blocked
            for dep in task.soft_dependencies
        )
        return hard_ready and soft_ready

    def _block_unreachable_tasks(
        self,
        remaining: dict[str, PlannedTask],
        failed: set[str],
        blocked: set[str],
        task_results: dict[str, TaskExecutionResult],
    ) -> None:
        blocked_now = [
            task
            for task in remaining.values()
            if any(dep in failed or dep in blocked for dep in task.dependencies)
        ]
        for task in blocked_now:
            task_results[task.task_id] = TaskExecutionResult(
                task_id=task.task_id,
                agent_name=task.agent_name,
                status="blocked",
                attempts=0,
                error="dependency_failed",
            )
            blocked.add(task.task_id)
            remaining.pop(task.task_id, None)

    def _threshold_for(self, plan: InvestigationPlan) -> float | None:
        return plan.early_stop_threshold if plan.early_stop_threshold is not None else self.confidence_threshold

    def _mandatory_confidence(self, plan: InvestigationPlan, task_results: Mapping[str, TaskExecutionResult]) -> float | None:
        mandatory = [
            task
            for task in plan.tasks
            if not task.optional and task.agent_name != "reporter"
        ]
        if not mandatory:
            return None

        confidences: list[float] = []
        for task in mandatory:
            result = task_results.get(task.task_id)
            if result is None or result.status != "completed":
                return None
            confidences.append(result.confidence if result.confidence is not None else 1.0)

        return sum(confidences) / len(confidences)

    def _should_early_stop(
        self,
        plan: InvestigationPlan,
        task_results: Mapping[str, TaskExecutionResult],
        remaining: Mapping[str, PlannedTask],
        completed: set[str],
        skipped: set[str],
        failed: set[str],
        blocked: set[str],
    ) -> bool:
        threshold = self._threshold_for(plan)
        if threshold is None:
            return False

        if any(
            task.task_id not in completed
            for task in plan.tasks
            if not task.optional and task.agent_name != "reporter"
        ):
            return False

        confidence = self._mandatory_confidence(plan, task_results)
        if confidence is None or confidence < threshold:
            return False

        return any(task.optional for task in remaining.values()) and not failed and not blocked

    def _extract_confidence(self, output: Any) -> float:
        if isinstance(output, (int, float)):
            return float(output)
        if isinstance(output, dict) and isinstance(output.get("confidence"), (int, float)):
            return float(output["confidence"])
        return 1.0

    def _append_event(self, event_type: str, agent: str, data: dict) -> None:
        if self._event_log is not None:
            self._event_log.append(event_type, agent=agent, data=data)
