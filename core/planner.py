from __future__ import annotations

import uuid
from dataclasses import dataclass

from core.models import AlertType, Severity
from core.schemas import InvestigationPlan, PlannedTask


@dataclass(frozen=True)
class _TaskSpec:
    agent_name: str
    depends_on: tuple[str, ...] = ()
    optional: bool = False
    max_retries: int = 0
    timeout_override: int | None = None


class Planner:
    """Deterministically map an alert into a task DAG."""

    def __init__(self, default_early_stop_threshold: float = 0.85):
        self.default_early_stop_threshold = default_early_stop_threshold

    def build_plan(self, alert) -> InvestigationPlan:
        alert_type = self._normalize_alert_type(getattr(alert, "type", None))
        severity = self._normalize_severity(getattr(alert, "severity", None))

        objective = self._objective_for(alert_type, alert)
        plan_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"soc-agent:plan:{getattr(alert, 'id', 'unknown')}:{alert_type}:{severity}",
            )
        )

        task_specs, threshold = self._task_specs_for(alert_type, severity)
        tasks = self._materialize_tasks(alert_type, task_specs)

        return InvestigationPlan(
            plan_id=plan_id,
            alert_id=getattr(alert, "id", "unknown"),
            alert_type=alert_type,
            objective=objective,
            tasks=tasks,
            early_stop_threshold=threshold,
        )

    def _task_specs_for(self, alert_type: str, severity: str) -> tuple[list[_TaskSpec], float]:
        if alert_type == AlertType.INTRUSION.value:
            remediation_optional = severity not in (Severity.HIGH.value, Severity.CRITICAL.value)
            return (
                [
                    _TaskSpec("recon", timeout_override=60, max_retries=1),
                    _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=90, max_retries=1),
                    _TaskSpec("forensics", depends_on=("recon",), timeout_override=90),
                    _TaskSpec(
                        "remediation",
                        depends_on=("threat_intel", "forensics"),
                        optional=remediation_optional,
                        timeout_override=60,
                    ),
                    _TaskSpec(
                        "reporter",
                        depends_on=("recon", "threat_intel", "forensics", "remediation"),
                        timeout_override=120,
                    ),
                ],
                0.90,
            )

        if alert_type == AlertType.MALWARE.value:
            return (
                [
                    _TaskSpec("recon", timeout_override=60, max_retries=1),
                    _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=90, max_retries=1),
                    _TaskSpec("forensics", depends_on=("recon",), timeout_override=90),
                    _TaskSpec("remediation", depends_on=("threat_intel", "forensics"), timeout_override=60),
                    _TaskSpec(
                        "reporter",
                        depends_on=("recon", "threat_intel", "forensics", "remediation"),
                        timeout_override=120,
                    ),
                ],
                0.95,
            )

        if alert_type == AlertType.BRUTE_FORCE.value:
            return (
                [
                    _TaskSpec("recon", timeout_override=45, max_retries=1),
                    _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=75, max_retries=1),
                    _TaskSpec("forensics", depends_on=("recon",), timeout_override=75),
                    _TaskSpec(
                        "remediation",
                        depends_on=("threat_intel", "forensics"),
                        optional=True,
                        timeout_override=60,
                    ),
                    _TaskSpec(
                        "reporter",
                        depends_on=("recon", "threat_intel", "forensics", "remediation"),
                        timeout_override=90,
                    ),
                ],
                0.80,
            )

        if alert_type == AlertType.DATA_EXFILTRATION.value:
            return (
                [
                    _TaskSpec("recon", timeout_override=60, max_retries=1),
                    _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=90, max_retries=1),
                    _TaskSpec("forensics", depends_on=("recon",), timeout_override=90),
                    _TaskSpec("remediation", depends_on=("threat_intel", "forensics"), timeout_override=60),
                    _TaskSpec(
                        "reporter",
                        depends_on=("recon", "threat_intel", "forensics", "remediation"),
                        timeout_override=120,
                    ),
                ],
                0.95,
            )

        if alert_type == AlertType.ANOMALY.value:
            return (
                [
                    _TaskSpec("recon", timeout_override=45, max_retries=1),
                    _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=75, max_retries=1),
                    _TaskSpec("forensics", depends_on=("recon",), timeout_override=75),
                    _TaskSpec(
                        "remediation",
                        depends_on=("threat_intel", "forensics"),
                        optional=True,
                        timeout_override=60,
                    ),
                    _TaskSpec(
                        "reporter",
                        depends_on=("recon", "threat_intel", "forensics", "remediation"),
                        timeout_override=90,
                    ),
                ],
                0.65,
            )

        return (
            [
                _TaskSpec("recon", timeout_override=45, max_retries=1),
                _TaskSpec("threat_intel", depends_on=("recon",), timeout_override=75, max_retries=1),
                _TaskSpec("forensics", depends_on=("recon",), timeout_override=75),
                _TaskSpec(
                    "remediation",
                    depends_on=("threat_intel", "forensics"),
                    optional=True,
                    timeout_override=60,
                ),
                _TaskSpec(
                    "reporter",
                    depends_on=("recon", "threat_intel", "forensics", "remediation"),
                    timeout_override=90,
                ),
            ],
            self.default_early_stop_threshold,
        )

    def _materialize_tasks(self, alert_type: str, specs: list[_TaskSpec]) -> list[PlannedTask]:
        task_ids = {spec.agent_name: f"{alert_type}:{spec.agent_name}" for spec in specs}
        tasks: list[PlannedTask] = []
        for spec in specs:
            tasks.append(
                PlannedTask(
                    task_id=task_ids[spec.agent_name],
                    agent_name=spec.agent_name,
                    objective=self._objective_for_task(alert_type, spec.agent_name),
                    dependencies=[task_ids[dep] for dep in spec.depends_on],
                    optional=spec.optional,
                    max_retries=spec.max_retries,
                    timeout_override=spec.timeout_override,
                )
            )
        return tasks

    def _objective_for(self, alert_type: str, alert) -> str:
        hostname = getattr(alert, "hostname", None) or getattr(alert, "source_ip", None) or "the affected asset"
        severity = self._normalize_severity(getattr(alert, "severity", None)).upper()
        return f"Investigate {severity} {alert_type} activity on {hostname}"

    def _objective_for_task(self, alert_type: str, agent_name: str) -> str:
        return {
            "recon": f"Gather initial context for the {alert_type} alert",
            "threat_intel": f"Enrich the {alert_type} alert with external intelligence",
            "forensics": f"Reconstruct the timeline for the {alert_type} alert",
            "remediation": f"Propose containment for the {alert_type} alert",
            "reporter": f"Summarize the {alert_type} investigation",
        }.get(agent_name, f"Execute {agent_name} analysis for the {alert_type} alert")

    def _normalize_alert_type(self, value) -> str:
        if value is None:
            return "fallback"
        if isinstance(value, AlertType):
            return value.value
        return str(value).strip().lower().replace(" ", "_").replace("-", "_") or "fallback"

    def _normalize_severity(self, value) -> str:
        if value is None:
            return Severity.LOW.value
        if isinstance(value, Severity):
            return value.value
        normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        return normalized or Severity.LOW.value
