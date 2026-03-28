from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import json
import uuid

from core.models import ActionStatus, TaskStatus


@dataclass
class InvestigationRun:
    run_id: str
    alert_id: str
    started_at: datetime
    db_path: str
    reports_dir: str
    dry_run: bool
    completed_at: datetime | None = None
    report_path: str | None = None


@dataclass
class InvestigationTask:
    task_id: str
    agent_name: str
    node_id: str
    status: TaskStatus = TaskStatus.QUEUED
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None


@dataclass
class EvidenceRecord:
    evidence_id: str
    source_agent: str
    data: dict[str, Any]
    node_id: str | None = None
    confidence: float | None = None


@dataclass
class ActionProposal:
    action_id: str
    action_type: str
    target: str
    reason: str
    urgency: str
    status: ActionStatus = ActionStatus.PROPOSED
    node_id: str | None = None
    blast_radius: str | None = None


@dataclass(slots=True)
class IntegrationQuery:
    alert_id: str
    alert_type: str
    entity_type: str
    entity_value: str
    time_range_hours: int = 24
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class NormalizedEvidence:
    source: str
    source_type: str
    entity_type: str
    entity_value: str
    title: str
    summary: str
    severity: str | None = None
    confidence: float | None = None
    observed_at: datetime | None = None
    raw_ref: str | None = None
    tags: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class EvidenceBatch:
    adapter_name: str
    query: IntegrationQuery
    records: list[NormalizedEvidence]
    partial: bool = False
    error: str | None = None


@dataclass(slots=True)
class ActionExecutionRequest:
    action_type: str
    target: str
    reason: str
    urgency: str
    requested_by: str
    allow_execution: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ActionExecutionResult:
    adapter_name: str
    action_type: str
    target: str
    status: str
    executed: bool
    external_id: str | None = None
    rollback_supported: bool = False
    message: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlannedTask:
    task_id: str
    agent_name: str
    objective: str
    dependencies: list[str] = field(default_factory=list)
    optional: bool = False
    max_retries: int = 0
    timeout_override: int | None = None


@dataclass
class InvestigationPlan:
    plan_id: str
    alert_id: str
    alert_type: str
    objective: str
    tasks: list[PlannedTask]
    early_stop_threshold: float | None = None


@dataclass
class TaskExecutionResult:
    task_id: str
    agent_name: str
    status: str
    attempts: int
    skipped: bool = False
    error: str | None = None
    output: Any | None = None
    confidence: float | None = None


@dataclass
class ScheduleResult:
    plan_id: str
    task_results: list[TaskExecutionResult]
    early_stopped: bool
    confidence: float | None = None
    skipped_task_ids: list[str] = field(default_factory=list)


@dataclass
class IncidentMemory:
    memory_id: str
    incident_id: str
    run_id: str
    alert_type: str
    alert_json: str
    entities: dict[str, list[str]]
    actions_taken: list[dict[str, Any]]
    started_at: str
    completed_at: str | None = None
    outcome: str | None = None
    analyst_notes: str | None = None
    confidence_score: float | None = None
    created_at: str | None = None


@dataclass
class AssetBaseline:
    baseline_id: str
    entity_type: str
    entity_value: str
    baseline_type: str
    first_seen: str
    last_seen: str
    incident_count: int = 1
    tags: list[str] = field(default_factory=list)


@dataclass
class PriorContext:
    prior_incidents: list[IncidentMemory]
    entity_baselines: list[AssetBaseline]

    @property
    def has_context(self) -> bool:
        return bool(self.prior_incidents or self.entity_baselines)

    def format_for_prompt(self, limit: int = 3) -> str:
        lines = ["[Prior Investigation Context]"]
        for incident in self.prior_incidents[:limit]:
            entities_summary = ", ".join(
                f"{key}: {value}" for key, value in incident.entities.items() if value
            )
            lines.append(
                f"- {incident.alert_type} incident on {incident.started_at[:10]} "
                f"(run {incident.run_id[:8]}): entities=[{entities_summary}] "
                f"outcome={incident.outcome or 'unknown'}"
            )
        for baseline in self.entity_baselines[:limit]:
            lines.append(
                f"- {baseline.entity_type} '{baseline.entity_value}': "
                f"{baseline.baseline_type}, seen in {baseline.incident_count} incident(s)"
            )
        return "\n".join(lines)


@dataclass
class PendingAction:
    action_id: str
    run_id: str
    alert_id: str
    action_type: str
    target: str
    reason: str
    urgency: str
    blast_radius: str
    status: str
    created_at: str
    reviewed_at: str | None = None
    reviewed_by: str | None = None
    rollback_supported: bool = False
    rollback_action_type: str | None = None
    rollback_data: dict[str, Any] = field(default_factory=dict)
    execution_result: dict[str, Any] | None = None


@dataclass
class WorkerTask:
    task_id: str
    run_id: str
    plan_task_id: str
    task_node_id: str
    agent_name: str
    alert_json: str
    db_path: str
    status: str
    created_at: str
    worker_id: str | None = None
    claimed_at: str | None = None
    completed_at: str | None = None
    result_json: str | None = None
    error: str | None = None
    lease_expires_at: str | None = None
    attempt_count: int = 0


@dataclass
class WorkerState:
    worker_id: str
    started_at: str
    last_heartbeat_at: str
    status: str
    current_task_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


def validate_action_proposals(raw_json: str) -> list[ActionProposal]:
    """Parse and validate LLM action proposals before any execution path."""
    try:
        items = json.loads(raw_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Action proposals JSON is invalid: {e}") from e

    if not isinstance(items, list):
        raise ValueError(f"Expected a JSON array, got {type(items).__name__}")

    proposals: list[ActionProposal] = []
    for index, item in enumerate(items):
        for field in ("action_type", "target", "reason", "urgency"):
            if field not in item:
                raise ValueError(
                    f"Action proposal[{index}] missing required field '{field}'"
                )
        proposals.append(
            ActionProposal(
                action_id=str(uuid.uuid4()),
                action_type=item["action_type"],
                target=item["target"],
                reason=item["reason"],
                urgency=item["urgency"],
            )
        )
    return proposals
