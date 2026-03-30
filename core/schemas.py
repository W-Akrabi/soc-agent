from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import json
import re
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
    soft_dependencies: list[str] = field(default_factory=list)
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


def _extract_json_payload(raw_json: str) -> Any:
    text = (raw_json or "").strip()
    if not text:
        raise ValueError("Action proposals JSON is invalid: empty response")

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        pass

    fenced = re.search(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char not in "[{":
            continue
        try:
            payload, _ = decoder.raw_decode(text[index:])
            return payload
        except json.JSONDecodeError:
            continue

    raise ValueError("Action proposals JSON is invalid: unable to locate JSON payload")


def _coerce_action_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("actions", "proposals", "items", "results"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        if any(key in payload for key in ("action_type", "action", "type", "target")):
            return [payload]
    raise ValueError(f"Expected a JSON array, got {type(payload).__name__}")


def _first_non_empty_string(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str):
            normalized = value.strip()
            if normalized:
                return normalized
    return None


def _normalize_urgency(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"immediate", "urgent", "critical", "asap", "now"}:
        return "immediate"
    if normalized in {"within_24h", "24h", "within24h", "today", "soon"}:
        return "within_24h"
    if normalized in {"scheduled", "later", "planned", "routine"}:
        return "scheduled"
    return "scheduled"


def _default_reason(action_type: str, target: str) -> str:
    return f"Model proposed {action_type} for {target} without an explicit reason."


def _normalize_action_item(item: dict[str, Any]) -> dict[str, str] | None:
    action_type = _first_non_empty_string(
        item.get("action_type"),
        item.get("action"),
        item.get("type"),
        item.get("name"),
    )
    target = _first_non_empty_string(
        item.get("target"),
        item.get("host"),
        item.get("hostname"),
        item.get("ip"),
        item.get("address"),
        item.get("account"),
        item.get("user"),
        item.get("entity"),
    )
    if not action_type or not target:
        return None

    reason = _first_non_empty_string(
        item.get("reason"),
        item.get("rationale"),
        item.get("description"),
        item.get("details"),
        item.get("why"),
    ) or _default_reason(action_type, target)
    urgency = _normalize_urgency(
        _first_non_empty_string(item.get("urgency"), item.get("priority"), item.get("severity"))
    )

    return {
        "action_type": action_type,
        "target": target,
        "reason": reason,
        "urgency": urgency,
    }


def validate_action_proposals(raw_json: str) -> list[ActionProposal]:
    """Parse and validate LLM action proposals before any execution path."""
    payload = _extract_json_payload(raw_json)
    items = _coerce_action_items(payload)

    if not items:
        raise ValueError("Expected a JSON array, got empty or unsupported payload")

    proposals: list[ActionProposal] = []
    for item in items:
        normalized = _normalize_action_item(item)
        if normalized is None:
            continue
        proposals.append(
            ActionProposal(
                action_id=str(uuid.uuid4()),
                action_type=normalized["action_type"],
                target=normalized["target"],
                reason=normalized["reason"],
                urgency=normalized["urgency"],
            )
        )

    if not proposals:
        raise ValueError("No valid action proposals could be recovered from model output")

    return proposals
