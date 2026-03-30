from dataclasses import fields
from datetime import datetime, timezone

import pytest

from core.models import ActionStatus
from core.schemas import (
    ActionProposal,
    AssetBaseline,
    EvidenceRecord,
    IncidentMemory,
    InvestigationRun,
    InvestigationTask,
    PendingAction,
    PriorContext,
    WorkerTask,
    validate_action_proposals,
)


def test_investigation_run_has_required_fields():
    required = {field.name for field in fields(InvestigationRun)}
    assert "run_id" in required
    assert "alert_id" in required
    assert "started_at" in required
    assert "db_path" in required
    assert "reports_dir" in required
    assert "dry_run" in required


def test_investigation_task_has_required_fields():
    required = {field.name for field in fields(InvestigationTask)}
    assert "task_id" in required
    assert "agent_name" in required
    assert "node_id" in required
    assert "status" in required


def test_evidence_record_has_required_fields():
    required = {field.name for field in fields(EvidenceRecord)}
    assert "evidence_id" in required
    assert "source_agent" in required
    assert "data" in required


def test_action_proposal_has_required_fields():
    required = {field.name for field in fields(ActionProposal)}
    assert "action_id" in required
    assert "action_type" in required
    assert "target" in required
    assert "reason" in required
    assert "urgency" in required
    assert "status" in required


def test_incident_memory_required_fields():
    required = {field.name for field in fields(IncidentMemory)}
    assert "memory_id" in required
    assert "incident_id" in required
    assert "run_id" in required
    assert "alert_type" in required
    assert "alert_json" in required
    assert "entities" in required
    assert "actions_taken" in required
    assert "started_at" in required


def test_asset_baseline_required_fields():
    required = {field.name for field in fields(AssetBaseline)}
    assert "baseline_id" in required
    assert "entity_type" in required
    assert "entity_value" in required
    assert "baseline_type" in required
    assert "incident_count" in required


def test_pending_action_required_fields():
    required = {field.name for field in fields(PendingAction)}
    assert "action_id" in required
    assert "run_id" in required
    assert "alert_id" in required
    assert "action_type" in required
    assert "target" in required
    assert "reason" in required
    assert "urgency" in required
    assert "blast_radius" in required
    assert "status" in required
    assert "created_at" in required


def test_worker_task_required_fields():
    required = {field.name for field in fields(WorkerTask)}
    assert "task_id" in required
    assert "run_id" in required
    assert "plan_task_id" in required
    assert "task_node_id" in required
    assert "agent_name" in required
    assert "alert_json" in required
    assert "db_path" in required
    assert "status" in required
    assert "created_at" in required


def test_investigation_run_instantiation():
    run = InvestigationRun(
        run_id="r1",
        alert_id="a1",
        started_at=datetime.now(timezone.utc),
        db_path="/tmp/test.db",
        reports_dir="/tmp/reports",
        dry_run=True,
    )
    assert run.dry_run is True


def test_action_proposal_default_status():
    proposal = ActionProposal(
        action_id="x1",
        action_type="block_ip",
        target="1.2.3.4",
        reason="test",
        urgency="immediate",
    )
    assert proposal.status == ActionStatus.PROPOSED


def test_prior_context_has_content_check():
    ctx = PriorContext(prior_incidents=[], entity_baselines=[])
    assert ctx.has_context is False
    mem = IncidentMemory(
        memory_id="m1",
        incident_id="i1",
        run_id="r1",
        alert_type="intrusion",
        alert_json="{}",
        entities={"hosts": ["web-01"]},
        actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    ctx2 = PriorContext(prior_incidents=[mem], entity_baselines=[])
    assert ctx2.has_context is True


def test_format_for_prompt_limit_truncates():
    def _memory(run_id: str) -> IncidentMemory:
        return IncidentMemory(
            memory_id=f"m-{run_id}",
            incident_id=f"i-{run_id}",
            run_id=run_id,
            alert_type="brute_force",
            alert_json="{}",
            entities={"ips": ["10.0.0.1"]},
            actions_taken=[],
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    text = PriorContext(
        prior_incidents=[_memory("run-AAA"), _memory("run-BBB")],
        entity_baselines=[],
    ).format_for_prompt(limit=1)
    assert text.count("run-") == 1


def test_pending_action_defaults():
    pending = PendingAction(
        action_id="a1",
        run_id="r1",
        alert_id="al1",
        action_type="block_ip",
        target="10.0.0.1",
        reason="C2 traffic",
        urgency="immediate",
        blast_radius="Blocks all traffic from 10.0.0.1",
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert pending.reviewed_at is None
    assert pending.reviewed_by is None
    assert pending.rollback_supported is False
    assert pending.rollback_action_type is None
    assert pending.execution_result is None


def test_worker_task_defaults():
    task = WorkerTask(
        task_id="t1",
        run_id="r1",
        plan_task_id="intrusion:recon",
        task_node_id="node-1",
        agent_name="recon",
        alert_json='{"id":"a1"}',
        db_path="./case.db",
        status="pending",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert task.worker_id is None
    assert task.claimed_at is None
    assert task.completed_at is None
    assert task.result_json is None
    assert task.error is None


def test_validate_action_proposals_happy_path():
    raw = (
        '[{"action_type": "block_ip", "target": "1.2.3.4", '
        '"reason": "scanner", "urgency": "immediate"}]'
    )
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].action_type == "block_ip"
    assert proposals[0].target == "1.2.3.4"


def test_validate_action_proposals_rejects_unsalvageable_single_object():
    with pytest.raises(ValueError, match="No valid action proposals"):
        validate_action_proposals('{"action_type": "block_ip"}')


def test_validate_action_proposals_rejects_missing_field():
    raw = '[{"action_type": "block_ip", "target": "1.2.3.4", "urgency": "immediate"}]'
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].reason.startswith("Model proposed block_ip")


def test_validate_action_proposals_rejects_invalid_json():
    with pytest.raises(ValueError, match="invalid"):
        validate_action_proposals("not json at all")


def test_validate_action_proposals_accepts_markdown_fenced_json():
    raw = """```json
    [
      {"action_type": "isolate_host", "target": "workstation-14", "reason": "possible malware", "urgency": "urgent"}
    ]
    ```"""
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].urgency == "immediate"


def test_validate_action_proposals_accepts_wrapper_object():
    raw = (
        '{"actions":[{"action":"disable_account","account":"jdoe",'
        '"description":"credential misuse risk","priority":"today"}]}'
    )
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].action_type == "disable_account"
    assert proposals[0].target == "jdoe"
    assert proposals[0].urgency == "within_24h"


def test_validate_action_proposals_skips_invalid_items_when_some_are_salvageable():
    raw = (
        '['
        '{"action_type":"block_ip","target":"1.2.3.4","reason":"scanner","urgency":"immediate"},'
        '{"foo":"bar"}'
        ']'
    )
    proposals = validate_action_proposals(raw)
    assert len(proposals) == 1
    assert proposals[0].target == "1.2.3.4"


def test_validate_action_proposals_rejects_when_no_items_salvageable():
    raw = '[{"foo":"bar"}]'
    with pytest.raises(ValueError, match="No valid action proposals"):
        validate_action_proposals(raw)
