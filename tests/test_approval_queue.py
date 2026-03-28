from core.approval_queue import ApprovalQueue


def _pending_action(action_id: str = "action-1") -> dict:
    return {
        "action_id": action_id,
        "run_id": "run-1",
        "alert_id": "alert-1",
        "action_type": "isolate_host",
        "target": "web-prod-01",
        "reason": "containment required",
        "urgency": "immediate",
        "blast_radius": "Will isolate host 'web-prod-01' from the network.",
        "status": "awaiting_approval",
        "rollback_supported": True,
        "rollback_action_type": "unisolate_host",
        "rollback_data": {"machine_id": "machine-123"},
    }


def test_enqueue_normalizes_awaiting_approval_to_pending(tmp_path):
    queue = ApprovalQueue(str(tmp_path / "approvals.db"))

    stored = queue.enqueue(_pending_action())

    assert stored["action_id"] == "action-1"
    assert stored["status"] == "pending"
    assert stored["rollback_supported"] is True
    assert stored["rollback_action_type"] == "unisolate_host"

    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0]["action_id"] == "action-1"


def test_queue_transitions_persist_across_instances(tmp_path):
    db_path = str(tmp_path / "approvals.db")
    queue = ApprovalQueue(db_path)
    queue.enqueue(_pending_action("action-2"))

    approved = queue.approve("action-2", reviewed_by="analyst")
    assert approved["status"] == "approved"
    assert approved["reviewed_by"] == "analyst"
    assert approved["reviewed_at"] is not None

    reopened = ApprovalQueue(db_path)
    record = reopened.get("action-2")
    assert record is not None
    assert record["status"] == "approved"


def test_reject_and_rollback_update_status(tmp_path):
    queue = ApprovalQueue(str(tmp_path / "approvals.db"))
    queue.enqueue(_pending_action("action-3"))
    queue.enqueue({**_pending_action("action-4"), "action_type": "disable_account", "rollback_action_type": "enable_account"})

    rejected = queue.reject("action-3", reviewed_by="analyst")
    rolled_back = queue.rollback("action-4", reviewed_by="analyst", execution_result={"executed": True})

    assert rejected["status"] == "rejected"
    assert rolled_back["status"] == "rolled_back"


def test_enqueue_is_idempotent_for_same_pending_action(tmp_path):
    queue = ApprovalQueue(str(tmp_path / "approvals.db"))

    first = queue.enqueue(_pending_action("action-5"))
    second = queue.enqueue(_pending_action("action-6"))

    assert first["action_id"] == "action-5"
    assert second["action_id"] == "action-5"
    pending = queue.list_pending()
    assert len(pending) == 1
