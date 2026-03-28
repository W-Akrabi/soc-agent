from datetime import datetime, timezone
import json

from core.models import ActionStatus, Alert, AlertType, Severity, TaskStatus, reconstruct_alert_from_json


def test_alert_type_enum():
    assert AlertType.INTRUSION.value == "intrusion"
    assert AlertType.MALWARE.value == "malware"
    assert AlertType.BRUTE_FORCE.value == "brute_force"
    assert AlertType.DATA_EXFILTRATION.value == "data_exfiltration"
    assert AlertType.ANOMALY.value == "anomaly"


def test_severity_enum():
    assert Severity.LOW.value == "low"
    assert Severity.CRITICAL.value == "critical"


def test_task_status_values():
    assert TaskStatus.QUEUED.value == "queued"
    assert TaskStatus.RUNNING.value == "running"
    assert TaskStatus.BLOCKED.value == "blocked"
    assert TaskStatus.COMPLETED.value == "completed"
    assert TaskStatus.FAILED.value == "failed"
    assert TaskStatus.CANCELLED.value == "cancelled"


def test_action_status_values():
    assert ActionStatus.PROPOSED.value == "proposed"
    assert ActionStatus.AWAITING_APPROVAL.value == "awaiting_approval"
    assert ActionStatus.APPROVED.value == "approved"
    assert ActionStatus.EXECUTING.value == "executing"
    assert ActionStatus.EXECUTED.value == "executed"
    assert ActionStatus.ROLLED_BACK.value == "rolled_back"
    assert ActionStatus.REJECTED.value == "rejected"
    assert ActionStatus.FAILED.value == "failed"


def test_alert_required_fields():
    alert = Alert(
        id="test-id",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={"raw": "data"},
    )
    assert alert.id == "test-id"
    assert alert.source_ip is None
    assert alert.tags == []


def test_alert_optional_fields():
    alert = Alert(
        id="test-id",
        type=AlertType.MALWARE,
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="1.2.3.4",
        user_account="jsmith",
        tags=["lateral-movement"],
    )
    assert alert.source_ip == "1.2.3.4"
    assert alert.user_account == "jsmith"
    assert "lateral-movement" in alert.tags


def test_reconstruct_alert_from_json_roundtrip():
    original = Alert(
        id="a1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc),
        raw_payload={"key": "value"},
        source_ip="10.0.0.1",
        hostname="web-01",
        dest_port=443,
    )
    alert_json = json.dumps(
        {
            "id": original.id,
            "type": original.type.value,
            "severity": original.severity.value,
            "timestamp": original.timestamp.isoformat(),
            "source_ip": original.source_ip,
            "dest_ip": None,
            "source_port": None,
            "dest_port": original.dest_port,
            "hostname": original.hostname,
            "user_account": None,
            "process": None,
            "tags": [],
            "raw_payload": original.raw_payload,
        }
    )

    reconstructed = reconstruct_alert_from_json(alert_json)
    assert reconstructed.id == "a1"
    assert reconstructed.type == AlertType.INTRUSION
    assert reconstructed.severity == Severity.HIGH
    assert reconstructed.source_ip == "10.0.0.1"
    assert reconstructed.hostname == "web-01"
    assert reconstructed.dest_port == 443
