from dataclasses import asdict
from datetime import datetime, timezone

from core.models import Alert, AlertType, Severity
from core.planner import Planner


def make_alert(alert_type, severity=Severity.HIGH, **overrides):
    values = {
        "id": "alert-1",
        "type": alert_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc),
        "raw_payload": {},
        "source_ip": "10.0.0.1",
        "dest_ip": "10.0.0.2",
        "dest_port": 443,
        "hostname": "host-01",
        "user_account": "jsmith",
        "process": "proc",
    }
    values.update(overrides)
    return Alert(**values)


def tasks_by_agent(plan):
    return {task.agent_name: task for task in plan.tasks}


def test_intrusion_plan_builds_expected_dag():
    planner = Planner()
    alert = make_alert(AlertType.INTRUSION, severity=Severity.HIGH)

    plan = planner.build_plan(alert)
    tasks = tasks_by_agent(plan)

    assert plan.alert_id == alert.id
    assert plan.alert_type == "intrusion"
    assert plan.objective.startswith("Investigate HIGH intrusion activity")
    assert tasks["recon"].dependencies == []
    assert tasks["threat_intel"].dependencies == [tasks["recon"].task_id]
    assert tasks["forensics"].dependencies == [tasks["recon"].task_id]
    assert tasks["remediation"].dependencies == [tasks["recon"].task_id]
    assert tasks["remediation"].soft_dependencies == [
        tasks["threat_intel"].task_id,
        tasks["forensics"].task_id,
    ]
    assert tasks["reporter"].dependencies == [
        tasks["recon"].task_id,
        tasks["threat_intel"].task_id,
        tasks["forensics"].task_id,
        tasks["remediation"].task_id,
    ]
    assert tasks["remediation"].optional is False
    assert tasks["recon"].max_retries == 1
    assert tasks["reporter"].timeout_override == 120
    assert plan == planner.build_plan(alert)


def test_brute_force_plan_marks_remediation_optional():
    planner = Planner()
    alert = make_alert(AlertType.BRUTE_FORCE, severity=Severity.MEDIUM)

    plan = planner.build_plan(alert)
    tasks = tasks_by_agent(plan)

    assert plan.alert_type == "brute_force"
    assert tasks["remediation"].optional is True
    assert tasks["remediation"].dependencies == [tasks["recon"].task_id]
    assert tasks["remediation"].soft_dependencies == [
        tasks["threat_intel"].task_id,
        tasks["forensics"].task_id,
    ]
    assert tasks["reporter"].dependencies[-1] == tasks["remediation"].task_id
    assert plan.early_stop_threshold == 0.80


def test_malware_plan_keeps_remediation_mandatory():
    planner = Planner()
    alert = make_alert(AlertType.MALWARE, severity=Severity.CRITICAL)

    plan = planner.build_plan(alert)
    tasks = tasks_by_agent(plan)

    assert plan.alert_type == "malware"
    assert tasks["remediation"].optional is False
    assert tasks["remediation"].dependencies == [tasks["recon"].task_id]
    assert tasks["remediation"].soft_dependencies == [
        tasks["threat_intel"].task_id,
        tasks["forensics"].task_id,
    ]
    assert plan.early_stop_threshold == 0.95


def test_anomaly_plan_uses_lower_threshold_and_optional_remediation():
    planner = Planner()
    alert = make_alert(AlertType.ANOMALY, severity=Severity.LOW)

    plan = planner.build_plan(alert)
    tasks = tasks_by_agent(plan)

    assert plan.alert_type == "anomaly"
    assert tasks["remediation"].optional is True
    assert plan.early_stop_threshold == 0.65


def test_unknown_type_uses_safe_fallback_plan():
    planner = Planner()

    class FakeAlert:
        id = "fake-1"
        type = "mystery"
        severity = "medium"
        hostname = "fallback-host"
        source_ip = "192.0.2.10"

    plan = planner.build_plan(FakeAlert())
    tasks = tasks_by_agent(plan)

    assert plan.alert_type == "mystery"
    assert tasks["recon"].agent_name == "recon"
    assert tasks["remediation"].optional is True
    assert tasks["reporter"].dependencies[-1] == tasks["remediation"].task_id
    assert plan.early_stop_threshold == planner.default_early_stop_threshold
