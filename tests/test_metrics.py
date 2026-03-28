from core import metrics


def test_prometheus_export_formats_counters_and_gauges():
    metrics.reset_registry()
    registry = metrics.get_registry()
    registry.inc_counter("soc_example_counter_total", amount=2, labels={"a": "1", "b": "2"})
    registry.set_gauge("soc_example_gauge", 3.5, labels={"worker_id": "worker-1"})

    text = registry.export_prometheus_text()

    assert "# HELP soc_example_counter_total soc_example_counter_total" in text
    assert "# TYPE soc_example_counter_total counter" in text
    assert 'soc_example_counter_total{a="1",b="2"} 2' in text
    assert "# TYPE soc_example_gauge gauge" in text
    assert 'soc_example_gauge{worker_id="worker-1"} 3.5' in text


def test_high_level_helpers_record_metrics():
    metrics.reset_registry()

    metrics.record_investigation_started(alert_type="intrusion", dry_run=True)
    metrics.record_investigation_completed(alert_type="intrusion", dry_run=True, duration_seconds=1.25)
    metrics.record_investigation_failed(alert_type="malware", dry_run=False, duration_seconds=0.5)
    metrics.record_worker_heartbeat(worker_id="worker-1", status="idle")
    metrics.record_worker_claim(worker_id="worker-1", task_id="task-1")
    metrics.record_worker_completion(worker_id="worker-1", task_id="task-1")
    metrics.record_worker_failure(worker_id="worker-1", task_id="task-2")

    assert metrics.get_counter_value(
        "soc_investigations_started_total",
        {"alert_type": "intrusion", "dry_run": "true"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_investigations_completed_total",
        {"alert_type": "intrusion", "dry_run": "true"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_investigations_failed_total",
        {"alert_type": "malware", "dry_run": "false"},
    ) == 1
    assert metrics.get_gauge_value(
        "soc_investigations_duration_seconds_last",
        {"alert_type": "intrusion", "dry_run": "true"},
    ) == 1.25
    assert metrics.get_counter_value(
        "soc_worker_heartbeats_total",
        {"worker_id": "worker-1", "status": "idle"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_worker_claims_total",
        {"worker_id": "worker-1", "task_id": "task-1"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_worker_completions_total",
        {"worker_id": "worker-1", "task_id": "task-1"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_worker_failures_total",
        {"worker_id": "worker-1", "task_id": "task-2"},
    ) == 1
