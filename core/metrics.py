from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Any, Iterable


def _normalize_labels(labels: dict[str, Any] | None = None) -> tuple[tuple[str, str], ...]:
    if not labels:
        return ()
    items = []
    for key, value in labels.items():
        if value is None:
            continue
        items.append((str(key), str(value)))
    return tuple(sorted(items))


def _labels_to_text(labels: tuple[tuple[str, str], ...]) -> str:
    if not labels:
        return ""
    parts = []
    for key, value in labels:
        escaped = value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
        parts.append(f'{key}="{escaped}"')
    return "{" + ",".join(parts) + "}"


@dataclass(slots=True)
class MetricDef:
    name: str
    kind: str
    help_text: str


_DEFAULT_METRICS: dict[str, MetricDef] = {
    "soc_investigations_started_total": MetricDef(
        name="soc_investigations_started_total",
        kind="counter",
        help_text="Total investigations started.",
    ),
    "soc_investigations_completed_total": MetricDef(
        name="soc_investigations_completed_total",
        kind="counter",
        help_text="Total investigations completed successfully.",
    ),
    "soc_investigations_failed_total": MetricDef(
        name="soc_investigations_failed_total",
        kind="counter",
        help_text="Total investigations that failed.",
    ),
    "soc_investigations_duration_seconds_total": MetricDef(
        name="soc_investigations_duration_seconds_total",
        kind="counter",
        help_text="Cumulative investigation duration in seconds.",
    ),
    "soc_investigations_duration_seconds_last": MetricDef(
        name="soc_investigations_duration_seconds_last",
        kind="gauge",
        help_text="Last observed investigation duration in seconds.",
    ),
    "soc_worker_heartbeats_total": MetricDef(
        name="soc_worker_heartbeats_total",
        kind="counter",
        help_text="Total worker heartbeats recorded.",
    ),
    "soc_worker_claims_total": MetricDef(
        name="soc_worker_claims_total",
        kind="counter",
        help_text="Total worker task claims.",
    ),
    "soc_worker_completions_total": MetricDef(
        name="soc_worker_completions_total",
        kind="counter",
        help_text="Total worker task completions.",
    ),
    "soc_worker_failures_total": MetricDef(
        name="soc_worker_failures_total",
        kind="counter",
        help_text="Total worker task failures.",
    ),
    "soc_worker_last_heartbeat_timestamp_seconds": MetricDef(
        name="soc_worker_last_heartbeat_timestamp_seconds",
        kind="gauge",
        help_text="Unix timestamp of the last heartbeat per worker.",
    ),
}


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = Lock()
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)

    def inc_counter(self, name: str, amount: float = 1.0, labels: dict[str, Any] | None = None) -> None:
        key = _normalize_labels(labels)
        with self._lock:
            current = self._counters[name].get(key, 0.0)
            self._counters[name][key] = current + float(amount)

    def set_gauge(self, name: str, value: float, labels: dict[str, Any] | None = None) -> None:
        key = _normalize_labels(labels)
        with self._lock:
            self._gauges[name][key] = float(value)

    def snapshot(self) -> dict[str, dict[tuple[tuple[str, str], ...], float]]:
        with self._lock:
            return {
                "counters": {name: dict(values) for name, values in self._counters.items()},
                "gauges": {name: dict(values) for name, values in self._gauges.items()},
            }

    def export_prometheus_text(self) -> str:
        with self._lock:
            lines: list[str] = []
            names = sorted(set(self._counters) | set(self._gauges))
            for name in names:
                metric_def = _DEFAULT_METRICS.get(
                    name,
                    MetricDef(name=name, kind="gauge" if name in self._gauges else "counter", help_text=name),
                )
                lines.append(f"# HELP {metric_def.name} {metric_def.help_text}")
                lines.append(f"# TYPE {metric_def.name} {metric_def.kind}")
                if metric_def.kind == "counter":
                    series = self._counters.get(name, {})
                else:
                    series = self._gauges.get(name, {})
                for labels, value in sorted(series.items(), key=lambda item: item[0]):
                    lines.append(f"{metric_def.name}{_labels_to_text(labels)} {value:g}")
            return "\n".join(lines) + ("\n" if lines else "")

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()


_REGISTRY = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    return _REGISTRY


def reset_registry() -> None:
    _REGISTRY.reset()


def export_metrics_text() -> str:
    return _REGISTRY.export_prometheus_text()


def get_counter_value(name: str, labels: dict[str, Any] | None = None) -> float:
    key = _normalize_labels(labels)
    snapshot = _REGISTRY.snapshot()["counters"]
    return float(snapshot.get(name, {}).get(key, 0.0))


def get_gauge_value(name: str, labels: dict[str, Any] | None = None) -> float:
    key = _normalize_labels(labels)
    snapshot = _REGISTRY.snapshot()["gauges"]
    return float(snapshot.get(name, {}).get(key, 0.0))


def record_investigation_started(*, alert_type: str, dry_run: bool) -> None:
    _REGISTRY.inc_counter(
        "soc_investigations_started_total",
        labels={"alert_type": alert_type, "dry_run": str(bool(dry_run)).lower()},
    )


def record_investigation_completed(*, alert_type: str, dry_run: bool, duration_seconds: float) -> None:
    labels = {"alert_type": alert_type, "dry_run": str(bool(dry_run)).lower()}
    _REGISTRY.inc_counter("soc_investigations_completed_total", labels=labels)
    _REGISTRY.inc_counter("soc_investigations_duration_seconds_total", amount=duration_seconds, labels=labels)
    _REGISTRY.set_gauge("soc_investigations_duration_seconds_last", duration_seconds, labels=labels)


def record_investigation_failed(*, alert_type: str, dry_run: bool, duration_seconds: float) -> None:
    labels = {"alert_type": alert_type, "dry_run": str(bool(dry_run)).lower()}
    _REGISTRY.inc_counter("soc_investigations_failed_total", labels=labels)
    _REGISTRY.inc_counter("soc_investigations_duration_seconds_total", amount=duration_seconds, labels=labels)
    _REGISTRY.set_gauge("soc_investigations_duration_seconds_last", duration_seconds, labels=labels)


def record_worker_heartbeat(*, worker_id: str, status: str, current_task_id: str | None = None) -> None:
    _REGISTRY.inc_counter(
        "soc_worker_heartbeats_total",
        labels={"worker_id": worker_id, "status": status},
    )
    # The timestamp gauge is wall-clock-ish rather than monotonic so that operators can compare with logs.
    from datetime import datetime, timezone

    _REGISTRY.set_gauge(
        "soc_worker_last_heartbeat_timestamp_seconds",
        datetime.now(timezone.utc).timestamp(),
        labels={"worker_id": worker_id, "status": status},
    )


def record_worker_claim(*, worker_id: str, task_id: str) -> None:
    _REGISTRY.inc_counter("soc_worker_claims_total", labels={"worker_id": worker_id, "task_id": task_id})


def record_worker_completion(*, worker_id: str, task_id: str) -> None:
    _REGISTRY.inc_counter("soc_worker_completions_total", labels={"worker_id": worker_id, "task_id": task_id})


def record_worker_failure(*, worker_id: str, task_id: str) -> None:
    _REGISTRY.inc_counter("soc_worker_failures_total", labels={"worker_id": worker_id, "task_id": task_id})
