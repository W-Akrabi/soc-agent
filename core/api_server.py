from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
import threading
import urllib.parse
from collections.abc import Iterable
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from core.approval_identity import ApprovalIdentityError, ApprovalIdentityPolicy


Jsonable = Any


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._started_at = datetime.now(timezone.utc)
        self._counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._gauges: dict[str, dict[tuple[tuple[str, str], ...], float]] = {}
        self._summaries: dict[str, dict[tuple[tuple[str, str], ...], dict[str, float]]] = {}

    @staticmethod
    def _label_key(labels: dict[str, Any] | None = None) -> tuple[tuple[str, str], ...]:
        if not labels:
            return ()
        return tuple(sorted((str(key), str(value)) for key, value in labels.items()))

    @staticmethod
    def _format_labels(labels: tuple[tuple[str, str], ...]) -> str:
        if not labels:
            return ""
        return "{" + ",".join(f'{key}="{value}"' for key, value in labels) + "}"

    def inc(self, name: str, amount: float = 1.0, *, labels: dict[str, Any] | None = None) -> None:
        with self._lock:
            series = self._counters.setdefault(name, {})
            key = self._label_key(labels)
            series[key] = series.get(key, 0.0) + amount

    def set_gauge(self, name: str, value: float, *, labels: dict[str, Any] | None = None) -> None:
        with self._lock:
            series = self._gauges.setdefault(name, {})
            series[self._label_key(labels)] = float(value)

    def observe(self, name: str, value: float, *, labels: dict[str, Any] | None = None) -> None:
        with self._lock:
            series = self._summaries.setdefault(name, {})
            key = self._label_key(labels)
            slot = series.setdefault(key, {"count": 0.0, "sum": 0.0})
            slot["count"] += 1.0
            slot["sum"] += float(value)

    def record_api_request(self, method: str, path: str, status: int) -> None:
        self.inc(
            "soc_api_requests_total",
            labels={"method": method, "path": path, "status": str(status)},
        )

    def record_investigation_started(self) -> None:
        self.inc("soc_investigations_started_total")

    def record_investigation_completed(self, duration_seconds: float) -> None:
        self.inc("soc_investigations_completed_total")
        self.observe("soc_investigation_duration_seconds", duration_seconds)

    def record_investigation_failed(self, duration_seconds: float) -> None:
        self.inc("soc_investigations_failed_total")
        self.observe("soc_investigation_duration_seconds", duration_seconds)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds()
            self.set_gauge("soc_api_uptime_seconds", uptime)
            return {
                "uptime_seconds": uptime,
                "counters": {
                    name: [
                        {"labels": dict(labels), "value": value}
                        for labels, value in sorted(series.items())
                    ]
                    for name, series in sorted(self._counters.items())
                },
                "gauges": {
                    name: [
                        {"labels": dict(labels), "value": value}
                        for labels, value in sorted(series.items())
                    ]
                    for name, series in sorted(self._gauges.items())
                },
                "summaries": {
                    name: [
                        {"labels": dict(labels), "count": slot["count"], "sum": slot["sum"]}
                        for labels, slot in sorted(series.items())
                    ]
                    for name, series in sorted(self._summaries.items())
                },
            }

    def render_prometheus(self) -> str:
        with self._lock:
            uptime = (datetime.now(timezone.utc) - self._started_at).total_seconds()
            self.set_gauge("soc_api_uptime_seconds", uptime)
            lines: list[str] = []
            for name, series in sorted(self._counters.items()):
                lines.append(f"# TYPE {name} counter")
                for labels, value in sorted(series.items()):
                    lines.append(f"{name}{self._format_labels(labels)} {value:g}")
            for name, series in sorted(self._gauges.items()):
                lines.append(f"# TYPE {name} gauge")
                for labels, value in sorted(series.items()):
                    lines.append(f"{name}{self._format_labels(labels)} {value:g}")
            for name, series in sorted(self._summaries.items()):
                lines.append(f"# TYPE {name} summary")
                for labels, slot in sorted(series.items()):
                    label_text = self._format_labels(labels)
                    lines.append(f"{name}_count{label_text} {slot['count']:g}")
                    lines.append(f"{name}_sum{label_text} {slot['sum']:g}")
            return "\n".join(lines) + ("\n" if lines else "")


_METRICS_REGISTRY = MetricsRegistry()


def get_metrics_registry() -> MetricsRegistry:
    return _METRICS_REGISTRY


def reset_metrics_registry() -> MetricsRegistry:
    global _METRICS_REGISTRY
    _METRICS_REGISTRY = MetricsRegistry()
    return _METRICS_REGISTRY


def _to_jsonable(value: Any) -> Jsonable:
    if value is None:
        return None
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {key: _to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): _to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(item) for item in value]
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _to_jsonable(value.to_dict())
    if hasattr(value, "__dict__"):
        return {key: _to_jsonable(item) for key, item in vars(value).items() if not key.startswith("_")}
    return value


def _call_maybe_async(func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        return asyncio.run(result)
    return result


def _load_json(body: bytes) -> dict[str, Any]:
    if not body:
        return {}
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


@dataclass(slots=True)
class APIHandlers:
    load_alert: Callable[[str], Any]
    run_investigation: Callable[..., Any]
    list_approvals: Callable[..., Any]
    approve_action: Callable[..., Any]
    reject_action: Callable[..., Any]
    rollback_action: Callable[..., Any]
    recall_entity: Callable[..., Any]
    replay_run: Callable[..., Any]


def build_default_handlers(config) -> APIHandlers:
    from core.app import run_investigation
    from core.approval_queue import ApprovalQueue
    from core.memory_store import MemoryStore
    from core.replay import replay_investigation
    from ingestion.loader import load_alert

    memory_store = MemoryStore(
        config.memory_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    approval_queue = ApprovalQueue(
        config.approval_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )

    def list_approvals(*, status: str | None = None, limit: int | None = None):
        return approval_queue.list_actions(status=status, limit=limit)

    def approve_action(action_id: str, *, reviewed_by: str | None = None, execution_result=None, rollback_data=None):
        return approval_queue.approve(
            action_id,
            reviewed_by=reviewed_by,
            execution_result=execution_result,
            rollback_data=rollback_data,
        )

    def reject_action(action_id: str, *, reviewed_by: str | None = None):
        return approval_queue.reject(action_id, reviewed_by=reviewed_by)

    def rollback_action(
        action_id: str,
        *,
        reviewed_by: str | None = None,
        execution_result=None,
        rollback_data=None,
    ):
        return approval_queue.rollback(
            action_id,
            reviewed_by=reviewed_by,
            execution_result=execution_result,
            rollback_data=rollback_data,
        )

    def recall_entity(entity: str, *, limit: int = 5):
        entity_types = ("host", "user", "ip", "domain", "hash")
        seen_runs: set[str] = set()
        matches = []
        for entity_type in entity_types:
            for memory in memory_store.list_memories_for_entity(entity_type, entity, limit=limit):
                if memory.run_id in seen_runs:
                    continue
                seen_runs.add(memory.run_id)
                matches.append(memory)
        return matches[:limit]

    def replay_run(run_id: str, *, dry_run: bool = True):
        return replay_investigation(run_id, memory_store, config, dry_run=dry_run)

    return APIHandlers(
        load_alert=load_alert,
        run_investigation=run_investigation,
        list_approvals=list_approvals,
        approve_action=approve_action,
        reject_action=reject_action,
        rollback_action=rollback_action,
        recall_entity=recall_entity,
        replay_run=replay_run,
    )


class APIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def dispatch_api_request(
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    auth_token: str | None = None,
    approval_auth_token: str | None = None,
    approval_identities: Iterable[str] | str | None = None,
    handlers: APIHandlers,
    config=None,
    metrics_registry: MetricsRegistry | None = None,
) -> tuple[int, Any]:
    headers = {str(key): str(value) for key, value in (headers or {}).items()}
    parsed = urllib.parse.urlparse(path)
    clean_path = parsed.path.rstrip("/") or "/"
    query = parsed.query
    metrics = metrics_registry or get_metrics_registry()
    metrics_enabled = getattr(config, "enable_metrics", True) if config is not None else True
    identity_policy = ApprovalIdentityPolicy.from_config(
        config,
        general_token=auth_token,
        approval_token=approval_auth_token,
        allowed_reviewers=approval_identities,
    )
    is_approval_route = method == "POST" and re.match(r"^/api/approvals/(?P<action_id>.+)/(?P<action>approve|reject|rollback)$", clean_path)

    if clean_path != "/health":
        try:
            identity_policy.authorize(headers, approval_route=bool(is_approval_route))
        except ApprovalIdentityError as exc:
            raise APIError(exc.status, exc.message) from exc

    if method == "GET" and clean_path == "/health":
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"status": "ok"}

    if method == "GET" and clean_path in {"/metrics", "/api/metrics"}:
        if not metrics_enabled:
            raise APIError(HTTPStatus.NOT_FOUND, "metrics are disabled")
        payload = metrics.render_prometheus() if clean_path == "/metrics" else metrics.snapshot()
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, payload

    if method == "POST" and clean_path == "/api/investigations":
        payload = _load_json(body)
        source = str(payload.get("source") or "simulated")
        dry_run = bool(payload.get("dry_run", True))
        event_log_dir = payload.get("event_log_dir")
        timeout = payload.get("timeout")
        alert = handlers.load_alert(source)
        started_at = time.monotonic()
        metrics.record_investigation_started()
        try:
            result = _call_maybe_async(
                handlers.run_investigation,
                config=config,
                alert=alert,
                dry_run=dry_run,
                event_log_dir=event_log_dir,
                commander_timeout_override=timeout,
                console=None,
            )
        except Exception:
            duration = max(0.0, time.monotonic() - started_at)
            metrics.record_investigation_failed(duration)
            raise
        duration = max(0.0, time.monotonic() - started_at)
        metrics.record_investigation_completed(duration)
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"run": _to_jsonable(result)}

    if method == "GET" and clean_path == "/api/approvals":
        params = urllib.parse.parse_qs(query)
        status = params.get("status", [None])[0]
        limit_raw = params.get("limit", [None])[0]
        limit = int(limit_raw) if limit_raw is not None else None
        approvals = _call_maybe_async(handlers.list_approvals, status=status, limit=limit)
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"items": _to_jsonable(approvals)}

    approval_re = re.compile(r"^/api/approvals/(?P<action_id>.+)/(?P<action>approve|reject|rollback)$")
    if method == "POST" and (m := approval_re.match(clean_path)):
        try:
            payload = _load_json(body)
            action_id = urllib.parse.unquote(m.group("action_id"))
            action = m.group("action")
            reviewed_by = identity_policy.validate_reviewer(payload.get("reviewed_by"))
            execution_result = payload.get("execution_result")
            rollback_data = payload.get("rollback_data")
            if action == "approve":
                result = _call_maybe_async(
                    handlers.approve_action,
                    action_id,
                    reviewed_by=reviewed_by,
                    execution_result=execution_result,
                    rollback_data=rollback_data,
                )
            elif action == "reject":
                result = _call_maybe_async(
                    handlers.reject_action,
                    action_id,
                    reviewed_by=reviewed_by,
                )
            else:
                result = _call_maybe_async(
                    handlers.rollback_action,
                    action_id,
                    reviewed_by=reviewed_by,
                    execution_result=execution_result,
                    rollback_data=rollback_data,
                )
        except ApprovalIdentityError as exc:
            raise APIError(exc.status, exc.message) from exc
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"item": _to_jsonable(result)}

    recall_re = re.compile(r"^/api/memory/recall/(?P<entity>.+)$")
    if method == "GET" and (m := recall_re.match(clean_path)):
        params = urllib.parse.parse_qs(query)
        limit_raw = params.get("limit", [None])[0]
        limit = int(limit_raw) if limit_raw is not None else 5
        entity = urllib.parse.unquote(m.group("entity"))
        result = _call_maybe_async(handlers.recall_entity, entity, limit=limit)
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"entity": entity, "items": _to_jsonable(result)}

    replay_re = re.compile(r"^/api/replay/(?P<run_id>.+)$")
    if method == "POST" and (m := replay_re.match(clean_path)):
        payload = _load_json(body)
        params = urllib.parse.parse_qs(query)
        dry_run = bool(payload.get("dry_run", params.get("dry_run", ["true"])[0].lower() != "false"))
        run_id = urllib.parse.unquote(m.group("run_id"))
        result = _call_maybe_async(handlers.replay_run, run_id, dry_run=dry_run)
        metrics.record_api_request(method, clean_path, HTTPStatus.OK)
        return HTTPStatus.OK, {"run_id": run_id, "result": _to_jsonable(result)}

    raise APIError(HTTPStatus.NOT_FOUND, "route not found")


class SOCAPIHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        *,
        auth_token: str | None,
        approval_auth_token: str | None = None,
        approval_identities: Iterable[str] | str | None = None,
        handlers: APIHandlers,
        config=None,
        metrics_registry: MetricsRegistry | None = None,
    ):
        super().__init__(server_address, RequestHandlerClass)
        self.auth_token = auth_token or ""
        self.approval_auth_token = approval_auth_token or ""
        self.approval_identities = tuple(approval_identities) if approval_identities is not None and not isinstance(approval_identities, str) else approval_identities
        self.handlers = handlers
        self.config = config
        self.metrics_registry = metrics_registry or get_metrics_registry()


def create_api_server(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    auth_token: str | None = None,
    approval_auth_token: str | None = None,
    approval_identities: Iterable[str] | str | None = None,
    handlers: APIHandlers | None = None,
    config=None,
    metrics_registry: MetricsRegistry | None = None,
) -> SOCAPIHTTPServer:
    if handlers is None:
        if config is None:
            from core.config import Config

            config = Config.for_dry_run()
        handlers = build_default_handlers(config)
    if config is not None:
        host = getattr(config, "api_host", host)
        port = getattr(config, "api_port", port)
        if auth_token is None:
            auth_token = getattr(config, "api_token", None)
        if approval_auth_token is None:
            approval_auth_token = (
                getattr(config, "api_approver_token", None)
                or getattr(config, "approver_api_token", None)
                or getattr(config, "approver_token", None)
            )
        if approval_identities is None:
            approval_identities = (
                getattr(config, "approver_identities", None)
                or getattr(config, "approval_identities", None)
                or getattr(config, "api_approver_identities", None)
            )

    handler_cls = _build_handler_class()
    return SOCAPIHTTPServer(
        (host, port),
        handler_cls,
        auth_token=auth_token,
        approval_auth_token=approval_auth_token,
        approval_identities=approval_identities,
        handlers=handlers,
        config=config,
        metrics_registry=metrics_registry,
    )


def serve_api(
    host: str = "127.0.0.1",
    port: int = 8000,
    *,
    auth_token: str | None = None,
    approval_auth_token: str | None = None,
    approval_identities: Iterable[str] | str | None = None,
    handlers: APIHandlers | None = None,
    config=None,
    metrics_registry: MetricsRegistry | None = None,
) -> None:
    if config is not None:
        host = getattr(config, "api_host", host)
        port = getattr(config, "api_port", port)
        if auth_token is None:
            auth_token = getattr(config, "api_token", None)
        if approval_auth_token is None:
            approval_auth_token = (
                getattr(config, "api_approver_token", None)
                or getattr(config, "approver_api_token", None)
                or getattr(config, "approver_token", None)
            )
        if approval_identities is None:
            approval_identities = (
                getattr(config, "approver_identities", None)
                or getattr(config, "approval_identities", None)
                or getattr(config, "api_approver_identities", None)
            )
    server = create_api_server(
        host,
        port,
        auth_token=auth_token,
        approval_auth_token=approval_auth_token,
        approval_identities=approval_identities,
        handlers=handlers,
        config=config,
        metrics_registry=metrics_registry,
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _build_handler_class():
    recall_re = re.compile(r"^/api/memory/recall/(?P<entity>.+)$")
    replay_re = re.compile(r"^/api/replay/(?P<run_id>.+)$")
    approval_re = re.compile(r"^/api/approvals/(?P<action_id>.+)/(?P<action>approve|reject|rollback)$")

    class RequestHandler(BaseHTTPRequestHandler):
        server_version = "SOCAgentAPI/1.0"

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def _handle(self, method: str):
            metrics_registry = getattr(self.server, "metrics_registry", None)
            try:
                status, payload = dispatch_api_request(
                    method,
                    self.path,
                    headers=dict(self.headers.items()),
                    body=self._read_body(),
                    auth_token=self.server.auth_token,
                    approval_auth_token=self.server.approval_auth_token,
                    approval_identities=self.server.approval_identities,
                    handlers=self.server.handlers,
                    config=self.server.config,
                    metrics_registry=metrics_registry,
                )
                self._write_response(status, payload)
            except APIError as exc:
                if metrics_registry is not None:
                    metrics_registry.record_api_request(method, urllib.parse.urlparse(self.path).path.rstrip("/") or "/", exc.status)
                self._write_response(exc.status, {"error": exc.message})
            except ValueError as exc:
                if metrics_registry is not None:
                    metrics_registry.record_api_request(method, urllib.parse.urlparse(self.path).path.rstrip("/") or "/", HTTPStatus.BAD_REQUEST)
                self._write_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except json.JSONDecodeError as exc:
                if metrics_registry is not None:
                    metrics_registry.record_api_request(method, urllib.parse.urlparse(self.path).path.rstrip("/") or "/", HTTPStatus.BAD_REQUEST)
                self._write_response(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc.msg}"})
            except Exception as exc:  # pragma: no cover - defensive fallback
                if metrics_registry is not None:
                    metrics_registry.record_api_request(method, urllib.parse.urlparse(self.path).path.rstrip("/") or "/", HTTPStatus.INTERNAL_SERVER_ERROR)
                self._write_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _write_response(self, status: HTTPStatus, payload: Any):
            if isinstance(payload, str):
                body = payload.encode("utf-8")
                content_type = "text/plain; charset=utf-8"
            else:
                body = json.dumps(_to_jsonable(payload), separators=(",", ":"), ensure_ascii=True).encode("utf-8")
                content_type = "application/json"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # pragma: no cover - quiet test server
            return

    return RequestHandler


def start_server_in_thread(server: SOCAPIHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
