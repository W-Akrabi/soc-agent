from datetime import datetime, timezone
from types import SimpleNamespace

from unittest.mock import AsyncMock, MagicMock

import pytest
from core.api_server import (
    APIError,
    APIHandlers,
    create_api_server,
    dispatch_api_request,
    reset_metrics_registry,
    serve_api,
)
from core.models import Alert, AlertType, Severity
from core.schemas import InvestigationRun


def _make_alert() -> Alert:
    return Alert(
        id="alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        hostname="web-prod-01",
        source_ip="10.0.0.10",
    )


def _make_run() -> InvestigationRun:
    return InvestigationRun(
        run_id="run-1",
        alert_id="alert-1",
        started_at=datetime.now(timezone.utc),
        db_path="./cases.db",
        reports_dir="./reports",
        dry_run=True,
    )


@pytest.fixture
def api_context():
    config = SimpleNamespace(name="api-config")
    handlers = APIHandlers(
        load_alert=MagicMock(return_value=_make_alert()),
        run_investigation=AsyncMock(return_value=_make_run()),
        list_approvals=MagicMock(return_value=[{"action_id": "action-1", "status": "pending"}]),
        approve_action=MagicMock(return_value={"action_id": "action-1", "status": "approved"}),
        reject_action=MagicMock(return_value={"action_id": "action-1", "status": "rejected"}),
        rollback_action=MagicMock(return_value={"action_id": "action-1", "status": "rolled_back"}),
        recall_entity=MagicMock(return_value=[{"run_id": "run-1", "outcome": "contained"}]),
        replay_run=AsyncMock(return_value={"run_id": "run-1", "completed": True}),
    )
    return config, handlers


@pytest.fixture
def metrics_registry():
    return reset_metrics_registry()


def test_health_is_public(api_context):
    config, handlers = api_context
    status, payload = dispatch_api_request(
        "GET",
        "/health",
        headers={},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
    )

    assert status == 200
    assert payload == {"status": "ok"}


def test_protected_routes_require_bearer_token(api_context):
    config, handlers = api_context
    with pytest.raises(APIError) as excinfo:
        dispatch_api_request(
            "GET",
            "/api/approvals",
            headers={},
            body=b"",
            auth_token="secret",
            handlers=handlers,
            config=config,
        )

    assert excinfo.value.status == 401
    assert "missing or invalid bearer token" in excinfo.value.message


def test_approval_routes_use_separate_approver_token_when_configured(api_context):
    config, handlers = api_context
    config.api_token = "general-token"
    config.api_approver_token = "approval-token"
    config.approver_identities = ("analyst1",)
    import json

    with pytest.raises(APIError) as excinfo:
        dispatch_api_request(
            "POST",
            "/api/approvals/action-1/approve",
            headers={"Authorization": "Bearer general-token"},
            body=json.dumps({"reviewed_by": "analyst1"}).encode("utf-8"),
            auth_token="general-token",
            approval_auth_token="approval-token",
            approval_identities=("analyst1",),
            handlers=handlers,
            config=config,
        )
    assert excinfo.value.status == 401

    status, payload = dispatch_api_request(
        "POST",
        "/api/approvals/action-1/approve",
        headers={"Authorization": "Bearer approval-token"},
        body=json.dumps({"reviewed_by": "analyst1"}).encode("utf-8"),
        auth_token="general-token",
        approval_auth_token="approval-token",
        approval_identities=("analyst1",),
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["item"]["status"] == "approved"


def test_investigation_endpoint_runs_via_injected_handler(api_context):
    config, handlers = api_context
    import json

    status, payload = dispatch_api_request(
        "POST",
        "/api/investigations",
        headers={"Authorization": "Bearer secret"},
        body=json.dumps({"source": "simulated", "dry_run": True}).encode("utf-8"),
        auth_token="secret",
        handlers=handlers,
        config=config,
    )

    assert status == 200
    assert "run" in payload
    handlers.load_alert.assert_called_once_with("simulated")
    handlers.run_investigation.assert_awaited_once()
    assert handlers.run_investigation.call_args.kwargs["config"] is config
    assert handlers.run_investigation.call_args.kwargs["dry_run"] is True


def test_approvals_and_action_routes_use_injected_handlers(api_context):
    config, handlers = api_context
    import json

    status, payload = dispatch_api_request(
        "GET",
        "/api/approvals?status=pending&limit=5",
        headers={"Authorization": "Bearer secret"},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["items"][0]["action_id"] == "action-1"

    status, payload = dispatch_api_request(
        "POST",
        "/api/approvals/action-1/approve",
        headers={"Authorization": "Bearer secret"},
        body=json.dumps({"reviewed_by": "analyst"}).encode("utf-8"),
        auth_token="secret",
        approval_identities=("analyst",),
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["item"]["status"] == "approved"

    status, payload = dispatch_api_request(
        "POST",
        "/api/approvals/action-1/reject",
        headers={"Authorization": "Bearer secret"},
        body=json.dumps({"reviewed_by": "analyst"}).encode("utf-8"),
        auth_token="secret",
        approval_identities=("analyst",),
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["item"]["status"] == "rejected"

    status, payload = dispatch_api_request(
        "POST",
        "/api/approvals/action-1/rollback",
        headers={"Authorization": "Bearer secret"},
        body=json.dumps({"reviewed_by": "analyst"}).encode("utf-8"),
        auth_token="secret",
        approval_identities=("analyst",),
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["item"]["status"] == "rolled_back"

    handlers.list_approvals.assert_called_once_with(status="pending", limit=5)
    handlers.approve_action.assert_called_once_with(
        "action-1",
        reviewed_by="analyst",
        execution_result=None,
        rollback_data=None,
    )


def test_metrics_endpoints_expose_shared_registry(api_context, metrics_registry):
    config, handlers = api_context

    status, payload = dispatch_api_request(
        "GET",
        "/api/approvals",
        headers={"Authorization": "Bearer secret"},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
        metrics_registry=metrics_registry,
    )
    assert status == 200
    assert payload["items"][0]["action_id"] == "action-1"

    status, payload = dispatch_api_request(
        "GET",
        "/api/metrics",
        headers={"Authorization": "Bearer secret"},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
        metrics_registry=metrics_registry,
    )
    assert status == 200
    approvals_counter = payload["counters"]["soc_api_requests_total"]
    assert any(
        item["labels"] == {"method": "GET", "path": "/api/approvals", "status": "200"} and item["value"] == 1.0
        for item in approvals_counter
    )
    assert payload["gauges"]["soc_api_uptime_seconds"]

    status, payload = dispatch_api_request(
        "GET",
        "/metrics",
        headers={"Authorization": "Bearer secret"},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
        metrics_registry=metrics_registry,
    )
    assert status == 200
    assert "# TYPE soc_api_requests_total counter" in payload
    assert 'soc_api_requests_total{method="GET",path="/api/approvals",status="200"} 1' in payload


def test_metrics_endpoints_respect_config_switch(api_context, metrics_registry):
    config, handlers = api_context
    config.enable_metrics = False

    with pytest.raises(APIError) as excinfo:
        dispatch_api_request(
            "GET",
            "/metrics",
            headers={"Authorization": "Bearer secret"},
            body=b"",
            auth_token="secret",
            handlers=handlers,
            config=config,
            metrics_registry=metrics_registry,
        )
    assert excinfo.value.status == 404

    with pytest.raises(APIError) as excinfo:
        dispatch_api_request(
            "GET",
            "/api/metrics",
            headers={"Authorization": "Bearer secret"},
            body=b"",
            auth_token="secret",
            handlers=handlers,
            config=config,
            metrics_registry=metrics_registry,
        )
    assert excinfo.value.status == 404


def test_approval_routes_reject_missing_or_invalid_reviewer(api_context):
    config, handlers = api_context
    import json

    with pytest.raises(APIError) as missing:
        dispatch_api_request(
            "POST",
            "/api/approvals/action-1/approve",
            headers={"Authorization": "Bearer secret"},
            body=json.dumps({}).encode("utf-8"),
            auth_token="secret",
            approval_identities=("analyst1",),
            handlers=handlers,
            config=config,
        )
    assert missing.value.status == 400

    with pytest.raises(APIError) as invalid:
        dispatch_api_request(
            "POST",
            "/api/approvals/action-1/approve",
            headers={"Authorization": "Bearer secret"},
            body=json.dumps({"reviewed_by": "outsider"}).encode("utf-8"),
            auth_token="secret",
            approval_identities=("analyst1",),
            handlers=handlers,
            config=config,
        )
    assert invalid.value.status == 403


def test_recall_and_replay_routes_use_injected_handlers(api_context):
    config, handlers = api_context
    import json

    status, payload = dispatch_api_request(
        "GET",
        "/api/memory/recall/web-prod-01?limit=2",
        headers={"Authorization": "Bearer secret"},
        body=b"",
        auth_token="secret",
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["entity"] == "web-prod-01"

    status, payload = dispatch_api_request(
        "POST",
        "/api/replay/run-1",
        headers={"Authorization": "Bearer secret"},
        body=json.dumps({"dry_run": False}).encode("utf-8"),
        auth_token="secret",
        handlers=handlers,
        config=config,
    )
    assert status == 200
    assert payload["run_id"] == "run-1"

    handlers.recall_entity.assert_called_once_with("web-prod-01", limit=2)
    handlers.replay_run.assert_awaited_once_with("run-1", dry_run=False)


def test_create_api_server_uses_config_defaults(api_context, monkeypatch):
    config, handlers = api_context
    config.api_host = "127.0.0.1"
    config.api_port = 8080
    config.api_token = "secret"
    config.api_approver_token = "approval-secret"
    config.approver_identities = ("analyst1", "lead")
    captured = {}

    class FakeServer:
        def __init__(
            self,
            server_address,
            handler_cls,
            *,
            auth_token,
            approval_auth_token=None,
            approval_identities=None,
            handlers,
            config,
            metrics_registry=None,
        ):
            captured["server_address"] = server_address
            captured["auth_token"] = auth_token
            captured["approval_auth_token"] = approval_auth_token
            captured["approval_identities"] = approval_identities
            captured["handlers"] = handlers
            captured["config"] = config
            captured["metrics_registry"] = metrics_registry

    monkeypatch.setattr("core.api_server.SOCAPIHTTPServer", FakeServer)

    server = create_api_server(handlers=handlers, config=config)

    assert isinstance(server, FakeServer)
    assert captured["server_address"] == ("127.0.0.1", 8080)
    assert captured["auth_token"] == "secret"
    assert captured["handlers"] is handlers
    assert captured["config"] is config
    assert captured["metrics_registry"] is None
    assert captured["approval_auth_token"] == "approval-secret"
    assert captured["approval_identities"] == ("analyst1", "lead")


def test_serve_api_uses_config_defaults(api_context, monkeypatch):
    config, handlers = api_context
    config.api_host = "127.0.0.1"
    config.api_port = 8081
    config.api_token = "secret"
    config.api_approver_token = "approval-secret"
    config.approver_identities = ("analyst1",)

    events = []

    class FakeServer:
        def serve_forever(self):
            events.append("serve_forever")

        def server_close(self):
            events.append("server_close")

    def fake_create_api_server(
        host="127.0.0.1",
        port=8000,
        *,
        auth_token=None,
        approval_auth_token=None,
        approval_identities=None,
        handlers=None,
        config=None,
        metrics_registry=None,
    ):
        events.append((
            "create",
            host,
            port,
            auth_token,
            approval_auth_token,
            approval_identities,
            handlers,
            config,
            metrics_registry,
        ))
        return FakeServer()

    monkeypatch.setattr("core.api_server.create_api_server", fake_create_api_server)

    serve_api(handlers=handlers, config=config)

    assert events[0] == (
        "create",
        "127.0.0.1",
        8081,
        "secret",
        "approval-secret",
        ("analyst1",),
        handlers,
        config,
        None,
    )
    assert events[1:] == ["serve_forever", "server_close"]
