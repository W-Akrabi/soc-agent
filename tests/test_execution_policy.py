from __future__ import annotations

import pytest
from unittest.mock import AsyncMock

from core.execution_policy import ExecutionPolicy
from core.models import ActionStatus
from core.schemas import ActionExecutionRequest, ActionExecutionResult
from integrations.defender import DefenderAdapter
from integrations.entra import EntraAdapter
from tools.action_executor import ActionExecutorTool


class _FakeResponse:
    def __init__(self, payload=None):
        self._payload = payload or {}

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, *, response_payload=None):
        self.response_payload = response_payload or {}
        self.requests: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers=None, json=None, data=None):
        self.requests.append({"method": "post", "url": url, "headers": headers, "json": json, "data": data})
        return _FakeResponse(self.response_payload)

    async def patch(self, url, headers=None, json=None):
        self.requests.append({"method": "patch", "url": url, "headers": headers, "json": json})
        return _FakeResponse(self.response_payload)

    async def get(self, url, headers=None, params=None):
        self.requests.append({"method": "get", "url": url, "headers": headers, "params": params})
        return _FakeResponse({"value": [{"id": "machine-123"}]})


def test_execution_policy_defaults_to_propose_only():
    policy = ExecutionPolicy(enabled=False, allowed_actions=("isolate_host",))
    decision = policy.decide(
        ActionExecutionRequest(
            action_type="isolate_host",
            target="web-prod-01",
            reason="containment",
            urgency="immediate",
            requested_by="analyst",
            allow_execution=True,
        )
    )

    assert decision.status == ActionStatus.PROPOSED
    assert decision.should_execute is False
    assert "propose-only" in decision.reason


def test_execution_policy_requires_allowlist_and_explicit_execution_mode():
    policy = ExecutionPolicy(enabled=True, allowed_actions=("isolate_host",))

    awaiting = policy.decide(
        ActionExecutionRequest(
            action_type="isolate_host",
            target="web-prod-01",
            reason="containment",
            urgency="immediate",
            requested_by="analyst",
            allow_execution=False,
        )
    )
    assert awaiting.status == ActionStatus.AWAITING_APPROVAL
    assert awaiting.allowed is True
    assert awaiting.should_execute is False

    rejected = policy.decide(
        ActionExecutionRequest(
            action_type="disable_account",
            target="alice@example.com",
            reason="containment",
            urgency="immediate",
            requested_by="analyst",
            allow_execution=True,
        )
    )
    assert rejected.status == ActionStatus.PROPOSED
    assert rejected.allowed is False
    assert "not allowlisted" in rejected.reason

    approved = policy.decide(
        ActionExecutionRequest(
            action_type="isolate_host",
            target="web-prod-01",
            reason="containment",
            urgency="immediate",
            requested_by="analyst",
            allow_execution=True,
        )
    )
    assert approved.status == ActionStatus.APPROVED
    assert approved.should_execute is True


@pytest.mark.asyncio
async def test_defender_execute_isolates_machine():
    client = _FakeClient(response_payload={"id": "machine-action-1"})
    adapter = DefenderAdapter(
        bearer_token="token-abc",
        base_url="https://api.security.microsoft.com",
        client_factory=lambda: client,
    )

    result = await adapter.execute(
        ActionExecutionRequest(
            action_type="isolate_host",
            target="web-prod-01",
            reason="containment required",
            urgency="immediate",
            requested_by="analyst",
            metadata={"machine_id": "machine-123"},
        )
    )

    assert result.executed is True
    assert result.status == "executed"
    assert result.adapter_name == "defender"
    assert result.rollback_supported is True
    assert client.requests[0]["url"] == "https://api.security.microsoft.com/api/machines/machine-123/isolate"
    assert client.requests[0]["json"] == {"Comment": "containment required", "IsolationType": "Full"}


@pytest.mark.asyncio
async def test_entra_execute_disables_account_and_revokes_sessions():
    disable_client = _FakeClient(response_payload={})
    disable_adapter = EntraAdapter(
        bearer_token="token-abc",
        client_factory=lambda: disable_client,
    )

    disable_result = await disable_adapter.execute(
        ActionExecutionRequest(
            action_type="disable_account",
            target="alice@example.com",
            reason="credential compromise",
            urgency="immediate",
            requested_by="analyst",
            metadata={"user_principal_name": "alice@example.com"},
        )
    )

    assert disable_result.executed is True
    assert disable_result.status == "executed"
    assert disable_client.requests[0]["method"] == "patch"
    assert disable_client.requests[0]["url"] == "https://graph.microsoft.com/v1.0/users/alice@example.com"
    assert disable_client.requests[0]["json"] == {"accountEnabled": False}

    revoke_client = _FakeClient(response_payload={"value": True})
    revoke_adapter = EntraAdapter(
        bearer_token="token-abc",
        client_factory=lambda: revoke_client,
    )

    revoke_result = await revoke_adapter.execute(
        ActionExecutionRequest(
            action_type="revoke_sessions",
            target="alice@example.com",
            reason="session invalidation",
            urgency="immediate",
            requested_by="analyst",
            metadata={"user_principal_name": "alice@example.com"},
        )
    )

    assert revoke_result.executed is True
    assert revoke_result.status == "executed"
    assert revoke_client.requests[0]["method"] == "post"
    assert revoke_client.requests[0]["url"] == "https://graph.microsoft.com/v1.0/users/alice@example.com/revokeSignInSessions"
    assert revoke_client.requests[0]["json"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action_type,target,expected_adapter_name",
    [
        ("isolate_host", "web-prod-01", "defender"),
        ("disable_account", "alice@example.com", "entra"),
        ("revoke_sessions", "alice@example.com", "entra"),
        ("block_ip", "203.0.113.9", None),
    ],
)
async def test_action_executor_routes_allowlisted_actions(action_type, target, expected_adapter_name):
    defender_calls = []
    entra_calls = []

    class _Adapter:
        def __init__(self, name: str, calls: list[str]):
            self.name = name
            self.supports_write = True
            self._calls = calls

        async def execute(self, request):
            self._calls.append(request.action_type)
            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="executed",
                executed=True,
                message="ok",
            )

    defender = _Adapter("defender", defender_calls)
    entra = _Adapter("entra", entra_calls)
    policy = ExecutionPolicy(enabled=True, allowed_actions=("isolate_host", "disable_account", "revoke_sessions"))
    tool = ActionExecutorTool(
        auto_remediate=True,
        policy=policy,
        defender_adapter=defender,
        entra_adapter=entra,
    )

    result = await tool.run(
        {
            "action_type": action_type,
            "target": target,
            "reason": "containment required",
            "urgency": "immediate",
            "metadata": {"user_principal_name": target},
        }
    )

    if expected_adapter_name is None:
        assert result["status"] == "proposed"
        assert result["executed"] is False
        assert "not allowlisted" in result["message"]
        assert defender_calls == []
        assert entra_calls == []
    else:
        assert result["status"] == "executed"
        assert result["executed"] is True
        assert result["adapter_name"] == expected_adapter_name
        assert result["policy"]["status"] == ActionStatus.APPROVED.value
        if expected_adapter_name == "defender":
            assert defender_calls == ["isolate_host"]
            assert entra_calls == []
        else:
            assert defender_calls == []
            assert entra_calls == [action_type]
