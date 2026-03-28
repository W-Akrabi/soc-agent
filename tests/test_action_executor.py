from unittest.mock import AsyncMock, MagicMock

import pytest

from core.execution_policy import ExecutionPolicy
from core.schemas import ActionExecutionResult
from core.schemas import ActionExecutionRequest
from integrations.defender import DefenderAdapter
from integrations.entra import EntraAdapter
from tools.action_executor import ActionExecutorTool


class _ApprovalQueue:
    def __init__(self):
        self.records = []

    def enqueue(self, item):
        self.records.append(item)
        return item


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


@pytest.mark.asyncio
async def test_action_executor_enqueues_awaiting_approval_actions():
    queue = _ApprovalQueue()
    adapter = MagicMock()
    adapter.supports_write = True
    adapter.execute = AsyncMock()

    policy = ExecutionPolicy(enabled=True, allowed_actions=("disable_account",))
    tool = ActionExecutorTool(
        auto_remediate=False,
        policy=policy,
        entra_adapter=adapter,
        approval_queue=queue,
    )

    result = await tool.run(
        {
            "action_type": "disable_account",
            "target": "alice@example.com",
            "reason": "credential compromise",
            "urgency": "immediate",
            "metadata": {"alert_id": "alert-1", "run_id": "run-1"},
        }
    )

    assert result["status"] == "awaiting_approval"
    assert result["executed"] is False
    assert result["approval_queue"]["action_type"] == "disable_account"
    assert result["approval_queue"]["status"] == "pending"
    assert result["approval_queue"]["blast_radius"]
    assert result["approval_queue"]["rollback_supported"] is True
    assert result["approval_queue"]["rollback_action_type"] == "enable_account"
    assert len(queue.records) == 1
    adapter.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_action_executor_routes_enable_account_to_entra():
    adapter = MagicMock()
    adapter.supports_write = True
    adapter.execute = AsyncMock(
        return_value=ActionExecutionResult(
            adapter_name="entra",
            action_type="enable_account",
            target="alice@example.com",
            status="executed",
            executed=True,
            rollback_supported=False,
            message="ok",
            metadata={},
        )
    )

    policy = ExecutionPolicy(enabled=True, allowed_actions=("enable_account",))
    tool = ActionExecutorTool(
        auto_remediate=True,
        policy=policy,
        entra_adapter=adapter,
    )

    result = await tool.run(
        {
            "action_type": "enable_account",
            "target": "alice@example.com",
            "reason": "rollback containment",
            "urgency": "immediate",
            "metadata": {"user_principal_name": "alice@example.com"},
        }
    )

    assert result["status"] == "executed"
    assert result["executed"] is True
    adapter.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_defender_execute_unisolates_machine():
    client = _FakeClient(response_payload={"id": "machine-action-2"})
    adapter = DefenderAdapter(
        bearer_token="token-abc",
        base_url="https://api.security.microsoft.com",
        client_factory=lambda: client,
    )

    result = await adapter.execute(
        ActionExecutionRequest(
            action_type="unisolate_host",
            target="web-prod-01",
            reason="rollback",
            urgency="immediate",
            requested_by="analyst",
            metadata={"machine_id": "machine-123"},
        )
    )

    assert result.executed is True
    assert result.status == "executed"
    assert result.rollback_supported is False
    assert client.requests[0]["url"] == "https://api.security.microsoft.com/api/machines/machine-123/unisolate"


@pytest.mark.asyncio
async def test_entra_execute_enables_account():
    client = _FakeClient(response_payload={})
    adapter = EntraAdapter(
        bearer_token="token-abc",
        client_factory=lambda: client,
    )

    result = await adapter.execute(
        ActionExecutionRequest(
            action_type="enable_account",
            target="alice@example.com",
            reason="rollback",
            urgency="immediate",
            requested_by="analyst",
            metadata={"user_principal_name": "alice@example.com"},
        )
    )

    assert result.executed is True
    assert result.status == "executed"
    assert client.requests[0]["method"] == "patch"
    assert client.requests[0]["url"] == "https://graph.microsoft.com/v1.0/users/alice@example.com"
    assert client.requests[0]["json"] == {"accountEnabled": True}
