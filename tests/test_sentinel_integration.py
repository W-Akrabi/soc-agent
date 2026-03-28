from __future__ import annotations

import pytest

from core.schemas import IntegrationQuery
from integrations.sentinel import SentinelAdapter


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, *, token_payload=None, query_payload=None):
        self.token_payload = token_payload or {"access_token": "token-abc", "expires_in": 3600}
        self.query_payload = query_payload or {"tables": []}
        self.requests: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers=None, json=None, data=None):
        self.requests.append({"url": url, "headers": headers, "json": json, "data": data})
        if "login.microsoftonline.com" in url:
            return _FakeResponse(self.token_payload)
        if url.endswith("/query"):
            return _FakeResponse(self.query_payload)
        raise AssertionError(f"unexpected url: {url}")


@pytest.mark.asyncio
async def test_sentinel_collect_uses_bearer_token_without_token_exchange():
    client = _FakeClient(
        query_payload={
            "tables": [
                {
                    "name": "SecurityAlert",
                    "columns": [
                        {"name": "TimeGenerated"},
                        {"name": "Severity"},
                        {"name": "AlertName"},
                        {"name": "Account"},
                    ],
                    "rows": [
                        ["2026-03-27T12:34:56Z", "Medium", "Suspicious login", "alice@example.com"]
                    ],
                }
            ]
        }
    )
    adapter = SentinelAdapter(
        workspace_id="workspace-1",
        bearer_token="access-token",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-1",
            alert_type="identity",
            entity_type="user",
            entity_value="alice@example.com",
            context={"kql": "SecurityAlert | take 1"},
        )
    )

    assert batch.adapter_name == "sentinel"
    assert batch.partial is False
    assert len(client.requests) == 1
    assert client.requests[0]["url"] == "https://api.loganalytics.io/v1/workspaces/workspace-1/query"
    assert client.requests[0]["headers"]["Authorization"] == "Bearer access-token"
    assert client.requests[0]["json"] == {"query": "SecurityAlert | take 1"}
    assert len(batch.records) == 1
    assert batch.records[0].source == "sentinel"
    assert batch.records[0].title == "Suspicious login"
    assert batch.records[0].severity == "medium"


@pytest.mark.asyncio
async def test_sentinel_collect_exchanges_client_credentials_for_token_and_normalizes_rows():
    client = _FakeClient(
        query_payload={
            "tables": [
                {
                    "name": "SigninLogs",
                    "columns": [
                        {"name": "TimeGenerated"},
                        {"name": "Severity"},
                        {"name": "AlertName"},
                        {"name": "Account"},
                        {"name": "ConfidenceScore"},
                    ],
                    "rows": [
                        [
                            "2026-03-27T15:00:00Z",
                            "High",
                            "Password spray",
                            "bob@example.com",
                            0.88,
                        ]
                    ],
                }
            ]
        }
    )
    adapter = SentinelAdapter(
        workspace_id="workspace-2",
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret-1",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-2",
            alert_type="identity",
            entity_type="user",
            entity_value="bob@example.com",
        )
    )

    assert len(client.requests) == 2
    assert client.requests[0]["url"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    assert client.requests[0]["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "secret-1",
        "scope": "https://api.loganalytics.io/.default",
    }
    assert client.requests[1]["headers"]["Authorization"] == "Bearer token-abc"
    assert client.requests[1]["json"] == {"query": 'search "bob@example.com" | where TimeGenerated >= ago(24h) | take 100'}

    assert batch.partial is False
    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.source == "sentinel"
    assert record.source_type == "siem"
    assert record.severity == "high"
    assert record.confidence == 88.0
    assert "signinlogs" in record.tags
    assert record.attributes["table"] == "SigninLogs"
    assert record.attributes["row_index"] == 0
