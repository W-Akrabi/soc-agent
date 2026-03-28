from __future__ import annotations

import pytest

from core.schemas import IntegrationQuery
from integrations.entra import EntraAdapter


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, *, token_payload=None, signins_payload=None, audits_payload=None):
        self.token_payload = token_payload or {"access_token": "token-abc", "expires_in": 3600}
        self.signins_payload = signins_payload or {"value": []}
        self.audits_payload = audits_payload or {"value": []}
        self.requests: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, headers=None, json=None, data=None):
        self.requests.append({"method": "post", "url": url, "headers": headers, "json": json, "data": data})
        if "login.microsoftonline.com" in url:
            return _FakeResponse(self.token_payload)
        raise AssertionError(f"unexpected url: {url}")

    async def get(self, url, headers=None):
        self.requests.append({"method": "get", "url": url, "headers": headers})
        if url.endswith("/auditLogs/signIns"):
            return _FakeResponse(self.signins_payload)
        if url.endswith("/auditLogs/directoryAudits"):
            return _FakeResponse(self.audits_payload)
        raise AssertionError(f"unexpected url: {url}")


@pytest.mark.asyncio
async def test_entra_collects_identity_and_audit_evidence_with_bearer_token():
    client = _FakeClient(
        signins_payload={
            "value": [
                {
                    "id": "signin-1",
                    "createdDateTime": "2026-03-27T12:00:00Z",
                    "userPrincipalName": "alice@example.com",
                    "ipAddress": "203.0.113.9",
                    "appDisplayName": "Office 365",
                    "resourceDisplayName": "Exchange Online",
                    "conditionalAccessStatus": "failure",
                    "status": {"errorCode": 50074, "failureReason": "MFA required"},
                    "riskState": "high",
                }
            ]
        },
        audits_payload={
            "value": [
                {
                    "id": "audit-1",
                    "activityDateTime": "2026-03-27T12:05:00Z",
                    "activityDisplayName": "Add member to role",
                    "category": "RoleManagement",
                    "initiatedBy": {"user": {"userPrincipalName": "alice@example.com"}},
                    "status": "success",
                }
            ]
        },
    )
    adapter = EntraAdapter(
        bearer_token="access-token",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-1",
            alert_type="intrusion",
            entity_type="user",
            entity_value="alice@example.com",
            context={"source_types": ["identity", "audit"]},
        )
    )

    assert batch.adapter_name == "entra"
    assert batch.partial is False
    assert len(client.requests) == 2
    assert client.requests[0]["url"].endswith("/auditLogs/signIns")
    assert client.requests[1]["url"].endswith("/auditLogs/directoryAudits")
    assert client.requests[0]["headers"]["Authorization"] == "Bearer access-token"
    assert client.requests[1]["headers"]["Authorization"] == "Bearer access-token"
    assert {record.source for record in batch.records} == {"entra"}
    assert {record.source_type for record in batch.records} == {"identity", "audit"}
    assert any(record.title == "Office 365" for record in batch.records)
    assert any(record.title == "Add member to role" for record in batch.records)


@pytest.mark.asyncio
async def test_entra_collect_exchanges_client_credentials_and_normalizes_rows():
    client = _FakeClient(
        signins_payload={
            "value": [
                {
                    "id": "signin-2",
                    "createdDateTime": "2026-03-27T13:30:00Z",
                    "userPrincipalName": "bob@example.com",
                    "ipAddress": "198.51.100.50",
                    "appDisplayName": "Microsoft Teams",
                    "status": {"errorCode": 0, "failureReason": ""},
                    "riskState": "low",
                }
            ]
        },
        audits_payload={"value": []},
    )
    adapter = EntraAdapter(
        tenant_id="tenant-1",
        client_id="client-1",
        client_secret="secret-1",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-2",
            alert_type="intrusion",
            entity_type="ip",
            entity_value="198.51.100.50",
            context={"source_types": ["identity"]},
        )
    )

    assert len(client.requests) == 2
    assert client.requests[0]["url"] == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token"
    assert client.requests[0]["data"] == {
        "grant_type": "client_credentials",
        "client_id": "client-1",
        "client_secret": "secret-1",
        "scope": "https://graph.microsoft.com/.default",
    }
    assert client.requests[1]["url"].endswith("/auditLogs/signIns")
    assert batch.partial is False
    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.source == "entra"
    assert record.source_type == "identity"
    assert record.entity_type == "ip"
    assert record.entity_value == "198.51.100.50"
    assert record.attributes["endpoint"] == "signIns"
    assert record.raw_ref.startswith("entra:signins:")
    assert record.severity in {"low", "medium", "high", "critical"}


@pytest.mark.asyncio
async def test_entra_collect_is_partial_when_unconfigured(monkeypatch):
    monkeypatch.delenv("SOC_ENTRA_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("SOC_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("SOC_ENTRA_CLIENT_ID", raising=False)
    monkeypatch.delenv("SOC_ENTRA_CLIENT_SECRET", raising=False)

    adapter = EntraAdapter(client_factory=lambda: _FakeClient())
    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-3",
            alert_type="intrusion",
            entity_type="user",
            entity_value="carol@example.com",
        )
    )

    assert batch.partial is True
    assert batch.records == []
    assert "not set" in (batch.error or "")
