from __future__ import annotations

import pytest

from core.schemas import IntegrationQuery
from integrations.defender import DefenderAdapter


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, *, host_payload=None, file_payload=None):
        self.host_payload = host_payload or {"value": []}
        self.file_payload = file_payload or {"value": []}
        self.requests: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None, params=None):
        self.requests.append({"url": url, "headers": headers, "params": params})
        if "/api/machines" in url:
            return _FakeResponse(self.host_payload)
        if "/api/files" in url:
            return _FakeResponse(self.file_payload)
        raise AssertionError(f"unexpected url: {url}")


@pytest.mark.asyncio
async def test_defender_collects_normalized_host_evidence():
    client = _FakeClient(
        host_payload={
            "value": [
                {
                    "deviceName": "web-prod-01",
                    "osPlatform": "Windows Server 2022",
                    "healthStatus": "unhealthy",
                    "riskScore": "high",
                    "lastSeen": "2026-03-27T12:00:00Z",
                    "ipAddresses": ["10.0.1.50"],
                }
            ]
        }
    )
    adapter = DefenderAdapter(
        bearer_token="token-abc",
        base_url="https://api.securitycenter.microsoft.com",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-1",
            alert_type="intrusion",
            entity_type="host",
            entity_value="web-prod-01",
        )
    )

    assert batch.adapter_name == "defender"
    assert batch.partial is False
    assert len(client.requests) == 1
    assert client.requests[0]["url"] == "https://api.securitycenter.microsoft.com/api/machines"
    assert client.requests[0]["params"] == {"$filter": "deviceName eq 'web-prod-01'"}

    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.source == "defender"
    assert record.source_type == "edr"
    assert record.entity_type == "host"
    assert record.entity_value == "web-prod-01"
    assert record.severity == "high"
    assert "defender" in record.tags
    assert record.attributes["device_name"] == "web-prod-01"


@pytest.mark.asyncio
async def test_defender_collects_normalized_file_evidence():
    client = _FakeClient(
        file_payload={
            "value": [
                {
                    "fileName": "payload.dll",
                    "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                    "folderPath": "C:\\Temp",
                    "detectionState": "malicious",
                    "lastSeen": "2026-03-27T12:03:00Z",
                }
            ]
        }
    )
    adapter = DefenderAdapter(
        bearer_token="token-abc",
        base_url="https://api.securitycenter.microsoft.com",
        client_factory=lambda: client,
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-2",
            alert_type="malware",
            entity_type="file",
            entity_value="d41d8cd98f00b204e9800998ecf8427e",
        )
    )

    assert batch.partial is False
    assert len(client.requests) == 1
    assert client.requests[0]["url"] == "https://api.securitycenter.microsoft.com/api/files"
    assert client.requests[0]["params"] == {"$filter": "sha256 eq 'd41d8cd98f00b204e9800998ecf8427e'"}

    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.source == "defender"
    assert record.entity_type == "file"
    assert record.entity_value == "d41d8cd98f00b204e9800998ecf8427e"
    assert record.severity == "critical"
    assert "payload-dll" in record.tags
    assert record.attributes["file_name"] == "payload.dll"


@pytest.mark.asyncio
async def test_defender_collect_is_partial_without_auth():
    adapter = DefenderAdapter(client_factory=lambda: _FakeClient())

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-3",
            alert_type="anomaly",
            entity_type="host",
            entity_value="ws-01",
        )
    )

    assert batch.partial is True
    assert batch.records == []
    assert "Microsoft auth requires" in batch.error
