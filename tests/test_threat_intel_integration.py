import pytest

from core.schemas import IntegrationQuery
from integrations.threat_intel import ThreatIntelAdapter
from tools.threat_feed import ThreatFeedTool


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, payloads):
        self.payloads = payloads

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None, params=None):
        if "abuseipdb" in url:
            return _FakeResponse(self.payloads["abuseipdb"])
        if "/ip_addresses/" in url:
            return _FakeResponse(self.payloads["virustotal_ip"])
        if "/files/" in url:
            return _FakeResponse(self.payloads["virustotal_hash"])
        raise AssertionError(f"unexpected url: {url}")


@pytest.mark.asyncio
async def test_threat_intel_adapter_collects_normalized_ip_evidence():
    adapter = ThreatIntelAdapter(
        client_factory=lambda: _FakeClient(
            {
                "abuseipdb": {
                    "data": {
                        "abuseConfidenceScore": 95,
                        "totalReports": 17,
                        "countryCode": "RU",
                        "isp": "Tor Exit",
                        "usageType": "Data Center/Web Hosting",
                        "isTor": True,
                    }
                },
                "virustotal_ip": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 4,
                                "suspicious": 1,
                                "harmless": 58,
                            },
                            "reputation": -18,
                            "country": "RU",
                        }
                    }
                },
                "virustotal_hash": {"data": {"attributes": {}}},
            }
        ),
        abuseipdb_api_key="abuse-key",
        virustotal_api_key="vt-key",
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-1",
            alert_type="intrusion",
            entity_type="ip",
            entity_value="185.220.101.45",
        )
    )

    assert batch.adapter_name == "threat_intel"
    assert batch.partial is False
    assert len(batch.records) == 2
    assert {record.source for record in batch.records} == {"abuseipdb", "virustotal"}


@pytest.mark.asyncio
async def test_threat_intel_adapter_collects_hash_evidence_and_tool_shim():
    adapter = ThreatIntelAdapter(
        client_factory=lambda: _FakeClient(
            {
                "abuseipdb": {"data": {}},
                "virustotal_ip": {"data": {"attributes": {}}},
                "virustotal_hash": {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 6,
                                "suspicious": 0,
                                "harmless": 50,
                            },
                            "popular_threat_classification": {
                                "suggested_threat_label": "AgentTesla"
                            },
                        }
                    }
                },
            }
        ),
        abuseipdb_api_key="abuse-key",
        virustotal_api_key="vt-key",
    )

    batch = await adapter.collect(
        IntegrationQuery(
            alert_id="alert-2",
            alert_type="malware",
            entity_type="hash",
            entity_value="d41d8cd98f00b204e9800998ecf8427e",
        )
    )
    assert len(batch.records) == 1
    assert batch.records[0].source == "virustotal"
    assert batch.records[0].severity == "critical"

    tool = ThreatFeedTool(adapter=adapter)
    legacy = await tool.run({"hash": "d41d8cd98f00b204e9800998ecf8427e"})
    assert "malicious" in legacy
    assert "categories" in legacy
    assert "confidence" in legacy
    assert legacy["malicious"] is True
