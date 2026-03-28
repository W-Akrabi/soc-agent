from core.schemas import EvidenceBatch, IntegrationQuery
from integrations.threat_intel import (
    evidence_record_to_dict,
    normalize_abuseipdb_ip_batch,
    normalize_virustotal_hash_batch,
    normalize_virustotal_ip_batch,
)
from integrations.sentinel import normalize_sentinel_batch


def test_normalize_abuseipdb_ip_batch_builds_evidence():
    query = IntegrationQuery(
        alert_id="alert-1",
        alert_type="intrusion",
        entity_type="ip",
        entity_value="185.220.101.45",
    )
    batch = normalize_abuseipdb_ip_batch(
        query,
        {
            "confidence": 87,
            "total_reports": 12,
            "country": "RU",
            "isp": "Example ISP",
            "usage_type": "Data Center/Web Hosting",
            "is_tor": True,
        },
    )

    assert isinstance(batch, EvidenceBatch)
    assert batch.adapter_name == "threat_intel"
    assert batch.partial is False
    assert len(batch.records) == 1

    record = batch.records[0]
    assert record.source == "abuseipdb"
    assert record.entity_type == "ip"
    assert record.entity_value == "185.220.101.45"
    assert "tor-exit-node" in record.tags

    payload = evidence_record_to_dict(record)
    assert payload["observed_at"] is not None
    assert payload["observed_at"].endswith("+00:00")


def test_normalize_virustotal_ip_batch_builds_evidence():
    query = IntegrationQuery(
        alert_id="alert-2",
        alert_type="malware",
        entity_type="ip",
        entity_value="8.8.8.8",
    )
    batch = normalize_virustotal_ip_batch(
        query,
        {
            "malicious": 3,
            "suspicious": 1,
            "harmless": 61,
            "reputation": -12,
            "country": "US",
        },
    )

    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.source == "virustotal"
    assert record.severity == "high"
    assert record.attributes["malicious"] == 3
    assert "virustotal" in record.tags


def test_normalize_virustotal_hash_batch_builds_evidence():
    query = IntegrationQuery(
        alert_id="alert-3",
        alert_type="malware",
        entity_type="hash",
        entity_value="d41d8cd98f00b204e9800998ecf8427e",
    )
    batch = normalize_virustotal_hash_batch(
        query,
        {
            "malicious": 5,
            "suspicious": 0,
            "harmless": 54,
            "threat_label": "AgentTesla",
        },
    )

    assert len(batch.records) == 1
    record = batch.records[0]
    assert record.entity_type == "hash"
    assert record.entity_value == "d41d8cd98f00b204e9800998ecf8427e"
    assert record.severity == "critical"
    assert "agenttesla" in record.tags


def test_normalize_sentinel_batch_builds_evidence():
    query = IntegrationQuery(
        alert_id="alert-4",
        alert_type="identity",
        entity_type="user",
        entity_value="alice@example.com",
    )
    batch = normalize_sentinel_batch(
        query,
        {
            "tables": [
                {
                    "name": "SecurityAlert",
                    "columns": [
                        {"name": "TimeGenerated"},
                        {"name": "Severity"},
                        {"name": "AlertName"},
                        {"name": "Account"},
                        {"name": "ConfidenceScore"},
                    ],
                    "rows": [
                        [
                            "2026-03-27T12:34:56Z",
                            "High",
                            "Suspicious sign-in",
                            "alice@example.com",
                            0.92,
                        ]
                    ],
                }
            ]
        },
    )

    assert batch.adapter_name == "sentinel"
    assert batch.partial is False
    assert len(batch.records) == 1

    record = batch.records[0]
    assert record.source == "sentinel"
    assert record.source_type == "siem"
    assert record.severity == "high"
    assert record.entity_type == "user"
    assert record.entity_value == "alice@example.com"
    assert "securityalert" in record.tags

    payload = evidence_record_to_dict(record)
    assert payload["observed_at"] is not None
    assert payload["observed_at"].endswith("+00:00")
    assert payload["attributes"]["table"] == "SecurityAlert"
