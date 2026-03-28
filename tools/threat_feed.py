from tools.base import BaseTool
from core.schemas import IntegrationQuery
from integrations.threat_intel import (
    ThreatIntelAdapter,
    evidence_record_to_dict,
)


class ThreatFeedTool(BaseTool):
    name = "threat_feed_lookup"
    description = "Look up IPs or file hashes in AbuseIPDB and VirusTotal threat feeds"

    def __init__(self, adapter: ThreatIntelAdapter | None = None):
        self.adapter = adapter or ThreatIntelAdapter()

    async def run(self, input: dict) -> dict:
        ip = input.get("ip")
        file_hash = input.get("hash")

        if ip:
            query = IntegrationQuery(
                alert_id=input.get("alert_id", "legacy"),
                alert_type=input.get("alert_type", "unknown"),
                entity_type="ip",
                entity_value=ip,
                context={"source": "legacy_tool"},
            )
            batch = await self.adapter.collect(query)
            return self._legacy_response(batch)

        if file_hash:
            query = IntegrationQuery(
                alert_id=input.get("alert_id", "legacy"),
                alert_type=input.get("alert_type", "unknown"),
                entity_type="hash",
                entity_value=file_hash,
                context={"source": "legacy_tool"},
            )
            batch = await self.adapter.collect(query)
            return self._legacy_response(batch)

        return {}

    def _legacy_response(self, batch) -> dict:
        result = {"malicious": False, "categories": [], "confidence": 0}
        if batch.error:
            result["note"] = batch.error
        if batch.records:
            result["evidence"] = [evidence_record_to_dict(record) for record in batch.records]

        for record in batch.records:
            result["categories"].extend(record.tags)
            if record.confidence is not None:
                result["confidence"] = max(result["confidence"], int(record.confidence))
            if record.severity in {"high", "critical"}:
                result["malicious"] = True
            if record.source == "abuseipdb":
                result["abuseipdb"] = record.attributes
            elif record.source == "virustotal":
                result["virustotal"] = record.attributes

        result["categories"] = sorted(set(result["categories"]))
        return result
