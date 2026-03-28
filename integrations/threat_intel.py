from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
import asyncio
import os
from typing import Any, Callable

import httpx

from core.schemas import (
    ActionExecutionRequest,
    ActionExecutionResult,
    EvidenceBatch,
    IntegrationQuery,
    NormalizedEvidence,
)
from integrations.base import BaseIntegrationAdapter


ClientFactory = Callable[[], Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _severity_from_abuseipdb(confidence: int, is_tor: bool, total_reports: int) -> str:
    if confidence >= 90 or (is_tor and total_reports > 0):
        return "critical"
    if confidence >= 50 or is_tor:
        return "high"
    if confidence >= 20:
        return "medium"
    return "low"


def _severity_from_virustotal_ip(malicious: int, suspicious: int, reputation: int) -> str:
    if malicious >= 5:
        return "critical"
    if malicious > 0 or suspicious > 2:
        return "high"
    if suspicious > 0 or reputation < 0:
        return "medium"
    return "low"


def _severity_from_virustotal_hash(malicious: int, suspicious: int) -> str:
    if malicious >= 5:
        return "critical"
    if malicious > 0:
        return "high"
    if suspicious > 0:
        return "medium"
    return "low"


def evidence_record_to_dict(record: NormalizedEvidence) -> dict[str, Any]:
    payload = asdict(record)
    observed_at = payload.get("observed_at")
    if observed_at is not None:
        payload["observed_at"] = observed_at.isoformat()
    return payload


def normalize_abuseipdb_ip_batch(
    query: IntegrationQuery,
    payload: dict[str, Any] | None,
    *,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    if payload:
        confidence = int(payload.get("confidence", 0) or 0)
        total_reports = int(payload.get("total_reports", 0) or 0)
        is_tor = bool(payload.get("is_tor", False))
        usage_type = payload.get("usage_type", "")
        title = f"AbuseIPDB reputation for {query.entity_value}"
        summary = (
            f"AbuseIPDB confidence {confidence} with {total_reports} reports"
            + (f"; usage type {usage_type}" if usage_type else "")
            + ("" if not is_tor else "; TOR exit node flagged")
        )
        records.append(
            NormalizedEvidence(
                source="abuseipdb",
                source_type="threat_intel",
                entity_type=query.entity_type,
                entity_value=query.entity_value,
                title=title,
                summary=summary,
                severity=_severity_from_abuseipdb(confidence, is_tor, total_reports),
                confidence=float(confidence),
                observed_at=_now(),
                raw_ref=f"abuseipdb:{query.entity_type}:{query.entity_value}",
                tags=sorted({
                    "abuseipdb",
                    "tor-exit-node" if is_tor else "",
                    usage_type.lower().replace(" ", "-") if usage_type else "",
                } - {""}),
                attributes={
                    "confidence": confidence,
                    "total_reports": total_reports,
                    "country": payload.get("country", ""),
                    "isp": payload.get("isp", ""),
                    "usage_type": usage_type,
                    "is_tor": is_tor,
                },
            )
        )

    return EvidenceBatch(
        adapter_name="threat_intel",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


def normalize_virustotal_ip_batch(
    query: IntegrationQuery,
    payload: dict[str, Any] | None,
    *,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    if payload:
        malicious = int(payload.get("malicious", 0) or 0)
        suspicious = int(payload.get("suspicious", 0) or 0)
        harmless = int(payload.get("harmless", 0) or 0)
        reputation = int(payload.get("reputation", 0) or 0)
        country = payload.get("country", "")
        title = f"VirusTotal reputation for {query.entity_value}"
        summary = (
            f"VirusTotal analysis: {malicious} malicious, {suspicious} suspicious, "
            f"{harmless} harmless engines; reputation {reputation}"
        )
        records.append(
            NormalizedEvidence(
                source="virustotal",
                source_type="threat_intel",
                entity_type=query.entity_type,
                entity_value=query.entity_value,
                title=title,
                summary=summary,
                severity=_severity_from_virustotal_ip(malicious, suspicious, reputation),
                confidence=min(float(max(malicious * 15, suspicious * 5, max(reputation, 0))), 100.0)
                if malicious or suspicious or reputation > 0
                else 0.0,
                observed_at=_now(),
                raw_ref=f"virustotal:ip:{query.entity_value}",
                tags=sorted({
                    "virustotal",
                    "flagged" if malicious or suspicious else "clean",
                    country.lower() if country else "",
                } - {""}),
                attributes={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "reputation": reputation,
                    "country": country,
                },
            )
        )

    return EvidenceBatch(
        adapter_name="threat_intel",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


def normalize_virustotal_hash_batch(
    query: IntegrationQuery,
    payload: dict[str, Any] | None,
    *,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    if payload:
        malicious = int(payload.get("malicious", 0) or 0)
        suspicious = int(payload.get("suspicious", 0) or 0)
        harmless = int(payload.get("harmless", 0) or 0)
        stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
        }
        threat_label = payload.get("threat_label") or payload.get("popular_threat_classification", "")
        summary = (
            f"VirusTotal file analysis: {malicious} malicious, {suspicious} suspicious, "
            f"{harmless} harmless engines"
        )
        if threat_label:
            summary += f"; label {threat_label}"
        records.append(
            NormalizedEvidence(
                source="virustotal",
                source_type="threat_intel",
                entity_type=query.entity_type,
                entity_value=query.entity_value,
                title=f"VirusTotal file reputation for {query.entity_value[:12]}",
                summary=summary,
                severity=_severity_from_virustotal_hash(malicious, suspicious),
                confidence=min(float(max(malicious * 10, suspicious * 5)), 100.0),
                observed_at=_now(),
                raw_ref=f"virustotal:file:{query.entity_value}",
                tags=sorted({
                    "virustotal",
                    "malware" if malicious > 0 else "benign",
                    threat_label.lower().replace(" ", "-") if isinstance(threat_label, str) and threat_label else "",
                } - {""}),
                attributes={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "stats": stats,
                    "threat_label": threat_label,
                },
            )
        )

    return EvidenceBatch(
        adapter_name="threat_intel",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


class ThreatIntelAdapter(BaseIntegrationAdapter):
    name = "threat_intel"
    supports_read = True
    supports_write = False

    def __init__(
        self,
        *,
        client_factory: ClientFactory | None = None,
        abuseipdb_api_key: str | None = None,
        virustotal_api_key: str | None = None,
    ):
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))
        self.abuseipdb_api_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_api_key = virustotal_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        if query.entity_type == "ip":
            abuse_payload, abuse_error = await self._fetch_abuseipdb_ip(query.entity_value)
            vt_payload, vt_error = await self._fetch_virustotal_ip(query.entity_value)
            batches = [
                normalize_abuseipdb_ip_batch(query, abuse_payload, partial=abuse_error is not None, error=abuse_error),
                normalize_virustotal_ip_batch(query, vt_payload, partial=vt_error is not None, error=vt_error),
            ]
            return self._combine_batches(query, batches)

        if query.entity_type in {"hash", "file_hash"}:
            vt_payload, vt_error = await self._fetch_virustotal_hash(query.entity_value)
            return normalize_virustotal_hash_batch(
                query,
                vt_payload,
                partial=vt_error is not None,
                error=vt_error,
            )

        return EvidenceBatch(
            adapter_name=self.name,
            query=query,
            records=[],
            partial=True,
            error=f"Unsupported entity_type {query.entity_type!r}",
        )

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        return ActionExecutionResult(
            adapter_name=self.name,
            action_type=request.action_type,
            target=request.target,
            status="unsupported",
            executed=False,
            message="Threat intel adapter does not support execution",
            metadata={"requested_by": request.requested_by},
        )

    async def _fetch_abuseipdb_ip(self, ip: str) -> tuple[dict[str, Any] | None, str | None]:
        if not self.abuseipdb_api_key:
            return None, "ABUSEIPDB_API_KEY not set"

        try:
            async with self._client_factory() as client:
                response = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": self.abuseipdb_api_key, "Accept": "application/json"},
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                )
                response.raise_for_status()
                data = response.json().get("data", {})
            return {
                "confidence": int(data.get("abuseConfidenceScore", 0) or 0),
                "total_reports": int(data.get("totalReports", 0) or 0),
                "country": data.get("countryCode", ""),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
                "is_tor": bool(data.get("isTor", False)),
            }, None
        except Exception as exc:
            return None, str(exc)

    async def _fetch_virustotal_ip(self, ip: str) -> tuple[dict[str, Any] | None, str | None]:
        if not self.virustotal_api_key:
            return None, "VIRUSTOTAL_API_KEY not set"

        try:
            async with self._client_factory() as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_api_key},
                )
                response.raise_for_status()
                data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "reputation": int(data.get("reputation", 0) or 0),
                "country": data.get("country", ""),
            }, None
        except Exception as exc:
            return None, str(exc)

    async def _fetch_virustotal_hash(self, file_hash: str) -> tuple[dict[str, Any] | None, str | None]:
        if not self.virustotal_api_key:
            return None, "VIRUSTOTAL_API_KEY not set"

        try:
            async with self._client_factory() as client:
                response = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers={"x-apikey": self.virustotal_api_key},
                )
                response.raise_for_status()
                data = response.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            threat_label = data.get("popular_threat_classification", {}).get("suggested_threat_label", "")
            return {
                "malicious": int(stats.get("malicious", 0) or 0),
                "suspicious": int(stats.get("suspicious", 0) or 0),
                "harmless": int(stats.get("harmless", 0) or 0),
                "threat_label": threat_label,
                "stats": stats,
            }, None
        except Exception as exc:
            return None, str(exc)

    def _combine_batches(
        self,
        query: IntegrationQuery,
        batches: list[EvidenceBatch],
    ) -> EvidenceBatch:
        records: list[NormalizedEvidence] = []
        errors = [batch.error for batch in batches if batch.error]
        for batch in batches:
            records.extend(batch.records)
        return EvidenceBatch(
            adapter_name=self.name,
            query=query,
            records=records,
            partial=bool(errors),
            error="; ".join(errors) if errors else None,
        )
