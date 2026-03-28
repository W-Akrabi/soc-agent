from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
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
from integrations.base import BaseIntegrationAdapter, MicrosoftAuthConfig, MicrosoftAuthHelper


ClientFactory = Callable[[], Any]


def _slugify(value: Any) -> str:
    text = str(value or "").strip().lower()
    return "".join(ch if ch.isalnum() else "-" for ch in text).strip("-")


def _parse_timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        normalized = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def _severity_from_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    mapping = {
        "0": "informational",
        "informational": "informational",
        "info": "informational",
        "1": "low",
        "low": "low",
        "2": "medium",
        "medium": "medium",
        "3": "high",
        "high": "high",
        "4": "critical",
        "critical": "critical",
        "unhealthy": "high",
        "compromised": "critical",
        "malicious": "critical",
    }
    return mapping.get(text, text or None)


def _confidence_from_row(row: dict[str, Any]) -> float | None:
    for key in (
        "confidence",
        "ConfidenceScore",
        "score",
        "riskScoreConfidence",
        "riskScorePercent",
    ):
        value = row.get(key)
        if value is None:
            continue
        try:
            confidence = float(value)
        except (TypeError, ValueError):
            continue
        if 0.0 <= confidence <= 1.0:
            confidence *= 100.0
        return round(confidence, 2)
    return None


def _record_batches(payload: dict[str, Any] | list[Any] | None, keys: tuple[str, ...]) -> list[tuple[str, dict[str, Any], int]]:
    if payload is None:
        return []

    if isinstance(payload, list):
        rows = payload
        table_name = keys[0] if keys else "records"
        return [
            (table_name, dict(row) if isinstance(row, dict) else {"value": row}, index)
            for index, row in enumerate(rows)
        ]

    records: list[tuple[str, dict[str, Any], int]] = []
    for key in keys:
        value = payload.get(key)
        if not value:
            continue
        table_name = str(key)
        if isinstance(value, list):
            for index, row in enumerate(value):
                records.append(
                    (
                        table_name,
                        dict(row) if isinstance(row, dict) else {"value": row},
                        index,
                    )
                )
        elif isinstance(value, dict):
            records.append((table_name, dict(value), 0))
    if records:
        return records

    value = payload.get("value")
    if isinstance(value, list):
        return [
            ("value", dict(row) if isinstance(row, dict) else {"value": row}, index)
            for index, row in enumerate(value)
        ]
    if isinstance(value, dict):
        return [("value", dict(value), 0)]
    return []


def evidence_record_to_dict(record: NormalizedEvidence) -> dict[str, Any]:
    payload = asdict(record)
    observed_at = payload.get("observed_at")
    if observed_at is not None:
        payload["observed_at"] = observed_at.isoformat()
    return payload


def _normalize_host_record(query: IntegrationQuery, row: dict[str, Any], row_index: int, table_name: str) -> NormalizedEvidence:
    device_name = str(
        row.get("deviceName")
        or row.get("computerDnsName")
        or row.get("hostName")
        or row.get("hostname")
        or row.get("name")
        or query.entity_value
    )
    platform = str(row.get("osPlatform") or row.get("platform") or row.get("devicePlatform") or "").strip()
    health_status = str(row.get("healthStatus") or row.get("status") or row.get("deviceHealthStatus") or "").strip()
    risk = str(row.get("riskScore") or row.get("risk") or row.get("riskLevel") or "").strip()
    observed_at = (
        _parse_timestamp(row.get("lastSeen"))
        or _parse_timestamp(row.get("lastSeenAt"))
        or _parse_timestamp(row.get("lastContacted"))
        or _parse_timestamp(row.get("timestamp"))
        or datetime.now(timezone.utc)
    )

    summary_parts = [f"Device {device_name}"]
    if platform:
        summary_parts.append(f"platform {platform}")
    if health_status:
        summary_parts.append(f"health {health_status}")
    if risk:
        summary_parts.append(f"risk {risk}")
    if observed_at is not None:
        summary_parts.append(f"last seen {observed_at.isoformat()}")

    severity = _severity_from_value(risk or health_status)
    confidence = _confidence_from_row(row)
    if confidence is None:
        risk_confidence = {
            "critical": 95.0,
            "high": 80.0,
            "medium": 60.0,
            "low": 35.0,
            "informational": 10.0,
        }
        confidence = risk_confidence.get((severity or "").lower()) if severity else None

    return NormalizedEvidence(
        source="defender",
        source_type="edr",
        entity_type="host",
        entity_value=device_name,
        title=f"Defender host evidence for {device_name}",
        summary="; ".join(summary_parts),
        severity=severity,
        confidence=confidence,
        observed_at=observed_at,
        raw_ref=f"defender:host:{_slugify(device_name)}:{row_index}",
        tags=sorted(
            {
                "defender",
                "edr",
                "host",
                _slugify(device_name),
                _slugify(platform),
                _slugify(table_name),
            }
            - {""}
        ),
        attributes={
            "table": table_name,
            "row_index": row_index,
            "device_name": device_name,
            "platform": platform,
            "health_status": health_status,
            "risk": risk,
            "row": row,
        },
    )


def _normalize_file_record(query: IntegrationQuery, row: dict[str, Any], row_index: int, table_name: str) -> NormalizedEvidence:
    file_name = str(
        row.get("fileName")
        or row.get("name")
        or row.get("file_name")
        or row.get("path")
        or query.context.get("file_path")
        or query.entity_value
    )
    file_hash = str(
        row.get("sha256")
        or row.get("SHA256")
        or row.get("sha1")
        or row.get("SHA1")
        or row.get("md5")
        or row.get("MD5")
        or query.entity_value
    )
    verdict = str(
        row.get("detectionState")
        or row.get("verdict")
        or row.get("threatName")
        or row.get("threat_name")
        or row.get("malwareFamily")
        or ""
    ).strip()
    folder_path = str(row.get("folderPath") or row.get("directory") or row.get("path") or "").strip()
    observed_at = (
        _parse_timestamp(row.get("lastSeen"))
        or _parse_timestamp(row.get("firstSeen"))
        or _parse_timestamp(row.get("timestamp"))
        or datetime.now(timezone.utc)
    )

    summary_parts = [f"File {file_name}"]
    if file_hash:
        summary_parts.append(f"hash {file_hash}")
    if folder_path:
        summary_parts.append(f"path {folder_path}")
    if verdict:
        summary_parts.append(f"verdict {verdict}")
    if observed_at is not None:
        summary_parts.append(f"observed {observed_at.isoformat()}")

    severity = _severity_from_value(verdict or row.get("severity") or row.get("risk"))
    confidence = _confidence_from_row(row)
    if confidence is None:
        confidence = 90.0 if severity in {"critical", "high"} else 60.0 if severity == "medium" else 25.0

    return NormalizedEvidence(
        source="defender",
        source_type="edr",
        entity_type="file",
        entity_value=file_hash or file_name,
        title=f"Defender file evidence for {file_name}",
        summary="; ".join(summary_parts),
        severity=severity,
        confidence=confidence,
        observed_at=observed_at,
        raw_ref=f"defender:file:{_slugify(file_name)}:{row_index}",
        tags=sorted(
            {
                "defender",
                "edr",
                "file",
                _slugify(file_name),
                _slugify(verdict),
                _slugify(table_name),
            }
            - {""}
        ),
        attributes={
            "table": table_name,
            "row_index": row_index,
            "file_name": file_name,
            "file_hash": file_hash,
            "folder_path": folder_path,
            "verdict": verdict,
            "row": row,
        },
    )


def normalize_defender_batch(
    query: IntegrationQuery,
    payload: dict[str, Any] | list[Any] | None,
    *,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    if payload:
        if query.entity_type == "host":
            rows = _record_batches(payload, ("machines", "devices", "records"))
            for table_name, row, row_index in rows:
                records.append(_normalize_host_record(query, row, row_index, table_name))
        elif query.entity_type == "file":
            rows = _record_batches(payload, ("files", "records"))
            for table_name, row, row_index in rows:
                records.append(_normalize_file_record(query, row, row_index, table_name))

    return EvidenceBatch(
        adapter_name="defender",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


class DefenderAdapter(BaseIntegrationAdapter):
    name = "defender"
    supports_read = True
    supports_write = True

    def __init__(
        self,
        *,
        base_url: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        bearer_token: str | None = None,
        scope: str = "https://api.securitycenter.microsoft.com/.default",
        client_factory: ClientFactory | None = None,
        auth: MicrosoftAuthHelper | None = None,
    ):
        self.base_url = (base_url or os.getenv("SOC_DEFENDER_BASE_URL", "https://api.securitycenter.microsoft.com")).rstrip("/")
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))
        self._auth = auth or MicrosoftAuthHelper(
            MicrosoftAuthConfig(
                tenant_id=tenant_id or os.getenv("SOC_DEFENDER_TENANT_ID", ""),
                client_id=client_id or os.getenv("SOC_DEFENDER_CLIENT_ID", ""),
                client_secret=client_secret or os.getenv("SOC_DEFENDER_CLIENT_SECRET", ""),
                bearer_token=bearer_token or os.getenv("SOC_DEFENDER_BEARER_TOKEN", ""),
                scope=scope,
            ),
            client_factory=self._client_factory,
        )

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        try:
            headers = await self._auth.authorization_headers()
        except Exception as exc:
            return normalize_defender_batch(query, None, partial=True, error=str(exc))

        try:
            if query.entity_type == "host":
                payload = await self._fetch_host_payload(query, headers=headers)
                return normalize_defender_batch(query, payload)
            if query.entity_type == "file":
                payload = await self._fetch_file_payload(query, headers=headers)
                return normalize_defender_batch(query, payload)
            return normalize_defender_batch(
                query,
                None,
                partial=True,
                error=f"Unsupported entity_type {query.entity_type!r}",
            )
        except Exception as exc:
            return normalize_defender_batch(query, None, partial=True, error=str(exc))

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        action_type = (request.action_type or "").strip().lower()
        if action_type not in {"isolate_host", "unisolate_host"}:
            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="unsupported",
                executed=False,
                message=f"Defender adapter does not support action_type {request.action_type!r}",
                metadata={"requested_by": request.requested_by},
            )

        try:
            headers = await self._auth.authorization_headers()
            machine_id, resolution = await self._resolve_machine_id(request, headers=headers)
            endpoint = "isolate" if action_type == "isolate_host" else "unisolate"
            payload = {
                "Comment": request.reason,
                "IsolationType": request.metadata.get("isolation_type", "Full"),
            }
            async with self._client_factory() as client:
                response = await client.post(
                    f"{self.base_url}/api/machines/{machine_id}/{endpoint}",
                    headers={**headers, "Content-Type": "application/json", "Accept": "application/json"},
                    json=payload,
                )
                response.raise_for_status()
                response_payload = response.json() if hasattr(response, "json") else {}

            external_id = None
            if isinstance(response_payload, dict):
                external_id = str(
                    response_payload.get("id")
                    or response_payload.get("machineActionId")
                    or response_payload.get("actionId")
                    or ""
                ) or None
            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="executed",
                executed=True,
                external_id=external_id,
                rollback_supported=action_type == "isolate_host",
                message=(
                    "Machine isolate request submitted successfully"
                    if action_type == "isolate_host"
                    else "Machine unisolate request submitted successfully"
                ),
                metadata={
                    "requested_by": request.requested_by,
                    "machine_id": machine_id,
                    "resolution": resolution,
                    "request": payload,
                    "response": response_payload,
                },
            )
        except Exception as exc:
            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="failed",
                executed=False,
                message=str(exc),
                metadata={"requested_by": request.requested_by},
            )

    async def _fetch_host_payload(self, query: IntegrationQuery, *, headers: dict[str, str]) -> dict[str, Any] | list[Any]:
        machine_id = query.context.get("device_id") or query.context.get("machine_id")
        params = None
        url = f"{self.base_url}/api/machines"
        if machine_id:
            url = f"{url}/{machine_id}"
        else:
            params = {"$filter": f"deviceName eq '{query.entity_value}'"}

        async with self._client_factory() as client:
            response = await client.get(
                url,
                headers={**headers, "Accept": "application/json"},
                params=params,
            )
            response.raise_for_status()
            payload = response.json()

        if isinstance(payload, dict) and isinstance(payload.get("value"), list):
            return {"machines": payload["value"]}
        return payload

    async def _fetch_file_payload(self, query: IntegrationQuery, *, headers: dict[str, str]) -> dict[str, Any] | list[Any]:
        identifier = str(
            query.context.get("sha256")
            or query.context.get("file_hash")
            or query.context.get("hash")
            or query.entity_value
        )
        params = None
        url = f"{self.base_url}/api/files"
        if len(identifier) in {32, 40, 64} and identifier.replace("-", "").isalnum():
            params = {"$filter": f"sha256 eq '{identifier}'"}
        else:
            params = {"filePath": identifier}

        async with self._client_factory() as client:
            response = await client.get(
                url,
                headers={**headers, "Accept": "application/json"},
                params=params,
            )
            response.raise_for_status()
            payload = response.json()

        if isinstance(payload, dict) and isinstance(payload.get("value"), list):
            return {"files": payload["value"]}
        return payload

    async def _resolve_machine_id(
        self,
        request: ActionExecutionRequest,
        *,
        headers: dict[str, str],
    ) -> tuple[str, str]:
        machine_id = str(
            request.metadata.get("machine_id")
            or request.metadata.get("device_id")
            or request.metadata.get("id")
            or request.target
        )
        if request.metadata.get("machine_id") or request.metadata.get("device_id") or request.metadata.get("id"):
            return machine_id, "metadata"

        if machine_id and len(machine_id) in {32, 36, 64} and machine_id.replace("-", "").isalnum():
            return machine_id, "target"

        async with self._client_factory() as client:
            response = await client.get(
                f"{self.base_url}/api/machines",
                headers={**headers, "Accept": "application/json"},
                params={"$filter": f"deviceName eq '{machine_id}'"},
            )
            response.raise_for_status()
            payload = response.json()

        if isinstance(payload, dict):
            machines = payload.get("value")
            if isinstance(machines, list) and machines:
                first = machines[0]
                if isinstance(first, dict):
                    resolved = str(first.get("id") or first.get("machineId") or first.get("computerDnsName") or machine_id)
                    return resolved, "lookup"
        return machine_id, "target"
