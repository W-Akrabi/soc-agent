from __future__ import annotations

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
    }
    return mapping.get(text, text or None)


def _confidence_from_row(row: dict[str, Any]) -> float | None:
    for key in ("ConfidenceScore", "confidence", "Score", "score"):
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


def _title_from_row(row: dict[str, Any], table_name: str) -> str:
    for key in ("AlertName", "RuleName", "DisplayName", "Activity", "OperationName", "EventName"):
        value = row.get(key)
        if value:
            return str(value)
    return f"Sentinel row from {table_name}"


def _summary_from_row(row: dict[str, Any]) -> str:
    keys = [
        key
        for key in (
            "AlertName",
            "RuleName",
            "DisplayName",
            "Severity",
            "Level",
            "Account",
            "UserPrincipalName",
            "IPAddress",
            "Computer",
            "Activity",
            "OperationName",
            "ResultDescription",
            "Description",
        )
        if row.get(key) not in (None, "")
    ]
    if not keys:
        selected = list(row.items())[:4]
        return ", ".join(f"{key}={value}" for key, value in selected) if selected else "Sentinel row"
    return ", ".join(f"{key}={row[key]}" for key in keys)


def _records_from_tables(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any], int]]:
    records: list[tuple[str, dict[str, Any], int]] = []
    tables = payload.get("tables", []) or []
    for table in tables:
        table_name = str(table.get("name", "table") or "table")
        columns = [column.get("name", "") for column in table.get("columns", []) or []]
        for row_index, row in enumerate(table.get("rows", []) or []):
            if isinstance(row, dict):
                row_data = dict(row)
            else:
                row_data = {
                    column: row[position]
                    for position, column in enumerate(columns)
                    if column and position < len(row)
                }
            row_data.setdefault("_table_name", table_name)
            records.append((table_name, row_data, row_index))
    return records


def normalize_sentinel_batch(
    query: IntegrationQuery,
    payload: dict[str, Any] | None,
    *,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    if payload:
        rows: list[tuple[str, dict[str, Any], int]] = []
        if isinstance(payload, dict) and payload.get("tables"):
            rows = _records_from_tables(payload)
        elif isinstance(payload, dict) and payload.get("records"):
            records_payload = payload.get("records", []) or []
            rows = [
                (
                    str(payload.get("table_name", "records") or "records"),
                    dict(row) if isinstance(row, dict) else {"value": row},
                    index,
                )
                for index, row in enumerate(records_payload)
            ]

        for table_name, row, row_index in rows:
            title = _title_from_row(row, table_name)
            severity = _severity_from_value(row.get("Severity") or row.get("Level") or row.get("severity"))
            observed_at = None
            for key in ("TimeGenerated", "CreatedTime", "Timestamp", "EventTime", "ObservedTime"):
                observed_at = _parse_timestamp(row.get(key))
                if observed_at is not None:
                    break
            if observed_at is None:
                observed_at = datetime.now(timezone.utc)

            confidence = _confidence_from_row(row)
            records.append(
                NormalizedEvidence(
                    source="sentinel",
                    source_type="siem",
                    entity_type=query.entity_type,
                    entity_value=query.entity_value,
                    title=title,
                    summary=_summary_from_row(row),
                    severity=severity,
                    confidence=confidence,
                    observed_at=observed_at,
                    raw_ref=f"sentinel:{query.alert_id}:{_slugify(table_name)}:{row_index}",
                    tags=sorted(
                        {
                            "sentinel",
                            "azure-sentinel",
                            "siem",
                            _slugify(table_name),
                            _slugify(title),
                        }
                        - {""}
                    ),
                    attributes={
                        "table": table_name,
                        "row_index": row_index,
                        "row": row,
                    },
                )
            )

    return EvidenceBatch(
        adapter_name="sentinel",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


class SentinelAdapter(BaseIntegrationAdapter):
    name = "sentinel"
    supports_read = True
    supports_write = False

    def __init__(
        self,
        *,
        workspace_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        bearer_token: str | None = None,
        scope: str = "https://api.loganalytics.io/.default",
        client_factory: ClientFactory | None = None,
        auth: MicrosoftAuthHelper | None = None,
    ):
        self.workspace_id = workspace_id or os.getenv("SOC_SENTINEL_WORKSPACE_ID") or os.getenv(
            "AZURE_LOG_ANALYTICS_WORKSPACE_ID", ""
        )
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))
        self._auth = auth or MicrosoftAuthHelper(
            MicrosoftAuthConfig(
                tenant_id=tenant_id or os.getenv("AZURE_TENANT_ID", ""),
                client_id=client_id or os.getenv("AZURE_CLIENT_ID", ""),
                client_secret=client_secret or os.getenv("AZURE_CLIENT_SECRET", ""),
                bearer_token=bearer_token or os.getenv("AZURE_ACCESS_TOKEN", ""),
                scope=scope,
            ),
            client_factory=self._client_factory,
        )

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        if not self.workspace_id:
            return EvidenceBatch(
                adapter_name=self.name,
                query=query,
                records=[],
                partial=True,
                error="SOC_SENTINEL_WORKSPACE_ID or AZURE_LOG_ANALYTICS_WORKSPACE_ID not set",
            )

        kql = self._build_query(query)
        try:
            headers = await self._auth.authorization_headers()
            async with self._client_factory() as client:
                response = await client.post(
                    f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query",
                    headers={
                        **headers,
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json={"query": kql},
                )
                response.raise_for_status()
                payload = response.json()
            return normalize_sentinel_batch(query, payload)
        except Exception as exc:
            return normalize_sentinel_batch(query, None, partial=True, error=str(exc))

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        return ActionExecutionResult(
            adapter_name=self.name,
            action_type=request.action_type,
            target=request.target,
            status="unsupported",
            executed=False,
            message="Sentinel adapter does not support execution",
            metadata={"requested_by": request.requested_by},
        )

    def _build_query(self, query: IntegrationQuery) -> str:
        override = query.context.get("kql") if query.context else None
        if override:
            return str(override)
        hours = max(int(query.time_range_hours or 24), 1)
        return f'search "{query.entity_value}" | where TimeGenerated >= ago({hours}h) | take 100'
