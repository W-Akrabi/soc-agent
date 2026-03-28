from __future__ import annotations

from datetime import datetime, timezone
import json
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


def _now() -> datetime:
    return datetime.now(timezone.utc)


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


def _payload_rows(payload: Any) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if isinstance(payload, list):
        return [dict(row) if isinstance(row, dict) else {"value": row} for row in payload]
    if isinstance(payload, dict):
        for key in ("value", "records", "data"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [dict(row) if isinstance(row, dict) else {"value": row} for row in rows]
    return []


def _row_text(row: dict[str, Any]) -> str:
    try:
        return json.dumps(row, sort_keys=True, default=str).lower()
    except TypeError:
        return str(row).lower()


def _row_matches_query(row: dict[str, Any], query: IntegrationQuery) -> bool:
    if not query.entity_value:
        return True
    return query.entity_value.strip().lower() in _row_text(row)


def _first_present(row: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return value
    return None


def _status_text(row: dict[str, Any]) -> str:
    status = row.get("status")
    if isinstance(status, dict):
        return " ".join(
            str(status.get(key, "") or "")
            for key in ("errorCode", "failureReason", "additionalDetails")
        ).strip()
    if status not in (None, ""):
        return str(status)
    return ""


def _severity_from_identity_row(row: dict[str, Any]) -> str:
    risk = str(
        _first_present(
            row,
            ("riskLevelAggregated", "riskState", "riskDetail", "riskLevel", "riskLevelDuringSignIn"),
        )
        or ""
    ).strip().lower()
    status = row.get("status")
    status_text = _status_text(row).lower()
    if risk in {"high", "at risk", "at_risk", "confirmedcompromised", "confirmed_compromised"}:
        return "critical"
    if risk in {"medium", "elevated"}:
        return "high"
    if isinstance(status, dict):
        try:
            if int(status.get("errorCode", 0) or 0) != 0:
                return "high"
        except (TypeError, ValueError):
            if status_text:
                return "high"
    if any(token in status_text for token in ("failure", "blocked", "denied", "error")):
        return "medium"
    return "low"


def _severity_from_audit_row(row: dict[str, Any]) -> str:
    activity = str(
        _first_present(row, ("activityDisplayName", "operationName", "activity"))
        or ""
    ).lower()
    status_text = _status_text(row).lower()
    risky_tokens = (
        "add user",
        "add member",
        "grant",
        "consent",
        "credential",
        "password",
        "role",
        "delete",
        "remove",
        "disable",
        "update",
    )
    if any(token in activity for token in risky_tokens):
        return "high"
    if any(token in status_text for token in ("failure", "denied", "blocked", "error")):
        return "medium"
    return "low"


def _confidence_from_row(row: dict[str, Any], source_type: str) -> float | None:
    if source_type == "identity":
        for key in ("riskScore", "riskScoreAggregated", "riskLevel", "confidence"):
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
        status = row.get("status")
        if isinstance(status, dict):
            try:
                error_code = int(status.get("errorCode", 0) or 0)
            except (TypeError, ValueError):
                error_code = 1
            return 95.0 if error_code == 0 else 80.0
        return 75.0
    if source_type == "audit":
        status_text = _status_text(row).lower()
        if any(token in status_text for token in ("failure", "denied", "blocked", "error")):
            return 85.0
        return 70.0
    return None


def _title_from_row(row: dict[str, Any], source_type: str) -> str:
    if source_type == "identity":
        return str(
            _first_present(
                row,
                (
                    "activityDisplayName",
                    "appDisplayName",
                    "userPrincipalName",
                    "userDisplayName",
                    "displayName",
                ),
            )
            or "Entra identity event"
        )
    return str(
        _first_present(
            row,
            (
                "activityDisplayName",
                "operationName",
                "activity",
                "displayName",
                "initiatedBy",
            ),
        )
        or "Entra audit event"
    )


def _summary_from_row(row: dict[str, Any], source_type: str) -> str:
    keys = []
    if source_type == "identity":
        keys = [
            "createdDateTime",
            "userPrincipalName",
            "ipAddress",
            "appDisplayName",
            "resourceDisplayName",
            "conditionalAccessStatus",
            "status",
            "riskState",
        ]
    else:
        keys = [
            "activityDateTime",
            "activityDisplayName",
            "operationName",
            "category",
            "initiatedBy",
            "targetResources",
            "status",
        ]
    parts: list[str] = []
    for key in keys:
        value = row.get(key)
        if value in (None, ""):
            continue
        if isinstance(value, (dict, list)):
            value_text = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
        else:
            value_text = str(value)
        parts.append(f"{key}={value_text}")
    if parts:
        return "; ".join(parts)
    selected = list(row.items())[:4]
    return ", ".join(f"{key}={value}" for key, value in selected) if selected else f"Entra {source_type} event"


def _observed_at_from_row(row: dict[str, Any], source_type: str) -> datetime:
    if source_type == "identity":
        keys = ("createdDateTime", "signInDateTime", "activityDateTime", "timestamp")
    else:
        keys = ("activityDateTime", "createdDateTime", "timestamp", "dateTime")
    for key in keys:
        observed_at = _parse_timestamp(row.get(key))
        if observed_at is not None:
            return observed_at
    return _now()


def _normalize_batch(
    query: IntegrationQuery,
    payload: Any,
    *,
    source_type: str,
    endpoint_name: str,
    partial: bool = False,
    error: str | None = None,
) -> EvidenceBatch:
    records: list[NormalizedEvidence] = []
    for row_index, row in enumerate(_payload_rows(payload)):
        if not _row_matches_query(row, query):
            continue

        title = _title_from_row(row, source_type)
        observed_at = _observed_at_from_row(row, source_type)
        severity = _severity_from_identity_row(row) if source_type == "identity" else _severity_from_audit_row(row)
        confidence = _confidence_from_row(row, source_type)
        raw_ref = str(
            _first_present(row, ("id", "correlationId", "requestId", "activityId", "auditId"))
            or f"{endpoint_name}:{row_index}"
        )
        records.append(
            NormalizedEvidence(
                source="entra",
                source_type=source_type,
                entity_type=query.entity_type,
                entity_value=query.entity_value,
                title=title,
                summary=_summary_from_row(row, source_type),
                severity=severity,
                confidence=confidence,
                observed_at=observed_at,
                raw_ref=f"entra:{_slugify(endpoint_name)}:{_slugify(raw_ref)}",
                tags=sorted(
                    {
                        "entra",
                        source_type,
                        _slugify(endpoint_name),
                        _slugify(title),
                        _slugify(query.entity_type),
                    }
                    - {""}
                ),
                attributes={
                    "endpoint": endpoint_name,
                    "row_index": row_index,
                    "row": row,
                },
            )
        )

    return EvidenceBatch(
        adapter_name="entra",
        query=query,
        records=records,
        partial=partial or error is not None,
        error=error,
    )


class EntraAdapter(BaseIntegrationAdapter):
    name = "entra"
    supports_read = True
    supports_write = True

    def __init__(
        self,
        *,
        tenant_id: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        bearer_token: str | None = None,
        base_url: str | None = None,
        scope: str = "https://graph.microsoft.com/.default",
        client_factory: ClientFactory | None = None,
        auth: MicrosoftAuthHelper | None = None,
    ):
        self.base_url = (base_url or os.getenv("SOC_ENTRA_BASE_URL") or "https://graph.microsoft.com").rstrip("/")
        self.signins_path = os.getenv("SOC_ENTRA_SIGNINS_PATH", "/v1.0/auditLogs/signIns")
        self.audits_path = os.getenv("SOC_ENTRA_AUDIT_PATH", "/v1.0/auditLogs/directoryAudits")
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))
        self._auth = auth or MicrosoftAuthHelper(
            MicrosoftAuthConfig(
                tenant_id=tenant_id or os.getenv("SOC_ENTRA_TENANT_ID", ""),
                client_id=client_id or os.getenv("SOC_ENTRA_CLIENT_ID", ""),
                client_secret=client_secret or os.getenv("SOC_ENTRA_CLIENT_SECRET", ""),
                bearer_token=bearer_token or os.getenv("SOC_ENTRA_BEARER_TOKEN", ""),
                scope=scope,
            ),
            client_factory=self._client_factory,
        )

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        requested_source_types = self._requested_source_types(query)
        if not requested_source_types:
            requested_source_types = ("identity", "audit")

        if not self._has_auth_config():
            return EvidenceBatch(
                adapter_name=self.name,
                query=query,
                records=[],
                partial=True,
                error="SOC_ENTRA_BEARER_TOKEN or SOC_ENTRA_TENANT_ID/SOC_ENTRA_CLIENT_ID/SOC_ENTRA_CLIENT_SECRET not set",
            )

        headers = await self._auth.authorization_headers()
        records: list[NormalizedEvidence] = []
        errors: list[str] = []

        if "identity" in requested_source_types:
            payload, error = await self._fetch_collection(
                path=self.signins_path,
                headers=headers,
            )
            if error:
                errors.append(f"signIns: {error}")
            else:
                batch = _normalize_batch(
                    query,
                    payload,
                    source_type="identity",
                    endpoint_name="signIns",
                )
                records.extend(batch.records)

        if "audit" in requested_source_types:
            payload, error = await self._fetch_collection(
                path=self.audits_path,
                headers=headers,
            )
            if error:
                errors.append(f"directoryAudits: {error}")
            else:
                batch = _normalize_batch(
                    query,
                    payload,
                    source_type="audit",
                    endpoint_name="directoryAudits",
                )
                records.extend(batch.records)

        return EvidenceBatch(
            adapter_name=self.name,
            query=query,
            records=records,
            partial=bool(errors),
            error="; ".join(errors) if errors else None,
        )

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        action_type = (request.action_type or "").strip().lower()
        if action_type not in {"disable_account", "revoke_sessions", "enable_account"}:
            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="unsupported",
                executed=False,
                message=f"Entra adapter does not support action_type {request.action_type!r}",
                metadata={"requested_by": request.requested_by},
            )

        try:
            headers = await self._auth.authorization_headers()
            user_id = str(
                request.metadata.get("user_id")
                or request.metadata.get("user_principal_name")
                or request.metadata.get("upn")
                or request.target
            )
            if action_type == "disable_account":
                url = self._graph_v1_url(f"/users/{user_id}")
                body = {"accountEnabled": False}
                method = "patch"
            elif action_type == "enable_account":
                url = self._graph_v1_url(f"/users/{user_id}")
                body = {"accountEnabled": True}
                method = "patch"
            else:
                url = self._graph_v1_url(f"/users/{user_id}/revokeSignInSessions")
                body = None
                method = "post"

            async with self._client_factory() as client:
                if method == "patch":
                    response = await client.patch(
                        url,
                        headers={**headers, "Content-Type": "application/json", "Accept": "application/json"},
                        json=body,
                    )
                else:
                    response = await client.post(
                        url,
                        headers={**headers, "Content-Type": "application/json", "Accept": "application/json"},
                    )
                response.raise_for_status()
                response_payload = response.json() if hasattr(response, "json") else {}

            return ActionExecutionResult(
                adapter_name=self.name,
                action_type=request.action_type,
                target=request.target,
                status="executed",
                executed=True,
                rollback_supported=action_type == "disable_account",
                message=(
                    "User account disabled successfully"
                    if action_type == "disable_account"
                    else "User account enabled successfully"
                    if action_type == "enable_account"
                    else "User sign-in sessions revoked successfully"
                ),
                metadata={
                    "requested_by": request.requested_by,
                    "user_id": user_id,
                    "request": body or {},
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

    def _has_auth_config(self) -> bool:
        auth = self._auth._config
        return bool(auth.bearer_token or (auth.tenant_id and auth.client_id and auth.client_secret))

    def _requested_source_types(self, query: IntegrationQuery) -> tuple[str, ...]:
        context = query.context or {}
        raw = (
            context.get("source_types")
            or context.get("sources")
            or context.get("collect")
            or context.get("kind")
        )
        values: list[str] = []
        if isinstance(raw, str):
            values = [raw]
        elif isinstance(raw, (list, tuple, set)):
            values = [str(item) for item in raw]
        elif raw is not None:
            values = [str(raw)]
        normalized = {
            str(value).strip().lower().replace(" ", "_").replace("-", "_")
            for value in values
        }
        result = []
        for candidate in ("identity", "audit"):
            if candidate in normalized:
                result.append(candidate)
        return tuple(result)

    async def _fetch_collection(
        self,
        *,
        path: str,
        headers: dict[str, str],
    ) -> tuple[dict[str, Any] | list[dict[str, Any]] | None, str | None]:
        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"
        try:
            async with self._client_factory() as client:
                response = await client.get(
                    url,
                    headers={
                        **headers,
                        "Accept": "application/json",
                    },
                )
                response.raise_for_status()
                return response.json(), None
        except Exception as exc:
            return None, str(exc)

    def _graph_v1_url(self, path: str) -> str:
        base = self.base_url
        if base.endswith("/v1.0"):
            return f"{base}/{path.lstrip('/')}"
        return f"{base}/v1.0/{path.lstrip('/')}"
