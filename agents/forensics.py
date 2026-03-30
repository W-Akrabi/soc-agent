from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from agents.base import AgentBase
from core.models import Alert
from core.schemas import IntegrationQuery, NormalizedEvidence
from integrations.entra import EntraAdapter
from tools.log_parser import LogParserTool

SYSTEM_PROMPT = """You are a Digital Forensics Investigator in a SOC investigation.
Given the alert payload and parsed logs, reconstruct the attack timeline.
Identify: initial access vector, lateral movement, persistence, data touched.
List the timeline events in chronological order. Be specific about timestamps.

If timeline reconstruction reveals an unknown external IP or domain not already in the
case graph, use dispatch_agent to request recon or threat_intel analysis with that
specific indicator. Only dispatch when the timeline surfaces a new IOC."""


class ForensicsAgent(AgentBase):
    name = "forensics"

    def __init__(
        self,
        *args,
        entra_adapter: EntraAdapter | None = None,
        use_env_adapter: bool = True,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.log_tool = LogParserTool()
        self.entra_adapter = entra_adapter if entra_adapter is not None else (
            self._build_entra_adapter_from_env() if use_env_adapter else None
        )

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Starting forensic log analysis")

        logs = alert.raw_payload.get("logs", [])
        parsed = await self.log_tool.run({"logs": logs})
        entra_records, entra_errors = await self._collect_entra_records(alert)

        timeline_items = []
        for event in parsed.get("events", []):
            timeline_items.append(self._timeline_item_from_log(event))
        for record in entra_records:
            timeline_items.append(self._timeline_item_from_evidence(record))
        timeline_items.sort(key=lambda item: item["sort_at"])

        prev_node_id = None
        for item in timeline_items:
            node_id = self.graph.write_node(
                type=item["node_type"],
                label=item["label"],
                data=item["data"],
                created_by=self.name,
            )
            if prev_node_id:
                self.graph.write_edge(prev_node_id, node_id, "followed_by", self.name)
            prev_node_id = node_id

        context_parts = [
            f"Alert: {alert.type.value} | Severity: {alert.severity.value}",
            f"Parsed events:\n{json.dumps(parsed.get('events', []), indent=2, default=str)}",
        ]
        if entra_records:
            context_parts.append(
                "Identity and audit evidence:\n"
                + json.dumps(
                    [self._serialise_evidence(record) for record in entra_records],
                    indent=2,
                    default=str,
                )
            )
        if entra_errors:
            context_parts.append(f"Entra collection warnings: {json.dumps(entra_errors)}")
        context = "\n\n".join(context_parts)
        analysis = await self._llm_call_with_dispatch(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": context}],
        )

        self.graph.write_node(
            type="timeline_event",
            label=f"attack-chain-{alert.id}",
            data={
                "analysis": analysis,
                "event_count": len(timeline_items),
                "parsed_event_count": len(parsed.get("events", [])),
                "identity_event_count": len(entra_records),
                "identity_collection_warnings": entra_errors,
            },
            created_by=self.name
        )
        if self.dispatch_context is not None:
            self.graph.write_node(
                type="finding",
                label=f"dispatch-summary:forensics:{task_node_id}",
                data={"summary": analysis},
                created_by=self.name,
            )
        self.log(f"Reconstructed {len(timeline_items)} events")
        self.log(analysis[:120] + "..." if len(analysis) > 120 else analysis)

    def _build_entra_adapter_from_env(self) -> EntraAdapter | None:
        enabled = {
            value.strip().lower()
            for value in os.getenv("SOC_ENABLED_INTEGRATIONS", "").split(",")
            if value.strip()
        }
        if "entra" not in enabled:
            return None

        return EntraAdapter(
            tenant_id=os.getenv("SOC_ENTRA_TENANT_ID"),
            client_id=os.getenv("SOC_ENTRA_CLIENT_ID"),
            client_secret=os.getenv("SOC_ENTRA_CLIENT_SECRET"),
            bearer_token=os.getenv("SOC_ENTRA_BEARER_TOKEN"),
            base_url=os.getenv("SOC_ENTRA_BASE_URL"),
        )

    async def _collect_entra_records(self, alert: Alert) -> tuple[list[NormalizedEvidence], list[str]]:
        if self.entra_adapter is None:
            return [], []

        queries: list[IntegrationQuery] = []
        seen_targets: set[tuple[str, str]] = set()
        for entity_type, value in self._identity_targets(alert):
            key = (entity_type, value)
            if not value or key in seen_targets:
                continue
            seen_targets.add(key)
            queries.append(
                IntegrationQuery(
                    alert_id=alert.id,
                    alert_type=alert.type.value,
                    entity_type=entity_type,
                    entity_value=value,
                    context={"source_types": ["identity", "audit"]},
                )
            )

        records: list[NormalizedEvidence] = []
        warnings: list[str] = []
        seen_refs: set[str] = set()
        for query in queries:
            try:
                batch = await self.entra_adapter.collect(query)
            except Exception as exc:
                warnings.append(str(exc))
                continue
            if batch.error:
                warnings.append(batch.error)
            for record in batch.records:
                key = record.raw_ref or f"{record.source}:{record.source_type}:{record.entity_value}:{record.title}"
                if key in seen_refs:
                    continue
                seen_refs.add(key)
                records.append(record)

        return records, warnings

    def _identity_targets(self, alert: Alert) -> list[tuple[str, str]]:
        targets: list[tuple[str, str]] = []
        for entity_type, value in (
            ("user", alert.user_account),
            ("ip", alert.source_ip),
        ):
            if value:
                targets.append((entity_type, value))

        if alert.raw_payload:
            for key in ("user_account", "user", "user_principal_name", "upn", "source_ip"):
                value = alert.raw_payload.get(key)
                if value:
                    entity_type = "ip" if "ip" in key else "user"
                    targets.append((entity_type, str(value)))

        return targets

    def _timeline_item_from_log(self, event: dict[str, Any]) -> dict[str, Any]:
        event_copy = dict(event)
        sort_at = self._event_timestamp(event_copy)
        event_copy.setdefault("source", "log")
        timestamp_text = event_copy.get("timestamp") or sort_at.isoformat()
        event_label = event_copy.get("event_type") or event_copy.get("event") or "log event"
        return {
            "node_type": "log_entry",
            "label": f"{event_label} @ {timestamp_text}",
            "data": event_copy,
            "sort_at": sort_at,
        }

    def _timeline_item_from_evidence(self, record: NormalizedEvidence) -> dict[str, Any]:
        payload = self._serialise_evidence(record)
        sort_at = record.observed_at or datetime.now(timezone.utc)
        return {
            "node_type": "timeline_event",
            "label": f"{record.title} @ {sort_at.isoformat()}",
            "data": payload,
            "sort_at": sort_at,
        }

    def _serialise_evidence(self, record: NormalizedEvidence) -> dict[str, Any]:
        payload = asdict(record)
        observed_at = payload.get("observed_at")
        if observed_at is not None:
            payload["observed_at"] = observed_at.isoformat()
        return payload

    def _event_timestamp(self, event: dict[str, Any]) -> datetime:
        for key in ("timestamp", "ts", "observed_at", "createdDateTime", "activityDateTime"):
            value = event.get(key)
            if isinstance(value, datetime):
                return value.astimezone(timezone.utc)
            if isinstance(value, str):
                normalized = value.replace("Z", "+00:00")
                try:
                    parsed = datetime.fromisoformat(normalized)
                except ValueError:
                    continue
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)
        return datetime.now(timezone.utc)
