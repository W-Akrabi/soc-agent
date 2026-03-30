import json

from agents.base import AgentBase
from core.models import Alert
from core.schemas import IntegrationQuery
from integrations.defender import evidence_record_to_dict
from tools.ip_lookup import IPLookupTool
from tools.whois_lookup import WHOISTool
from tools.port_scan import PortScanTool

SYSTEM_PROMPT = """You are a Reconnaissance Specialist in a SOC investigation.
You have access to IP lookup, WHOIS, and port scan tools.
Given an alert, gather all available information about the involved IPs, domains, hostnames.
Think step by step. Use tools in order: IP lookup → WHOIS → port scan.
Summarize what you found in 2-3 sentences.

If you discover a file hash, malware sample, or forensic artifact, use dispatch_agent to
request forensics analysis with the specific artifact as context. If you find a suspicious
IP with no clear attribution, use dispatch_agent to request threat_intel analysis.
Only dispatch when you have a specific concrete IOC, not as a general enrichment step."""


class ReconAgent(AgentBase):
    name = "recon"

    def __init__(self, *args, integration_registry=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_tool = IPLookupTool()
        self.whois_tool = WHOISTool()
        self.port_tool = PortScanTool()
        self.integration_registry = integration_registry

    def _get_defender_adapter(self):
        registry = self.integration_registry
        if not registry:
            return None
        getter = getattr(registry, "get", None)
        if not callable(getter):
            return None
        try:
            return getter("defender")
        except KeyError:
            return None

    def _build_defender_queries(self, alert: Alert) -> list[IntegrationQuery]:
        queries: list[IntegrationQuery] = []
        seen: set[tuple[str, str]] = set()

        def add_query(entity_value: str | None, *, entity_type: str, source: str, context: dict | None = None):
            if not entity_value:
                return
            key = (entity_type, entity_value)
            if key in seen:
                return
            seen.add(key)
            queries.append(
                IntegrationQuery(
                    alert_id=alert.id,
                    alert_type=alert.type.value,
                    entity_type=entity_type,
                    entity_value=entity_value,
                    context={"source": source, **(context or {})},
                )
            )

        add_query(alert.hostname, entity_type="host", source="alert.hostname")
        add_query(alert.source_ip, entity_type="host", source="alert.source_ip", context={"ip_address": alert.source_ip})
        add_query(alert.dest_ip, entity_type="host", source="alert.dest_ip", context={"ip_address": alert.dest_ip})

        raw_payload = alert.raw_payload or {}
        for key in ("file_hash", "sha256", "sha1", "md5"):
            add_query(raw_payload.get(key), entity_type="file", source=f"alert.raw_payload.{key}")
        file_path = raw_payload.get("file_path") or raw_payload.get("path") or raw_payload.get("filename")
        add_query(file_path, entity_type="file", source="alert.raw_payload.file_path", context={"file_path": file_path})

        return queries

    def _write_defender_evidence(self, batch, *, alert_node_id: str | None = None):
        records = []
        for record in batch.records:
            payload = evidence_record_to_dict(record)
            records.append(payload)
            evidence_node_id = self.graph.write_node(
                type="evidence",
                label=record.title,
                data=payload,
                created_by=self.name,
            )
            if alert_node_id:
                self.graph.write_edge(alert_node_id, evidence_node_id, "supports", self.name)
        return records

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log(f"Starting recon for alert {alert.id}")

        findings = {}
        defender_findings = []
        alert_nodes = self.graph.get_nodes_by_type("alert")
        alert_node_id = alert_nodes[0]["id"] if alert_nodes else None

        defender = self._get_defender_adapter()
        if defender is not None:
            for query in self._build_defender_queries(alert):
                batch = await defender.collect(query)
                if batch.records:
                    defender_findings.extend(self._write_defender_evidence(batch, alert_node_id=alert_node_id))
                elif batch.partial and batch.error:
                    self.log(f"Defender lookup for {query.entity_type}:{query.entity_value} returned no evidence: {batch.error}", style="yellow")
        elif self.integration_registry is not None and getattr(self.integration_registry, "names", lambda: ())():
            self.log("Defender integration not configured; continuing without Defender evidence", style="yellow")

        if alert.source_ip:
            self.log(f"Querying {alert.source_ip}...")
            ip_data = await self.ip_tool.run({"ip": alert.source_ip})
            port_data = await self.port_tool.run({"ip": alert.source_ip})
            findings["source_ip"] = {**ip_data, **port_data}

            ip_node_id = self.graph.write_node(
                type="ip", label=alert.source_ip,
                data={**ip_data, "open_ports": port_data.get("open_ports", [])},
                created_by=self.name
            )

            if alert_node_id:
                self.graph.write_edge(alert_node_id, ip_node_id, "involves", self.name)

        if alert.dest_ip:
            dest_data = await self.ip_tool.run({"ip": alert.dest_ip})
            self.graph.write_node(type="ip", label=alert.dest_ip, data=dest_data, created_by=self.name)

        if defender_findings:
            findings["defender"] = defender_findings

        user_msg = f"Alert: {json.dumps({'type': alert.type.value, 'severity': alert.severity.value, 'source_ip': alert.source_ip, 'dest_ip': alert.dest_ip, 'hostname': alert.hostname})}\n\nTool findings: {json.dumps(findings)}"
        summary = await self._llm_call_with_dispatch(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )

        self.graph.write_node(
            type="finding", label=f"recon-summary-{alert.id}",
            data={"summary": summary, "raw_findings": findings},
            created_by=self.name
        )
        if self.dispatch_context is not None:
            self.graph.write_node(
                type="finding",
                label=f"dispatch-summary:recon:{task_node_id}",
                data={"summary": summary},
                created_by=self.name,
            )
        self.log(summary[:120] + "..." if len(summary) > 120 else summary)
