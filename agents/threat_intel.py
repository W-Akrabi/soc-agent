import json

from agents.base import AgentBase
from core.models import Alert
from core.schemas import IntegrationQuery
from tools.cve_search import CVESearchTool
from integrations.threat_intel import ThreatIntelAdapter, evidence_record_to_dict

SYSTEM_PROMPT = """You are a Threat Intelligence Analyst in a SOC investigation.
Given the Case Graph findings (IPs, ports, domains), look up CVEs and threat feeds.
Identify what threat actor or campaign this may be associated with.
Respond with a 2-3 sentence threat assessment."""


class ThreatIntelAgent(AgentBase):
    name = "threat_intel"

    def __init__(self, *args, threat_adapter: ThreatIntelAdapter | None = None, use_env_adapter: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self.cve_tool = CVESearchTool()
        self.threat_adapter = threat_adapter if threat_adapter is not None else (ThreatIntelAdapter() if use_env_adapter else None)

    def _write_evidence_nodes(self, evidence_records, *, related_node_id: str | None = None):
        evidence_payloads = []
        for record in evidence_records:
            payload = evidence_record_to_dict(record)
            evidence_payloads.append(payload)
            evidence_node_id = self.graph.write_node(
                type="evidence",
                label=record.title,
                data=payload,
                created_by=self.name,
            )
            if related_node_id:
                self.graph.write_edge(related_node_id, evidence_node_id, "supports", self.name)
        return evidence_payloads

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Starting threat intelligence lookups")

        cve_findings = []
        evidence_findings = []

        if self.threat_adapter is None:
            self.log("Threat intel integration not configured; continuing without external evidence", style="yellow")

        ip_nodes = self.graph.get_nodes_by_type("ip")
        for ip_node in ip_nodes:
            ip = ip_node["label"]
            if ip.startswith("10.") or ip.startswith("192.168."):
                continue  # Skip internal IPs

            if self.threat_adapter is not None:
                batch = await self.threat_adapter.collect(
                    IntegrationQuery(
                        alert_id=alert.id,
                        alert_type=alert.type.value,
                        entity_type="ip",
                        entity_value=ip,
                        context={"source_ports": ip_node["data"].get("open_ports", [])},
                    )
                )
                evidence_findings.extend(self._write_evidence_nodes(batch.records, related_node_id=ip_node["id"]))

            for port_info in ip_node["data"].get("open_ports", []):
                cve_result = await self.cve_tool.run({"port": port_info["port"], "service": port_info.get("service", "")})
                for cve in cve_result.get("cves", []):
                    cve_findings.append(cve)
                    node_id = self.graph.write_node(
                        type="cve", label=cve["id"],
                        data=cve, created_by=self.name
                    )
                    self.graph.write_edge(ip_node["id"], node_id, "linked_to", self.name)

        file_hash = alert.raw_payload.get("file_hash")
        if file_hash and self.threat_adapter is not None:
            batch = await self.threat_adapter.collect(
                IntegrationQuery(
                    alert_id=alert.id,
                    alert_type=alert.type.value,
                    entity_type="hash",
                    entity_value=file_hash,
                    context={"source": "alert_payload"},
                )
            )
            evidence_findings.extend(self._write_evidence_nodes(batch.records))

        context = (
            f"Alert type: {alert.type.value}\n"
            f"CVEs found: {json.dumps(cve_findings)}\n"
            f"Evidence: {json.dumps(evidence_findings)}"
        )
        assessment = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])

        self.graph.write_node(
            type="finding", label=f"intel-assessment-{alert.id}",
            data={"assessment": assessment, "cves": cve_findings, "evidence": evidence_findings},
            created_by=self.name
        )
        self.log(assessment[:120] + "..." if len(assessment) > 120 else assessment)
