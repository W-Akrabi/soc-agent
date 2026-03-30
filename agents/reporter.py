import json
import os
from datetime import datetime, timezone
from pathlib import Path
from agents.base import AgentBase
from core.models import Alert

SYSTEM_PROMPT = """You are a SOC Incident Reporter.
Given the complete Case Graph of an investigation, write a structured incident report in markdown.
Include these sections:
# Incident Report
## Executive Summary (2-3 sentences)
## Alert Details (type, severity, timestamp, IPs, hostname)
## Recon Findings
## Normalized Evidence by Source
## Threat Intelligence
## Attack Timeline
## Remediation Actions (proposed, approved, executed, rolled back)
## Open Questions
## Recommended Next Steps

Note any gaps where an agent failed or data is unavailable.
Be specific with IPs, CVE IDs, timestamps, and file hashes."""


class ReporterAgent(AgentBase):
    name = "reporter"

    def __init__(self, *args, reports_dir: str = "./reports", **kwargs):
        super().__init__(*args, **kwargs)
        self.reports_dir = reports_dir

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Synthesizing investigation findings into report")

        full_graph = self.graph.get_full_graph()
        summary = {
            "alert_id": alert.id,
            "alert_type": alert.type.value,
            "severity": alert.severity.value,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "hostname": alert.hostname,
            "user_account": alert.user_account,
            "node_counts": {t: 0 for t in ["ip", "cve", "finding", "evidence", "timeline_event", "action", "task"]},
            "evidence_by_source": {},
            "findings": [],
            "cves": [],
            "timeline": [],
            "actions": [],
            "proposed_actions": [],
            "executed_actions": [],
            "action_status_counts": {},
            "failed_tasks": [],
        }
        for node in full_graph["nodes"]:
            t = node["type"]
            if t in summary["node_counts"]:
                summary["node_counts"][t] += 1
            if t == "evidence":
                evidence = {**node["data"], "status": node["status"], "node_id": node["id"]}
                source = evidence.get("source", "unknown")
                summary["evidence_by_source"].setdefault(source, []).append(evidence)
            if t == "finding":
                summary["findings"].append(node["data"])
            elif t == "cve":
                summary["cves"].append(node["data"])
            elif t == "timeline_event":
                summary["timeline"].append(node["data"])
            elif t == "action":
                action = {**node["data"], "status": node["status"], "node_id": node["id"]}
                summary["actions"].append(action)
                summary["action_status_counts"][node["status"]] = summary["action_status_counts"].get(node["status"], 0) + 1
                if node["status"] in {"proposed", "awaiting_approval", "approved", "executing"}:
                    summary["proposed_actions"].append(action)
                elif node["status"] in {"executed", "rolled_back"}:
                    summary["executed_actions"].append(action)
            elif t == "task" and node["status"] == "failed":
                summary["failed_tasks"].append(node["label"])

        context = json.dumps(summary, indent=2)
        report_response = await self.llm.call(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Investigation data:\n{context}"}],
            max_tokens=8192,
        )
        report_text = report_response.text if hasattr(report_response, "text") else str(report_response)

        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M")
        filename = f"{ts}-{alert.id[:8]}.md"
        report_path = os.path.join(self.reports_dir, filename)
        with open(report_path, "w") as f:
            f.write(report_text)

        self.console.rule("[bold green]INCIDENT REPORT[/bold green]")
        self.console.print(report_text)
        self.console.rule()
        self.log(f"Report saved: {report_path}", style="bold green")
