import json
from agents.base import AgentBase
from core.models import ActionStatus, Alert
from core.execution_policy import ExecutionPolicy
from core.schemas import validate_action_proposals
from tools.action_executor import ActionExecutorTool

SYSTEM_PROMPT = """You are a SOC Remediation Specialist.
Given the Case Graph findings (CVEs, timeline, threat intel), propose containment actions.
For each action return a JSON array. Each item must have:
  action_type: block_ip | disable_account | isolate_host | revoke_sessions | patch_recommendation
  target: the specific IP, account, host, or CVE to act on
  reason: why this action is needed
  urgency: immediate | within_24h | scheduled

Respond ONLY with a valid JSON array. No other text."""


class RemediationAgent(AgentBase):
    name = "remediation"

    def __init__(
        self,
        *args,
        auto_remediate: bool = False,
        execution_policy: ExecutionPolicy | None = None,
        defender_adapter=None,
        entra_adapter=None,
        approval_queue=None,
        allowed_actions: tuple[str, ...] = (),
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        policy = execution_policy or ExecutionPolicy(
            enabled=auto_remediate,
            allowed_actions=allowed_actions,
        )
        self.executor = ActionExecutorTool(
            auto_remediate=auto_remediate,
            policy=policy,
            defender_adapter=defender_adapter,
            entra_adapter=entra_adapter,
            approval_queue=approval_queue,
        )
        self.approval_queue = approval_queue

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Analyzing findings for remediation actions")

        findings = self.graph.get_nodes_by_type("finding")
        cves = self.graph.get_nodes_by_type("cve")
        timeline = self.graph.get_nodes_by_type("timeline_event")
        run_id = getattr(self._event_log, "run_id", None)

        context = json.dumps({
            "alert": {"type": alert.type.value, "severity": alert.severity.value,
                      "source_ip": alert.source_ip, "user_account": alert.user_account, "hostname": alert.hostname},
            "findings": [f["data"] for f in findings],
            "cves": [c["data"] for c in cves],
            "timeline": [t["data"] for t in timeline],
        }, indent=2)

        raw = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])

        try:
            proposals = validate_action_proposals(raw)
        except ValueError as e:
            self.log(f"Action validation failed: {e}", style="yellow")
            proposals = []

        for proposal in proposals:
            action = {
                "action_type": proposal.action_type,
                "target": proposal.target,
                "reason": proposal.reason,
                "urgency": proposal.urgency,
                "metadata": {
                    "alert_id": alert.id,
                    "alert_type": alert.type.value,
                    "hostname": alert.hostname,
                    "user_account": alert.user_account,
                    "source_ip": alert.source_ip,
                    "run_id": run_id,
                    "task_node_id": task_node_id,
                },
            }
            result = await self.executor.run(action)
            action_status = self._status_from_result(result["status"])
            action_node_id = self.graph.write_node(
                type="action",
                label=f"{action.get('action_type', 'action')}:{action.get('target', '')}",
                data={**action, "result": result},
                created_by=self.name,
            )
            self.graph.update_node_status(action_node_id, action_status)
            self.log(
                f"[{action_status.upper()}] {action.get('action_type')} → "
                f"{action.get('target')} ({action.get('urgency')})"
            )

    def _status_from_result(self, status: str) -> str:
        mapping = {
            "executed": ActionStatus.EXECUTED.value,
            "approved": ActionStatus.APPROVED.value,
            "executing": ActionStatus.EXECUTING.value,
            "awaiting_approval": ActionStatus.AWAITING_APPROVAL.value,
            "rejected": ActionStatus.REJECTED.value,
            "failed": ActionStatus.FAILED.value,
            "unsupported": ActionStatus.PROPOSED.value,
            "suggested": ActionStatus.PROPOSED.value,
            "proposed": ActionStatus.PROPOSED.value,
        }
        return mapping.get(status, ActionStatus.PROPOSED.value)
