from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

from core.blast_radius import estimate_blast_radius, rollback_details
from core.execution_policy import ExecutionPolicy
from core.schemas import ActionExecutionRequest
from tools.base import BaseTool


class ActionExecutorTool(BaseTool):
    name = "action_executor"
    description = "Execute or suggest remediation actions"

    def __init__(
        self,
        auto_remediate: bool = False,
        *,
        policy: ExecutionPolicy | None = None,
        defender_adapter: Any | None = None,
        entra_adapter: Any | None = None,
        approval_queue: Any | None = None,
    ):
        self.auto_remediate = auto_remediate
        self.policy = policy
        self.defender_adapter = defender_adapter
        self.entra_adapter = entra_adapter
        self.approval_queue = approval_queue

    def _adapter_for(self, action_type: str):
        normalized = (action_type or "").strip().lower()
        if normalized in {"isolate_host", "unisolate_host"}:
            return self.defender_adapter
        if normalized in {"disable_account", "revoke_sessions", "enable_account"}:
            return self.entra_adapter
        return None

    async def run(self, input: dict) -> dict:
        action_type = input.get("action_type", "")
        target = input.get("target", "")
        urgency = input.get("urgency", "scheduled")
        reason = input.get("reason", "")
        metadata = dict(input.get("metadata") or {})

        if self.policy is None:
            should_execute = self.auto_remediate and urgency == "immediate"

            if should_execute:
                print(f"[ACTION EXECUTED] {action_type} → {target}")
                return {
                    "status": "executed",
                    "executed": True,
                    "action_type": action_type,
                    "target": target,
                }
            return {
                "status": "suggested",
                "executed": False,
                "action_type": action_type,
                "target": target,
            }

        request = ActionExecutionRequest(
            action_type=action_type,
            target=target,
            reason=reason,
            urgency=urgency,
            requested_by=input.get("requested_by", "remediation"),
            allow_execution=self.auto_remediate,
            metadata=metadata,
        )
        adapter = self._adapter_for(action_type)
        decision = self.policy.decide(request, adapter_supported=adapter is not None and getattr(adapter, "supports_write", False))

        if not decision.should_execute:
            queue_item = None
            if decision.status.value == "awaiting_approval" and self.approval_queue is not None:
                rollback_action_type, rollback_supported = rollback_details(action_type)
                queue_item = {
                    "action_id": str(metadata.get("approval_action_id") or uuid.uuid4()),
                    "run_id": str(metadata.get("run_id") or metadata.get("investigation_run_id") or ""),
                    "alert_id": str(metadata.get("alert_id") or ""),
                    "action_type": action_type,
                    "target": target,
                    "reason": reason,
                    "urgency": urgency,
                    "blast_radius": estimate_blast_radius(action_type, target),
                    "status": "pending",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "rollback_supported": rollback_supported,
                    "rollback_action_type": rollback_action_type,
                    "rollback_data": metadata.get("rollback_data") or metadata,
                    "execution_result": None,
                    "reviewed_at": None,
                    "reviewed_by": None,
                }
                queue_item = self.approval_queue.enqueue(queue_item)
            return {
                "status": decision.status.value,
                "executed": False,
                "action_type": action_type,
                "target": target,
                "message": decision.reason,
                "approval_queue": queue_item,
                "policy": {
                    "action_type": decision.action_type,
                    "status": decision.status.value,
                    "allowed": decision.allowed,
                    "should_execute": decision.should_execute,
                    "reason": decision.reason,
                    "metadata": decision.metadata,
                },
            }

        if adapter is None:
            return {
                "status": "proposed",
                "executed": False,
                "action_type": action_type,
                "target": target,
                "message": f"No adapter available for action_type {action_type!r}",
                "policy": {
                    "action_type": decision.action_type,
                    "status": decision.status.value,
                    "allowed": decision.allowed,
                    "should_execute": False,
                    "reason": f"No adapter available for action_type {action_type!r}",
                    "metadata": decision.metadata,
                },
            }

        request.metadata.setdefault("policy_reason", decision.reason)
        result = await adapter.execute(request)
        payload = {
            "status": result.status,
            "executed": result.executed,
            "action_type": result.action_type,
            "target": result.target,
            "message": result.message,
            "adapter_name": result.adapter_name,
            "external_id": result.external_id,
            "rollback_supported": result.rollback_supported,
            "metadata": result.metadata,
            "policy": {
                "action_type": decision.action_type,
                "status": decision.status.value,
                "allowed": decision.allowed,
                "should_execute": decision.should_execute,
                "reason": decision.reason,
                "metadata": decision.metadata,
            },
        }
        if result.executed:
            payload["status"] = "executed"
        return payload
