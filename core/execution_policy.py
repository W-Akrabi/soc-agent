from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.models import ActionStatus
from core.schemas import ActionExecutionRequest


def _normalize_action_type(action_type: str) -> str:
    return (action_type or "").strip().lower()


@dataclass(slots=True)
class ExecutionDecision:
    action_type: str
    status: ActionStatus
    allowed: bool
    should_execute: bool
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExecutionPolicy:
    enabled: bool = False
    allowed_actions: tuple[str, ...] = ()

    def is_allowlisted(self, action_type: str) -> bool:
        normalized = _normalize_action_type(action_type)
        return normalized in {item.strip().lower() for item in self.allowed_actions if item}

    def decide(
        self,
        request: ActionExecutionRequest,
        *,
        adapter_supported: bool = True,
    ) -> ExecutionDecision:
        action_type = _normalize_action_type(request.action_type)
        if not self.enabled:
            return ExecutionDecision(
                action_type=action_type,
                status=ActionStatus.PROPOSED,
                allowed=False,
                should_execute=False,
                reason="execution disabled; propose-only policy is active",
            )

        if not self.is_allowlisted(action_type):
            return ExecutionDecision(
                action_type=action_type,
                status=ActionStatus.PROPOSED,
                allowed=False,
                should_execute=False,
                reason=f"action_type {action_type!r} is not allowlisted",
            )

        if not adapter_supported:
            return ExecutionDecision(
                action_type=action_type,
                status=ActionStatus.PROPOSED,
                allowed=False,
                should_execute=False,
                reason=f"adapter does not support action_type {action_type!r}",
            )

        if not request.allow_execution:
            return ExecutionDecision(
                action_type=action_type,
                status=ActionStatus.AWAITING_APPROVAL,
                allowed=True,
                should_execute=False,
                reason=f"execution mode not enabled for {action_type!r}",
            )

        return ExecutionDecision(
            action_type=action_type,
            status=ActionStatus.APPROVED,
            allowed=True,
            should_execute=True,
            reason=f"{action_type!r} allowed by policy",
        )

    @classmethod
    def from_config(cls, config) -> "ExecutionPolicy":
        return cls(
            enabled=bool(getattr(config, "allow_integration_execution", False)),
            allowed_actions=tuple(getattr(config, "allowed_actions", ()) or ()),
        )
