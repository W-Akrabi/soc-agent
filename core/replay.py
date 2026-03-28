from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from core.memory_store import MemoryStore


def _reconstruct_alert(alert_json: str):
    """Deserialize a stored alert JSON string back to an Alert dataclass."""
    try:
        from core.models import Alert, AlertType, Severity, reconstruct_alert_from_json
    except Exception:  # pragma: no cover - current checkout fallback
        Alert = AlertType = Severity = reconstruct_alert_from_json = None

    if reconstruct_alert_from_json is not None:
        return reconstruct_alert_from_json(alert_json)

    from core.models import Alert, AlertType, Severity

    data = json.loads(alert_json)
    return Alert(
        id=data["id"],
        type=AlertType(data["type"]),
        severity=Severity(data["severity"]),
        timestamp=datetime.fromisoformat(data["timestamp"]),
        raw_payload=data.get("raw_payload", {}),
        source_ip=data.get("source_ip"),
        dest_ip=data.get("dest_ip"),
        source_port=data.get("source_port"),
        dest_port=data.get("dest_port"),
        hostname=data.get("hostname"),
        user_account=data.get("user_account"),
        process=data.get("process"),
        tags=data.get("tags", []),
    )


async def replay_investigation(
    run_id: str,
    memory_store: MemoryStore,
    config: Any,
    *,
    dry_run: bool = True,
    console: Any | None = None,
):
    """Re-run a past investigation identified by its run_id."""
    from core.app import run_investigation

    memory = memory_store.get_memory_by_run_id(run_id)
    if memory is None:
        raise ValueError(
            f"run_id {run_id!r} not found in memory store. "
            "Cannot replay an investigation that was never recorded."
        )

    alert = _reconstruct_alert(memory.alert_json)
    return await run_investigation(
        config=config,
        alert=alert,
        dry_run=dry_run,
        console=console,
    )


__all__ = ["replay_investigation"]
