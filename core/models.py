import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class AlertType(Enum):
    INTRUSION = "intrusion"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    ANOMALY = "anomaly"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionStatus(Enum):
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    EXECUTED = "executed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"
    FAILED = "failed"


@dataclass
class Alert:
    id: str
    type: AlertType
    severity: Severity
    timestamp: datetime
    raw_payload: dict
    source_ip: str | None = None
    dest_ip: str | None = None
    source_port: int | None = None
    dest_port: int | None = None
    user_account: str | None = None
    hostname: str | None = None
    process: str | None = None
    tags: list[str] = field(default_factory=list)


def reconstruct_alert_from_json(alert_json: str) -> Alert:
    """Deserialize a persisted alert payload back into an Alert."""
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
        tags=list(data.get("tags", [])),
    )
