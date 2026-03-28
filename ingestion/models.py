import uuid
from datetime import datetime, timezone
from core.models import Alert, AlertType, Severity


def normalize_alert(raw: dict) -> Alert:
    """Normalize a raw dict into an Alert dataclass."""
    type_str = raw.get("type", "").lower().replace("-", "_")
    try:
        alert_type = AlertType(type_str)
    except ValueError:
        raise ValueError(f"Invalid alert type: '{type_str}'. Must be one of: {[e.value for e in AlertType]}")

    severity_str = raw.get("severity", "low").lower()
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.LOW

    return Alert(
        id=str(uuid.uuid4()),
        type=alert_type,
        severity=severity,
        timestamp=datetime.now(timezone.utc),
        raw_payload=raw.get("raw_payload", raw),
        source_ip=raw.get("source_ip"),
        dest_ip=raw.get("dest_ip"),
        source_port=raw.get("source_port"),
        dest_port=raw.get("dest_port"),
        user_account=raw.get("user_account"),
        hostname=raw.get("hostname"),
        process=raw.get("process"),
        tags=raw.get("tags", []),
    )
