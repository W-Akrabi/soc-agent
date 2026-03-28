import json
from core.models import Alert
from ingestion.models import normalize_alert
from ingestion.simulator import generate_alert


def load_alert(source: str) -> Alert:
    """Load an alert from a file path or 'simulated'."""
    if source == "simulated":
        return generate_alert()
    with open(source) as f:
        raw = json.load(f)
    return normalize_alert(raw)
