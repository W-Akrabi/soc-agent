import json
import pytest
from ingestion.loader import load_alert
from ingestion.simulator import generate_alert
from core.models import AlertType, Severity


def test_load_alert_from_file(tmp_path):
    alert_data = {
        "type": "intrusion",
        "severity": "high",
        "source_ip": "192.168.1.100",
        "dest_ip": "10.0.0.5",
        "source_port": 54321,
        "dest_port": 22,
        "hostname": "web-server-01",
        "raw_payload": {"rule": "SSH_BRUTE_FORCE"}
    }
    alert_file = tmp_path / "test_alert.json"
    alert_file.write_text(json.dumps(alert_data))
    alert = load_alert(str(alert_file))
    assert alert.type == AlertType.INTRUSION
    assert alert.severity == Severity.HIGH
    assert alert.source_ip == "192.168.1.100"
    assert alert.dest_port == 22
    assert alert.id is not None  # UUID generated


def test_load_alert_missing_optional_fields(tmp_path):
    alert_data = {
        "type": "anomaly",
        "severity": "low",
        "raw_payload": {}
    }
    alert_file = tmp_path / "minimal.json"
    alert_file.write_text(json.dumps(alert_data))
    alert = load_alert(str(alert_file))
    assert alert.source_ip is None
    assert alert.tags == []


def test_load_alert_invalid_type(tmp_path):
    alert_data = {"type": "unknown_type", "severity": "high", "raw_payload": {}}
    alert_file = tmp_path / "bad.json"
    alert_file.write_text(json.dumps(alert_data))
    with pytest.raises(ValueError, match="Invalid alert type"):
        load_alert(str(alert_file))


def test_generate_simulated_alert():
    alert = generate_alert(alert_type="intrusion")
    assert alert.type == AlertType.INTRUSION
    assert alert.severity in list(Severity)
    assert alert.source_ip is not None


def test_load_alert_simulated():
    alert = load_alert("simulated")
    assert alert.type in list(AlertType)
    assert alert.id is not None
