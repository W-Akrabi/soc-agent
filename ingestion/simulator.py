import random
from ingestion.models import normalize_alert

_TEMPLATES = {
    "intrusion": {
        "type": "intrusion", "severity": "high",
        "source_ip": "185.220.101.45", "dest_ip": "10.0.1.50",
        "dest_port": 8080, "hostname": "web-prod-01",
        "raw_payload": {"rule_name": "EXPLOIT_ATTEMPT", "logs": []}
    },
    "malware": {
        "type": "malware", "severity": "critical",
        "source_ip": "10.0.2.88", "dest_ip": "91.108.4.200",
        "dest_port": 443, "hostname": "workstation-14", "user_account": "jdoe",
        "raw_payload": {"rule_name": "MALWARE_BEACON", "file_hash": "d41d8cd98f00b204e9800998ecf8427e", "logs": []}
    },
    "brute_force": {
        "type": "brute_force", "severity": "medium",
        "source_ip": "203.0.113.99", "dest_ip": "10.0.0.10",
        "dest_port": 22, "hostname": "bastion-01", "user_account": "admin",
        "raw_payload": {"rule_name": "SSH_BRUTE_FORCE", "attempt_count": 247, "logs": []}
    },
}


def generate_alert(alert_type: str = None) -> object:
    if alert_type is None:
        alert_type = random.choice(list(_TEMPLATES.keys()))
    if alert_type not in _TEMPLATES:
        alert_type = "intrusion"
    return normalize_alert(_TEMPLATES[alert_type])
