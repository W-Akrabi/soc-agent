from __future__ import annotations

import json
from datetime import datetime, timezone

from core.llm_response import LLMResponse
from core.models import AlertType

_DEFAULT_ALERT_TYPE = AlertType.INTRUSION.value

_RESPONSES = {
    "intrusion": {
        "commander": '{"objective": "Investigate suspicious external IP exploiting web service on port 8080", "priority_agents": ["recon", "threat_intel", "forensics"]}',
        "recon": (
            "Reconnaissance complete. Source IP 185.220.101.45 is a known Tor exit node (ASN AS60117, RU) "
            "with ports 22, 80, and 8080 open. Destination host 10.0.1.50 is an internal web server. "
            "The connection pattern is consistent with an automated exploit attempt."
        ),
        "threat_intel": (
            "CVE-2024-1337 (CVSS 9.8) matches the HTTP service on port 8080 — a critical RCE vulnerability "
            "in popular web frameworks. The source IP 185.220.101.45 appears in threat feeds with 95% "
            "confidence as a Tor exit node used for scanning and exploitation. This is consistent with "
            "an opportunistic exploit campaign targeting unpatched web servers."
        ),
        "forensics": (
            "Attack timeline reconstructed from 5 log events:\n"
            "1. 03:12:01 — Initial connection established from 185.220.101.45 to port 8080\n"
            "2. 03:12:03 — Exploit payload sent (4096 bytes), targeting CVE-2024-1337\n"
            "3. 03:12:05 — Shell spawned under nginx process (initial access confirmed)\n"
            "4. 03:14:10 — Privilege escalation to root achieved\n"
            "5. 03:19:22 — Data staged at /tmp/.exfil (52 KB), suggesting imminent exfiltration\n"
            "Attack vector: unauthenticated RCE via HTTP. Attacker achieved root in under 3 minutes."
        ),
        "remediation": (
            '[{"action_type": "block_ip", "target": "185.220.101.45", "reason": "Known Tor exit node, confirmed exploit source", "urgency": "immediate"}, '
            '{"action_type": "isolate_host", "target": "web-prod-01", "reason": "Host compromised, root shell confirmed, data staged for exfil", "urgency": "immediate"}, '
            '{"action_type": "disable_account", "target": "www-data", "reason": "Account used as initial foothold", "urgency": "within_24h"}, '
            '{"action_type": "patch_recommendation", "target": "CVE-2024-1337", "reason": "Vulnerability exploited in this incident, patch all affected web servers", "urgency": "within_24h"}]'
        ),
        "reporter": """\
# Incident Report

**Severity:** 🔴 HIGH
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Investigation Status:** Complete

---

## Executive Summary

A critical intrusion was detected on web-prod-01 originating from known Tor exit node 185.220.101.45. \
The attacker exploited CVE-2024-1337 (CVSS 9.8) to achieve unauthenticated remote code execution, \
escalated to root within 3 minutes, and staged 52 KB of data for exfiltration. Immediate containment \
actions have been suggested.

---

## Alert Details

| Field | Value |
|---|---|
| Type | INTRUSION |
| Severity | HIGH |
| Source IP | 185.220.101.45 |
| Destination | 10.0.1.50:8080 (web-prod-01) |
| Process | nginx |
| Account | www-data |

---

## Recon Findings

- **185.220.101.45** — Tor exit node, ASN AS60117, Moscow RU, risk: HIGH
- Open ports: 22 (SSH), 80 (HTTP), 8080 (HTTP-ALT)
- **10.0.1.50** — Internal LAN host, web server

---

## Threat Intelligence

- **CVE-2024-1337** (CVSS 9.8) — Critical RCE in web frameworks, matches port 8080 service
- Source IP confirmed malicious in threat feeds (confidence: 95%) — categories: tor-exit-node, scanner
- Campaign assessment: opportunistic automated exploit targeting unpatched web services

---

## Attack Timeline

| Time | Event |
|---|---|
| 03:12:01 | Connection established from 185.220.101.45 → 10.0.1.50:8080 |
| 03:12:03 | Exploit payload delivered (4096 bytes) via CVE-2024-1337 |
| 03:12:05 | Shell spawned under nginx → initial access confirmed |
| 03:14:10 | Privilege escalation → root achieved |
| 03:19:22 | Data staged at /tmp/.exfil (52,428 bytes) — exfiltration imminent |

---

## Remediation Actions

| Action | Target | Urgency | Status |
|---|---|---|---|
| block_ip | 185.220.101.45 | immediate | SUGGESTED |
| isolate_host | web-prod-01 | immediate | SUGGESTED |
| disable_account | www-data | within_24h | SUGGESTED |
| patch_recommendation | CVE-2024-1337 | within_24h | SUGGESTED |

---

## Open Questions

- Was the staged data at /tmp/.exfil successfully exfiltrated before isolation?
- Are other hosts on the 10.0.1.x subnet running the same vulnerable service?
- Has the attacker established any persistence mechanisms beyond the staged files?

---

## Recommended Next Steps

1. **Immediately** isolate web-prod-01 from the network
2. **Immediately** block 185.220.101.45 at the perimeter firewall
3. Forensically image /tmp/.exfil to determine what data was staged
4. Scan all web servers for CVE-2024-1337 exposure
5. Review nginx access logs for earlier reconnaissance attempts
6. Check for lateral movement from web-prod-01 to internal hosts
""",
    },
    "malware": {
        "commander": '{"objective": "Investigate malware beaconing from endpoint to suspected command and control infrastructure", "priority_agents": ["recon", "threat_intel", "forensics"]}',
        "recon": (
            "Recon complete. Source host {hostname} is a Windows endpoint showing outbound TLS traffic to "
            "{dest_ip} on port 443. The destination resolves to infrastructure associated with malware "
            "command and control, and the pattern matches a beaconing endpoint."
        ),
        "threat_intel": (
            "Threat intelligence indicates {dest_ip} is associated with malware hosting and command-and-control "
            "activity. The observed file hash on {hostname} is consistent with a known malware family, and the endpoint behavior "
            "matches post-infection callback patterns."
        ),
        "forensics": (
            "Timeline reconstructed from endpoint telemetry:\n"
            "1. 08:01:12 — Suspicious executable launched from user profile\n"
            "2. 08:01:30 — Persistence artifact created in startup folder\n"
            "3. 08:02:05 — Outbound TLS beacon established to 198.51.100.77\n"
            "4. 08:05:44 — Credential access attempt detected\n"
            "5. 08:08:10 — Registry run key modified for persistence\n"
            "The activity is consistent with active malware infection and callback."
        ),
        "remediation": (
            '[{"action_type": "isolate_host", "target": "workstation-99", "reason": "Endpoint beaconing to suspected C2 infrastructure", "urgency": "immediate"}, '
            '{"action_type": "block_ip", "target": "198.51.100.77", "reason": "Malware C2 infrastructure", "urgency": "immediate"}, '
            '{"action_type": "disable_account", "target": "jdoe", "reason": "Potential credential compromise", "urgency": "within_24h"}, '
            '{"action_type": "patch_recommendation", "target": "malware-sample", "reason": "Remove malicious payload and persistence", "urgency": "within_24h"}]'
        ),
        "reporter": """\
# Incident Report

**Severity:** 🔴 HIGH
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Investigation Status:** Complete

---

## Executive Summary

A malware infection was detected on workstation-99. The endpoint established outbound beacons to suspected
command and control infrastructure and exhibited persistence, credential access, and registry modification
behavior. Immediate isolation is recommended.

---

## Alert Details

| Field | Value |
|---|---|
| Type | MALWARE |
| Severity | HIGH |
| Source IP | 10.0.2.88 |
| Destination | 198.51.100.77:443 |
| Hostname | workstation-99 |
| User Account | jdoe |

---

## Recon Findings

- **workstation-99** — internal Windows endpoint, suspected malware infection
- **198.51.100.77** — external host associated with malware C2 and hosting

---

## Threat Intelligence

- Destination infrastructure is associated with malware callback activity
- File hash and beacon pattern are consistent with known malicious tooling
- Confidence is high that the endpoint is actively compromised

---

## Attack Timeline

| Time | Event |
|---|---|
| 08:01:12 | Suspicious executable launched from user profile |
| 08:01:30 | Persistence artifact created in startup folder |
| 08:02:05 | Outbound TLS beacon established to 198.51.100.77 |
| 08:05:44 | Credential access attempt detected |
| 08:08:10 | Registry run key modified for persistence |

---

## Remediation Actions

| Action | Target | Urgency | Status |
|---|---|---|---|
| isolate_host | workstation-99 | immediate | SUGGESTED |
| block_ip | 198.51.100.77 | immediate | SUGGESTED |
| disable_account | jdoe | within_24h | SUGGESTED |
| patch_recommendation | malware-sample | within_24h | SUGGESTED |

---

## Recommended Next Steps

1. Isolate workstation-99 from the network
2. Collect the malicious binary and persistence artifacts
3. Hunt for the same beaconing pattern across other endpoints
4. Reset affected credentials if compromise is confirmed
""",
    },
    "brute_force": {
        "commander": '{"objective": "Investigate repeated authentication failures suggesting brute force activity", "priority_agents": ["recon", "threat_intel", "forensics"]}',
        "recon": (
            "Recon complete. Source IP 203.0.113.99 is a remote host generating repeated authentication attempts "
            "against bastion-01 over SSH. The volume and cadence indicate automated brute force activity."
        ),
        "threat_intel": (
            "Threat feeds indicate source IP {source_ip} is associated with credential-stuffing and brute force activity. "
            "The target service on {hostname} is exposed and vulnerable to repeated login attempts, but no confirmed compromise "
            "has yet been observed."
        ),
        "forensics": (
            "Timeline reconstructed from authentication logs:\n"
            "1. 02:14:01 — First failed SSH login attempt\n"
            "2. 02:14:10 — Burst of password guesses begins\n"
            "3. 02:15:44 — Rate of attempts increases significantly\n"
            "4. 02:18:22 — Source IP rotated through multiple usernames\n"
            "5. 02:24:05 — Account lockout triggered for admin\n"
            "The pattern is consistent with automated brute force and credential stuffing."
        ),
        "remediation": (
            '[{"action_type": "block_ip", "target": "203.0.113.99", "reason": "Automated brute force source", "urgency": "immediate"}, '
            '{"action_type": "disable_account", "target": "admin", "reason": "Account lockout and targeted credential attack", "urgency": "within_24h"}, '
            '{"action_type": "patch_recommendation", "target": "bastion-01", "reason": "Harden authentication and rate limiting", "urgency": "within_24h"}]'
        ),
        "reporter": """\
# Incident Report

**Severity:** {severity_badge}
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Investigation Status:** Complete

---

## Executive Summary

A brute force authentication campaign was detected against bastion-01. The source repeatedly attempted SSH
logins across multiple accounts, triggering lockout behavior. No confirmed compromise is evident in the
available data.

---

## Alert Details

| Field | Value |
|---|---|
| Type | BRUTE_FORCE |
| Severity | {severity_upper} |
| Source IP | 203.0.113.99 |
| Destination | 10.0.0.10:22 (bastion-01) |
| Account | admin |

---

## Recon Findings

- Source IP is consistent with automated credential abuse
- Target is an exposed SSH bastion host

---

## Threat Intelligence

- Source is associated with brute force and credential stuffing behavior
- Activity suggests repeated password guessing rather than targeted exploitation

---

## Attack Timeline

| Time | Event |
|---|---|
| 02:14:01 | First failed SSH login attempt |
| 02:14:10 | Burst of password guesses begins |
| 02:15:44 | Rate of attempts increases significantly |
| 02:18:22 | Source IP rotated through multiple usernames |
| 02:24:05 | Account lockout triggered for admin |

---

## Remediation Actions

| Action | Target | Urgency | Status |
|---|---|---|---|
| block_ip | 203.0.113.99 | immediate | SUGGESTED |
| disable_account | admin | within_24h | SUGGESTED |
| patch_recommendation | bastion-01 | within_24h | SUGGESTED |
""",
    },
    "data_exfiltration": {
        "commander": '{"objective": "Investigate possible data exfiltration from an internal asset", "priority_agents": ["recon", "threat_intel", "forensics"]}',
        "recon": (
            "Recon complete. The source endpoint {hostname} shows outbound HTTPS transfers to {dest_ip} with "
            "unusually large payloads and unusual timing. The destination resembles a staging endpoint used for data "
            "exfiltration."
        ),
        "threat_intel": (
            "The destination IP and transfer pattern are consistent with exfiltration infrastructure. The observed "
            "behavior aligns with data staging and external transfer rather than normal user activity."
        ),
        "forensics": (
            "Timeline reconstructed from endpoint and network logs:\n"
            "1. 11:42:10 — Archive file created in temp directory\n"
            "2. 11:43:01 — Compression utility launched\n"
            "3. 11:44:12 — Large HTTPS upload begins to 192.0.2.44\n"
            "4. 11:46:30 — Secondary upload follows from same host\n"
            "5. 11:49:05 — Temp archive removed after transfer\n"
            "The sequence is consistent with active data exfiltration."
        ),
        "remediation": (
            '[{"action_type": "isolate_host", "target": "workstation-14", "reason": "Possible active exfiltration", "urgency": "immediate"}, '
            '{"action_type": "block_ip", "target": "192.0.2.44", "reason": "Suspected exfiltration endpoint", "urgency": "immediate"}, '
            '{"action_type": "patch_recommendation", "target": "data-transfer-controls", "reason": "Harden outbound transfer detection", "urgency": "within_24h"}]'
        ),
        "reporter": """\
# Incident Report

**Severity:** 🔴 HIGH
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Investigation Status:** Complete

---

## Executive Summary

Potential data exfiltration was detected from workstation-14. The host staged archives locally and sent
large HTTPS transfers to a suspicious external endpoint. Immediate containment and evidence preservation
are recommended.

---

## Alert Details

| Field | Value |
|---|---|
| Type | DATA_EXFILTRATION |
| Severity | HIGH |
| Source IP | 10.0.3.14 |
| Destination | 192.0.2.44:443 |
| Hostname | workstation-14 |

---

## Recon Findings

- Internal host generated abnormal outbound transfer volume
- Destination endpoint resembles exfiltration staging infrastructure

---

## Threat Intelligence

- Transfer pattern is consistent with staged file movement and external upload
- Destination infrastructure should be treated as suspicious until disproven

---

## Attack Timeline

| Time | Event |
|---|---|
| 11:42:10 | Archive file created in temp directory |
| 11:43:01 | Compression utility launched |
| 11:44:12 | Large HTTPS upload begins to 192.0.2.44 |
| 11:46:30 | Secondary upload follows from same host |
| 11:49:05 | Temp archive removed after transfer |

---

## Remediation Actions

| Action | Target | Urgency | Status |
|---|---|---|---|
| isolate_host | workstation-14 | immediate | SUGGESTED |
| block_ip | 192.0.2.44 | immediate | SUGGESTED |
| patch_recommendation | data-transfer-controls | within_24h | SUGGESTED |
""",
    },
    "anomaly": {
        "commander": '{"objective": "Investigate anomalous activity requiring triage and enrichment", "priority_agents": ["recon", "threat_intel", "forensics"]}',
        "recon": (
            "Recon complete. The alert involves {hostname} exhibiting unusual access patterns and mixed behavior across "
            "endpoint and network telemetry. No single malicious signature dominates, but the deviation from baseline "
            "is significant."
        ),
        "threat_intel": (
            "Threat intel does not yet identify a specific campaign, but the behavior is worth triage because it "
            "overlaps with several known suspicious patterns including authentication anomalies and unusual traffic."
        ),
        "forensics": (
            "Timeline reconstructed from available logs:\n"
            "1. 09:05:00 — Baseline deviation detected\n"
            "2. 09:06:15 — Unusual process start observed\n"
            "3. 09:08:40 — Outlier network destination contacted\n"
            "4. 09:12:10 — Manual user activity not confirmed\n"
            "5. 09:18:55 — Alert escalated for analysis\n"
            "The behavior remains anomalous and merits continued investigation."
        ),
        "remediation": (
            '[{"action_type": "patch_recommendation", "target": "anomaly-investigation-playbook", "reason": "Continue triage and tune detections", "urgency": "scheduled"}]'
        ),
        "reporter": """\
# Incident Report

**Severity:** 🟡 LOW
**Alert ID:** {alert_id}
**Timestamp:** {timestamp}
**Investigation Status:** Complete

---

## Executive Summary

An anomalous activity pattern was detected and triaged. The evidence does not yet support a specific
malicious campaign, but the behavior deviates from baseline and should continue to be monitored.

---

## Alert Details

| Field | Value |
|---|---|
| Type | ANOMALY |
| Severity | LOW |

---

## Recon Findings

- Host activity deviates from normal baseline
- No single definitive malicious indicator identified

---

## Threat Intelligence

- No confirmed campaign match yet
- Continue correlation against additional telemetry sources

---

## Attack Timeline

| Time | Event |
|---|---|
| 09:05:00 | Baseline deviation detected |
| 09:06:15 | Unusual process start observed |
| 09:08:40 | Outlier network destination contacted |
| 09:12:10 | Manual user activity not confirmed |
| 09:18:55 | Alert escalated for analysis |
""",
    },
}


def _normalize_alert_type(value) -> str:
    if value is None:
        return _DEFAULT_ALERT_TYPE
    if isinstance(value, AlertType):
        return value.value
    return str(value).strip().lower().replace(" ", "_").replace("-", "_") or _DEFAULT_ALERT_TYPE


def _system_role(system: str) -> str:
    system_lower = system.lower()
    if "you are the commander" in system_lower:
        return "commander"
    if "you are a reconnaissance" in system_lower:
        return "recon"
    if "you are a threat intelligence" in system_lower:
        return "threat_intel"
    if "you are a digital forensics" in system_lower:
        return "forensics"
    if "you are a soc remediation" in system_lower:
        return "remediation"
    if "you are a soc incident reporter" in system_lower:
        return "reporter"
    return "generic"


class MockLLMClient:
    """Hardcoded LLM responses for dry-run / demo mode. No API key required."""

    def __init__(self):
        self.model = "mock"
        self._alert_context: dict[str, str] | None = None
        self._event_log = None
        self._dispatched: set[str] = set()

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    def set_alert_context(self, alert) -> None:
        self._dispatched.clear()
        alert_type = _normalize_alert_type(getattr(alert, "type", None))
        self._alert_context = {
            "alert_type": alert_type,
            "alert_id": getattr(alert, "id", "dry-run"),
            "severity": getattr(getattr(alert, "severity", None), "value", getattr(alert, "severity", "")) or "",
            "source_ip": getattr(alert, "source_ip", None) or "",
            "dest_ip": getattr(alert, "dest_ip", None) or "",
            "hostname": getattr(alert, "hostname", None) or "",
            "user_account": getattr(alert, "user_account", None) or "",
            "dest_port": str(getattr(alert, "dest_port", "") or ""),
            "process": getattr(alert, "process", None) or "",
            "timestamp": getattr(alert, "timestamp", None).isoformat() if getattr(alert, "timestamp", None) else "",
        }

    def _context(self) -> dict[str, str]:
        return self._alert_context or {"alert_type": _DEFAULT_ALERT_TYPE}

    def _report_format_context(self) -> dict[str, str]:
        context = dict(self._context())
        severity = str(context.get("severity") or "low").strip().lower() or "low"
        context["severity_upper"] = severity.upper()
        context["severity_badge"] = {
            "low": "🟡 LOW",
            "medium": "🟠 MEDIUM",
            "high": "🔴 HIGH",
            "critical": "🚨 CRITICAL",
        }.get(severity, severity.upper())
        return context

    def _render(self, template: str) -> str:
        placeholders = (
            "{source_ip}",
            "{dest_ip}",
            "{hostname}",
            "{user_account}",
            "{alert_id}",
            "{dest_port}",
            "{process}",
            "{timestamp}",
            "{severity}",
            "{severity_upper}",
            "{severity_badge}",
        )
        if not any(token in template for token in placeholders):
            return template
        try:
            return template.format_map(_SafeFormatDict(self._report_format_context()))
        except (KeyError, ValueError):
            return template

    def _should_mock_dispatch(self, role: str, alert_type: str, tools: list[dict] | None) -> bool:
        if not tools or role in self._dispatched:
            return False
        if alert_type not in {"intrusion", "malware", "data_exfiltration"}:
            return False
        return role in {"recon", "threat_intel", "forensics", "remediation"}

    def _mock_dispatch_call(self, role: str) -> dict | None:
        mapping = {
            "recon": {
                "agent": "forensics",
                "objective": "Analyse suspicious forensic artifact discovered during recon",
                "context": {
                    "artifact_type": "file_hash",
                    "file_hash": "abc123",
                    "source": "recon",
                },
            },
            "threat_intel": {
                "agent": "forensics",
                "objective": "Corroborate campaign indicators against host evidence",
                "context": {
                    "campaign": "opportunistic exploit activity",
                    "source": "threat_intel",
                },
            },
            "forensics": {
                "agent": "threat_intel",
                "objective": "Attribute newly surfaced IOC from timeline reconstruction",
                "context": {
                    "indicator": self._context().get("source_ip") or "185.220.101.45",
                    "source": "forensics",
                },
            },
            "remediation": {
                "agent": "recon",
                "objective": "Confirm live host state before containment action",
                "context": {
                    "hostname": self._context().get("hostname"),
                    "source": "remediation",
                },
            },
        }
        payload = mapping.get(role)
        if payload is None:
            return None
        return {"id": f"mock-{role}-dispatch", "name": "dispatch_agent", "input": payload}

    async def call(self, system: str, messages: list[dict], tools: list[dict] = None, max_tokens: int = 4096) -> LLMResponse:
        role = _system_role(system)
        alert_type = _normalize_alert_type(self._context().get("alert_type"))
        bucket = _RESPONSES.get(alert_type, _RESPONSES[_DEFAULT_ALERT_TYPE])

        if role == "reporter":
            ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            alert_id = self._context().get("alert_id", "dry-run")[:8]
            if self._alert_context is None:
                try:
                    content = messages[-1]["content"]
                    data = json.loads(content.split("Investigation data:\n", 1)[-1])
                    alert_id = str(data.get("alert_id", alert_id))[:8]
                    alert_type = _normalize_alert_type(data.get("alert_type", alert_type))
                except Exception:
                    pass
            report = bucket["reporter"].format_map(
                _SafeFormatDict(
                    {
                        **self._report_format_context(),
                        "alert_id": alert_id,
                        "timestamp": ts,
                    }
                )
            )
            if self._event_log is not None:
                self._event_log.append(
                    "llm_call",
                    agent="llm",
                    data={"system_snippet": system[:120], "response_snippet": report[:120]},
                )
            return LLMResponse(text=report, tool_calls=[])

        if role == "generic":
            return LLMResponse(text="No findings.", tool_calls=[])

        if self._should_mock_dispatch(role, alert_type, tools):
            tool_call = self._mock_dispatch_call(role)
            if tool_call is not None:
                self._dispatched.add(role)
                return LLMResponse(text="", tool_calls=[tool_call])

        response = bucket.get(role)
        if response is None:
            response = _RESPONSES[_DEFAULT_ALERT_TYPE].get(role, "No findings.")
        rendered = self._render(response)
        if self._event_log is not None:
            self._event_log.append(
                "llm_call",
                agent="llm",
                data={"system_snippet": system[:120], "response_snippet": rendered[:120]},
            )
        return LLMResponse(text=rendered, tool_calls=[])


class _SafeFormatDict(dict):
    def __missing__(self, key):
        return ""
