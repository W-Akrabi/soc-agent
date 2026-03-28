# SOC Automation Multi-Agent System — Design Spec

**Date:** 2026-03-26
**Status:** Approved
**Domain:** Cybersecurity — Security Operations Center (SOC) Automation

---

## Overview

A terminal-based multi-agent system that automatically investigates security alerts the moment they arrive. When an alert comes in, a team of specialized AI agents spins up, works in parallel, shares findings through a shared Case Graph, and either resolves the incident or produces a detailed report — all before the on-call engineer picks up the phone.

The architecture is modeled on PentAGI: an orchestrator agent delegates to domain specialists, all agents communicate through a shared knowledge store, and every finding is traceable and queryable.

---

## Goals

- Reduce mean time to investigate (MTTI) by automating the first-response workflow
- Give on-call engineers a complete picture of an incident before they engage
- Keep it terminal-only — no web server, no frontend
- Start with simulated alerts; design for real SIEM/log sources to be plugged in later
- Default to safe mode — suggest remediation actions, don't auto-execute unless explicitly enabled

---

## Non-Goals

- No web UI or REST API
- No real exploit execution or offensive tooling
- No integration with real SIEM tools in v1 (adapter pattern prepares for this)
- No user authentication or multi-tenancy
- No multi-alert correlation in v1 — one alert = one investigation (noted for v2)

---

## Architecture

```
Alert Source (simulated JSON / future: SIEM adapter)
        │
        ▼
┌─────────────────────┐
│   Ingestion Layer   │  Normalizes alerts into a standard schema
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Commander Agent   │  Classifies alert, creates tasks, monitors progress
└──┬──────────────────┘
   │  Phase 1: launch Recon (blocking)
   ▼
Recon Agent  ──writes findings──▶ Case Graph
   │
   │  Phase 2: launch Intel + Forensics concurrently (after Recon complete)
   ├──▶ Threat Intel Agent ──writes findings──▶ Case Graph
   └──▶ Forensics Agent    ──writes findings──▶ Case Graph
              │
              │  Phase 3: launch Remediation (after Intel + Forensics complete)
              ▼
         Remediation Agent ──writes actions──▶ Case Graph
              │
              │  Phase 4: signal Reporter
              ▼
         Reporter Agent ──reads full graph──▶ Terminal output + report file
```

---

## Agent Execution Phases (Sequencing)

Agent execution is divided into 4 explicit phases managed by the Commander:

| Phase | Agents | Trigger | Concurrency |
|---|---|---|---|
| 1 | Recon | Alert ingested | Sequential (blocks Phase 2) |
| 2 | Threat Intel, Forensics | Recon Task status = `complete` OR `failed` | Concurrent (`asyncio.gather`) |
| 3 | Remediation | Both Intel AND Forensics Task status = `complete` OR `failed` | Sequential |
| 4 | Reporter | Remediation Task status = `complete` OR `failed` | Sequential |

**Sequencing rules:**
- Phase 2 always starts once Recon finishes, regardless of success/failure — Intel and Forensics read whatever Recon found (even partial)
- Phase 3 starts once BOTH Phase 2 agents finish (success or failure) — Remediation never blocks waiting for a single agent
- Commander polls Task statuses every 2 seconds via `CaseGraph.get_task_status(task_id)`
- Overall investigation timeout (default: 5 min) fires a `TimeoutError` that cancels all in-flight agents, retains all Case Graph writes made up to that point, and immediately triggers Phase 4 (Reporter)
- Per-agent timeout (default: 2 min): LLM calls cancelled, partial Case Graph writes retained, Task marked `failed`

---

## Alert Schema

Alerts are normalized to this dataclass before anything else runs:

```python
@dataclass
class Alert:
    id: str                    # UUID, generated on ingestion
    type: AlertType            # Enum: INTRUSION | MALWARE | BRUTE_FORCE | DATA_EXFILTRATION | ANOMALY
    severity: Severity         # Enum: LOW | MEDIUM | HIGH | CRITICAL
    timestamp: datetime        # UTC
    source_ip: str | None      # May be absent (e.g. insider threat)
    dest_ip: str | None
    source_port: int | None
    dest_port: int | None
    user_account: str | None   # Involved user if known
    hostname: str | None       # Affected host
    process: str | None        # Triggering process if known
    raw_payload: dict          # Full original alert as-received
    tags: list[str]            # Free-form labels from source system
```

All fields except `id`, `type`, `severity`, `timestamp`, and `raw_payload` are nullable. Agents must handle absent fields gracefully.

---

## Case Graph

### Database Schema (SQLite DDL)

```sql
CREATE TABLE nodes (
    id          TEXT PRIMARY KEY,       -- UUID
    type        TEXT NOT NULL,          -- See node types below
    label       TEXT NOT NULL,          -- Human-readable name
    data        TEXT NOT NULL,          -- JSON blob of node-specific fields
    status      TEXT NOT NULL DEFAULT 'active',  -- active | failed | suggested | executed
    created_by  TEXT NOT NULL,          -- Agent name (e.g. 'recon', 'commander')
    created_at  TEXT NOT NULL           -- ISO 8601 UTC timestamp
);

CREATE TABLE edges (
    id          TEXT PRIMARY KEY,       -- UUID
    src_id      TEXT NOT NULL REFERENCES nodes(id),
    dst_id      TEXT NOT NULL REFERENCES nodes(id),
    relation    TEXT NOT NULL,          -- e.g. 'linked_to', 'triggered', 'accessed'
    data        TEXT,                   -- Optional JSON metadata
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_nodes_type ON nodes(type);
CREATE INDEX idx_nodes_status ON nodes(status);
CREATE INDEX idx_edges_src ON edges(src_id);
CREATE INDEX idx_edges_dst ON edges(dst_id);
```

### Node Types

| Type | Description | Status Values |
|---|---|---|
| `alert` | Root node; the incoming alert | `active` |
| `task` | Work unit assigned to a specialist agent | `pending → in_progress → complete → failed` |
| `ip` | An IP address entity | `active` |
| `domain` | A domain name entity | `active` |
| `user_account` | A user identity | `active` |
| `file_hash` | A file hash (MD5/SHA) | `active` |
| `cve` | A known CVE | `active` |
| `log_entry` | A parsed log line | `active` |
| `timeline_event` | A reconstructed attack chain event | `active` |
| `finding` | A structured agent finding | `active` |
| `action` | A remediation action | `suggested → executed → rolled_back` |

### CaseGraph API

```python
class CaseGraph:
    def write_node(self, type: str, label: str, data: dict, created_by: str) -> str:
        """Write a node. Returns the new node's UUID."""

    def write_edge(self, src_id: str, dst_id: str, relation: str,
                   created_by: str, data: dict = None) -> str:
        """Write a directed edge between two existing nodes. Returns edge UUID."""

    def update_node_status(self, node_id: str, status: str) -> None:
        """Update the status field of a node (e.g. task lifecycle)."""

    def get_node(self, node_id: str) -> dict | None:
        """Retrieve a single node by ID."""

    def get_nodes_by_type(self, type: str) -> list[dict]:
        """Return all nodes of a given type."""

    def get_neighbors(self, node_id: str, relation: str = None) -> list[dict]:
        """Return all nodes connected to node_id, optionally filtered by relation."""

    def get_task_status(self, task_id: str) -> str:
        """Shortcut: return status of a task node."""

    def get_full_graph(self) -> dict:
        """Return {'nodes': [...], 'edges': [...]} — used by Reporter."""

    def search_nodes(self, type: str = None, label_contains: str = None,
                     data_contains: dict = None) -> list[dict]:
        """Search nodes by type and/or partial label/data match."""
```

All writes are wrapped in SQLite transactions. A failed write raises a `CaseGraphError` and does not partially commit. Agents catch `CaseGraphError`, log the failure, and continue — a write failure does not fail the task.

Concurrent writes are safe: SQLite WAL mode is enabled on initialization.

---

## Components

### Ingestion Layer

- Reads a JSON file or generates a synthetic alert
- Validates and normalizes to the `Alert` dataclass
- Writes the alert as a root `alert` node in the Case Graph
- Adapter interface for future sources:

```python
class BaseAdapter:
    def next_alert(self) -> Alert: ...   # blocking or async generator
```

### AgentBase

All agents subclass `AgentBase`:

```python
class AgentBase:
    def __init__(self, case_graph: CaseGraph, llm: LLMClient, console: Console): ...
    async def run(self, task_node_id: str, alert: Alert) -> None: ...
    # run() must: mark task in_progress, do work, mark task complete/failed
```

### LLMClient

Thin wrapper around the Anthropic SDK:

```python
class LLMClient:
    async def call(self, system: str, messages: list[dict],
                   tools: list[dict] = None) -> str: ...
    # Retries once on failure. Raises LLMError on second failure.
    # Default model: claude-sonnet-4-6
    # Max tokens: 4096 per call
```

---

## Agent Prompts (Templates)

Each agent receives a system prompt tailored to its role. The Case Graph snapshot is injected into the user message.

### Commander System Prompt
```
You are the Commander of a Security Operations Center investigation.
You receive a normalized security alert and must:
1. Classify the incident type and severity
2. Identify which specialist agents are needed
3. Return a JSON list of tasks with: agent_name, objective, priority

Respond only with valid JSON. Example:
{"tasks": [{"agent": "recon", "objective": "Investigate source IP 1.2.3.4 and destination host web-01"}, ...]}
```

### Recon Agent System Prompt
```
You are a Reconnaissance Specialist in a SOC investigation.
You have access to IP lookup, WHOIS, and asset query tools.
Given an alert and your task objective, gather all available information about
the involved IPs, domains, hostnames, and user accounts.
Write each discovered entity to the Case Graph with relationships.
Think step by step. Use tools in order: IP lookup → WHOIS → asset query.
```

### Threat Intel Agent System Prompt
```
You are a Threat Intelligence Analyst.
Given the current Case Graph (especially IPs, domains, and port data from Recon),
look up CVEs, threat feed matches, and known malware signatures.
Identify what threat actor or campaign this may be associated with.
Write CVE nodes and finding nodes to the Case Graph.
```

### Forensics Agent System Prompt
```
You are a Digital Forensics Investigator.
Given the alert payload and log entries, reconstruct the attack timeline.
Identify: initial access vector, lateral movement, persistence mechanisms, data touched.
Write timeline_event nodes in chronological order with relationships between events.
```

### Remediation Agent System Prompt
```
You are a SOC Remediation Specialist.
Given the full Case Graph (findings, CVEs, timeline), propose containment actions.
For each action, specify: type (block_ip | disable_account | isolate_host | patch_recommendation),
target, reason, and urgency (immediate | within_24h | scheduled).
Write each as an action node with status 'suggested'.
In auto-remediate mode, execute immediate-urgency actions and update their status to 'executed'.
```

### Reporter Agent System Prompt
```
You are a SOC Incident Reporter.
Given the complete Case Graph of an investigation, write a structured incident report.
Include: executive summary, alert details, recon findings, threat intelligence, attack timeline,
remediation actions taken or suggested, open questions, and recommended next steps.
Note any gaps where an agent failed or data was unavailable.
Format the report in clear markdown with severity badge, timestamps, and bullet points where appropriate.
```

---

## Error Handling

| Scenario | Behavior |
|---|---|
| LLM call fails | Retry once after 2s. On second failure, mark Task `failed`, log error to console |
| Agent exceeds per-agent timeout (2 min) | Cancel all pending LLM calls, retain Case Graph writes made so far, mark Task `failed` |
| Overall investigation timeout (5 min) | Cancel all in-flight agents, retain all graph data, immediately run Reporter |
| CaseGraph write fails | Log error, continue agent execution, do not fail the task |
| CaseGraph read fails | Raise `CaseGraphError`, propagate to agent, mark task `failed` |
| Missing alert fields (nullable) | Each agent checks for None and skips tools that require absent fields |
| Recon fails entirely | Phases 2, 3, 4 still run — Intel and Forensics work with the raw alert only |

---

## Environment Configuration

`.env.example`:
```
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Optional — defaults shown
SOC_MODEL=claude-sonnet-4-6
SOC_DB_PATH=./soc_cases.db
SOC_REPORTS_DIR=./reports
SOC_COMMANDER_TIMEOUT=300      # seconds, overall investigation
SOC_AGENT_TIMEOUT=120          # seconds, per specialist agent
SOC_AUTO_REMEDIATE=false       # true to enable auto-execution of actions
SOC_LOG_LEVEL=INFO             # DEBUG | INFO | WARNING
```

Database is auto-initialized (CREATE TABLE IF NOT EXISTS) on first run.

---

## CLI Interface

```bash
# Run with a simulated alert
python main.py --alert simulated

# Run with a specific alert file
python main.py --alert alerts/sample_intrusion.json

# Enable auto-remediation
python main.py --alert alerts/sample_intrusion.json --auto-remediate

# Override timeout
python main.py --alert alerts/sample_intrusion.json --timeout 300

# Debug mode (verbose LLM inputs/outputs)
python main.py --alert alerts/sample_intrusion.json --debug
```

---

## Terminal Output Design

```
╔══════════════════════════════════════════════════════╗
║  SOC AGENT  │  Alert: INTRUSION_DETECTED  │  HIGH    ║
╚══════════════════════════════════════════════════════╝

[Commander]   Alert received. Spinning up: Recon → then Intel + Forensics
[Recon]       Querying 192.168.1.105... found 3 open ports, geo: RU
[Recon]       Linked to domain: malicious-c2.net  ✓ complete
[Intel]       CVE-2024-1337 matches service on port 8080
[Forensics]   Timeline: Login 03:12 → Escalation 03:14 → Exfil 03:19
[Intel]       ✓ complete   [Forensics]   ✓ complete
[Remediation] SUGGEST: Block 192.168.1.105 (immediate), disable jsmith (within_24h)

══════════════ INCIDENT REPORT ══════════════
Severity:     HIGH
Root Cause:   Exploitation of CVE-2024-1337 on internal web service
...
Report saved: reports/2026-03-26-03-20-alert-abc123.md
```

---

## Simulated Tools (v1 stubs)

All tools implement the same interface:
```python
async def run(self, input: dict) -> dict:
    """Input and output are typed dicts documented per tool."""
```

| Tool | v1 Implementation | Real v2 Implementation |
|---|---|---|
| `ip_lookup` | Returns hardcoded geo/ASN for known test IPs; random for others | ip-api.com |
| `whois_lookup` | Returns fixture WHOIS data | python-whois |
| `port_scan` | Returns predefined open ports for test IPs | nmap subprocess |
| `cve_search` | Returns fixture CVEs matching port/service patterns | NVD API |
| `threat_feed_lookup` | Returns fixture IOC matches | AbuseIPDB, VirusTotal |
| `log_parser` | Parses structured JSON log fixtures | syslog / CEF parser |
| `action_executor` | Prints action to console; no real execution | iptables, AD API, etc. |

---

## Testing Strategy

- **Unit tests:** `CaseGraph` read/write/query operations with an in-memory SQLite DB
- **Unit tests:** Alert ingestion + normalization with valid and malformed JSON inputs
- **Agent tests:** Each agent tested with a mocked `LLMClient` that returns fixture responses; verify correct node types written to Case Graph
- **Integration tests:** Full investigation run on `sample_intrusion.json` with real LLM calls (requires `ANTHROPIC_API_KEY`); assert report file is created and contains expected sections
- **Timeout tests:** Verify per-agent and overall timeout behavior using `asyncio` test utilities

---

## Project Structure

```
soc-agent/
├── main.py                      # CLI entry point
├── .env.example
├── agents/
│   ├── base.py                  # AgentBase class
│   ├── commander.py
│   ├── recon.py
│   ├── threat_intel.py
│   ├── forensics.py
│   ├── remediation.py
│   └── reporter.py
├── core/
│   ├── case_graph.py            # SQLite CaseGraph client
│   ├── llm_client.py            # Anthropic SDK wrapper
│   └── models.py                # Alert, AlertType, Severity dataclasses
├── ingestion/
│   ├── alert_schema.py
│   ├── simulator.py             # Synthetic alert generator
│   └── adapters/
│       └── base_adapter.py
├── tools/
│   ├── ip_lookup.py
│   ├── whois_lookup.py
│   ├── port_scan.py
│   ├── cve_search.py
│   ├── threat_feed.py
│   ├── log_parser.py
│   └── action_executor.py
├── reports/                     # Generated reports (gitignored)
├── alerts/
│   ├── sample_intrusion.json
│   ├── sample_malware.json
│   └── sample_brute_force.json
├── docs/
│   └── superpowers/specs/
│       └── 2026-03-26-soc-automation-design.md
└── tests/
    ├── test_case_graph.py
    ├── test_ingestion.py
    ├── test_agents.py
    └── test_integration.py
```

---

## Success Criteria

- An alert fires, agents run through all phases, and a complete incident report is produced within 5 minutes
- Each agent's findings are independently readable in the Case Graph after the run
- The system runs from a single `python main.py` command
- Simulated alerts cover 3 attack types: intrusion, malware, brute force
- Report is saved as a markdown file and clearly printed to the terminal
- System handles agent failures gracefully — one failed agent does not abort the investigation
