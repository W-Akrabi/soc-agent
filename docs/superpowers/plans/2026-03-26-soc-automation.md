# SOC Automation Multi-Agent System — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a terminal-based multi-agent SOC system where specialized AI agents investigate security alerts autonomously and produce incident reports.

**Architecture:** A Commander agent receives a normalized alert, runs Recon first, then Threat Intel + Forensics in parallel, then Remediation, then a Reporter synthesizes everything. All agents share findings through a SQLite Case Graph.

**Tech Stack:** Python 3.11+, Anthropic SDK (`anthropic`), `rich` for terminal UI, `python-dotenv`, `pytest` + `pytest-asyncio` for tests.

---

## File Map

| File | Responsibility |
|---|---|
| `main.py` | CLI entry point — parse args, load config, kick off investigation |
| `core/models.py` | `Alert`, `AlertType`, `Severity` dataclasses + enums |
| `core/case_graph.py` | SQLite `CaseGraph` client — all read/write/query operations |
| `core/llm_client.py` | Anthropic SDK wrapper with retry logic |
| `core/config.py` | Load `.env` into typed `Config` dataclass |
| `agents/base.py` | `AgentBase` abstract class |
| `agents/commander.py` | Orchestrates phases, creates tasks, monitors progress |
| `agents/recon.py` | IP/domain/asset reconnaissance |
| `agents/threat_intel.py` | CVE and threat feed lookups |
| `agents/forensics.py` | Log parsing + attack timeline reconstruction |
| `agents/remediation.py` | Containment action suggestion / execution |
| `agents/reporter.py` | Synthesizes graph into final incident report |
| `ingestion/models.py` | `Alert` normalization + validation |
| `ingestion/adapters/base.py` | `BaseAdapter` interface |
| `ingestion/simulator.py` | Synthetic alert generator |
| `ingestion/loader.py` | Load alert from file or simulator |
| `tools/base.py` | `BaseTool` interface |
| `tools/ip_lookup.py` | IP geo/ASN lookup (stub) |
| `tools/whois_lookup.py` | WHOIS lookup (stub) |
| `tools/port_scan.py` | Port/service fingerprint (stub) |
| `tools/cve_search.py` | CVE database search (stub) |
| `tools/threat_feed.py` | Threat feed / IOC lookup (stub) |
| `tools/log_parser.py` | Structured log parser (stub) |
| `tools/action_executor.py` | Remediation action executor (stub) |
| `alerts/sample_intrusion.json` | Sample intrusion alert fixture |
| `alerts/sample_malware.json` | Sample malware alert fixture |
| `alerts/sample_brute_force.json` | Sample brute force alert fixture |
| `.env.example` | Environment variable template |
| `requirements.txt` | Python dependencies |
| `tests/test_models.py` | Alert schema tests |
| `tests/test_case_graph.py` | CaseGraph unit tests |
| `tests/test_llm_client.py` | LLMClient retry/error tests |
| `tests/test_ingestion.py` | Ingestion + normalization tests |
| `tests/test_tools.py` | Tool stub tests |
| `tests/test_agents.py` | Agent unit tests with mocked LLM |
| `tests/test_integration.py` | Full investigation run (real LLM) |

---

## Task 1: Project Scaffolding

**Files:**
- Create: `requirements.txt`
- Create: `.env.example`
- Create: `core/__init__.py`, `agents/__init__.py`, `ingestion/__init__.py`, `ingestion/adapters/__init__.py`, `tools/__init__.py`, `tests/__init__.py`, `alerts/` (dir)

- [ ] **Step 1: Create directory structure**

```bash
cd /path/to/soc-agent
mkdir -p core agents ingestion/adapters tools tests alerts reports
touch core/__init__.py agents/__init__.py ingestion/__init__.py
touch ingestion/adapters/__init__.py tools/__init__.py tests/__init__.py
```

- [ ] **Step 2: Create `requirements.txt`**

```
anthropic>=0.40.0
rich>=13.0.0
python-dotenv>=1.0.0
pytest>=8.0.0
pytest-asyncio>=0.23.0
```

- [ ] **Step 3: Create `.env.example`**

```
# Required
ANTHROPIC_API_KEY=sk-ant-...

# Optional — defaults shown
SOC_MODEL=claude-sonnet-4-6
SOC_DB_PATH=./soc_cases.db
SOC_REPORTS_DIR=./reports
SOC_COMMANDER_TIMEOUT=300
SOC_AGENT_TIMEOUT=120
SOC_AUTO_REMEDIATE=false
SOC_LOG_LEVEL=INFO
```

- [ ] **Step 4: Install dependencies**

```bash
pip install -r requirements.txt
```

Expected: All packages install without errors.

- [ ] **Step 5: Commit**

```bash
git init
git add requirements.txt .env.example
git commit -m "chore: project scaffolding and dependencies"
```

---

## Task 2: Core Models

**Files:**
- Create: `core/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_models.py
from datetime import datetime, timezone
from core.models import Alert, AlertType, Severity

def test_alert_type_enum():
    assert AlertType.INTRUSION.value == "intrusion"
    assert AlertType.MALWARE.value == "malware"
    assert AlertType.BRUTE_FORCE.value == "brute_force"
    assert AlertType.DATA_EXFILTRATION.value == "data_exfiltration"
    assert AlertType.ANOMALY.value == "anomaly"

def test_severity_enum():
    assert Severity.LOW.value == "low"
    assert Severity.CRITICAL.value == "critical"

def test_alert_required_fields():
    alert = Alert(
        id="test-id",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={"raw": "data"},
    )
    assert alert.id == "test-id"
    assert alert.source_ip is None
    assert alert.tags == []

def test_alert_optional_fields():
    alert = Alert(
        id="test-id",
        type=AlertType.MALWARE,
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="1.2.3.4",
        user_account="jsmith",
        tags=["lateral-movement"],
    )
    assert alert.source_ip == "1.2.3.4"
    assert alert.user_account == "jsmith"
    assert "lateral-movement" in alert.tags
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_models.py -v
```

Expected: `ImportError: cannot import name 'Alert' from 'core.models'`

- [ ] **Step 3: Implement `core/models.py`**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_models.py -v
```

Expected: All 4 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add core/models.py tests/test_models.py
git commit -m "feat: core Alert, AlertType, Severity models"
```

---

## Task 3: Configuration Loader

**Files:**
- Create: `core/config.py`

- [ ] **Step 1: Implement `core/config.py`**

```python
import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    anthropic_api_key: str
    model: str
    db_path: str
    reports_dir: str
    commander_timeout: int
    agent_timeout: int
    auto_remediate: bool
    log_level: str

    @classmethod
    def from_env(cls) -> "Config":
        key = os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is required. Copy .env.example to .env and fill it in.")
        return cls(
            anthropic_api_key=key,
            model=os.getenv("SOC_MODEL", "claude-sonnet-4-6"),
            db_path=os.getenv("SOC_DB_PATH", "./soc_cases.db"),
            reports_dir=os.getenv("SOC_REPORTS_DIR", "./reports"),
            commander_timeout=int(os.getenv("SOC_COMMANDER_TIMEOUT", "300")),
            agent_timeout=int(os.getenv("SOC_AGENT_TIMEOUT", "120")),
            auto_remediate=os.getenv("SOC_AUTO_REMEDIATE", "false").lower() == "true",
            log_level=os.getenv("SOC_LOG_LEVEL", "INFO"),
        )
```

- [ ] **Step 2: Verify it loads without error (no test needed — no logic to branch)**

```bash
python -c "from core.config import Config; print('Config OK')"
```

Expected: `Config OK`

- [ ] **Step 3: Commit**

```bash
git add core/config.py
git commit -m "feat: config loader from .env"
```

---

## Task 4: Case Graph

**Files:**
- Create: `core/case_graph.py`
- Create: `tests/test_case_graph.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_case_graph.py
import pytest
from core.case_graph import CaseGraph, CaseGraphError


@pytest.fixture
def graph(tmp_path):
    db = str(tmp_path / "test.db")
    return CaseGraph(db_path=db)


def test_write_and_get_node(graph):
    node_id = graph.write_node(type="ip", label="1.2.3.4", data={"geo": "RU"}, created_by="recon")
    node = graph.get_node(node_id)
    assert node["type"] == "ip"
    assert node["label"] == "1.2.3.4"
    assert node["data"]["geo"] == "RU"
    assert node["status"] == "active"
    assert node["created_by"] == "recon"


def test_write_edge(graph):
    ip_id = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    cve_id = graph.write_node(type="cve", label="CVE-2024-1337", data={}, created_by="intel")
    edge_id = graph.write_edge(src_id=ip_id, dst_id=cve_id, relation="linked_to", created_by="intel")
    assert edge_id is not None
    neighbors = graph.get_neighbors(ip_id)
    assert any(n["id"] == cve_id for n in neighbors)


def test_update_node_status(graph):
    node_id = graph.write_node(type="task", label="recon-task", data={}, created_by="commander")
    graph.update_node_status(node_id, "in_progress")
    node = graph.get_node(node_id)
    assert node["status"] == "in_progress"


def test_get_nodes_by_type(graph):
    graph.write_node(type="ip", label="1.1.1.1", data={}, created_by="recon")
    graph.write_node(type="ip", label="2.2.2.2", data={}, created_by="recon")
    graph.write_node(type="cve", label="CVE-X", data={}, created_by="intel")
    ips = graph.get_nodes_by_type("ip")
    assert len(ips) == 2
    assert all(n["type"] == "ip" for n in ips)


def test_get_task_status(graph):
    node_id = graph.write_node(type="task", label="task-1", data={}, created_by="commander")
    assert graph.get_task_status(node_id) == "active"
    graph.update_node_status(node_id, "complete")
    assert graph.get_task_status(node_id) == "complete"


def test_get_full_graph(graph):
    n1 = graph.write_node(type="alert", label="alert-1", data={}, created_by="ingestion")
    n2 = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    graph.write_edge(src_id=n1, dst_id=n2, relation="involves", created_by="recon")
    full = graph.get_full_graph()
    assert len(full["nodes"]) == 2
    assert len(full["edges"]) == 1


def test_search_nodes(graph):
    graph.write_node(type="ip", label="192.168.1.1", data={"geo": "US"}, created_by="recon")
    graph.write_node(type="ip", label="10.0.0.1", data={"geo": "RU"}, created_by="recon")
    results = graph.search_nodes(type="ip", label_contains="192")
    assert len(results) == 1
    assert results[0]["label"] == "192.168.1.1"


def test_missing_node_returns_none(graph):
    assert graph.get_node("nonexistent-id") is None


def test_get_neighbors_with_relation_filter(graph):
    ip_id = graph.write_node(type="ip", label="1.2.3.4", data={}, created_by="recon")
    cve_id = graph.write_node(type="cve", label="CVE-X", data={}, created_by="intel")
    domain_id = graph.write_node(type="domain", label="evil.com", data={}, created_by="recon")
    graph.write_edge(ip_id, cve_id, "linked_to", "intel")
    graph.write_edge(ip_id, domain_id, "resolves_to", "recon")
    linked = graph.get_neighbors(ip_id, relation="linked_to")
    assert len(linked) == 1
    assert linked[0]["id"] == cve_id
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_case_graph.py -v
```

Expected: `ImportError: cannot import name 'CaseGraph'`

- [ ] **Step 3: Implement `core/case_graph.py`**

```python
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from contextlib import contextmanager


class CaseGraphError(Exception):
    pass


class CaseGraph:
    def __init__(self, db_path: str = "./soc_cases.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id         TEXT PRIMARY KEY,
                    type       TEXT NOT NULL,
                    label      TEXT NOT NULL,
                    data       TEXT NOT NULL,
                    status     TEXT NOT NULL DEFAULT 'active',
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id         TEXT PRIMARY KEY,
                    src_id     TEXT NOT NULL REFERENCES nodes(id),
                    dst_id     TEXT NOT NULL REFERENCES nodes(id),
                    relation   TEXT NOT NULL,
                    data       TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_type   ON nodes(type);
                CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
                CREATE INDEX IF NOT EXISTS idx_edges_src    ON edges(src_id);
                CREATE INDEX IF NOT EXISTS idx_edges_dst    ON edges(dst_id);
            """)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _row_to_dict(self, row) -> dict:
        d = dict(row)
        d["data"] = json.loads(d["data"])
        return d

    def write_node(self, type: str, label: str, data: dict, created_by: str) -> str:
        node_id = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO nodes (id, type, label, data, status, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, 'active', ?, ?)",
                    (node_id, type, label, json.dumps(data), created_by, self._now()),
                )
        except sqlite3.Error as e:
            raise CaseGraphError(f"write_node failed: {e}") from e
        return node_id

    def write_edge(self, src_id: str, dst_id: str, relation: str,
                   created_by: str, data: dict = None) -> str:
        edge_id = str(uuid.uuid4())
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO edges (id, src_id, dst_id, relation, data, created_by, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (edge_id, src_id, dst_id, relation,
                     json.dumps(data) if data else None, created_by, self._now()),
                )
        except sqlite3.Error as e:
            raise CaseGraphError(f"write_edge failed: {e}") from e
        return edge_id

    def update_node_status(self, node_id: str, status: str) -> None:
        try:
            with self._connect() as conn:
                conn.execute("UPDATE nodes SET status=? WHERE id=?", (status, node_id))
        except sqlite3.Error as e:
            raise CaseGraphError(f"update_node_status failed: {e}") from e

    def get_node(self, node_id: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def get_nodes_by_type(self, type: str) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM nodes WHERE type=?", (type,)).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_neighbors(self, node_id: str, relation: str = None) -> list[dict]:
        with self._connect() as conn:
            if relation:
                rows = conn.execute(
                    "SELECT n.* FROM nodes n "
                    "JOIN edges e ON e.dst_id = n.id "
                    "WHERE e.src_id=? AND e.relation=?",
                    (node_id, relation),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT n.* FROM nodes n "
                    "JOIN edges e ON e.dst_id = n.id "
                    "WHERE e.src_id=?",
                    (node_id,),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_task_status(self, task_id: str) -> str:
        node = self.get_node(task_id)
        if not node:
            raise CaseGraphError(f"Task node {task_id} not found")
        return node["status"]

    def get_full_graph(self) -> dict:
        with self._connect() as conn:
            nodes = [self._row_to_dict(r) for r in conn.execute("SELECT * FROM nodes").fetchall()]
            rows = conn.execute("SELECT * FROM edges").fetchall()
            edges = [dict(r) for r in rows]
        return {"nodes": nodes, "edges": edges}

    def search_nodes(self, type: str = None, label_contains: str = None,
                     data_contains: dict = None) -> list[dict]:
        query = "SELECT * FROM nodes WHERE 1=1"
        params: list = []
        if type:
            query += " AND type=?"
            params.append(type)
        if label_contains:
            query += " AND label LIKE ?"
            params.append(f"%{label_contains}%")
        if data_contains:
            for k, v in data_contains.items():
                query += " AND json_extract(data, ?) = ?"
                params.extend([f"$.{k}", v])
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_case_graph.py -v
```

Expected: All 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add core/case_graph.py tests/test_case_graph.py
git commit -m "feat: CaseGraph SQLite client with full read/write/query API"
```

---

## Task 5: LLM Client

**Files:**
- Create: `core/llm_client.py`
- Create: `tests/test_llm_client.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_llm_client.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.llm_client import LLMClient, LLMError


@pytest.fixture
def client():
    return LLMClient(api_key="test-key", model="claude-sonnet-4-6")


@pytest.mark.asyncio
async def test_call_returns_text(client):
    mock_response = MagicMock()
    mock_response.content = [MagicMock(type="text", text="Hello world")]
    with patch.object(client._client.messages, "create", new=AsyncMock(return_value=mock_response)):
        result = await client.call(system="Be helpful", messages=[{"role": "user", "content": "Hi"}])
    assert result == "Hello world"


@pytest.mark.asyncio
async def test_call_retries_once_on_failure(client):
    mock_response = MagicMock()
    mock_response.content = [MagicMock(type="text", text="Retry worked")]
    call_mock = AsyncMock(side_effect=[Exception("API error"), mock_response])
    with patch.object(client._client.messages, "create", new=call_mock):
        result = await client.call(system="test", messages=[{"role": "user", "content": "test"}])
    assert result == "Retry worked"
    assert call_mock.call_count == 2


@pytest.mark.asyncio
async def test_call_raises_llm_error_after_two_failures(client):
    call_mock = AsyncMock(side_effect=Exception("always fails"))
    with patch.object(client._client.messages, "create", new=call_mock):
        with pytest.raises(LLMError, match="LLM call failed after retry"):
            await client.call(system="test", messages=[{"role": "user", "content": "test"}])
    assert call_mock.call_count == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_llm_client.py -v
```

Expected: `ImportError: cannot import name 'LLMClient'`

- [ ] **Step 3: Implement `core/llm_client.py`**

```python
import asyncio
import anthropic


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.model = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] = None,
        max_tokens: int = 4096,
    ) -> str:
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = await self._client.messages.create(**kwargs)
                # Extract text from response
                for block in response.content:
                    if hasattr(block, "text"):
                        return block.text
                return ""
            except Exception as e:
                last_error = e
                if attempt == 0:
                    await asyncio.sleep(2)

        raise LLMError(f"LLM call failed after retry: {last_error}") from last_error
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_llm_client.py -v
```

Expected: All 3 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add core/llm_client.py tests/test_llm_client.py
git commit -m "feat: LLMClient Anthropic wrapper with retry logic"
```

---

## Task 6: Alert Ingestion Layer

**Files:**
- Create: `ingestion/models.py`
- Create: `ingestion/adapters/base.py`
- Create: `ingestion/simulator.py`
- Create: `ingestion/loader.py`
- Create: `alerts/sample_intrusion.json`
- Create: `alerts/sample_malware.json`
- Create: `alerts/sample_brute_force.json`
- Create: `tests/test_ingestion.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_ingestion.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_ingestion.py -v
```

Expected: `ImportError: cannot import name 'load_alert'`

- [ ] **Step 3: Create sample alert JSON files**

`alerts/sample_intrusion.json`:
```json
{
  "type": "intrusion",
  "severity": "high",
  "source_ip": "185.220.101.45",
  "dest_ip": "10.0.1.50",
  "source_port": 49200,
  "dest_port": 8080,
  "hostname": "web-prod-01",
  "process": "nginx",
  "user_account": "www-data",
  "tags": ["external-ip", "web-server"],
  "raw_payload": {
    "rule_name": "EXPLOIT_ATTEMPT_CVE_2024_1337",
    "signature": "HTTP exploit payload detected",
    "bytes_in": 4096,
    "bytes_out": 512,
    "log_source": "suricata",
    "logs": [
      {"ts": "2026-03-26T03:12:01Z", "event": "connection_established", "src": "185.220.101.45", "dst": "10.0.1.50:8080"},
      {"ts": "2026-03-26T03:12:03Z", "event": "exploit_payload_sent", "payload_size": 4096},
      {"ts": "2026-03-26T03:12:05Z", "event": "shell_spawned", "process": "sh", "parent": "nginx"},
      {"ts": "2026-03-26T03:14:10Z", "event": "privilege_escalation", "user": "root"},
      {"ts": "2026-03-26T03:19:22Z", "event": "data_staged", "path": "/tmp/.exfil", "bytes": 52428}
    ]
  }
}
```

`alerts/sample_malware.json`:
```json
{
  "type": "malware",
  "severity": "critical",
  "source_ip": "10.0.2.88",
  "dest_ip": "91.108.4.200",
  "source_port": 51000,
  "dest_port": 443,
  "hostname": "workstation-14",
  "process": "svchost.exe",
  "user_account": "jdoe",
  "tags": ["c2-communication", "beacon"],
  "raw_payload": {
    "rule_name": "MALWARE_BEACON_DETECTED",
    "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    "signature": "Cobalt Strike beacon pattern",
    "log_source": "endpoint-edr",
    "logs": [
      {"ts": "2026-03-26T08:00:01Z", "event": "process_created", "process": "svchost.exe", "hash": "d41d8cd98f00b204e9800998ecf8427e"},
      {"ts": "2026-03-26T08:00:03Z", "event": "network_connection", "dst": "91.108.4.200:443"},
      {"ts": "2026-03-26T08:05:00Z", "event": "beacon_interval", "interval_sec": 300},
      {"ts": "2026-03-26T08:10:00Z", "event": "beacon_interval", "interval_sec": 300}
    ]
  }
}
```

`alerts/sample_brute_force.json`:
```json
{
  "type": "brute_force",
  "severity": "medium",
  "source_ip": "203.0.113.99",
  "dest_ip": "10.0.0.10",
  "source_port": 0,
  "dest_port": 22,
  "hostname": "bastion-01",
  "user_account": "admin",
  "tags": ["ssh", "authentication-failure"],
  "raw_payload": {
    "rule_name": "SSH_BRUTE_FORCE",
    "attempt_count": 247,
    "window_seconds": 60,
    "log_source": "sshd",
    "logs": [
      {"ts": "2026-03-26T01:00:00Z", "event": "auth_failure", "user": "admin", "src": "203.0.113.99"},
      {"ts": "2026-03-26T01:00:01Z", "event": "auth_failure", "user": "admin", "src": "203.0.113.99"},
      {"ts": "2026-03-26T01:01:00Z", "event": "auth_failure", "user": "root", "src": "203.0.113.99"}
    ]
  }
}
```

- [ ] **Step 4: Implement ingestion modules**

`ingestion/adapters/base.py`:
```python
from abc import ABC, abstractmethod
from core.models import Alert


class BaseAdapter(ABC):
    @abstractmethod
    def next_alert(self) -> Alert:
        """Return the next alert. Blocking."""
        ...
```

`ingestion/models.py`:
```python
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
```

`ingestion/simulator.py`:
```python
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
```

`ingestion/loader.py`:
```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_ingestion.py -v
```

Expected: All 5 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add ingestion/ alerts/ tests/test_ingestion.py
git commit -m "feat: alert ingestion layer with normalization, simulator, and sample fixtures"
```

---

## Task 7: Tool Stubs

**Files:**
- Create: `tools/base.py`
- Create: `tools/ip_lookup.py`
- Create: `tools/whois_lookup.py`
- Create: `tools/port_scan.py`
- Create: `tools/cve_search.py`
- Create: `tools/threat_feed.py`
- Create: `tools/log_parser.py`
- Create: `tools/action_executor.py`
- Create: `tests/test_tools.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_tools.py
import pytest
from tools.ip_lookup import IPLookupTool
from tools.whois_lookup import WHOISTool
from tools.port_scan import PortScanTool
from tools.cve_search import CVESearchTool
from tools.threat_feed import ThreatFeedTool
from tools.log_parser import LogParserTool
from tools.action_executor import ActionExecutorTool


@pytest.mark.asyncio
async def test_ip_lookup_known_ip():
    tool = IPLookupTool()
    result = await tool.run({"ip": "185.220.101.45"})
    assert "geo" in result
    assert "asn" in result


@pytest.mark.asyncio
async def test_ip_lookup_unknown_ip():
    tool = IPLookupTool()
    result = await tool.run({"ip": "1.2.3.4"})
    assert "geo" in result  # returns something even for unknown


@pytest.mark.asyncio
async def test_whois_lookup():
    tool = WHOISTool()
    result = await tool.run({"domain": "malicious-c2.net"})
    assert "registrar" in result


@pytest.mark.asyncio
async def test_port_scan():
    tool = PortScanTool()
    result = await tool.run({"ip": "185.220.101.45"})
    assert "open_ports" in result
    assert isinstance(result["open_ports"], list)


@pytest.mark.asyncio
async def test_cve_search_by_port():
    tool = CVESearchTool()
    result = await tool.run({"port": 8080, "service": "http"})
    assert "cves" in result
    assert isinstance(result["cves"], list)


@pytest.mark.asyncio
async def test_threat_feed_lookup():
    tool = ThreatFeedTool()
    result = await tool.run({"ip": "185.220.101.45"})
    assert "malicious" in result
    assert "categories" in result


@pytest.mark.asyncio
async def test_log_parser():
    tool = LogParserTool()
    logs = [
        {"ts": "2026-03-26T03:12:01Z", "event": "connection_established", "src": "1.2.3.4"},
        {"ts": "2026-03-26T03:14:10Z", "event": "privilege_escalation", "user": "root"},
    ]
    result = await tool.run({"logs": logs})
    assert "events" in result
    assert len(result["events"]) == 2


@pytest.mark.asyncio
async def test_action_executor_suggest_mode():
    tool = ActionExecutorTool(auto_remediate=False)
    result = await tool.run({
        "action_type": "block_ip",
        "target": "1.2.3.4",
        "reason": "known malicious IP",
        "urgency": "immediate"
    })
    assert result["status"] == "suggested"
    assert result["executed"] is False


@pytest.mark.asyncio
async def test_action_executor_auto_remediate_immediate():
    tool = ActionExecutorTool(auto_remediate=True)
    result = await tool.run({
        "action_type": "block_ip",
        "target": "1.2.3.4",
        "reason": "known malicious IP",
        "urgency": "immediate"
    })
    assert result["status"] == "executed"
    assert result["executed"] is True


@pytest.mark.asyncio
async def test_action_executor_auto_remediate_non_immediate():
    tool = ActionExecutorTool(auto_remediate=True)
    result = await tool.run({
        "action_type": "patch_recommendation",
        "target": "web-prod-01",
        "reason": "CVE patch required",
        "urgency": "within_24h"
    })
    # Non-immediate actions are only suggested even in auto mode
    assert result["status"] == "suggested"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_tools.py -v
```

Expected: `ImportError: cannot import name 'IPLookupTool'`

- [ ] **Step 3: Implement `tools/base.py`**

```python
from abc import ABC, abstractmethod


class BaseTool(ABC):
    name: str = "base_tool"
    description: str = ""

    @abstractmethod
    async def run(self, input: dict) -> dict:
        """Execute the tool. Input/output are typed dicts."""
        ...
```

- [ ] **Step 4: Implement all tool stubs**

`tools/ip_lookup.py`:
```python
from tools.base import BaseTool

_KNOWN_IPS = {
    "185.220.101.45": {"geo": "RU", "city": "Moscow", "asn": "AS60117", "org": "Tor exit node", "risk": "high"},
    "91.108.4.200":   {"geo": "NL", "city": "Amsterdam", "asn": "AS62041", "org": "Telegram", "risk": "medium"},
    "203.0.113.99":   {"geo": "CN", "city": "Beijing", "asn": "AS4134", "org": "CHINANET", "risk": "high"},
    "10.0.1.50":      {"geo": "internal", "city": "", "asn": "internal", "org": "LAN", "risk": "low"},
}

class IPLookupTool(BaseTool):
    name = "ip_lookup"
    description = "Look up geographic and ASN information for an IP address"

    async def run(self, input: dict) -> dict:
        ip = input.get("ip", "")
        return _KNOWN_IPS.get(ip, {"geo": "US", "city": "Unknown", "asn": "AS0", "org": "Unknown", "risk": "unknown"})
```

`tools/whois_lookup.py`:
```python
from tools.base import BaseTool

_FIXTURE = {
    "malicious-c2.net": {"registrar": "NameCheap", "created": "2025-11-01", "country": "RU", "status": "active"},
    "evil-domain.io":   {"registrar": "GoDaddy", "created": "2026-01-15", "country": "CN", "status": "active"},
}

class WHOISTool(BaseTool):
    name = "whois_lookup"
    description = "Look up WHOIS registration data for a domain"

    async def run(self, input: dict) -> dict:
        domain = input.get("domain", "")
        return _FIXTURE.get(domain, {"registrar": "Unknown", "created": "unknown", "country": "unknown", "status": "unknown"})
```

`tools/port_scan.py`:
```python
from tools.base import BaseTool

_KNOWN_PORTS = {
    "185.220.101.45": [{"port": 22, "service": "ssh"}, {"port": 80, "service": "http"}, {"port": 8080, "service": "http-alt"}],
    "10.0.1.50":      [{"port": 80, "service": "http"}, {"port": 8080, "service": "http-alt"}, {"port": 443, "service": "https"}],
}

class PortScanTool(BaseTool):
    name = "port_scan"
    description = "Scan open ports and identify services on a host"

    async def run(self, input: dict) -> dict:
        ip = input.get("ip", "")
        return {"ip": ip, "open_ports": _KNOWN_PORTS.get(ip, [{"port": 443, "service": "https"}])}
```

`tools/cve_search.py`:
```python
from tools.base import BaseTool

_CVE_DB = {
    8080: [{"id": "CVE-2024-1337", "severity": "critical", "description": "RCE via HTTP exploit in web frameworks", "cvss": 9.8}],
    22:   [{"id": "CVE-2023-38408", "severity": "critical", "description": "OpenSSH RCE via ssh-agent forwarding", "cvss": 9.8}],
    443:  [{"id": "CVE-2024-3094",  "severity": "critical", "description": "XZ Utils backdoor in liblzma", "cvss": 10.0}],
}

class CVESearchTool(BaseTool):
    name = "cve_search"
    description = "Search CVE database for vulnerabilities matching a port or service"

    async def run(self, input: dict) -> dict:
        port = input.get("port")
        cves = _CVE_DB.get(port, [])
        return {"port": port, "service": input.get("service", ""), "cves": cves}
```

`tools/threat_feed.py`:
```python
from tools.base import BaseTool

_THREAT_FEED = {
    "185.220.101.45": {"malicious": True, "categories": ["tor-exit-node", "scanner"], "confidence": 95},
    "203.0.113.99":   {"malicious": True, "categories": ["brute-force", "ssh-scanner"], "confidence": 88},
    "91.108.4.200":   {"malicious": False, "categories": [], "confidence": 10},
    "d41d8cd98f00b204e9800998ecf8427e": {"malicious": True, "categories": ["cobalt-strike", "c2-beacon"], "confidence": 99},
}

class ThreatFeedTool(BaseTool):
    name = "threat_feed_lookup"
    description = "Look up IPs or file hashes in threat intelligence feeds"

    async def run(self, input: dict) -> dict:
        ioc = input.get("ip") or input.get("hash", "")
        return _THREAT_FEED.get(ioc, {"malicious": False, "categories": [], "confidence": 0})
```

`tools/log_parser.py`:
```python
from tools.base import BaseTool

class LogParserTool(BaseTool):
    name = "log_parser"
    description = "Parse structured JSON log entries into normalized security events"

    async def run(self, input: dict) -> dict:
        logs = input.get("logs", [])
        events = []
        for log in logs:
            events.append({
                "timestamp": log.get("ts", ""),
                "event_type": log.get("event", "unknown"),
                "details": {k: v for k, v in log.items() if k not in ("ts", "event")},
            })
        return {"events": events, "count": len(events)}
```

`tools/action_executor.py`:
```python
from tools.base import BaseTool

class ActionExecutorTool(BaseTool):
    name = "action_executor"
    description = "Execute or suggest remediation actions"

    def __init__(self, auto_remediate: bool = False):
        self.auto_remediate = auto_remediate

    async def run(self, input: dict) -> dict:
        action_type = input.get("action_type", "")
        target = input.get("target", "")
        urgency = input.get("urgency", "scheduled")

        should_execute = self.auto_remediate and urgency == "immediate"

        if should_execute:
            # In v1: print to console, no real execution
            print(f"[ACTION EXECUTED] {action_type} → {target}")
            return {"status": "executed", "executed": True, "action_type": action_type, "target": target}
        else:
            return {"status": "suggested", "executed": False, "action_type": action_type, "target": target}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_tools.py -v
```

Expected: All 10 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add tools/ tests/test_tools.py
git commit -m "feat: tool stubs — ip_lookup, whois, port_scan, cve_search, threat_feed, log_parser, action_executor"
```

---

## Task 8: Agent Base Class

**Files:**
- Create: `agents/base.py`

- [ ] **Step 1: Implement `agents/base.py`**

```python
import asyncio
from abc import ABC, abstractmethod
from rich.console import Console
from core.case_graph import CaseGraph, CaseGraphError
from core.llm_client import LLMClient
from core.models import Alert


class AgentBase(ABC):
    name: str = "base"

    def __init__(self, case_graph: CaseGraph, llm: LLMClient, console: Console,
                 agent_timeout: int = 120):
        self.graph = case_graph
        self.llm = llm
        self.console = console
        self.agent_timeout = agent_timeout

    def log(self, message: str, style: str = "white") -> None:
        self.console.print(f"[bold cyan]\\[{self.name.upper()}][/bold cyan] {message}", style=style)

    async def run(self, task_node_id: str, alert: Alert) -> None:
        """Run the agent with a timeout. Marks task complete or failed."""
        self.graph.update_node_status(task_node_id, "in_progress")
        try:
            await asyncio.wait_for(self._run(task_node_id, alert), timeout=self.agent_timeout)
            self.graph.update_node_status(task_node_id, "complete")
            self.log(f"✓ complete", style="green")
        except asyncio.TimeoutError:
            self.graph.update_node_status(task_node_id, "failed")
            self.log(f"✗ timed out after {self.agent_timeout}s", style="red")
        except Exception as e:
            self.graph.update_node_status(task_node_id, "failed")
            self.log(f"✗ failed: {e}", style="red")

    @abstractmethod
    async def _run(self, task_node_id: str, alert: Alert) -> None:
        """Subclasses implement their investigation logic here."""
        ...
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from agents.base import AgentBase; print('AgentBase OK')"
```

Expected: `AgentBase OK`

- [ ] **Step 3: Commit**

```bash
git add agents/base.py
git commit -m "feat: AgentBase with timeout handling and task lifecycle"
```

---

## Task 9: Specialist Agents

**Files:**
- Create: `agents/recon.py`
- Create: `agents/threat_intel.py`
- Create: `agents/forensics.py`
- Create: `agents/remediation.py`
- Create: `agents/reporter.py`
- Create: `tests/test_agents.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/test_agents.py
import pytest
from unittest.mock import AsyncMock, MagicMock
from core.case_graph import CaseGraph
from core.models import Alert, AlertType, Severity
from datetime import datetime, timezone
from rich.console import Console
from agents.recon import ReconAgent
from agents.threat_intel import ThreatIntelAgent
from agents.forensics import ForensicsAgent
from agents.remediation import RemediationAgent
from agents.reporter import ReporterAgent


@pytest.fixture
def graph(tmp_path):
    return CaseGraph(str(tmp_path / "test.db"))

@pytest.fixture
def console():
    return Console(quiet=True)

@pytest.fixture
def alert():
    return Alert(
        id="test-alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={"rule_name": "TEST", "logs": [{"ts": "2026-01-01T00:00:00Z", "event": "test"}]},
        source_ip="185.220.101.45",
        dest_ip="10.0.1.50",
        dest_port=8080,
        hostname="web-prod-01",
    )

@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.call = AsyncMock(return_value='{"tasks": []}')
    return llm


@pytest.mark.asyncio
async def test_recon_agent_writes_ip_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="I found geo data for the IP.")
    alert_node_id = graph.write_node("alert", "test-alert-1", {"alert_id": alert.id}, "ingestion")
    task_id = graph.write_node("task", "recon-task", {"agent": "recon", "objective": "Investigate IP"}, "commander")

    agent = ReconAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    ip_nodes = graph.get_nodes_by_type("ip")
    assert len(ip_nodes) >= 1
    assert graph.get_task_status(task_id) == "complete"


@pytest.mark.asyncio
async def test_threat_intel_agent_writes_cve_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="CVE-2024-1337 is critical.")
    graph.write_node("ip", "185.220.101.45", {"open_ports": [{"port": 8080}]}, "recon")
    task_id = graph.write_node("task", "intel-task", {"agent": "threat_intel", "objective": "Look up CVEs"}, "commander")

    agent = ThreatIntelAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    cve_nodes = graph.get_nodes_by_type("cve")
    finding_nodes = graph.get_nodes_by_type("finding")
    assert len(cve_nodes) + len(finding_nodes) >= 1
    assert graph.get_task_status(task_id) == "complete"


@pytest.mark.asyncio
async def test_forensics_agent_writes_timeline_events(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value="Timeline: login then escalation then exfil.")
    task_id = graph.write_node("task", "forensics-task", {"agent": "forensics", "objective": "Build timeline"}, "commander")

    agent = ForensicsAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    timeline_nodes = graph.get_nodes_by_type("timeline_event")
    assert len(timeline_nodes) >= 1
    assert graph.get_task_status(task_id) == "complete"


@pytest.mark.asyncio
async def test_remediation_agent_writes_action_nodes(graph, console, alert, mock_llm):
    mock_llm.call = AsyncMock(return_value='[{"action_type": "block_ip", "target": "185.220.101.45", "reason": "malicious", "urgency": "immediate"}]')
    task_id = graph.write_node("task", "remediation-task", {"agent": "remediation"}, "commander")

    agent = RemediationAgent(graph, mock_llm, console, auto_remediate=False)
    await agent.run(task_id, alert)

    action_nodes = graph.get_nodes_by_type("action")
    assert len(action_nodes) >= 1
    assert action_nodes[0]["status"] == "suggested"
    assert graph.get_task_status(task_id) == "complete"


@pytest.mark.asyncio
async def test_reporter_agent_returns_report_text(graph, console, alert, mock_llm, tmp_path):
    mock_llm.call = AsyncMock(return_value="# Incident Report\n\nSeverity: HIGH\n\nSummary: exploit detected.")
    graph.write_node("alert", "test-alert-1", {"alert_id": alert.id}, "ingestion")
    task_id = graph.write_node("task", "reporter-task", {"agent": "reporter"}, "commander")

    agent = ReporterAgent(graph, mock_llm, console, reports_dir=str(tmp_path))
    await agent.run(task_id, alert)

    # Report file should be saved
    report_files = list(tmp_path.glob("*.md"))
    assert len(report_files) == 1
    content = report_files[0].read_text()
    assert "Incident Report" in content
    assert graph.get_task_status(task_id) == "complete"


@pytest.mark.asyncio
async def test_agent_marks_task_failed_on_llm_error(graph, console, alert, mock_llm):
    from core.llm_client import LLMError
    mock_llm.call = AsyncMock(side_effect=LLMError("LLM unavailable"))
    task_id = graph.write_node("task", "recon-task", {"agent": "recon"}, "commander")

    agent = ReconAgent(graph, mock_llm, console)
    await agent.run(task_id, alert)

    assert graph.get_task_status(task_id) == "failed"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_agents.py -v
```

Expected: `ImportError: cannot import name 'ReconAgent'`

- [ ] **Step 3: Implement `agents/recon.py`**

```python
import json
from agents.base import AgentBase
from core.models import Alert
from tools.ip_lookup import IPLookupTool
from tools.whois_lookup import WHOISTool
from tools.port_scan import PortScanTool

SYSTEM_PROMPT = """You are a Reconnaissance Specialist in a SOC investigation.
You have access to IP lookup, WHOIS, and port scan tools.
Given an alert, gather all available information about the involved IPs, domains, hostnames.
Think step by step. Use tools in order: IP lookup → WHOIS → port scan.
Summarize what you found in 2-3 sentences."""


class ReconAgent(AgentBase):
    name = "recon"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ip_tool = IPLookupTool()
        self.whois_tool = WHOISTool()
        self.port_tool = PortScanTool()

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log(f"Starting recon for alert {alert.id}")

        # Run tool lookups
        findings = {}
        if alert.source_ip:
            self.log(f"Querying {alert.source_ip}...")
            ip_data = await self.ip_tool.run({"ip": alert.source_ip})
            port_data = await self.port_tool.run({"ip": alert.source_ip})
            findings["source_ip"] = {**ip_data, **port_data}

            # Write IP node
            ip_node_id = self.graph.write_node(
                type="ip", label=alert.source_ip,
                data={**ip_data, "open_ports": port_data.get("open_ports", [])},
                created_by=self.name
            )

            # Link alert node to IP node
            alert_nodes = self.graph.get_nodes_by_type("alert")
            if alert_nodes:
                self.graph.write_edge(alert_nodes[0]["id"], ip_node_id, "involves", self.name)

        if alert.dest_ip:
            dest_data = await self.ip_tool.run({"ip": alert.dest_ip})
            self.graph.write_node(type="ip", label=alert.dest_ip, data=dest_data, created_by=self.name)

        # Ask LLM to summarize findings
        user_msg = f"Alert: {json.dumps({'type': alert.type.value, 'severity': alert.severity.value, 'source_ip': alert.source_ip, 'dest_ip': alert.dest_ip, 'hostname': alert.hostname})}\n\nTool findings: {json.dumps(findings)}"
        summary = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": user_msg}])

        self.graph.write_node(
            type="finding", label=f"recon-summary-{alert.id}",
            data={"summary": summary, "raw_findings": findings},
            created_by=self.name
        )
        self.log(summary[:120] + "..." if len(summary) > 120 else summary)
```

- [ ] **Step 4: Implement `agents/threat_intel.py`**

```python
import json
from agents.base import AgentBase
from core.models import Alert
from tools.cve_search import CVESearchTool
from tools.threat_feed import ThreatFeedTool

SYSTEM_PROMPT = """You are a Threat Intelligence Analyst in a SOC investigation.
Given the Case Graph findings (IPs, ports, domains), look up CVEs and threat feeds.
Identify what threat actor or campaign this may be associated with.
Respond with a 2-3 sentence threat assessment."""


class ThreatIntelAgent(AgentBase):
    name = "threat_intel"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cve_tool = CVESearchTool()
        self.feed_tool = ThreatFeedTool()

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Starting threat intelligence lookups")

        cve_findings = []
        feed_findings = []

        # Get IP nodes from Recon
        ip_nodes = self.graph.get_nodes_by_type("ip")
        for ip_node in ip_nodes:
            ip = ip_node["label"]
            if ip.startswith("10.") or ip.startswith("192.168."):
                continue  # Skip internal IPs

            feed_result = await self.feed_tool.run({"ip": ip})
            feed_findings.append({"ip": ip, **feed_result})

            for port_info in ip_node["data"].get("open_ports", []):
                cve_result = await self.cve_tool.run({"port": port_info["port"], "service": port_info.get("service", "")})
                for cve in cve_result.get("cves", []):
                    cve_findings.append(cve)
                    node_id = self.graph.write_node(
                        type="cve", label=cve["id"],
                        data=cve, created_by=self.name
                    )
                    self.graph.write_edge(ip_node["id"], node_id, "linked_to", self.name)

        # Check file hash if present
        file_hash = alert.raw_payload.get("file_hash")
        if file_hash:
            hash_result = await self.feed_tool.run({"hash": file_hash})
            feed_findings.append({"hash": file_hash, **hash_result})
            if hash_result.get("malicious"):
                self.graph.write_node(type="file_hash", label=file_hash, data=hash_result, created_by=self.name)

        context = f"Alert type: {alert.type.value}\nCVEs found: {json.dumps(cve_findings)}\nThreat feed: {json.dumps(feed_findings)}"
        assessment = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])

        self.graph.write_node(
            type="finding", label=f"intel-assessment-{alert.id}",
            data={"assessment": assessment, "cves": cve_findings, "feed": feed_findings},
            created_by=self.name
        )
        self.log(assessment[:120] + "..." if len(assessment) > 120 else assessment)
```

- [ ] **Step 5: Implement `agents/forensics.py`**

```python
import json
from agents.base import AgentBase
from core.models import Alert
from tools.log_parser import LogParserTool

SYSTEM_PROMPT = """You are a Digital Forensics Investigator in a SOC investigation.
Given the alert payload and parsed logs, reconstruct the attack timeline.
Identify: initial access vector, lateral movement, persistence, data touched.
List the timeline events in chronological order. Be specific about timestamps."""


class ForensicsAgent(AgentBase):
    name = "forensics"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_tool = LogParserTool()

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Starting forensic log analysis")

        logs = alert.raw_payload.get("logs", [])
        parsed = await self.log_tool.run({"logs": logs})

        # Write each log event as a log_entry node
        prev_node_id = None
        for event in parsed.get("events", []):
            node_id = self.graph.write_node(
                type="log_entry",
                label=f"{event['event_type']} @ {event['timestamp']}",
                data=event, created_by=self.name
            )
            if prev_node_id:
                self.graph.write_edge(prev_node_id, node_id, "followed_by", self.name)
            prev_node_id = node_id

        # Ask LLM to reconstruct the attack chain
        context = f"Alert: {alert.type.value} | Severity: {alert.severity.value}\nParsed events:\n{json.dumps(parsed['events'], indent=2)}"
        analysis = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])

        # Write timeline summary
        timeline_node_id = self.graph.write_node(
            type="timeline_event",
            label=f"attack-chain-{alert.id}",
            data={"analysis": analysis, "event_count": parsed["count"]},
            created_by=self.name
        )
        self.log(f"Reconstructed {parsed['count']} events")
        self.log(analysis[:120] + "..." if len(analysis) > 120 else analysis)
```

- [ ] **Step 6: Implement `agents/remediation.py`**

```python
import json
from agents.base import AgentBase
from core.models import Alert
from tools.action_executor import ActionExecutorTool

SYSTEM_PROMPT = """You are a SOC Remediation Specialist.
Given the Case Graph findings (CVEs, timeline, threat intel), propose containment actions.
For each action return a JSON array. Each item must have:
  action_type: block_ip | disable_account | isolate_host | patch_recommendation
  target: the specific IP, account, host, or CVE to act on
  reason: why this action is needed
  urgency: immediate | within_24h | scheduled

Respond ONLY with a valid JSON array. No other text."""


class RemediationAgent(AgentBase):
    name = "remediation"

    def __init__(self, *args, auto_remediate: bool = False, **kwargs):
        super().__init__(*args, **kwargs)
        self.executor = ActionExecutorTool(auto_remediate=auto_remediate)

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Analyzing findings for remediation actions")

        # Gather context from graph
        findings = self.graph.get_nodes_by_type("finding")
        cves = self.graph.get_nodes_by_type("cve")
        timeline = self.graph.get_nodes_by_type("timeline_event")

        context = json.dumps({
            "alert": {"type": alert.type.value, "severity": alert.severity.value,
                      "source_ip": alert.source_ip, "user_account": alert.user_account, "hostname": alert.hostname},
            "findings": [f["data"] for f in findings],
            "cves": [c["data"] for c in cves],
            "timeline": [t["data"] for t in timeline],
        }, indent=2)

        raw = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": context}])

        # Parse and execute/suggest actions
        try:
            actions = json.loads(raw)
            if not isinstance(actions, list):
                actions = []
        except json.JSONDecodeError:
            self.log("Could not parse actions from LLM response", style="yellow")
            actions = []

        for action in actions:
            result = await self.executor.run(action)
            status = result["status"]
            self.graph.write_node(
                type="action",
                label=f"{action.get('action_type', 'action')}:{action.get('target', '')}",
                data={**action, "result": result},
                created_by=self.name,
            )
            # update_node_status is handled via write_node default 'active', but actions use 'suggested'/'executed'
            action_nodes = self.graph.get_nodes_by_type("action")
            if action_nodes:
                self.graph.update_node_status(action_nodes[-1]["id"], status)
            self.log(f"[{status.upper()}] {action.get('action_type')} → {action.get('target')} ({action.get('urgency')})")
```

- [ ] **Step 7: Implement `agents/reporter.py`**

```python
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from agents.base import AgentBase
from core.models import Alert

SYSTEM_PROMPT = """You are a SOC Incident Reporter.
Given the complete Case Graph of an investigation, write a structured incident report in markdown.
Include these sections:
# Incident Report
## Executive Summary (2-3 sentences)
## Alert Details (type, severity, timestamp, IPs, hostname)
## Recon Findings
## Threat Intelligence
## Attack Timeline
## Remediation Actions (taken and suggested)
## Open Questions
## Recommended Next Steps

Note any gaps where an agent failed or data is unavailable.
Be specific with IPs, CVE IDs, timestamps, and file hashes."""


class ReporterAgent(AgentBase):
    name = "reporter"

    def __init__(self, *args, reports_dir: str = "./reports", **kwargs):
        super().__init__(*args, **kwargs)
        self.reports_dir = reports_dir

    async def _run(self, task_node_id: str, alert: Alert) -> None:
        self.log("Synthesizing investigation findings into report")

        full_graph = self.graph.get_full_graph()
        # Summarize graph for LLM (avoid token overflow)
        summary = {
            "alert_id": alert.id,
            "alert_type": alert.type.value,
            "severity": alert.severity.value,
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "hostname": alert.hostname,
            "user_account": alert.user_account,
            "node_counts": {t: 0 for t in ["ip", "cve", "finding", "timeline_event", "action", "task"]},
            "findings": [],
            "cves": [],
            "timeline": [],
            "actions": [],
            "failed_tasks": [],
        }
        for node in full_graph["nodes"]:
            t = node["type"]
            if t in summary["node_counts"]:
                summary["node_counts"][t] += 1
            if t == "finding":
                summary["findings"].append(node["data"])
            elif t == "cve":
                summary["cves"].append(node["data"])
            elif t == "timeline_event":
                summary["timeline"].append(node["data"])
            elif t == "action":
                summary["actions"].append({**node["data"], "status": node["status"]})
            elif t == "task" and node["status"] == "failed":
                summary["failed_tasks"].append(node["label"])

        context = json.dumps(summary, indent=2)
        report_text = await self.llm.call(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": f"Investigation data:\n{context}"}],
            max_tokens=8192,
        )

        # Save report
        Path(self.reports_dir).mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M")
        filename = f"{ts}-{alert.id[:8]}.md"
        report_path = os.path.join(self.reports_dir, filename)
        with open(report_path, "w") as f:
            f.write(report_text)

        # Print to terminal
        self.console.rule("[bold green]INCIDENT REPORT[/bold green]")
        self.console.print(report_text)
        self.console.rule()
        self.log(f"Report saved: {report_path}", style="bold green")
```

- [ ] **Step 8: Run all agent tests**

```bash
pytest tests/test_agents.py -v
```

Expected: All 6 tests PASS.

- [ ] **Step 9: Commit**

```bash
git add agents/ tests/test_agents.py
git commit -m "feat: all 5 specialist agents — recon, threat_intel, forensics, remediation, reporter"
```

---

## Task 10: Commander Agent

**Files:**
- Create: `agents/commander.py`

- [ ] **Step 1: Implement `agents/commander.py`**

```python
import asyncio
import json
from datetime import datetime, timezone
from rich.console import Console
from core.case_graph import CaseGraph
from core.llm_client import LLMClient
from core.models import Alert
from agents.recon import ReconAgent
from agents.threat_intel import ThreatIntelAgent
from agents.forensics import ForensicsAgent
from agents.remediation import RemediationAgent
from agents.reporter import ReporterAgent

SYSTEM_PROMPT = """You are the Commander of a Security Operations Center investigation.
You receive a normalized security alert. Respond ONLY with valid JSON:
{"objective": "one sentence describing what happened", "priority_agents": ["recon", "threat_intel", "forensics"]}
Always include recon. Include threat_intel and forensics for all alerts. Include remediation only if severity is high or critical."""


class Commander:
    name = "commander"

    def __init__(self, case_graph: CaseGraph, llm: LLMClient, console: Console,
                 agent_timeout: int = 120, commander_timeout: int = 300,
                 auto_remediate: bool = False, reports_dir: str = "./reports"):
        self.graph = case_graph
        self.llm = llm
        self.console = console
        self.agent_timeout = agent_timeout
        self.commander_timeout = commander_timeout
        self.auto_remediate = auto_remediate
        self.reports_dir = reports_dir

    def log(self, message: str, style: str = "bold magenta") -> None:
        self.console.print(f"[bold magenta][COMMANDER][/bold magenta] {message}")

    async def investigate(self, alert: Alert) -> None:
        """Run the full investigation pipeline."""
        start = datetime.now(timezone.utc)

        # Print header
        severity_color = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}.get(alert.severity.value, "white")
        self.console.rule(
            f"[bold]SOC AGENT[/bold]  │  Alert: [bold]{alert.type.value.upper()}[/bold]  │  [{severity_color}]{alert.severity.value.upper()}[/{severity_color}]"
        )

        # Write alert node to graph
        alert_node_id = self.graph.write_node(
            type="alert", label=alert.id,
            data={"type": alert.type.value, "severity": alert.severity.value,
                  "source_ip": alert.source_ip, "dest_ip": alert.dest_ip,
                  "hostname": alert.hostname, "user_account": alert.user_account},
            created_by=self.name
        )

        # Classify alert
        alert_summary = json.dumps({
            "type": alert.type.value, "severity": alert.severity.value,
            "source_ip": alert.source_ip, "dest_ip": alert.dest_ip,
            "dest_port": alert.dest_port, "hostname": alert.hostname,
            "user_account": alert.user_account,
        })
        try:
            raw = await self.llm.call(system=SYSTEM_PROMPT, messages=[{"role": "user", "content": alert_summary}])
            plan = json.loads(raw)
        except Exception:
            plan = {"objective": f"Investigate {alert.type.value} alert", "priority_agents": ["recon", "threat_intel", "forensics"]}

        self.log(f"Alert received. Objective: {plan.get('objective', 'Investigate')}")

        # Build agent instances
        kwargs = dict(case_graph=self.graph, llm=self.llm, console=self.console, agent_timeout=self.agent_timeout)
        agents_map = {
            "recon":        ReconAgent(**kwargs),
            "threat_intel": ThreatIntelAgent(**kwargs),
            "forensics":    ForensicsAgent(**kwargs),
            "remediation":  RemediationAgent(**kwargs, auto_remediate=self.auto_remediate),
            "reporter":     ReporterAgent(**kwargs, reports_dir=self.reports_dir),
        }

        try:
            await asyncio.wait_for(
                self._run_phases(alert, agents_map),
                timeout=self.commander_timeout
            )
        except asyncio.TimeoutError:
            self.log(f"Overall investigation timeout ({self.commander_timeout}s). Running reporter with available data.", style="red")
            reporter_task_id = self.graph.write_node("task", "reporter-task", {"agent": "reporter"}, self.name)
            await agents_map["reporter"].run(reporter_task_id, alert)

        elapsed = (datetime.now(timezone.utc) - start).seconds
        self.log(f"Investigation complete in {elapsed}s")

    async def _run_phases(self, alert: Alert, agents_map: dict) -> None:
        # Phase 1: Recon (sequential)
        self.log("Phase 1: Recon")
        recon_task_id = self.graph.write_node("task", "recon-task", {"agent": "recon"}, self.name)
        await agents_map["recon"].run(recon_task_id, alert)

        # Phase 2: Threat Intel + Forensics (concurrent)
        self.log("Phase 2: Threat Intel + Forensics (concurrent)")
        intel_task_id = self.graph.write_node("task", "intel-task", {"agent": "threat_intel"}, self.name)
        forensics_task_id = self.graph.write_node("task", "forensics-task", {"agent": "forensics"}, self.name)
        await asyncio.gather(
            agents_map["threat_intel"].run(intel_task_id, alert),
            agents_map["forensics"].run(forensics_task_id, alert),
        )

        # Phase 3: Remediation (sequential)
        self.log("Phase 3: Remediation")
        remediation_task_id = self.graph.write_node("task", "remediation-task", {"agent": "remediation"}, self.name)
        await agents_map["remediation"].run(remediation_task_id, alert)

        # Phase 4: Reporter
        self.log("Phase 4: Generating incident report")
        reporter_task_id = self.graph.write_node("task", "reporter-task", {"agent": "reporter"}, self.name)
        await agents_map["reporter"].run(reporter_task_id, alert)
```

- [ ] **Step 2: Verify import works**

```bash
python -c "from agents.commander import Commander; print('Commander OK')"
```

Expected: `Commander OK`

- [ ] **Step 3: Commit**

```bash
git add agents/commander.py
git commit -m "feat: Commander agent — 4-phase orchestration with timeout handling"
```

---

## Task 11: CLI Entry Point

**Files:**
- Create: `main.py`

- [ ] **Step 1: Implement `main.py`**

```python
#!/usr/bin/env python3
import argparse
import asyncio
import os
import sys
from pathlib import Path

from rich.console import Console
from dotenv import load_dotenv

load_dotenv()


def main():
    parser = argparse.ArgumentParser(
        description="SOC Agent — autonomous multi-agent security incident investigation"
    )
    parser.add_argument(
        "--alert",
        required=True,
        help="Alert source: 'simulated' or path to JSON alert file"
    )
    parser.add_argument(
        "--auto-remediate",
        action="store_true",
        default=False,
        help="Execute immediate-urgency remediation actions (default: suggest only)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Override overall investigation timeout in seconds"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Verbose output including LLM inputs/outputs"
    )
    args = parser.parse_args()

    # Lazy imports after arg parsing
    from core.config import Config
    from core.case_graph import CaseGraph
    from core.llm_client import LLMClient
    from ingestion.loader import load_alert
    from agents.commander import Commander

    try:
        config = Config.from_env()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    console = Console()

    # Load alert
    try:
        alert = load_alert(args.alert)
    except (FileNotFoundError, ValueError) as e:
        console.print(f"[red]Error loading alert:[/red] {e}")
        sys.exit(1)

    # Initialize Case Graph (fresh DB per investigation — use timestamp in path)
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    db_path = config.db_path.replace(".db", f"-{ts}.db")
    graph = CaseGraph(db_path=db_path)

    # Initialize LLM
    llm = LLMClient(api_key=config.anthropic_api_key, model=config.model)

    # Build and run commander
    commander_timeout = args.timeout or config.commander_timeout
    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        agent_timeout=config.agent_timeout,
        commander_timeout=commander_timeout,
        auto_remediate=args.auto_remediate or config.auto_remediate,
        reports_dir=config.reports_dir,
    )

    Path(config.reports_dir).mkdir(parents=True, exist_ok=True)

    asyncio.run(commander.investigate(alert))


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Verify CLI help works**

```bash
python main.py --help
```

Expected: Shows usage with `--alert`, `--auto-remediate`, `--timeout`, `--debug` options.

- [ ] **Step 3: Commit**

```bash
git add main.py
git commit -m "feat: CLI entry point with argparse and dotenv config"
```

---

## Task 12: Integration Test

**Files:**
- Create: `tests/test_integration.py`

> **Note:** This test requires a real `ANTHROPIC_API_KEY`. It is skipped in CI without one.

- [ ] **Step 1: Write integration test**

```python
# tests/test_integration.py
import os
import pytest
import asyncio
from pathlib import Path

pytestmark = pytest.mark.skipif(
    not os.getenv("ANTHROPIC_API_KEY"),
    reason="ANTHROPIC_API_KEY required for integration tests"
)


@pytest.mark.asyncio
async def test_full_intrusion_investigation(tmp_path):
    """End-to-end: load sample intrusion alert, run full pipeline, verify report produced."""
    from core.case_graph import CaseGraph
    from core.llm_client import LLMClient
    from core.config import Config
    from ingestion.loader import load_alert
    from agents.commander import Commander
    from rich.console import Console

    config = Config.from_env()
    alert = load_alert("alerts/sample_intrusion.json")

    graph = CaseGraph(db_path=str(tmp_path / "test.db"))
    llm = LLMClient(api_key=config.anthropic_api_key, model=config.model)
    console = Console(quiet=True)
    reports_dir = str(tmp_path / "reports")

    commander = Commander(
        case_graph=graph, llm=llm, console=console,
        agent_timeout=60, commander_timeout=180,
        reports_dir=reports_dir,
    )

    await commander.investigate(alert)

    # Assert report file was created
    report_files = list(Path(reports_dir).glob("*.md"))
    assert len(report_files) == 1, "Expected exactly one report file"

    content = report_files[0].read_text()
    assert len(content) > 200, "Report should have meaningful content"
    assert "Incident Report" in content or "incident" in content.lower()

    # Assert Case Graph has entries from all agents
    nodes = graph.get_full_graph()["nodes"]
    node_types = {n["type"] for n in nodes}
    assert "alert" in node_types
    assert "task" in node_types
    assert "ip" in node_types

    # Assert all tasks completed or failed (none left pending/in_progress)
    task_nodes = graph.get_nodes_by_type("task")
    for task in task_nodes:
        assert task["status"] in ("complete", "failed"), \
            f"Task {task['label']} left in status {task['status']}"
```

- [ ] **Step 2: Run integration test (requires `.env` with real key)**

```bash
pytest tests/test_integration.py -v -s
```

Expected: 1 test PASS. Full terminal output from all agents. Report file created in `tmp` dir.

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: integration test — full intrusion investigation pipeline"
```

---

## Task 13: Final Smoke Test and README

**Files:**
- Create: `README.md`

- [ ] **Step 1: Run full test suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py
```

Expected: All unit tests PASS. No failures. Zero warnings (or only asyncio deprecation warnings from pytest-asyncio).

- [ ] **Step 2: Create `.env` from template and run with simulated alert**

```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
python main.py --alert simulated
```

Expected: Terminal output shows all 4 phases running. Report file created in `./reports/`.

- [ ] **Step 3: Run with a real sample alert**

```bash
python main.py --alert alerts/sample_intrusion.json
```

Expected: Agents run, findings appear in terminal, report saved.

- [ ] **Step 4: Write `README.md`**

```markdown
# SOC Agent

Autonomous multi-agent security incident investigation system. When an alert arrives, a team of specialized AI agents investigates in parallel and produces an incident report — before your on-call engineer picks up the phone.

## Architecture

```
Alert → Commander → Recon → [Threat Intel + Forensics] → Remediation → Reporter
```

All agents share findings through a SQLite Case Graph.

## Setup

1. Install dependencies: `pip install -r requirements.txt`
2. Copy config: `cp .env.example .env` and add your `ANTHROPIC_API_KEY`
3. Run: `python main.py --alert simulated`

## Usage

```bash
python main.py --alert simulated                          # Simulated alert
python main.py --alert alerts/sample_intrusion.json      # From file
python main.py --alert alerts/sample_malware.json --auto-remediate  # Auto-fix
python main.py --alert alerts/sample_brute_force.json --timeout 120
```

## Agents

| Agent | Role |
|---|---|
| Commander | Orchestrates all phases |
| Recon | IP/domain/asset reconnaissance |
| Threat Intel | CVE and threat feed lookups |
| Forensics | Log analysis and attack timeline |
| Remediation | Containment actions (suggest or execute) |
| Reporter | Final incident report |

## Testing

```bash
pytest tests/ -v --ignore=tests/test_integration.py   # Unit tests (no API key needed)
pytest tests/test_integration.py -v -s                 # Integration test (needs API key)
```
```

- [ ] **Step 5: Final commit**

```bash
git add README.md
git commit -m "docs: README with setup and usage instructions"
git tag v0.1.0
```

---

## Summary

| Task | Files Created | Tests |
|---|---|---|
| 1 — Scaffolding | `requirements.txt`, `.env.example`, dirs | — |
| 2 — Models | `core/models.py` | `tests/test_models.py` (4 tests) |
| 3 — Config | `core/config.py` | manual verify |
| 4 — Case Graph | `core/case_graph.py` | `tests/test_case_graph.py` (9 tests) |
| 5 — LLM Client | `core/llm_client.py` | `tests/test_llm_client.py` (3 tests) |
| 6 — Ingestion | `ingestion/`, `alerts/` | `tests/test_ingestion.py` (5 tests) |
| 7 — Tools | `tools/` (7 stubs) | `tests/test_tools.py` (10 tests) |
| 8 — AgentBase | `agents/base.py` | manual verify |
| 9 — Agents | `agents/` (5 agents) | `tests/test_agents.py` (6 tests) |
| 10 — Commander | `agents/commander.py` | manual verify |
| 11 — CLI | `main.py` | manual verify |
| 12 — Integration | — | `tests/test_integration.py` (1 test) |
| 13 — README | `README.md` | full smoke test |

**Total unit tests: 37** (excluding integration)
