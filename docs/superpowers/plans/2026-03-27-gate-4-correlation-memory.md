# Gate 4: Correlation and Memory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-incident memory and entity correlation so every investigation is aware of prior incidents involving the same hosts, users, IPs, and hashes — and so completed investigations can be replayed or audited.

**Architecture:** A shared `MemoryStore` (SQLite file `soc_memory.db`, separate from per-run case graphs) persists `IncidentMemory` and `AssetBaseline` rows after each investigation. A `CorrelationService` queries those rows before each investigation and injects a prior-context summary into the Commander's LLM prompt. Entity extraction reads the completed case-graph nodes after `commander.investigate()` returns. A `replay` module re-runs a past investigation by reconstructing the alert and plan from stored memory and the event log.

**Tech Stack:** Python 3.11+, stdlib `sqlite3`, existing `core.event_log.EventLog`, existing `core.schemas`, existing `core.models`, existing `rich` for CLI output. No new packages.

---

## Scope note

This plan covers Gate 4 only. Gates 5 and 6 are separate plans. Gate 4 has no hard runtime dependency on Gates 5 or 6, but both use the `MemoryStore` pattern established here as a reference.

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `core/schemas.py` | **Modify** | Add `IncidentMemory`, `AssetBaseline`, `PriorContext` dataclasses |
| `core/memory_store.py` | **Create** | `MemoryStore` — SQLite-backed cross-incident memory (incident_memory + asset_baseline tables) |
| `core/correlation.py` | **Create** | `CorrelationService` — entity overlap queries, prior context assembly |
| `core/entity_extractor.py` | **Create** | `extract_entities_from_graph(graph)` — pulls hosts/users/IPs/hashes from a completed case graph |
| `core/replay.py` | **Create** | `replay_investigation(run_id, memory_store, config)` — reconstruct and re-run a past investigation |
| `core/config.py` | **Modify** | Add `memory_db_path`, `memory_context_limit`, `enable_memory` fields |
| `core/app.py` | **Modify** | After `commander.investigate()`: extract entities, write memory, update baselines |
| `agents/commander.py` | **Modify** | Before LLM planning call: fetch prior context from CorrelationService, inject into prompt |
| `main.py` | **Modify** | Add `soc recall <entity>` and `soc replay <run_id>` subcommands |
| `tests/test_memory_store.py` | **Create** | Unit tests for MemoryStore read/write/upsert |
| `tests/test_correlation.py` | **Create** | Unit tests for CorrelationService entity matching |
| `tests/test_entity_extractor.py` | **Create** | Unit tests for entity extraction from a fake graph |
| `tests/test_replay.py` | **Create** | Unit tests for replay with a stored memory + mock LLM |
| `tests/test_schemas.py` | **Modify** | Add tests for new schema dataclasses |

---

## Task 1: Add memory schemas

**Files:**
- Modify: `core/schemas.py`
- Modify: `tests/test_schemas.py`

- [ ] **Step 1: Write failing tests**

Add to `tests/test_schemas.py`:

```python
from core.schemas import IncidentMemory, AssetBaseline, PriorContext
from dataclasses import fields

def test_incident_memory_required_fields():
    required = {f.name for f in fields(IncidentMemory)}
    assert "memory_id" in required
    assert "incident_id" in required
    assert "run_id" in required
    assert "alert_type" in required
    assert "alert_json" in required   # serialized Alert for replay
    assert "entities" in required
    assert "actions_taken" in required
    assert "started_at" in required

def test_asset_baseline_required_fields():
    required = {f.name for f in fields(AssetBaseline)}
    assert "baseline_id" in required
    assert "entity_type" in required
    assert "entity_value" in required
    assert "baseline_type" in required
    assert "incident_count" in required

def test_prior_context_has_content_check():
    ctx = PriorContext(prior_incidents=[], entity_baselines=[])
    assert ctx.has_context is False
    from core.schemas import IncidentMemory
    from datetime import datetime, timezone
    mem = IncidentMemory(
        memory_id="m1", incident_id="i1", run_id="r1",
        alert_type="intrusion", alert_json="{}",
        entities={"hosts": ["web-01"]}, actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    ctx2 = PriorContext(prior_incidents=[mem], entity_baselines=[])
    assert ctx2.has_context is True


def test_format_for_prompt_limit_truncates():
    """format_for_prompt(limit=1) must return exactly one incident block even when two are present."""
    from core.schemas import IncidentMemory, PriorContext
    from datetime import datetime, timezone
    def _m(run_id):
        return IncidentMemory(
            memory_id=f"m-{run_id}", incident_id=f"i-{run_id}", run_id=run_id,
            alert_type="brute_force", alert_json="{}",
            entities={"ips": ["10.0.0.1"]}, actions_taken=[],
            started_at=datetime.now(timezone.utc).isoformat(),
        )
    ctx = PriorContext(prior_incidents=[_m("run-AAA"), _m("run-BBB")], entity_baselines=[])
    text = ctx.format_for_prompt(limit=1)
    assert text.count("run-") == 1, "Only one incident should appear when limit=1"
```

- [ ] **Step 2: Run to confirm failure**

```bash
cd /Users/waleedakrabi/Desktop/Github-forks/soc-agent
pytest tests/test_schemas.py::test_incident_memory_required_fields tests/test_schemas.py::test_asset_baseline_required_fields tests/test_schemas.py::test_prior_context_has_content_check -v
```

Expected: `ImportError: cannot import name 'IncidentMemory'`

- [ ] **Step 3: Add schemas to `core/schemas.py`**

Append after the `validate_action_proposals` function:

```python
@dataclass
class IncidentMemory:
    memory_id: str
    incident_id: str          # alert.id
    run_id: str               # InvestigationRun.run_id
    alert_type: str           # alert.type.value
    alert_json: str           # JSON-serialized Alert for replay
    entities: dict            # {hosts: [], users: [], ips: [], domains: [], hashes: []}
    actions_taken: list       # [{action_type, target, status, urgency}]
    started_at: str           # ISO timestamp
    completed_at: str | None = None
    outcome: str | None = None          # contained | inconclusive | false_positive | escalated
    analyst_notes: str | None = None
    confidence_score: float | None = None
    created_at: str | None = None       # set by MemoryStore on write


@dataclass
class AssetBaseline:
    baseline_id: str
    entity_type: str     # host | user | ip | domain | hash
    entity_value: str
    baseline_type: str   # observed | known_good | known_bad | suspicious
    first_seen: str      # ISO timestamp
    last_seen: str       # ISO timestamp
    incident_count: int = 1
    tags: list[str] = field(default_factory=list)


@dataclass
class PriorContext:
    prior_incidents: list[IncidentMemory]
    entity_baselines: list[AssetBaseline]

    @property
    def has_context(self) -> bool:
        return bool(self.prior_incidents or self.entity_baselines)

    def format_for_prompt(self, limit: int = 3) -> str:
        """Return a concise text block for injection into the Commander's LLM prompt."""
        lines = ["[Prior Investigation Context]"]
        for mem in self.prior_incidents[:limit]:
            entities_summary = ", ".join(
                f"{k}: {v}" for k, v in mem.entities.items() if v
            )
            lines.append(
                f"- {mem.alert_type} incident on {mem.started_at[:10]} "
                f"(run {mem.run_id[:8]}): entities=[{entities_summary}] "
                f"outcome={mem.outcome or 'unknown'}"
            )
        for baseline in self.entity_baselines[:limit]:
            lines.append(
                f"- {baseline.entity_type} '{baseline.entity_value}': "
                f"{baseline.baseline_type}, seen in {baseline.incident_count} incident(s)"
            )
        return "\n".join(lines)
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_schemas.py -v
```

Expected: all schema tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/schemas.py tests/test_schemas.py
git commit -m "feat(gate4): add IncidentMemory, AssetBaseline, PriorContext schemas"
```

---

## Task 2: Create MemoryStore

**Files:**
- Create: `core/memory_store.py`
- Create: `tests/test_memory_store.py`

The `MemoryStore` owns a shared SQLite file (`soc_memory.db` by default). All runs read from and write to this same file — it persists across investigations.

- [ ] **Step 1: Write failing tests**

Create `tests/test_memory_store.py`:

```python
import pytest
from datetime import datetime, timezone
from core.memory_store import MemoryStore
from core.schemas import IncidentMemory, AssetBaseline


def _mem(incident_id="i1", run_id="r1", alert_type="intrusion",
         entities=None, actions_taken=None) -> IncidentMemory:
    return IncidentMemory(
        memory_id=f"m-{incident_id}",
        incident_id=incident_id,
        run_id=run_id,
        alert_type=alert_type,
        alert_json='{"id": "' + incident_id + '"}',
        entities=entities or {"hosts": ["web-01"], "ips": ["1.2.3.4"]},
        actions_taken=actions_taken or [{"action_type": "block_ip", "target": "1.2.3.4"}],
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def test_write_and_read_incident_memory(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    mem = _mem()
    store.write_memory(mem)
    results = store.get_memories_by_alert_type("intrusion", limit=10)
    assert len(results) == 1
    assert results[0].incident_id == "i1"


def test_get_memories_by_entity_ip(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1", entities={"ips": ["10.0.0.1"]}))
    store.write_memory(_mem("i2", entities={"ips": ["10.0.0.2"]}))
    results = store.get_memories_by_entity("ip", "10.0.0.1", limit=10)
    assert len(results) == 1
    assert results[0].incident_id == "i1"


def test_get_memories_by_entity_host(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1", entities={"hosts": ["bastion-01"]}))
    store.write_memory(_mem("i2", entities={"hosts": ["workstation-99"]}))
    results = store.get_memories_by_entity("host", "bastion-01", limit=10)
    assert len(results) == 1
    assert results[0].incident_id == "i1"


def test_upsert_baseline_increments_count(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.upsert_baseline("ip", "10.0.0.1", "observed", incident_id="i1")
    store.upsert_baseline("ip", "10.0.0.1", "observed", incident_id="i2")
    baseline = store.get_baseline("ip", "10.0.0.1")
    assert baseline is not None
    assert baseline.incident_count == 2
    assert baseline.entity_value == "10.0.0.1"


def test_upsert_baseline_promotes_to_known_bad(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.upsert_baseline("ip", "10.0.0.1", "observed", incident_id="i1")
    store.upsert_baseline("ip", "10.0.0.1", "known_bad", incident_id="i2")
    baseline = store.get_baseline("ip", "10.0.0.1")
    assert baseline.baseline_type == "known_bad"


def test_record_feedback_updates_outcome(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    mem = _mem(incident_id="i99")
    store.write_memory(mem)
    store.record_feedback("i99", outcome="false_positive", notes="Pen test activity")
    results = store.get_memories_by_alert_type("intrusion")
    assert results[0].outcome == "false_positive"
    assert results[0].analyst_notes == "Pen test activity"


def test_get_memories_by_alert_type_limit(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    for i in range(5):
        store.write_memory(_mem(incident_id=f"i{i}", alert_type="malware"))
    results = store.get_memories_by_alert_type("malware", limit=3)
    assert len(results) == 3
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_memory_store.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.memory_store'`

- [ ] **Step 3: Create `core/memory_store.py`**

```python
from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from core.schemas import AssetBaseline, IncidentMemory

_BASELINE_PRIORITY = {
    "known_bad": 3,
    "suspicious": 2,
    "observed": 1,
    "known_good": 0,
}


class MemoryStore:
    """Shared cross-incident SQLite memory store.

    This is NOT a per-run case graph. It accumulates facts across all runs
    and is the foundation for correlation and asset baselines.
    """

    def __init__(self, db_path: str = "./soc_memory.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
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
                CREATE TABLE IF NOT EXISTS incident_memory (
                    memory_id       TEXT PRIMARY KEY,
                    incident_id     TEXT NOT NULL,
                    run_id          TEXT NOT NULL,
                    alert_type      TEXT NOT NULL,
                    alert_json      TEXT NOT NULL,
                    entities_json   TEXT NOT NULL,
                    actions_json    TEXT NOT NULL,
                    started_at      TEXT NOT NULL,
                    completed_at    TEXT,
                    outcome         TEXT,
                    analyst_notes   TEXT,
                    confidence_score REAL,
                    created_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_im_alert_type ON incident_memory(alert_type);
                CREATE INDEX IF NOT EXISTS idx_im_incident_id ON incident_memory(incident_id);

                CREATE TABLE IF NOT EXISTS asset_baseline (
                    baseline_id     TEXT PRIMARY KEY,
                    entity_type     TEXT NOT NULL,
                    entity_value    TEXT NOT NULL,
                    baseline_type   TEXT NOT NULL,
                    first_seen      TEXT NOT NULL,
                    last_seen       TEXT NOT NULL,
                    incident_count  INTEGER NOT NULL DEFAULT 1,
                    tags_json       TEXT NOT NULL DEFAULT '[]',
                    UNIQUE(entity_type, entity_value)
                );
                CREATE INDEX IF NOT EXISTS idx_ab_entity ON asset_baseline(entity_type, entity_value);
            """)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ── Incident Memory ──────────────────────────────────────────────────────

    def write_memory(self, mem: IncidentMemory) -> None:
        created_at = mem.created_at or self._now()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO incident_memory
                   (memory_id, incident_id, run_id, alert_type, alert_json,
                    entities_json, actions_json, started_at, completed_at,
                    outcome, analyst_notes, confidence_score, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    mem.memory_id, mem.incident_id, mem.run_id,
                    mem.alert_type, mem.alert_json,
                    json.dumps(mem.entities), json.dumps(mem.actions_taken),
                    mem.started_at, mem.completed_at,
                    mem.outcome, mem.analyst_notes, mem.confidence_score,
                    created_at,
                ),
            )

    def get_memories_by_alert_type(
        self, alert_type: str, limit: int = 10
    ) -> list[IncidentMemory]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_memory WHERE alert_type=? "
                "ORDER BY started_at DESC LIMIT ?",
                (alert_type, limit),
            ).fetchall()
        return [self._row_to_memory(r) for r in rows]

    def get_memories_by_entity(
        self, entity_type: str, entity_value: str, limit: int = 10
    ) -> list[IncidentMemory]:
        """Find incidents where this entity appears. Uses JSON contains check."""
        key_map = {
            "host": "hosts", "user": "users", "ip": "ips",
            "domain": "domains", "hash": "hashes",
        }
        json_key = key_map.get(entity_type, entity_type + "s")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_memory "
                "WHERE json_extract(entities_json, '$.' || ?) IS NOT NULL "
                "AND entities_json LIKE ? "
                "ORDER BY started_at DESC LIMIT ?",
                (json_key, f"%{entity_value}%", limit),
            ).fetchall()
        return [
            r for r in (self._row_to_memory(row) for row in rows)
            if entity_value in r.entities.get(json_key, [])
        ]

    def get_memory_by_run_id(self, run_id: str) -> IncidentMemory | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incident_memory WHERE run_id=?", (run_id,)
            ).fetchone()
        return self._row_to_memory(row) if row else None

    def record_feedback(
        self, incident_id: str, outcome: str, notes: str = ""
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE incident_memory SET outcome=?, analyst_notes=? "
                "WHERE incident_id=?",
                (outcome, notes or None, incident_id),
            )

    @staticmethod
    def _row_to_memory(row) -> IncidentMemory:
        d = dict(row)
        return IncidentMemory(
            memory_id=d["memory_id"],
            incident_id=d["incident_id"],
            run_id=d["run_id"],
            alert_type=d["alert_type"],
            alert_json=d["alert_json"],
            entities=json.loads(d["entities_json"]),
            actions_taken=json.loads(d["actions_json"]),
            started_at=d["started_at"],
            completed_at=d.get("completed_at"),
            outcome=d.get("outcome"),
            analyst_notes=d.get("analyst_notes"),
            confidence_score=d.get("confidence_score"),
            created_at=d.get("created_at"),
        )

    # ── Asset Baseline ───────────────────────────────────────────────────────

    def upsert_baseline(
        self,
        entity_type: str,
        entity_value: str,
        baseline_type: str,
        *,
        incident_id: str = "",
        tags: list[str] | None = None,
    ) -> None:
        now = self._now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT baseline_id, baseline_type, incident_count "
                "FROM asset_baseline WHERE entity_type=? AND entity_value=?",
                (entity_type, entity_value),
            ).fetchone()
            if existing:
                new_type = (
                    baseline_type
                    if _BASELINE_PRIORITY.get(baseline_type, 0)
                    > _BASELINE_PRIORITY.get(existing["baseline_type"], 0)
                    else existing["baseline_type"]
                )
                conn.execute(
                    "UPDATE asset_baseline SET baseline_type=?, last_seen=?, "
                    "incident_count=incident_count+1 WHERE entity_type=? AND entity_value=?",
                    (new_type, now, entity_type, entity_value),
                )
            else:
                conn.execute(
                    "INSERT INTO asset_baseline "
                    "(baseline_id, entity_type, entity_value, baseline_type, "
                    "first_seen, last_seen, incident_count, tags_json) "
                    "VALUES (?,?,?,?,?,?,1,?)",
                    (
                        str(uuid.uuid4()),
                        entity_type, entity_value, baseline_type,
                        now, now,
                        json.dumps(tags or []),
                    ),
                )

    def get_baseline(
        self, entity_type: str, entity_value: str
    ) -> AssetBaseline | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM asset_baseline WHERE entity_type=? AND entity_value=?",
                (entity_type, entity_value),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        return AssetBaseline(
            baseline_id=d["baseline_id"],
            entity_type=d["entity_type"],
            entity_value=d["entity_value"],
            baseline_type=d["baseline_type"],
            first_seen=d["first_seen"],
            last_seen=d["last_seen"],
            incident_count=d["incident_count"],
            tags=json.loads(d["tags_json"]),
        )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_memory_store.py -v
```

Expected: all 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/memory_store.py tests/test_memory_store.py
git commit -m "feat(gate4): add MemoryStore with incident_memory and asset_baseline tables"
```

---

## Task 3: Create entity extractor

**Files:**
- Create: `core/entity_extractor.py`
- Create: `tests/test_entity_extractor.py`

After an investigation completes, we extract entity values from the case graph nodes so they can be stored in `IncidentMemory.entities` and indexed for later correlation.

- [ ] **Step 1: Write failing tests**

Create `tests/test_entity_extractor.py`:

```python
import pytest
from unittest.mock import MagicMock
from core.entity_extractor import extract_entities_from_graph, extract_actions_from_graph


def _fake_graph(nodes_by_type: dict):
    graph = MagicMock()
    graph.get_nodes_by_type.side_effect = lambda t: nodes_by_type.get(t, [])
    return graph


def test_extract_ips(tmp_path):
    graph = _fake_graph({
        "ip": [{"data": {"ip": "1.2.3.4"}}, {"data": {"ip": "5.6.7.8"}}],
    })
    entities = extract_entities_from_graph(graph)
    assert "1.2.3.4" in entities["ips"]
    assert "5.6.7.8" in entities["ips"]


def test_extract_hosts_from_task_data(tmp_path):
    graph = _fake_graph({
        "ip": [{"data": {"hostname": "web-prod-01"}}],
    })
    entities = extract_entities_from_graph(graph)
    assert "web-prod-01" in entities["hosts"]


def test_extract_alert_entities(tmp_path):
    from core.models import Alert, AlertType, Severity
    from datetime import datetime, timezone
    alert = Alert(
        id="a1", type=AlertType.INTRUSION, severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc), raw_payload={},
        source_ip="10.0.0.1", hostname="bastion-01", user_account="jdoe",
    )
    graph = _fake_graph({})
    entities = extract_entities_from_graph(graph, alert=alert)
    assert "10.0.0.1" in entities["ips"]
    assert "bastion-01" in entities["hosts"]
    assert "jdoe" in entities["users"]


def test_extract_actions(tmp_path):
    graph = _fake_graph({
        "action": [
            {"data": {"action_type": "block_ip", "target": "1.2.3.4", "urgency": "immediate"},
             "status": "proposed"},
        ],
    })
    actions = extract_actions_from_graph(graph)
    assert len(actions) == 1
    assert actions[0]["action_type"] == "block_ip"
    assert actions[0]["status"] == "proposed"


def test_empty_graph_returns_empty_entities(tmp_path):
    graph = _fake_graph({})
    entities = extract_entities_from_graph(graph)
    assert entities == {"hosts": [], "users": [], "ips": [], "domains": [], "hashes": []}
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_entity_extractor.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.entity_extractor'`

- [ ] **Step 3: Create `core/entity_extractor.py`**

```python
"""Extract structured entities from a completed investigation case graph."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import Alert
    from core.storage import StorageBackend


def extract_entities_from_graph(
    graph: "StorageBackend",
    alert: "Alert | None" = None,
) -> dict:
    """Return a dict of entity lists: {hosts, users, ips, domains, hashes}."""
    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()

    # Seed from alert fields (most reliable source)
    if alert:
        if alert.source_ip:
            ips.add(alert.source_ip)
        if alert.dest_ip:
            ips.add(alert.dest_ip)
        if alert.hostname:
            hosts.add(alert.hostname)
        if alert.user_account:
            users.add(alert.user_account)

    # Enrich from IP-type nodes written by recon agent
    for node in graph.get_nodes_by_type("ip"):
        data = node.get("data", {})
        if ip := data.get("ip"):
            ips.add(ip)
        if host := data.get("hostname"):
            hosts.add(host)
        if domain := data.get("domain") or data.get("hostname", ""):
            if "." in domain and not domain[0].isdigit():
                domains.add(domain)

    # Users and accounts from log entries and findings
    for node in graph.get_nodes_by_type("log_entry"):
        data = node.get("data", {})
        if user := data.get("user") or data.get("user_account") or data.get("account"):
            users.add(str(user))

    for node in graph.get_nodes_by_type("finding"):
        data = node.get("data", {})
        if user := data.get("user_account"):
            users.add(str(user))

    # Hashes from CVE or threat intel nodes
    for node in graph.get_nodes_by_type("cve"):
        data = node.get("data", {})
        if h := data.get("file_hash") or data.get("hash"):
            hashes.add(str(h))

    return {
        "hosts": sorted(hosts),
        "users": sorted(users),
        "ips": sorted(ips),
        "domains": sorted(domains),
        "hashes": sorted(hashes),
    }


def extract_actions_from_graph(graph: "StorageBackend") -> list[dict]:
    """Return summary dicts for all action nodes in the graph."""
    results = []
    for node in graph.get_nodes_by_type("action"):
        data = node.get("data", {})
        results.append({
            "action_type": data.get("action_type", "unknown"),
            "target": data.get("target", ""),
            "urgency": data.get("urgency", ""),
            "status": node.get("status", "proposed"),
        })
    return results
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_entity_extractor.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/entity_extractor.py tests/test_entity_extractor.py
git commit -m "feat(gate4): add entity extractor for post-investigation memory writing"
```

---

## Task 4: Create CorrelationService

**Files:**
- Create: `core/correlation.py`
- Create: `tests/test_correlation.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_correlation.py`:

```python
import pytest
from datetime import datetime, timezone
from core.correlation import CorrelationService
from core.memory_store import MemoryStore
from core.schemas import IncidentMemory
from core.models import Alert, AlertType, Severity


def _mem(incident_id, alert_type="intrusion", entities=None):
    return IncidentMemory(
        memory_id=f"m-{incident_id}",
        incident_id=incident_id,
        run_id=f"r-{incident_id}",
        alert_type=alert_type,
        alert_json="{}",
        entities=entities or {"ips": ["10.0.0.1"]},
        actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
    )


def _alert(source_ip="10.0.0.1", hostname="host-01", user_account=None):
    return Alert(
        id="test-alert-id",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip=source_ip,
        hostname=hostname,
        user_account=user_account,
    )


def test_get_prior_context_finds_matching_ip(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1", entities={"ips": ["10.0.0.1"], "hosts": []}))
    svc = CorrelationService(store)
    ctx = svc.get_prior_context(_alert(source_ip="10.0.0.1"))
    assert ctx.has_context
    assert any(m.incident_id == "i1" for m in ctx.prior_incidents)


def test_get_prior_context_no_match_returns_empty(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1", entities={"ips": ["99.99.99.99"]}))
    svc = CorrelationService(store)
    ctx = svc.get_prior_context(_alert(source_ip="10.0.0.1"))
    assert not ctx.has_context


def test_get_prior_context_includes_baseline(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.upsert_baseline("ip", "10.0.0.1", "known_bad", incident_id="i0")
    svc = CorrelationService(store)
    ctx = svc.get_prior_context(_alert(source_ip="10.0.0.1"))
    assert ctx.has_context
    assert any(b.entity_value == "10.0.0.1" for b in ctx.entity_baselines)


def test_format_for_prompt_returns_string(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1"))
    svc = CorrelationService(store)
    ctx = svc.get_prior_context(_alert())
    text = ctx.format_for_prompt()
    assert "[Prior Investigation Context]" in text
    assert "intrusion" in text


def test_deduplication_same_incident_not_returned_twice(tmp_path):
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(_mem("i1", entities={"ips": ["10.0.0.1"], "hosts": ["web-01"]}))
    svc = CorrelationService(store)
    alert = _alert(source_ip="10.0.0.1", hostname="web-01")
    ctx = svc.get_prior_context(alert)
    incident_ids = [m.incident_id for m in ctx.prior_incidents]
    assert len(incident_ids) == len(set(incident_ids))
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_correlation.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.correlation'`

- [ ] **Step 3: Create `core/correlation.py`**

```python
"""CorrelationService: assemble prior-investigation context for a new alert."""
from __future__ import annotations

from core.schemas import PriorContext
from core.memory_store import MemoryStore

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import Alert


class CorrelationService:
    def __init__(self, memory_store: MemoryStore, limit: int = 5):
        self._store = memory_store
        self._limit = limit

    def get_prior_context(self, alert: "Alert") -> PriorContext:
        """Find prior incidents and baselines relevant to this alert."""
        seen_ids: set[str] = set()
        prior_incidents = []
        entity_baselines = []

        # Collect candidate entities from the alert
        candidates: list[tuple[str, str]] = []  # (entity_type, entity_value)
        if alert.source_ip:
            candidates.append(("ip", alert.source_ip))
        if alert.dest_ip:
            candidates.append(("ip", alert.dest_ip))
        if alert.hostname:
            candidates.append(("host", alert.hostname))
        if alert.user_account:
            candidates.append(("user", alert.user_account))

        for entity_type, entity_value in candidates:
            # Prior incidents for this entity
            for mem in self._store.get_memories_by_entity(
                entity_type, entity_value, limit=self._limit
            ):
                if mem.incident_id not in seen_ids:
                    seen_ids.add(mem.incident_id)
                    prior_incidents.append(mem)

            # Asset baseline for this entity
            baseline = self._store.get_baseline(entity_type, entity_value)
            if baseline is not None:
                entity_baselines.append(baseline)

        # Also add alert-type-matched prior incidents (context even without entity overlap).
        # NOTE: this fallback is intentional — it provides general context about the alert
        # type even when no specific entity matches. All tests that assert ctx.has_context
        # is False must use a fresh MemoryStore (tmp_path) with no prior records of the
        # same alert type; shared state would make them non-deterministic.
        if not prior_incidents:
            prior_incidents = self._store.get_memories_by_alert_type(
                alert.type.value, limit=self._limit
            )

        return PriorContext(
            prior_incidents=prior_incidents[:self._limit],
            entity_baselines=entity_baselines,
        )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_correlation.py -v
```

Expected: all 5 tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/correlation.py tests/test_correlation.py
git commit -m "feat(gate4): add CorrelationService for prior-incident context retrieval"
```

---

## Task 5: Wire memory into Config and app.py

**Files:**
- Modify: `core/config.py`
- Modify: `core/app.py`
- Modify: `tests/test_app.py`

After each investigation, extract entities from the completed graph and write an `IncidentMemory` row. Update asset baselines for each entity. Before each investigation, the Commander will receive prior context (Task 6 handles the Commander side).

- [ ] **Step 1: Add memory config fields**

In `core/config.py`, add three optional fields to the `Config` dataclass (after `event_log_dir`):

```python
memory_db_path: str = "./soc_memory.db"
enable_memory: bool = True
memory_context_limit: int = 5
```

Add to both `_from_env()` return (both `from_env` and `for_dry_run` use `_from_env`):

```python
memory_db_path=os.getenv("SOC_MEMORY_DB_PATH", "./soc_memory.db"),
enable_memory=parse_bool_flag(os.getenv("SOC_ENABLE_MEMORY"), default=True),
memory_context_limit=int(os.getenv("SOC_MEMORY_CONTEXT_LIMIT", "5")),
```

- [ ] **Step 2: Write failing test in `tests/test_app.py`**

Add to `tests/test_app.py`. Use the existing `_make_config(tmp_path)` helper (defined at the top of the file) to build the base `Config`, then override memory fields with `dataclasses.replace` — this ensures the test stays valid if new required Config fields are added later:

```python
import dataclasses

@pytest.mark.asyncio
async def test_run_investigation_writes_memory(tmp_path):
    from core.app import run_investigation
    from core.memory_store import MemoryStore
    mem_db = str(tmp_path / "mem.db")
    config = dataclasses.replace(
        _make_config(tmp_path),
        memory_db_path=mem_db,
        enable_memory=True,
    )
    from core.models import Alert, AlertType, Severity
    from datetime import datetime, timezone
    alert = Alert(
        id="mem-test-id",
        type=AlertType.BRUTE_FORCE,
        severity=Severity.MEDIUM,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="10.1.2.3",
        hostname="bastion-01",
    )
    await run_investigation(config=config, alert=alert, dry_run=True)
    store = MemoryStore(db_path=mem_db)
    mems = store.get_memories_by_alert_type("brute_force")
    assert len(mems) == 1
    assert mems[0].incident_id == "mem-test-id"
```

- [ ] **Step 3: Run to confirm failure**

```bash
pytest tests/test_app.py::test_run_investigation_writes_memory -v
```

Expected: `AssertionError: assert 0 == 1` (memory not written yet)

- [ ] **Step 4: Update `core/app.py` to write memory after investigation**

Add imports at the **top of `core/app.py`** (not inside any function):

```python
import json
import uuid as _uuid
from core.entity_extractor import extract_actions_from_graph, extract_entities_from_graph
from core.memory_store import MemoryStore
from core.schemas import IncidentMemory
```

> **Note:** `CorrelationService` will also be imported here in Task 6 Step 4. Add it to this same import block then — do not add it inside `run_investigation()`.

After `run.completed_at = datetime.now(timezone.utc)` in `run_investigation()`, add:

```python
    # --- Gate 4: write cross-incident memory ---
    mem_store: MemoryStore | None = None
    if config.enable_memory:
        mem_store = MemoryStore(db_path=config.memory_db_path)
        _write_investigation_memory(
            run=run,
            alert=alert,
            storage=storage,
            memory_store=mem_store,
            console=console,
        )
```

> **Note:** `mem_store` is created here (once) and will also be passed to `CorrelationService` in Task 6 Step 4. This eliminates the need to open a second SQLite connection later.

Add the helper function (outside `run_investigation`):

```python
def _write_investigation_memory(run, alert, storage, memory_store: MemoryStore,
                                 console=None) -> None:
    """Extract entities from completed graph and persist to MemoryStore."""
    try:
        entities = extract_entities_from_graph(storage, alert=alert)
        actions = extract_actions_from_graph(storage)
        alert_json = json.dumps({
            "id": alert.id,
            "type": alert.type.value,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "hostname": alert.hostname,
            "user_account": alert.user_account,
            "process": alert.process,
            "tags": alert.tags,
            "raw_payload": alert.raw_payload,
        })
        mem = IncidentMemory(
            memory_id=str(_uuid.uuid4()),
            incident_id=alert.id,
            run_id=run.run_id,
            alert_type=alert.type.value,
            alert_json=alert_json,
            entities=entities,
            actions_taken=actions,
            started_at=run.started_at.isoformat(),
            completed_at=run.completed_at.isoformat() if run.completed_at else None,
        )
        memory_store.write_memory(mem)
        # Update asset baselines for each entity
        for entity_type, key in [("ip", "ips"), ("host", "hosts"),
                                   ("user", "users"), ("domain", "domains")]:
            for value in entities.get(key, []):
                memory_store.upsert_baseline(entity_type, value, "observed",
                                             incident_id=alert.id)
    except Exception as exc:
        # Memory write must never crash an investigation, but failures must be observable
        if console is not None:
            console.print(f"[yellow][MEMORY][/yellow] Failed to write memory: {exc}")
```

- [ ] **Step 5: Run tests**

```bash
pytest tests/test_app.py -v
```

Expected: all app tests pass including the new memory test.

- [ ] **Step 6: Commit**

```bash
git add core/config.py core/app.py tests/test_app.py
git commit -m "feat(gate4): wire MemoryStore into app.py — write memory after each investigation"
```

---

## Task 6: Inject prior context into Commander

**Files:**
- Modify: `agents/commander.py`
- Modify: `tests/test_agents.py`

The Commander fetches prior context from `CorrelationService` before calling the LLM for its planning prompt. Context is appended to the user message if available.

- [ ] **Step 1: Write failing test**

Add to `tests/test_agents.py`:

```python
@pytest.mark.asyncio
async def test_commander_injects_prior_context(tmp_path):
    """If CorrelationService returns context, it appears in the LLM call."""
    import asyncio
    from unittest.mock import MagicMock
    from agents.commander import Commander
    from core.memory_store import MemoryStore
    from core.correlation import CorrelationService
    from core.schemas import IncidentMemory
    from datetime import datetime, timezone

    graph = MagicMock()
    graph.write_node.return_value = "node-1"
    graph.get_nodes_by_type.return_value = []

    captured_messages = []
    llm = MagicMock()
    async def fake_call(system, messages, **kwargs):
        captured_messages.extend(messages)
        return '{"objective": "test", "priority_agents": ["recon"]}'
    llm.call = fake_call
    llm.attach_event_log = MagicMock()

    from rich.console import Console
    console = Console(quiet=True)

    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    mem = IncidentMemory(
        memory_id="m1", incident_id="i1", run_id="r1",
        alert_type="intrusion", alert_json="{}",
        entities={"ips": ["10.0.0.1"]}, actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
        outcome="contained",
    )
    store.write_memory(mem)
    svc = CorrelationService(store)

    from core.models import Alert, AlertType, Severity
    alert = Alert(
        id="a1", type=AlertType.INTRUSION, severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc), raw_payload={},
        source_ip="10.0.0.1",
    )

    commander = Commander(
        case_graph=graph,
        llm=llm,
        console=console,
        commander_timeout=5,
        correlation_service=svc,
    )
    # Run investigate — we don't care about full pipeline, just the LLM call
    try:
        await asyncio.wait_for(commander.investigate(alert), timeout=3)
    except Exception:
        pass

    # At least one captured message should contain the prior context
    all_content = " ".join(m.get("content", "") for m in captured_messages)
    assert "Prior Investigation Context" in all_content
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_agents.py::test_commander_injects_prior_context -v
```

Expected: fails because `Commander` doesn't accept `correlation_service` yet.

- [ ] **Step 3: Update `agents/commander.py`**

Add `correlation_service` and `memory_context_limit` parameters to `Commander.__init__()`:

```python
from core.correlation import CorrelationService  # add import at module top

def __init__(self, ...,
             correlation_service: CorrelationService | None = None,
             memory_context_limit: int = 3):
    ...
    self.correlation_service = correlation_service
    self._memory_context_limit = memory_context_limit  # forwarded from config.memory_context_limit
```

In `Commander.investigate()`, before the `self.llm.call(...)` for planning, build the context note:

```python
async def investigate(self, alert: Alert) -> None:
    ...
    # Build context note from correlation service
    context_note = ""
    if self.correlation_service:
        try:
            prior = self.correlation_service.get_prior_context(alert)
            if prior.has_context:
                context_note = "\n\n" + prior.format_for_prompt(
                    limit=self._memory_context_limit
                )
        except Exception:
            pass  # correlation must never block an investigation

    try:
        raw = await self.llm.call(
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": alert_summary + context_note}]
        )
        plan = json.loads(raw)
    except Exception:
        ...
```

- [ ] **Step 4: Wire `CorrelationService` into `core/app.py`**

Add `CorrelationService` to the top-level imports added in Task 5, Step 4 (do **not** add them inside the function):

```python
from core.correlation import CorrelationService  # add to Task 5's import block
```

In `run_investigation()`, after creating `storage` and **before** creating `commander`, reuse the `mem_store` created in Task 5's memory-write block. Replace the Task 5 snippet so both paths share one instance:

```python
    mem_store: MemoryStore | None = None
    correlation_service = None
    if config.enable_memory:
        mem_store = MemoryStore(db_path=config.memory_db_path)
        correlation_service = CorrelationService(
            mem_store, limit=config.memory_context_limit
        )
```

After investigation completes, pass the already-created `mem_store` to the memory writer (replacing the Task 5 pattern):

```python
    if config.enable_memory and mem_store is not None:
        _write_investigation_memory(
            run=run, alert=alert, storage=storage,
            memory_store=mem_store, console=console,
        )
```

Pass to `Commander(...)`:

```python
commander = Commander(
    ...,
    correlation_service=correlation_service,
    memory_context_limit=config.memory_context_limit,
)
```

- [ ] **Step 5: Run full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add agents/commander.py core/app.py tests/test_agents.py
git commit -m "feat(gate4): inject prior-investigation context into Commander LLM planning call"
```

---

## Task 7: Replay mechanism

**Files:**
- Create: `core/replay.py`
- Create: `tests/test_replay.py`

Replay re-runs a past investigation using the same alert (from `IncidentMemory.alert_json`) and the same planner-generated plan. The original plan is reconstructed from the `IncidentMemory` data; the event log is used for audit only.

- [ ] **Step 1: Write failing tests**

Create `tests/test_replay.py`:

```python
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from core.replay import replay_investigation
from core.memory_store import MemoryStore
from core.schemas import IncidentMemory
import json


@pytest.mark.asyncio
async def test_replay_returns_investigation_run(tmp_path):
    from core.models import Alert, AlertType, Severity
    alert = Alert(
        id="replay-id",
        type=AlertType.BRUTE_FORCE,
        severity=Severity.MEDIUM,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="10.0.0.1",
        hostname="bastion-01",
    )
    mem = IncidentMemory(
        memory_id="m1",
        incident_id="replay-id",
        run_id="r1",
        alert_type="brute_force",
        alert_json=json.dumps({
            "id": alert.id, "type": alert.type.value,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "source_ip": alert.source_ip, "dest_ip": None,
            "hostname": alert.hostname, "user_account": None,
            "process": None, "tags": [], "raw_payload": {},
        }),
        entities={"ips": ["10.0.0.1"], "hosts": ["bastion-01"]},
        actions_taken=[],
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    store.write_memory(mem)

    from core.config import Config
    config = Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
        memory_db_path=str(tmp_path / "mem.db"),
        enable_memory=False,  # Don't write memory again during replay
    )
    from rich.console import Console
    result = await replay_investigation(
        run_id="r1",
        memory_store=store,
        config=config,
        console=Console(quiet=True),
        dry_run=True,
    )
    from core.schemas import InvestigationRun
    assert isinstance(result, InvestigationRun)
    assert result.alert_id == "replay-id"


@pytest.mark.asyncio
async def test_replay_raises_if_run_not_found(tmp_path):
    import dataclasses
    from core.config import Config
    store = MemoryStore(db_path=str(tmp_path / "mem.db"))
    # Build Config using dataclasses.replace on a minimal instance so the test
    # remains valid if Config gains new required fields.
    config = Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
        memory_db_path=str(tmp_path / "mem.db"),  # explicit path; avoids writing to ./
        enable_memory=False,
    )
    with pytest.raises(ValueError, match="not found"):
        await replay_investigation(
            run_id="nonexistent-run",
            memory_store=store,
            config=config,
            dry_run=True,
        )
```

- [ ] **Step 2: Run to confirm failure**

```bash
pytest tests/test_replay.py -v
```

Expected: `ModuleNotFoundError: No module named 'core.replay'`

- [ ] **Step 3: Create `core/replay.py`**

```python
"""Replay a past investigation from stored IncidentMemory."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rich.console import Console
    from core.config import Config
    from core.memory_store import MemoryStore
    from core.schemas import InvestigationRun


def _reconstruct_alert(alert_json: str):
    """Deserialize a stored alert JSON back to an Alert dataclass."""
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
        hostname=data.get("hostname"),
        user_account=data.get("user_account"),
        process=data.get("process"),
        tags=data.get("tags", []),
    )


async def replay_investigation(
    run_id: str,
    memory_store: "MemoryStore",
    config: "Config",
    *,
    dry_run: bool = True,
    console: "Console | None" = None,
) -> "InvestigationRun":
    """Re-run a past investigation identified by its run_id.

    Fetches the original alert from IncidentMemory, then calls run_investigation()
    with the same alert. The replay always writes a new InvestigationRun row.

    Raises ValueError if the run_id is not found in memory.
    """
    from core.app import run_investigation

    mem = memory_store.get_memory_by_run_id(run_id)
    if mem is None:
        raise ValueError(
            f"run_id {run_id!r} not found in memory store. "
            "Cannot replay an investigation that was never recorded."
        )

    alert = _reconstruct_alert(mem.alert_json)
    return await run_investigation(
        config=config,
        alert=alert,
        dry_run=dry_run,
        console=console,
    )
```

- [ ] **Step 4: Run tests**

```bash
pytest tests/test_replay.py -v
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add core/replay.py tests/test_replay.py
git commit -m "feat(gate4): add replay_investigation from stored IncidentMemory"
```

---

## Task 8: Analyst feedback CLI and `soc recall`

**Files:**
- Modify: `main.py`
- Modify: `tests/test_dry_run_smoke.py` (add `soc recall` marker)

Add two CLI subcommands:
- `python main.py recall --entity ip:10.0.0.1` — shows prior incidents involving that entity
- `python main.py feedback --incident <id> --outcome contained --notes "..."` — records analyst verdict
- `python main.py replay --run-id <run_id>` — replays a past investigation

- [ ] **Step 1: Update `main.py` to accept subcommands**

Replace the existing `mode` group in `main()` with a broader structure that supports both the existing `--alert`/`--watch` modes and new subcommands. The cleanest approach is using `argparse` subparsers.

```python
def main():
    parser = argparse.ArgumentParser(
        description="SOC Agent — autonomous multi-agent security incident investigation"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── investigate (default: --alert / --watch) ────────────────────────────
    investigate_parser = subparsers.add_parser("investigate", help="Run an investigation")
    mode = investigate_parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--alert", help="'simulated' or path to a JSON alert file")
    mode.add_argument("--watch", nargs="?", const="alerts/incoming", metavar="DIR")
    investigate_parser.add_argument("--auto-remediate", action="store_true", default=False)
    investigate_parser.add_argument("--timeout", type=int, default=None)
    investigate_parser.add_argument("--debug", action="store_true", default=False)
    investigate_parser.add_argument("--dry-run", action="store_true", default=False)

    # ── recall ───────────────────────────────────────────────────────────────
    recall_parser = subparsers.add_parser("recall", help="Query memory for prior incidents")
    recall_parser.add_argument(
        "--entity", required=True,
        help="Entity in format type:value, e.g. ip:10.0.0.1 or host:web-01"
    )
    recall_parser.add_argument("--limit", type=int, default=5)

    # ── feedback ─────────────────────────────────────────────────────────────
    feedback_parser = subparsers.add_parser("feedback", help="Record analyst verdict")
    feedback_parser.add_argument("--incident", required=True, help="Alert ID")
    feedback_parser.add_argument(
        "--outcome", required=True,
        choices=["contained", "inconclusive", "false_positive", "escalated"],
    )
    feedback_parser.add_argument("--notes", default="", help="Analyst notes")

    # ── replay ───────────────────────────────────────────────────────────────
    replay_parser = subparsers.add_parser("replay", help="Replay a past investigation")
    replay_parser.add_argument("--run-id", required=True)
    replay_parser.add_argument("--dry-run", action="store_true", default=False)

    # Backwards compat: bare --alert/--watch without 'investigate' subcommand
    parser.add_argument("--alert", help=argparse.SUPPRESS)
    parser.add_argument("--watch", nargs="?", const="alerts/incoming",
                        metavar="DIR", help=argparse.SUPPRESS)
    parser.add_argument("--auto-remediate", action="store_true", default=False)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--debug", action="store_true", default=False)
    # NOTE: --dry-run is defined on both the root parser and investigate_parser.
    # argparse merges subparser args into the same namespace, so
    # `getattr(args, "dry_run", False)` works for both `python main.py --dry-run`
    # and `python main.py investigate --dry-run`. This is safe but only because
    # the flag has the same dest ("dry_run") and default (False) in both parsers.
    # Do not rename or add action= changes to one without updating the other.
    parser.add_argument("--dry-run", action="store_true", default=False)

    args = parser.parse_args()

    from core.config import Config
    dry_run = getattr(args, "dry_run", False)
    if dry_run:
        config = Config.for_dry_run()
    else:
        try:
            config = Config.from_env()
        except ValueError as e:
            print(f"Configuration error: {e}", file=sys.stderr)
            sys.exit(1)

    if getattr(args, "auto_remediate", False):
        config = replace(config, auto_remediate=True)

    command = args.command

    # Dispatch
    if command == "recall":
        _cmd_recall(args, config)
    elif command == "feedback":
        _cmd_feedback(args, config)
    elif command == "replay":
        asyncio.run(_cmd_replay(args, config))
    elif command == "investigate" or command is None:
        # 'investigate' subcommand or bare legacy flags
        alert_source = getattr(args, "alert", None)
        watch_dir = getattr(args, "watch", None)
        if alert_source:
            asyncio.run(_run_once(alert_source, config, args))
        elif watch_dir:
            try:
                asyncio.run(_run_watch(watch_dir, config, args))
            except (KeyboardInterrupt, asyncio.CancelledError):
                pass
        else:
            parser.print_help()
    else:
        parser.print_help()
```

Add the three command handlers:

```python
def _cmd_recall(args, config) -> None:
    from rich.console import Console
    from rich.table import Table
    from core.memory_store import MemoryStore
    from core.correlation import CorrelationService

    console = Console()
    entity_str = args.entity
    if ":" not in entity_str:
        console.print("[red]--entity must be in format type:value (e.g. ip:10.0.0.1)[/red]")
        return
    entity_type, entity_value = entity_str.split(":", 1)
    store = MemoryStore(db_path=config.memory_db_path)
    results = store.get_memories_by_entity(entity_type, entity_value, limit=args.limit)
    baseline = store.get_baseline(entity_type, entity_value)

    if baseline:
        console.print(
            f"[bold]Baseline:[/bold] {entity_type} '{entity_value}' — "
            f"{baseline.baseline_type}, seen in {baseline.incident_count} incident(s)"
        )

    if not results:
        console.print(f"[dim]No prior incidents found for {entity_str}[/dim]")
        return

    table = Table(title=f"Prior incidents for {entity_str}")
    table.add_column("Incident ID", style="cyan")
    table.add_column("Type")
    table.add_column("Date")
    table.add_column("Outcome")
    table.add_column("Actions")
    for mem in results:
        table.add_row(
            mem.incident_id[:12],
            mem.alert_type,
            mem.started_at[:10],
            mem.outcome or "—",
            str(len(mem.actions_taken)),
        )
    console.print(table)


def _cmd_feedback(args, config) -> None:
    from rich.console import Console
    from core.memory_store import MemoryStore
    console = Console()
    store = MemoryStore(db_path=config.memory_db_path)
    store.record_feedback(args.incident, outcome=args.outcome, notes=args.notes)
    console.print(
        f"[green]✓[/green] Feedback recorded for incident [bold]{args.incident}[/bold]: "
        f"outcome=[bold]{args.outcome}[/bold]"
    )


async def _cmd_replay(args, config) -> None:
    from rich.console import Console
    from core.memory_store import MemoryStore
    from core.replay import replay_investigation
    console = Console()
    store = MemoryStore(db_path=config.memory_db_path)
    dry_run = getattr(args, "dry_run", False)
    try:
        run = await replay_investigation(
            run_id=args.run_id,
            memory_store=store,
            config=config,
            dry_run=dry_run,
            console=console,
        )
        console.print(
            f"[green]✓[/green] Replay complete. New run_id: [bold]{run.run_id}[/bold]"
        )
    except ValueError as e:
        console.print(f"[red]Replay failed:[/red] {e}")
```

- [ ] **Step 2: Run the full suite**

```bash
pytest tests/ -v --ignore=tests/test_integration.py -m "not slow"
```

Expected: all tests pass.

- [ ] **Step 3: Smoke test the new subcommands**

```bash
# recall with no data — should say "No prior incidents found"
python main.py recall --entity ip:10.0.0.1

# feedback requires a valid incident_id — use a fake one, should succeed silently
python main.py feedback --incident fake-id --outcome false_positive --notes "test"
```

Expected: no Python exceptions; console output as described.

- [ ] **Step 4: Commit**

```bash
git add main.py
git commit -m "feat(gate4): add recall, feedback, replay CLI subcommands"
```

---

## Gate 4 Complete — Verification Checklist

- [ ] `pytest tests/ --ignore=tests/test_integration.py -m "not slow"` — all pass
- [ ] `python main.py --alert simulated --dry-run` completes and writes to `./soc_memory.db`
- [ ] `python main.py recall --entity ip:185.220.101.45` shows prior incidents after one dry-run
- [ ] `python main.py feedback --incident <id> --outcome contained` updates the record
- [ ] `python main.py replay --run-id <run_id> --dry-run` completes with a new run_id

---

## Next: Gate 5

Write `docs/superpowers/plans/2026-03-27-gate-5-approval-queue.md` covering the interactive approval queue, terminal approval UI, `soc approve` and `soc rollback` CLI subcommands, idempotency enforcement, and blast-radius display.
