from datetime import datetime, timezone
import uuid

import pytest
from rich.console import Console

from agents.commander import Commander
from core.event_log import EventLog
from core.mock_llm import MockLLMClient
from core.models import Alert, AlertType, Severity
from core.storage_sqlite import SQLiteStorageBackend


@pytest.fixture
def tmp_db(tmp_path):
    return SQLiteStorageBackend(str(tmp_path / "dispatch.db"))


def _make_alert(alert_type: AlertType, severity: Severity, **overrides) -> Alert:
    values = {
        "id": str(uuid.uuid4()),
        "type": alert_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc),
        "source_ip": "185.220.101.45",
        "dest_ip": "10.0.1.50",
        "dest_port": 8080,
        "hostname": "web-prod-01",
        "user_account": "www-data",
        "raw_payload": {},
    }
    values.update(overrides)
    return Alert(**values)


@pytest.mark.asyncio
async def test_dry_run_produces_dispatch_task_node(tmp_db, tmp_path):
    alert = _make_alert(AlertType.INTRUSION, Severity.HIGH)
    llm = MockLLMClient()
    llm.set_alert_context(alert)
    event_log = EventLog(run_id="dispatch-intrusion", log_dir=str(tmp_path))
    llm.attach_event_log(event_log)

    commander = Commander(
        case_graph=tmp_db,
        llm=llm,
        console=Console(quiet=True),
        agent_timeout=30,
        commander_timeout=120,
        event_log=event_log,
        reports_dir=str(tmp_path),
    )

    await commander.investigate(alert)

    all_tasks = tmp_db.get_nodes_by_type("task")
    dispatch_tasks = [node for node in all_tasks if node.get("label", "").startswith("dispatch:")]
    assert dispatch_tasks


@pytest.mark.asyncio
async def test_dry_run_brute_force_no_dispatch(tmp_db, tmp_path):
    alert = _make_alert(
        AlertType.BRUTE_FORCE,
        Severity.MEDIUM,
        source_ip="203.0.113.99",
        dest_ip="10.0.0.10",
        dest_port=22,
        hostname="bastion-01",
        user_account="admin",
    )
    llm = MockLLMClient()
    llm.set_alert_context(alert)
    event_log = EventLog(run_id="dispatch-bruteforce", log_dir=str(tmp_path))
    llm.attach_event_log(event_log)

    commander = Commander(
        case_graph=tmp_db,
        llm=llm,
        console=Console(quiet=True),
        agent_timeout=30,
        commander_timeout=120,
        event_log=event_log,
        reports_dir=str(tmp_path),
    )

    await commander.investigate(alert)

    all_tasks = tmp_db.get_nodes_by_type("task")
    dispatch_tasks = [node for node in all_tasks if node.get("label", "").startswith("dispatch:")]
    assert dispatch_tasks == []
