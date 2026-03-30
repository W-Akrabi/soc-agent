from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.app import run_investigation
from core.config import Config
from core.execution_policy import ExecutionPolicy
from core import metrics
from core.models import Alert, AlertType, Severity
from core.schemas import InvestigationRun


def _make_alert() -> Alert:
    return Alert(
        id="test-app-id",
        type=AlertType.BRUTE_FORCE,
        severity=Severity.MEDIUM,
        timestamp=datetime.now(timezone.utc),
        raw_payload={},
        source_ip="10.1.2.3",
        hostname="bastion-01",
    )


def _make_config(tmp_path) -> Config:
    return Config(
        anthropic_api_key="",
        model="mock",
        db_path=str(tmp_path / "test.db"),
        reports_dir=str(tmp_path / "reports"),
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="WARNING",
        provider="anthropic",
        openai_api_key="",
        openai_base_url=None,
        ollama_base_url="http://127.0.0.1:11434",
        storage_backend="sqlite",
        postgres_dsn=None,
        postgres_schema="public",
        vector_dimensions=1536,
        controlplane_backend="sqlite",
        controlplane_postgres_dsn=None,
        controlplane_postgres_schema="soc_control",
    )


@pytest.mark.asyncio
async def test_run_investigation_returns_investigation_run(tmp_path):
    config = _make_config(tmp_path)
    alert = _make_alert()

    result = await run_investigation(config=config, alert=alert, dry_run=True)

    assert isinstance(result, InvestigationRun)
    assert result.alert_id == alert.id
    assert result.dry_run is True


@pytest.mark.asyncio
async def test_run_investigation_creates_report_file(tmp_path):
    config = _make_config(tmp_path)
    alert = _make_alert()

    await run_investigation(config=config, alert=alert, dry_run=True)

    reports = list(Path(config.reports_dir).glob("*.md"))
    assert len(reports) >= 1


@pytest.mark.asyncio
async def test_run_investigation_creates_event_log(tmp_path):
    config = _make_config(tmp_path)
    alert = _make_alert()

    result = await run_investigation(
        config=config,
        alert=alert,
        dry_run=True,
        event_log_dir=str(tmp_path / "logs"),
    )

    logs = list((tmp_path / "logs").glob("*.jsonl"))
    assert len(logs) == 1

    from core.event_log import EventLog

    log = EventLog(run_id=result.run_id, log_dir=str(tmp_path / "logs"))
    entries = log.read_all()
    assert len(entries) > 0
    event_types = {entry["event_type"] for entry in entries}
    assert "agent_state" in event_types


@pytest.mark.asyncio
async def test_run_investigation_uses_provider_and_storage_factories_when_not_dry_run(tmp_path):
    config = _make_config(tmp_path)
    config.provider = "openai"
    config.storage_backend = "postgres"
    config.postgres_dsn = "postgresql://user:pass@localhost:5432/soc"
    config.enabled_integrations = ("defender", "entra", "threat_intel")
    config.allow_integration_execution = True
    config.allowed_actions = ("isolate_host",)
    alert = _make_alert()

    fake_provider = MagicMock()
    fake_provider.attach_event_log = MagicMock()
    fake_storage = MagicMock()
    fake_storage.db_path = "postgresql://test"
    fake_registry = MagicMock()
    fake_policy = ExecutionPolicy(enabled=True, allowed_actions=("isolate_host",))

    with patch("core.app.build_provider", return_value=fake_provider) as build_provider_mock, \
         patch("core.app.build_storage", return_value=fake_storage) as build_storage_mock, \
         patch("core.app.build_integration_registry", return_value=fake_registry) as build_registry_mock, \
         patch("core.app.ExecutionPolicy.from_config", return_value=fake_policy) as policy_mock, \
         patch("core.app.Commander") as commander_cls:
        commander = MagicMock()
        commander.investigate = AsyncMock()
        commander_cls.return_value = commander

        result = await run_investigation(config=config, alert=alert, dry_run=False)

    assert isinstance(result, InvestigationRun)
    build_provider_mock.assert_called_once_with(config)
    build_storage_mock.assert_called_once()
    build_registry_mock.assert_called_once()
    policy_mock.assert_called_once_with(config)
    assert commander_cls.call_args.kwargs["integration_registry"] is fake_registry
    assert commander_cls.call_args.kwargs["execution_policy"] is fake_policy
    assert result.db_path == "postgresql://test"


@pytest.mark.asyncio
async def test_run_investigation_dry_run_skips_live_integration_registry(tmp_path):
    config = _make_config(tmp_path)
    config.enabled_integrations = ("defender", "entra", "threat_intel", "sentinel")
    alert = _make_alert()

    fake_provider = MagicMock()
    fake_provider.attach_event_log = MagicMock()
    fake_storage = MagicMock()
    fake_storage.db_path = "sqlite://dry-run"

    with patch("core.app.build_provider", return_value=fake_provider), \
         patch("core.app.build_storage", return_value=fake_storage), \
         patch("core.app.build_integration_registry") as build_registry_mock, \
         patch("core.app.Commander") as commander_cls:
        commander = MagicMock()
        commander.investigate = AsyncMock()
        commander_cls.return_value = commander

        result = await run_investigation(config=config, alert=alert, dry_run=True)

    assert isinstance(result, InvestigationRun)
    build_registry_mock.assert_not_called()
    assert commander_cls.call_args.kwargs["integration_registry"].names() == ()
    assert commander_cls.call_args.kwargs["execution_policy"].enabled is False


@pytest.mark.asyncio
async def test_run_investigation_uses_postgres_controlplane_backends(tmp_path):
    config = _make_config(tmp_path)
    config.controlplane_backend = "postgres"
    config.controlplane_postgres_dsn = "postgresql://user:pass@localhost:5432/soc_control"
    config.controlplane_postgres_schema = "soc_control"
    config.enable_memory = True
    config.enable_approval_queue = True
    config.worker_mode = "remote"
    alert = _make_alert()

    fake_storage = MagicMock()
    fake_storage.db_path = "sqlite:///case.db"

    with patch("core.app.build_storage", return_value=fake_storage), \
         patch("core.app.MemoryStore") as memory_cls, \
         patch("core.app.ApprovalQueue") as approval_cls, \
         patch("core.app.WorkerQueue") as worker_cls, \
         patch("core.app.Commander") as commander_cls:
        commander = MagicMock()
        commander.investigate = AsyncMock()
        commander_cls.return_value = commander
        memory_cls.return_value = MagicMock()
        approval_cls.return_value = MagicMock()
        worker_cls.return_value = MagicMock()

        await run_investigation(config=config, alert=alert, dry_run=True)

    memory_cls.assert_called_once_with(
        config.memory_db_path,
        backend="postgres",
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    approval_cls.assert_called_once_with(
        config.approval_db_path,
        backend="postgres",
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    worker_cls.assert_called_once_with(
        config.worker_db_path,
        backend="postgres",
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )


@pytest.mark.asyncio
async def test_run_investigation_records_success_metrics(tmp_path):
    metrics.reset_registry()
    config = _make_config(tmp_path)
    alert = _make_alert()

    await run_investigation(config=config, alert=alert, dry_run=True)

    assert metrics.get_counter_value(
        "soc_investigations_started_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_investigations_completed_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_investigations_failed_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 0
    assert metrics.get_gauge_value(
        "soc_investigations_duration_seconds_last",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) > 0


@pytest.mark.asyncio
async def test_run_investigation_records_failure_metrics(tmp_path):
    metrics.reset_registry()
    config = _make_config(tmp_path)
    alert = _make_alert()

    fake_storage = MagicMock()
    fake_storage.db_path = "sqlite://dry-run"

    with patch("core.app.build_storage", return_value=fake_storage), \
         patch("core.app.Commander") as commander_cls:
        commander = MagicMock()
        commander.investigate = AsyncMock(side_effect=RuntimeError("boom"))
        commander_cls.return_value = commander

        with pytest.raises(RuntimeError, match="boom"):
            await run_investigation(config=config, alert=alert, dry_run=True)

    assert metrics.get_counter_value(
        "soc_investigations_started_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 1
    assert metrics.get_counter_value(
        "soc_investigations_completed_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 0
    assert metrics.get_counter_value(
        "soc_investigations_failed_total",
        {"alert_type": alert.type.value, "dry_run": "true"},
    ) == 1
