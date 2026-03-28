import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from rich.console import Console

from agents.commander import Commander
from core.config import Config
from core.correlation import CorrelationService
from core.entity_extractor import extract_entities_from_graph
from core.execution_policy import ExecutionPolicy
from core.event_log import EventLog
from core.memory_store import MemoryStore
from core.models import Alert
from core.metrics import (
    record_investigation_completed,
    record_investigation_failed,
    record_investigation_started,
)
from core.planner import Planner
from core.providers import build_provider
from core.scheduler import Scheduler
from core.schemas import IncidentMemory, InvestigationRun
from core.storage import build_storage
from core.worker_queue import WorkerQueue
from core.approval_queue import ApprovalQueue
from integrations.defender import DefenderAdapter
from integrations.entra import EntraAdapter
from integrations.registry import IntegrationRegistry, build_integration_registry
from integrations.sentinel import SentinelAdapter
from integrations.threat_intel import ThreatIntelAdapter


def _build_integration_factories():
    return {
        "sentinel": lambda _config: SentinelAdapter(),
        "threat_intel": lambda _config: ThreatIntelAdapter(),
        "defender": lambda _config: DefenderAdapter(),
        "entra": lambda _config: EntraAdapter(),
    }


def compose_integration_registry(config: Config, *, dry_run: bool) -> IntegrationRegistry:
    if dry_run:
        return IntegrationRegistry()
    return build_integration_registry(config, factories=_build_integration_factories())


_compose_integration_registry = compose_integration_registry


async def run_investigation(
    config: Config,
    alert: Alert,
    dry_run: bool = False,
    event_log_dir: str | None = None,
    commander_timeout_override: int | None = None,
    console: Console | None = None,
) -> InvestigationRun:
    """Run a single investigation and return the run metadata."""
    if console is None:
        console = Console()

    if dry_run:
        from core.mock_llm import MockLLMClient

        llm = MockLLMClient()
        llm.set_alert_context(alert)
    else:
        llm = build_provider(config)

    run_id = str(uuid.uuid4())
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    suffix = "_dry" if dry_run else ""
    db_path = config.db_path.replace(".db", "") + suffix + f"-{ts}-{alert.id[:8]}.db"

    reports_dir = Path(config.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    before_reports = {path.resolve() for path in reports_dir.glob("*.md")}

    active_event_log_dir = event_log_dir if event_log_dir is not None else config.event_log_dir
    event_log = EventLog(run_id=run_id, log_dir=active_event_log_dir)
    llm.attach_event_log(event_log)
    execution_policy = ExecutionPolicy.from_config(config)
    integration_registry = compose_integration_registry(config, dry_run=dry_run)
    memory_store = (
        MemoryStore(
            config.memory_db_path,
            backend=config.controlplane_backend,
            postgres_dsn=config.controlplane_postgres_dsn,
            postgres_schema=config.controlplane_postgres_schema,
        )
        if config.enable_memory
        else None
    )
    correlation_service = (
        CorrelationService(memory_store=memory_store, limit=config.memory_context_limit)
        if memory_store is not None
        else None
    )
    approval_queue = (
        ApprovalQueue(
            config.approval_db_path,
            backend=config.controlplane_backend,
            postgres_dsn=config.controlplane_postgres_dsn,
            postgres_schema=config.controlplane_postgres_schema,
        )
        if config.enable_approval_queue
        else None
    )
    worker_queue = (
        WorkerQueue(
            config.worker_db_path,
            backend=config.controlplane_backend,
            postgres_dsn=config.controlplane_postgres_dsn,
            postgres_schema=config.controlplane_postgres_schema,
        )
        if config.worker_mode == "remote"
        else None
    )

    if config.storage_backend == "sqlite":
        storage = build_storage(
            backend="sqlite",
            db_path=db_path,
        )
        resolved_db_path = db_path
    else:
        storage = build_storage(
            backend=config.storage_backend,
            db_path=db_path,
            postgres_dsn=config.postgres_dsn,
            postgres_schema=config.postgres_schema,
            vector_dimensions=config.vector_dimensions,
        )
        resolved_db_path = getattr(storage, "db_path", config.postgres_dsn or db_path)

    commander = Commander(
        case_graph=storage,
        llm=llm,
        console=console,
        agent_timeout=config.agent_timeout,
        commander_timeout=commander_timeout_override or config.commander_timeout,
        auto_remediate=config.auto_remediate,
        reports_dir=config.reports_dir,
        event_log=event_log,
        planner=Planner(),
        scheduler=Scheduler(default_timeout=float(config.agent_timeout)),
        integration_registry=integration_registry,
        execution_policy=execution_policy,
        run_id=run_id,
        correlation_service=correlation_service,
        memory_context_limit=config.memory_context_limit,
        approval_queue=approval_queue,
        worker_queue=worker_queue,
        worker_poll_interval=config.worker_poll_interval,
    )

    started_at = datetime.now(timezone.utc)
    run = InvestigationRun(
        run_id=run_id,
        alert_id=alert.id,
        started_at=started_at,
        db_path=resolved_db_path,
        reports_dir=config.reports_dir,
        dry_run=dry_run,
    )

    record_investigation_started(alert_type=alert.type.value, dry_run=dry_run)
    run_started = perf_counter()
    try:
        await commander.investigate(alert)

        run.completed_at = datetime.now(timezone.utc)
        if memory_store is not None:
            entities = extract_entities_from_graph(storage)
            actions_taken = [
                {
                    "action_type": node["data"].get("action_type"),
                    "target": node["data"].get("target"),
                    "status": node.get("status"),
                    "urgency": node["data"].get("urgency"),
                }
                for node in storage.get_nodes_by_type("action")
            ]
            memory_store.write_memory(
                IncidentMemory(
                    memory_id=str(uuid.uuid4()),
                    incident_id=alert.id,
                    run_id=run_id,
                    alert_type=alert.type.value,
                    alert_json=_serialize_alert(alert),
                    entities=entities,
                    actions_taken=actions_taken,
                    started_at=started_at.isoformat(),
                    completed_at=run.completed_at.isoformat(),
                )
            )
    except Exception:
        record_investigation_failed(
            alert_type=alert.type.value,
            dry_run=dry_run,
            duration_seconds=perf_counter() - run_started,
        )
        raise
    else:
        record_investigation_completed(
            alert_type=alert.type.value,
            dry_run=dry_run,
            duration_seconds=perf_counter() - run_started,
        )
    after_reports = {path.resolve() for path in reports_dir.glob("*.md")}
    new_reports = sorted(after_reports - before_reports)
    if new_reports:
        run.report_path = str(new_reports[-1])
    return run


async def run_watch(
    config: Config,
    watch_dir: str,
    dry_run: bool = False,
    commander_timeout_override: int | None = None,
    console: Console | None = None,
) -> None:
    """Watch a directory and investigate alerts as they arrive."""
    if console is None:
        console = Console()

    from ingestion.adapters.folder_watcher import FolderWatcher
    from ui import WatchUI

    watcher = FolderWatcher(watch_dir)
    model_name = "mock" if dry_run else config.model
    watch_ui = WatchUI(console=console, model=model_name, watch_dir=watch_dir, dry_run=dry_run)

    watch_ui.show_banner()
    watch_ui.start_watching()

    try:
        async for alert, path in watcher.watch():
            watch_ui.alert_received(alert.type.value, alert.severity.value, path.name)
            try:
                await run_investigation(
                    config=config,
                    alert=alert,
                    dry_run=dry_run,
                    event_log_dir=config.event_log_dir,
                    commander_timeout_override=commander_timeout_override,
                    console=console,
                )
                watcher.mark_processed(path)
                watch_ui.investigation_done(alert.id)
            except (KeyboardInterrupt, asyncio.CancelledError):
                watcher.mark_failed(path)
                raise
            except Exception as e:
                console.print(f"[red]Investigation failed:[/red] {e}")
                watcher.mark_failed(path)
                watch_ui.investigation_done(alert.id)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        watch_ui.stop_watching()
        console.print("\n[dim]Watcher stopped.[/dim]")


def _serialize_alert(alert: Alert) -> str:
    return json.dumps(
        {
            "id": alert.id,
            "type": alert.type.value,
            "severity": alert.severity.value,
            "timestamp": alert.timestamp.isoformat(),
            "source_ip": alert.source_ip,
            "dest_ip": alert.dest_ip,
            "source_port": alert.source_port,
            "dest_port": alert.dest_port,
            "hostname": alert.hostname,
            "user_account": alert.user_account,
            "process": alert.process,
            "tags": list(alert.tags),
            "raw_payload": alert.raw_payload,
        }
    )
