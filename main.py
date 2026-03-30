#!/usr/bin/env python3
import argparse
import asyncio
import inspect
import sys
from datetime import datetime, timezone
from dataclasses import asdict, replace

from dotenv import load_dotenv

load_dotenv()

SUBCOMMANDS = {"investigate", "watch", "detect", "recall", "replay", "approve", "reject", "rollback", "worker", "api"}
HELP_FLAGS = {"-h", "--help"}
HELP_EPILOG = """Legacy entry points still work:
  python3 main.py --alert simulated --dry-run
  python3 main.py --watch alerts/incoming --dry-run
"""


class ApproverAuthorizationError(Exception):
    pass


def main(argv: list[str] | None = None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return _main_subcommands(["--help"])
    if argv[0] in HELP_FLAGS:
        return _main_subcommands(argv)
    if argv and argv[0] in SUBCOMMANDS:
        return _main_subcommands(argv)
    return _main_legacy(argv)


def _main_legacy(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        description="SOC Agent — autonomous multi-agent security incident investigation"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--alert", help="Run once: 'simulated', or path to a JSON alert file")
    mode.add_argument(
        "--watch",
        nargs="?",
        const="alerts/incoming",
        metavar="DIR",
        help="Watch a folder for incoming alert files (default: alerts/incoming/)",
    )

    parser.add_argument("--auto-remediate", action="store_true", default=False)
    parser.add_argument("--timeout", type=int, default=None)
    parser.add_argument("--debug", action="store_true", default=False)
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args(argv)

    config = _load_config_for_execution(args.dry_run)
    if args.auto_remediate:
        config = replace(config, auto_remediate=True)

    if args.alert:
        asyncio.run(_run_once(args.alert, config, args))
        return

    try:
        asyncio.run(_run_watch(args.watch, config, args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


def _main_subcommands(argv: list[str]) -> None:
    parser = argparse.ArgumentParser(
        description="SOC Agent — autonomous multi-agent security incident investigation",
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    investigate = subparsers.add_parser("investigate", help="Run a single investigation")
    investigate.add_argument("source", help="Alert source: 'simulated' or path to a JSON alert file")
    investigate.add_argument("--auto-remediate", action="store_true", default=False)
    investigate.add_argument("--timeout", type=int, default=None)
    investigate.add_argument("--dry-run", action="store_true", default=False)

    watch = subparsers.add_parser("watch", help="Watch a directory for incoming alerts")
    watch.add_argument("watch_dir", nargs="?", default="alerts/incoming")
    watch.add_argument("--timeout", type=int, default=None)
    watch.add_argument("--dry-run", action="store_true", default=False)

    detect = subparsers.add_parser("detect", help="Run built-in detectors against live telemetry")
    detect_subparsers = detect.add_subparsers(dest="detect_command", required=True)

    detect_ssh = detect_subparsers.add_parser(
        "ssh-bruteforce",
        help="Monitor SSH authentication logs and trigger investigations on repeated failures",
    )
    detect_ssh.add_argument("--log-file", default="/var/log/auth.log")
    detect_ssh.add_argument("--threshold", type=int, default=5)
    detect_ssh.add_argument("--window", type=int, default=300)
    detect_ssh.add_argument("--cooldown", type=int, default=900)
    detect_ssh.add_argument("--poll-interval", type=float, default=2.0)
    detect_ssh.add_argument("--hostname", default=None)
    detect_ssh.add_argument("--from-start", action="store_true", default=False)
    detect_ssh.add_argument("--once", action="store_true", default=False)
    detect_ssh.add_argument("--auto-remediate", action="store_true", default=False)
    detect_ssh.add_argument("--timeout", type=int, default=None)
    detect_ssh.add_argument("--dry-run", action="store_true", default=False)

    recall = subparsers.add_parser("recall", help="Recall prior incidents for an entity")
    recall.add_argument("entity", help="Entity value to search for")
    recall.add_argument("--limit", type=int, default=5)

    replay = subparsers.add_parser("replay", help="Replay a past investigation by run id")
    replay.add_argument("run_id")
    replay.add_argument("--dry-run", action="store_true", default=False)

    approve = subparsers.add_parser("approve", help="List or execute approval queue actions")
    approve_subparsers = approve.add_subparsers(dest="approve_command", required=True)
    approve_subparsers.add_parser("list", help="List pending approval actions")
    approve_action = approve_subparsers.add_parser("action", help="Approve and execute a queued action")
    approve_action.add_argument("action_id")
    approve_action.add_argument("--reviewed-by", default="cli")
    approve_action.add_argument("--approver-token", default=None)

    reject = subparsers.add_parser("reject", help="Reject a queued action")
    reject.add_argument("action_id")
    reject.add_argument("--reviewed-by", default="cli")
    reject.add_argument("--approver-token", default=None)

    rollback = subparsers.add_parser("rollback", help="Roll back a previously executed action")
    rollback.add_argument("action_id")
    rollback.add_argument("--reviewed-by", default="cli")
    rollback.add_argument("--approver-token", default=None)

    worker = subparsers.add_parser("worker", help="Run a remote worker process")
    worker_subparsers = worker.add_subparsers(dest="worker_command", required=True)
    worker_start = worker_subparsers.add_parser("start", help="Start the worker loop")
    worker_start.add_argument("--once", action="store_true", default=False)
    worker_start.add_argument("--worker-id", default=None)
    worker_start.add_argument("--dry-run", action="store_true", default=False)
    worker_start.add_argument("--heartbeat-interval", type=float, default=None)
    worker_start.add_argument("--lease-timeout", type=int, default=None)

    worker_inspect = worker_subparsers.add_parser("inspect", help="Inspect queued and claimed worker tasks")
    worker_inspect.add_argument("--limit", type=int, default=25)
    worker_inspect.add_argument("--lease-timeout", type=int, default=None)

    worker_reap = worker_subparsers.add_parser("reap", help="Requeue stale claimed/running worker tasks")
    worker_reap.add_argument("--lease-timeout", type=int, default=None)

    api = subparsers.add_parser("api", help="Run the API server")
    api_subparsers = api.add_subparsers(dest="api_command", required=True)
    api_serve = api_subparsers.add_parser("serve", help="Start the API server")
    api_serve.add_argument("--dry-run", action="store_true", default=False)

    args = parser.parse_args(argv)

    if args.command == "investigate":
        config = _load_config_for_execution(args.dry_run)
        if args.auto_remediate:
            config = replace(config, auto_remediate=True)
        asyncio.run(_run_once(args.source, config, args))
        return

    if args.command == "watch":
        config = _load_config_for_execution(args.dry_run)
        try:
            asyncio.run(_run_watch(args.watch_dir, config, args))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        return

    if args.command == "detect":
        config = _load_config_for_execution(args.dry_run)
        if args.auto_remediate:
            config = replace(config, auto_remediate=True)
        try:
            asyncio.run(_run_detect(config, args))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        return

    if args.command == "recall":
        _handle_recall(args)
        return

    if args.command == "replay":
        asyncio.run(_handle_replay(args))
        return

    if args.command == "approve":
        _handle_approve(args)
        return

    if args.command == "reject":
        _handle_reject(args)
        return

    if args.command == "rollback":
        _handle_rollback(args)
        return

    if args.command == "worker":
        if args.worker_command == "start":
            asyncio.run(_handle_worker(args))
            return
        if args.worker_command == "inspect":
            _handle_worker_inspect(args)
            return
        if args.worker_command == "reap":
            _handle_worker_reap(args)
            return
        return

    if args.command == "api":
        asyncio.run(_handle_api(args))
        return


def _load_config_for_execution(dry_run: bool):
    from core.config import Config

    if dry_run:
        return Config.for_dry_run()
    try:
        return Config.from_env()
    except ValueError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)


def _load_config_for_stateful_cli(*, require_live_execution: bool):
    from core.config import Config

    if require_live_execution:
        try:
            return Config.from_env()
        except ValueError as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            sys.exit(1)
    return Config.for_dry_run()


async def _run_once(source: str, config, args) -> None:
    from rich.console import Console
    from core.app import run_investigation
    from ingestion.loader import load_alert

    console = Console()
    try:
        alert = load_alert(source)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Error loading alert:[/red] {exc}")
        return
    await run_investigation(
        config=config,
        alert=alert,
        dry_run=args.dry_run,
        event_log_dir=config.event_log_dir,
        commander_timeout_override=args.timeout,
        console=console,
    )


async def _run_watch(watch_dir: str, config, args) -> None:
    from rich.console import Console
    from core.app import run_watch

    console = Console()
    await run_watch(
        config=config,
        watch_dir=watch_dir,
        dry_run=args.dry_run,
        commander_timeout_override=args.timeout,
        console=console,
    )


async def _run_detect(config, args) -> None:
    from rich.console import Console

    from core.app import run_investigation
    from ingestion.detectors.registry import build_detector

    console = Console()
    detector = build_detector(args)
    console.print(
        f"[green]Detector[/green] {detector.name} watching "
        f"{getattr(detector, 'log_path', 'configured source')}"
    )

    async for alert in detector.watch(run_once=getattr(args, "once", False)):
        console.rule(
            f"[bold]DETECTED[/bold]  │  {alert.type.value.upper()}  │  {alert.severity.value.upper()}  │  "
            f"{alert.source_ip or '-'}"
        )
        try:
            await run_investigation(
                config=config,
                alert=alert,
                dry_run=args.dry_run,
                event_log_dir=config.event_log_dir,
                commander_timeout_override=getattr(args, "timeout", None),
                console=console,
            )
        except Exception as exc:
            console.print(f"[red]Detector-triggered investigation failed:[/red] {exc}")


def _handle_recall(args) -> None:
    from rich.console import Console

    from core.config import Config
    from core.memory_store import MemoryStore

    console = Console()
    config = Config.for_dry_run()
    store = MemoryStore(
        config.memory_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    entity = args.entity
    entity_types = ("host", "user", "ip", "domain", "hash")
    seen_runs: set[str] = set()
    matches = []
    for entity_type in entity_types:
        for memory in store.list_memories_for_entity(entity_type, entity, limit=args.limit):
            if memory.run_id in seen_runs:
                continue
            seen_runs.add(memory.run_id)
            matches.append(memory)
    if not matches:
        console.print(f"[yellow]No prior incidents found for[/yellow] {entity}")
        return
    for memory in matches[: args.limit]:
        console.print(
            f"- run={memory.run_id} alert={memory.alert_type} started={memory.started_at} "
            f"outcome={memory.outcome or 'unknown'}"
        )


async def _handle_replay(args) -> None:
    from rich.console import Console

    from core.config import Config
    from core.memory_store import MemoryStore
    from core.replay import replay_investigation

    config = _load_config_for_execution(args.dry_run)
    memory_store = MemoryStore(
        config.memory_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    await replay_investigation(
        args.run_id,
        memory_store,
        config,
        dry_run=args.dry_run,
        console=Console(),
    )


def _handle_approve(args) -> None:
    from rich.console import Console

    from core.approval_queue import ApprovalQueue

    console = Console()
    config = _load_config_for_stateful_cli(require_live_execution=args.approve_command == "action")
    queue = ApprovalQueue(
        config.approval_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )

    if args.approve_command == "list":
        pending = queue.list_pending()
        if not pending:
            console.print("[yellow]No pending approval actions.[/yellow]")
            return
        for item in pending:
            console.print(
                f"- id={item['action_id']} action={item['action_type']} target={item['target']} "
                f"urgency={item['urgency']} blast_radius={item['blast_radius']}"
            )
        return

    try:
        _authorize_approver(config, args.reviewed_by, getattr(args, "approver_token", None))
    except ApproverAuthorizationError as exc:
        console.print(f"[red]Unauthorized[/red] {exc}")
        return

    item = queue.get(args.action_id)
    if item is None:
        console.print(f"[red]Approval action not found:[/red] {args.action_id}")
        return
    result, rollback_data = asyncio.run(_execute_pending_action(config, item))
    updated = queue.approve(
        item["action_id"],
        reviewed_by=args.reviewed_by,
        execution_result=result,
        rollback_data=rollback_data,
    )
    console.print(
        f"[green]Approved[/green] {updated['action_id']} -> {updated['status']} ({updated['action_type']} {updated['target']})"
    )


def _handle_reject(args) -> None:
    from rich.console import Console

    from core.approval_queue import ApprovalQueue

    console = Console()
    config = _load_config_for_stateful_cli(require_live_execution=False)
    queue = ApprovalQueue(
        config.approval_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    try:
        _authorize_approver(config, args.reviewed_by, getattr(args, "approver_token", None))
    except ApproverAuthorizationError as exc:
        console.print(f"[red]Unauthorized[/red] {exc}")
        return
    updated = queue.reject(args.action_id, reviewed_by=args.reviewed_by)
    console.print(f"[yellow]Rejected[/yellow] {updated['action_id']}")


def _handle_rollback(args) -> None:
    from rich.console import Console

    from core.approval_queue import ApprovalQueue

    console = Console()
    config = _load_config_for_stateful_cli(require_live_execution=True)
    queue = ApprovalQueue(
        config.approval_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    try:
        _authorize_approver(config, args.reviewed_by, getattr(args, "approver_token", None))
    except ApproverAuthorizationError as exc:
        console.print(f"[red]Unauthorized[/red] {exc}")
        return
    item = queue.get(args.action_id)
    if item is None:
        console.print(f"[red]Approval action not found:[/red] {args.action_id}")
        return
    if not item.get("rollback_supported") or not item.get("rollback_action_type"):
        console.print(f"[red]Rollback not supported for action:[/red] {args.action_id}")
        return
    result, rollback_data = asyncio.run(_execute_pending_action(config, item, rollback=True))
    updated = queue.rollback(
        item["action_id"],
        reviewed_by=args.reviewed_by,
        execution_result=result,
        rollback_data=rollback_data,
    )
    console.print(
        f"[green]Rollback complete[/green] {updated['action_id']} -> {updated['status']} "
        f"({updated['rollback_action_type']} {updated['target']})"
    )


async def _handle_worker(args) -> None:
    from rich.console import Console

    from agents.commander import Commander
    from core.app import compose_integration_registry
    from core.config import Config
    from core.execution_policy import ExecutionPolicy
    from core.providers import build_provider
    from core.worker import SOCWorker
    from core.worker_queue import WorkerQueue

    config = Config.for_dry_run() if args.dry_run else Config.from_env()
    heartbeat_interval = args.heartbeat_interval if args.heartbeat_interval is not None else config.worker_heartbeat_interval
    lease_timeout = args.lease_timeout if args.lease_timeout is not None else config.worker_lease_timeout
    config = replace(
        config,
        worker_poll_interval=float(heartbeat_interval),
        worker_heartbeat_interval=float(heartbeat_interval),
        worker_lease_timeout=int(lease_timeout),
    )
    queue = WorkerQueue(
        config.worker_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    console = Console()
    if args.dry_run:
        from core.mock_llm import MockLLMClient

        llm = MockLLMClient()
    else:
        llm = build_provider(config)
    integration_registry = compose_integration_registry(config, dry_run=args.dry_run)
    execution_policy = ExecutionPolicy.from_config(config)

    def agent_factory(task, alert, storage):
        if hasattr(llm, "set_alert_context"):
            llm.set_alert_context(alert)
        commander = Commander(
            case_graph=storage,
            llm=llm,
            console=console,
            agent_timeout=config.agent_timeout,
            commander_timeout=config.commander_timeout,
            auto_remediate=config.auto_remediate,
            reports_dir=config.reports_dir,
            event_log=None,
            integration_registry=integration_registry,
            execution_policy=execution_policy,
        )
        agents = commander._build_agents()
        return agents[task["agent_name"]]

    worker = SOCWorker(
        queue,
        worker_id=args.worker_id,
        agent_factory=agent_factory,
        console=console,
        poll_interval=config.worker_heartbeat_interval,
    )
    if args.once:
        await worker.run_once()
        return
    await worker.run_forever()


def _handle_worker_inspect(args) -> None:
    from rich.console import Console

    from core.config import Config
    from core.worker_queue import WorkerQueue

    console = Console()
    config = Config.for_dry_run()
    queue = WorkerQueue(
        config.worker_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    lease_timeout = args.lease_timeout if args.lease_timeout is not None else config.worker_lease_timeout
    tasks = queue.list_tasks(limit=args.limit)
    if not tasks:
        console.print("[yellow]No worker tasks found.[/yellow]")
        return
    stale = 0
    now = datetime.now(timezone.utc)
    for task in tasks:
        age = _task_age_seconds(task, now)
        is_stale = _task_is_stale(task, lease_timeout_seconds=lease_timeout, now=now)
        stale += 1 if is_stale else 0
        stale_flag = " stale" if is_stale else ""
        console.print(
            f"- id={task['task_id']} status={task['status']} agent={task['agent_name']} "
            f"worker={task.get('worker_id') or '-'} age={age:.0f}s{stale_flag}"
        )
    if stale:
        console.print(f"[yellow]{stale} task(s) are past the lease timeout.[/yellow]")


def _handle_worker_reap(args) -> None:
    from rich.console import Console

    from core.config import Config
    from core.worker_queue import WorkerQueue

    console = Console()
    config = Config.for_dry_run()
    queue = WorkerQueue(
        config.worker_db_path,
        backend=config.controlplane_backend,
        postgres_dsn=config.controlplane_postgres_dsn,
        postgres_schema=config.controlplane_postgres_schema,
    )
    lease_timeout = args.lease_timeout if args.lease_timeout is not None else config.worker_lease_timeout
    now = datetime.now(timezone.utc)
    requeued = 0
    for status in ("claimed", "running"):
        for task in queue.list_tasks(status=status):
            if not _task_is_stale(task, lease_timeout_seconds=lease_timeout, now=now):
                continue
            queue.update_task(
                task["task_id"],
                status="pending",
                worker_id=None,
                claimed_at=None,
                completed_at=None,
                result=None,
                error=f"requeued after lease timeout of {lease_timeout}s",
            )
            requeued += 1
            console.print(f"[yellow]Requeued[/yellow] {task['task_id']} (worker={task.get('worker_id') or '-'})")
    if not requeued:
        console.print("[green]No stale worker tasks found.[/green]")


def _task_age_seconds(task: dict, now: datetime | None = None) -> float:
    now = now or datetime.now(timezone.utc)
    reference = task.get("claimed_at") or task.get("created_at")
    if not reference:
        return 0.0
    try:
        started = datetime.fromisoformat(reference)
    except ValueError:
        return 0.0
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    return max(0.0, (now - started).total_seconds())


def _task_is_stale(task: dict, *, lease_timeout_seconds: int, now: datetime | None = None) -> bool:
    if lease_timeout_seconds <= 0:
        return False
    status = str(task.get("status") or "").lower()
    if status not in {"claimed", "running"}:
        return False
    return _task_age_seconds(task, now=now) >= float(lease_timeout_seconds)


def _authorize_approver(config, reviewed_by: str | None, approver_token: str | None = None) -> None:
    identity = _normalize_identity(reviewed_by)
    if not identity:
        raise ApproverAuthorizationError("reviewed_by is required")

    allowed_identities = {
        _normalize_identity(value)
        for value in getattr(config, "approver_identities", ())
        if _normalize_identity(value)
    }
    if allowed_identities and identity not in allowed_identities:
        raise ApproverAuthorizationError(
            f"reviewed_by {reviewed_by!r} is not in SOC_APPROVER_IDENTITIES"
        )

    expected_token = getattr(config, "api_approver_token", None)
    if expected_token:
        if not approver_token:
            raise ApproverAuthorizationError(
                "approval token required for approval-changing actions"
            )
        if approver_token != expected_token:
            raise ApproverAuthorizationError("invalid approval token")


def _normalize_identity(value: str | None) -> str:
    return (value or "").strip().lower()


async def _handle_api(args) -> None:
    from core.api_server import serve_api
    from core.config import Config

    config = Config.for_dry_run() if getattr(args, "dry_run", False) else Config.from_env()
    result = serve_api(config=config)
    if inspect.isawaitable(result):
        await result


async def _execute_pending_action(config, item: dict, *, rollback: bool = False):
    from core.app import compose_integration_registry
    from core.schemas import ActionExecutionRequest

    registry = compose_integration_registry(config, dry_run=False)
    action_type = item["rollback_action_type"] if rollback else item["action_type"]
    adapter = _adapter_for_action_type(action_type, registry)
    if adapter is None:
        raise RuntimeError(f"No adapter available for action_type {action_type!r}")

    metadata = dict(item.get("rollback_data") or {})
    execution_result = item.get("execution_result") or {}
    if isinstance(execution_result, dict):
        metadata.update(execution_result.get("metadata") or {})

    request = ActionExecutionRequest(
        action_type=action_type,
        target=item["target"],
        reason=("Rollback: " if rollback else "") + item["reason"],
        urgency=item["urgency"],
        requested_by="cli",
        allow_execution=True,
        metadata=metadata,
    )
    result = await adapter.execute(request)
    payload = asdict(result)
    merged_rollback_data = dict(metadata)
    merged_rollback_data.update(payload.get("metadata") or {})
    return payload, merged_rollback_data


def _adapter_for_action_type(action_type: str, registry):
    normalized = (action_type or "").strip().lower()
    if normalized in {"isolate_host", "unisolate_host"}:
        return registry.adapters.get("defender")
    if normalized in {"disable_account", "enable_account", "revoke_sessions"}:
        return registry.adapters.get("entra")
    return None


if __name__ == "__main__":
    main()
