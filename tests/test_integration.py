import os
import pytest
from pathlib import Path

pytestmark = pytest.mark.skipif(
    not (os.getenv("SOC_RUN_LIVE_TESTS") and os.getenv("ANTHROPIC_API_KEY")),
    reason="SOC_RUN_LIVE_TESTS and ANTHROPIC_API_KEY are required for live integration tests",
)


@pytest.mark.asyncio
async def test_full_intrusion_investigation(tmp_path):
    """End-to-end: load sample intrusion alert, run full pipeline, verify report produced."""
    from core.app import run_investigation
    from core.config import Config
    from ingestion.loader import load_alert
    from rich.console import Console

    config = Config.from_env()
    alert = load_alert("alerts/sample_intrusion.json")
    config.db_path = str(tmp_path / "test.db")
    config.reports_dir = str(tmp_path / "reports")
    console = Console(quiet=True)

    result = await run_investigation(
        config=config,
        alert=alert,
        dry_run=False,
        event_log_dir=str(tmp_path / "logs"),
        commander_timeout_override=180,
        console=console,
    )

    report_files = list(Path(config.reports_dir).glob("*.md"))
    assert len(report_files) == 1, "Expected exactly one report file"
    assert result.report_path == str(report_files[0])

    content = report_files[0].read_text()
    assert len(content) > 200, "Report should have meaningful content"
    assert "Incident Report" in content or "incident" in content.lower()

    from core.storage import build_storage

    graph = build_storage(backend="sqlite", db_path=result.db_path)
    nodes = graph.get_full_graph()["nodes"]
    node_types = {n["type"] for n in nodes}
    assert "alert" in node_types
    assert "task" in node_types
    assert "ip" in node_types

    task_nodes = graph.get_nodes_by_type("task")
    for task in task_nodes:
        assert task["status"] in ("completed", "failed"), \
            f"Task {task['label']} left in status {task['status']}"
