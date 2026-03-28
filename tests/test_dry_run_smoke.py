import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


@pytest.mark.slow
def test_dry_run_honors_soc_db_path_and_outputs(tmp_path):
    db_dir = tmp_path / "db"
    reports_dir = tmp_path / "reports"
    logs_dir = tmp_path / "logs"
    db_dir.mkdir()
    reports_dir.mkdir()
    logs_dir.mkdir()

    env = {
        **os.environ,
        "SOC_DB_PATH": str(db_dir / "mytest.db"),
        "SOC_REPORTS_DIR": str(reports_dir),
        "SOC_EVENT_LOG_DIR": str(logs_dir),
        "SOC_ENABLED_INTEGRATIONS": "defender,entra,threat_intel,sentinel",
        "ANTHROPIC_API_KEY": "",
        "SOC_AGENT_TIMEOUT": "5",
        "SOC_COMMANDER_TIMEOUT": "45",
    }

    repo_root = Path(__file__).parent.parent
    result = subprocess.run(
        [sys.executable, "main.py", "--alert", "simulated", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo_root,
        timeout=90,
    )

    assert result.returncode == 0, (
        f"dry-run exited non-zero.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    assert list(db_dir.glob("*.db")), f"No DB files found under {db_dir}"
    assert list(reports_dir.glob("*.md")), f"No report files found under {reports_dir}"
    assert list(logs_dir.glob("*.jsonl")), f"No event log files found under {logs_dir}"


@pytest.mark.slow
def test_dry_run_does_not_write_new_db_to_repo_root(tmp_path):
    db_dir = tmp_path / "db"
    reports_dir = tmp_path / "reports"
    logs_dir = tmp_path / "logs"
    db_dir.mkdir()
    reports_dir.mkdir()
    logs_dir.mkdir()

    repo_root = Path(__file__).parent.parent
    db_files_before = set(repo_root.glob("*.db"))

    env = {
        **os.environ,
        "SOC_DB_PATH": str(db_dir / "mytest.db"),
        "SOC_REPORTS_DIR": str(reports_dir),
        "SOC_EVENT_LOG_DIR": str(logs_dir),
        "SOC_ENABLED_INTEGRATIONS": "defender,entra,threat_intel,sentinel",
        "ANTHROPIC_API_KEY": "",
        "SOC_AGENT_TIMEOUT": "5",
        "SOC_COMMANDER_TIMEOUT": "45",
    }

    result = subprocess.run(
        [sys.executable, "main.py", "--alert", "simulated", "--dry-run"],
        capture_output=True,
        text=True,
        env=env,
        cwd=repo_root,
        timeout=90,
    )

    assert result.returncode == 0, (
        f"dry-run exited non-zero.\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )

    db_files_after = set(repo_root.glob("*.db"))
    new_db_files = db_files_after - db_files_before
    assert len(new_db_files) == 0, f"Unexpected DB files written to repo root: {new_db_files}"
