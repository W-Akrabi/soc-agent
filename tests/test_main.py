import subprocess
import sys
from pathlib import Path


def test_main_help_shows_subcommands():
    repo_root = Path(__file__).parent.parent
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=30,
    )

    assert result.returncode == 0
    assert "investigate" in result.stdout
    assert "worker" in result.stdout
    assert "Legacy entry points still work" in result.stdout


def test_main_without_args_shows_help():
    repo_root = Path(__file__).parent.parent
    result = subprocess.run(
        [sys.executable, "main.py"],
        capture_output=True,
        text=True,
        cwd=repo_root,
        timeout=30,
    )

    assert result.returncode == 0
    assert "usage: main.py" in result.stdout
    assert "investigate" in result.stdout
