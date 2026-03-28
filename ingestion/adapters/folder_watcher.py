import asyncio
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from ingestion.models import normalize_alert
from core.models import Alert


class FolderWatcher:
    """
    Watches a directory for new .json alert files.
    When a file appears it yields a normalized Alert.
    Processed files are moved to a 'processed/' subdirectory.
    Failed files are moved to a 'failed/' subdirectory.
    """

    def __init__(self, watch_dir: str, poll_interval: float = 2.0):
        self.watch_dir = Path(watch_dir)
        self.processed_dir = self.watch_dir / "processed"
        self.failed_dir = self.watch_dir / "failed"
        self.poll_interval = poll_interval
        self._seen: set[str] = set()

    def _setup(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        self.processed_dir.mkdir(exist_ok=True)
        self.failed_dir.mkdir(exist_ok=True)

    async def watch(self):
        """Async generator — yields Alert objects as files appear."""
        self._setup()
        while True:
            for path in sorted(self.watch_dir.glob("*.json")):
                if path.name in self._seen:
                    continue
                self._seen.add(path.name)
                alert = self._load(path)
                if alert:
                    yield alert, path
                else:
                    shutil.move(str(path), self.failed_dir / path.name)
            await asyncio.sleep(self.poll_interval)

    def mark_processed(self, path: Path) -> None:
        if not path.exists():
            return
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        dest = self.processed_dir / f"{ts}-{path.name}"
        shutil.move(str(path), dest)

    def mark_failed(self, path: Path) -> None:
        if not path.exists():
            return
        dest = self.failed_dir / path.name
        shutil.move(str(path), dest)

    def _load(self, path: Path) -> Alert | None:
        try:
            raw = json.loads(path.read_text())
            return normalize_alert(raw)
        except Exception:
            return None
