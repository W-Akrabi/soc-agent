import json
from datetime import datetime, timezone
from pathlib import Path


class EventLog:
    """Append-only JSONL event log for a single investigation run."""

    def __init__(self, run_id: str, log_dir: str | None):
        self.run_id = run_id
        self._path: Path | None = None
        if log_dir is not None:
            self._path = Path(log_dir) / f"{run_id}.jsonl"
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event_type: str, agent: str, data: dict) -> None:
        if self._path is None:
            return

        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event_type": event_type,
            "agent": agent,
            "data": data,
        }
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def read_all(self) -> list[dict]:
        if self._path is None or not self._path.exists():
            return []

        entries: list[dict] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries
