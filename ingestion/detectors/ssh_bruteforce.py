from __future__ import annotations

import asyncio
import re
import socket
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from core.models import Alert, AlertType, Severity

SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<hostname>[A-Za-z0-9._:-]+))?"
    r"\s+(?P<process>[A-Za-z0-9_./@-]+)(?:\[\d+\])?:\s+"
    r"(?P<message>.*)$"
)
FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:(?:invalid|illegal) user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
PAM_AUTH_FAILURE_RE = re.compile(
    r"authentication failure;.*(?:rhost|ruserhost)=(?P<ip>[0-9a-fA-F:.]+).*user=(?P<user>\S+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FailedLoginEvent:
    observed_at: datetime
    source_ip: str
    source_port: int | None
    user_account: str | None
    hostname: str | None
    process: str | None
    raw_line: str


class SSHBruteForceDetector:
    name = "ssh-bruteforce"

    def __init__(
        self,
        *,
        log_path: str,
        threshold: int = 5,
        window_seconds: int = 300,
        cooldown_seconds: int = 900,
        poll_interval: float = 2.0,
        hostname: str | None = None,
        start_at_end: bool = True,
    ):
        self.log_path = Path(log_path)
        self.threshold = max(1, int(threshold))
        self.window_seconds = max(1, int(window_seconds))
        self.cooldown_seconds = max(1, int(cooldown_seconds))
        self.poll_interval = max(0.1, float(poll_interval))
        self.hostname = hostname or socket.gethostname()
        self.start_at_end = start_at_end
        self._offset: int | None = None
        self._failures: dict[tuple[str, str, str], deque[FailedLoginEvent]] = defaultdict(deque)
        self._last_emitted_at: dict[tuple[str, str, str], datetime] = {}

    async def watch(self, *, run_once: bool = False):
        while True:
            for alert in self.poll():
                yield alert
            if run_once:
                return
            await asyncio.sleep(self.poll_interval)

    def poll(self) -> list[Alert]:
        try:
            current_size = self.log_path.stat().st_size
        except FileNotFoundError:
            if self._offset is None:
                self._offset = 0
            return []

        if self._offset is None:
            self._offset = current_size if self.start_at_end else 0
        elif current_size < self._offset:
            self._offset = 0

        alerts: list[Alert] = []
        with self.log_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._offset)
            for line in handle:
                event = parse_failed_login_event(line, default_hostname=self.hostname)
                if event is None:
                    continue
                maybe_alert = self._record_failure(event)
                if maybe_alert is not None:
                    alerts.append(maybe_alert)
            self._offset = handle.tell()
        return alerts

    def _record_failure(self, event: FailedLoginEvent) -> Alert | None:
        key = (
            event.source_ip,
            (event.user_account or "unknown").lower(),
            event.hostname or self.hostname,
        )
        bucket = self._failures[key]
        bucket.append(event)

        cutoff = event.observed_at - timedelta(seconds=self.window_seconds)
        while bucket and bucket[0].observed_at < cutoff:
            bucket.popleft()

        if len(bucket) < self.threshold:
            return None

        last_emitted_at = self._last_emitted_at.get(key)
        if last_emitted_at is not None:
            since_last = (event.observed_at - last_emitted_at).total_seconds()
            if since_last < self.cooldown_seconds:
                return None

        self._last_emitted_at[key] = event.observed_at
        return self._build_alert(key, list(bucket), observed_at=event.observed_at)

    def _build_alert(
        self,
        key: tuple[str, str, str],
        events: list[FailedLoginEvent],
        *,
        observed_at: datetime,
    ) -> Alert:
        source_ip, normalized_user, hostname = key
        user_account = None if normalized_user == "unknown" else normalized_user
        event_count = len(events)
        severity = Severity.MEDIUM
        if user_account in {"root", "admin"} or event_count >= self.threshold * 2:
            severity = Severity.HIGH
        if user_account == "root" and event_count >= self.threshold * 3:
            severity = Severity.CRITICAL

        sample_events = events[-min(len(events), 10):]
        return Alert(
            id=str(uuid.uuid4()),
            type=AlertType.BRUTE_FORCE,
            severity=severity,
            timestamp=observed_at,
            raw_payload={
                "detector": self.name,
                "log_path": str(self.log_path),
                "failure_count": event_count,
                "window_seconds": self.window_seconds,
                "cooldown_seconds": self.cooldown_seconds,
                "first_seen": events[0].observed_at.isoformat(),
                "last_seen": events[-1].observed_at.isoformat(),
                "events": [
                    {
                        "observed_at": item.observed_at.isoformat(),
                        "source_ip": item.source_ip,
                        "source_port": item.source_port,
                        "user_account": item.user_account,
                        "hostname": item.hostname,
                        "process": item.process,
                        "raw_line": item.raw_line,
                    }
                    for item in sample_events
                ],
            },
            source_ip=source_ip,
            source_port=sample_events[-1].source_port,
            dest_port=22,
            user_account=user_account,
            hostname=hostname,
            process=sample_events[-1].process,
            tags=["detector:ssh_bruteforce", "source:auth_log"],
        )


def parse_failed_login_event(line: str, *, default_hostname: str | None = None) -> FailedLoginEvent | None:
    match = SYSLOG_RE.match(line.strip())
    if match is None:
        return None

    message = match.group("message")
    parsed = FAILED_PASSWORD_RE.search(message) or PAM_AUTH_FAILURE_RE.search(message)
    if parsed is None:
        return None

    observed_at = _parse_syslog_timestamp(
        month=match.group("month"),
        day=match.group("day"),
        time_str=match.group("time"),
    )
    hostname = match.group("hostname") or default_hostname
    source_port = parsed.groupdict().get("port")
    return FailedLoginEvent(
        observed_at=observed_at,
        source_ip=parsed.group("ip"),
        source_port=int(source_port) if source_port else None,
        user_account=parsed.groupdict().get("user"),
        hostname=hostname,
        process=match.group("process"),
        raw_line=line.rstrip("\n"),
    )


def _parse_syslog_timestamp(*, month: str, day: str, time_str: str) -> datetime:
    now = datetime.now().astimezone()
    candidate = datetime.strptime(
        f"{now.year} {month} {day} {time_str}",
        "%Y %b %d %H:%M:%S",
    ).replace(tzinfo=now.tzinfo)
    if candidate - now > timedelta(days=1):
        candidate = candidate.replace(year=candidate.year - 1)
    return candidate
