from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FixtureMode(Enum):
    OFF = "off"
    RECORD = "record"
    REPLAY = "replay"

    @classmethod
    def from_value(cls, value: str) -> "FixtureMode":
        normalized = (value or cls.OFF.value).strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            raise ValueError(
                f"Invalid SOC_FIXTURE_MODE {value!r}. Expected one of: off, record, replay."
            ) from exc


def parse_bool_flag(value: str | None, *, default: bool = False) -> bool:
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean flag value: {value!r}")


def parse_csv_names(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    names: list[str] = []
    seen: set[str] = set()
    for part in value.split(","):
        name = part.strip().lower()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return tuple(names)


@dataclass(slots=True)
class IntegrationSafetyConfig:
    enabled_integrations: tuple[str, ...] = ()
    fixture_mode: FixtureMode = FixtureMode.OFF
    fixture_dir: str | None = None
    allow_live_integrations: bool = False
    allow_write_integrations: bool = False
    allow_integration_execution: bool = False
    integration_timeout: int = 30
