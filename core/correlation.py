from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.memory_store import AssetBaseline, IncidentMemory, MemoryStore, PriorContext


def _alert_entities(alert: Any) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {
        "hosts": [],
        "users": [],
        "ips": [],
        "domains": [],
        "hashes": [],
    }

    def add(bucket: str, value: Any) -> None:
        if value in (None, ""):
            return
        text = str(value).strip()
        if text and text not in entities[bucket]:
            entities[bucket].append(text)

    for value in (
        getattr(alert, "hostname", None),
        getattr(alert, "source_ip", None),
        getattr(alert, "dest_ip", None),
    ):
        if value and _looks_like_ip(str(value)):
            add("ips", value)
        elif value:
            add("hosts", value)

    add("users", getattr(alert, "user_account", None))

    raw_payload = getattr(alert, "raw_payload", None) or {}
    if isinstance(raw_payload, dict):
        for key in ("hostname", "host", "device_name", "deviceName", "computerDnsName"):
            add("hosts", raw_payload.get(key))
        for key in ("user", "user_account", "userPrincipalName", "upn", "account"):
            add("users", raw_payload.get(key))
        for key in ("source_ip", "dest_ip", "ip", "ip_address", "ipAddress"):
            value = raw_payload.get(key)
            if value:
                add("ips", value)
        for key in ("domain", "fqdn", "url"):
            add("domains", raw_payload.get(key))
        for key in ("file_hash", "sha256", "sha1", "md5", "hash"):
            add("hashes", raw_payload.get(key))

    return entities


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _canonical_entity_type(entity_type: str) -> str:
    normalized = str(entity_type or "").strip().lower()
    aliases = {
        "hosts": "host",
        "host": "host",
        "users": "user",
        "user": "user",
        "ips": "ip",
        "ip": "ip",
        "domains": "domain",
        "domain": "domain",
        "hashes": "hash",
        "hash": "hash",
    }
    return aliases.get(normalized, normalized)


@dataclass(slots=True)
class CorrelationService:
    memory_store: MemoryStore
    limit: int = 3

    def get_prior_context(self, alert: Any) -> PriorContext:
        entities = _alert_entities(alert)
        return self.get_prior_context_for_entities(entities)

    def get_prior_context_for_entities(self, entities: dict[str, list[str]]) -> PriorContext:
        prior_incidents: list[IncidentMemory] = []
        baselines: list[AssetBaseline] = []
        seen_runs: set[str] = set()
        seen_baselines: set[tuple[str, str, str]] = set()

        for key, values in entities.items():
            canonical = _canonical_entity_type(key)
            for value in values:
                for memory in self.memory_store.list_memories_for_entity(canonical, value, limit=self.limit):
                    if memory.run_id in seen_runs:
                        continue
                    seen_runs.add(memory.run_id)
                    prior_incidents.append(memory)
                    if len(prior_incidents) >= self.limit:
                        break
                for baseline in self.memory_store.list_baselines_for_entity(canonical, value, limit=self.limit):
                    baseline_key = (baseline.entity_type, baseline.entity_value, baseline.baseline_type)
                    if baseline_key in seen_baselines:
                        continue
                    seen_baselines.add(baseline_key)
                    baselines.append(baseline)
                    if len(baselines) >= self.limit:
                        break
            if len(prior_incidents) >= self.limit and len(baselines) >= self.limit:
                break

        return PriorContext(
            prior_incidents=prior_incidents[: self.limit],
            entity_baselines=baselines[: self.limit],
        )


__all__ = ["CorrelationService"]
