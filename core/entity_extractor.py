from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def extract_entities_from_graph(graph: Any) -> dict[str, list[str]]:
    """Extract host/user/ip/domain/hash entities from a completed case graph."""
    nodes = _graph_nodes(graph)
    entities: dict[str, set[str]] = defaultdict(set)

    for node in nodes:
        node_type = str(node.get("type", "")).lower()
        label = _as_text(node.get("label"))
        data = node.get("data") or {}
        flat_values = _flatten_values(data)
        search_space = " ".join([label, *flat_values])

        if node_type == "ip" and label:
            entities["ips"].add(label)
        if node_type == "host" and label:
            entities["hosts"].add(label)
        if node_type == "domain" and label:
            entities["domains"].add(label)
        if node_type == "user" and label:
            entities["users"].add(label)
        if node_type in {"file", "hash"} and label and _looks_like_hash(label):
            entities["hashes"].add(label)

        _add_structured_entities(node_type, label, data, entities)
        _add_regex_matches(search_space, entities)

    return {key: sorted(values) for key, values in sorted(entities.items())}


def _graph_nodes(graph: Any) -> list[dict[str, Any]]:
    if graph is None:
        return []
    if hasattr(graph, "get_full_graph") and callable(graph.get_full_graph):
        full = graph.get_full_graph()
        if isinstance(full, dict):
            return list(full.get("nodes", []))
    if hasattr(graph, "get_nodes_by_type") and callable(graph.get_nodes_by_type):
        collected: list[dict[str, Any]] = []
        for node_type in ("alert", "host", "ip", "user", "domain", "file", "hash", "evidence", "finding", "cve", "timeline_event", "action", "task", "log_entry"):
            try:
                collected.extend(graph.get_nodes_by_type(node_type))
            except Exception:
                continue
        if collected:
            return collected
    return []


def _add_structured_entities(node_type: str, label: str, data: Any, entities: dict[str, set[str]]) -> None:
    if not isinstance(data, dict):
        return

    def add(bucket: str, value: Any) -> None:
        text = _as_text(value)
        if text:
            entities[bucket].add(text)

    if node_type == "evidence":
        entity_type = str(data.get("entity_type", "")).lower()
        entity_value = data.get("entity_value")
        if entity_type == "host":
            add("hosts", entity_value or label)
        elif entity_type == "user":
            add("users", entity_value or label)
        elif entity_type == "ip":
            add("ips", entity_value or label)
        elif entity_type == "domain":
            add("domains", entity_value or label)
        elif entity_type == "hash":
            add("hashes", entity_value or label)

    for key in ("hostname", "host", "deviceName", "computerDnsName", "target_host"):
        add("hosts", data.get(key))
    for key in ("user", "user_account", "userPrincipalName", "upn", "principalName", "account"):
        add("users", data.get(key))
    for key in ("source_ip", "dest_ip", "ip", "ip_address", "ipAddress", "src_ip", "dst_ip"):
        add("ips", data.get(key))
    for key in ("domain", "fqdn", "host_domain"):
        add("domains", data.get(key))
    for key in ("file_hash", "sha256", "sha1", "md5", "hash"):
        add("hashes", data.get(key))


def _add_regex_matches(text: str, entities: dict[str, set[str]]) -> None:
    for match in _IP_RE.findall(text):
        entities["ips"].add(match)
    for match in _HEX_RE.findall(text):
        entities["hashes"].add(match.lower())
    for match in _DOMAIN_RE.findall(text):
        if not _looks_like_ip(match):
            entities["domains"].add(match.lower())


def _flatten_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for nested in value.values():
            values.extend(_flatten_values(nested))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_flatten_values(nested))
    elif value not in (None, ""):
        values.append(_as_text(value))
    return [item for item in values if item]


def _as_text(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _looks_like_hash(value: str) -> bool:
    text = value.strip()
    return bool(_HEX_RE.fullmatch(text))


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


__all__ = ["extract_entities_from_graph"]
