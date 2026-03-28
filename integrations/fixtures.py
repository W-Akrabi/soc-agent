from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any


_SENSITIVE_KEYS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "client_secret",
    "clientsecret",
    "secret",
    "password",
}

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+\b")
_ASSIGN_SECRET_RE = re.compile(
    r"(?i)\b((?:access_token|refresh_token|token|api_key|apikey|client_secret|secret|password)\s*=\s*)[^&\s,;]+"
)


class FixtureNotFoundError(FileNotFoundError):
    pass


@dataclass(slots=True)
class FixtureRecord:
    adapter: str
    operation: str
    query_key: Any
    fingerprint: str
    status: str
    recorded_at: str
    request: Any | None = None
    response: Any | None = None
    error: Any | None = None
    metadata: dict[str, Any] = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if data["metadata"] is None:
            data["metadata"] = {}
        return data


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


def _sanitize_string(value: str) -> str:
    value = _BEARER_RE.sub("Bearer [REDACTED]", value)
    value = _ASSIGN_SECRET_RE.sub(r"\1[REDACTED]", value)
    return value


def _sanitize(value: Any, *, key: str | None = None) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if key and _is_sensitive_key(key):
            return "[REDACTED]"
        return _sanitize_string(value)
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for item_key, item_value in value.items():
            if _is_sensitive_key(str(item_key)):
                redacted[str(item_key)] = "[REDACTED]"
            else:
                redacted[str(item_key)] = _sanitize(item_value, key=str(item_key))
        return redacted
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    return value


def _is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("-", "_")
    return any(marker in normalized for marker in _SENSITIVE_KEYS)


def _slugify(value: Any) -> str:
    text = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")) if not isinstance(value, str) else value
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-._")
    return text or "query"


def _fingerprint(adapter: str, operation: str, query_key: Any) -> str:
    payload = {
        "adapter": adapter,
        "operation": operation,
        "query_key": _jsonable(query_key),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class FixtureStore:
    def __init__(self, root_dir: str | Path):
        self.root_dir = Path(root_dir)

    def fingerprint(self, adapter: str, operation: str, query_key: Any) -> str:
        return _fingerprint(adapter, operation, query_key)

    def path_for(self, adapter: str, operation: str, query_key: Any) -> Path:
        digest = self.fingerprint(adapter, operation, query_key)
        slug = _slugify(query_key)
        return self.root_dir / _slugify(adapter) / _slugify(operation) / f"{slug}-{digest[:16]}.json"

    def record(
        self,
        adapter: str,
        operation: str,
        query_key: Any,
        *,
        request: Any | None = None,
        response: Any | None = None,
        error: Any | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> FixtureRecord:
        status = "error" if error is not None else "ok"
        entry = FixtureRecord(
            adapter=adapter,
            operation=operation,
            query_key=_sanitize(_jsonable(query_key)),
            fingerprint=self.fingerprint(adapter, operation, query_key),
            status=status,
            recorded_at=datetime.now(timezone.utc).isoformat(),
            request=_sanitize(_jsonable(request)) if request is not None else None,
            response=_sanitize(_jsonable(response)) if response is not None else None,
            error=_sanitize(_jsonable(error)) if error is not None else None,
            metadata=_sanitize(_jsonable(metadata or {})),
        )

        path = self.path_for(adapter, operation, query_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(entry.to_dict(), indent=2, sort_keys=True))
        return entry

    def replay(self, adapter: str, operation: str, query_key: Any) -> FixtureRecord:
        path = self.path_for(adapter, operation, query_key)
        if not path.exists():
            raise FixtureNotFoundError(
                f"Missing fixture for adapter={adapter!r}, operation={operation!r}, "
                f"query_key={query_key!r} at {path}"
            )

        payload = json.loads(path.read_text())
        return FixtureRecord(
            adapter=payload["adapter"],
            operation=payload["operation"],
            query_key=payload["query_key"],
            fingerprint=payload["fingerprint"],
            status=payload["status"],
            recorded_at=payload["recorded_at"],
            request=payload.get("request"),
            response=payload.get("response"),
            error=payload.get("error"),
            metadata=payload.get("metadata") or {},
        )
