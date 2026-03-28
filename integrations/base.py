from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol, runtime_checkable

import httpx

from core.schemas import ActionExecutionRequest, ActionExecutionResult, EvidenceBatch, IntegrationQuery


@runtime_checkable
class IntegrationAdapter(Protocol):
    name: str
    supports_read: bool
    supports_write: bool

    async def healthcheck(self) -> dict[str, Any]: ...

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch: ...

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult: ...


class BaseIntegrationAdapter(ABC):
    name: str = "integration"
    supports_read: bool = True
    supports_write: bool = False

    async def healthcheck(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "supports_read": self.supports_read,
            "supports_write": self.supports_write,
            "ok": True,
        }

    @abstractmethod
    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        raise NotImplementedError

    @abstractmethod
    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        raise NotImplementedError


@dataclass(slots=True)
class MicrosoftAuthConfig:
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    bearer_token: str = ""
    scope: str = "https://api.loganalytics.io/.default"


class MicrosoftAuthHelper:
    def __init__(
        self,
        config: MicrosoftAuthConfig,
        *,
        client_factory: Callable[[], Any] | None = None,
    ):
        self._config = config
        self._client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=10.0))
        self._cached_token: str | None = None
        self._expires_at: datetime | None = None
        self._lock = asyncio.Lock()

    async def authorization_headers(self) -> dict[str, str]:
        token = await self._resolve_token()
        return {"Authorization": f"Bearer {token}"}

    async def _resolve_token(self) -> str:
        if self._config.bearer_token:
            return self._config.bearer_token

        now = datetime.now(timezone.utc)
        if self._cached_token and self._expires_at and now < self._expires_at:
            return self._cached_token

        async with self._lock:
            now = datetime.now(timezone.utc)
            if self._cached_token and self._expires_at and now < self._expires_at:
                return self._cached_token

            missing = [
                name
                for name, value in (
                    ("tenant_id", self._config.tenant_id),
                    ("client_id", self._config.client_id),
                    ("client_secret", self._config.client_secret),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "Microsoft auth requires bearer_token or tenant_id/client_id/client_secret"
                )

            token_url = (
                f"https://login.microsoftonline.com/{self._config.tenant_id}"
                "/oauth2/v2.0/token"
            )
            payload = {
                "grant_type": "client_credentials",
                "client_id": self._config.client_id,
                "client_secret": self._config.client_secret,
                "scope": self._config.scope,
            }

            async with self._client_factory() as client:
                response = await client.post(token_url, data=payload)
                response.raise_for_status()
                body = response.json()

            token = str(body.get("access_token", "") or "")
            if not token:
                raise ValueError("Microsoft auth response did not include access_token")

            expires_in = int(body.get("expires_in", 3600) or 3600)
            expiry_margin = max(expires_in - 60, 60)
            self._cached_token = token
            self._expires_at = datetime.now(timezone.utc) + timedelta(seconds=expiry_margin)
            return token
