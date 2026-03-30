from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol

from core.models import Alert


class Detector(Protocol):
    name: str

    async def watch(self, *, run_once: bool = False) -> AsyncIterator[Alert]: ...
