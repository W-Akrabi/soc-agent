from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMResponse:
    text: str
    tool_calls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)

    @property
    def first_tool_call(self) -> dict[str, Any] | None:
        return self.tool_calls[0] if self.tool_calls else None

    def __bool__(self) -> bool:
        return bool(self.text or self.tool_calls)

    def __str__(self) -> str:
        return self.text

    def __eq__(self, other: object) -> bool:
        if isinstance(other, LLMResponse):
            return self.text == other.text and self.tool_calls == other.tool_calls
        if isinstance(other, str):
            return self.text == other
        return NotImplemented

    def __getattr__(self, name: str) -> Any:
        return getattr(self.text, name)
