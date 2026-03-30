from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable

from core.config import Config
from core.llm_response import LLMResponse

__path__ = [str(Path(__file__).with_name("providers"))]


@runtime_checkable
class ModelProvider(Protocol):
    name: str

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse: ...

    def attach_event_log(self, event_log) -> None: ...


def build_provider(config: Config) -> ModelProvider:
    provider = (config.provider or "anthropic").strip().lower()

    if provider == "anthropic":
        from core.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(api_key=config.anthropic_api_key, model=config.model)
    if provider == "openai":
        from core.providers.openai_provider import OpenAIProvider

        base_url = config.openai_base_url or "https://api.openai.com/v1"
        return OpenAIProvider(
            api_key=config.openai_api_key,
            model=config.model,
            base_url=base_url,
        )
    if provider == "ollama":
        from core.providers.ollama_provider import OllamaProvider

        return OllamaProvider(
            model=config.model,
            base_url=config.ollama_base_url or "http://127.0.0.1:11434",
        )

    raise ValueError(f"Unsupported model provider: {config.provider!r}")
