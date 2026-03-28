from __future__ import annotations

from dataclasses import replace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.config import Config
from core.providers import build_provider
from core.providers.anthropic_provider import AnthropicProvider
from core.providers.openai_provider import OpenAIProvider
from core.providers.ollama_provider import OllamaProvider


class DummyEventLog:
    def __init__(self):
        self.entries = []

    def append(self, event_type: str, agent: str, data: dict) -> None:
        self.entries.append({"event_type": event_type, "agent": agent, "data": data})


def _base_config(**overrides) -> Config:
    config = Config(
        anthropic_api_key="anthropic-key",
        model="test-model",
        db_path="/tmp/test.db",
        reports_dir="/tmp/reports",
        commander_timeout=30,
        agent_timeout=10,
        auto_remediate=False,
        log_level="INFO",
        provider="anthropic",
        openai_api_key="openai-key",
        openai_base_url="https://api.openai.com/v1",
        ollama_base_url="http://localhost:11434",
    )
    return replace(config, **overrides)


def test_build_provider_selects_anthropic():
    provider = build_provider(_base_config(provider="anthropic"))
    assert isinstance(provider, AnthropicProvider)


def test_build_provider_selects_openai():
    provider = build_provider(_base_config(provider="openai"))
    assert isinstance(provider, OpenAIProvider)


def test_build_provider_selects_ollama():
    provider = build_provider(_base_config(provider="ollama"))
    assert isinstance(provider, OllamaProvider)


def test_build_provider_rejects_unknown_provider():
    with pytest.raises(ValueError, match="Unsupported model provider"):
        build_provider(_base_config(provider="unknown"))


@pytest.mark.asyncio
async def test_anthropic_provider_emits_event_log():
    provider = AnthropicProvider(api_key="test-key", model="claude-sonnet-4-6")
    log = DummyEventLog()
    provider.attach_event_log(log)

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="anthropic result")]
    with patch.object(provider._client.messages, "create", new=AsyncMock(return_value=mock_response)):
        result = await provider.call(system="system prompt", messages=[{"role": "user", "content": "hi"}])

    assert result == "anthropic result"
    assert log.entries[0]["event_type"] == "llm_call"
    assert log.entries[0]["data"]["response_snippet"] == "anthropic result"


@pytest.mark.asyncio
async def test_openai_provider_posts_chat_completions_and_emits_event_log():
    provider = OpenAIProvider(api_key="openai-key", model="gpt-test", base_url="https://example.com/v1")
    log = DummyEventLog()
    provider.attach_event_log(log)

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"choices": [{"message": {"content": "openai result"}}]}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, headers=None, json=None):
            captured["url"] = url
            captured["headers"] = headers
            captured["json"] = json
            return FakeResponse()

    with patch("core.providers.openai_provider.httpx.AsyncClient", FakeClient):
        result = await provider.call(system="system prompt", messages=[{"role": "user", "content": "hi"}])

    assert result == "openai result"
    assert captured["url"] == "https://example.com/v1/chat/completions"
    assert captured["headers"]["Authorization"] == "Bearer openai-key"
    assert captured["json"]["model"] == "gpt-test"
    assert captured["json"]["messages"][0]["role"] == "system"
    assert log.entries[0]["event_type"] == "llm_call"


@pytest.mark.asyncio
async def test_ollama_provider_posts_chat_endpoint_and_emits_event_log():
    provider = OllamaProvider(model="llama3", base_url="http://localhost:11434/")
    log = DummyEventLog()
    provider.attach_event_log(log)

    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": "ollama result"}}

    class FakeClient:
        def __init__(self, *args, **kwargs):
            captured["timeout"] = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResponse()

    with patch("core.providers.ollama_provider.httpx.AsyncClient", FakeClient):
        result = await provider.call(system="system prompt", messages=[{"role": "user", "content": "hi"}])

    assert result == "ollama result"
    assert captured["url"] == "http://localhost:11434/api/chat"
    assert captured["json"]["model"] == "llama3"
    assert captured["json"]["messages"][0]["role"] == "system"
    assert log.entries[0]["event_type"] == "llm_call"
