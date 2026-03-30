from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.llm_client import LLMClient
from core.llm_response import LLMResponse


def test_llm_response_text_only():
    response = LLMResponse(text="hello", tool_calls=[])
    assert response.text == "hello"
    assert response.tool_calls == []
    assert not response.has_tool_calls
    assert response == "hello"
    assert response.lower() == "hello"


def test_llm_response_with_tool_calls():
    calls = [{"name": "dispatch_agent", "input": {"agent": "forensics"}, "id": "tc1"}]
    response = LLMResponse(text="", tool_calls=calls)
    assert response.has_tool_calls
    assert response.tool_calls[0]["name"] == "dispatch_agent"


def test_llm_response_first_tool_call():
    calls = [{"name": "dispatch_agent", "input": {"agent": "forensics"}, "id": "tc1"}]
    response = LLMResponse(text="", tool_calls=calls)
    assert response.first_tool_call["name"] == "dispatch_agent"


def test_llm_response_first_tool_call_empty():
    response = LLMResponse(text="ok", tool_calls=[])
    assert response.first_tool_call is None


@pytest.mark.asyncio
async def test_llm_client_returns_llm_response():
    mock_block = MagicMock()
    mock_block.text = "hello world"
    mock_block.type = "text"

    mock_response = MagicMock()
    mock_response.content = [mock_block]

    with patch("anthropic.AsyncAnthropic") as mock_anthropic:
        mock_client = MagicMock()
        mock_client.messages.create = AsyncMock(return_value=mock_response)
        mock_anthropic.return_value = mock_client

        llm = LLMClient(api_key="test", model="claude-test")
        result = await llm.call(system="sys", messages=[{"role": "user", "content": "hi"}])

    assert isinstance(result, LLMResponse)
    assert result.text == "hello world"
    assert result.tool_calls == []
