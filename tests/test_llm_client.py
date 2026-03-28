import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from core.llm_client import LLMClient, LLMError


@pytest.fixture
def client():
    return LLMClient(api_key="test-key", model="claude-sonnet-4-6")


@pytest.mark.asyncio
async def test_call_returns_text(client):
    mock_response = MagicMock()
    mock_response.content = [MagicMock(type="text", text="Hello world")]
    with patch.object(client._client.messages, "create", new=AsyncMock(return_value=mock_response)):
        result = await client.call(system="Be helpful", messages=[{"role": "user", "content": "Hi"}])
    assert result == "Hello world"


@pytest.mark.asyncio
async def test_call_retries_once_on_failure(client):
    mock_response = MagicMock()
    mock_response.content = [MagicMock(type="text", text="Retry worked")]
    call_mock = AsyncMock(side_effect=[Exception("API error"), mock_response])
    with patch.object(client._client.messages, "create", new=call_mock):
        result = await client.call(system="test", messages=[{"role": "user", "content": "test"}])
    assert result == "Retry worked"
    assert call_mock.call_count == 2


@pytest.mark.asyncio
async def test_call_raises_llm_error_after_two_failures(client):
    call_mock = AsyncMock(side_effect=Exception("always fails"))
    with patch.object(client._client.messages, "create", new=call_mock):
        with pytest.raises(LLMError, match="LLM call failed after retry"):
            await client.call(system="test", messages=[{"role": "user", "content": "test"}])
    assert call_mock.call_count == 2
