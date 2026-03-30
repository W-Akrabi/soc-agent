import asyncio
import anthropic

from core.llm_response import LLMResponse


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.model = model
        self._client = anthropic.AsyncAnthropic(api_key=api_key)
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        kwargs = dict(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )
        if tools:
            kwargs["tools"] = tools

        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = await self._client.messages.create(**kwargs)
                text_parts: list[str] = []
                tool_calls: list[dict] = []
                for block in response.content:
                    block_type = getattr(block, "type", None)
                    if block_type == "tool_use":
                        tool_calls.append(
                            {
                                "id": getattr(block, "id", ""),
                                "name": getattr(block, "name", ""),
                                "input": getattr(block, "input", {}),
                            }
                        )
                        continue
                    if hasattr(block, "text") and block.text:
                        text_parts.append(block.text)
                result = "".join(text_parts)
                if self._event_log is not None:
                    self._event_log.append(
                        "llm_call",
                        agent="llm",
                        data={
                            "system_snippet": system[:120],
                            "response_snippet": result[:120],
                        },
                    )
                return LLMResponse(text=result, tool_calls=tool_calls)
            except Exception as e:
                last_error = e
                if attempt == 0:
                    await asyncio.sleep(2)

        raise LLMError(f"LLM call failed after retry: {last_error}") from last_error
