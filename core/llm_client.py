import asyncio
import anthropic


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
    ) -> str:
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
                for block in response.content:
                    if hasattr(block, "text"):
                        result = block.text
                        if self._event_log is not None:
                            self._event_log.append(
                                "llm_call",
                                agent="llm",
                                data={
                                    "system_snippet": system[:120],
                                    "response_snippet": result[:120],
                                },
                            )
                        return result
                if self._event_log is not None:
                    self._event_log.append(
                        "llm_call",
                        agent="llm",
                        data={"system_snippet": system[:120], "response_snippet": ""},
                    )
                return ""
            except Exception as e:
                last_error = e
                if attempt == 0:
                    await asyncio.sleep(2)

        raise LLMError(f"LLM call failed after retry: {last_error}") from last_error
