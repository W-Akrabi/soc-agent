from __future__ import annotations

import httpx


class OpenAIProvider:
    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._event_log = None

    def attach_event_log(self, event_log) -> None:
        self._event_log = event_log

    def _emit_call_event(self, system: str, response: str) -> None:
        if self._event_log is not None:
            self._event_log.append(
                "llm_call",
                agent="llm",
                data={
                    "system_snippet": system[:120],
                    "response_snippet": response[:120],
                },
            )

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> str:
        payload_messages = [{"role": "system", "content": system}, *messages]
        payload = {
            "model": self.model,
            "messages": payload_messages,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = ""
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = message.get("content", "") or ""

        self._emit_call_event(system, content)
        return content
