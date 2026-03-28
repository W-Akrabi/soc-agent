from __future__ import annotations

import httpx


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str):
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
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            response.raise_for_status()
            data = response.json()

        content = ""
        if isinstance(data, dict):
            message = data.get("message") or {}
            content = message.get("content") or data.get("response") or ""

        self._emit_call_event(system, content)
        return content
