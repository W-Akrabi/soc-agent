from __future__ import annotations

import json

import httpx

from core.llm_response import LLMResponse


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, base_url: str, request_timeout: float = 180.0):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.request_timeout = request_timeout
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

    def _extract_tool_calls(self, message: dict) -> list[dict]:
        tool_calls: list[dict] = []
        for tool_call in message.get("tool_calls", []) or []:
            function = tool_call.get("function") or {}
            arguments = function.get("arguments", "{}")
            if isinstance(arguments, str):
                try:
                    parsed_arguments = json.loads(arguments) if arguments else {}
                except json.JSONDecodeError:
                    parsed_arguments = {"raw": arguments}
            elif isinstance(arguments, dict):
                parsed_arguments = arguments
            else:
                parsed_arguments = {}
            tool_calls.append(
                {
                    "id": tool_call.get("id", ""),
                    "name": function.get("name", ""),
                    "input": parsed_arguments,
                }
            )
        return tool_calls

    def _format_tools(self, tools: list[dict] | None) -> list[dict] | None:
        if not tools:
            return None
        formatted: list[dict] = []
        for tool in tools:
            if "function" in tool or tool.get("type") == "function":
                formatted.append(tool)
                continue
            formatted.append(
                {
                    "type": "function",
                    "function": {
                        "name": tool.get("name", ""),
                        "description": tool.get("description", ""),
                        "parameters": tool.get("input_schema", {}),
                    },
                }
            )
        return formatted

    async def call(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *messages],
            "stream": False,
        }
        formatted_tools = self._format_tools(tools)
        if formatted_tools:
            payload["tools"] = formatted_tools

        async with httpx.AsyncClient(timeout=self.request_timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
            except httpx.ConnectError as exc:
                raise RuntimeError(
                    "Could not connect to Ollama. Ensure Ollama is running and "
                    f"OLLAMA_BASE_URL is correct (current: {self.base_url}). "
                    "On macOS, launching Ollama.app is usually sufficient."
                ) from exc

        content = ""
        tool_calls: list[dict] = []
        if isinstance(data, dict):
            message = data.get("message") or {}
            content = message.get("content") or data.get("response") or ""
            tool_calls = self._extract_tool_calls(message) if isinstance(message, dict) else []

        self._emit_call_event(system, content)
        return LLMResponse(text=content, tool_calls=tool_calls)
