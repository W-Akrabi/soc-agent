from __future__ import annotations

import json

import httpx

from core.llm_response import LLMResponse


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

    def _extract_text(self, content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(str(item.get("text") or item.get("content") or ""))
            return "".join(parts)
        return ""

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
        payload_messages = [{"role": "system", "content": system}, *messages]
        payload = {
            "model": self.model,
            "messages": payload_messages,
            "max_tokens": max_tokens,
        }
        formatted_tools = self._format_tools(tools)
        if formatted_tools:
            payload["tools"] = formatted_tools

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
        tool_calls: list[dict] = []
        choices = data.get("choices", [])
        if choices:
            message = choices[0].get("message", {})
            content = self._extract_text(message.get("content", "") or "")
            tool_calls = self._extract_tool_calls(message)

        self._emit_call_event(system, content)
        return LLMResponse(text=content, tool_calls=tool_calls)
