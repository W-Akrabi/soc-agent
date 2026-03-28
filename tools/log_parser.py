from tools.base import BaseTool


class LogParserTool(BaseTool):
    name = "log_parser"
    description = "Parse structured JSON log entries into normalized security events"

    async def run(self, input: dict) -> dict:
        logs = input.get("logs", [])
        events = []
        for log in logs:
            events.append({
                "timestamp": log.get("ts", ""),
                "event_type": log.get("event", "unknown"),
                "details": {k: v for k, v in log.items() if k not in ("ts", "event")},
            })
        return {"events": events, "count": len(events)}
