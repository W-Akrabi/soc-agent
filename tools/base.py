from abc import ABC, abstractmethod


class BaseTool(ABC):
    name: str = "base_tool"
    description: str = ""

    @abstractmethod
    async def run(self, input: dict) -> dict:
        """Execute the tool. Input/output are typed dicts."""
        ...
