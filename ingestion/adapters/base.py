from abc import ABC, abstractmethod
from core.models import Alert


class BaseAdapter(ABC):
    @abstractmethod
    def next_alert(self) -> Alert:
        """Return the next alert. Blocking."""
        ...
