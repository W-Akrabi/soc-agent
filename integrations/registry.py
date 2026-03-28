from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Mapping

from core.config import Config
from integrations.base import IntegrationAdapter


IntegrationFactory = Callable[[Config], IntegrationAdapter]


@dataclass
class IntegrationRegistry:
    adapters: dict[str, IntegrationAdapter] = field(default_factory=dict)

    def register(self, adapter: IntegrationAdapter) -> None:
        if adapter.name in self.adapters:
            raise ValueError(f"Integration {adapter.name!r} is already registered")
        self.adapters[adapter.name] = adapter

    def get(self, name: str) -> IntegrationAdapter:
        try:
            return self.adapters[name]
        except KeyError as exc:
            raise KeyError(f"Integration {name!r} is not registered") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self.adapters.keys())


def build_integration_registry(
    config: Config,
    *,
    factories: Mapping[str, IntegrationFactory] | None = None,
) -> IntegrationRegistry:
    registry = IntegrationRegistry()
    enabled = config.enabled_integrations
    if not enabled:
        return registry

    available_factories = dict(factories or {})
    missing = [name for name in enabled if name not in available_factories]
    if missing:
        raise ValueError(f"No integration factory registered for: {', '.join(missing)}")

    for name in enabled:
        adapter = available_factories[name](config)
        if adapter.name != name:
            raise ValueError(
                f"Integration factory for {name!r} returned adapter named {adapter.name!r}"
            )
        registry.register(adapter)

    return registry
