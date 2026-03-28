from unittest.mock import MagicMock

import pytest

from core.config import Config
from integrations.base import BaseIntegrationAdapter, IntegrationAdapter
from integrations.registry import IntegrationRegistry, build_integration_registry
from core.schemas import (
    ActionExecutionRequest,
    ActionExecutionResult,
    EvidenceBatch,
    IntegrationQuery,
)


class DummyIntegration(BaseIntegrationAdapter):
    def __init__(self, name: str, supports_read: bool = True, supports_write: bool = False):
        self.name = name
        self.supports_read = supports_read
        self.supports_write = supports_write

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        return EvidenceBatch(adapter_name=self.name, query=query, records=[])

    async def execute(self, request: ActionExecutionRequest) -> ActionExecutionResult:
        return ActionExecutionResult(
            adapter_name=self.name,
            action_type=request.action_type,
            target=request.target,
            status="suggested",
            executed=False,
        )


def _base_config() -> Config:
    return Config.for_dry_run()


def test_empty_registry_when_no_integrations_enabled():
    registry = build_integration_registry(_base_config(), factories={})
    assert isinstance(registry, IntegrationRegistry)
    assert registry.names() == ()
    with pytest.raises(KeyError, match="not registered"):
        registry.get("sentinel")


def test_registry_builds_enabled_integrations_from_factories():
    config = _base_config()
    config.enabled_integrations = ("sentinel", "threat_intel")

    sentinel = DummyIntegration("sentinel")
    threat_intel = DummyIntegration("threat_intel")

    registry = build_integration_registry(
        config,
        factories={
            "sentinel": lambda _: sentinel,
            "threat_intel": lambda _: threat_intel,
        },
    )

    assert registry.names() == ("sentinel", "threat_intel")
    assert registry.get("sentinel") is sentinel
    assert registry.get("threat_intel") is threat_intel
    assert isinstance(sentinel, IntegrationAdapter)


def test_registry_rejects_unknown_enabled_integration():
    config = _base_config()
    config.enabled_integrations = ("missing",)

    with pytest.raises(ValueError, match="No integration factory registered"):
        build_integration_registry(config, factories={})


def test_registry_rejects_factory_adapter_name_mismatch():
    config = _base_config()
    config.enabled_integrations = ("sentinel",)

    mismatch = DummyIntegration("different")

    with pytest.raises(ValueError, match="returned adapter named"):
        build_integration_registry(
            config,
            factories={"sentinel": lambda _: mismatch},
        )
