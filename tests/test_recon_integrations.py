from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from rich.console import Console

from agents.recon import ReconAgent
from core.case_graph import CaseGraph
from core.models import Alert, AlertType, Severity
from core.schemas import EvidenceBatch, IntegrationQuery, NormalizedEvidence
from integrations.registry import IntegrationRegistry


@pytest.fixture
def graph(tmp_path):
    return CaseGraph(str(tmp_path / "test.db"))


@pytest.fixture
def console():
    return Console(quiet=True)


@pytest.fixture
def alert():
    return Alert(
        id="test-alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_path": "C:/Temp/payload.dll",
        },
        source_ip="10.0.1.45",
        dest_ip="10.0.1.50",
        hostname="web-prod-01",
    )


@pytest.fixture
def mock_llm():
    llm = MagicMock()
    llm.call = AsyncMock(return_value="Recon summary.")
    return llm


class _FakeDefenderAdapter:
    name = "defender"
    supports_read = True
    supports_write = False

    def __init__(self):
        self.queries: list[IntegrationQuery] = []

    async def healthcheck(self):
        return {"name": self.name, "ok": True}

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        self.queries.append(query)
        if query.entity_type == "host":
            return EvidenceBatch(
                adapter_name=self.name,
                query=query,
                records=[
                    NormalizedEvidence(
                        source="defender",
                        source_type="edr",
                        entity_type="host",
                        entity_value=query.entity_value,
                        title=f"Defender host evidence for {query.entity_value}",
                        summary="Device healthy",
                        severity="medium",
                        confidence=72.0,
                    )
                ],
            )
        if query.entity_type == "file":
            return EvidenceBatch(
                adapter_name=self.name,
                query=query,
                records=[
                    NormalizedEvidence(
                        source="defender",
                        source_type="edr",
                        entity_type="file",
                        entity_value=query.entity_value,
                        title=f"Defender file evidence for {query.entity_value}",
                        summary="File flagged by Defender",
                        severity="high",
                        confidence=91.0,
                    )
                ],
            )
        return EvidenceBatch(adapter_name=self.name, query=query, records=[], partial=True, error="unsupported")

    async def execute(self, request):
        raise AssertionError("execute should not be called in read coverage")


@pytest.mark.asyncio
async def test_recon_agent_consumes_registry_defender_evidence(graph, console, alert, mock_llm):
    defender = _FakeDefenderAdapter()
    registry = IntegrationRegistry()
    registry.register(defender)

    task_id = graph.write_node("task", "recon-task", {"agent": "recon", "objective": "Investigate"}, "commander")
    agent = ReconAgent(graph, mock_llm, console, integration_registry=registry)
    agent.ip_tool.run = AsyncMock(return_value={"geo": "internal", "city": "", "asn": "internal", "org": "LAN", "risk": "low"})
    agent.port_tool.run = AsyncMock(return_value={"ip": alert.source_ip, "open_ports": [{"port": 443, "service": "https"}]})

    await agent.run(task_id, alert)

    assert [query.entity_type for query in defender.queries] == ["host", "host", "host", "file", "file"]
    assert any(query.entity_value == "web-prod-01" for query in defender.queries)
    assert any(query.entity_value == "d41d8cd98f00b204e9800998ecf8427e" for query in defender.queries)

    evidence_nodes = graph.get_nodes_by_type("evidence")
    assert len(evidence_nodes) == 5
    assert all(node["data"]["source"] == "defender" for node in evidence_nodes)
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_recon_agent_degrades_gracefully_without_defender_registry(graph, console, alert, mock_llm):
    registry = IntegrationRegistry()
    task_id = graph.write_node("task", "recon-task", {"agent": "recon", "objective": "Investigate"}, "commander")
    agent = ReconAgent(graph, mock_llm, console, integration_registry=registry)
    agent.ip_tool.run = AsyncMock(return_value={"geo": "internal", "city": "", "asn": "internal", "org": "LAN", "risk": "low"})
    agent.port_tool.run = AsyncMock(return_value={"ip": alert.source_ip, "open_ports": []})

    await agent.run(task_id, alert)

    assert graph.get_task_status(task_id) == "completed"
    assert len(graph.get_nodes_by_type("evidence")) == 0
