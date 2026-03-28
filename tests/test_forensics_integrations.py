from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock
from datetime import datetime, timezone
from rich.console import Console

from agents.forensics import ForensicsAgent
from core.case_graph import CaseGraph
from core.models import Alert, AlertType, Severity
from core.schemas import EvidenceBatch, IntegrationQuery, NormalizedEvidence


class _FakeEntraAdapter:
    name = "entra"
    supports_read = True
    supports_write = False

    def __init__(self, batch: EvidenceBatch):
        self.batch = batch
        self.queries: list[IntegrationQuery] = []

    async def collect(self, query: IntegrationQuery) -> EvidenceBatch:
        self.queries.append(query)
        return self.batch

    async def execute(self, request):  # pragma: no cover - not used in these tests
        raise AssertionError("execute should not be called")


@pytest.fixture
def graph(tmp_path):
    return CaseGraph(str(tmp_path / "test.db"))


@pytest.fixture
def console():
    return Console(quiet=True)


@pytest.fixture
def alert():
    return Alert(
        id="forensics-alert-1",
        type=AlertType.INTRUSION,
        severity=Severity.HIGH,
        timestamp=datetime.now(timezone.utc),
        raw_payload={
            "logs": [
                {"timestamp": "2026-03-27T12:00:00Z", "event_type": "login", "message": "user login"},
                {"timestamp": "2026-03-27T12:05:00Z", "event_type": "escalation", "message": "privilege escalation"},
            ]
        },
        user_account="alice@example.com",
        source_ip="203.0.113.9",
        hostname="web-prod-01",
    )


@pytest.mark.asyncio
async def test_forensics_agent_consumes_entra_evidence_when_available(graph, console, alert):
    mock_llm = MagicMock()
    mock_llm.call = AsyncMock(return_value="Timeline includes sign-in and audit activity.")

    batch = EvidenceBatch(
        adapter_name="entra",
        query=IntegrationQuery(
            alert_id=alert.id,
            alert_type=alert.type.value,
            entity_type="user",
            entity_value="alice@example.com",
        ),
        records=[
            NormalizedEvidence(
                source="entra",
                source_type="identity",
                entity_type="user",
                entity_value="alice@example.com",
                title="Suspicious sign-in",
                summary="Sign-in from unfamiliar IP",
                severity="high",
                confidence=92.0,
                observed_at=datetime(2026, 3, 27, 12, 2, tzinfo=timezone.utc),
                raw_ref="entra:signins:signin-1",
                tags=["entra", "identity"],
                attributes={"endpoint": "signIns"},
            ),
            NormalizedEvidence(
                source="entra",
                source_type="audit",
                entity_type="user",
                entity_value="alice@example.com",
                title="Add member to role",
                summary="Role assignment changed",
                severity="high",
                confidence=88.0,
                observed_at=datetime(2026, 3, 27, 12, 4, tzinfo=timezone.utc),
                raw_ref="entra:directoryaudits:audit-1",
                tags=["entra", "audit"],
                attributes={"endpoint": "directoryAudits"},
            ),
        ],
    )
    entra_adapter = _FakeEntraAdapter(batch)

    task_id = graph.write_node("task", "forensics-task", {"agent": "forensics", "objective": "Build timeline"}, "commander")

    agent = ForensicsAgent(graph, mock_llm, console, entra_adapter=entra_adapter)
    await agent.run(task_id, alert)

    assert len(entra_adapter.queries) >= 1
    assert any(query.entity_type == "user" for query in entra_adapter.queries)

    entra_timeline_nodes = graph.search_nodes(type="timeline_event", data_contains={"source": "entra"})
    assert len(entra_timeline_nodes) == 2

    prompt = mock_llm.call.await_args.kwargs["messages"][0]["content"]
    assert "Identity and audit evidence" in prompt
    assert "alice@example.com" in prompt
    assert graph.get_task_status(task_id) == "completed"


@pytest.mark.asyncio
async def test_forensics_agent_degrades_gracefully_without_entra_adapter(graph, console, alert, monkeypatch):
    monkeypatch.delenv("SOC_ENTRA_BEARER_TOKEN", raising=False)
    monkeypatch.delenv("SOC_ENTRA_TENANT_ID", raising=False)
    monkeypatch.delenv("SOC_ENTRA_CLIENT_ID", raising=False)
    monkeypatch.delenv("SOC_ENTRA_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("SOC_ENTRA_BASE_URL", raising=False)
    monkeypatch.delenv("SOC_ENABLED_INTEGRATIONS", raising=False)

    mock_llm = MagicMock()
    mock_llm.call = AsyncMock(return_value="Timeline reconstructed from logs only.")

    task_id = graph.write_node("task", "forensics-task", {"agent": "forensics", "objective": "Build timeline"}, "commander")

    agent = ForensicsAgent(graph, mock_llm, console)
    assert agent.entra_adapter is None

    await agent.run(task_id, alert)

    assert graph.get_task_status(task_id) == "completed"
    assert len(graph.get_nodes_by_type("timeline_event")) >= 1
    assert graph.search_nodes(type="timeline_event", data_contains={"source": "entra"}) == []
